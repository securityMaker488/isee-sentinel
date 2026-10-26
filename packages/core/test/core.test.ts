import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  BARRIER_CATALOG, OPERATIONS, SCAN_LIMITS, ScanValidationError, assessRisk, evaluateBarrierMatrix,
  evaluatePolicy, hashEvent, isSecurityEvent, scanFiles, sha256,
  type AuthorizationScope, type Identity, type Operation, type PolicyRequest, type SecurityEvent,
} from '../src/index.js';

const identity: Identity = { id: 'user-1', organizationId: 'org-1', role: 'admin' };
const scope: AuthorizationScope = {
  id: 'scope-1', organizationId: 'org-1', assetId: 'asset-1', environment: 'lab',
  operations: ['scan', 'evidence.import', 'event.ingest'],
  authorizationRef: 'Internal approval #42', notBefore: '2026-10-23T10:00:00.000Z', expiresAt: '2026-10-23T11:00:00.000Z',
};
const baseRequest: PolicyRequest = {
  identity, operation: 'scan', resource: { organizationId: 'org-1', assetId: 'asset-1', environment: 'lab' },
  scope, now: new Date('2026-10-23T10:30:00.000Z'),
};

test('PolicyGate permits an exact current scope and honors role distinctions', () => {
  assert.equal(evaluatePolicy(baseRequest).allowed, true);
  assert.equal(evaluatePolicy({ ...baseRequest, identity: { ...identity, role: 'analyst' } }).allowed, true);
  assert.equal(evaluatePolicy({ ...baseRequest, identity: { ...identity, role: 'viewer' } }).code, 'ROLE_DENIED');
  assert.equal(evaluatePolicy({ ...baseRequest, operation: 'assets.create', identity: { ...identity, role: 'analyst' } }).code, 'ROLE_DENIED');
  assert.equal(evaluatePolicy({ ...baseRequest, operation: 'assets.read', identity: { ...identity, role: 'viewer' } }).allowed, true);
});

test('PolicyGate denies missing scopes for all ingestion and scan operations, including administrators', () => {
  for (const operation of ['scan', 'evidence.import', 'event.ingest'] as Operation[]) {
    assert.equal(evaluatePolicy({ ...baseRequest, operation, scope: undefined }).code, 'SCOPE_REQUIRED');
  }
});

test('PolicyGate enforces tenant, asset, environment and exact operation boundaries', () => {
  assert.equal(evaluatePolicy({ ...baseRequest, resource: { ...baseRequest.resource, organizationId: 'org-2' } }).code, 'CROSS_ORGANIZATION');
  for (const change of [{ organizationId: 'org-2' }, { assetId: 'asset-2' }, { environment: 'production' as const }, { operations: ['evidence.import'] as Operation[] }]) {
    assert.equal(evaluatePolicy({ ...baseRequest, scope: { ...scope, ...change } }).code, 'SCOPE_MISMATCH');
  }
  assert.equal(evaluatePolicy({ ...baseRequest, resource: { organizationId: 'org-1' } }).code, 'INVALID_REQUEST');
});

test('PolicyGate is deny-by-default against unknown operations, roles and wildcard scopes', () => {
  assert.equal(evaluatePolicy({ ...baseRequest, operation: 'constructor' as Operation }).code, 'UNKNOWN_OPERATION');
  assert.equal(evaluatePolicy({ ...baseRequest, operation: '__proto__' as Operation }).allowed, false);
  assert.equal(evaluatePolicy({ ...baseRequest, identity: { ...identity, role: 'superadmin' as Identity['role'] } }).allowed, false);
  assert.equal(evaluatePolicy({ ...baseRequest, scope: { ...scope, operations: ['*'] as unknown as Operation[] } }).code, 'SCOPE_INVALID');
  assert.equal(evaluatePolicy({ ...baseRequest, scope: { ...scope, assetId: '*' } }).allowed, false);
  assert.equal(evaluatePolicy({} as PolicyRequest).allowed, false);
  assert.equal(evaluatePolicy(null as unknown as PolicyRequest).allowed, false);
});

test('PolicyGate includes start instant, excludes expiry, and rejects invalid or revoked intervals', () => {
  assert.equal(evaluatePolicy({ ...baseRequest, now: new Date(scope.notBefore) }).allowed, true);
  assert.equal(evaluatePolicy({ ...baseRequest, now: new Date(scope.expiresAt) }).code, 'SCOPE_EXPIRED');
  assert.equal(evaluatePolicy({ ...baseRequest, now: new Date('2026-10-23T09:59:59Z') }).code, 'SCOPE_NOT_STARTED');
  assert.equal(evaluatePolicy({ ...baseRequest, now: new Date(NaN) }).code, 'SCOPE_INVALID');
  assert.equal(evaluatePolicy({ ...baseRequest, scope: { ...scope, expiresAt: scope.notBefore } }).code, 'SCOPE_INVALID');
  assert.equal(evaluatePolicy({ ...baseRequest, scope: { ...scope, expiresAt: 'never' } }).code, 'SCOPE_INVALID');
  assert.equal(evaluatePolicy({ ...baseRequest, scope: { ...scope, revokedAt: '2026-10-23T10:01:00Z' } }).code, 'SCOPE_REVOKED');
});

test('PolicyGate cannot be used to authorize unimplemented critical executors', () => {
  for (const operation of ['response.execute', 'remediation.apply', 'recovery.execute'] as Operation[]) {
    for (const role of ['admin', 'analyst', 'viewer'] as const) {
      assert.equal(evaluatePolicy({ ...baseRequest, operation, identity: { ...identity, role }, scope: { ...scope, operations: [...OPERATIONS] } }).code, 'EXECUTOR_UNAVAILABLE');
    }
  }
});

test('SecureBuild detects real insecure configuration and emits evidence hashes without source snippets', () => {
  const env = '# exported deployment settings\nNODE_TLS_REJECT_UNAUTHORIZED="0"\nCORS_ORIGIN=*\nCORS_CREDENTIALS=true\n';
  const ssh = 'PermitRootLogin yes\nPasswordAuthentication yes\n';
  const result = scanFiles([{ path: '.env', content: env }, { path: 'etc/ssh/sshd_config', content: ssh }]);
  assert.deepEqual(result.findings.map(f => f.ruleId).sort(), ['SB-CORS-001', 'SB-SSH-001', 'SB-SSH-002', 'SB-TLS-001']);
  assert.equal(result.findings.find(f => f.ruleId === 'SB-TLS-001')?.line, 2);
  assert.equal(result.files.find(f => f.path === '.env')?.sha256, sha256(env));
  assert.equal(result.inputHash.length, 64);
  assert.equal(result.findings.every(f => f.ruleVersion === '1.0.0' && f.evidenceHash.length === 64), true);
  assert.equal(JSON.stringify(result).includes('NODE_TLS_REJECT_UNAUTHORIZED="0"'), false);
  assert.deepEqual(result, scanFiles([{ path: '.env', content: env }, { path: 'etc/ssh/sshd_config', content: ssh }]));
});

test('SecureBuild does not report examples, comments, unsupported source strings or similar directive names', () => {
  const result = scanFiles([
    { path: 'README.md', content: 'PermitRootLogin yes\nNODE_TLS_REJECT_UNAUTHORIZED=0\n{"rejectUnauthorized":false}' },
    { path: 'client.js', content: 'const example = "rejectUnauthorized: false"; throw Error("must never execute");' },
    { path: '.env', content: '# NODE_TLS_REJECT_UNAUTHORIZED=0\nMY_NODE_TLS_REJECT_UNAUTHORIZED=0\nNODE_TLS_REJECT_UNAUTHORIZED=1' },
    { path: 'sshd_config', content: '# PermitRootLogin yes\nOtherPermitRootLogin yes\nPermitRootLogin no\nPasswordAuthentication no\n' },
  ]);
  assert.equal(result.findings.length, 0);
  assert.equal(result.checks.length, 3);
  assert.equal(result.checks.every(check => check.status === 'pass'), true);
});

test('SecureBuild evaluates JSON booleans and pairs CORS options in the same object', () => {
  const result = scanFiles([{ path: 'config.json', content: JSON.stringify({ tls: { rejectUnauthorized: false }, cors: { origin: '*', credentials: true } }, null, 2) }]);
  assert.deepEqual(result.findings.map(f => f.ruleId).sort(), ['SB-CORS-001', 'SB-TLS-001']);
  const separated = scanFiles([{ path: 'config.json', content: '{"a":{"origin":"*"},"b":{"credentials":true},"rejectUnauthorized":"false"}' }]);
  assert.equal(separated.findings.length, 0);
  assert.equal(separated.checks.length, 0);
  const invalid = scanFiles([{ path: 'config.json', content: '{"rejectUnauthorized":false' }]);
  assert.equal(invalid.findings.length, 0);
  assert.equal(invalid.limitations.some(text => text.includes('JSON inválido')), true);
});

test('JSON findings preserve exact property lines across nested, repeated and escaped keys', () => {
  const result = scanFiles([{ path: 'settings.json', content: '{\n"safe": {"rejectUnauthorized": true},\n"unsafe": {\n"rejectUnauthorized": false\n},\n"escaped": {"reject\\u0055nauthorized": false}\n}' }]);
  assert.deepEqual(result.findings.map(finding => finding.line), [4, 6]);
  const duplicate = scanFiles([{ path: 'settings.json', content: '{"rejectUnauthorized":false, "rejectUnauthorized":{}}' }]);
  assert.equal(duplicate.checks.length, 0);
});

test('SSH Includes, Match contexts, duplicate and unknown values never produce false passes', () => {
  for (const content of [
    'Include sshd_config.d/*.conf\nPermitRootLogin no\nPasswordAuthentication no',
    'PermitRootLogin no\nMatch User deploy\nPasswordAuthentication no',
    'PermitRootLogin no\nPermitRootLogin yes',
    'PermitRootLogin prohibit-password\nPasswordAuthentication other',
  ]) {
    const result = scanFiles([{ path: 'sshd_config', content }]);
    assert.equal(result.checks.some(check => check.status === 'pass'), false);
  }
  const contextual = scanFiles([{ path: 'sshd_config', content: 'PermitRootLogin no\nMatch User deploy\nPermitRootLogin yes' }]);
  assert.equal(contextual.findings[0].ruleId, 'SB-SSH-001');
  assert.equal(contextual.findings[0].confidence, 'medium');
});

test('Secrets are detected but cannot leak through findings, checks, errors or reports', () => {
  const keyId = 'AKIA' + '1234567890ABCDEF';
  const privateBody = 'a_sensitive_private_body_that_must_not_appear';
  const secret = 'Q'.repeat(40);
  const result = scanFiles([{ path: 'credentials.txt', content: `AWS_ACCESS_KEY_ID=${keyId}\nAWS_SECRET_ACCESS_KEY=${secret}\n-----BEGIN PRIVATE KEY-----\n${privateBody}\n-----END PRIVATE KEY-----` }]);
  assert.equal(result.findings.filter(f => f.ruleId === 'SB-SECRET-002').length, 2);
  assert.equal(result.findings.filter(f => f.ruleId === 'SB-SECRET-001').length, 1);
  const output = JSON.stringify({ result, barriers: evaluateBarrierMatrix(result), risk: assessRisk(result.findings) });
  for (const sensitive of [keyId, secret, privateBody, '-----BEGIN PRIVATE KEY-----']) assert.equal(output.includes(sensitive), false);
});

test('Upload validation rejects traversal, absolutes, schemes, NUL, ambiguous paths and link metadata', () => {
  for (const path of ['../secret', 'a/../../secret', '/etc/passwd', 'C:/Windows/file', 'C:\\Windows\\file', '\\\\host\\share', 'https://example.test/a', 'a\0b', 'a//b', 'a/./b', '%2e%2e/secret', 'a:b', 'a.']) {
    assert.throws(() => scanFiles([{ path, content: 'test' }]), ScanValidationError);
  }
  assert.throws(() => scanFiles([{ path: 'config', content: 'x', symlink: '/etc/passwd' }]), ScanValidationError);
  assert.throws(() => scanFiles([{ path: 'binary', content: 'a\0b' }]), ScanValidationError);
  assert.throws(() => scanFiles([{ path: 'A', content: '' }, { path: 'a', content: '' }]), ScanValidationError);
});

test('Upload limits count UTF-8 bytes and reject oversize payloads before analysis', () => {
  assert.throws(() => scanFiles([]), ScanValidationError);
  assert.throws(() => scanFiles(Array.from({ length: SCAN_LIMITS.maxFiles + 1 }, (_, n) => ({ path: `file-${n}`, content: '' }))), ScanValidationError);
  assert.throws(() => scanFiles([{ path: 'large', content: 'é'.repeat(SCAN_LIMITS.maxFileBytes / 2 + 1) }]), ScanValidationError);
  assert.throws(() => scanFiles(Array.from({ length: 5 }, (_, n) => ({ path: `file-${n}`, content: 'a'.repeat(SCAN_LIMITS.maxFileBytes) }))), ScanValidationError);
});

test('BarrierMatrix marks only evaluated controls and never claims operational protection', () => {
  assert.equal(BARRIER_CATALOG.length, 14);
  const empty = evaluateBarrierMatrix();
  assert.equal(empty.every(layer => layer.status === 'not_evaluated' && !layer.runtimeVerified), true);
  const safe = evaluateBarrierMatrix(scanFiles([{ path: 'sshd_config', content: 'PermitRootLogin no\nPasswordAuthentication no' }]));
  const endpoint = safe.find(layer => layer.id === 'endpoint')!;
  assert.equal(endpoint.status, 'not_evaluated');
  assert.equal(endpoint.evaluatedControls.filter(control => control.status === 'pass').length, 2);
  assert.equal(endpoint.evaluatedControls.find(control => control.controlId === 'endpoint.runtime')?.status, 'not_evaluated');
  const unsafe = evaluateBarrierMatrix(scanFiles([{ path: 'sshd_config', content: 'PermitRootLogin yes' }]));
  assert.equal(unsafe.find(layer => layer.id === 'endpoint')?.status, 'fail');
  assert.equal(unsafe.find(layer => layer.id === 'edge')?.status, 'not_evaluated');
});

test('Risk is explainable, deduplicated and absence of findings means unknown', () => {
  assert.equal(assessRisk([]).level, 'unknown');
  const findings = scanFiles([{ path: '.env', content: 'NODE_TLS_REJECT_UNAUTHORIZED=0' }]).findings;
  const risk = assessRisk([...findings, ...findings]);
  assert.equal(risk.score, 25);
  assert.equal(risk.level, 'high');
  assert.equal(risk.factors.length, 1);
});

test('Event schema is versioned, typed and hashed deterministically', () => {
  const event: SecurityEvent = { schemaVersion: 1, id: 'event-1', organizationId: 'org-1', assetId: 'asset-1', type: 'auth.failure',
    occurredAt: '2026-10-23T10:00:00Z', receivedAt: '2026-10-23T10:00:01Z', source: 'manual', data: { subject: 'alice', synthetic: true } };
  assert.equal(isSecurityEvent(event), true);
  assert.equal(isSecurityEvent({ ...event, schemaVersion: 2 }), false);
  assert.equal(isSecurityEvent({ ...event, type: 'unknown' }), false);
  assert.equal(isSecurityEvent({ ...event, data: { token: 'not allowed' } }), false);
  assert.equal(hashEvent(event), hashEvent({ ...event, data: { synthetic: true, subject: 'alice' } }));
  assert.notEqual(hashEvent(event), hashEvent({ ...event, data: { subject: 'bob', synthetic: true } }));
});
