import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EXECUTION_PROFILES, evaluateManagedGrant, type ManagedGrant, type ManagedExecution, type Operation } from '../src/index.js';

const MiB = 1024 * 1024;
const asset = { id: '10000000-0000-4000-8000-000000000001', projectId: 'project-1', environment: 'staging' };
const grant: ManagedGrant = {
  status: 'approved', projectId: 'project-1', mode: 'assessment', risk: 'low',
  profiles: ['static.scan', 'artifact.analyze', 'archive.inspect', 'forensic.analyze', 'evidence.import', 'events.ingest', 'agent.observe'],
  limits: { maxInputBytes: 16 * MiB },
};
const labGrant: ManagedGrant = {
  status: 'approved', projectId: 'project-1', mode: 'lab', risk: 'moderate',
  profiles: ['lab.inventory', 'lab.remediate'], limits: { maxInputBytes: 256 * 1024, allowedPorts: [22, 443] },
  targetManifest: { version: 1, targets: [{ assetId: asset.id, address: '127.0.0.1', ports: [22, 443] }], exclusions: [] },
};
const execute = (profile = 'static.scan', inputBytes = 10): ManagedExecution => ({ profile, inputBytes });

test('approved grant maps each implemented offline profile to its exact operations', () => {
  for (const profile of EXECUTION_PROFILES.filter(profile => !profile.labOnly)) {
    for (const operation of profile.operations) {
      assert.equal(evaluateManagedGrant(grant, asset, operation, execute(profile.id)).allowed, true, `${profile.id}/${operation}`);
    }
  }
  assert.equal(evaluateManagedGrant(grant, { ...asset, environment: 'production' }, 'scan', execute()).allowed, true);
});

test('draft, revoked and unsupported grant states never authorize execution or preparation', () => {
  for (const status of ['draft', 'revoked', 'expired', 'pending', '', 'APPROVED']) {
    for (const execution of [execute(), { profile: 'static.scan', phase: 'prepare' } as ManagedExecution]) {
      assert.equal(evaluateManagedGrant({ ...grant, status }, asset, 'scan', execution).code, 'GRANT_INACTIVE');
    }
  }
});

test('project binding and permitted environment are mandatory even for preparation', () => {
  for (const changed of [{ ...asset, projectId: 'project-2' }, { ...asset, projectId: null }, { environment: 'lab' }]) {
    assert.equal(evaluateManagedGrant(grant, changed, 'scan', execute()).code, 'PROJECT_MISMATCH');
    assert.equal(evaluateManagedGrant(grant, changed, 'scan', { profile: 'static.scan', phase: 'prepare' }).allowed, false);
  }
  for (const environment of ['unknown', '', '*']) {
    assert.equal(evaluateManagedGrant(grant, { ...asset, environment }, 'scan', execute()).code, 'GRANT_INVALID');
  }
});

test('missing, unknown, duplicate or wildcard profiles fail closed without fallback to broad scan scope', () => {
  for (const selected of [[], ['static.scan', 'static.scan'], ['scan'], ['*'], ['constructor'], ['__proto__'], ['static.scan', 'unimplemented']]) {
    assert.equal(evaluateManagedGrant({ ...grant, profiles: selected }, asset, 'scan', execute()).code, 'GRANT_INVALID');
  }
  assert.equal(evaluateManagedGrant({ ...grant, profiles: ['archive.inspect'] }, asset, 'scan', execute()).code, 'PROFILE_DENIED');
  for (const profile of ['constructor', '__proto__', '*', 'response.execute']) {
    assert.equal(evaluateManagedGrant(grant, asset, 'scan', execute(profile)).code, 'PROFILE_DENIED');
  }
});

test('laboratory profiles require explicit lab mode and asset environment', () => {
  const lab = { ...asset, environment: 'lab' };
  const inventory: ManagedExecution = { profile: 'lab.inventory', address: '127.0.0.1', ports: [443] };
  assert.equal(evaluateManagedGrant(labGrant, lab, 'scan', inventory).allowed, true);
  assert.equal(evaluateManagedGrant(labGrant, lab, 'scan', execute('lab.remediate')).allowed, true);
  for (const environment of ['staging', 'production', 'development']) {
    assert.equal(evaluateManagedGrant(labGrant, { ...asset, environment }, 'scan', inventory).code, 'MODE_MISMATCH');
  }
  assert.equal(evaluateManagedGrant({ ...labGrant, mode: 'assessment' }, lab, 'scan', inventory).code, 'MODE_MISMATCH');
  assert.equal(evaluateManagedGrant({ ...grant, mode: 'lab' }, asset, 'scan', execute()).code, 'MODE_MISMATCH');
});

test('risk floor covers the full approved profile set and unsupported risk cannot bypass it', () => {
  const lab = { ...asset, environment: 'lab' };
  assert.equal(evaluateManagedGrant({ ...labGrant, risk: 'low' }, lab, 'scan', { profile: 'lab.inventory', address: '127.0.0.1', ports: [22] }).code, 'RISK_INSUFFICIENT');
  assert.equal(evaluateManagedGrant({ ...labGrant, risk: 'low' }, lab, 'scan', execute('lab.remediate')).code, 'RISK_INSUFFICIENT');
  assert.equal(evaluateManagedGrant({ ...grant, risk: 'high' as ManagedGrant['risk'] }, asset, 'scan', execute()).code, 'GRANT_INVALID');
  assert.equal(evaluateManagedGrant({ ...grant, mode: 'production-remediation' as ManagedGrant['mode'] }, asset, 'scan', execute()).code, 'GRANT_INVALID');
});

test('byte decisions honor both user and fixed executor limits including UTF-8 byte counts', () => {
  const narrow = { ...grant, limits: { maxInputBytes: 3 } };
  assert.equal(evaluateManagedGrant(narrow, asset, 'scan', execute('static.scan', 3)).allowed, true);
  assert.equal(evaluateManagedGrant(narrow, asset, 'scan', execute('static.scan', Buffer.byteLength('éé'))).code, 'INPUT_LIMIT');
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', execute('static.scan', MiB)).allowed, true);
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', execute('static.scan', MiB + 1)).code, 'INPUT_LIMIT');
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', execute('archive.inspect', 16 * MiB)).allowed, true);
  assert.equal(evaluateManagedGrant(grant, asset, 'event.ingest', execute('agent.observe', 16385)).code, 'INPUT_LIMIT');
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', execute('static.scan', 0)).allowed, true);
  for (const size of [-1, 0.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '10']) {
    assert.equal(evaluateManagedGrant(grant, asset, 'scan', { profile: 'static.scan', inputBytes: size as number }).code, 'INPUT_LIMIT');
  }
});

test('port execution requires a unique nonempty finite subset of the approved ports', () => {
  const lab = { ...asset, environment: 'lab' };
  assert.equal(evaluateManagedGrant(labGrant, lab, 'scan', { profile: 'lab.inventory', address: '127.0.0.1', ports: [443, 22] }).allowed, true);
  for (const ports of [undefined, [], [80], [22, 80], [22, 22], [0], [65536], [NaN], [22.5], ['22'], Array.from({ length: 17 }, (_, i) => i + 1)]) {
    assert.equal(evaluateManagedGrant(labGrant, lab, 'scan', { profile: 'lab.inventory', address: '127.0.0.1', ports: ports as number[] }).code, 'PORT_LIMIT');
  }
  assert.equal(evaluateManagedGrant(labGrant, lab, 'scan', { profile: 'lab.inventory', address: '127.0.0.1', ports: [22], inputBytes: 0 }).code, 'PORT_LIMIT');
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', { profile: 'static.scan', inputBytes: 1, ports: [22] }).code, 'INPUT_LIMIT');
});

test('invalid or unimplemented grant limits deny both prepare and execute', () => {
  const limits = [null, {}, { maxInputBytes: 0 }, { maxInputBytes: 16 * MiB + 1 }, { maxInputBytes: NaN },
    { maxInputBytes: 1.5 }, { maxInputBytes: '4' }, { maxInputBytes: 4, maxDurationSeconds: 1 },
    { maxInputBytes: 4, allowedPorts: [] }, { maxInputBytes: 4, allowedPorts: [22, 22] }, { maxInputBytes: 4, allowedPorts: [70000] }];
  for (const value of limits) {
    assert.equal(evaluateManagedGrant({ ...grant, limits: value as ManagedGrant['limits'] }, asset, 'scan', execute()).code, 'GRANT_INVALID');
    assert.equal(evaluateManagedGrant({ ...grant, limits: value as ManagedGrant['limits'] }, asset, 'scan', { profile: 'static.scan', phase: 'prepare' }).code, 'GRANT_INVALID');
  }
  assert.equal(evaluateManagedGrant({ ...labGrant, limits: { maxInputBytes: 1 } }, { ...asset, environment: 'lab' }, 'scan', { profile: 'lab.inventory', phase: 'prepare' }).code, 'GRANT_INVALID');
});

test('preparation does not imply execution and cannot bypass profile, mode, project or operation checks', () => {
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', { profile: 'archive.inspect', phase: 'prepare' }).allowed, true);
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', { profile: 'archive.inspect', phase: 'execute' }).code, 'INPUT_LIMIT');
  assert.equal(evaluateManagedGrant(grant, asset, 'event.ingest', { profile: 'archive.inspect', phase: 'prepare' }).code, 'OPERATION_DENIED');
  assert.equal(evaluateManagedGrant(grant, asset, 'scan', { profile: 'lab.inventory', phase: 'prepare' }).code, 'PROFILE_DENIED');
  assert.equal(evaluateManagedGrant(labGrant, { ...asset, environment: 'lab' }, 'scan', { profile: 'lab.inventory', phase: 'prepare' }).allowed, true);
});

test('critical and unrelated operations are never unlocked by a managed grant', () => {
  for (const operation of ['response.execute', 'remediation.apply', 'recovery.execute', 'scopes.create', 'unknown'] as Operation[]) {
    assert.equal(evaluateManagedGrant(grant, asset, operation, execute()).code, 'OPERATION_DENIED');
    assert.equal(evaluateManagedGrant(labGrant, { ...asset, environment: 'lab' }, operation, execute('lab.remediate')).code, 'OPERATION_DENIED');
  }
});

test('missing or malformed trusted execution context is rejected rather than accepting broad permission', () => {
  for (const execution of [undefined, null, [], {}, { profile: 1 }, { profile: 'static.scan', phase: 'preview' }, { profile: 'static.scan', inputBytes: 1, bypass: true }]) {
    assert.equal(evaluateManagedGrant(grant, asset, 'scan', execution as ManagedExecution).code, 'EXECUTION_REQUIRED');
  }
  for (const malformed of [null, undefined, [], {}, { ...grant, profiles: null }, { ...grant, limits: null }]) {
    assert.equal(evaluateManagedGrant(malformed as ManagedGrant, asset, 'scan', execute()).code, 'GRANT_INVALID');
  }
  assert.equal(evaluateManagedGrant(grant, null as unknown as typeof asset, 'scan', execute()).code, 'GRANT_INVALID');
});

test('decisions are deterministic and never mutate inputs or expose supplied values', () => {
  const input = structuredClone(grant), original = structuredClone(input), execution = execute();
  assert.deepEqual(evaluateManagedGrant(input, asset, 'scan', execution), evaluateManagedGrant(input, asset, 'scan', execution));
  assert.deepEqual(input, original);
  assert.deepEqual(execution, execute());
  const secret = 'SENSITIVE_UNTRUSTED_VALUE';
  assert.ok(!JSON.stringify(evaluateManagedGrant({ ...grant, projectId: secret }, asset, 'scan', execute(secret))).includes(secret));
  assert.ok(Object.isFrozen(EXECUTION_PROFILES));
  assert.ok(EXECUTION_PROFILES.every(profile => Object.isFrozen(profile) && Object.isFrozen(profile.operations)));
});
