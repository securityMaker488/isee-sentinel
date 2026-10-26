import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import { scanFiles } from '@sentinel/core';
import { openDatabase, migrate, type Database } from '../src/db.ts';
import { registerAuth } from '../src/auth.ts';
import { registerGraph, type GraphResult } from '../src/graph.ts';
import { digest, encrypt, randomToken } from '../src/security.ts';

let db: Database, app: FastifyInstance;
const key = randomBytes(32), organization = randomUUID(), foreignOrganization = randomUUID(), actor = randomUUID();
const project = randomUUID(), foreignProject = randomUUID(), asset = randomUUID(), foreignAsset = randomUUID();
const evidence = randomUUID(), proposed = randomUUID(), foreignEvidence = randomUUID(), incident = randomUUID(), latestScan = randomUUID(), oldScan = randomUUID();
const session = randomToken(), foreignSession = randomToken(), csrf = randomToken(), clock = Date.now();
const origin = 'http://127.0.0.1:4310';
const headers = (foreign = false) => ({ host: '127.0.0.1:4310', origin, cookie: `sentinel_session=${foreign ? foreignSession : session}`, 'x-csrf-token': csrf });
const result = scanFiles([{ path: 'sshd_config', content: 'PermitRootLogin yes\nPasswordAuthentication yes\n' }]);
const nodeId = (type: string, value: string) => `${type}:${value}`;

before(async () => {
  db = await openDatabase(); await migrate(db);
  for (const [id, name] of [[organization, 'Graph organization'], [foreignOrganization, 'FOREIGN_ORG_PRIVATE']]) await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)', [id, name]);
  await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)', [actor, organization, 'graph@sentinel.test', 'admin', 'not-used', encrypt('not-used', key, `totp:${actor}`)]);
  await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)', [actor, digest(randomToken())]);
  for (const org of [organization, foreignOrganization]) await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)', [actor, org]);
  for (const [token, org] of [[session, organization], [foreignSession, foreignOrganization]]) await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)', [digest(token), actor, csrf, new Date(clock + 3600000), org]);
  for (const [id, org, name] of [[project, organization, 'Graph project'], [foreignProject, foreignOrganization, 'FOREIGN_PROJECT_PRIVATE']]) await db.query('INSERT INTO projects(id,organization_id,name,contract_ref) VALUES($1,$2,$3,$4)', [id, org, name, 'Graph test authorization']);
  for (const [id, org, parent, name] of [[asset, organization, project, 'A primary asset'], [foreignAsset, foreignOrganization, foreignProject, 'FOREIGN_ASSET_PRIVATE']]) await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality,project_id) VALUES($1,$2,$3,$4,$5,$6,$7)', [id, org, name, 'server', 'lab', 4, parent]);
  for (const [id, org, resource, name] of [[evidence, organization, asset, 'original.conf'], [proposed, organization, asset, 'proposed.conf'], [foreignEvidence, foreignOrganization, foreignAsset, 'FOREIGN_EVIDENCE_PRIVATE']]) await db.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [id, org, resource, name, 'text/plain', digest('content'), 7, 'CIPHER_MUST_NOT_APPEAR', actor, 'graph-test']);
  for (const [id, when] of [[oldScan, new Date(clock - 60000)], [latestScan, new Date(clock)]]) {
    await db.query('INSERT INTO jobs(id,organization_id,asset_id,kind,status,created_at) VALUES($1,$2,$3,$4,$5,$6)', [id, organization, asset, 'scan', 'completed', when]);
    await db.query('INSERT INTO scans(id,organization_id,asset_id,result,created_at) VALUES($1,$2,$3,$4,$5)', [id, organization, asset, JSON.stringify(result), when]);
  }
  await db.query('INSERT INTO findings(id,organization_id,asset_id,scan_id,evidence_id,details) VALUES($1,$2,$3,$4,$5,$6)', [randomUUID(), organization, asset, oldScan, evidence, JSON.stringify({ ...result.findings[0], title: 'OLD_FINDING_MUST_NOT_APPEAR' })]);
  for (const finding of result.findings) await db.query('INSERT INTO findings(id,organization_id,asset_id,scan_id,evidence_id,details) VALUES($1,$2,$3,$4,$5,$6)', [randomUUID(), organization, asset, latestScan, evidence, JSON.stringify(finding)]);
  await db.query('INSERT INTO incidents(id,organization_id,asset_id,rule_id,title,event_ids) VALUES($1,$2,$3,$4,$5,$6)', [incident, organization, asset, 'GRAPH-TEST', 'Incident fixture', '[]']);
  await db.query('INSERT INTO alerts(id,organization_id,asset_id,incident_id,rule_id,rule_version,title,severity,confidence,synthetic,event_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)', [randomUUID(), organization, asset, incident, 'GRAPH-TEST', '1', 'Synthetic alert fixture', 'medium', 'medium', true, '[]']);
  await db.query('INSERT INTO incident_evidence(organization_id,incident_id,evidence_id,actor_id) VALUES($1,$2,$3,$4)', [organization, incident, evidence, actor]);
  await db.query('INSERT INTO artifact_analyses(id,organization_id,asset_id,kind,evidence_id,report) VALUES($1,$2,$3,$4,$5,$6)', [randomUUID(), organization, asset, 'dependency', evidence, JSON.stringify({ findings: [{}] })]);
  await db.query('INSERT INTO remediation_plans(id,organization_id,asset_id,name,status,original_evidence_id,proposed_evidence_id,original_hash,proposed_hash,changes,reasons,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)', [randomUUID(), organization, asset, 'Artifact correction', 'proposed', evidence, proposed, digest('a'), digest('b'), '[]', '[]', actor]);
  app = Fastify(); await app.register(cookie); await registerAuth(app, db, key, origin, false, () => clock);
  app.setErrorHandler((error, _request, reply) => { const value = error as any; reply.code(value.statusCode ?? 500).send({ error: { code: value.code, message: value.message } }); });
  await registerGraph(app, { db }); await app.ready();
});
after(async () => { await app?.close(); await db?.close(); });

async function graph(foreign = false): Promise<GraphResult> {
  const response = await app.inject({ url: '/api/graph', headers: headers(foreign) });
  assert.equal(response.statusCode, 200, response.body);
  return response.json();
}

test('graph requires a real session and allows the existing viewer read permission', async () => {
  assert.equal((await app.inject({ url: '/api/graph', headers: { host: '127.0.0.1:4310' } })).statusCode, 401);
  await db.query("UPDATE users SET role='viewer' WHERE id=$1", [actor]);
  try { assert.ok((await graph()).nodes.length > 0); }
  finally { await db.query("UPDATE users SET role='admin' WHERE id=$1", [actor]); }
});

test('graph has real relationships, stable identifiers and no dangling or duplicate edges', async () => {
  const data = await graph(), repeated = await graph();
  assert.deepEqual(data, repeated);
  const ids = new Set(data.nodes.map(node => node.id));
  assert.equal(ids.size, data.nodes.length);
  assert.equal(new Set(data.edges.map(edge => edge.id)).size, data.edges.length);
  for (const edge of data.edges) { assert.ok(ids.has(edge.from)); assert.ok(ids.has(edge.to)); }
  for (const type of ['organization', 'project', 'asset', 'scan', 'finding', 'evidence', 'incident', 'alert', 'analysis', 'remediation']) assert.ok(data.nodes.some(node => node.type === type), type);
  for (const relation of ['has_project', 'has_asset', 'latest_static_scan', 'produced_finding', 'supported_by', 'has_incident', 'has_alert', 'analyzed_evidence', 'original_evidence', 'proposed_evidence', 'case_evidence']) assert.ok(data.edges.some(edge => edge.relation === relation), relation);
  assert.equal(data.counts.nodes, data.nodes.length); assert.equal(data.counts.edges, data.edges.length); assert.equal(data.truncated, false);
  assert.equal(data.nodes.find(node => node.type === 'alert')?.data.synthetic, true);
});

test('graph isolates tenants and omits encrypted content and prior scan findings', async () => {
  const ours = await graph(), theirs = await graph(true);
  assert.ok(!JSON.stringify(ours).includes('FOREIGN_'));
  assert.ok(!JSON.stringify(ours).includes('CIPHER_MUST_NOT_APPEAR'));
  assert.ok(!JSON.stringify(ours).includes('OLD_FINDING_MUST_NOT_APPEAR'));
  assert.ok(!theirs.nodes.some(node => node.assetId === asset));
  assert.ok(theirs.nodes.some(node => node.id === nodeId('asset', foreignAsset)));
  assert.ok(!ours.nodes.some(node => node.id === nodeId('scan', oldScan)));
});

test('risk score is limited to complete findings from the latest static scan', async () => {
  const data = await graph();
  const risk = data.nodes.find(node => node.id === nodeId('asset', asset))?.data.risk as Record<string, unknown>;
  assert.equal(risk.scanId, latestScan); assert.equal(risk.findingCount, 2); assert.equal(typeof risk.score, 'number');
  assert.match(String(risk.method), /estático/);
  const empty = (await graph(true)).nodes.find(node => node.id === nodeId('asset', foreignAsset))?.data.risk as Record<string, unknown>;
  assert.equal(empty.level, 'unknown'); assert.equal(empty.score, undefined);
});

test('bounded subsets advertise truncation, retain parents and do not calculate risk from incomplete findings', async () => {
  const extra = Array.from({ length: 40 }, (_, index) => ({ ...result.findings[0], id: `extra-${index}` }));
  for (const finding of extra) await db.query('INSERT INTO findings(id,organization_id,asset_id,scan_id,evidence_id,details) VALUES($1,$2,$3,$4,$5,$6)', [randomUUID(), organization, asset, latestScan, evidence, JSON.stringify(finding)]);
  await db.query('UPDATE scans SET result=$2 WHERE id=$1', [latestScan, JSON.stringify({ ...result, findings: [...result.findings, ...extra] })]);
  const values: string[] = [], params: unknown[] = [];
  for (let index = 0; index < 45; index++) { const start = params.length; values.push(`($${start + 1},$${start + 2},$${start + 3},'server','lab',3)`); params.push(randomUUID(), organization, `Z extra ${index}`); }
  await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality) VALUES ' + values.join(','), params);
  const data = await graph();
  assert.equal(data.truncated, true); assert.ok(data.nodes.length <= 200); assert.ok(data.edges.length <= 500);
  assert.equal(data.nodes.filter(node => node.type === 'asset').length, 40);
  assert.equal(data.nodes.filter(node => node.type === 'finding').length, 30);
  assert.equal((data.nodes.find(node => node.id === nodeId('asset', asset))?.data.risk as Record<string, unknown>).level, 'unknown');
  const positions = new Map(data.nodes.map((node, index) => [node.id, index]));
  for (const edge of data.edges) { assert.ok(positions.has(edge.from)); assert.ok(positions.has(edge.to)); assert.ok(positions.get(edge.from)! < positions.get(edge.to)!); }
  assert.deepEqual(data, await graph());
});
