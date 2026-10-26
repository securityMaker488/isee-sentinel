import {after,before,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import Fastify,{type FastifyInstance} from 'fastify';
import cookie from '@fastify/cookie';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {registerAuth} from '../src/auth.ts';
import {registerOperations,proposeSshArtifact} from '../src/operations.ts';
import {digest,encrypt,randomToken} from '../src/security.ts';
import {verifyAuditChain} from '../src/audit.ts';

let db:Database,app:FastifyInstance;
const key=randomBytes(32),org=randomUUID(),otherOrg=randomUUID(),actor=randomUUID(),asset=randomUUID(),production=randomUUID(),foreignAsset=randomUUID(),incident=randomUUID();
const session=randomToken(),otherSession=randomToken(),csrf=randomToken(),clock=Date.now(),origin='http://127.0.0.1:4310';
const headers=(foreign=false)=>({host:'127.0.0.1:4310',origin,cookie:`sentinel_session=${foreign?otherSession:session}`,'x-csrf-token':csrf});
const send=(url:string,payload?:any,foreign=false)=>app.inject({method:'POST',url,headers:headers(foreign),...(payload===undefined?{}:{payload})});
const original='Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n';
let planId:string;

before(async()=>{
  db=await openDatabase();await migrate(db);
  for(const id of [org,otherOrg])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,'Operations test organization']);
  await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[actor,org,'operations@sentinel.test','admin','not-used',encrypt('not-used',key,`totp:${actor}`)]);
  await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[actor,digest(randomToken())]);
  for(const organization of [org,otherOrg])await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[actor,organization]);
  for(const [token,organization] of [[session,org],[otherSession,otherOrg]])await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),actor,csrf,new Date(clock+3600000),organization]);
  for(const [id,organization,environment] of [[asset,org,'lab'],[production,org,'production'],[foreignAsset,otherOrg,'lab']]) {
    await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality) VALUES($1,$2,$3,$4,$5,3)',[id,organization,'Controlled artifact','server',environment]);
    await db.query('INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[randomUUID(),organization,id,environment,JSON.stringify(['scan','evidence.import']),'Operations isolated test',new Date(clock-60000),new Date(clock+3600000),actor]);
  }
  await db.query('INSERT INTO incidents(id,organization_id,asset_id,rule_id,title,event_ids) VALUES($1,$2,$3,$4,$5,$6)',[incident,org,asset,'TEST','Incident fixture','[]']);
  app=Fastify({ajv:{customOptions:{removeAdditional:false,coerceTypes:false}}});await app.register(cookie);await registerAuth(app,db,key,origin,false,()=>clock);
  app.setErrorHandler((error,_req,reply)=>{const e=error as any;reply.code(e.statusCode??500).send({error:{code:e.code,message:e.message}});});
  await registerOperations(app,{db,masterKey:key,now:()=>clock});await app.ready();
});
after(async()=>{await app?.close();await db?.close();});

test('SSH proposal refuses ambiguous configurations and preserves safe content',()=>{
  const changed=proposeSshArtifact(original);assert.equal(changed.status,'proposed');assert.equal(changed.changes.length,2);assert.equal(changed.content,'Port 22\nPermitRootLogin no\nPasswordAuthentication no\n');
  const safe='PermitRootLogin no\r\nPasswordAuthentication no\r\n';assert.equal(proposeSshArtifact(safe).status,'no_change');assert.equal(proposeSshArtifact(safe).content,safe);
  for(const input of [original+'Include /etc/ssh/*.conf\n',original+'Match User root\n',original+'PermitRootLogin no\n','PermitRootLogin yes\n',original+'broken-line\n','PermitRootLogin "yes"\nPasswordAuthentication yes\n']) {
    const result=proposeSshArtifact(input);assert.equal(result.status,'manual_review');assert.equal(result.content,input);assert.equal(result.changes.length,0);assert.ok(result.reasons.length);
  }
  assert.throws(()=>proposeSshArtifact('x'.repeat(262145)),/256 KiB/);assert.throws(()=>proposeSshArtifact('a\0b'),/controle/);
});

test('remediation requires session, CSRF, administrator, lab asset and live scope',async()=>{
  assert.equal((await app.inject({url:'/api/remediations',headers:{host:'127.0.0.1:4310'}})).statusCode,401);
  const payload={assetId:asset,name:'sshd_config',content:original};
  assert.equal((await app.inject({method:'POST',url:'/api/remediations',headers:{...headers(),'x-csrf-token':'wrong'},payload})).statusCode,403);
  await db.query("UPDATE users SET role='viewer' WHERE id=$1",[actor]);assert.equal((await send('/api/remediations',payload)).statusCode,403);await db.query("UPDATE users SET role='admin' WHERE id=$1",[actor]);
  assert.equal((await send('/api/remediations',{...payload,assetId:production})).statusCode,403);
  assert.equal((await send('/api/remediations',{...payload,assetId:foreignAsset})).statusCode,404);
  await db.query('UPDATE authorizations SET revoked_at=$2 WHERE asset_id=$1',[asset,new Date(clock)]);
  assert.equal((await send('/api/remediations',payload)).statusCode,403);await db.query('UPDATE authorizations SET revoked_at=NULL WHERE asset_id=$1',[asset]);
  const result=await send('/api/remediations',payload);assert.equal(result.statusCode,200,result.body);planId=result.json().id;assert.equal(result.json().target,'stored_lab_artifact');assert.equal(result.json().status,'proposed');
});

test('remediation applies only after approval, verifies stored bytes, and recovers original revision',async()=>{
  assert.equal((await send(`/api/remediations/${planId}/apply`)).statusCode,409);
  assert.equal((await send(`/api/remediations/${planId}/approve`)).statusCode,200);
  assert.equal((await send(`/api/remediations/${planId}/approve`)).statusCode,409);
  const applied=await send(`/api/remediations/${planId}/apply`);assert.equal(applied.statusCode,200,applied.body);assert.equal(applied.json().currentRevision,2);
  const verified=await send(`/api/remediations/${planId}/verify`);assert.equal(verified.statusCode,200,verified.body);assert.equal(verified.json().status,'verified');assert.equal(verified.json().verification.checks.length,2);
  const rolledBack=await send(`/api/remediations/${planId}/rollback`);assert.equal(rolledBack.statusCode,200,rolledBack.body);assert.equal(rolledBack.json().status,'rolled_back');assert.equal(rolledBack.json().currentRevision,3);
  const detail=await app.inject({url:`/api/remediations/${planId}`,headers:headers()});assert.equal(detail.statusCode,200,detail.body);const result=detail.json();assert.equal(result.originalContent,original);assert.equal(result.proposedContent,original.replaceAll('yes','no'));assert.ok(result.patch.includes('-PermitRootLogin yes'));assert.deepEqual(result.revisions.map((r:any)=>r.action),['import','apply','rollback']);assert.equal(result.revisions[2].sha256,digest(original));
  const [stored]=await db.query('SELECT * FROM remediation_revisions WHERE plan_id=$1 AND revision=3',[planId]);assert.ok(!stored.content_cipher.includes('PermitRootLogin'));await assert.rejects(db.query('DELETE FROM remediation_revisions WHERE plan_id=$1',[planId]),/append-only/);
  assert.equal((await send(`/api/remediations/${planId}/apply`)).statusCode,409);
});

test('cross-organization reads, mutations and plaintext viewer access are denied',async()=>{
  assert.equal((await app.inject({url:`/api/remediations/${planId}`,headers:headers(true)})).statusCode,404);
  assert.equal((await send(`/api/remediations/${planId}/rollback`,undefined,true)).statusCode,404);
  assert.deepEqual((await app.inject({url:'/api/remediations',headers:headers(true)})).json().items,[]);
  await db.query("UPDATE users SET role='viewer' WHERE id=$1",[actor]);assert.equal((await app.inject({url:`/api/remediations/${planId}`,headers:headers()})).statusCode,403);await db.query("UPDATE users SET role='admin' WHERE id=$1",[actor]);
});

test('manual review cannot be approved and revoked scopes stop previously approved work',async()=>{
  const manual=await send('/api/remediations',{assetId:asset,name:'sshd_config',content:original+'Include extra.conf\n'});assert.equal(manual.statusCode,200,manual.body);assert.equal(manual.json().status,'manual_review');assert.equal((await send(`/api/remediations/${manual.json().id}/approve`)).statusCode,409);
  const proposed=await send('/api/remediations',{assetId:asset,name:'sshd_config',content:original});const id=proposed.json().id;assert.equal((await send(`/api/remediations/${id}/approve`)).statusCode,200);
  await db.query('UPDATE authorizations SET revoked_at=$2 WHERE asset_id=$1',[asset,new Date(clock)]);assert.equal((await send(`/api/remediations/${id}/apply`)).statusCode,403);await db.query('UPDATE authorizations SET revoked_at=NULL WHERE asset_id=$1',[asset]);
  const [stored]=await db.query('SELECT status,current_revision FROM remediation_plans WHERE id=$1',[id]);assert.equal(stored.status,'approved');assert.equal(stored.current_revision,1);
});

test('investigation stores encrypted immutable notes, valid transitions and same-asset evidence',async()=>{
  assert.equal((await send(`/api/incidents/${incident}/notes`,{body:'   '})).statusCode,400);
  const note=await send(`/api/incidents/${incident}/notes`,{body:'Investigação documentada: confirmar a origem.'});assert.equal(note.statusCode,200,note.body);
  const [stored]=await db.query('SELECT body_cipher FROM incident_notes WHERE id=$1',[note.json().id]);assert.ok(!stored.body_cipher.includes('Investiga'));await assert.rejects(db.query('DELETE FROM incident_notes WHERE id=$1',[note.json().id]),/append-only/);
  assert.equal((await send(`/api/incidents/${incident}/status`,{status:'resolved'})).statusCode,409);
  for(const status of ['investigating','resolved','closed','investigating'])assert.equal((await send(`/api/incidents/${incident}/status`,{status})).statusCode,200);
  const [plan]=await db.query('SELECT original_evidence_id FROM remediation_plans WHERE id=$1',[planId]);
  const link=await send(`/api/incidents/${incident}/evidence`,{evidenceId:plan.original_evidence_id});assert.equal(link.statusCode,200,link.body);assert.equal(link.json().duplicate,false);assert.equal((await send(`/api/incidents/${incident}/evidence`,{evidenceId:plan.original_evidence_id})).json().duplicate,true);
  const detail=await app.inject({url:`/api/incidents/${incident}/case`,headers:headers()});assert.equal(detail.statusCode,200,detail.body);assert.equal(detail.json().notes[0].body,'Investigação documentada: confirmar a origem.');assert.equal(detail.json().evidence.length,1);assert.ok(detail.json().history.length>=6);
  assert.equal((await app.inject({url:`/api/incidents/${incident}/case`,headers:headers(true)})).statusCode,404);assert.equal((await send(`/api/incidents/${incident}/notes`,{body:'Foreign'},true)).statusCode,404);
  assert.equal((await send(`/api/incidents/${incident}/evidence`,{evidenceId:randomUUID()})).statusCode,404);
  const chain=verifyAuditChain(await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[org]));assert.equal(chain.valid,true);
});
