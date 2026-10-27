import {after,before,test} from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,randomBytes,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {canonical,decrypt,digest,encrypt,randomToken} from '../src/security.ts';
import {verifyAuditChain} from '../src/audit.ts';

let db:Database,runtime:Database,app:Awaited<ReturnType<typeof buildApp>>,wrongKeyApp:Awaited<ReturnType<typeof buildApp>>;
const key=randomBytes(32),organization=randomUUID(),foreignOrganization=randomUUID(),operator=randomUUID();
const project=randomUUID(),otherProject=randomUUID(),foreignProject=randomUUID();
const session=randomToken(),foreignSession=randomToken(),csrf=randomToken(),initialTime=Date.now();
let clock=initialTime,nmapRuns=0,importRuns=0,forensicRuns=0;
const origin='http://127.0.0.1:4310';
const headers=(foreign=false)=>({host:'127.0.0.1:4310',origin,cookie:`sentinel_session=${foreign?foreignSession:session}`,'x-csrf-token':csrf});
const endpoint='/api/assessment-authorizations';
const send=(url:string,payload?:unknown,foreign=false)=>app.inject({method:'POST',url,headers:headers(foreign),...(payload===undefined?{}:{payload:payload as any})});
const get=(url:string,foreign=false)=>app.inject({url,headers:headers(foreign)});
const authorityBytes=Buffer.from('SYNTHETIC AUTHORITY EVIDENCE: local tests only; not a customer authorization.');
const base64=authorityBytes.toString('base64');
const safeConfiguration='PermitRootLogin no\nPasswordAuthentication no\n';
const nmapXml='<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="table" conf="3"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>';
const manifest=(assetId:string,address='127.0.0.1',ports=[22])=>({version:1,targets:[{assetId,address,ports}],exclusions:[] as {address:string}[]});

async function asset(options:{organization?:string;projectId?:string|null;environment?:string}={}) {
 const id=randomUUID(),org=options.organization??organization;
 const linkedProject=options.projectId===undefined?(org===organization?project:foreignProject):options.projectId;
 await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality,project_id) VALUES($1,$2,$3,$4,$5,3,$6)',[id,org,'Synthetic assessment asset','application',options.environment??'lab',linkedProject]);
 return id;
}
function draft(assetIds:string[],overrides:Record<string,unknown>={}) {
 return {projectId:project,assetIds,mode:'lab',risk:'low',profiles:['static.scan'],limits:{maxInputBytes:1024},
  notBefore:new Date(clock-1000).toISOString(),expiresAt:new Date(clock+3600000).toISOString(),
  responsible:{name:'Synthetic Responsible',role:'Fixture owner',organization:'Synthetic organization',contact:'fixture@sentinel.test'},
  purpose:'Exercise the authorization lifecycle with synthetic local fixtures.',
  authority:{channel:'document',reference:'SYNTHETIC-CONSENT-ONLY',evidence:{name:'authority-fixture.txt',mediaType:'text/plain',contentBase64:base64}},...overrides};
}
async function create(assetIds:string[],overrides:Record<string,unknown>={}) {
 const response=await send(endpoint,draft(assetIds,overrides));assert.equal(response.statusCode,200,response.body);return response.json();
}
async function detail(id:string) {
 const response=await get(`${endpoint}/${id}`);assert.equal(response.statusCode,200,response.body);return response.json();
}
async function approve(id:string) {
 const current=await detail(id),response=await send(`${endpoint}/${id}/approve`,{requestHash:current.requestHash,attested:true});
 assert.equal(response.statusCode,200,response.body);assert.equal(response.json().status,'approved');return response.json();
}
const scan=(assetId:string,content=safeConfiguration)=>send('/api/scans',{assetId,files:[{path:'sshd_config',content}]});
async function legacy(assetId:string,operations=['scan','evidence.import','event.ingest']) {
 const response=await send('/api/authorizations',{assetId,operations,authorizationRef:'SYNTHETIC-LEGACY-ONLY',expiresAt:new Date(clock+3600000).toISOString()});
 assert.equal(response.statusCode,200,response.body);return response.json().id as string;
}

before(async()=>{
 db=await openDatabase({url:process.env.SENTINEL_AUTHORIZATION_TEST_DATABASE_URL});await migrate(db);
 for(const id of [organization,foreignOrganization])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,'Synthetic authorization fixture']);
 await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[operator,organization,'authorizations@sentinel.test','admin','unused',encrypt('unused',key,`totp:${operator}`)]);
 await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[operator,digest(randomToken())]);
 for(const org of [organization,foreignOrganization])await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[operator,org]);
 for(const [token,org] of [[session,organization],[foreignSession,foreignOrganization]])await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),operator,csrf,new Date(clock+48*3600000),org]);
 for(const [id,org] of [[project,organization],[otherProject,organization],[foreignProject,foreignOrganization]])await db.query('INSERT INTO projects(id,organization_id,name,contract_ref) VALUES($1,$2,$3,$4)',[id,org,'Synthetic assessment project','SYNTHETIC-ONLY']);
 if(process.env.SENTINEL_AUTHORIZATION_TEST_RUNTIME_URL){
  for(const statement of (await readFile(new URL('../../../ops/runtime-grants.sql',import.meta.url),'utf8')).split(';').filter(s=>s.trim()))await db.query(statement);
  runtime=await openDatabase({url:process.env.SENTINEL_AUTHORIZATION_TEST_RUNTIME_URL});
 }else runtime=db;
 app=await buildApp({db:runtime,masterKey:key,now:()=>clock,
  nmapPath:process.platform==='win32'?'C:\\Trusted\\nmap.exe':'/trusted/nmap',labRunner:async()=>{nmapRuns++;return {stdout:Buffer.from(nmapXml),exitCode:0};},
  pythonPath:process.platform==='win32'?'C:\\Trusted\\python.exe':'/trusted/python',
  importRunner:async()=>{importRuns++;throw new Error('Unexpected worker execution in authorization rejection test');},
  forensicRunner:async()=>{forensicRuns++;throw new Error('Unexpected worker execution in authorization rejection test');}});
 wrongKeyApp=await buildApp({db:runtime,masterKey:randomBytes(32),now:()=>clock});
});
after(async()=>{await app?.close();await wrongKeyApp?.close();if(runtime&&runtime!==db)await runtime.close();await db?.close();});

test('managed authorization creation requires real authentication, CSRF and administrator role',async()=>{
 const target=await asset(),body=draft([target]);
 assert.equal((await app.inject({method:'POST',url:endpoint,headers:{host:headers().host,origin},payload:body})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:endpoint,headers:{...headers(),'x-csrf-token':'incorrect'},payload:body})).statusCode,403);
 for(const role of ['viewer','analyst']){
  await db.query('UPDATE users SET role=$2 WHERE id=$1',[operator,role]);
  try{assert.equal((await send(endpoint,body)).statusCode,403);}finally{await db.query("UPDATE users SET role='admin' WHERE id=$1",[operator]);}
 }
 const catalog=await get(`${endpoint}/catalog`);assert.equal(catalog.statusCode,200,catalog.body);assert.ok(catalog.json().items.some((item:any)=>item.id==='static.scan'));
 assert.ok(!catalog.json().items.some((item:any)=>item.id==='response.execute'));
});

test('invalid profiles, risk, unsupported limits and malformed authority bytes cannot persist a draft',async()=>{
 const target=await asset(),body=draft([target]);
 const beforeEvidence=(await db.query('SELECT count(*)::int AS total FROM evidence'))[0].total;
 const invalid=[
  {...body,profiles:['response.execute']},{...body,profiles:['static.scan','static.scan']},
  {...body,risk:'high'},{...body,mode:'production_remediation'},
  {...body,limits:{maxInputBytes:1024,unlimited:true}}, {...body,limits:{maxInputBytes:0}},
  {...body,limits:{maxInputBytes:16777217}}, {...body,authority:{...body.authority,evidence:{...body.authority.evidence,contentBase64:'!!!'}}},
  {...body,assetIds:[target,target]}, {...body,profiles:['lab.inventory'],risk:'low',limits:{maxInputBytes:1024,allowedPorts:[22]}},
  {...body,profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024}},
  {...body,expiresAt:new Date(clock+32*86400000).toISOString()},
  {...body,expiresAt:body.notBefore}, {...body,approved:true}
 ];
 for(const payload of invalid){const response=await send(endpoint,payload);assert.equal(response.statusCode,400,response.body);}
 assert.equal((await db.query('SELECT count(*)::int AS total FROM evidence'))[0].total,beforeEvidence);
});

test('project, asset and organization bindings are checked before creating authority evidence',async()=>{
 const own=await asset(),foreign=await asset({organization:foreignOrganization}),unlinked=await asset({projectId:null});
 const beforeEvidence=(await db.query('SELECT count(*)::int AS total FROM evidence'))[0].total;
 for(const body of [draft([own],{projectId:foreignProject}),draft([foreign]),draft([own],{projectId:otherProject}),draft([unlinked])]){
  const response=await send(endpoint,body);assert.equal(response.statusCode,404,response.body);
 }
 assert.equal((await db.query('SELECT count(*)::int AS total FROM evidence'))[0].total,beforeEvidence);
 const production=await asset({environment:'production'});
 assert.equal((await send(endpoint,draft([production]))).statusCode,400);
 const assessment=await create([production],{mode:'assessment'});assert.equal(assessment.status,'draft');
});

test('draft preserves encrypted authority evidence and does not grant execution until explicitly reviewed',async()=>{
 const target=await asset(),created=await create([target]);assert.equal(created.status,'draft');
 const current=await detail(created.id);assert.equal(current.projectId,project);assert.equal(current.responsible.name,'Synthetic Responsible');assert.equal(current.authority.reference,'SYNTHETIC-CONSENT-ONLY');
 assert.match(current.requestHash,/^[a-f0-9]{64}$/);assert.equal(current.authorityEvidenceHash,digest(authorityBytes));
 const [evidence]=await db.query('SELECT * FROM evidence WHERE id=$1',[current.authorityEvidenceId]);
 assert.ok(evidence);assert.ok(!evidence.content_cipher.includes(authorityBytes.toString()));
 assert.deepEqual(decrypt(evidence.content_cipher,key,`evidence:${organization}:${evidence.id}`),authorityBytes);
 assert.equal((await scan(target)).statusCode,403);
 assert.equal((await send(`${endpoint}/${created.id}/approve`,{requestHash:current.requestHash,attested:false})).statusCode,400);
 assert.equal((await send(`${endpoint}/${created.id}/approve`,{requestHash:'0'.repeat(64),attested:true})).statusCode,409);
 assert.equal((await send(`${endpoint}/${created.id}/approve`,{requestHash:current.requestHash,attested:true,profiles:['lab.inventory']})).statusCode,400);
 assert.equal((await scan(target)).statusCode,403);
 await approve(created.id);assert.equal((await scan(target)).statusCode,200);
 assert.equal((await send(`${endpoint}/${created.id}/approve`,{requestHash:current.requestHash,attested:true})).statusCode,409);
});

test('authority decryption failure prevents approval without creating execution scopes',async()=>{
 const target=await asset(),created=await create([target]),current=await detail(created.id);
 const response=await wrongKeyApp.inject({method:'POST',url:`${endpoint}/${created.id}/approve`,headers:headers(),payload:{requestHash:current.requestHash,attested:true}});
 assert.equal(response.statusCode,409,response.body);assert.equal(response.json().error.code,'AUTHORITY_INTEGRITY');
 assert.equal((await detail(created.id)).status,'draft');
 assert.equal((await db.query('SELECT id FROM authorizations WHERE asset_id=$1',[target])).length,0);
 assert.equal((await scan(target)).statusCode,403);
});

test('approval retires old scopes, enforces UTF-8 byte limits and cannot fall back to legacy authorization',async()=>{
 const target=await asset(),legacyId=await legacy(target),created=await create([target],{limits:{maxInputBytes:48}});
 await approve(created.id);
 const [stored]=await db.query('SELECT authorization_mode FROM assets WHERE id=$1',[target]);assert.equal(stored.authorization_mode,'managed');
 const [old]=await db.query('SELECT revoked_at FROM authorizations WHERE id=$1',[legacyId]);assert.ok(old.revoked_at);
 assert.equal((await scan(target,'#'+'a'.repeat(30)+'\n')).statusCode,200);
 assert.equal((await scan(target,'#'+'é'.repeat(30)+'\n')).statusCode,403);
 const replacementLegacy=await send('/api/authorizations',{assetId:target,operations:['scan'],authorizationRef:'SYNTHETIC-BYPASS-ATTEMPT',expiresAt:new Date(clock+3600000).toISOString()});
 assert.equal(replacementLegacy.statusCode,403);assert.equal(replacementLegacy.json().error.code,'MANAGED_AUTHORIZATION_REQUIRED');
 // A stale legacy row must not weaken the managed policy, even if restored by a database operator.
 await db.query('UPDATE authorizations SET revoked_at=NULL WHERE id=$1',[legacyId]);
 assert.equal((await scan(target,'#'+'é'.repeat(30)+'\n')).statusCode,403);
 const revoked=await send(`${endpoint}/${created.id}/revoke`,{reason:'Synthetic revocation after verification'});assert.equal(revoked.statusCode,200,revoked.body);assert.equal(revoked.json().status,'revoked');
 assert.equal((await scan(target)).statusCode,403);
 assert.equal((await send('/api/authorizations',{assetId:target,operations:['scan'],authorizationRef:'SYNTHETIC-BYPASS-AFTER-REVOCATION',expiresAt:new Date(clock+3600000).toISOString()})).statusCode,403);
 assert.equal((await send(`${endpoint}/${created.id}/revoke`,{reason:'Repeated synthetic revocation'})).statusCode,409);
});

test('shared scan/import operations cannot substitute for another approved execution profile',async()=>{
 const target=await asset(),created=await create([target],{profiles:['artifact.analyze'],limits:{maxInputBytes:4096}});await approve(created.id);
 const content=JSON.stringify({openapi:'3.1.0',info:{title:'Synthetic',version:'1'},paths:{}});
 assert.equal((await send('/api/analyses',{assetId:target,kind:'api',name:'openapi.json',mediaType:'application/json',content})).statusCode,200);
 assert.equal((await scan(target)).statusCode,403);
 assert.equal((await send('/api/lab/targets',{assetId:target,address:'127.0.0.1',name:'Synthetic loopback target'})).statusCode,403);
 assert.equal((await send('/api/remediations',{assetId:target,name:'sshd_config',content:'PermitRootLogin yes\nPasswordAuthentication yes\n'})).statusCode,403);
 assert.equal((await send('/api/evidence',{assetId:target,name:'fixture.txt',mediaType:'text/plain',contentBase64:base64})).statusCode,403);
 assert.equal((await send('/api/imports',{assetId:target,format:'zip',name:'fixture.zip',contentBase64:base64})).statusCode,403);
 assert.equal((await send('/api/forensics',{assetId:target,kind:'pcap',name:'fixture.pcap',contentBase64:base64})).statusCode,403);
});

test('managed inventory enforces approved ports before the injected Nmap adapter can run',async()=>{
 const target=await asset(),created=await create([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22]},targetManifest:manifest(target)});await approve(created.id);
 const registered=await send('/api/lab/targets',{assetId:target,address:'127.0.0.1',name:'Synthetic loopback inventory'});assert.equal(registered.statusCode,200,registered.body);
 const runsBefore=nmapRuns;
 const denied=await send('/api/lab/scans',{targetId:registered.json().id,ports:[443]});assert.equal(denied.statusCode,403,denied.body);assert.equal(nmapRuns,runsBefore);
 const allowed=await send('/api/lab/scans',{targetId:registered.json().id,ports:[22]});assert.equal(allowed.statusCode,200,allowed.body);assert.equal(nmapRuns,runsBefore+1);
});

test('signed service observations obey the managed profile rather than the shared event operation',async()=>{
 const target=await asset();await legacy(target,['event.ingest']);
 const enrollment=await send('/api/agents',{assetId:target,name:'Synthetic service fixture',expiresAt:new Date(clock+3600000).toISOString()});assert.equal(enrollment.statusCode,200,enrollment.body);
 const credential=enrollment.json().credential;
 const managed=await create([target],{profiles:['agent.observe'],limits:{maxInputBytes:2048}});await approve(managed.id);
 async function observation(){
  const raw=Buffer.from(JSON.stringify({schemaVersion:1,observationId:randomBytes(32).toString('hex'),assetId:target,observedAtEpochMs:clock,source:'sentinel-agent',type:'integrity.observation',synthetic:false,host:{os:'fixture',architecture:'fixture',agentProcessId:1,agentVersion:'0.1.0'},file:{pathId:digest('fixture-path'),pathLabel:'fixture.txt',bytes:1,sha256:digest('x')}}));
  const timestamp=String(Math.floor(clock/1000)),nonce=randomUUID(),signature=createHmac('sha256',Buffer.from(credential.secret,'hex')).update(`${timestamp}\n${nonce}\nPOST\n/agent/v1/observations\n${digest(raw)}`).digest('hex');
  return app.inject({method:'POST',url:'/agent/v1/observations',headers:{'content-type':'application/vnd.sentinel.agent+json','x-sentinel-agent':credential.agentId,'x-sentinel-timestamp':timestamp,'x-sentinel-nonce':nonce,'x-sentinel-signature':signature},payload:raw});
 }
 const accepted=await observation();assert.equal(accepted.statusCode,200,accepted.body);
 assert.equal((await send('/api/agents/baselines',{observationId:accepted.json().id})).statusCode,200);
 const capped=await create([target],{profiles:['agent.observe'],limits:{maxInputBytes:1}});await approve(capped.id);
 assert.equal((await observation()).statusCode,403);
 const replacement=await create([target],{profiles:['events.ingest'],limits:{maxInputBytes:2048}});await approve(replacement.id);
 assert.equal((await observation()).statusCode,403);
 assert.equal((await send('/api/agents/baselines',{observationId:accepted.json().id})).statusCode,403);
 assert.equal((await send('/api/agents',{assetId:target,name:'Unapproved service profile',expiresAt:new Date(clock+3600000).toISOString()})).statusCode,403);
 assert.equal((await send('/api/events',{assetId:target,schemaVersion:1,type:'auth.success',source:'Synthetic managed events',occurredAt:new Date(clock).toISOString(),data:{subject:'fixture',synthetic:true}})).statusCode,200);
});

test('expiry and project changes invalidate managed execution without reopening legacy scope creation',async()=>{
 const target=await asset(),created=await create([target],{expiresAt:new Date(clock+60000).toISOString()});await approve(created.id);
 assert.equal((await scan(target)).statusCode,200);
 await db.query('UPDATE assets SET project_id=$2 WHERE id=$1',[target,otherProject]);
 try{assert.equal((await scan(target)).statusCode,403);}finally{await db.query('UPDATE assets SET project_id=$2 WHERE id=$1',[target,project]);}
 clock+=60001;
 try{
  assert.equal((await scan(target)).statusCode,403);
  assert.equal((await send('/api/authorizations',{assetId:target,operations:['scan'],authorizationRef:'SYNTHETIC-EXPIRED-BYPASS',expiresAt:new Date(clock+60000).toISOString()})).statusCode,403);
 }finally{clock=initialTime;}
});

test('a changed risk or profile requires a fresh draft and approval before replacing an existing grant',async()=>{
 const target=await asset(),first=await create([target]);await approve(first.id);
 const next=await create([target],{profiles:['artifact.analyze'],risk:'moderate'});assert.equal(next.status,'draft');
 const original=await detail(first.id),replacement=await detail(next.id);assert.notEqual(original.requestHash,replacement.requestHash);
 assert.equal((await scan(target)).statusCode,200);
 await approve(next.id);assert.equal((await scan(target)).statusCode,403);
 assert.equal((await detail(first.id)).profiles.includes('static.scan'),true);
 const firstScopes=await db.query('SELECT revoked_at FROM authorizations WHERE mandate_id=$1',[first.id]);assert.ok(firstScopes.length);assert.ok(firstScopes.every(scope=>scope.revoked_at));
});

test('authority detail and mutations stay tenant-isolated and viewer reads do not disclose private details',async()=>{
 const target=await asset(),created=await create([target]);
 assert.equal((await get(`${endpoint}/${created.id}`,true)).statusCode,404);
 assert.equal((await send(`${endpoint}/${created.id}/approve`,{requestHash:(await detail(created.id)).requestHash,attested:true},true)).statusCode,404);
 assert.equal((await send(`${endpoint}/${created.id}/revoke`,{reason:'Foreign fixture request'},true)).statusCode,404);
 assert.deepEqual((await get(endpoint,true)).json().items,[]);
 await db.query("UPDATE users SET role='viewer' WHERE id=$1",[operator]);
 try{
  assert.equal((await get(`${endpoint}/${created.id}`)).statusCode,403);
  assert.equal((await send(`${endpoint}/${created.id}/revoke`,{reason:'Viewer request'})).statusCode,403);
  const list=await get(endpoint);assert.equal(list.statusCode,200,list.body);assert.ok(!list.body.includes('Synthetic Responsible'));assert.ok(!list.body.includes(base64));
 }finally{await db.query("UPDATE users SET role='admin' WHERE id=$1",[operator]);}
 const otherTarget=await asset();await legacy(otherTarget);assert.equal((await scan(otherTarget)).statusCode,200);
 const chain=verifyAuditChain(await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[organization]));assert.equal(chain.valid,true);
});

test('stored requests and approval history are immutable and revoked drafts cannot become approved',async()=>{
 const target=await asset(),created=await create([target]);
 for(const [column,value] of [['limits',JSON.stringify({maxInputBytes:16777216})],['profiles',JSON.stringify(['lab.inventory'])],['request_hash','f'.repeat(64)]]){
  await assert.rejects(db.query(`UPDATE authorization_mandates SET ${column}=$2 WHERE id=$1`,[created.id,value]),/immutable/i);
 }
 await approve(created.id);
 await assert.rejects(db.query("UPDATE authorization_mandates SET status='draft',approved_by=NULL,approved_at=NULL WHERE id=$1",[created.id]),/transition/i);
 const revocation=await send(`${endpoint}/${created.id}/revoke`,{reason:'Synthetic immutable history test'});assert.equal(revocation.statusCode,200,revocation.body);
 const revoked=await detail(created.id);assert.equal(revoked.revocationReason,'Synthetic immutable history test');assert.ok(revoked.approvedAt);
 await assert.rejects(db.query("UPDATE authorization_mandates SET status='approved',revoked_at=NULL,revocation_cipher=NULL WHERE id=$1",[created.id]),/transition/i);
 const unapproved=await create([await asset()]);
 assert.equal((await send(`${endpoint}/${unapproved.id}/revoke`,{reason:'Draft withdrawn by synthetic owner'})).statusCode,200);
 const response=await send(`${endpoint}/${unapproved.id}/approve`,{requestHash:unapproved.requestHash,attested:true});assert.equal(response.statusCode,409,response.body);
});

test('future grants wait for their start and an expired draft never revokes the existing active scope',async()=>{
 const target=await asset(),future=await create([target],{notBefore:new Date(clock+60000).toISOString(),expiresAt:new Date(clock+120000).toISOString()});
 await approve(future.id);assert.equal((await scan(target)).statusCode,403);
 clock+=60001;
 try{assert.equal((await scan(target)).statusCode,200);}finally{clock=initialTime;}
 const legacyTarget=await asset(),oldId=await legacy(legacyTarget),expiring=await create([legacyTarget],{expiresAt:new Date(clock+30000).toISOString()});
 clock+=30001;
 try{
  const response=await send(`${endpoint}/${expiring.id}/approve`,{requestHash:expiring.requestHash,attested:true});assert.equal(response.statusCode,409,response.body);assert.equal(response.json().error.code,'EXPIRED');
  assert.equal((await scan(legacyTarget)).statusCode,200);
  assert.equal((await db.query('SELECT revoked_at FROM authorizations WHERE id=$1',[oldId]))[0].revoked_at,null);
  assert.equal((await db.query('SELECT authorization_mode FROM assets WHERE id=$1',[legacyTarget]))[0].authorization_mode,'legacy');
 }finally{clock=initialTime;}
});

test('changed asset context rejects approval atomically without retiring its current authorization',async()=>{
 const target=await asset(),oldId=await legacy(target),created=await create([target]);
 await db.query('UPDATE assets SET project_id=$2 WHERE id=$1',[target,otherProject]);
 const response=await send(`${endpoint}/${created.id}/approve`,{requestHash:created.requestHash,attested:true});assert.equal(response.statusCode,409,response.body);assert.equal(response.json().error.code,'CONTEXT_CHANGED');
 assert.equal((await detail(created.id)).status,'draft');
 assert.equal((await db.query('SELECT revoked_at FROM authorizations WHERE id=$1',[oldId]))[0].revoked_at,null);
 assert.equal((await db.query('SELECT authorization_mode FROM assets WHERE id=$1',[target]))[0].authorization_mode,'legacy');
 assert.equal((await db.query('SELECT id FROM authorizations WHERE mandate_id=$1',[created.id])).length,0);
});

test('replacing one asset of a multi-asset authorization leaves the other active until its own grant is revoked',async()=>{
 const firstTarget=await asset(),secondTarget=await asset(),original=await create([firstTarget,secondTarget]);await approve(original.id);
 assert.equal((await scan(firstTarget)).statusCode,200);assert.equal((await scan(secondTarget)).statusCode,200);
 const replacement=await create([firstTarget],{profiles:['artifact.analyze']});await approve(replacement.id);
 assert.equal((await scan(firstTarget)).statusCode,403);assert.equal((await scan(secondTarget)).statusCode,200);
 const current=await detail(original.id);assert.equal(current.scopes.length,2);
 assert.ok(current.scopes.find((scope:any)=>scope.assetId===firstTarget).revokedAt);
 assert.equal(current.scopes.find((scope:any)=>scope.assetId===secondTarget).revokedAt,null);
 assert.equal((await send(`${endpoint}/${original.id}/revoke`,{reason:'Synthetic original engagement ended'})).statusCode,200);
 assert.equal((await scan(secondTarget)).statusCode,403);
 const stillActive=await detail(replacement.id);assert.equal(stillActive.status,'approved');assert.equal(stillActive.scopes[0].revokedAt,null);
});

test('evidence and event limits use decoded bytes and full UTF-8 payloads before persistence',async()=>{
 const evidenceTarget=await asset(),grant=await create([evidenceTarget],{profiles:['evidence.import'],limits:{maxInputBytes:8}});await approve(grant.id);
 const evidence=(bytes:Buffer)=>send('/api/evidence',{assetId:evidenceTarget,name:'fixture.txt',mediaType:'text/plain',contentBase64:bytes.toString('base64')});
 assert.equal((await evidence(Buffer.from('12345678'))).statusCode,200);
 const beforeEvidence=(await db.query('SELECT count(*)::int AS total FROM evidence WHERE asset_id=$1',[evidenceTarget]))[0].total;
 assert.equal((await evidence(Buffer.from('123456789'))).statusCode,403);
 assert.equal((await db.query('SELECT count(*)::int AS total FROM evidence WHERE asset_id=$1',[evidenceTarget]))[0].total,beforeEvidence);
 const eventTarget=await asset(),body={assetId:eventTarget,schemaVersion:1,type:'auth.success',source:'Synthetic bytes fixture',occurredAt:new Date(clock).toISOString(),data:{subject:'é'.repeat(40),synthetic:true}};
 const eventGrant=await create([eventTarget],{profiles:['events.ingest'],limits:{maxInputBytes:Buffer.byteLength(JSON.stringify(body),'utf8')-1}});await approve(eventGrant.id);
 assert.equal((await send('/api/events',body)).statusCode,403);
 assert.equal((await db.query('SELECT id FROM security_events WHERE asset_id=$1',[eventTarget])).length,0);
 const exact=await create([eventTarget],{profiles:['events.ingest'],limits:{maxInputBytes:Buffer.byteLength(JSON.stringify(body),'utf8')}});await approve(exact.id);
 assert.equal((await send('/api/events',body)).statusCode,200);
});

test('stored-copy remediation revalidates the current grant before every state transition',async()=>{
 const target=await asset(),grant=await create([target],{profiles:['lab.remediate'],limits:{maxInputBytes:1024}});await approve(grant.id);
 const proposal=await send('/api/remediations',{assetId:target,name:'sshd_config',content:'PermitRootLogin yes\nPasswordAuthentication yes\n'});assert.equal(proposal.statusCode,200,proposal.body);
 const id=proposal.json().id;assert.equal((await send(`/api/remediations/${id}/approve`)).statusCode,200);
 const restricted=await create([target],{profiles:['lab.remediate'],limits:{maxInputBytes:1}});await approve(restricted.id);
 const denied=await send(`/api/remediations/${id}/apply`);assert.equal(denied.statusCode,403,denied.body);
 let state=(await get(`/api/remediations/${id}`)).json();assert.equal(state.status,'approved');assert.equal(state.currentRevision,1);assert.equal(state.revisions.length,1);
 const replacement=await create([target],{profiles:['lab.remediate'],limits:{maxInputBytes:1024}});await approve(replacement.id);
 assert.equal((await send(`/api/remediations/${id}/apply`)).statusCode,200);
 assert.equal((await send(`/api/remediations/${id}/verify`)).statusCode,200);
 assert.equal((await send(`${endpoint}/${replacement.id}/revoke`,{reason:'Synthetic maintenance window ended'})).statusCode,200);
 assert.equal((await send(`/api/remediations/${id}/rollback`)).statusCode,403);
 state=(await get(`/api/remediations/${id}`)).json();assert.equal(state.status,'verified');assert.equal(state.currentRevision,2);assert.equal(state.revisions.length,2);
 const recovery=await create([target],{profiles:['lab.remediate'],limits:{maxInputBytes:1024}});await approve(recovery.id);
 const rollback=await send(`/api/remediations/${id}/rollback`);assert.equal(rollback.statusCode,200,rollback.body);assert.equal(rollback.json().status,'rolled_back');
});

test('managed inventory requires authorization for the full fixed execution timeout',async()=>{
 const target=await asset(),grant=await create([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22]},targetManifest:manifest(target),expiresAt:new Date(clock+30000).toISOString()});await approve(grant.id);
 const registered=await send('/api/lab/targets',{assetId:target,address:'127.0.0.1',name:'Synthetic short window'});assert.equal(registered.statusCode,200,registered.body);
 const beforeRuns=nmapRuns,response=await send('/api/lab/scans',{targetId:registered.json().id,ports:[22]});
 assert.equal(response.statusCode,403,response.body);assert.equal(response.json().error.code,'SCOPE_TOO_SHORT');assert.equal(nmapRuns,beforeRuns);
 assert.equal((await db.query('SELECT id FROM lab_scans WHERE asset_id=$1',[target])).length,0);
});

test('managed archive and forensic byte limits reject before worker dispatch or quarantine persistence',async()=>{
 for(const [profile,url,format] of [['archive.inspect','/api/imports',{format:'zip'}],['forensic.analyze','/api/forensics',{kind:'pcap'}]] as const){
  const target=await asset(),grant=await create([target],{profiles:[profile],limits:{maxInputBytes:8}});await approve(grant.id);
  const beforeEvidence=(await db.query('SELECT count(*)::int AS total FROM evidence WHERE asset_id=$1',[target]))[0].total;
  const beforeImports=importRuns,beforeForensics=forensicRuns;
  const response=await send(url,{assetId:target,name:'synthetic-input.bin',...format,contentBase64:Buffer.alloc(9,0).toString('base64')});
  assert.equal(response.statusCode,403,response.body);assert.equal(importRuns,beforeImports);assert.equal(forensicRuns,beforeForensics);
  assert.equal((await db.query('SELECT count(*)::int AS total FROM evidence WHERE asset_id=$1',[target]))[0].total,beforeEvidence);
  assert.equal((await db.query('SELECT id FROM import_runs WHERE asset_id=$1',[target])).length,0);
  assert.equal((await db.query('SELECT id FROM forensic_runs WHERE asset_id=$1',[target])).length,0);
 }
});

test('inventory drafts reject missing, unsafe, oversized and mismatched target manifests before preserving evidence',async()=>{
 const target=await asset(),foreign=await asset({organization:foreignOrganization}),outsideProject=await asset({projectId:otherProject});
 const base=draft([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22,443]}}),valid=manifest(target);
 const before=(await db.query('SELECT count(*)::int AS total FROM evidence'))[0].total;
 const missing=await send(endpoint,base);assert.equal(missing.statusCode,400,missing.body);assert.equal(missing.json().error.code,'TARGET_MANIFEST_REQUIRED');
 const invalid:any[]=[
  {...valid,version:2},{...valid,targets:[]},{...valid,extra:true},
  {...valid,targets:[...valid.targets,...valid.targets]},
  {...valid,targets:[{...valid.targets[0],assetId:foreign}]},
  {...valid,targets:[{...valid.targets[0],assetId:outsideProject}]},
  {...valid,targets:[{...valid.targets[0],ports:[80]}]},
  {...valid,targets:[{...valid.targets[0],ports:[22,22]}]},
  {...valid,targets:[{...valid.targets[0],ports:['22']}]},
  {...valid,targets:[{...valid.targets[0],ports:[]}]},
  {...valid,targets:[{...valid.targets[0],ports:Array.from({length:17},(_,i)=>i+1)}]},
  {...valid,targets:Array.from({length:101},(_,i)=>({assetId:target,address:`10.0.0.${i+1}`,ports:[22]}))},
  {...valid,exclusions:Array.from({length:101},(_,i)=>({address:`10.1.0.${i+1}`}))},
  {...valid,exclusions:[{address:'10.0.0.1'},{address:'10.0.0.1'}]},
 ];
 for(const address of ['localhost','8.8.8.8','127.00.0.1','127.0.0.1/32','127.0.0.1;id','::1','127.0.0.1\n']){
  invalid.push({...valid,targets:[{...valid.targets[0],address}]},{...valid,exclusions:[{address}]});
 }
 for(const targetManifest of invalid){const result=await send(endpoint,{...base,targetManifest});assert.equal(result.statusCode,400,result.body);}
 assert.equal((await db.query('SELECT count(*)::int AS total FROM evidence'))[0].total,before);
});

test('reviewed exact asset/address pairs and exclusions constrain registration and dispatch independently of parent ports',async()=>{
 const first=await asset(),second=await asset();
 const targetManifest={version:1,targets:[{assetId:first,address:'127.0.0.1',ports:[22]},{assetId:first,address:'10.0.0.2',ports:[22]},{assetId:second,address:'127.0.0.1',ports:[443]}],exclusions:[{address:'10.0.0.2'}]};
 const grant=await create([first,second],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22,443]},targetManifest});
 const reviewed=await detail(grant.id);assert.equal(reviewed.requestSchemaVersion,2);
 assert.deepEqual(reviewed.targetManifest.exclusions,[{address:'10.0.0.2'}]);
 const beforeRuns=nmapRuns;
 assert.equal((await send('/api/lab/targets',{assetId:first,address:'127.0.0.1',name:'Not yet approved'})).statusCode,403);
 await approve(grant.id);
 for(const address of ['10.0.0.2','127.0.0.2']){
  const denied=await send('/api/lab/targets',{assetId:first,address,name:'Outside effective consent'});assert.equal(denied.statusCode,403,denied.body);
 }
 const one=await send('/api/lab/targets',{assetId:first,address:'127.0.0.1',name:'First exact pair'});assert.equal(one.statusCode,200,one.body);
 const two=await send('/api/lab/targets',{assetId:second,address:'127.0.0.1',name:'Second exact pair'});assert.equal(two.statusCode,200,two.body);
 assert.equal((await send('/api/lab/scans',{targetId:one.json().id,ports:[443]})).statusCode,403);
 assert.equal((await send('/api/lab/scans',{targetId:two.json().id,ports:[22]})).statusCode,403);
 assert.equal(nmapRuns,beforeRuns);
 const allowed=await send('/api/lab/scans',{targetId:one.json().id,ports:[22]});assert.equal(allowed.statusCode,200,allowed.body);
 assert.equal(allowed.json().mandateId,grant.id);assert.equal(allowed.json().authorizationRequestHash,grant.requestHash);assert.equal(nmapRuns,beforeRuns+1);
 const scanId=allowed.json().id;
 await assert.rejects(db.query('UPDATE lab_scans SET authorization_request_hash=$2 WHERE id=$1',[scanId,'f'.repeat(64)]));
 await assert.rejects(db.query('UPDATE lab_scans SET mandate_id=NULL,authorization_request_hash=NULL WHERE id=$1',[scanId]));
});

test('manifest belongs to the reviewed hash and cannot be replaced or modified by approval input or database update',async()=>{
 const target=await asset(),targetManifest=manifest(target),grant=await create([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22]},targetManifest});
 const current=await detail(grant.id);
 const expected=digest(canonical({schemaVersion:2,organizationId:organization,projectId:project,assets:[{id:target,environment:'lab'}],mode:current.mode,risk:current.risk,profiles:current.profiles,limits:current.limits,notBefore:current.notBefore,expiresAt:current.expiresAt,details:{responsible:current.responsible,purpose:current.purpose,authority:current.authority},authorityEvidenceId:current.authorityEvidenceId,authorityEvidenceHash:current.authorityEvidenceHash,targetManifest:current.targetManifest}));
 assert.equal(current.requestHash,expected);
 const substituted={...current.targetManifest,targets:[{assetId:target,address:'127.0.0.2',ports:[22]}]};
 assert.equal((await send(`${endpoint}/${grant.id}/approve`,{requestHash:current.requestHash,attested:true,targetManifest:substituted})).statusCode,400);
 await assert.rejects(db.query('UPDATE authorization_mandates SET target_manifest=$2 WHERE id=$1',[grant.id,JSON.stringify(substituted)]),/immutable/i);
 await assert.rejects(db.query('UPDATE authorization_mandates SET request_schema_version=1,target_manifest=NULL WHERE id=$1',[grant.id]),/immutable/i);
 await approve(grant.id);
 await assert.rejects(db.query('UPDATE authorization_mandates SET target_manifest=$2 WHERE id=$1',[grant.id,JSON.stringify(substituted)]),/immutable/i);
 assert.deepEqual((await detail(grant.id)).targetManifest,current.targetManifest);
});

test('an excluded historical registration cannot execute after scope replacement and previous results retain their original review',async()=>{
 const target=await asset(),first=await create([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22]},targetManifest:manifest(target)});await approve(first.id);
 const registered=await send('/api/lab/targets',{assetId:target,address:'127.0.0.1',name:'Previously authorized exact target'});assert.equal(registered.statusCode,200,registered.body);
 const firstRun=await send('/api/lab/scans',{targetId:registered.json().id,ports:[22]});assert.equal(firstRun.statusCode,200,firstRun.body);
 const replacementManifest=manifest(target,'127.0.0.2');replacementManifest.targets.push({assetId:target,address:'127.0.0.1',ports:[22]});replacementManifest.exclusions.push({address:'127.0.0.1'});
 const replacement=await create([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22]},targetManifest:replacementManifest});await approve(replacement.id);
 const beforeRuns=nmapRuns,denied=await send('/api/lab/scans',{targetId:registered.json().id,ports:[22]});assert.equal(denied.statusCode,403,denied.body);assert.equal(nmapRuns,beforeRuns);
 const newTarget=await send('/api/lab/targets',{assetId:target,address:'127.0.0.2',name:'Revised exact target'});assert.equal(newTarget.statusCode,200,newTarget.body);
 const [old]=await db.query('SELECT mandate_id,authorization_request_hash FROM lab_scans WHERE id=$1',[firstRun.json().id]);assert.equal(old.mandate_id,first.id);assert.equal(old.authorization_request_hash,first.requestHash);
 assert.equal((await send(`${endpoint}/${replacement.id}/revoke`,{reason:'Synthetic revised scope revoked'})).statusCode,200);
 assert.equal((await send('/api/lab/scans',{targetId:newTarget.json().id,ports:[22]})).statusCode,403);assert.equal(nmapRuns,beforeRuns);
});

test('manifest dispatch verifies current project and organization and a future or expired window never runs the adapter',async()=>{
 const target=await asset(),grant=await create([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22]},targetManifest:manifest(target),expiresAt:new Date(clock+60000).toISOString()});await approve(grant.id);
 const registered=await send('/api/lab/targets',{assetId:target,address:'127.0.0.1',name:'Context-bound target'});assert.equal(registered.statusCode,200,registered.body);
 const input={targetId:registered.json().id,ports:[22]},beforeRuns=nmapRuns;
 assert.equal((await send('/api/lab/scans',input,true)).statusCode,404);
 await db.query('UPDATE assets SET project_id=$2 WHERE id=$1',[target,otherProject]);
 try{assert.equal((await send('/api/lab/scans',input)).statusCode,403);}finally{await db.query('UPDATE assets SET project_id=$2 WHERE id=$1',[target,project]);}
 clock+=60001;
 try{assert.equal((await send('/api/lab/scans',input)).statusCode,403);}finally{clock=initialTime;}
 const future=await create([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22]},targetManifest:manifest(target),notBefore:new Date(clock+60000).toISOString(),expiresAt:new Date(clock+120000).toISOString()});await approve(future.id);
 assert.equal((await send('/api/lab/scans',input)).statusCode,403);assert.equal(nmapRuns,beforeRuns);
});

test('legacy scopes and valid historical schema-one inventory grants do not imply approval for any network address',async()=>{
 const target=await asset();await legacy(target,['scan']);
 const registeredId=randomUUID();
 await db.query('INSERT INTO lab_targets(id,organization_id,asset_id,address,name,created_by) VALUES($1,$2,$3,$4,$5,$6)',[registeredId,organization,target,'127.0.0.1','Historical target without manifest',operator]);
 const beforeRuns=nmapRuns;
 assert.equal((await scan(target)).statusCode,200);
 assert.equal((await send('/api/lab/targets',{assetId:target,address:'127.0.0.2',name:'Legacy does not approve addresses'})).statusCode,403);
 assert.equal((await send('/api/lab/scans',{targetId:registeredId,ports:[22]})).statusCode,403);
 // Preserve a valid V1 approval fixture in the pre-manifest format, without rewriting any delivered migration.
 const id=randomUUID(),evidenceId=randomUUID(),proofHash=digest(authorityBytes),body=draft([target]);
 const privateDetails={responsible:body.responsible,purpose:body.purpose,authority:{channel:body.authority.channel,reference:body.authority.reference}},serialized=canonical(privateDetails),profiles=['lab.inventory'],limits={maxInputBytes:1024,allowedPorts:[22]};
 const requestHash=digest(canonical({schemaVersion:1,organizationId:organization,projectId:project,assets:[{id:target,environment:'lab'}],mode:'lab',risk:'moderate',profiles,limits,notBefore:body.notBefore,expiresAt:body.expiresAt,details:privateDetails,authorityEvidenceId:evidenceId,authorityEvidenceHash:proofHash}));
 await db.transaction(async tx=>{
  await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[evidenceId,organization,target,'historical-authority.txt','text/plain',proofHash,authorityBytes.length,encrypt(authorityBytes,key,`evidence:${organization}:${evidenceId}`),operator,`authority:${id}`]);
  await tx.query("INSERT INTO authorization_mandates(id,organization_id,project_id,mode,risk,profiles,limits,not_before,expires_at,details_cipher,details_hash,request_hash,authority_evidence_id,authority_evidence_hash,created_by,status,approved_by,approved_at) VALUES($1,$2,$3,'lab','moderate',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'approved',$13,$14)",[id,organization,project,JSON.stringify(profiles),JSON.stringify(limits),body.notBefore,body.expiresAt,encrypt(serialized,key,`authorization:${organization}:${id}`),digest(serialized),requestHash,evidenceId,proofHash,operator,new Date(clock)]);
  await tx.query("INSERT INTO authorization_mandate_assets(mandate_id,organization_id,asset_id,environment) VALUES($1,$2,$3,'lab')",[id,organization,target]);
  await tx.query("UPDATE assets SET authorization_mode='managed' WHERE id=$1",[target]);
  await tx.query("INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by,mandate_id) VALUES($1,$2,$3,'lab',$4,$5,$6,$7,$8,$9)",[randomUUID(),organization,target,JSON.stringify(['scan']),`Historical:${id}`,body.notBefore,body.expiresAt,operator,id]);
 });
 const old=await detail(id);assert.equal(old.requestSchemaVersion,1);assert.equal(old.targetManifest,null);assert.equal(old.requestHash,requestHash);
 assert.equal((await send('/api/lab/targets',{assetId:target,address:'127.0.0.2',name:'Old managed grant without target review'})).statusCode,403);
 assert.equal((await send('/api/lab/scans',{targetId:registeredId,ports:[22]})).statusCode,403);assert.equal(nmapRuns,beforeRuns);
 assert.equal(verifyAuditChain(await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[organization])).valid,true);
});
