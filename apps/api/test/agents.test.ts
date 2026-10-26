import {before,after,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHmac} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {encrypt,digest,hashPassword,generateEnrollment,totp} from '../src/security.ts';
import {evaluatePolicy} from '@sentinel/core';

let db:Database,appDb:Database,app:Awaited<ReturnType<typeof buildApp>>,clock=Date.now(),assetId:string,scopeId:string,agentId:string,secret:string;
const key=randomBytes(32),org=randomUUID(),user=randomUUID(),password=randomUUID(),enrollment=generateEnrollment('agent-tests@sentinel.test');
let headers:Record<string,string>={host:'127.0.0.1:4310',origin:'http://127.0.0.1:4310'};
const post=(url:string,payload:any)=>app.inject({method:'POST',url,headers,payload});
function payload(hash='a'.repeat(64)){return {schemaVersion:1,observationId:digest(randomUUID()),assetId,observedAtEpochMs:clock,source:'sentinel-agent',type:'integrity.observation',synthetic:false,host:{os:'linux',architecture:'x86_64',agentProcessId:42,agentVersion:'0.2.0'},file:{pathId:digest('/fixture/file'),pathLabel:'config',bytes:123,sha256:hash}};}
function signed(b:any,nonce=randomUUID(),timestamp=String(Math.floor(clock/1000))) {const raw=JSON.stringify(b);return {method:'POST' as const,url:'/agent/v1/observations',payload:raw,headers:{'content-type':'application/vnd.sentinel.agent+json','x-sentinel-agent':agentId,'x-sentinel-timestamp':timestamp,'x-sentinel-nonce':nonce,'x-sentinel-signature':createHmac('sha256',Buffer.from(secret,'hex')).update(`${timestamp}\n${nonce}\nPOST\n/agent/v1/observations\n${digest(raw)}`).digest('hex')}};}
before(async()=>{
 db=await openDatabase({url:process.env.SENTINEL_AGENT_TEST_DATABASE_URL});await migrate(db);
 await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'Agent tests']);
 await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[user,org,'agent-tests@sentinel.test','admin',await hashPassword(password),encrypt(enrollment.secret,key,`totp:${user}`)]);
 await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[user,digest(randomUUID())]);
 await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[user,org]);
 if(process.env.SENTINEL_AGENT_TEST_RUNTIME_URL){for(const sql of (await readFile(new URL('../../../ops/runtime-grants.sql',import.meta.url),'utf8')).split(';').filter(s=>s.trim()))await db.query(sql);appDb=await openDatabase({url:process.env.SENTINEL_AGENT_TEST_RUNTIME_URL});}else appDb=db;
 app=await buildApp({db:appDb,masterKey:key,now:()=>clock});
 const login=await post('/api/auth/login',{email:'agent-tests@sentinel.test',password,otp:totp(enrollment.secret).generate({timestamp:clock})});assert.equal(login.statusCode,200,login.body);headers={...headers,cookie:String(login.headers['set-cookie']).split(';')[0],'x-csrf-token':login.json().csrfToken};
 const asset=await post('/api/assets',{name:'Controlled fixture',kind:'server',environment:'lab',criticality:3});assetId=asset.json().id;
 const scope=await post('/api/authorizations',{assetId,operations:['event.ingest'],authorizationRef:'Controlled agent integration fixture',expiresAt:new Date(clock+86400000).toISOString()});scopeId=scope.json().id;
});
after(async()=>{await app?.close();if(appDb&&appDb!==db)await appDb.close();await db?.close();});
test('agent identity cannot read operator data or execute response',()=>{for(const operation of ['assets.read','scan','response.execute'] as const)assert.equal(evaluatePolicy({identity:{id:'agent',organizationId:'org',role:'agent'},operation,resource:{organizationId:'org'}}).allowed,false);});
test('enrollment returns a secret once and list never exposes encrypted credentials',async()=>{
 const r=await post('/api/agents',{assetId,name:'Linux sensor',expiresAt:new Date(clock+3600000).toISOString()});assert.equal(r.statusCode,200,r.body);agentId=r.json().id;secret=r.json().credential.secret;assert.match(secret,/^[a-f0-9]{64}$/);
 const list=await app.inject({url:'/api/agents',headers});assert.equal(list.statusCode,200);assert.ok(!list.body.includes(secret));assert.ok(!list.body.includes('secret_cipher'));assert.equal(list.json().items[0].status,'awaiting');
});
test('signed ingestion rejects tampering, stale timestamp, wrong asset, invalid schema and cookie alone',async()=>{
 const b=payload(),req=signed(b);req.payload=req.payload.replace('config','tampered');assert.equal((await app.inject(req)).statusCode,401);
 assert.equal((await app.inject(signed(b,randomUUID(),String(Math.floor(clock/1000)-301)))).statusCode,401);
 assert.equal((await app.inject(signed({...b,assetId:randomUUID()}))).statusCode,403);
 assert.equal((await app.inject(signed({...b,synthetic:true}))).statusCode,400);
 assert.equal((await app.inject(signed({...b,file:{...b.file,pathLabel:'../secret'}}))).statusCode,400);
 assert.equal((await app.inject({method:'POST',url:'/agent/v1/observations',headers,payload:b})).statusCode,401);
 assert.equal((await app.inject(signed({...b,command:'execute'}))).statusCode,400);
});
test('explicit baseline, replay protection, idempotence, evidence, drift incident suppression',async()=>{
 const b=payload(),req=signed(b),first=await app.inject(req);assert.equal(first.statusCode,200,first.body);assert.equal(first.json().result,'unbaselined');
 assert.equal((await app.inject(req)).statusCode,409);
 const repeat=await app.inject(signed(b));assert.equal(repeat.statusCode,200,repeat.body);assert.equal(repeat.json().duplicate,true);
 assert.equal((await app.inject(signed({...b,file:{...b.file,bytes:12}}))).statusCode,409);
 const approved=await post('/api/agents/baselines',{observationId:first.json().id});assert.equal(approved.statusCode,200,approved.body);
 const same=await app.inject(signed(payload()));assert.equal(same.json().result,'unchanged',same.body);
 const change=await app.inject(signed(payload('b'.repeat(64))));assert.equal(change.statusCode,200,change.body);assert.equal(change.json().result,'changed');assert.ok(change.json().incidentId);
 const again=await app.inject(signed(payload('b'.repeat(64))));assert.equal(again.json().incidentId,change.json().incidentId);
 const alerts=await db.query("SELECT * FROM alerts WHERE rule_id='FIM-CHANGE'");assert.equal(alerts.length,1);assert.equal(alerts[0].synthetic,false);
 const observations=await app.inject({url:'/api/agents/observations',headers});const evidenceId=observations.json().items[0].evidenceId;const evidence=await app.inject({url:`/api/evidence/${evidenceId}`,headers});assert.equal(evidence.json().integrityVerified,true);
 assert.equal((await app.inject({url:'/api/audit/verify',headers})).json().valid,true);
});
test('artifact analysis requires both scopes, preserves evidence and exports a verified report',async()=>{
 const input={assetId,kind:'dependency',name:'package-lock.json',mediaType:'application/json',content:JSON.stringify({name:'fixture',lockfileVersion:3,packages:{'':{name:'fixture',version:'1.0.0'},'node_modules/example':{version:'1.2.3',resolved:'http://example.invalid/package.tgz'}}})};
 assert.equal((await post('/api/analyses',input)).statusCode,403);
 assert.equal((await post('/api/authorizations',{assetId,operations:['scan','evidence.import'],authorizationRef:'Artifact fixture only',expiresAt:new Date(clock+86400000).toISOString()})).statusCode,200);
 const r=await post('/api/analyses',input);assert.equal(r.statusCode,200,r.body);assert.ok(r.json().report.findings.length>0);
 const report=await app.inject({url:`/api/reports/analysis/${r.json().id}`,headers});assert.equal(report.statusCode,200,report.body);assert.equal(report.json().evidence[0].integrityVerified,true);assert.equal(report.json().organization.id,org);
 assert.equal((await post('/api/analyses',{...input,content:'{broken'})).statusCode,400);
 const [incident]=await db.query("SELECT * FROM incidents WHERE organization_id=$1 LIMIT 1",[org]);
 assert.equal((await post(`/api/incidents/${incident.id}/notes`,{body:'Synthetic drift investigation.'})).statusCode,200);
 assert.equal((await post(`/api/incidents/${incident.id}/evidence`,{evidenceId:r.json().evidenceId})).statusCode,200);
 const ir=await app.inject({url:`/api/reports/incident/${incident.id}`,headers});assert.equal(ir.statusCode,200,ir.body);assert.equal(ir.json().notes[0].body,'Synthetic drift investigation.');assert.equal(ir.json().evidence[0].integrityVerified,true);
 const other=(await post('/api/organizations',{name:'Isolated fixture'})).json();const previous=headers['x-csrf-token'];
 const sw=await post('/api/context',{organizationId:other.id});headers['x-csrf-token']=sw.json().csrfToken;
 assert.equal((await app.inject({url:`/api/analyses/${r.json().id}`,headers})).statusCode,404);
 assert.equal((await app.inject({url:`/api/reports/incident/${incident.id}`,headers})).statusCode,404);
 assert.equal((await app.inject({url:'/api/agents/observations',headers})).json().items.length,0);
 const back=await post('/api/context',{organizationId:org});headers['x-csrf-token']=back.json().csrfToken;assert.notEqual(headers['x-csrf-token'],previous);
});
test('scope revocation immediately prevents ingestion; revoked credential cannot send',async()=>{
 assert.equal((await post(`/api/authorizations/${scopeId}/revoke`,{})).statusCode,200);
 assert.equal((await app.inject(signed(payload()))).statusCode,403);
 assert.equal((await post(`/api/agents/${agentId}/revoke`,{})).statusCode,200);
 assert.equal((await app.inject(signed(payload()))).statusCode,401);
});
