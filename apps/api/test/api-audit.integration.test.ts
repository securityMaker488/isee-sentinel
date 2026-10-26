import {before,after,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {analyzeArtifact,ArtifactAnalysisError} from '@sentinel/core';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {digest,encrypt,decrypt,randomToken} from '../src/security.ts';
import {verifyAuditChain} from '../src/audit.ts';

let db:Database,app:Awaited<ReturnType<typeof buildApp>>,analysisId:string,evidenceId:string;
const clock=Date.now(),key=randomBytes(32),org=randomUUID(),otherOrg=randomUUID(),actor=randomUUID(),asset=randomUUID(),scope=randomUUID();
const session=randomToken(),otherSession=randomToken(),csrf=randomToken(),origin='http://127.0.0.1:4310';
const headers=(foreign=false)=>({host:'127.0.0.1:4310',origin,cookie:`sentinel_session=${foreign?otherSession:session}`,'x-csrf-token':csrf});
const spec={
  openapi:'3.1.1',info:{title:'Private API fixture',version:'1.0'},
  servers:[{url:'http://api.example/?token=PRIVATE_QUERY'}],
  components:{securitySchemes:{key:{type:'apiKey',in:'query',name:'PRIVATE_KEY'}}},security:[{key:[]}],
  paths:{'/PRIVATE_PATH':{post:{security:[],responses:{'200':{description:'Result'}},
    requestBody:{content:{'application/json':{schema:{type:'string',example:'PRIVATE_EXAMPLE'}}}}
  }}}
};
const content=JSON.stringify(spec),payload=()=>({assetId:asset,kind:'api',name:'openapi.json',mediaType:'application/json',content});
const post=(body:any=payload(),foreign=false)=>app.inject({method:'POST',url:'/api/analyses',headers:headers(foreign),payload:body});

before(async()=>{
  db=await openDatabase();await migrate(db);
  for(const id of [org,otherOrg])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,'OpenAPI boundary fixture']);
  await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[actor,org,'openapi-boundary@sentinel.test','admin','not-used',encrypt('not-used',key,`totp:${actor}`)]);
  await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[actor,digest(randomToken())]);
  for(const id of [org,otherOrg])await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[actor,id]);
  for(const [token,id] of [[session,org],[otherSession,otherOrg]])await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),actor,csrf,new Date(clock+3600000),id]);
  await db.query("INSERT INTO assets(id,organization_id,name,kind,environment,criticality) VALUES($1,$2,'API fixture','server','lab',3)",[asset,org]);
  await db.query("INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by) VALUES($1,$2,$3,'lab',$4,'Offline OpenAPI fixture',$5,$6,$7)",[scope,org,asset,JSON.stringify(['scan','evidence.import']),new Date(clock-60000),new Date(clock+3600000),actor]);
  app=await buildApp({db,masterKey:key,now:()=>clock});
});
after(async()=>{await app?.close();await db?.close();});

test('artifact dispatcher routes kind api and provides reproducible completed report metadata',()=>{
  const report=analyzeArtifact({kind:'api',name:'openapi.json',mediaType:'application/json',content});
  assert.equal(report.kind,'api');assert.equal(report.format,'openapi-3.1.1');assert.equal(report.input.sha256,digest(content));
  assert.ok(report.summary.includes('openapi-3.1.1'));assert.ok(report.findings.some(item=>item.ruleId==='API-ANONYMOUS-001'));
  assert.deepEqual(report,analyzeArtifact({kind:'api',name:'openapi.json',mediaType:'application/json',content}));
  assert.throws(()=>analyzeArtifact({kind:'api',name:'openapi.json',mediaType:'application/json',content:'{"openapi":"3.1.1","openapi":"3.1.1"}'}),ArtifactAnalysisError);
});

test('OpenAPI API persists original bytes encrypted and exports the redacted analysis with verified evidence',async()=>{
  const created=await post();assert.equal(created.statusCode,200,created.body);
  const result=created.json();analysisId=result.id;evidenceId=result.evidenceId;
  assert.equal(result.kind,'api');assert.equal(result.report.kind,'api');assert.equal(result.report.format,'openapi-3.1.1');assert.equal(result.report.input.sha256,digest(content));
  for(const marker of ['PRIVATE_QUERY','PRIVATE_KEY','PRIVATE_PATH','PRIVATE_EXAMPLE'])assert.ok(!created.body.includes(marker));
  const [evidence]=await db.query('SELECT * FROM evidence WHERE id=$1',[evidenceId]);
  assert.equal(evidence.sha256,digest(content));assert.equal(evidence.size_bytes,Buffer.byteLength(content));assert.ok(!evidence.content_cipher.includes('PRIVATE_QUERY'));
  assert.equal(decrypt(evidence.content_cipher,key,`evidence:${org}:${evidenceId}`).toString(),content);
  const detail=await app.inject({url:`/api/analyses/${analysisId}`,headers:headers()});assert.equal(detail.statusCode,200);assert.deepEqual(detail.json().report,result.report);
  const history=await app.inject({url:'/api/analyses',headers:headers()});assert.equal(history.json().items[0].kind,'api');assert.equal(history.json().items[0].findingCount,result.report.findings.length);
  const exported=await app.inject({url:`/api/reports/analysis/${analysisId}`,headers:headers()});assert.equal(exported.statusCode,200,exported.body);
  assert.equal(exported.json().evidence[0].id,evidenceId);assert.equal(exported.json().evidence[0].integrityVerified,true);assert.equal(exported.json().executiveSummary,result.report.summary);
  for(const marker of ['PRIVATE_QUERY','PRIVATE_KEY','PRIVATE_PATH','PRIVATE_EXAMPLE'])assert.ok(!exported.body.includes(marker));
});

test('analysis and report reads remain isolated to the active organization',async()=>{
  assert.equal((await post(payload(),true)).statusCode,404);
  assert.deepEqual((await app.inject({url:'/api/analyses',headers:headers(true)})).json().items,[]);
  assert.equal((await app.inject({url:`/api/analyses/${analysisId}`,headers:headers(true)})).statusCode,404);
  assert.equal((await app.inject({url:`/api/reports/analysis/${analysisId}`,headers:headers(true)})).statusCode,404);
});

test('malformed OpenAPI, unknown API fields and UTF-8 byte overflow fail without inserting evidence',async()=>{
  const before=await db.query('SELECT count(*)::int AS total FROM evidence WHERE organization_id=$1',[org]);
  for(const invalid of ['{"openapi":"3.2.1"}',JSON.stringify({...spec,security:'invalid'}),JSON.stringify({...spec,'x-large':'é'.repeat(550000)})]){
    const response=await post({...payload(),content:invalid});assert.equal(response.statusCode,400,response.body);assert.equal(response.json().error.code,'INVALID_ARTIFACT');
  }
  const extra=await post({...payload(),fetchUrl:'https://do-not-fetch.example/'});assert.equal(extra.statusCode,400);assert.equal(extra.json().error.code,'INVALID_INPUT');
  const after=await db.query('SELECT count(*)::int AS total FROM evidence WHERE organization_id=$1',[org]);assert.deepEqual(after,before);
});

test('fresh scan and evidence scopes are required, revoked or short operation subsets cannot import',async()=>{
  await db.query('UPDATE authorizations SET revoked_at=$2 WHERE id=$1',[scope,new Date(clock)]);
  assert.equal((await post()).statusCode,403);
  await db.query('UPDATE authorizations SET revoked_at=NULL,operations=$2 WHERE id=$1',[scope,JSON.stringify(['scan'])]);
  assert.equal((await post()).statusCode,403);
  await db.query('UPDATE authorizations SET operations=$2,expires_at=$3 WHERE id=$1',[scope,JSON.stringify(['scan','evidence.import']),new Date(clock-1)]);
  assert.equal((await post()).statusCode,403);
  const [count]=await db.query('SELECT count(*)::int AS total FROM artifact_analyses WHERE organization_id=$1',[org]);assert.equal(count.total,1);
  const audit=await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[org]);assert.equal(verifyAuditChain(audit).valid,true);
  assert.ok(audit.some(event=>event.action==='analysis.completed'));assert.ok(audit.some(event=>event.action==='report.exported'));assert.ok(audit.some(event=>event.action==='policy.denied'));
});
