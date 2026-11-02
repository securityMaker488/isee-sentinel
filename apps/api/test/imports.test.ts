import {before,after,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFile,access,mkdtemp,writeFile,unlink,rmdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {runImportWorker,type ImportRunner} from '../src/imports.ts';
import {runSupervisedImport} from '../src/execution.ts';
import {digest,encrypt,randomToken} from '../src/security.ts';
let db:Database,runtime:Database,app:Awaited<ReturnType<typeof buildApp>>,seen='';
const key=randomBytes(32),org=randomUUID(),other=randomUUID(),user=randomUUID(),asset=randomUUID(),project=randomUUID(),token=randomToken(),csrf=randomToken();
let clock=Date.now();
const headers={host:'127.0.0.1:4310',origin:'http://127.0.0.1:4310',cookie:`sentinel_session=${token}`,'x-csrf-token':csrf};
const pythonPath=process.env.SENTINEL_TEST_PYTHON_PATH??(process.platform==='win32'?'C:\\Trusted\\python.exe':'/trusted/python3');
// Empty ZIP for API/worker transport; malicious and populated archives are tested in the worker suite.
const bytes=Buffer.from('504b0506000000000000000000000000000000000000','hex');
const payload={assetId:asset,format:'zip',name:'synthetic.zip',contentBase64:bytes.toString('base64')};
const normal:ImportRunner=async o=>{seen=o.file;const b=await readFile(o.file);return Buffer.from(JSON.stringify({schemaVersion:'1.0',engine:'Sentinel Import Inspector',quarantineOnly:true,input:{name:'temporary',format:o.format,sha256:digest(b),bytes:b.length,unchanged:true},entries:[],technologies:[],limitations:['Injected transport fixture']}));};
let behavior=normal;const send=(body:unknown=payload)=>app.inject({method:'POST',url:'/api/imports',headers,payload:body as any});
before(async()=>{
 db=await openDatabase({url:process.env.SENTINEL_IMPORT_TEST_DATABASE_URL});await migrate(db);
 for(const id of [org,other])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,'Synthetic ZIP fixture']);
 await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[user,org,'import@sentinel.test','admin','unused',encrypt('unused',key,`totp:${user}`)]);
 await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[user,digest(randomToken())]);
 for(const id of [org,other])await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[user,id]);
 await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),user,csrf,new Date(clock+3600000),org]);
 await db.query('INSERT INTO projects(id,organization_id,name,contract_ref) VALUES($1,$2,$3,$4)',[project,org,'ZIP project','TEST-ONLY']);
 await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality,project_id) VALUES($1,$2,$3,$4,$5,3,$6)',[asset,org,'Synthetic ZIP','application','lab',project]);
 await db.query('INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[randomUUID(),org,asset,'lab',JSON.stringify(['scan','evidence.import']),'Import fixture',new Date(clock-1000),new Date(clock+3600000),user]);
 if(process.env.SENTINEL_IMPORT_TEST_RUNTIME_URL){for(const sql of (await readFile(new URL('../../../ops/runtime-grants.sql',import.meta.url),'utf8')).split(';').filter(s=>s.trim()))await db.query(sql);runtime=await openDatabase({url:process.env.SENTINEL_IMPORT_TEST_RUNTIME_URL});}else runtime=db;
 app=await buildApp({db:runtime,masterKey:key,pythonPath,importRunner:o=>behavior(o),now:()=>clock});
});
after(async()=>{await app?.close();if(runtime&&runtime!==db)await runtime.close();await db?.close();});
test('ZIP import requires authentication, strict parameters, canonical bytes and two current scopes',async()=>{
 assert.equal((await app.inject({method:'POST',url:'/api/imports',headers:{host:headers.host,origin:headers.origin},payload})).statusCode,401);
 for(const body of [{...payload,url:'http://localhost'}, {...payload,format:'rar'}, {...payload,contentBase64:'!!!'}])assert.equal((await send(body)).statusCode,400);
 assert.equal((await send({...payload,assetId:randomUUID()})).statusCode,404);
 await db.query("UPDATE authorizations SET operations='[\"evidence.import\"]' WHERE asset_id=$1",[asset]);assert.equal((await send()).statusCode,403);
 await db.query("UPDATE authorizations SET operations='[\"scan\",\"evidence.import\"]' WHERE asset_id=$1",[asset]);
 assert.equal((await db.query('SELECT * FROM import_runs')).length,0);
});
test('ZIP quarantine preserves original, inherits project, isolates tenant and removes temporary copy',async()=>{
 const r=await send();assert.equal(r.statusCode,200,r.body);assert.equal(r.json().projectId,project);assert.equal(r.json().quarantineOnly,true);assert.equal(r.json().report.input.sha256,digest(bytes));assert.equal(r.json().report.input.name,payload.name);assert.ok(!r.body.includes(seen));await assert.rejects(access(seen));
 const evidence=await app.inject({url:`/api/evidence/${r.json().evidenceId}`,headers});assert.equal(evidence.json().integrityVerified,true);
 await db.query('UPDATE sessions SET active_organization_id=$2 WHERE token_hash=$1',[digest(token),other]);assert.equal((await app.inject({url:`/api/imports/${r.json().id}`,headers})).statusCode,404);assert.deepEqual((await app.inject({url:'/api/imports',headers})).json().items,[]);
 await db.query('UPDATE sessions SET active_organization_id=$2 WHERE token_hash=$1',[digest(token),org]);
 assert.equal((await app.inject({url:`/api/imports/${r.json().id}`,headers})).json().quarantineOnly,true);
});
test('untrusted worker output fails closed with evidence, error and lock recovery',async()=>{
 behavior=async o=>{const report=JSON.parse((await normal(o)).toString());report.input.sha256='0'.repeat(64);return Buffer.from(JSON.stringify(report));};
 const r=await send();assert.equal(r.statusCode,409,r.body);assert.equal(r.json().error.code,'IMPORT_INTEGRITY');await assert.rejects(access(seen));assert.equal((await db.query('SELECT * FROM import_execution_lock')).length,0);
 assert.equal((await db.query("SELECT r.evidence_id FROM import_runs r JOIN jobs j ON j.id=r.id WHERE j.status='failed' AND r.error_code='IMPORT_INTEGRITY'")).length,1);behavior=normal;assert.equal((await send()).statusCode,200);
});
test('ZIP inspections are serialized and interrupted completions cannot replace persisted state',async()=>{
 let release!:()=>void,entered!:()=>void;const gate=new Promise<void>(r=>release=r),started=new Promise<void>(r=>entered=r);behavior=async o=>{entered();await gate;return normal(o);};const first=send();await started;
 try{assert.equal((await send()).statusCode,409);await db.query("UPDATE jobs SET status='interrupted',completed_at=now() WHERE kind='import.zip' AND status='running'");}finally{release();}
 assert.equal((await first).statusCode,409);behavior=normal;assert.equal((await send()).statusCode,200);
});
test('real isolated Python rejects a malformed ZIP while retaining encrypted original',{skip:!process.env.SENTINEL_TEST_PYTHON_PATH},async()=>{
 behavior=runImportWorker;try{const r=await send({...payload,contentBase64:Buffer.from('Not a ZIP archive').toString('base64')});assert.equal(r.statusCode,422,r.body);assert.equal(r.json().error.code,'IMPORT_REJECTED');assert.equal((await db.query("SELECT * FROM import_runs WHERE error_code='IMPORT_REJECTED'")).length,1);}finally{behavior=normal;}
});
test('real isolated Python inspects a synthetic source project and binds its manifest to preserved bytes',{skip:!process.env.SENTINEL_TEST_PYTHON_PATH},async()=>{
 const source=(await readFile(new URL('../../../fixtures/lab/import-project.zip.base64',import.meta.url),'utf8')).trim();
 behavior=runImportWorker;try{const r=await send({...payload,contentBase64:source});assert.equal(r.statusCode,200,r.body);assert.equal(r.json().report.input.sha256,digest(Buffer.from(source,'base64')));assert.equal(r.json().report.entries.length,3);assert.ok(r.json().report.technologies.some((t:any)=>t.name==='react'));assert.ok(r.json().report.suggestedAnalyses.includes('api'));}finally{behavior=normal;}
});

test('real TAR and TAR.GZ inspections bind format, original, plan, evidence and job under restricted runtime',{skip:!process.env.SENTINEL_TEST_PYTHON_PATH},async()=>{
 const status=(await app.inject({url:'/api/imports/status',headers})).json();assert.deepEqual(status.formats,['zip','tar','tar.gz']);
 for(const format of ['tar','tar.gz']){
  const fixture=await reviewedPlan(),source=(await readFile(new URL(`../../../fixtures/lab/import-project.${format}.base64`,import.meta.url),'utf8')).trim();
  behavior=runImportWorker;
  try{
   const response=await send({...fixture.body,format,name:`synthetic.${format}`,contentBase64:source});assert.equal(response.statusCode,200,response.body);const result=response.json();
   assert.equal(result.format,format);assert.equal(result.report.input.format,format);assert.equal(result.report.input.sha256,digest(Buffer.from(source,'base64')));assert.equal(result.report.entries.length,3);assert.deepEqual(result.assessment,fixture.assessment);
   const read=(await app.inject({url:`/api/imports/${result.id}`,headers})).json();assert.equal(read.format,format);assert.equal(read.authorizationRequestHash,fixture.grant.requestHash);
   const plan=(await app.inject({url:`/api/assessment-plans/${fixture.plan.id}`,headers})).json();assert.equal(plan.results[0].kind,`import.${format}`);assert.deepEqual(plan.results[0].evidenceIds,[result.evidenceId]);
   const evidence=(await app.inject({url:`/api/evidence/${result.evidenceId}`,headers})).json();assert.equal(evidence.integrityVerified,true);
   const mismatch=await send({...fixture.body,format:'zip',name:'misleading.zip',contentBase64:source});assert.equal(mismatch.statusCode,422,mismatch.body);
   const [failed]=await db.query("SELECT r.*,j.status FROM import_runs r JOIN jobs j ON j.id=r.id WHERE r.asset_id=$1 AND r.error_code='IMPORT_REJECTED'",[fixture.body.assetId]);assert.equal(failed.status,'failed');assert.equal(failed.report,null);
  }finally{behavior=normal;}
 }
});

test('a worker format mismatch cannot be accepted as the requested inspection',async()=>{
 behavior=async options=>{const report=JSON.parse((await normal(options)).toString());report.input.format='tar';return Buffer.from(JSON.stringify(report));};
 try{const response=await send();assert.equal(response.statusCode,409,response.body);assert.equal(response.json().error.code,'IMPORT_INTEGRITY');}finally{behavior=normal;}
 assert.equal((await db.query('SELECT * FROM import_execution_lock')).length,0);await assert.rejects(access(seen));
});

const post=(url:string,body:unknown)=>app.inject({method:'POST',url,headers,payload:body as any});
async function reviewedPlan(maxInputBytes=1048576){
 const target=randomUUID();await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality,project_id) VALUES($1,$2,$3,$4,$5,2,$6)',[target,org,'Synthetic planned import','repository','lab',project]);
 const mandate=await post('/api/assessment-authorizations',{projectId:project,assetIds:[target],mode:'lab',risk:'low',profiles:['archive.inspect'],limits:{maxInputBytes},notBefore:new Date(clock-1000).toISOString(),expiresAt:new Date(clock+60000).toISOString(),responsible:{name:'Synthetic fixture',role:'Owner',organization:'Synthetic organization'},purpose:'Offline inspection of supplied fixture only',authority:{channel:'internal',reference:'SYNTHETIC-ONLY',evidence:{name:'consent.txt',mediaType:'text/plain',contentBase64:Buffer.from('Synthetic authorized fixture').toString('base64')}}});
 assert.equal(mandate.statusCode,200,mandate.body);const grant=mandate.json();
 assert.equal((await post(`/api/assessment-authorizations/${grant.id}/approve`,{requestHash:grant.requestHash,attested:true})).statusCode,200);
 const created=await post('/api/assessment-plans',{name:'Synthetic import plan',projectId:project,mandateId:grant.id,authorizationRequestHash:grant.requestHash,objective:'Inspect immutable archive evidence',steps:[{id:'archive',name:'Inspect archive',assetId:target,profile:'archive.inspect'}]});assert.equal(created.statusCode,200,created.body);
 const plan=created.json(),revision=plan.revisions[0],assessment={planId:plan.id,revisionId:revision.id,revisionHash:revision.hash,stepId:'archive'};
 return {grant,plan,assessment,body:{...payload,assetId:target,assessment}};
}
test('planned inspection binds the original and exact reviewed authorization to its result',async()=>{
 const fixture=await reviewedPlan();const response=await send(fixture.body);assert.equal(response.statusCode,200,response.body);const result=response.json();
 const read=(await app.inject({url:`/api/imports/${result.id}`,headers})).json();assert.deepEqual(read.assessment,fixture.assessment);assert.equal(read.mandateId,fixture.grant.id);assert.equal(read.authorizationRequestHash,fixture.grant.requestHash);
 const plan=(await app.inject({url:`/api/assessment-plans/${fixture.plan.id}`,headers})).json();assert.equal(plan.results.length,1);assert.equal(plan.results[0].kind,'import.zip');assert.equal(plan.results[0].status,'completed');assert.deepEqual(plan.results[0].evidenceIds,[result.evidenceId]);
 await assert.rejects(db.query('UPDATE import_runs SET authorization_request_hash=$2 WHERE id=$1',[result.id,'0'.repeat(64)]),/immutable/i);
 await assert.rejects(db.query('DELETE FROM import_runs WHERE id=$1',[result.id]),/append-only/i);
 const [event]=await db.query("SELECT details FROM audit_events WHERE resource_id=$1 AND action='assessment.execution.started'",[result.id]);assert.equal(event.details.profile,'archive.inspect');
});
test('wrong revision, cross-organization context and reviewed byte limits reject before quarantine or worker',async()=>{
 const fixture=await reviewedPlan(),small=await reviewedPlan(1);let calls=0;behavior=async options=>{calls++;return normal(options);};
 const before=(await db.query('SELECT count(*)::int AS total FROM import_runs'))[0].total;
 try{
  const mismatch=await send({...fixture.body,assessment:{...fixture.assessment,revisionHash:'0'.repeat(64)}});assert.equal(mismatch.statusCode,409,mismatch.body);
  assert.equal((await send(small.body)).statusCode,403);
  await db.query('UPDATE sessions SET active_organization_id=$2 WHERE token_hash=$1',[digest(token),other]);
  assert.equal((await send(fixture.body)).statusCode,404);
 }finally{await db.query('UPDATE sessions SET active_organization_id=$2 WHERE token_hash=$1',[digest(token),org]);behavior=normal;}
 assert.equal(calls,0);assert.equal((await db.query('SELECT count(*)::int AS total FROM import_runs'))[0].total,before);
});
test('revocation after quarantine is checked before worker dispatch and retains failed linked evidence',async()=>{
 const fixture=await reviewedPlan();let calls=0,armed=true;
 const wrapped:Database={...runtime,transaction:async fn=>{
  let quarantined=false;const result=await runtime.transaction(tx=>fn({query:async<T=Record<string,any>>(sql:string,params?:any[]):Promise<T[]>=>{if(/^INSERT INTO import_runs/i.test(sql))quarantined=true;return tx.query<T>(sql,params);}}));
  if(quarantined&&armed){armed=false;assert.equal((await post(`/api/assessment-authorizations/${fixture.grant.id}/revoke`,{reason:'Synthetic pre-dispatch revocation'})).statusCode,200);}
  return result;
 }};
 const alternate=await buildApp({db:wrapped,masterKey:key,pythonPath,importRunner:async options=>{calls++;return normal(options);},now:()=>clock});
 try{const result=await alternate.inject({method:'POST',url:'/api/imports',headers,payload:fixture.body});assert.equal(result.statusCode,403,result.body);}finally{await alternate.close();}
 assert.equal(calls,0);const [run]=await db.query('SELECT r.*,j.status FROM import_runs r JOIN jobs j ON j.id=r.id WHERE r.asset_id=$1',[fixture.body.assetId]);assert.equal(run.status,'failed');assert.equal(run.error_code,'SCOPE_REQUIRED');assert.equal(run.report,null);
 assert.equal((await db.query('SELECT * FROM assessment_execution_evidence WHERE job_id=$1',[run.id])).length,1);assert.equal((await db.query('SELECT * FROM import_execution_lock')).length,0);
 assert.equal((await app.inject({url:`/api/evidence/${run.evidence_id}`,headers})).json().integrityVerified,true);
});
test('revocation or expiry during inspection denies completion without losing original or replacing authorization',async()=>{
 for(const reason of ['revocation','expiry']){
  const fixture=await reviewedPlan(),previousClock=clock;
  behavior=async options=>{const output=await normal(options);if(reason==='revocation')assert.equal((await post(`/api/assessment-authorizations/${fixture.grant.id}/revoke`,{reason:'Synthetic revocation during worker'})).statusCode,200);else clock+=60001;return output;};
  try{const result=await send(fixture.body);assert.equal(result.statusCode,403,result.body);}finally{behavior=normal;clock=previousClock;}
  const [run]=await db.query('SELECT r.*,j.status FROM import_runs r JOIN jobs j ON j.id=r.id WHERE r.asset_id=$1',[fixture.body.assetId]);assert.equal(run.status,'failed');assert.equal(run.report,null);assert.equal(run.mandate_id,fixture.grant.id);await assert.rejects(access(seen));
  const plan=(await app.inject({url:`/api/assessment-plans/${fixture.plan.id}`,headers})).json();assert.equal(plan.results[0].status,'failed');assert.equal(plan.results[0].evidenceIds.length,1);
 }
 const retry=await reviewedPlan();assert.equal((await send(retry.body)).statusCode,200);
});

test('configured Rust supervision is integrated into real import report, plan and audit',{skip:!process.env.SENTINEL_TEST_EXECUTION_PATH||!process.env.SENTINEL_TEST_PYTHON_PATH},async()=>{
 const native=await buildApp({db:runtime,masterKey:key,pythonPath,executionPath:process.env.SENTINEL_TEST_EXECUTION_PATH,now:()=>clock});
 try{
  const status=(await native.inject({url:'/api/imports/status',headers})).json();assert.equal(status.supervisor,'rust');assert.equal(status.authorizationCancellation,true);
  for(const format of ['zip','tar','tar.gz']){
   const fixture=await reviewedPlan(),contentBase64=(await readFile(new URL(`../../../fixtures/lab/import-project.${format}.base64`,import.meta.url),'utf8')).trim();
   const result=await native.inject({method:'POST',url:'/api/imports',headers,payload:{...fixture.body,format,contentBase64}});assert.equal(result.statusCode,200,result.body);const response=result.json();
   assert.equal(response.report.execution.engine,'Sentinel Execution');assert.equal(response.report.execution.jobId,response.id);assert.equal(response.report.execution.status,'completed');assert.equal(response.report.execution.exitCode,0);
   const stored=(await native.inject({url:`/api/imports/${response.id}`,headers})).json();assert.deepEqual(stored.report.execution,response.report.execution);
   const [event]=await db.query("SELECT details FROM audit_events WHERE resource_id=$1 AND action='import.inspected'",[response.id]);assert.deepEqual(event.details.execution,response.report.execution);
   assert.equal((await app.inject({url:`/api/assessment-plans/${fixture.plan.id}`,headers})).json().results.length,1);
  }
 }finally{await native.close();}
});

test('revocation and expiry kill the supervised Python worker and preserve evidence with cancellation receipt',{skip:!process.env.SENTINEL_TEST_EXECUTION_PATH||!process.env.SENTINEL_TEST_PYTHON_PATH},async()=>{
 const folder=await mkdtemp(join(tmpdir(),'sentinel-policy-cancel-')),worker=join(folder,'worker.py'),pidFile=join(folder,'worker.pid');
 await writeFile(worker,"import os,time\nfrom pathlib import Path\nPath(__file__).with_name('worker.pid').write_text(str(os.getpid()))\nwhile True: time.sleep(0.02)\n");
 const native=await buildApp({db:runtime,masterKey:key,pythonPath,executionPath:process.env.SENTINEL_TEST_EXECUTION_PATH,now:()=>clock,importRunner:options=>runSupervisedImport({...options,executionPath:process.env.SENTINEL_TEST_EXECUTION_PATH!,workerPath:worker})});
 try{
  for(const reason of ['revocation','expiry']){
   const fixture=await reviewedPlan(),previous=clock;
   const running=native.inject({method:'POST',url:'/api/imports',headers,payload:fixture.body}).then(result=>result);
   let pid=0;for(let i=0;i<200;i++){try{pid=Number(await readFile(pidFile,'utf8'));break;}catch{await new Promise(resolve=>setTimeout(resolve,20));}}
   assert.ok(pid,'real Python worker started');const started=performance.now();
   try{
    if(reason==='revocation')assert.equal((await post(`/api/assessment-authorizations/${fixture.grant.id}/revoke`,{reason:'Synthetic native cancellation'})).statusCode,200);else clock+=60001;
    const result=await running;assert.equal(result.statusCode,403,result.body);assert.ok(performance.now()-started<5000);assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});
    const [run]=await db.query('SELECT r.*,j.status FROM import_runs r JOIN jobs j ON j.id=r.id WHERE r.asset_id=$1',[fixture.body.assetId]);assert.equal(run.status,'failed');assert.equal(run.error_code,'SCOPE_REQUIRED');assert.equal(run.report,null);
    const [event]=await db.query("SELECT details FROM audit_events WHERE resource_id=$1 AND action='import.failed'",[run.id]);assert.equal(event.details.execution.status,'cancelled');assert.equal(event.details.execution.jobId,run.id);
    assert.equal((await app.inject({url:`/api/evidence/${run.evidence_id}`,headers})).json().integrityVerified,true);assert.equal((await db.query('SELECT * FROM import_execution_lock')).length,0);
   }finally{clock=previous;await unlink(pidFile);}
  }
 }finally{await native.close();await unlink(worker);await rmdir(folder);}
});
