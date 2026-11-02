import {after,before,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {digest,encrypt,randomToken} from '../src/security.ts';
import {verifyAuditChain} from '../src/audit.ts';

let db:Database,runtime:Database,app:Awaited<ReturnType<typeof buildApp>>;
const key=randomBytes(32),organization=randomUUID(),foreignOrganization=randomUUID(),operator=randomUUID();
const project=randomUUID(),otherProject=randomUUID(),foreignProject=randomUUID();
const session=randomToken(),foreignSession=randomToken(),csrf=randomToken(),initialTime=Date.now();
let clock=initialTime;
const origin='http://127.0.0.1:4310',endpoint='/api/assessment-plans',authorityEndpoint='/api/assessment-authorizations';
const headers=(foreign=false)=>({host:'127.0.0.1:4310',origin,cookie:`sentinel_session=${foreign?foreignSession:session}`,'x-csrf-token':csrf});
const send=(url:string,payload:unknown,foreign=false)=>app.inject({method:'POST',url,headers:headers(foreign),payload:payload as any});
const get=(url:string,foreign=false)=>app.inject({url,headers:headers(foreign)});
const safeConfiguration='PermitRootLogin no\nPasswordAuthentication no\n';

async function asset(options:{organization?:string;projectId?:string|null}={}){
 const id=randomUUID(),org=options.organization??organization;
 const linked=options.projectId===undefined?(org===organization?project:foreignProject):options.projectId;
 await db.query("INSERT INTO assets(id,organization_id,name,kind,environment,criticality,project_id) VALUES($1,$2,'Synthetic plan asset','application','lab',3,$3)",[id,org,linked]);
 return id;
}
async function authorization(assetIds:string[],overrides:Record<string,unknown>={},approved=true){
 const payload={projectId:project,assetIds,mode:'lab',risk:'low',profiles:['static.scan'],limits:{maxInputBytes:1024},
  notBefore:new Date(clock-1000).toISOString(),expiresAt:new Date(clock+3600000).toISOString(),
  responsible:{name:'Synthetic Responsible',role:'Fixture owner',organization:'Synthetic organization'},
  purpose:'Verify versioned plans with synthetic local inputs.',authority:{channel:'internal',reference:'SYNTHETIC-AUTHORITY-ONLY',evidence:{name:'synthetic-authority.txt',mediaType:'text/plain',contentBase64:Buffer.from('SYNTHETIC: test fixture, not real customer authority.').toString('base64')}},...overrides};
 const created=await send(authorityEndpoint,payload);assert.equal(created.statusCode,200,created.body);const row=created.json();
 if(!approved)return row;
 const response=await send(`${authorityEndpoint}/${row.id}/approve`,{requestHash:row.requestHash,attested:true});assert.equal(response.statusCode,200,response.body);return response.json();
}
async function counts(){return (await db.query('SELECT (SELECT count(*)::int FROM jobs) AS jobs,(SELECT count(*)::int FROM scans) AS scans,(SELECT count(*)::int FROM evidence) AS evidence'))[0];}
const step=(assetId:string,overrides:Record<string,unknown>={})=>({id:'step-1',name:'Review supplied SSH configuration',assetId,profile:'static.scan',...overrides});
const planBody=(assetId:string,grant:any,overrides:Record<string,unknown>={})=>({name:'Synthetic versioned assessment',projectId:project,mandateId:grant.id,authorizationRequestHash:grant.requestHash,objective:'Inspect only synthetic supplied files.',steps:[step(assetId)],...overrides});
async function createPlan(assetId:string,grant:any,overrides:Record<string,unknown>={}){
 const response=await send(endpoint,planBody(assetId,grant,overrides));assert.equal(response.statusCode,200,response.body);return response.json();
}
async function detail(id:string){const response=await get(`${endpoint}/${id}`);assert.equal(response.statusCode,200,response.body);return response.json();}
// The API returns newest revision first; execution always uses the selected identity.
const revision=(plan:any)=>plan.revisions[0];
const context=(plan:any,rev=revision(plan),overrides:Record<string,unknown>={})=>({planId:plan.id,revisionId:rev.id,revisionHash:rev.hash,stepId:'step-1',...overrides});
const scan=(assetId:string,assessment?:Record<string,unknown>,content=safeConfiguration)=>send('/api/scans',{assetId,files:[{path:'sshd_config',content}],...(assessment?{assessment}:{})});
const nextBody=(plan:any,overrides:Record<string,unknown>={})=>{const current=revision(plan);return {parentHash:current.hash,mandateId:current.mandateId,authorizationRequestHash:current.authorizationRequestHash,objective:'Retest the same synthetic fixture.',steps:current.steps,...overrides};};
async function deniedWithoutResult(body:unknown,status:number,code?:string){const previous=await counts(),response=await send('/api/scans',body);assert.equal(response.statusCode,status,response.body);if(code)assert.equal(response.json().error.code,code);assert.deepEqual(await counts(),previous);}

before(async()=>{
 db=await openDatabase({url:process.env.SENTINEL_ASSESSMENT_TEST_DATABASE_URL});await migrate(db);
 for(const org of [organization,foreignOrganization])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'Synthetic assessment plan fixture']);
 await db.query("INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,'plans@sentinel.test','admin','unused',$3)",[operator,organization,encrypt('unused',key,`totp:${operator}`)]);
 await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[operator,digest(randomToken())]);
 for(const org of [organization,foreignOrganization])await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[operator,org]);
 for(const [token,org] of [[session,organization],[foreignSession,foreignOrganization]])await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),operator,csrf,new Date(clock+48*3600000),org]);
 for(const [id,org] of [[project,organization],[otherProject,organization],[foreignProject,foreignOrganization]])await db.query("INSERT INTO projects(id,organization_id,name,contract_ref) VALUES($1,$2,'Synthetic plan project','SYNTHETIC-ONLY')",[id,org]);
 if(process.env.SENTINEL_ASSESSMENT_TEST_RUNTIME_URL){
  for(const statement of (await readFile(new URL('../../../ops/runtime-grants.sql',import.meta.url),'utf8')).split(';').filter(s=>s.trim()))await db.query(statement);
  runtime=await openDatabase({url:process.env.SENTINEL_ASSESSMENT_TEST_RUNTIME_URL});
 }else runtime=db;
 app=await buildApp({db:runtime,masterKey:key,now:()=>clock});
});
after(async()=>{await app?.close();if(runtime&&runtime!==db)await runtime.close();await db?.close();});

test('plan API requires authentication, CSRF and administrator for mutations; read access does not grant execution',async()=>{
 const target=await asset(),grant=await authorization([target]),body=planBody(target,grant);
 assert.equal((await app.inject({method:'POST',url:endpoint,headers:{host:headers().host,origin},payload:body})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:endpoint,headers:{...headers(),'x-csrf-token':'incorrect'},payload:body})).statusCode,403);
 const plan=await createPlan(target,grant);
 for(const role of ['viewer','analyst']){
  await db.query('UPDATE users SET role=$2 WHERE id=$1',[operator,role]);
  try{
   assert.equal((await send(endpoint,body)).statusCode,403);
   assert.equal((await send(`${endpoint}/${plan.id}/revisions`,nextBody(plan))).statusCode,403);
   assert.equal((await get(`${endpoint}/${plan.id}`)).statusCode,200);
   if(role==='viewer')assert.equal((await scan(target,context(plan))).statusCode,403);
  }finally{await db.query("UPDATE users SET role='admin' WHERE id=$1",[operator]);}
 }
});

test('catalog identifies the implemented plan executor without implying dispatch for every existing profile',async()=>{
 const response=await get(`${endpoint}/catalog`);assert.equal(response.statusCode,200,response.body);const catalog=response.json();
 assert.equal(catalog.schemaVersion,1);assert.equal(catalog.limits.maxSteps,25);assert.equal(catalog.limits.maxRevisions,100);
 assert.deepEqual(catalog.profiles.filter((p:any)=>p.planExecutionSupported).map((p:any)=>p.id),['static.scan','archive.inspect']);
 assert.equal(catalog.profiles.find((p:any)=>p.id==='archive.inspect').planExecutionSupported,true);
 assert.ok(catalog.limitations.length>0);assert.ok(!catalog.profiles.some((p:any)=>p.id==='response.execute'));
});

test('creating a versioned plan preserves the reviewed mandate and steps but performs no scan',async()=>{
 const target=await asset(),grant=await authorization([target]),previous=await counts(),plan=await createPlan(target,grant);
 assert.equal(plan.name,'Synthetic versioned assessment');assert.equal(plan.projectId,project);assert.equal(plan.revisions.length,1);assert.deepEqual(plan.results,[]);
 const first=revision(plan);assert.equal(first.number,1);assert.equal(first.parentHash,null);assert.equal(first.mandateId,grant.id);assert.equal(first.authorizationRequestHash,grant.requestHash);assert.match(first.hash,/^[a-f0-9]{64}$/);assert.deepEqual(first.steps,[step(target)]);
 assert.deepEqual(await counts(),previous);
 const read=await detail(plan.id);assert.deepEqual(read.revisions,plan.revisions);
 const listed=(await get(endpoint)).json().items.find((item:any)=>item.id===plan.id);assert.equal(listed.latestRevision.hash,first.hash);assert.equal(listed.latestRevision.id,first.id);
});

test('uppercase UUID inputs resolve to the same canonical mandate, asset and immutable revision identity',async()=>{
 const target=await asset(),grant=await authorization([target]);
 const plan=await createPlan(target,grant,{projectId:project.toUpperCase(),mandateId:grant.id.toUpperCase(),steps:[step(target.toUpperCase())]});
 const first=revision(plan);
 assert.equal(plan.projectId,project);assert.equal(first.mandateId,grant.id);assert.equal(first.steps[0].assetId,target);
 assert.deepEqual((await detail(plan.id.toUpperCase())).revisions,plan.revisions);
 const revised=await send(`${endpoint}/${plan.id.toUpperCase()}/revisions`,nextBody(plan,{mandateId:grant.id.toUpperCase(),steps:[step(target.toUpperCase())]}));
 assert.equal(revised.statusCode,200,revised.body);const updated=revised.json(),latest=revision(updated);
 assert.equal(latest.mandateId,grant.id);assert.equal(latest.steps[0].assetId,target);assert.equal(latest.parentHash,first.hash);
 const executed=await scan(target.toUpperCase(),context(updated,latest,{planId:plan.id.toUpperCase(),revisionId:latest.id.toUpperCase()}));
 assert.equal(executed.statusCode,200,executed.body);
 const history=await detail(plan.id),result=history.results[0];
 assert.equal(result.revisionId,latest.id);assert.equal(result.jobId,executed.json().id);assert.equal(result.status,'completed');
 const [link]=await db.query('SELECT asset_id,revision_id FROM assessment_executions WHERE organization_id=$1 AND job_id=$2',[organization,result.jobId]);
 assert.equal(link.asset_id,target);assert.equal(link.revision_id,latest.id);
 assert.equal((await get(`/api/evidence/${result.evidenceIds[0]}`)).json().integrityVerified,true);
});

test('invalid metadata, unknown profiles, duplicate steps and excess capacity cannot persist a plan',async()=>{
 const target=await asset(),grant=await authorization([target]),base=planBody(target,grant);
 const beforeCount=(await db.query('SELECT count(*)::int AS total FROM assessment_plans'))[0].total;
 for(const payload of [
  {...base,name:'   '},{...base,objective:'\t '},{...base,approved:true},
  {...base,steps:[]},{...base,steps:Array.from({length:26},(_,i)=>step(target,{id:`step-${i}`}))},
  {...base,steps:[step(target),step(target)]},{...base,steps:[step(target,{profile:'response.execute'})]},
  {...base,steps:[step(target,{id:'../../outside'})]},{...base,steps:[step(target,{shell:'whoami'})]},
  {...base,steps:[step(target,{name:' '})]},
 ]){const response=await send(endpoint,payload);assert.equal(response.statusCode,400,response.body);}
 assert.equal((await db.query('SELECT count(*)::int AS total FROM assessment_plans'))[0].total,beforeCount);
});

test('draft, incorrect review hash and stale authorization do not create a plan or imply approval',async()=>{
 const target=await asset(),draft=await authorization([target],{},false);
 assert.equal((await send(endpoint,planBody(target,draft))).statusCode,403);
 const grant=await authorization([target]);
 const wrong=await send(endpoint,planBody(target,grant,{authorizationRequestHash:'0'.repeat(64)}));assert.equal(wrong.statusCode,409,wrong.body);assert.equal(wrong.json().error.code,'REVIEW_MISMATCH');
 await authorization([target]);
 assert.equal((await send(endpoint,planBody(target,grant))).statusCode,403);
});

test('plans and their revisions are isolated by organization, project and approved asset',async()=>{
 const target=await asset(),other=await asset({projectId:otherProject}),foreign=await asset({organization:foreignOrganization}),unlinked=await asset({projectId:null}),grant=await authorization([target]);
 const deniedPlans:[Record<string,unknown>,number,string][]=[
  [planBody(target,grant,{projectId:otherProject}),400,'INVALID_PLAN'],
  [planBody(target,grant,{projectId:foreignProject}),404,'NOT_FOUND'],
  [planBody(other,grant),400,'INVALID_PLAN'],
  [planBody(foreign,grant),404,'NOT_FOUND'],
  [planBody(unlinked,grant),400,'INVALID_PLAN'],
 ];
 const beforeCount=(await db.query('SELECT count(*)::int AS total FROM assessment_plans'))[0].total;
 for(const [payload,status,code] of deniedPlans){
  const response=await send(endpoint,payload);assert.equal(response.statusCode,status,response.body);assert.equal(response.json().error.code,code);
 }
 assert.equal((await db.query('SELECT count(*)::int AS total FROM assessment_plans'))[0].total,beforeCount);
 const plan=await createPlan(target,grant);
 assert.equal((await get(`${endpoint}/${plan.id}`,true)).statusCode,404);
 assert.equal((await send(`${endpoint}/${plan.id}/revisions`,nextBody(plan),true)).statusCode,404);
 assert.equal((await send(endpoint,planBody(target,grant),true)).statusCode,404);
 assert.ok(!(await get(endpoint,true)).json().items.some((p:any)=>p.id===plan.id));
 const previous=await counts();const response=await send('/api/scans',{assetId:target,files:[{path:'sshd_config',content:safeConfiguration}],assessment:context(plan)},true);assert.ok([403,404].includes(response.statusCode),response.body);assert.deepEqual(await counts(),previous);
});

test('plan revision appends immutable history and optimistic concurrency prevents divergent current revisions',async()=>{
 const target=await asset(),grant=await authorization([target]),plan=await createPlan(target,grant),first=revision(plan),body=nextBody(plan);
 const responses=await Promise.all([send(`${endpoint}/${plan.id}/revisions`,body),send(`${endpoint}/${plan.id}/revisions`,{...body,objective:'Concurrent different revision'})]);
 assert.deepEqual(responses.map(r=>r.statusCode).sort(),[200,409],responses.map(r=>r.body).join('\n'));
 assert.equal(responses.find(r=>r.statusCode===409)!.json().error.code,'REVISION_CONFLICT');
 const updated=await detail(plan.id);assert.equal(updated.revisions.length,2);assert.deepEqual(updated.revisions.map((r:any)=>r.number),[2,1]);assert.deepEqual(updated.revisions[1],first);assert.equal(revision(updated).number,2);assert.equal(revision(updated).parentHash,first.hash);assert.notEqual(revision(updated).hash,first.hash);
 assert.equal((await send(`${endpoint}/${plan.id}/revisions`,{...nextBody(updated),projectId:otherProject})).statusCode,400);
 assert.equal((await send(`${endpoint}/${plan.id}/revisions`,{...nextBody(updated),name:'Cannot rename history'})).statusCode,400);
 assert.equal((await get(endpoint)).json().items.find((p:any)=>p.id===plan.id).latestRevision.hash,revision(updated).hash);
});

test('a real plan-bound static scan atomically links its exact job and preserved evidence',async()=>{
 const target=await asset(),grant=await authorization([target]),plan=await createPlan(target,grant),first=revision(plan),response=await scan(target,context(plan));assert.equal(response.statusCode,200,response.body);
 const scanId=response.json().id,updated=await detail(plan.id);assert.equal(updated.results.length,1);const result=updated.results[0];
 assert.equal(result.revisionId,first.id);assert.equal(result.stepId,'step-1');assert.equal(result.jobId,scanId);assert.equal(result.status,'completed');assert.ok(result.completedAt);assert.equal(result.evidenceIds.length,1);
 const [job]=await db.query('SELECT * FROM jobs WHERE id=$1',[scanId]);assert.equal(job.organization_id,organization);assert.equal(job.asset_id,target);assert.equal(job.kind,'securebuild');assert.equal(job.status,'completed');
 const [evidence]=await db.query('SELECT * FROM evidence WHERE id=$1',[result.evidenceIds[0]]);assert.equal(evidence.organization_id,organization);assert.equal(evidence.asset_id,target);assert.equal(evidence.source,`securebuild:${scanId}`);assert.equal(evidence.sha256,digest(safeConfiguration));
 assert.deepEqual(updated.revisions,plan.revisions);
 assert.equal((await get(`/api/evidence/${evidence.id}`)).json().integrityVerified,true);
});

test('revision and step binding rejects substituted hashes, assets and non-integrated profiles before any job exists',async()=>{
 const target=await asset(),other=await asset(),grant=await authorization([target,other],{profiles:['static.scan','artifact.analyze']}),plan=await createPlan(target,grant,{steps:[step(target),step(target,{id:'artifact',profile:'artifact.analyze'})]}),base={assetId:target,files:[{path:'sshd_config',content:safeConfiguration}]};
 await deniedWithoutResult({...base,assessment:context(plan,revision(plan),{revisionHash:'0'.repeat(64)})},409,'REVIEW_MISMATCH');
 await deniedWithoutResult({...base,assetId:other,assessment:context(plan)},403,'PLAN_STEP_MISMATCH');
 await deniedWithoutResult({...base,assessment:context(plan,revision(plan),{stepId:'artifact'})},403,'PLAN_STEP_MISMATCH');
 const missing=await scan(target,context(plan,revision(plan),{stepId:'missing'}));assert.ok([403,404].includes(missing.statusCode),missing.body);
 const second=await createPlan(target,grant);await deniedWithoutResult({...base,assessment:context(second,revision(plan))},404);
 await deniedWithoutResult({...base,assessment:{...context(plan),mandateId:grant.id}},400);
});

test('executions enforce the reviewed byte ceiling and rejected files leave no partial result',async()=>{
 const target=await asset(),grant=await authorization([target],{limits:{maxInputBytes:64}}),plan=await createPlan(target,grant);
 await deniedWithoutResult({assetId:target,files:[{path:'sshd_config',content:'x'.repeat(65)}],assessment:context(plan)},403);
 await deniedWithoutResult({assetId:target,files:[{path:'../../outside',content:'x'}],assessment:context(plan)},400);
 assert.deepEqual((await detail(plan.id)).results,[]);
});

test('grant revocation, replacement and expiration prevent further planned execution while preserving historical results',async()=>{
 for(const mode of ['revocation','replacement','expiration']){
  const target=await asset(),grant=await authorization([target],{expiresAt:new Date(clock+60000).toISOString()}),plan=await createPlan(target,grant);
  const first=await scan(target,context(plan));assert.equal(first.statusCode,200,first.body);const history=(await detail(plan.id)).results;
  if(mode==='revocation')assert.equal((await send(`${authorityEndpoint}/${grant.id}/revoke`,{reason:'Synthetic exercise concluded'})).statusCode,200);
  if(mode==='replacement')await authorization([target]);
  if(mode==='expiration')clock+=60001;
  try{
   await deniedWithoutResult({assetId:target,files:[{path:'sshd_config',content:safeConfiguration}],assessment:context(plan)},403);
   assert.deepEqual((await detail(plan.id)).results,history);
   assert.equal((await send(`${endpoint}/${plan.id}/revisions`,nextBody(plan))).statusCode,403);
  }finally{clock=initialTime;}
 }
});

test('older revisions remain executable only under their original live grant; an explicit new revision can use the replacement',async()=>{
 const target=await asset(),grant=await authorization([target]),plan=await createPlan(target,grant),first=revision(plan);
 const secondResponse=await send(`${endpoint}/${plan.id}/revisions`,nextBody(plan));assert.equal(secondResponse.statusCode,200,secondResponse.body);const second=secondResponse.json();
 assert.equal((await scan(target,context(plan,first))).statusCode,200);
 assert.equal((await scan(target,context(second))).statusCode,200);
 const replacement=await authorization([target]),thirdResponse=await send(`${endpoint}/${plan.id}/revisions`,nextBody(second,{mandateId:replacement.id,authorizationRequestHash:replacement.requestHash}));assert.equal(thirdResponse.statusCode,200,thirdResponse.body);const third=thirdResponse.json();
 assert.equal((await scan(target,context(third))).statusCode,200);
 await deniedWithoutResult({assetId:target,files:[{path:'sshd_config',content:safeConfiguration}],assessment:context(plan,first)},403);
 const history=await detail(plan.id);assert.equal(history.revisions.length,3);assert.equal(history.results.length,3);assert.deepEqual(history.revisions.map((r:any)=>r.number),[3,2,1]);assert.equal(history.revisions[2].mandateId,grant.id);assert.equal(history.revisions[0].mandateId,replacement.id);
});

test('ordinary scans remain unlinked and no route or supplied field can retroactively attach a result',async()=>{
 const target=await asset(),grant=await authorization([target]),scanResponse=await scan(target);assert.equal(scanResponse.statusCode,200,scanResponse.body);const plan=await createPlan(target,grant);
 assert.deepEqual(plan.results,[]);
 assert.equal((await send(`${endpoint}/${plan.id}/results`,{revisionId:revision(plan).id,stepId:'step-1',jobId:scanResponse.json().id})).statusCode,404);
 assert.equal((await send(`${endpoint}/${plan.id}/revisions`,{...nextBody(plan),results:[{jobId:scanResponse.json().id}]})).statusCode,400);
 assert.deepEqual((await detail(plan.id)).results,[]);
});

test('inventory metadata is constrained to the exact reviewed target and excluded addresses never become planned scope',async()=>{
 const target=await asset(),grant=await authorization([target],{profiles:['lab.inventory'],risk:'moderate',limits:{maxInputBytes:1024,allowedPorts:[22,443]},targetManifest:{version:1,targets:[{assetId:target,address:'127.0.0.1',ports:[22]},{assetId:target,address:'127.0.0.2',ports:[443]}],exclusions:[{address:'127.0.0.2'}]}});
 const inventoryStep=step(target,{profile:'lab.inventory',address:'127.0.0.1',ports:[22]}),previous=await counts();
 const plan=await createPlan(target,grant,{steps:[inventoryStep]});assert.deepEqual(revision(plan).steps,[inventoryStep]);assert.deepEqual(plan.results,[]);
 for(const alteration of [{address:'127.0.0.2',ports:[443]},{address:'127.0.0.3'},{ports:[443]}]){
  const response=await send(endpoint,planBody(target,grant,{steps:[{...inventoryStep,...alteration}]}));assert.equal(response.statusCode,403,response.body);assert.equal(response.json().error.code,'SCOPE_REQUIRED');
 }
 for(const altered of [step(target,{profile:'lab.inventory'}),{...inventoryStep,address:'example.test'},{...inventoryStep,ports:[22,22]}]){
  const response=await send(endpoint,planBody(target,grant,{steps:[altered]}));assert.equal(response.statusCode,400,response.body);
 }
 assert.deepEqual(await counts(),previous);
});

test('database enforces append-only history and cross-asset execution/evidence references even outside the API',async()=>{
 const target=await asset(),other=await asset(),grant=await authorization([target,other]),plan=await createPlan(target,grant),first=revision(plan);
 const completed=await scan(target,context(plan));assert.equal(completed.statusCode,200,completed.body);
 const foreignAssetScan=await scan(other);assert.equal(foreignAssetScan.statusCode,200,foreignAssetScan.body);const otherJob=foreignAssetScan.json().id;
 const [otherEvidence]=await db.query('SELECT id FROM evidence WHERE organization_id=$1 AND source=$2',[organization,`securebuild:${otherJob}`]);
 const result=(await detail(plan.id)).results[0];
 await assert.rejects(db.query('INSERT INTO assessment_executions(job_id,organization_id,revision_id,revision_hash,step_id,asset_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)',[otherJob,organization,first.id,first.hash,'step-1',other,operator]),/foreign key/i);
 await assert.rejects(db.query('INSERT INTO assessment_execution_evidence(organization_id,job_id,asset_id,evidence_id) VALUES($1,$2,$3,$4)',[organization,result.jobId,target,otherEvidence.id]),/foreign key/i);
 await assert.rejects(db.query('INSERT INTO assessment_executions(job_id,organization_id,revision_id,revision_hash,step_id,asset_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)',[otherJob,organization,first.id,'0'.repeat(64),'step-1',target,operator]),/foreign key/i);
 const before=await detail(plan.id);
 // All table names are fixed test constants; no user input reaches SQL identifiers.
 for(const table of ['assessment_plans','assessment_plan_revisions','assessment_plan_steps','assessment_executions','assessment_execution_evidence']){
  assert.ok((await db.query(`SELECT count(*)::int AS total FROM ${table} WHERE organization_id=$1`,[organization]))[0].total>0);
  await assert.rejects(db.query(`UPDATE ${table} SET organization_id=$2 WHERE organization_id=$1`,[organization,foreignOrganization]),/append-only record/i);
  await assert.rejects(db.query(`DELETE FROM ${table} WHERE organization_id=$1`,[organization]),/append-only record/i);
 }
 assert.deepEqual(await detail(plan.id),before);
});

test('a failure during evidence preservation rolls back the whole planned execution without dangling results',async()=>{
 const target=await asset(),grant=await authorization([target]),plan=await createPlan(target,grant);
 const tableCounts=async()=>{
  const result:Record<string,number>={};
  for(const table of ['jobs','scans','evidence','findings','security_events','assessment_executions','assessment_execution_evidence','audit_events']){
   result[table]=(await db.query(`SELECT count(*)::int AS total FROM ${table} WHERE organization_id=$1`,[organization]))[0].total;
  }
  return result;
 };
 const previous=await tableCounts();let writes=0;
 const failing:Database={...runtime,transaction:fn=>runtime.transaction(tx=>fn({
  query:async<T=Record<string,any>>(sql:string,params?:any[]):Promise<T[]>=>{
   if(/^INSERT INTO evidence\b/i.test(sql)&&++writes===2)throw new Error('SYNTHETIC_PRESERVATION_FAILURE');
   return tx.query<T>(sql,params);
  },
 }))};
 const faultApp=await buildApp({db:failing,masterKey:key,now:()=>clock});
 try{
  const response=await faultApp.inject({method:'POST',url:'/api/scans',headers:headers(),payload:{assetId:target,assessment:context(plan),files:[{path:'sshd_config',content:safeConfiguration},{path:'notes.txt',content:'Synthetic bounded fixture'}]}});
  assert.equal(response.statusCode,500,response.body);assert.equal(response.json().error.code,'INTERNAL');assert.equal(writes,2);
  assert.deepEqual(await tableCounts(),previous);
  assert.deepEqual((await detail(plan.id)).results,[]);
  // The failed transaction must not poison a following authorized execution.
  const retry=await scan(target,context(plan));assert.equal(retry.statusCode,200,retry.body);
  assert.equal((await detail(plan.id)).results.length,1);
 }finally{await faultApp.close();}
});

test('audit history stays verifiable after plan creation, revision, execution and rejected requests',async()=>{
 const rows=await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[organization]);assert.equal(verifyAuditChain(rows).valid,true);
 assert.ok(rows.some(row=>row.action.includes('assessment')),'Plan actions must be present in the audit trail.');
});
