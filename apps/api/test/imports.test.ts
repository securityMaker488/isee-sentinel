import {before,after,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFile,access} from 'node:fs/promises';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {runImportWorker,type ImportRunner} from '../src/imports.ts';
import {digest,encrypt,randomToken} from '../src/security.ts';
let db:Database,runtime:Database,app:Awaited<ReturnType<typeof buildApp>>,seen='';
const key=randomBytes(32),org=randomUUID(),other=randomUUID(),user=randomUUID(),asset=randomUUID(),project=randomUUID(),token=randomToken(),csrf=randomToken(),clock=Date.now();
const headers={host:'127.0.0.1:4310',origin:'http://127.0.0.1:4310',cookie:`sentinel_session=${token}`,'x-csrf-token':csrf};
const pythonPath=process.env.SENTINEL_TEST_PYTHON_PATH??(process.platform==='win32'?'C:\\Trusted\\python.exe':'/trusted/python3');
// Empty ZIP for API/worker transport; malicious and populated archives are tested in the worker suite.
const bytes=Buffer.from('504b0506000000000000000000000000000000000000','hex');
const payload={assetId:asset,format:'zip',name:'synthetic.zip',contentBase64:bytes.toString('base64')};
const normal:ImportRunner=async o=>{seen=o.file;const b=await readFile(o.file);return Buffer.from(JSON.stringify({schemaVersion:'1.0',engine:'Sentinel Import Inspector',quarantineOnly:true,input:{name:'temporary',sha256:digest(b),bytes:b.length,unchanged:true},entries:[],technologies:[],limitations:['Injected transport fixture']}));};
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
 for(const body of [{...payload,url:'http://localhost'}, {...payload,format:'tar'}, {...payload,contentBase64:'!!!'}])assert.equal((await send(body)).statusCode,400);
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
