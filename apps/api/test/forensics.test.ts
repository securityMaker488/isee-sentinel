import {before,after,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFile,access} from 'node:fs/promises';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {runForensicWorker,type ForensicRunner} from '../src/forensics.ts';
import {digest,encrypt,randomToken} from '../src/security.ts';
let db:Database,appDb:Database,app:Awaited<ReturnType<typeof buildApp>>,fileSeen='';
const key=randomBytes(32),org=randomUUID(),other=randomUUID(),user=randomUUID(),asset=randomUUID(),token=randomToken(),csrf=randomToken(),clock=Date.now();
const headers={host:'127.0.0.1:4310',origin:'http://127.0.0.1:4310',cookie:`sentinel_session=${token}`,'x-csrf-token':csrf};
const pythonPath=process.env.SENTINEL_TEST_PYTHON_PATH??(process.platform==='win32'?'C:\\Trusted\\python.exe':'/trusted/python3');
const bytes=Buffer.alloc(24);bytes.writeUInt32LE(0xa1b2c3d4,0);bytes.writeUInt16LE(2,4);bytes.writeUInt16LE(4,6);bytes.writeUInt32LE(65535,16);bytes.writeUInt32LE(1,20);
const payload={assetId:asset,kind:'pcap',name:'synthetic-empty.pcap',contentBase64:bytes.toString('base64')};
const normal:ForensicRunner=async options=>{fileSeen=options.file;const b=await readFile(options.file);return Buffer.from(JSON.stringify({schemaVersion:'1.0',engine:'Sentinel Offline Forensics',engineVersion:'1.0.0',kind:options.kind,input:{name:'temporary',sha256:digest(b),bytes:b.length,unchanged:true},summary:'Injected runner fixture',metrics:{packets:0},limitations:['Synthetic runner; no parsing claimed.']}));};
let behavior=normal;const runner:ForensicRunner=options=>behavior(options);
const send=(body:unknown=payload)=>app.inject({method:'POST',url:'/api/forensics',headers,payload:body as any});
before(async()=>{
 db=await openDatabase({url:process.env.SENTINEL_FORENSIC_TEST_DATABASE_URL});await migrate(db);
 for(const id of [org,other])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,'Synthetic forensic fixture']);
 await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[user,org,'forensic@sentinel.test','admin','not-used',encrypt('not-used',key,`totp:${user}`)]);
 await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[user,digest(randomToken())]);
 for(const id of [org,other])await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[user,id]);
 await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),user,csrf,new Date(clock+3600000),org]);
 await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality) VALUES($1,$2,$3,$4,$5,3)',[asset,org,'Synthetic file','server','lab']);
 await db.query('INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[randomUUID(),org,asset,'lab',JSON.stringify(['scan','evidence.import']),'Forensic fixture authorization',new Date(clock-1000),new Date(clock+3600000),user]);
 if(process.env.SENTINEL_FORENSIC_TEST_RUNTIME_URL){for(const sql of (await readFile(new URL('../../../ops/runtime-grants.sql',import.meta.url),'utf8')).split(';').filter(s=>s.trim()))await db.query(sql);appDb=await openDatabase({url:process.env.SENTINEL_FORENSIC_TEST_RUNTIME_URL});}else appDb=db;
 app=await buildApp({db:appDb,masterKey:key,pythonPath,forensicRunner:runner,now:()=>clock});
});
after(async()=>{await app?.close();if(appDb&&appDb!==db)await appDb.close();await db?.close();});
test('forensic upload rejects unauthenticated, noncanonical, unscoped and arbitrary worker options',async()=>{
 assert.equal((await app.inject({method:'POST',url:'/api/forensics',headers:{host:'127.0.0.1:4310',origin:headers.origin},payload})).statusCode,401);
 assert.equal((await send({...payload,contentBase64:'!!!'})).statusCode,400);
 assert.equal((await send({...payload,includeValues:true})).statusCode,400);
 assert.equal((await send({...payload,table:'anything'})).statusCode,400);
 assert.equal((await send({...payload,assetId:randomUUID()})).statusCode,404);
 assert.equal((await send({...payload,command:'execute'})).statusCode,400);
});
test('worker binds report to preserved bytes, hides temporary paths and cleans plaintext copy',async()=>{
 const r=await send();assert.equal(r.statusCode,200,r.body);assert.equal(r.json().report.input.sha256,digest(bytes));assert.equal(r.json().report.input.name,payload.name);assert.ok(!r.body.includes(fileSeen));await assert.rejects(access(fileSeen));
 const e=await app.inject({url:`/api/evidence/${r.json().evidenceId}`,headers});assert.equal(e.json().integrityVerified,true);
 const detail=await app.inject({url:`/api/forensics/${r.json().id}`,headers});assert.equal(detail.statusCode,200);
 await db.query('UPDATE sessions SET active_organization_id=$2 WHERE token_hash=$1',[digest(token),other]);
 assert.equal((await app.inject({url:`/api/forensics/${r.json().id}`,headers})).statusCode,404);assert.deepEqual((await app.inject({url:'/api/forensics',headers})).json().items,[]);
 await db.query('UPDATE sessions SET active_organization_id=$2 WHERE token_hash=$1',[digest(token),org]);
});
test('mismatched worker report fails closed but preserves original and releases lock',async()=>{
 behavior=async o=>{const r=JSON.parse((await normal(o)).toString());r.input.sha256='0'.repeat(64);return Buffer.from(JSON.stringify(r));};
 const r=await send();assert.equal(r.statusCode,409,r.body);assert.equal(r.json().error.code,'WORKER_INTEGRITY');await assert.rejects(access(fileSeen));
 const failed=await db.query("SELECT r.evidence_id FROM forensic_runs r JOIN jobs j ON j.id=r.id WHERE j.status='failed' AND r.error_code='WORKER_INTEGRITY'");assert.equal(failed.length,1);assert.equal((await db.query('SELECT * FROM forensic_execution_lock')).length,0);behavior=normal;
 assert.equal((await send()).statusCode,200);
});
test('only one forensic worker runs concurrently',async()=>{
 let entered!:()=>void,release!:()=>void;const started=new Promise<void>(r=>{entered=r;}),gate=new Promise<void>(r=>{release=r;});
 behavior=async o=>{entered();await gate;return normal(o);};const first=send();await started;
 try{assert.equal((await send()).statusCode,409);}finally{release();}
 assert.equal((await first).statusCode,200);behavior=normal;
});
test('real Python worker executes with isolated runtime against the uploaded PCAP fixture',{skip:!process.env.SENTINEL_TEST_PYTHON_PATH},async()=>{
 behavior=runForensicWorker;
 try{const r=await send();assert.equal(r.statusCode,200,r.body);assert.equal(r.json().report.engine,'Sentinel Offline Forensics');assert.equal(r.json().report.input.unchanged,true);assert.equal(r.json().report.input.sha256,digest(bytes));}finally{behavior=normal;}
});
