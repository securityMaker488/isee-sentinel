import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,writeFile,unlink,rmdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {openDatabase,migrate} from '../apps/api/src/db.ts';
import {buildApp} from '../apps/api/src/app.ts';
import {digest,encrypt,generateEnrollment,hashPassword,totp} from '../apps/api/src/security.ts';

const binary=resolve(process.env.SENTINEL_AGENT_BINARY??`packages/endpoint-agent/target/debug/sentinel-agent${process.platform==='win32'?'.exe':''}`);
const db=await openDatabase();await migrate(db);
const key=randomBytes(32),org=randomUUID(),user=randomUUID(),password=randomUUID(),enrollment=generateEnrollment('fixture@sentinel.test');
const folder=await mkdtemp(join(tmpdir(),'sentinel-agent-validation-'));
const credentialFile=join(folder,'credential.json'),observedFile=join(folder,'fixture.txt');
await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'Synthetic agent fixture']);
await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[user,org,'fixture@sentinel.test','admin',await hashPassword(password),encrypt(enrollment.secret,key,`totp:${user}`)]);
await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[user,digest(randomUUID())]);
await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[user,org]);
const app=await buildApp({db,masterKey:key});
try {
 const endpoint=await app.listen({host:'127.0.0.1',port:0});
 let headers:Record<string,string>={host:'127.0.0.1:4310',origin:'http://127.0.0.1:4310'};
 const post=async(url:string,payload:unknown)=>{const r=await app.inject({method:'POST',url,headers,payload:payload as any});assert.equal(r.statusCode,200,r.body);return r;};
 const login=await post('/api/auth/login',{email:'fixture@sentinel.test',password,otp:totp(enrollment.secret).generate()});headers={...headers,cookie:String(login.headers['set-cookie']).split(';')[0],'x-csrf-token':login.json().csrfToken};
 const asset=(await post('/api/assets',{name:'Synthetic watched fixture',kind:'server',environment:'lab',criticality:2})).json();
 await post('/api/authorizations',{assetId:asset.id,operations:['event.ingest'],authorizationRef:'Loopback fixture only',expiresAt:new Date(Date.now()+3600000).toISOString()});
 const agent=(await post('/api/agents',{assetId:asset.id,name:'Actual Rust fixture',expiresAt:new Date(Date.now()+3600000).toISOString()})).json();
 await writeFile(credentialFile,JSON.stringify(agent.credential),{mode:0o600,flag:'wx'});await writeFile(observedFile,'baseline fixture\n',{mode:0o600,flag:'wx'});
 const args=['--consent','--asset-id',asset.id,'--file',observedFile,'--endpoint',endpoint,'--allow-loopback-http','--credential-file',credentialFile];
 const collect=()=>promisify(execFile)(binary,args,{timeout:45000,maxBuffer:65536,windowsHide:true});
 await collect();const [first]=await db.query('SELECT * FROM agent_observations');assert.equal(first.result,'unbaselined');
 await post('/api/agents/baselines',{observationId:first.id});await collect();
 await writeFile(observedFile,'changed fixture\n');await collect();
 const observations=await db.query('SELECT result FROM agent_observations ORDER BY received_at');assert.deepEqual(observations.map(o=>o.result),['unbaselined','unchanged','changed']);
 assert.equal((await db.query("SELECT id FROM alerts WHERE rule_id='FIM-CHANGE'")).length,1);
 await post(`/api/agents/${agent.id}/revoke`,{});
 await assert.rejects(collect());assert.equal((await db.query('SELECT id FROM agent_observations')).length,3);
 console.info('PASS: actual Rust binary → authenticated loopback API → explicit baseline → drift alert → revoked credential blocked. Synthetic isolated DB; no host configuration changes.');
}finally{
 await app.close();await db.close();
 if(dirname(resolve(folder))!==resolve(tmpdir())||!resolve(folder).startsWith(join(resolve(tmpdir()),'sentinel-agent-validation-')))throw new Error('Unexpected temporary path');
 for(const file of [credentialFile,observedFile])await unlink(file).catch(e=>{if(e.code!=='ENOENT')throw e;});await rmdir(folder);
}
