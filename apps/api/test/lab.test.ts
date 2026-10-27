import {after,before,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import Fastify,{type FastifyInstance} from 'fastify';
import cookie from '@fastify/cookie';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {registerAuth} from '../src/auth.ts';
import {registerAuthorizationManager} from '../src/authorization-manager.ts';
import {registerLab,isLabAddress,nmapArguments,LAB_LIMITS,type LabRunner,type LabRunOptions} from '../src/lab.ts';
import {digest,encrypt,decrypt,randomToken} from '../src/security.ts';
import {verifyAuditChain} from '../src/audit.ts';

let db:Database,app:FastifyInstance,clock=Date.now(),targetId:string,mandateId:string,requestHash:string;
const project=randomUUID();
const key=randomBytes(32),org=randomUUID(),otherOrg=randomUUID(),actor=randomUUID(),asset=randomUUID(),production=randomUUID(),foreignAsset=randomUUID(),unscoped=randomUUID();
const session=randomToken(),otherSession=randomToken(),csrf=randomToken(),origin='http://127.0.0.1:4310';
const nmapPath=process.platform==='win32'?'C:\\Trusted\\nmap.exe':'/usr/bin/nmap';
const headers=(foreign=false)=>({host:'127.0.0.1:4310',origin,cookie:`sentinel_session=${foreign?otherSession:session}`,'x-csrf-token':csrf});
const post=(url:string,payload:any,foreign=false)=>app.inject({method:'POST',url,headers:headers(foreign),payload});
const xml=Buffer.from('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="table" conf="3"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>');
let behavior:LabRunner=async()=>({stdout:xml,exitCode:0});
const calls:{file:string;args:readonly string[];options:LabRunOptions}[]=[];
const runner:LabRunner=async(file,args,options)=>{calls.push({file,args,options});return behavior(file,args,options);};

async function makeApp(path=nmapPath,child:LabRunner=runner,database=db) {
  const instance=Fastify({ajv:{customOptions:{removeAdditional:false,coerceTypes:false}}});
  await instance.register(cookie);await registerAuth(instance,database,key,origin,false,()=>clock);
  instance.setErrorHandler((error,_request,reply)=>{const e=error as any;reply.code(e.statusCode??500).send({error:{code:e.code,message:e.message}});});
  await registerAuthorizationManager(instance,{db:database,masterKey:key,now:()=>clock});
  await registerLab(instance,{db:database,masterKey:key,now:()=>clock,nmapPath:path,runner:child});await instance.ready();return instance;
}

before(async()=>{
  db=await openDatabase();await migrate(db);
  for(const id of [org,otherOrg])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,'Controlled lab fixture']);
  await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[actor,org,'lab@sentinel.test','admin','not-used',encrypt('not-used',key,`totp:${actor}`)]);
  await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[actor,digest(randomToken())]);
  for(const organization of [org,otherOrg])await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[actor,organization]);
  for(const [token,organization] of [[session,org],[otherSession,otherOrg]])await db.query('INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,active_organization_id) VALUES($1,$2,$3,$4,$5)',[digest(token),actor,csrf,new Date(clock+3600000),organization]);
  for(const [id,organization,environment] of [[asset,org,'lab'],[production,org,'production'],[foreignAsset,otherOrg,'lab'],[unscoped,org,'lab']]) {
    await db.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality) VALUES($1,$2,$3,$4,$5,3)',[id,organization,'Lab fixture','server',environment]);
    if(id!==unscoped)await db.query('INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[randomUUID(),organization,id,environment,JSON.stringify(['scan']),'Injected runner fixture; no network tests',new Date(clock-60000),new Date(clock+3600000),actor]);
  }
  app=await makeApp();
  await db.query('INSERT INTO projects(id,organization_id,name,contract_ref) VALUES($1,$2,$3,$4)',[project,org,'Synthetic target manifest','SYNTHETIC-ONLY']);
  await db.query('UPDATE assets SET project_id=$2 WHERE id=$1',[asset,project]);
  const draft=await post('/api/assessment-authorizations',{
    projectId:project,assetIds:[asset],mode:'lab',risk:'moderate',profiles:['lab.inventory'],
    limits:{maxInputBytes:1024,allowedPorts:[22,443]},
    targetManifest:{version:1,targets:[{assetId:asset,address:'127.0.0.1',ports:[22,443]}],exclusions:[]},
    notBefore:new Date(clock-1000).toISOString(),expiresAt:new Date(clock+3600000).toISOString(),
    responsible:{name:'Synthetic lab owner',role:'Fixture owner',organization:'Synthetic organization'},
    purpose:'Injected runner fixture; no network tests.',
    authority:{channel:'internal',reference:'SYNTHETIC-ONLY',evidence:{name:'fixture.txt',mediaType:'text/plain',contentBase64:Buffer.from('Synthetic local fixture authorization, no real network permission.').toString('base64')}}
  });
  assert.equal(draft.statusCode,200,draft.body);mandateId=draft.json().id;requestHash=draft.json().requestHash;
  const approval=await post(`/api/assessment-authorizations/${mandateId}/approve`,{requestHash,attested:true});assert.equal(approval.statusCode,200,approval.body);
});
after(async()=>{await app?.close();await db?.close();});

test('literal private IPv4 and fixed TCP arguments reject DNS, ranges, public targets and option injection',()=>{
  for(const address of ['127.0.0.1','127.3.2.1','10.1.2.3','172.16.0.1','172.31.255.254','192.168.1.2'])assert.equal(isLabAddress(address),true,address);
  for(const address of ['localhost','https://127.0.0.1','127.1','127.00.0.1','127.0.0.1/32','127.0.0.1-2','127.0.0.1,10.0.0.1','::1','8.8.8.8','172.15.1.1','172.32.1.1','169.254.169.254','100.64.0.1','0.0.0.0','255.255.255.255','--script=all','127.0.0.1\n'])assert.equal(isLabAddress(address),false,address);
  assert.deepEqual(nmapArguments('127.0.0.1',[443,22]),['--unprivileged','--disable-arp-ping','-sT','-Pn','-n','--max-retries','1','--host-timeout','30s','-p','22,443','-oX','-','127.0.0.1']);
  for(const ports of [[],[0],[65536],[22,22],[1.1],[true],['22'],Array.from({length:17},(_,i)=>i+1)])assert.throws(()=>nmapArguments('127.0.0.1',ports as number[]));
  assert.throws(()=>nmapArguments('scanme.nmap.org',[22]));
});

test('target registration requires admin, same organization, lab environment and current scope; binding is immutable',async()=>{
  const result=await post('/api/lab/targets',{assetId:asset,address:'127.0.0.1',name:'Loopback fixture'});
  assert.equal(result.statusCode,200,result.body);targetId=result.json().id;assert.equal(result.json().assetId,asset);
  assert.equal((await post('/api/lab/targets',{assetId:asset,address:'127.0.0.1',name:'Duplicate'})).statusCode,409);
  assert.equal((await post('/api/lab/targets',{assetId:production,address:'10.0.0.1',name:'No production'})).statusCode,403);
  assert.equal((await post('/api/lab/targets',{assetId:foreignAsset,address:'10.0.0.1',name:'Other organization'})).statusCode,404);
  assert.equal((await post('/api/lab/targets',{assetId:unscoped,address:'10.0.0.1',name:'No scope'})).statusCode,403);
  for(const address of ['8.8.8.8','localhost','10.0.0.0/24','--script=all'])assert.equal((await post('/api/lab/targets',{assetId:asset,address,name:'Rejected'})).statusCode,400);
  await db.query("UPDATE users SET role='analyst' WHERE id=$1",[actor]);
  assert.equal((await post('/api/lab/targets',{assetId:asset,address:'10.0.0.2',name:'No admin'})).statusCode,403);
  await db.query("UPDATE users SET role='admin' WHERE id=$1",[actor]);
  await assert.rejects(db.query('UPDATE lab_targets SET address=$2 WHERE id=$1',[targetId,'10.0.0.1']));
  const foreign=await app.inject({url:'/api/lab/targets',headers:headers(true)});assert.deepEqual(foreign.json().items,[]);
  assert.equal(calls.length,0);
});

test('runtime capability is honest and never exposes configured path; missing adapter fails without child',async()=>{
  const status=await app.inject({url:'/api/lab/status',headers:headers()});assert.equal(status.json().configured,true);assert.equal(status.json().versionVerified,false);assert.ok(!status.body.includes('Trusted'));
  const missing=await makeApp('');
  try{
    const disabled=await missing.inject({url:'/api/lab/status',headers:headers()});assert.equal(disabled.json().configured,false);
    const result=await missing.inject({method:'POST',url:'/api/lab/scans',headers:headers(),payload:{targetId,ports:[22]}});assert.equal(result.statusCode,503);assert.equal(result.json().error.code,'NMAP_UNAVAILABLE');
  }finally{await missing.close();}
  assert.equal(calls.length,0);
});

test('strict request schema and organization guards run before subprocess',async()=>{
  for(const payload of [{targetId,ports:[]},{targetId,ports:[22,22]},{targetId,ports:['22']},{targetId,ports:[65536]},{targetId,ports:[22],args:['--script=all']},{targetId,ports:[22],address:'8.8.8.8'}])assert.equal((await post('/api/lab/scans',payload)).statusCode,400);
  assert.equal((await post('/api/lab/scans',{targetId,ports:[22]},true)).statusCode,404);
  const unauthorized=await app.inject({method:'POST',url:'/api/lab/scans',headers:{host:'127.0.0.1:4310',origin},payload:{targetId,ports:[22]}});assert.equal(unauthorized.statusCode,401);
  assert.equal(calls.length,0);
});

test('injected successful execution keeps fixed arguments, encrypted XML, analysis, job state and audit',async()=>{
  behavior=async()=>({stdout:xml,exitCode:0});
  const result=await post('/api/lab/scans',{targetId,ports:[443,22]});assert.equal(result.statusCode,200,result.body);
  const scan=result.json();assert.equal(scan.status,'completed');assert.equal(scan.report.format,'nmap-xml');assert.ok(scan.analysisId);assert.equal(scan.findingCount,1);
  assert.equal(scan.mandateId,mandateId);assert.equal(scan.authorizationRequestHash,requestHash);
  const call=calls.at(-1)!;assert.equal(call.file,nmapPath);assert.deepEqual(call.args,nmapArguments('127.0.0.1',[443,22]));
  assert.equal(call.options.shell,false);assert.equal(call.options.windowsHide,true);assert.equal(call.options.timeout,40000);assert.equal(call.options.maxBuffer,1048576);assert.equal(call.options.killSignal,'SIGKILL');
  assert.equal(call.options.env.SENTINEL_MASTER_KEY,undefined);assert.equal(call.options.env.DATABASE_URL,undefined);assert.equal(call.options.env.NMAP_UNPRIVILEGED,'1');
  const [evidence]=await db.query('SELECT * FROM evidence WHERE id=$1',[scan.evidenceId]);assert.equal(evidence.sha256,digest(xml));assert.equal(evidence.media_type,'application/xml');assert.ok(!evidence.content_cipher.includes('<nmaprun'));
  assert.deepEqual(decrypt(evidence.content_cipher,key,`evidence:${org}:${scan.evidenceId}`),xml);
  assert.deepEqual(await db.query('SELECT * FROM lab_execution_lock'),[]);
  const history=await app.inject({url:'/api/lab/scans',headers:headers()});assert.equal(history.json().items[0].id,scan.id);assert.equal(history.json().items[0].status,'completed');assert.equal(history.json().items[0].report,undefined);
  assert.deepEqual((await app.inject({url:'/api/lab/scans',headers:headers(true)})).json().items,[]);
});

test('malformed, partial, failed and oversized output are bounded, preserved and release the execution lock',async()=>{
  for(const [output,code,failure,expected,status] of [
    [Buffer.from('<nmaprun scanner="nmap"><broken>'),0,undefined,'NMAP_INVALID_OUTPUT',502],
    [Buffer.from('<partial>'),null,'NMAP_TIMEOUT','NMAP_TIMEOUT',502],
    [Buffer.from('<partial>'),1,undefined,'NMAP_EXIT_FAILED',502],
    [Buffer.alloc(LAB_LIMITS.outputBytes+1,120),0,undefined,'NMAP_OUTPUT_LIMIT',502],
    [Buffer.alloc(0),null,'NMAP_UNAVAILABLE','NMAP_UNAVAILABLE',503],
  ] as const){
    behavior=async()=>({stdout:output,exitCode:code,failure});
    const response=await post('/api/lab/scans',{targetId,ports:[22]});assert.equal(response.statusCode,status,response.body);assert.equal(response.json().error.code,expected);
    const [scan]=await db.query('SELECT s.*,j.status FROM lab_scans s JOIN jobs j ON j.id=s.id WHERE s.organization_id=$1 ORDER BY s.created_at DESC LIMIT 1',[org]);
    assert.equal(scan.status,'failed');assert.equal(scan.error_code,expected);assert.equal(scan.analysis_id,null);
    if(output.length){const [e]=await db.query('SELECT * FROM evidence WHERE id=$1',[scan.evidence_id]);assert.ok(e.size_bytes<=LAB_LIMITS.outputBytes);assert.deepEqual(decrypt(e.content_cipher,key,`evidence:${org}:${e.id}`),output.subarray(0,LAB_LIMITS.outputBytes));}
    assert.deepEqual(await db.query('SELECT * FROM lab_execution_lock'),[]);
  }
});

test('scope is rechecked on every execution, including revoked, expired, and insufficient remaining lifetime',async()=>{
  const before=calls.length;
  await db.query('UPDATE authorizations SET revoked_at=$2 WHERE asset_id=$1',[asset,new Date(clock)]);
  assert.equal((await post('/api/lab/scans',{targetId,ports:[22]})).statusCode,403);
  await db.query('UPDATE authorizations SET revoked_at=NULL,expires_at=$2 WHERE asset_id=$1',[asset,new Date(clock-1)]);
  assert.equal((await post('/api/lab/scans',{targetId,ports:[22]})).statusCode,403);
  await db.query('UPDATE authorizations SET expires_at=$2 WHERE asset_id=$1',[asset,new Date(clock+10000)]);
  const short=await post('/api/lab/scans',{targetId,ports:[22]});assert.equal(short.statusCode,403);assert.equal(short.json().error.code,'SCOPE_TOO_SHORT');
  await db.query('UPDATE authorizations SET expires_at=$2 WHERE asset_id=$1',[asset,new Date(clock+3600000)]);
  assert.equal(calls.length,before);
});

test('concurrency is rejected both locally and through the global database lock',async()=>{
  let release!:()=>void,started!:()=>void;
  const entered=new Promise<void>(resolve=>{started=resolve;});
  const hold=new Promise<void>(resolve=>{release=resolve;});
  behavior=async()=>{started();await hold;return {stdout:xml,exitCode:0};};
  const pending=post('/api/lab/scans',{targetId,ports:[22]});
  const running=Promise.resolve(pending);await entered;
  const local=await post('/api/lab/scans',{targetId,ports:[22]});assert.equal(local.statusCode,409);assert.equal(local.json().error.code,'LAB_BUSY');
  const second=await makeApp();
  try{const other=await second.inject({method:'POST',url:'/api/lab/scans',headers:headers(),payload:{targetId,ports:[22]}});assert.equal(other.statusCode,409);assert.equal(other.json().error.code,'LAB_BUSY');}
  finally{release();await second.close();}
  assert.equal((await running).statusCode,200);
  assert.deepEqual(await db.query('SELECT * FROM lab_execution_lock'),[]);
});

test('expired lease interrupts an orphaned job before a new run and late results cannot complete',async()=>{
  const orphan=randomUUID();
  await db.query("INSERT INTO jobs(id,organization_id,asset_id,kind,status) VALUES($1,$2,$3,'lab_nmap','running')",[orphan,org,asset]);
  await db.query('INSERT INTO lab_scans(id,organization_id,asset_id,target_id,ports) VALUES($1,$2,$3,$4,$5)',[orphan,org,asset,targetId,'[22]']);
  await db.query('INSERT INTO lab_execution_lock(slot,job_id,expires_at) VALUES(1,$1,$2)',[orphan,new Date(clock-1)]);
  behavior=async()=>({stdout:xml,exitCode:0});
  assert.equal((await post('/api/lab/scans',{targetId,ports:[22]})).statusCode,200);
  const [stale]=await db.query('SELECT s.error_code,j.status FROM lab_scans s JOIN jobs j ON j.id=s.id WHERE s.id=$1',[orphan]);assert.equal(stale.status,'interrupted');assert.equal(stale.error_code,'LEASE_EXPIRED');
  behavior=async()=>{clock+=LAB_LIMITS.leaseMs+1;return {stdout:xml,exitCode:0};};
  const late=await post('/api/lab/scans',{targetId,ports:[22]});assert.equal(late.statusCode,409);assert.equal(late.json().error.code,'LAB_INTERRUPTED');
  const [last]=await db.query('SELECT s.analysis_id,j.status FROM lab_scans s JOIN jobs j ON j.id=s.id WHERE s.organization_id=$1 ORDER BY s.created_at DESC LIMIT 1',[org]);assert.equal(last.analysis_id,null);assert.notEqual(last.status,'completed');
  assert.deepEqual(await db.query('SELECT * FROM lab_execution_lock'),[]);
});

test('revocation committed after job acquisition is rechecked before runner dispatch and releases the lease',async()=>{
  let intercepted=false;
  const database:Database={...db,transaction:async fn=>{
    let acquired=false;
    const result=await db.transaction(tx=>fn({query:async<T>(sql:string,params?:any[])=>{
      const rows=await tx.query<T>(sql,params);
      if(sql.startsWith('INSERT INTO lab_scans'))acquired=true;
      return rows;
    }}));
    if(acquired&&!intercepted){
      intercepted=true;
      await db.query('UPDATE authorizations SET revoked_at=$2 WHERE mandate_id=$1 AND revoked_at IS NULL',[mandateId,new Date(clock)]);
    }
    return result;
  }};
  const concurrent=await makeApp(nmapPath,runner,database),beforeCalls=calls.length;
  try{
    const response=await concurrent.inject({method:'POST',url:'/api/lab/scans',headers:headers(),payload:{targetId,ports:[22]}});
    assert.equal(intercepted,true);assert.equal(response.statusCode,403,response.body);assert.equal(response.json().error.code,'SCOPE_REQUIRED');
    assert.equal(calls.length,beforeCalls);
    assert.deepEqual(await db.query('SELECT * FROM lab_execution_lock'),[]);
    const [failed]=await db.query('SELECT s.error_code,s.evidence_id,j.status FROM lab_scans s JOIN jobs j ON j.id=s.id WHERE s.organization_id=$1 ORDER BY s.created_at DESC LIMIT 1',[org]);
    assert.equal(failed.status,'failed');assert.equal(failed.error_code,'SCOPE_REQUIRED');assert.equal(failed.evidence_id,null);
  }finally{await concurrent.close();}
});

test('audit chain remains valid across registration, successful, failed and interrupted runs',async()=>{
  const events=await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[org]);
  assert.equal(verifyAuditChain(events).valid,true);
  for(const action of ['lab.target_registered','lab.started','lab.output_preserved','lab.completed','lab.failed','lab.interrupted'])assert.ok(events.some(event=>event.action===action),action);
  assert.ok(events.every(event=>!JSON.stringify(event.details).includes('<nmaprun')));
});
