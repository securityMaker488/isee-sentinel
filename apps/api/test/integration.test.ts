import {before,after,test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import type {FastifyInstance} from 'fastify';
import {openDatabase,migrate,type Database} from '../src/db.ts';
import {buildApp} from '../src/app.ts';
import {encrypt,decrypt,hashPassword,verifyPassword,generateEnrollment,totp,digest} from '../src/security.ts';
import {recoverOperator} from '../src/operator.ts';

let db:Database,appDb:Database,app:FastifyInstance,clock=Date.now(),assetId:string,scanId:string,evidenceId:string;
const key=randomBytes(32),origin='http://127.0.0.1:4310';
const organizations=[randomUUID(),randomUUID()];
const users=['admin','analyst','viewer','other','locked'].map((name,i)=>({id:randomUUID(),email:`${name}@sentinel.test`,role:name==='other'||name==='locked'?'admin':name,org:organizations[i===3?1:0],password:`Tests-only-${randomUUID()}`,secret:generateEnrollment(`${name}@sentinel.test`).secret}));
type Session={cookie:string;csrf:string};const sessions:Record<string,Session>={};
const headers=(s?:Session)=>({host:'127.0.0.1:4310',origin,...(s?{cookie:s.cookie,'x-csrf-token':s.csrf}:{})});
async function login(index:number) {clock+=30000;const u=users[index];const response=await app.inject({method:'POST',url:'/api/auth/login',headers:headers(),payload:{email:u.email,password:u.password,otp:totp(u.secret).generate({timestamp:clock})}});assert.equal(response.statusCode,200,response.body);assert.match(String(response.headers['set-cookie']),/HttpOnly/);assert.match(String(response.headers['set-cookie']),/SameSite=Strict/i);const cookie=String(response.headers['set-cookie']).split(';')[0];return {cookie,csrf:response.json().csrfToken};}
async function createAsset(session:Session,name='Laboratório autorizado') {const r=await app.inject({method:'POST',url:'/api/assets',headers:headers(session),payload:{name,kind:'server',environment:'lab',criticality:4}});assert.equal(r.statusCode,200,r.body);return r.json().id;}
async function grant(id:string,session=sessions.admin,expiresAt=new Date(clock+86400000).toISOString()) {return app.inject({method:'POST',url:'/api/authorizations',headers:headers(session),payload:{assetId:id,operations:['scan','evidence.import','event.ingest'],authorizationRef:'LAB-TEST-001 / fixture de integração',expiresAt}});}
async function asRole<T>(role:string,fn:()=>Promise<T>):Promise<T> {await db.query('UPDATE users SET role=$2 WHERE id=$1',[users[0].id,role]);try{return await fn();}finally{await db.query("UPDATE users SET role='admin' WHERE id=$1",[users[0].id]);}}
before(async()=>{
  db=await openDatabase({url:process.env.SENTINEL_TEST_DATABASE_URL});await migrate(db);await migrate(db);
  for(const org of organizations)await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'Test organization']);
  for(const u of users)await db.query('INSERT INTO users(id,organization_id,email,role,password_hash,totp_cipher) VALUES($1,$2,$3,$4,$5,$6)',[u.id,u.org,u.email,u.role,await hashPassword(u.password),encrypt(u.secret,key,`totp:${u.id}`)]);
  await db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(1,$1,$2)',[users[0].id,digest(randomBytes(32))]);
  for(const org of organizations)await db.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[users[0].id,org]);
  if(process.env.SENTINEL_TEST_RUNTIME_URL) {
    const grants=await readFile(new URL('../../../ops/runtime-grants.sql',import.meta.url),'utf8');
    for(const statement of grants.split(';').filter(s=>s.trim()))await db.query(statement);
    appDb=await openDatabase({url:process.env.SENTINEL_TEST_RUNTIME_URL});
  }else appDb=db;
  app=await buildApp({db:appDb,masterKey:key,now:()=>clock});
  for(let i=0;i<4;i++)sessions[i===3?'other':users[i].role]=await login(0);
  const switched=await app.inject({method:'POST',url:'/api/context',headers:headers(sessions.other),payload:{organizationId:organizations[1]}});assert.equal(switched.statusCode,200,switched.body);sessions.other.csrf=switched.json().csrfToken;
});
after(async()=>{await app?.close();if(appDb&&appDb!==db)await appDb.close();await db?.close();});
test('API exige sessão; login exige origem; MFA e replay de OTP são bloqueados',async()=>{
  assert.equal((await app.inject({url:'/api/assets',headers:headers()})).statusCode,401);
  const u=users[0];const body={email:u.email,password:u.password,otp:totp(u.secret).generate({timestamp:clock})};
  assert.equal((await app.inject({method:'POST',url:'/api/auth/login',headers:{host:'127.0.0.1:4310'},payload:body})).statusCode,403);
  assert.equal((await app.inject({method:'POST',url:'/api/auth/login',headers:headers(),payload:{...body,otp:'000000'}})).statusCode,401);
  assert.equal((await app.inject({method:'POST',url:'/api/auth/login',headers:headers(),payload:body})).statusCode,401);
  const other=users[3];assert.equal((await app.inject({method:'POST',url:'/api/auth/login',headers:headers(),payload:{email:other.email,password:other.password,otp:totp(other.secret).generate({timestamp:clock})}})).statusCode,401);
});
test('CSRF, mass assignment e papéis restringem criação de ativos',async()=>{
  const payload={name:'Host',kind:'server',environment:'lab',criticality:3};
  assert.equal((await app.inject({method:'POST',url:'/api/assets',headers:{...headers(sessions.admin),'x-csrf-token':'bad'},payload})).statusCode,403);
  assert.equal((await app.inject({method:'POST',url:'/api/assets',headers:headers(sessions.admin),payload:{...payload,organizationId:organizations[1]}})).statusCode,400);
  await asRole('viewer',async()=>assert.equal((await app.inject({method:'POST',url:'/api/assets',headers:headers(sessions.viewer),payload})).statusCode,403));
  assetId=await createAsset(sessions.admin);
});
test('escopo obrigatório, isolado por organização e concedido somente por admin',async()=>{
  const payload={assetId,files:[{path:'sshd_config',content:'PermitRootLogin yes\nPasswordAuthentication yes\n'}]};
  assert.equal((await app.inject({method:'POST',url:'/api/scans',headers:headers(sessions.admin),payload})).statusCode,403);
  await asRole('analyst',async()=>assert.equal((await grant(assetId,sessions.analyst)).statusCode,403));
  assert.equal((await grant(assetId,sessions.other)).statusCode,404);
  assert.equal((await grant(assetId)).statusCode,200);
  assert.equal((await app.inject({method:'POST',url:'/api/scans',headers:headers(sessions.other),payload})).statusCode,404);
  await asRole('viewer',async()=>assert.equal((await app.inject({method:'POST',url:'/api/scans',headers:headers(sessions.viewer),payload})).statusCode,403));
});
test('scan real produz achados, originais criptografados, barreiras e relatório',async()=>{
  const file={path:'sshd_config',content:'PermitRootLogin yes\nPasswordAuthentication yes\n'};
  const r=await app.inject({method:'POST',url:'/api/scans',headers:headers(sessions.analyst),payload:{assetId,files:[file]}});
  assert.equal(r.statusCode,200,r.body);scanId=r.json().id;assert.ok(r.json().result.findings.length>=2);
  const findings=(await app.inject({url:'/api/findings',headers:headers(sessions.admin)})).json().items;assert.equal(findings[0].scanId,scanId);evidenceId=findings[0].evidenceId;
  const evidence=(await app.inject({url:`/api/evidence/${evidenceId}`,headers:headers(sessions.admin)})).json();assert.equal(evidence.integrityVerified,true);assert.equal(evidence.sha256,digest(file.content));
  const [stored]=await db.query('SELECT * FROM evidence WHERE id=$1',[evidenceId]);assert.ok(!stored.content_cipher.includes('PermitRootLogin'));assert.equal(decrypt(stored.content_cipher,key,`evidence:${organizations[0]}:${evidenceId}`).toString(),file.content);
  const report=await app.inject({url:`/api/reports/${scanId}`,headers:headers(sessions.viewer)});assert.equal(report.statusCode,200);assert.equal(report.json().evidence[0].sha256,digest(file.content));assert.ok(report.json().risk.factors.length>=2);
  const barriers=(await app.inject({url:'/api/barriers',headers:headers(sessions.viewer)})).json().items;assert.equal(barriers.length,14);assert.ok(barriers.some((b:any)=>b.status==='fail'));assert.ok(barriers.some((b:any)=>b.status==='not_evaluated'));
});
test('path traversal, payload acima do limite e objetos inesperados são rejeitados',async()=>{
  for(const path of ['../secret','C:\\Windows\\secret','/etc/passwd'])assert.equal((await app.inject({method:'POST',url:'/api/scans',headers:headers(sessions.admin),payload:{assetId,files:[{path,content:'a'}]}})).statusCode,400);
  assert.equal((await app.inject({method:'POST',url:'/api/scans',headers:headers(sessions.admin),payload:{assetId,files:[{path:'config.json',content:'a'.repeat(262145)}]}})).statusCode,400);
});
test('BOLA: relatórios, evidências e dados de outra organização ficam inacessíveis',async()=>{
  for(const url of [`/api/evidence/${evidenceId}`,`/api/evidence/${evidenceId}/download`,`/api/reports/${scanId}`])assert.equal((await app.inject({url,headers:headers(sessions.other)})).statusCode,404);
  for(const url of ['/api/findings','/api/scans','/api/evidence'])assert.deepEqual((await app.inject({url,headers:headers(sessions.other)})).json().items,[]);
  await asRole('viewer',async()=>assert.equal((await app.inject({url:`/api/evidence/${evidenceId}/download`,headers:headers(sessions.viewer)})).statusCode,403));
});
test('evidência binária preserva bytes e exportação gera custódia verificável',async()=>{
  const bytes=Buffer.from([0,255,1,13,10,128]);const r=await app.inject({method:'POST',url:'/api/evidence',headers:headers(sessions.analyst),payload:{assetId,name:'amostra.bin',mediaType:'application/octet-stream',contentBase64:bytes.toString('base64')}});assert.equal(r.statusCode,200,r.body);
  const download=await app.inject({url:`/api/evidence/${r.json().id}/download`,headers:headers(sessions.analyst)});assert.deepEqual(download.rawPayload,bytes);assert.equal(download.headers['content-type'],'application/octet-stream');
  await assert.rejects(db.query('UPDATE evidence SET name=$2 WHERE id=$1',[r.json().id,'changed']),/append-only/);
  await assert.rejects(db.query('DELETE FROM audit_events WHERE organization_id=$1',[organizations[0]]),/append-only/);
});
test('auditoria em cadeia valida e detecção identifica adulteração criptográfica',async()=>{
  const response=await app.inject({url:'/api/audit/verify',headers:headers(sessions.admin)});assert.equal(response.statusCode,200,response.body);assert.equal(response.json().valid,true);assert.ok(response.json().checked>10);
  const cipher=Buffer.from(encrypt('evidence',key,'test'),'base64');cipher[13]^=1;assert.throws(()=>decrypt(cipher.toString('base64'),key,'test'));assert.throws(()=>decrypt(encrypt('data',key,'a'),key,'b'));
});
test('ingestão versionada detecta cinco falhas e não duplica incidente na janela',async()=>{
  let incident:string|null=null;
  for(let i=0;i<6;i++) {const r=await app.inject({method:'POST',url:'/api/events',headers:headers(sessions.analyst),payload:{assetId,schemaVersion:1,type:'auth.failure',source:'test-fixture',occurredAt:new Date(clock).toISOString(),data:{subject:'lab-user',synthetic:true}}});assert.equal(r.statusCode,200,r.body);if(i<4)assert.equal(r.json().incidentId,null);if(i===4)incident=r.json().incidentId;if(i===5)assert.equal(r.json().incidentId,null);}
  assert.ok(incident);const items=(await app.inject({url:'/api/incidents',headers:headers(sessions.viewer)})).json().items;assert.equal(items.length,1);assert.equal(items[0].eventIds.length,5);assert.equal(items[0].synthetic,true);
});
test('revogação e expiração de escopo impedem nova análise',async()=>{
  const id=await createAsset(sessions.admin,'Revocation test'),grantResponse=await grant(id),scopeId=grantResponse.json().id;
  assert.equal((await app.inject({method:'POST',url:`/api/authorizations/${scopeId}/revoke`,headers:headers(sessions.admin)})).statusCode,200);
  assert.equal((await app.inject({method:'POST',url:'/api/scans',headers:headers(sessions.admin),payload:{assetId:id,files:[{path:'sshd_config',content:'PermitRootLogin no'}]}})).statusCode,403);
  assert.equal((await grant(id,sessions.admin,new Date(clock-1).toISOString())).statusCode,400);
});
test('cookie seguro HttpOnly SameSite, logout revoga sessão, OpenAPI protegido',async()=>{
  assert.equal((await app.inject({url:'/api/openapi.json',headers:headers()})).statusCode,401);
  const spec=(await app.inject({url:'/api/openapi.json',headers:headers(sessions.admin)})).json();assert.ok(spec.paths['/api/scans']);
  assert.equal((await app.inject({method:'POST',url:'/api/auth/logout',headers:headers(sessions.viewer)})).statusCode,200);
  assert.equal((await app.inject({url:'/api/assets',headers:headers(sessions.viewer)})).statusCode,401);
});
test('limite persistente por conta bloqueia tentativa mesmo com IP diferente',async()=>{
  const u=users[4];
  for(let i=0;i<5;i++) {const r=await app.inject({method:'POST',url:'/api/auth/login',remoteAddress:`127.0.1.${i+1}`,headers:headers(),payload:{email:u.email,password:'wrong-password',otp:'111111'}});assert.equal(r.statusCode,401,r.body);}
  const r=await app.inject({method:'POST',url:'/api/auth/login',remoteAddress:'127.0.2.1',headers:headers(),payload:{email:u.email,password:u.password,otp:totp(u.secret).generate({timestamp:clock})}});assert.equal(r.statusCode,429,r.body);
});
test('sessão expirada não autoriza leituras',async()=>{
  await db.query('UPDATE sessions SET expires_at=$2 WHERE token_hash=$1',[digest(sessions.other.cookie.split('=')[1]),new Date(clock-1)]);
  assert.equal((await app.inject({url:'/api/assets',headers:headers(sessions.other)})).statusCode,401);
});
test('V6.3: banco impede segundo fundador e sessão não entra em organização sem vínculo',async()=>{
  await assert.rejects(db.query('INSERT INTO private_operator(slot,user_id,recovery_hash) VALUES(2,$1,$2)',[users[1].id,'no']),/check constraint/);
  const detached=randomUUID();await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[detached,'Não autorizada']);
  assert.equal((await app.inject({method:'POST',url:'/api/context',headers:headers(sessions.admin),payload:{organizationId:detached}})).statusCode,404);
});
test('V6.3: empresas/projetos pertencem ao fundador e troca de contexto rotaciona CSRF',async()=>{
  const org=await app.inject({method:'POST',url:'/api/organizations',headers:headers(sessions.admin),payload:{name:'Cliente de laboratório'}});assert.equal(org.statusCode,200,org.body);
  const oldCsrf=sessions.admin.csrf;const switched=await app.inject({method:'POST',url:'/api/context',headers:headers(sessions.admin),payload:{organizationId:org.json().id}});assert.equal(switched.statusCode,200,switched.body);sessions.admin.csrf=switched.json().csrfToken;assert.notEqual(oldCsrf,sessions.admin.csrf);
  assert.deepEqual((await app.inject({url:'/api/assets',headers:headers(sessions.admin)})).json().items,[]);
  assert.equal((await app.inject({url:`/api/reports/${scanId}`,headers:headers(sessions.admin)})).statusCode,404);
  const project=await app.inject({method:'POST',url:'/api/projects',headers:headers(sessions.admin),payload:{name:'Avaliação',contractRef:'CONTRATO-LAB-001'}});assert.equal(project.statusCode,200,project.body);
  const asset=await app.inject({method:'POST',url:'/api/assets',headers:headers(sessions.admin),payload:{name:'Aplicação teste',kind:'application',environment:'lab',criticality:2,projectId:project.json().id}});assert.equal(asset.statusCode,200,asset.body);
  const back=await app.inject({method:'POST',url:'/api/context',headers:headers(sessions.admin),payload:{organizationId:organizations[0]}});sessions.admin.csrf=back.json().csrfToken;
  assert.equal((await app.inject({method:'POST',url:'/api/assets',headers:headers(sessions.admin),payload:{name:'Cross-project',kind:'application',environment:'lab',criticality:2,projectId:project.json().id}})).statusCode,404);
});
test('V6.3: deduplica eventos, persiste alerta rastreável e permite triagem',async()=>{
  const payload={assetId,externalId:randomUUID(),schemaVersion:1,type:'auth.failure',source:'dedup-test',occurredAt:new Date(clock).toISOString(),data:{subject:'synthetic-subject',synthetic:true}};
  const first=await app.inject({method:'POST',url:'/api/events',headers:headers(sessions.admin),payload});assert.equal(first.statusCode,200,first.body);
  const repeat=await app.inject({method:'POST',url:'/api/events',headers:headers(sessions.admin),payload});assert.equal(repeat.json().duplicate,true);assert.equal(repeat.json().id,first.json().id);
  assert.equal((await app.inject({method:'POST',url:'/api/events',headers:headers(sessions.admin),payload:{...payload,data:{...payload.data,subject:'changed'}}})).statusCode,409);
  for(let i=0;i<4;i++)assert.equal((await app.inject({method:'POST',url:'/api/events',headers:headers(sessions.admin),payload:{...payload,externalId:randomUUID()}})).statusCode,200);
  const alerts=(await app.inject({url:'/api/alerts',headers:headers(sessions.admin)})).json().items;assert.equal(alerts.length,2);const alert=alerts[0];assert.equal(alert.synthetic,true);assert.equal(alert.eventIds.length,5);assert.equal(alert.ruleVersion,'1.0.0');assert.ok(alert.incidentId);
  assert.equal((await app.inject({method:'POST',url:`/api/alerts/${alert.id}/status`,headers:headers(sessions.admin),payload:{status:'false_positive'}})).statusCode,200);
});
test('regressão: delimitadores nos campos não suprimem correlações distintas',async()=>{
  for(const [source,subject] of [['a:b','c'],['a','b:c']]) {
    let last:any;
    for(let i=0;i<5;i++)last=await app.inject({method:'POST',url:'/api/events',headers:headers(sessions.admin),payload:{assetId,externalId:randomUUID(),schemaVersion:1,type:'auth.failure',source,occurredAt:new Date(clock).toISOString(),data:{subject,synthetic:true}}});
    assert.equal(last.statusCode,200,last.body);assert.ok(last.json().alertId);
  }
});
test('simulação não pode ser direcionada a ativo de produção',async()=>{
  const r=await app.inject({method:'POST',url:'/api/assets',headers:headers(sessions.admin),payload:{name:'Produção sem telemetria',kind:'application',environment:'production',criticality:5}});assert.equal(r.statusCode,200,r.body);const id=r.json().id;assert.equal((await grant(id)).statusCode,200);
  const result=await app.inject({method:'POST',url:'/api/events',headers:headers(sessions.admin),payload:{assetId:id,schemaVersion:1,type:'auth.failure',source:'lab',occurredAt:new Date(clock).toISOString(),data:{subject:'lab',synthetic:true}}});assert.equal(result.statusCode,403);
});
test('recuperação administrativa exige segredo, revoga sessões e consome código',async()=>{
  const recovery=randomBytes(32).toString('base64url');await db.query('UPDATE private_operator SET recovery_hash=$1 WHERE slot=1',[digest(recovery)]);
  await assert.rejects(recoverOperator(db,key,'wrong'),/inválido/);
  assert.equal((await app.inject({url:'/api/auth/session',headers:headers(sessions.admin)})).statusCode,200);
  const result=await recoverOperator(db,key,recovery);
  assert.equal((await app.inject({url:'/api/auth/session',headers:headers(sessions.admin)})).statusCode,401);
  await assert.rejects(recoverOperator(db,key,recovery),/inválido/);
  const [operator]=await db.query('SELECT * FROM users WHERE id=$1',[users[0].id]);assert.equal(await verifyPassword(operator.password_hash,result.password),true);assert.equal(decrypt(operator.totp_cipher,key,`totp:${users[0].id}`).toString(),result.enrollment.secret);
});
