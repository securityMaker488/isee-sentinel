const {chromium}=require('playwright');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const OTPAuth=require('otpauth');

// Only the ephemeral, synthetic qa:server database on loopback is supported.
(async()=>{
 const base='http://127.0.0.1:4311',qaDir=path.resolve('.sentinel/qa');
 const credentials=JSON.parse(fs.readFileSync(path.join(qaDir,'browser-session.json'),'utf8'));
 const edgePath='C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
 const browserPath=process.env.SENTINEL_BROWSER_PATH||(fs.existsSync(edgePath)?edgePath:undefined);
 const browser=await chromium.launch({...(browserPath?{executablePath:browserPath}:{}),headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 page.on('console',entry=>{if(entry.type()==='error'&&!entry.text().includes('401'))errors.push(entry.text());});
 async function api(route,body){
  const sessionResponse=await page.request.get(`${base}/api/auth/session`);assert.equal(sessionResponse.status(),200);
  const session=await sessionResponse.json();
  const response=body===undefined?await page.request.get(`${base}/api${route}`):await page.request.post(`${base}/api${route}`,{headers:{Origin:base,'x-csrf-token':session.csrfToken},data:body});
  return {status:response.status(),body:await response.json()};
 }
 async function post(route,body){const result=await api(route,body);assert.ok(result.status>=200&&result.status<300,`${route}: ${JSON.stringify(result)}`);return result.body;}
 const mutation=(suffix)=>page.waitForResponse(response=>response.url()===`${base}/api${suffix}`&&response.request().method()==='POST');
 try{
  await page.goto(base);
  await page.getByLabel('E-mail',{exact:true}).fill(credentials.email);
  await page.getByLabel('Senha',{exact:true}).fill(credentials.password);
  const otp=new OTPAuth.TOTP({secret:OTPAuth.Secret.fromBase32(credentials.secret),digits:6,period:30});
  for(let attempt=0;attempt<2;attempt++){
   await page.getByLabel('Código do autenticador').fill(otp.generate());
   const loginResponse=mutation('/auth/login');
   await page.getByRole('button',{name:'Acessar Command Center'}).click();
   const login=await loginResponse;if(login.ok())break;
   if(login.status()!==401||attempt===1)throw new Error(`QA login failed (${login.status()})`);
   // Consecutive QA runs may reuse a consumed TOTP; preserve replay protection.
   await new Promise(resolve=>setTimeout(resolve,30000-Date.now()%30000+1000));
  }
  await page.getByRole('heading',{name:'Visão operacional.'}).waitFor();
  const suffix=randomUUID().slice(0,8),organization=await post('/organizations',{name:`QA Autorizações ${suffix}`});
  await post('/context',{organizationId:organization.id});
  const project=await post('/projects',{name:`Projeto sintético ${suffix}`,contractRef:'QA-AUTHORITY-SYNTHETIC-ONLY'});
  const asset=await post('/assets',{name:`Ativo sintético ${suffix}`,kind:'repository',environment:'lab',criticality:2,projectId:project.id});
  await post('/authorizations',{assetId:asset.id,operations:['scan','evidence.import'],authorizationRef:'QA-LEGACY-REPLACED',expiresAt:new Date(Date.now()+86400000).toISOString()});
  await page.reload();await page.getByRole('heading',{name:'Visão operacional.'}).waitFor();
  await page.getByRole('button',{name:'Autorizações',exact:true}).click();
  await page.getByLabel('Projeto da autorização',{exact:true}).selectOption(project.id);
  await page.getByLabel(`Autorizar ativo ${asset.name}`,{exact:true}).check();
  await page.getByLabel('Responsável pela autorização',{exact:true}).fill('Responsável sintético QA');
  await page.getByLabel('Função do responsável',{exact:true}).fill('Operador de laboratório');
  await page.getByLabel('Empresa do responsável',{exact:true}).fill('Empresa sintética QA');
  await page.getByLabel('Finalidade da avaliação',{exact:true}).fill('Verificar autorização explícita no banco temporário de QA.');
  await page.getByLabel('Referência da autorização',{exact:true}).fill('QA-SYNTHETIC-AUTHORITY');
  const proof=Buffer.from('SYNTHETIC QA ONLY: permission for local static analysis of this fixture.\n');
  await page.getByLabel('Comprovação de autoridade',{exact:true}).setInputFiles({name:'synthetic-authority.txt',mimeType:'text/plain',buffer:proof});
  await page.getByLabel('Permitir SecureBuild estático',{exact:true}).check();
  await page.getByLabel('Risco máximo autorizado',{exact:true}).selectOption('moderate');
  await page.getByLabel('Permitir Inventário TCP de laboratório',{exact:true}).check();
  await page.getByLabel('Portas TCP autorizadas',{exact:true}).fill('80,443');
  await page.getByLabel(`Alvos de ${asset.name}`,{exact:true}).fill('127.0.0.1:80\n127.0.0.2:443');
  await page.getByLabel('Endereços excluídos',{exact:true}).fill('127.0.0.2');
  await page.getByLabel('Limite por entrada (bytes)',{exact:true}).fill('512');
  const draftResponse=mutation('/assessment-authorizations');
  await page.getByRole('button',{name:'Salvar rascunho',exact:true}).click();
  const draftHttp=await draftResponse;assert.ok(draftHttp.ok());const draft=await draftHttp.json();assert.equal(draft.status,'draft');
  const review=page.getByRole('region',{name:'Detalhes da autorização'});
  await review.getByRole('heading',{name:'Revisar autorização',exact:true}).waitFor();
  const manifest=review.getByRole('region',{name:'Manifesto de alvos revisado'});
  await manifest.getByText('Bloqueado por exclusão',{exact:true}).waitFor();
  assert.equal(await manifest.getByRole('cell',{name:'127.0.0.1',exact:true}).count(),1);
  assert.equal(await review.getByRole('button',{name:'Aprovar autorização',exact:true}).isDisabled(),true);
  const proofDownload=page.waitForEvent('download');
  await review.getByRole('link',{name:'Baixar comprovação de autoridade',exact:true}).click();
  const proofPath=path.join(qaDir,'authorization-proof.bin');await(await proofDownload).saveAs(proofPath);assert.deepEqual(fs.readFileSync(proofPath),proof);
  console.log('PASS draft through UI + proof original download + approval requires review');
  await review.getByLabel('Revisei a autoridade, os ativos, os testes e os limites desta autorização',{exact:true}).check();
  const approvalResponse=mutation(`/assessment-authorizations/${draft.id}/approve`);
  await review.getByRole('button',{name:'Aprovar autorização',exact:true}).click();
  const approvalHttp=await approvalResponse;assert.ok(approvalHttp.ok());assert.equal((await approvalHttp.json()).status,'approved');
  await review.locator('.authorization-summary').getByText('Aprovada',{exact:true}).waitFor();
  const recordDownload=page.waitForEvent('download');await review.getByRole('button',{name:'Baixar registro da autorização',exact:true}).click();
  const recordPath=path.join(qaDir,'authorization-record.json');await(await recordDownload).saveAs(recordPath);
  const record=JSON.parse(fs.readFileSync(recordPath,'utf8'));assert.equal(record.status,'approved');assert.deepEqual(record.profiles,['lab.inventory','static.scan']);assert.equal(record.limits.maxInputBytes,512);
  assert.deepEqual(record.targetManifest,{version:1,targets:[{assetId:asset.id,address:'127.0.0.1',ports:[80]},{assetId:asset.id,address:'127.0.0.2',ports:[443]}],exclusions:[{address:'127.0.0.2'}]});
  assert.equal((await api('/lab/targets',{assetId:asset.id,address:'127.0.0.1',name:'QA approved target'})).status,200);
  assert.equal((await api('/lab/targets',{assetId:asset.id,address:'127.0.0.2',name:'QA excluded target'})).status,403);
  assert.equal((await api('/lab/targets',{assetId:asset.id,address:'127.0.0.3',name:'QA unapproved target'})).status,403);
  console.log('PASS exact target manifest through UI + export + approved registration + exclusions/outside addresses denied; no scan dispatched');
  const scan={assetId:asset.id,files:[{path:'sshd_config',content:'PermitRootLogin yes\n'}]};
  assert.equal((await api('/scans',scan)).status,200);
  assert.equal((await api('/scans',{...scan,files:[{path:'oversized.txt',content:'x'.repeat(513)}]})).status,403);
  assert.equal((await api('/evidence',{assetId:asset.id,name:'denied.txt',mediaType:'text/plain',contentBase64:Buffer.from('synthetic').toString('base64')})).status,403);
  const legacy=await api('/authorizations',{assetId:asset.id,operations:['scan'],authorizationRef:'QA-BYPASS-MUST-FAIL',expiresAt:new Date(Date.now()+86400000).toISOString()});
  assert.equal(legacy.status,403);assert.equal(legacy.body.error.code,'MANAGED_AUTHORIZATION_REQUIRED');
  console.log('PASS reviewed approval + permitted scan + byte limit + profile limit + legacy bypass denied');
  await review.screenshot({path:path.join(qaDir,'authorization-approved.png')});
  await review.getByLabel('Motivo da revogação',{exact:true}).fill('Encerramento do teste sintético QA.');
  const revocationResponse=mutation(`/assessment-authorizations/${draft.id}/revoke`);
  await review.getByRole('button',{name:'Revogar autorização',exact:true}).click();
  const revocationHttp=await revocationResponse;assert.ok(revocationHttp.ok());assert.equal((await revocationHttp.json()).status,'revoked');
  await review.locator('.authorization-summary').getByText('Revogada',{exact:true}).waitFor();assert.equal((await api('/scans',scan)).status,403);
  console.log('PASS revocation through UI + subsequent operation denied');
  await page.setViewportSize({width:390,height:844});
  await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=1);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  assert.equal(await review.locator('.authorization-review').evaluate(element=>[...element.children].every(child=>child.getBoundingClientRect().right<=element.getBoundingClientRect().right+1)),true,'review content must fit its panel; scrolling is confined to the target table');
  await review.screenshot({path:path.join(qaDir,'authorization-mobile.png')});
  assert.deepEqual(errors,[]);console.log('PASS mobile authorization view without overflow + no browser JavaScript/console errors');
 }catch(error){await page.screenshot({path:path.join(qaDir,'authorization-failure.png'),fullPage:true});throw error;}
 finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
