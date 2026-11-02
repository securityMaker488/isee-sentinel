const {chromium}=require('playwright');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const OTPAuth=require('otpauth');

// This workflow is limited to the ephemeral synthetic qa:server on loopback.
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
 const mutation=route=>page.waitForResponse(response=>response.url()===`${base}/api${route}`&&response.request().method()==='POST');
 try{
  await page.goto(base);await page.getByLabel('E-mail',{exact:true}).fill(credentials.email);await page.getByLabel('Senha',{exact:true}).fill(credentials.password);
  const otp=new OTPAuth.TOTP({secret:OTPAuth.Secret.fromBase32(credentials.secret),digits:6,period:30});
  for(let attempt=0;attempt<2;attempt++){
   await page.getByLabel('Código do autenticador').fill(otp.generate());const loginResponse=mutation('/auth/login');await page.getByRole('button',{name:'Acessar Command Center'}).click();const login=await loginResponse;if(login.ok())break;
   if(login.status()!==401||attempt===1)throw new Error(`QA login failed (${login.status()})`);
   await new Promise(resolve=>setTimeout(resolve,30000-Date.now()%30000+1000));
  }
  await page.getByRole('heading',{name:'Visão operacional.'}).waitFor();

  const suffix=randomUUID().slice(0,8),organization=await post('/organizations',{name:`QA Arquivos ${suffix}`});
  await post('/context',{organizationId:organization.id});
  const project=await post('/projects',{name:`Importação sintética ${suffix}`,contractRef:'QA-ARCHIVE-SYNTHETIC'});
  const asset=await post('/assets',{name:`Artefato sintético ${suffix}`,kind:'repository',environment:'lab',criticality:2,projectId:project.id});
  const mandate=await post('/assessment-authorizations',{projectId:project.id,assetIds:[asset.id],mode:'lab',risk:'low',profiles:['archive.inspect'],limits:{maxInputBytes:1048576},notBefore:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),responsible:{name:'Responsável sintético QA',role:'Operador de testes',organization:'Organização sintética QA'},purpose:'Inspecionar arquivos sintéticos locais sem extração ou execução.',authority:{channel:'internal',reference:'QA-SYNTHETIC-AUTHORITY',evidence:{name:'synthetic-authority.txt',mediaType:'text/plain',contentBase64:Buffer.from('SYNTHETIC QA ONLY: authorized local fixture.').toString('base64')}}});
  await post(`/assessment-authorizations/${mandate.id}/approve`,{requestHash:mandate.requestHash,attested:true});
  await page.reload();await page.getByRole('heading',{name:'Visão operacional.'}).waitFor();await page.getByRole('button',{name:'Avaliações',exact:true}).click();
  const editor=page.getByRole('region',{name:'Editor de avaliação'}),planName=`Avaliação de arquivos ${suffix}`;
  await editor.getByLabel('Nome da avaliação',{exact:true}).fill(planName);
  await editor.getByLabel('Projeto da avaliação',{exact:true}).selectOption(project.id);
  await editor.getByLabel('Autorização da avaliação',{exact:true}).selectOption(mandate.id);
  await editor.getByLabel('Objetivo da avaliação',{exact:true}).fill('Vincular a inspeção e o original à revisão autorizada.');
  await editor.getByLabel('Nome da etapa 1',{exact:true}).fill('Inspecionar projeto sintético');
  await editor.getByLabel('Ativo da etapa 1',{exact:true}).selectOption(asset.id);
  await editor.getByLabel('Teste da etapa 1',{exact:true}).selectOption('archive.inspect');
  const createdResponse=mutation('/assessment-plans');await editor.getByRole('button',{name:'Criar avaliação',exact:true}).click();const createdHttp=await createdResponse;assert.ok(createdHttp.ok(),await createdHttp.text());const plan=await createdHttp.json(),revision=plan.revisions[0];
  const details=page.getByRole('region',{name:'Detalhes da avaliação'}),execution=details.getByRole('form',{name:'Executar etapa da avaliação'});
  const input=format=>({name:`synthetic.${format}`,mimeType:'application/octet-stream',buffer:Buffer.from(fs.readFileSync(`fixtures/lab/import-project.${format}.base64`,'utf8').trim(),'base64')});
  for(const format of ['zip','tar','tar.gz']){
   await execution.getByLabel('Etapa a executar',{exact:true}).selectOption(revision.steps[0].id);
   await execution.getByLabel('Formato da etapa',{exact:true}).selectOption(format);
   await execution.getByLabel('Arquivo da etapa',{exact:true}).setInputFiles(input(format));
   assert.equal(await execution.getByRole('button',{name:'Executar etapa revisada',exact:true}).isDisabled(),true);
   await execution.getByLabel('Revisei a etapa, o arquivo e a revisão selecionada',{exact:true}).check();
   await execution.getByLabel('Formato da etapa',{exact:true}).selectOption(format==='zip'?'tar':'zip');
   assert.equal(await execution.getByRole('button',{name:'Executar etapa revisada',exact:true}).isDisabled(),true,'format change invalidates review');
   await execution.getByLabel('Formato da etapa',{exact:true}).selectOption(format);await execution.getByLabel('Revisei a etapa, o arquivo e a revisão selecionada',{exact:true}).check();
   const inspected=mutation('/imports');await execution.getByRole('button',{name:'Executar etapa revisada',exact:true}).click();const result=await inspected;assert.ok(result.ok(),await result.text());const body=await result.json();
   const link=details.locator(`a[href="/api/imports/${body.id}"]`);await link.waitFor();const downloaded=page.waitForEvent('download');await link.click();const saved=path.join(qaDir,`archive-${format}-report.json`);await(await downloaded).saveAs(saved);const report=JSON.parse(fs.readFileSync(saved,'utf8'));assert.equal(report.format,format);assert.equal(report.report.input.format,format);assert.equal(report.assessment.revisionHash,revision.hash);assert.equal(report.report.entries.length,3);
   assert.equal((await api(`/evidence/${report.evidenceId}`)).body.integrityVerified,true);
  }
  console.log('PASS real ZIP/TAR/TAR.GZ uploads from plan + explicit review + downloadable exact revision and verified evidence');
  // Rejected bytes must still show the failed job and preserved original in the plan.
  await execution.getByLabel('Etapa a executar',{exact:true}).selectOption(revision.steps[0].id);
  await execution.getByLabel('Formato da etapa',{exact:true}).selectOption('tar');
  await execution.getByLabel('Arquivo da etapa',{exact:true}).setInputFiles({name:'malformed.tar',mimeType:'application/x-tar',buffer:Buffer.from('Synthetic malformed archive')});
  await execution.getByLabel('Revisei a etapa, o arquivo e a revisão selecionada',{exact:true}).check();
  const rejected=mutation('/imports');await execution.getByRole('button',{name:'Executar etapa revisada',exact:true}).click();assert.equal((await rejected).status(),422);
  await details.getByText('Inspecionar projeto sintético · Falhou',{exact:true}).waitFor();assert.equal(await details.getByRole('link',{name:'Baixar registro da inspeção',exact:true}).count(),4);
  console.log('PASS malformed archive refreshes failed result and preserves downloadable inspection record');
  await execution.getByLabel('Etapa a executar',{exact:true}).selectOption(revision.steps[0].id);await execution.getByLabel('Formato da etapa',{exact:true}).selectOption('tar.gz');await page.evaluate(()=>document.activeElement?.blur());
  await page.setViewportSize({width:390,height:844});await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=1);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);await details.screenshot({path:path.join(qaDir,'archive-plan-mobile.png')});await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('button',{name:'Universal Import Lab',exact:true}).click();
  await page.getByLabel('Ativo da importação',{exact:true}).selectOption(asset.id);await page.getByLabel('Formato do arquivo',{exact:true}).selectOption('tar.gz');await page.getByLabel('Projeto compactado',{exact:true}).setInputFiles(input('tar.gz'));
  const imported=mutation('/imports');await page.getByRole('button',{name:'Preservar e inspecionar arquivo',exact:true}).click();assert.equal((await imported).status(),200);await page.getByRole('heading',{name:'Resultado da importação',exact:true}).waitFor();
  assert.equal((await api(`/assessment-plans/${plan.id}`)).body.results.length,4,'ordinary import must not silently attach to plan');
  console.log('PASS standalone TAR.GZ form and mobile plan without horizontal overflow');
  await post(`/assessment-authorizations/${mandate.id}/revoke`,{reason:'Encerramento da inspeção sintética QA.'});
  const denied=await api('/imports',{assetId:asset.id,name:'synthetic.zip',format:'zip',contentBase64:input('zip').buffer.toString('base64'),assessment:{planId:plan.id,revisionId:revision.id,revisionHash:revision.hash,stepId:revision.steps[0].id}});assert.equal(denied.status,403);assert.equal((await api(`/assessment-plans/${plan.id}`)).body.results.length,4);
  // Browsers log HTTP error statuses for the deliberately rejected malformed file.
  assert.deepEqual(errors.filter(message=>!message.includes('422')),[]);console.log('PASS revoked review denies further import; no unexpected browser errors');
 }catch(error){await page.screenshot({path:path.join(qaDir,'archive-failure.png'),fullPage:true});throw error;}
 finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
