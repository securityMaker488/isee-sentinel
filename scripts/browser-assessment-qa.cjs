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
  const suffix=randomUUID().slice(0,8),organization=await post('/organizations',{name:`QA Avaliações ${suffix}`}),other=await post('/organizations',{name:`QA Contexto vazio ${suffix}`});
  await post('/context',{organizationId:organization.id});
  const project=await post('/projects',{name:`Projeto de avaliação ${suffix}`,contractRef:'QA-ASSESSMENT-SYNTHETIC-ONLY'});
  const asset=await post('/assets',{name:`Repositório sintético ${suffix}`,kind:'repository',environment:'lab',criticality:2,projectId:project.id});
  const mandate=await post('/assessment-authorizations',{projectId:project.id,assetIds:[asset.id],mode:'lab',risk:'low',profiles:['static.scan','artifact.analyze'],limits:{maxInputBytes:1048576},notBefore:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),responsible:{name:'Responsável sintético QA',role:'Operador de testes',organization:'Organização sintética QA'},purpose:'Verificar plano e execução integrada com arquivos sintéticos locais.',authority:{channel:'internal',reference:'QA-SYNTHETIC-AUTHORITY',evidence:{name:'synthetic-authority.txt',mediaType:'text/plain',contentBase64:Buffer.from('SYNTHETIC QA ONLY: authorized local fixture.').toString('base64')}}});
  await post(`/assessment-authorizations/${mandate.id}/approve`,{requestHash:mandate.requestHash,attested:true});
  await page.reload();await page.getByRole('heading',{name:'Visão operacional.'}).waitFor();await page.getByRole('button',{name:'Avaliações',exact:true}).click();
  const editor=page.getByRole('region',{name:'Editor de avaliação'}),planName=`Avaliação sintética ${suffix}`;
  await editor.getByLabel('Nome da avaliação',{exact:true}).fill(planName);
  await editor.getByLabel('Projeto da avaliação',{exact:true}).selectOption(project.id);
  await editor.getByLabel('Autorização da avaliação',{exact:true}).selectOption(mandate.id);
  await editor.getByLabel('Objetivo da avaliação',{exact:true}).fill('Preservar a revisão e vincular análise estática ao plano sintético.');
  await editor.getByLabel('Nome da etapa 1',{exact:true}).fill('Verificar configuração SSH');
  await editor.getByLabel('Ativo da etapa 1',{exact:true}).selectOption(asset.id);
  await editor.getByLabel('Teste da etapa 1',{exact:true}).selectOption('static.scan');
  await editor.getByRole('button',{name:'Adicionar etapa',exact:true}).click();
  await editor.getByLabel('Nome da etapa 2',{exact:true}).fill('Planejar análise de artefato');
  await editor.getByLabel('Ativo da etapa 2',{exact:true}).selectOption(asset.id);
  await editor.getByLabel('Teste da etapa 2',{exact:true}).selectOption('artifact.analyze');
  await editor.getByText('Esta etapa pode ser planejada. Seu executor ainda não grava resultados vinculados ao plano.',{exact:true}).waitFor();
  const createdResponse=mutation('/assessment-plans');await editor.getByRole('button',{name:'Criar avaliação',exact:true}).click();const createdHttp=await createdResponse;assert.ok(createdHttp.ok(),await createdHttp.text());const created=await createdHttp.json(),v1=created.revisions[0];
  const details=page.getByRole('region',{name:'Detalhes da avaliação'});
  await details.getByRole('heading',{name:planName,exact:true}).waitFor();assert.equal(v1.steps.length,2);
  assert.equal(await details.getByLabel('Etapa a executar',{exact:true}).locator('option').count(),2,'only placeholder and static.scan may be executed through plan');
  console.log('PASS create immutable plan from approved authorization + supported and planning-only steps clearly separated');
  const execution=details.getByRole('form',{name:'Executar etapa da avaliação'});
  await execution.getByLabel('Etapa a executar',{exact:true}).selectOption(v1.steps[0].id);
  await execution.getByLabel('Caminho relativo do arquivo',{exact:true}).fill('config/sshd_config');
  await execution.getByLabel('Conteúdo autorizado',{exact:true}).fill('PermitRootLogin yes\nPasswordAuthentication yes\n');
  assert.equal(await execution.getByRole('button',{name:'Executar etapa revisada',exact:true}).isDisabled(),true);
  await execution.getByLabel('Revisei a etapa, o arquivo e a revisão selecionada',{exact:true}).check();
  await execution.getByLabel('Conteúdo autorizado',{exact:true}).fill('PermitRootLogin yes\nPasswordAuthentication yes\n# Synthetic assessment fixture\n');
  assert.equal(await execution.getByRole('button',{name:'Executar etapa revisada',exact:true}).isDisabled(),true,'changing reviewed input requires reviewing it again');
  await execution.getByLabel('Revisei a etapa, o arquivo e a revisão selecionada',{exact:true}).check();
  const scanResponse=mutation('/scans');await execution.getByRole('button',{name:'Executar etapa revisada',exact:true}).click();const scanHttp=await scanResponse;assert.ok(scanHttp.ok(),await scanHttp.text());
  await details.getByRole('link',{name:'Baixar análise e hashes das evidências',exact:true}).waitFor();
  const stored=await api(`/assessment-plans/${created.id}`);assert.equal(stored.status,200);assert.equal(stored.body.results.length,1);assert.equal(stored.body.results[0].revisionId,v1.id);assert.equal(stored.body.results[0].evidenceIds.length,1);assert.equal(stored.body.results[0].status,'completed');
  const reportDownload=page.waitForEvent('download');await details.getByRole('button',{name:'Baixar relatório da avaliação',exact:true}).click();const reportPath=path.join(qaDir,'assessment-report.json');await(await reportDownload).saveAs(reportPath);const report=JSON.parse(fs.readFileSync(reportPath,'utf8'));assert.equal(report.assessment.revisions[0].hash,v1.hash);assert.equal(report.assessment.results[0].jobId,stored.body.results[0].jobId);
  const analysisDownload=page.waitForEvent('download');await details.getByRole('link',{name:'Baixar análise e hashes das evidências',exact:true}).click();const analysisPath=path.join(qaDir,'assessment-analysis.json');await(await analysisDownload).saveAs(analysisPath);const analysis=JSON.parse(fs.readFileSync(analysisPath,'utf8'));assert.equal(analysis.evidence.length,1);assert.match(analysis.evidence[0].sha256,/^[0-9a-f]{64}$/);
  await details.screenshot({path:path.join(qaDir,'assessment-completed.png')});
  console.log('PASS reviewed static execution + real job and evidence links + structured plan and analysis exports');
  await details.getByRole('button',{name:'Preparar nova revisão',exact:true}).click();
  assert.equal(await editor.getByLabel('Nome da avaliação',{exact:true}).isDisabled(),true);
  await editor.getByLabel('Objetivo da avaliação',{exact:true}).fill('Reteste planejado após revisão de configuração; resultado anterior permanece histórico.');
  const revisedResponse=mutation(`/assessment-plans/${created.id}/revisions`);await editor.getByRole('button',{name:'Salvar nova revisão',exact:true}).click();const revisedHttp=await revisedResponse;assert.ok(revisedHttp.ok(),await revisedHttp.text());const revised=await revisedHttp.json(),v2=revised.revisions[0];assert.equal(v2.number,2);assert.equal(v2.parentHash,v1.hash);assert.equal(revised.results.length,1);
  await details.getByText('Nenhuma execução vinculada a esta revisão. Planejar uma etapa não registra um teste realizado.',{exact:true}).waitFor();
  await details.getByLabel('Revisão exibida',{exact:true}).selectOption(v1.id);await details.getByRole('link',{name:'Baixar análise e hashes das evidências',exact:true}).waitFor();
  const after=await api(`/assessment-plans/${created.id}`);assert.deepEqual(after.body.revisions.find(item=>item.id===v1.id),v1);
  console.log('PASS new revision preserves old terms/results and does not inherit completed executions');
  // UI-only response fixture: exercise the API's truncation flag without creating 101 scans.
  const detailUrl=`${base}/api/assessment-plans/${created.id}`;
  await page.route(detailUrl,async route=>{const response=await route.fetch(),body=await response.json();await route.fulfill({response,json:{...body,results:[],resultsTruncated:true}});});
  await details.getByRole('button',{name:'Atualizar detalhes e resultados',exact:true}).click();
  await details.getByText('Nenhuma execução desta revisão nos resultados retornados. Há resultados anteriores fora deste recorte.',{exact:true}).waitFor();
  await details.getByText('Exibindo somente as 100 execuções mais recentes do plano. Resultados anteriores permanecem no banco e não estão incluídos nesta consulta ou exportação.',{exact:true}).waitFor();
  assert.equal(await details.getByText('Nenhuma execução vinculada a esta revisão. Planejar uma etapa não registra um teste realizado.',{exact:true}).count(),0);
  const truncatedDownload=page.waitForEvent('download');await details.getByRole('button',{name:'Baixar relatório da avaliação',exact:true}).click();const truncatedPath=path.join(qaDir,'assessment-truncated-ui-fixture.json');await(await truncatedDownload).saveAs(truncatedPath);const truncatedReport=JSON.parse(fs.readFileSync(truncatedPath,'utf8'));assert.equal(truncatedReport.assessment.resultsTruncated,true);assert.equal(truncatedReport.resultCoverage.truncated,true);assert.match(truncatedReport.resultCoverage.notice,/100 execuções/);
  await page.unroute(detailUrl);await details.getByRole('button',{name:'Atualizar detalhes e resultados',exact:true}).click();await details.getByRole('link',{name:'Baixar análise e hashes das evidências',exact:true}).waitFor();
  console.log('PASS truncation response fixture is explicit in UI/export and does not imply an untested revision');
  await page.setViewportSize({width:390,height:844});await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=1);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  assert.equal(await details.locator('.assessment-detail').evaluateAll(elements=>elements.every(element=>[...element.children].every(child=>child.getBoundingClientRect().right<=element.getBoundingClientRect().right+1))),true,'details must fit; tables scroll within their container');
  await details.screenshot({path:path.join(qaDir,'assessment-mobile.png')});console.log('PASS mobile 390px without page or detail overflow');
  await page.setViewportSize({width:1440,height:1000});
  // Hold a detail response from the old organization while changing context.
  let release,started;const held=new Promise(resolve=>{release=resolve;}),intercepted=new Promise(resolve=>{started=resolve;});
  await page.route(`${base}/api/assessment-plans/${created.id}`,async route=>{const response=await route.fetch();started();await held;await route.fulfill({response});});
  await details.getByRole('button',{name:'Atualizar detalhes e resultados',exact:true}).click();await intercepted;
  await page.getByLabel('Empresa em contexto',{exact:true}).selectOption(other.id);
  await page.getByText('Nenhuma avaliação registrada nesta empresa.',{exact:true}).waitFor();release();await page.unrouteAll({behavior:'wait'});
  assert.equal(await page.getByRole('region',{name:'Detalhes da avaliação'}).count(),0);assert.equal(await page.getByRole('heading',{name:planName,exact:true}).count(),0);
  assert.equal(await page.getByLabel('Nome da avaliação',{exact:true}).isEnabled(),true,'new organization must not retain a busy state from the previous request');
  console.log('PASS organization switch discards delayed detail from prior context');
  await post('/context',{organizationId:organization.id});await post(`/assessment-authorizations/${mandate.id}/revoke`,{reason:'Encerramento da avaliação sintética de QA.'});
  const denied=await api('/scans',{assetId:asset.id,files:[{path:'config/sshd_config',content:'PermitRootLogin no\n'}],assessment:{planId:created.id,revisionId:v1.id,revisionHash:v1.hash,stepId:v1.steps[0].id}});assert.equal(denied.status,403);assert.equal((await api(`/assessment-plans/${created.id}`)).body.results.length,1);
  assert.deepEqual(errors,[]);console.log('PASS revoked authorization denies execution without adding result + no JavaScript/console errors');
 }catch(error){await page.screenshot({path:path.join(qaDir,'assessment-failure.png'),fullPage:true});throw error;}
 finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
