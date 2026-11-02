import {useEffect,useRef,useState,type FormEvent} from 'react';
import {date,message,request,text,type Asset,type RecordData,type Session} from './api';
import './assessment-view.css';

interface Profile {id:string;label:string;planExecutionSupported:boolean;inputKind:'bytes'|'ports'}
interface Mandate {id:string;projectId:string;assetIds:string[];profiles:string[];requestHash:string;status:string;notBefore:string;expiresAt:string;limits:{maxInputBytes:number}}
interface Step {id:string;name:string;assetId:string;profile:string;address?:string;ports?:number[]}
interface Revision {id:string;number:number;hash:string;parentHash:string|null;mandateId:string;authorizationRequestHash:string;objective:string;steps:Step[];createdAt:string}
interface PlanRow {id:string;name:string;projectId:string;createdAt:string;latestRevision:{id:string;number:number;hash:string;mandateId:string;authorizationRequestHash:string}}
interface PlanResult {revisionId:string;stepId:string;jobId:string;kind:string;status:string;evidenceIds:string[];createdAt:string;completedAt:string|null}
interface PlanDetail {id:string;name:string;projectId:string;createdAt:string;revisions:Revision[];results:PlanResult[];resultsTruncated:boolean;limitations:string[]}
interface EditorStep extends Step {portText:string}
interface Props {session:Session;assets:Asset[];projects:RecordData[];onChanged:()=>void}
const statusLabels:Record<string,string>={completed:'Concluída',running:'Em execução',failed:'Falhou',cancelled:'Cancelada'};
const blankStep=(id:string):EditorStep=>({id,name:'',assetId:'',profile:'',portText:''});

export default function AssessmentView({session,assets,projects,onChanged}:Props){
 const [rows,setRows]=useState<PlanRow[]>([]),[profiles,setProfiles]=useState<Profile[]>([]),[mandates,setMandates]=useState<Mandate[]>([]);
 const [detail,setDetail]=useState<PlanDetail|null>(null),[revisionId,setRevisionId]=useState(''),[editorBase,setEditorBase]=useState<PlanDetail|null>(null);
 const [name,setName]=useState(''),[projectId,setProjectId]=useState(''),[mandateId,setMandateId]=useState(''),[objective,setObjective]=useState(''),[steps,setSteps]=useState<EditorStep[]>([blankStep('step-1')]);
 const [busy,setBusy]=useState(false),[loading,setLoading]=useState(true),[error,setError]=useState(''),[notice,setNotice]=useState(''),[reviewed,setReviewed]=useState(false),[executeStep,setExecuteStep]=useState('');
 const alive=useRef(false),context=useRef(0),listGeneration=useRef(0),detailGeneration=useRef(0),stepSequence=useRef(1),editorRef=useRef<HTMLElement>(null);
 const current=(scope:number)=>alive.current&&scope===context.current;
 const admin=session.user.role==='admin',canExecute=admin||session.user.role==='analyst';
 const selectedMandate=mandates.find(item=>item.id===mandateId);
 const revision=detail?.revisions.find(item=>item.id===revisionId);
 const eligibleMandates=mandates.filter(item=>item.projectId===projectId&&item.status==='approved'&&Date.parse(item.notBefore)<=Date.now()&&Date.parse(item.expiresAt)>Date.now());
 const assetName=(id:string)=>assets.find(item=>item.id===id)?.name??id;
 const projectName=(id:string)=>projects.find(item=>text(item,'id')===id)?.name as string|undefined;
 const profileName=(id:string)=>profiles.find(item=>item.id===id)?.label??id;
 const integratedSteps=revision?.steps.filter(step=>profiles.some(profile=>profile.id===step.profile&&profile.planExecutionSupported))??[];
 const archiveStep=integratedSteps.find(step=>step.id===executeStep)?.profile==='archive.inspect';

 async function load(){
  const scope=context.current,generation=++listGeneration.current;setLoading(true);
  try{const [plans,catalog,authorizations]=await Promise.all([request<{items:PlanRow[]}>('/assessment-plans'),request<{profiles:Profile[]}>('/assessment-plans/catalog'),request<{items:Mandate[]}>('/assessment-authorizations')]);
   if(current(scope)&&generation===listGeneration.current){setRows(plans.items);setProfiles(catalog.profiles);setMandates(authorizations.items);}
  }catch(err){if(current(scope)&&generation===listGeneration.current)setError(message(err));}
  finally{if(current(scope)&&generation===listGeneration.current)setLoading(false);}
 }
 function show(value:PlanDetail,preferred?:string){setDetail(value);setRevisionId(value.revisions.some(item=>item.id===preferred)?preferred!:value.revisions[0]?.id??'');setReviewed(false);setExecuteStep('');}
 async function inspect(id:string,preferred?:string){
  const scope=context.current,generation=++detailGeneration.current;setBusy(true);setError('');setReviewed(false);
  try{const value=await request<PlanDetail>(`/assessment-plans/${encodeURIComponent(id)}`);if(current(scope)&&generation===detailGeneration.current)show(value,preferred);}
  catch(err){if(current(scope)&&generation===detailGeneration.current)setError(message(err));}
  finally{if(current(scope)&&generation===detailGeneration.current)setBusy(false);}
 }
 function resetEditor(){setEditorBase(null);setName('');setProjectId('');setMandateId('');setObjective('');setSteps([blankStep('step-1')]);stepSequence.current=1;}
 useEffect(()=>{alive.current=true;++context.current;setBusy(false);setRows([]);setProfiles([]);setMandates([]);setDetail(null);setRevisionId('');setReviewed(false);setExecuteStep('');setError('');setNotice('');resetEditor();void load();return()=>{alive.current=false;++context.current;++listGeneration.current;++detailGeneration.current;};},[session.user.organizationId]);
 function updateStep(index:number,patch:Partial<EditorStep>){setSteps(previous=>previous.map((step,position)=>position===index?{...step,...patch}:step));}
 function revise(){
  if(!detail)return;const latest=detail.revisions[0];if(!latest)return;
  setEditorBase(detail);setName(detail.name);setProjectId(detail.projectId);setMandateId(latest.mandateId);setObjective(latest.objective);setSteps(latest.steps.map(step=>({...step,portText:step.ports?.join(',')??''})));stepSequence.current=latest.steps.length;
  setError('');setNotice('Edite a próxima revisão. As versões anteriores e seus resultados serão preservados.');editorRef.current?.scrollIntoView({behavior:'smooth',block:'start'});
 }
 async function save(event:FormEvent<HTMLFormElement>){
  event.preventDefault();const scope=context.current;setBusy(true);setError('');setNotice('');
  try{
   if(!selectedMandate||!eligibleMandates.some(item=>item.id===selectedMandate.id))throw new Error('Selecione uma autorização aprovada e ainda vigente para este projeto.');
   if(!name.trim()||!objective.trim())throw new Error('Informe o nome e o objetivo da avaliação.');
   const normalized=steps.map(step=>{
    if(!step.name.trim()||!selectedMandate.assetIds.includes(step.assetId)||!selectedMandate.profiles.includes(step.profile))throw new Error('Cada etapa precisa de nome, ativo e perfil permitidos pela autorização selecionada.');
    const profile=profiles.find(item=>item.id===step.profile);if(!profile)throw new Error('O perfil selecionado não está disponível.');
    let ports:number[]|undefined;
    if(profile.inputKind==='ports'){
     const values=step.portText.split(',').map(value=>value.trim());if(!step.address?.trim()||!values.length||values.length>16||values.some(value=>!/^\d{1,5}$/.test(value)||Number(value)<1||Number(value)>65535))throw new Error('Informe o endereço e de uma a dezesseis portas autorizadas para o inventário.');
     ports=values.map(Number);if(new Set(ports).size!==ports.length)throw new Error('Não repita portas na etapa.');
    }
    return {id:step.id,name:step.name.trim(),assetId:step.assetId,profile:step.profile,...(ports?{address:step.address!.trim(),ports}:{})};
   });
   const body={mandateId:selectedMandate.id,authorizationRequestHash:selectedMandate.requestHash,objective:objective.trim(),steps:normalized};
   const result=await request<PlanDetail>(editorBase?`/assessment-plans/${encodeURIComponent(editorBase.id)}/revisions`:'/assessment-plans',{method:'POST',csrfToken:session.csrfToken,body:editorBase?{...body,parentHash:editorBase.revisions[0].hash}:{...body,name:name.trim(),projectId}});
   if(!current(scope))return;show(result);resetEditor();setNotice('Revisão preservada. O plano organiza os testes; cada execução continua sujeita à autorização vigente.');await load();
  }catch(err){if(current(scope))setError(message(err));}
  finally{if(current(scope))setBusy(false);}
 }
 async function execute(event:FormEvent<HTMLFormElement>){
  event.preventDefault();if(!detail||!revision)return;const scope=context.current,form=event.currentTarget,data=new FormData(form),selected=integratedSteps.find(step=>step.id===executeStep);setBusy(true);setError('');setNotice('');
  try{
   if(!selected||!['static.scan','archive.inspect'].includes(selected.profile)||!reviewed)throw new Error('Selecione a etapa e confirme a revisão antes de iniciar.');
   const assessment={planId:detail.id,revisionId:revision.id,revisionHash:revision.hash,stepId:selected.id};
   if(selected.profile==='archive.inspect'){
    const file=data.get('archive');if(!(file instanceof File)||!file.size||file.size>16777216)throw new Error('Selecione um ZIP, TAR ou TAR.GZ autorizado de até 16 MiB.');
    const bytes=new Uint8Array(await file.arrayBuffer());let raw='';for(let offset=0;offset<bytes.length;offset+=32768)raw+=String.fromCharCode(...bytes.subarray(offset,offset+32768));
    if(!current(scope))return;
    await request('/imports',{method:'POST',csrfToken:session.csrfToken,timeoutMs:60000,body:{assetId:selected.assetId,name:file.name,format:data.get('archiveFormat'),contentBase64:btoa(raw),assessment}});
   }else{
    const path=String(data.get('path')??'').trim(),content=String(data.get('content')??'');if(!path||!content)throw new Error('Informe o caminho relativo e o conteúdo do arquivo autorizado.');
    if(new TextEncoder().encode(content).length>262144)throw new Error('Este formulário aceita um arquivo de até 256 KiB por execução.');
    await request('/scans',{method:'POST',csrfToken:session.csrfToken,body:{assetId:selected.assetId,files:[{path,content}],assessment}});
   }
   if(!current(scope))return;form.reset();setNotice('Análise concluída. A execução e as evidências foram vinculadas à revisão selecionada.');onChanged();await inspect(detail.id,revision.id);await load();
  }catch(err){if(current(scope)){await inspect(detail.id,revision.id);if(current(scope)){setReviewed(false);setError(message(err));}}}
  finally{if(current(scope))setBusy(false);}
 }
 function download(){
  if(!detail)return;const report={schemaVersion:1,exportedAt:new Date().toISOString(),product:'I.See Sentinel',assessment:detail,resultCoverage:{limit:100,truncated:detail.resultsTruncated,notice:detail.resultsTruncated?'Este relatório contém somente as 100 execuções mais recentes do plano. A ausência de uma revisão neste recorte não comprova ausência de execução.':'Este relatório contém os resultados retornados na consulta do plano.'},basis:'Resultados vinculados somente por execução integrada. A presença de uma etapa no plano não comprova sua execução.'};
  const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'})),anchor=document.createElement('a');anchor.href=url;anchor.download=`sentinel-assessment-${detail.id}.json`;anchor.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);
 }

 return <div className="assessment-view">
  <div className="info-strip"><span>Organize uma avaliação por etapas, preserve cada revisão e acompanhe seus resultados. O plano usa uma autorização já aprovada. Cada execução verifica novamente seu escopo e sua validade.</span></div>
  {error&&<p role="alert" className="form-error">{error}</p>}{notice&&<p role="status" className="assessment-notice">{notice}</p>}
  {admin&&<section ref={editorRef} className="panel section-gap" aria-label="Editor de avaliação"><div className="panel-header"><h2>{editorBase?'Nova revisão da avaliação':'Nova avaliação'}</h2>{editorBase&&<button type="button" className="button secondary" disabled={busy} onClick={resetEditor}>Cancelar edição</button>}</div>
   <form className="module-form assessment-form" onSubmit={event=>void save(event)}><fieldset disabled={busy||loading} className="assessment-fields">
    <label>Nome da avaliação<input aria-label="Nome da avaliação" value={name} onChange={event=>setName(event.target.value)} required maxLength={120} disabled={Boolean(editorBase)}/></label>
    <label>Projeto da avaliação<select aria-label="Projeto da avaliação" value={projectId} required disabled={Boolean(editorBase)} onChange={event=>{setProjectId(event.target.value);setMandateId('');setSteps([blankStep('step-1')]);stepSequence.current=1;}}><option value="">Selecione um projeto</option>{projects.map(project=><option key={text(project,'id')} value={text(project,'id')}>{text(project,'name')}</option>)}</select></label>
    <label>Autorização da avaliação<select aria-label="Autorização da avaliação" value={mandateId} required onChange={event=>{setMandateId(event.target.value);setSteps(previous=>previous.map(step=>({...step,assetId:'',profile:'',address:'',portText:''})));}}><option value="">Selecione uma autorização aprovada</option>{eligibleMandates.map(item=><option key={item.id} value={item.id}>{item.id.slice(0,8)} · {item.assetIds.length} ativo(s) · até {date(item.expiresAt)}</option>)}</select></label>
    {!eligibleMandates.length&&<p>Crie e aprove uma autorização na área Autorizações para o projeto selecionado. As etapas devem permanecer dentro dos ativos e perfis dessa autorização.</p>}
    {selectedMandate&&<p>Referência revisada: <code className="assessment-hash">{selectedMandate.requestHash}</code>Limite por entrada: {selectedMandate.limits.maxInputBytes.toLocaleString('pt-BR')} bytes. A autorização também será verificada no servidor.</p>}
    <label>Objetivo da avaliação<textarea aria-label="Objetivo da avaliação" value={objective} onChange={event=>setObjective(event.target.value)} required maxLength={2000}/></label>
    <fieldset className="assessment-steps"><legend>Etapas da avaliação · até 25</legend>{steps.map((step,index)=><div className="assessment-step" key={step.id}>
     <div className="assessment-step-head"><strong>Etapa {index+1}</strong>{steps.length>1&&<button type="button" className="text-button" aria-label={`Remover etapa ${index+1}`} onClick={()=>setSteps(previous=>previous.filter(item=>item.id!==step.id))}>Remover</button>}</div>
     <label>Nome da etapa {index+1}<input aria-label={`Nome da etapa ${index+1}`} value={step.name} required maxLength={160} onChange={event=>updateStep(index,{name:event.target.value})}/></label>
     <div className="module-columns"><label>Ativo da etapa {index+1}<select aria-label={`Ativo da etapa ${index+1}`} value={step.assetId} required onChange={event=>updateStep(index,{assetId:event.target.value})}><option value="">Selecione um ativo</option>{assets.filter(asset=>asset.projectId===projectId&&selectedMandate?.assetIds.includes(asset.id)).map(asset=><option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></label>
      <label>Teste da etapa {index+1}<select aria-label={`Teste da etapa ${index+1}`} value={step.profile} required onChange={event=>updateStep(index,{profile:event.target.value,address:'',portText:''})}><option value="">Selecione um teste</option>{profiles.filter(profile=>selectedMandate?.profiles.includes(profile.id)).map(profile=><option key={profile.id} value={profile.id}>{profile.label}{profile.planExecutionSupported?'':' · planejamento'}</option>)}</select></label></div>
     {step.profile&&!profiles.find(profile=>profile.id===step.profile)?.planExecutionSupported&&<p>Esta etapa pode ser planejada. Seu executor ainda não grava resultados vinculados ao plano.</p>}
     {profiles.find(profile=>profile.id===step.profile)?.inputKind==='ports'&&<div className="module-columns"><label>Endereço da etapa {index+1}<input aria-label={`Endereço da etapa ${index+1}`} value={step.address??''} maxLength={15} required onChange={event=>updateStep(index,{address:event.target.value})}/></label><label>Portas da etapa {index+1}<input aria-label={`Portas da etapa ${index+1}`} value={step.portText} maxLength={95} required placeholder="80,443" onChange={event=>updateStep(index,{portText:event.target.value})}/></label></div>}
    </div>)}<button type="button" className="button secondary" disabled={steps.length>=25} onClick={()=>{let id:string;do{id=`step-${++stepSequence.current}`;}while(steps.some(step=>step.id===id));setSteps(previous=>[...previous,blankStep(id)]);}}>Adicionar etapa</button></fieldset>
    {editorBase&&<p>Base: revisão {editorBase.revisions[0].number}. Se outra revisão for salva antes desta, será necessário atualizar e revisar novamente.</p>}
    <button className="button primary" disabled={busy||loading||!selectedMandate}>{busy?'Salvando…':editorBase?'Salvar nova revisão':'Criar avaliação'}</button>
   </fieldset></form>
  </section>}
  <section className="panel section-gap"><div className="panel-header"><h2>Avaliações registradas</h2><button className="button secondary" disabled={loading||busy} onClick={()=>{setError('');void load();}}>{loading?'Consultando…':'Atualizar avaliações'}</button></div><div className="table-scroll"><table><thead><tr><th>Avaliação</th><th>Projeto</th><th>Revisão atual</th><th>Registro</th></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td>{row.name}<small className="module-small">{date(row.createdAt)}</small></td><td>{projectName(row.projectId)??row.projectId}</td><td>{row.latestRevision.number}</td><td><button type="button" className="text-button" disabled={busy} onClick={()=>void inspect(row.id)}>Abrir avaliação</button></td></tr>)}</tbody></table>{!rows.length&&!loading&&<p className="plain-note">Nenhuma avaliação registrada nesta empresa.</p>}</div></section>
  {detail&&revision&&<section className="panel section-gap" aria-label="Detalhes da avaliação"><div className="panel-header"><div><span className="eyebrow">AVALIAÇÃO VERSIONADA</span><h2>{detail.name}</h2></div><div className="assessment-actions"><button className="button secondary" disabled={busy} onClick={download}>Baixar relatório da avaliação</button>{admin&&<button className="button secondary" disabled={busy||detail.revisions.length>=100} onClick={revise}>Preparar nova revisão</button>}</div></div>
   <div className="module-form assessment-detail"><label>Revisão exibida<select aria-label="Revisão exibida" disabled={busy} value={revisionId} onChange={event=>{setRevisionId(event.target.value);setReviewed(false);setExecuteStep('');}}>{detail.revisions.map(item=><option key={item.id} value={item.id}>Revisão {item.number} · {date(item.createdAt)}</option>)}</select></label>
    <dl><div><dt>Projeto</dt><dd>{projectName(detail.projectId)??detail.projectId}</dd></div><div><dt>Revisão preservada</dt><dd>{revision.number} de {detail.revisions.length}</dd></div><div><dt>Objetivo</dt><dd>{revision.objective}</dd></div><div><dt>Autorização vinculada</dt><dd>{revision.mandateId}</dd></div><div><dt>SHA-256 da revisão</dt><dd className="assessment-hash">{revision.hash}</dd></div><div><dt>SHA-256 da autorização</dt><dd className="assessment-hash">{revision.authorizationRequestHash}</dd></div></dl>
    <div className="table-scroll"><table><thead><tr><th>Etapa</th><th>Ativo</th><th>Teste</th><th>Vínculo de execução</th></tr></thead><tbody>{revision.steps.map(step=><tr key={step.id}><td>{step.name}<small className="module-small">{step.id}</small></td><td>{assetName(step.assetId)}{step.address&&<small className="module-small">{step.address}:{step.ports?.join(',')}</small>}</td><td>{profileName(step.profile)}</td><td>{profiles.find(profile=>profile.id===step.profile)?.planExecutionSupported?'Disponível neste plano':'Planejamento; vínculo pendente'}</td></tr>)}</tbody></table></div>
    <section aria-label="Resultados da revisão"><h3>Resultados da revisão {revision.number}</h3>{detail.resultsTruncated&&<p role="status" className="assessment-result-limit">Exibindo somente as 100 execuções mais recentes do plano. Resultados anteriores permanecem no banco e não estão incluídos nesta consulta ou exportação.</p>}{detail.results.filter(result=>result.revisionId===revision.id).map(result=><article className="assessment-result" key={result.jobId}><strong>{revision.steps.find(step=>step.id===result.stepId)?.name??result.stepId} · {statusLabels[result.status]??result.status}</strong><p>Execução <code>{result.jobId}</code></p><p>{date(result.createdAt)}{result.completedAt?` · finalizada em ${date(result.completedAt)}`:''}</p><p>{result.evidenceIds.length} evidência(s) preservada(s)</p>{result.evidenceIds.length>0&&<ul>{result.evidenceIds.map(id=><li key={id}><code>{id}</code></li>)}</ul>}{result.kind?.startsWith('import.')?<a href={`/api/imports/${encodeURIComponent(result.jobId)}`} className="text-button" download>Baixar registro da inspeção</a>:result.status==='completed'&&<a href={`/api/reports/${encodeURIComponent(result.jobId)}`} className="text-button" download>Baixar análise e hashes das evidências</a>}</article>)}{!detail.results.some(result=>result.revisionId===revision.id)&&<p>{detail.resultsTruncated?'Nenhuma execução desta revisão nos resultados retornados. Há resultados anteriores fora deste recorte.':'Nenhuma execução vinculada a esta revisão. Planejar uma etapa não registra um teste realizado.'}</p>}</section>
   </div>
   {canExecute&&integratedSteps.length>0&&<form className="module-form assessment-detail assessment-execute" aria-label="Executar etapa da avaliação" onSubmit={event=>void execute(event)}><fieldset className="assessment-fields" disabled={busy}>
    <h3>Executar etapa autorizada</h3><p>{!executeStep?'Selecione uma etapa para informar o arquivo autorizado.':archiveStep?'Envie um ZIP, TAR ou TAR.GZ autorizado de até 16 MiB. O original permanece em quarentena, mesmo se a inspeção falhar.':'Envie o conteúdo de um arquivo autorizado, até 256 KiB.'} O limite da autorização também é aplicado. O conteúdo não é executado nem enviado à rede.</p>
    <label>Etapa a executar<select aria-label="Etapa a executar" required value={executeStep} onChange={event=>{setExecuteStep(event.target.value);setReviewed(false);}}><option value="">Selecione uma etapa</option>{integratedSteps.map(step=><option key={step.id} value={step.id}>{step.name} · {assetName(step.assetId)}</option>)}</select></label>
    {executeStep&&(archiveStep?<><label>Formato da etapa<select aria-label="Formato da etapa" name="archiveFormat" required onChange={()=>setReviewed(false)}><option value="zip">ZIP</option><option value="tar">TAR (USTAR)</option><option value="tar.gz">TAR.GZ (USTAR + gzip)</option></select></label><label>Arquivo da etapa<input aria-label="Arquivo da etapa" name="archive" type="file" accept=".zip,.tar,.tar.gz,.tgz,application/zip,application/x-tar,application/gzip" required onChange={()=>setReviewed(false)}/></label></>:<><label>Caminho relativo do arquivo<input aria-label="Caminho relativo do arquivo" name="path" required maxLength={240} placeholder="config/sshd_config" onChange={()=>setReviewed(false)}/></label><label>Conteúdo autorizado<textarea aria-label="Conteúdo autorizado" name="content" required maxLength={262144} spellCheck={false} onChange={()=>setReviewed(false)}/></label></>)}
    <label className="assessment-check"><input type="checkbox" aria-label="Revisei a etapa, o arquivo e a revisão selecionada" checked={reviewed} onChange={event=>setReviewed(event.target.checked)}/><span>Revisei a etapa, o arquivo e a revisão {revision.number} selecionada. A autorização vinculada deve permanecer válida.</span></label>
    <button className="button primary" disabled={busy||!reviewed||!executeStep}>{busy?'Analisando…':'Executar etapa revisada'}</button>
   </fieldset></form>}
   <div className="module-form assessment-detail">{detail.limitations.map((limitation,index)=><p key={index}>{limitation}</p>)}<button className="button secondary" disabled={busy} onClick={()=>void inspect(detail.id,revision.id)}>Atualizar detalhes e resultados</button></div>
  </section>}
 </div>;
}
