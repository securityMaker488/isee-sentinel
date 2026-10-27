import {useEffect,useMemo,useRef,useState,type FormEvent} from 'react';
import {date,message,request,text,type Asset,type RecordData,type Session} from './api';
import './authorization-view.css';

interface Props {session:Session;assets:Asset[];projects:RecordData[];onChanged:()=>void}
interface Profile {id:string;label:string;operations:string[];minimumRisk:'low'|'moderate';labOnly:boolean;inputKind:'bytes'|'ports';maxInputBytes:number|null;timeoutSeconds:number|null}
interface TargetManifest {version:1;targets:{assetId:string;address:string;ports:number[]}[];exclusions:{address:string}[]}
interface AuthorizationRow {
 id:string;projectId:string;mode:'lab'|'assessment';risk:'low'|'moderate';profiles:string[];
 limits:{maxInputBytes:number;allowedPorts?:number[]};notBefore:string;expiresAt:string;
 status:string;createdAt?:string;approvedAt?:string;revokedAt?:string;requestHash:string;assetIds:string[];
 targetManifest?:TargetManifest|null;
}
interface AuthorizationDetail extends AuthorizationRow {
 responsible:{name:string;role:string;organization:string;contact?:string};purpose:string;
 authority:{channel:'document'|'email'|'whatsapp'|'internal';reference:string};
 authorityEvidenceId:string;authorityEvidenceHash:string;reviewMessage?:string;
 scopes?:{assetId:string;revokedAt?:string|null}[];revocationReason?:string;
}
const states:Record<string,string>={draft:'Rascunho',approved:'Aprovada',revoked:'Revogada'};
const channels:Record<string,string>={document:'Documento ou contrato',email:'E-mail',whatsapp:'WhatsApp',internal:'Autorização interna'};
const environment:Record<string,string>={lab:'Laboratório',staging:'Homologação',production:'Produção'};
function localMinute(time:number){const value=new Date(time);return new Date(value.getTime()-value.getTimezoneOffset()*60000).toISOString().slice(0,16);}
function byteLabel(value:number){return value>=1048576?`${Number((value/1048576).toFixed(3))} MiB`:value>=1024?`${Number((value/1024).toFixed(3))} KiB`:`${value} bytes`;}
function requiredText(form:FormData,name:string,label:string){const value=String(form.get(name)??'').trim();if(!value)throw new Error(`Preencha ${label}.`);return value;}

export default function AuthorizationView({session,assets,projects,onChanged}:Props){
 const [rows,setRows]=useState<AuthorizationRow[]>([]),[catalog,setCatalog]=useState<Profile[]>([]),[detail,setDetail]=useState<AuthorizationDetail|null>(null);
 const [projectId,setProjectId]=useState(''),[assetIds,setAssetIds]=useState<string[]>([]),[profiles,setProfiles]=useState<string[]>([]);
 const [mode,setMode]=useState<'lab'|'assessment'>('lab'),[risk,setRisk]=useState<'low'|'moderate'>('low');
 const [loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[reviewed,setReviewed]=useState(false),[reason,setReason]=useState('');
 const alive=useRef(true),context=useRef(0),listGeneration=useRef(0),detailGeneration=useRef(0);
 const admin=session.user.role==='admin',canReadDetail=admin||session.user.role==='analyst';
 const candidateAssets=useMemo(()=>assets.filter(asset=>asset.projectId===projectId&&(mode!=='lab'||asset.environment==='lab')),[assets,projectId,mode]);
 const chosenProfiles=catalog.filter(profile=>profiles.includes(profile.id));
 const needsPorts=chosenProfiles.some(profile=>profile.inputKind==='ports');
 const projectName=(id:string)=>projects.find(project=>project.id===id)?.name as string|undefined;
 const assetName=(id:string)=>assets.find(asset=>asset.id===id)?.name??id;
 const profileName=(id:string)=>catalog.find(profile=>profile.id===id)?.label??id;

 async function load(){
  const current=++listGeneration.current,scope=context.current;setLoading(true);
  try{const [list,definitions]=await Promise.all([request<{items:AuthorizationRow[]}>('/assessment-authorizations'),request<{items:Profile[]}>('/assessment-authorizations/catalog')]);
   if(alive.current&&current===listGeneration.current&&scope===context.current){setRows(list.items);setCatalog(definitions.items);}
  }catch(err){if(alive.current&&current===listGeneration.current&&scope===context.current)setError(message(err));}
  finally{if(alive.current&&current===listGeneration.current&&scope===context.current)setLoading(false);}
 }
 useEffect(()=>{
  alive.current=true;++context.current;setRows([]);setCatalog([]);setDetail(null);setAssetIds([]);setProfiles([]);setProjectId('');setError('');setNotice('');setReviewed(false);setReason('');void load();
  return()=>{alive.current=false;++context.current;++listGeneration.current;++detailGeneration.current;};
 },[session.user.organizationId]);
 async function inspect(id:string){
  const generation=++detailGeneration.current,scope=context.current;setError('');setReviewed(false);setReason('');setDetail(null);setBusy(true);
  try{const result=await request<AuthorizationDetail>(`/assessment-authorizations/${encodeURIComponent(id)}`);if(alive.current&&generation===detailGeneration.current&&scope===context.current)setDetail(result);}
  catch(err){if(alive.current&&generation===detailGeneration.current&&scope===context.current)setError(message(err));}
  finally{if(alive.current&&generation===detailGeneration.current&&scope===context.current)setBusy(false);}
 }
 function changeMode(value:'lab'|'assessment'){
  setMode(value);setAssetIds([]);setProfiles(previous=>previous.filter(id=>{const profile=catalog.find(item=>item.id===id);return profile&&(!profile.labOnly||value==='lab');}));
 }
 function changeRisk(value:'low'|'moderate'){
  setRisk(value);if(value==='low')setProfiles(previous=>previous.filter(id=>catalog.find(item=>item.id===id)?.minimumRisk==='low'));
 }
 async function create(event:FormEvent<HTMLFormElement>){
  event.preventDefault();const formElement=event.currentTarget,form=new FormData(formElement),scope=context.current;setBusy(true);setError('');setNotice('');
  try{
   if(!projectId||!assetIds.length||assetIds.length>10||assetIds.some(id=>!candidateAssets.some(asset=>asset.id===id)))throw new Error('Selecione um projeto e entre um e dez ativos vinculados a ele.');
   if(!profiles.length||chosenProfiles.length!==profiles.length)throw new Error('Selecione ao menos um teste disponível no catálogo.');
   const maxInputBytes=Number(form.get('maxInputBytes'));if(!Number.isInteger(maxInputBytes)||maxInputBytes<1||maxInputBytes>16777216)throw new Error('O limite por entrada deve ser um número inteiro entre 1 e 16.777.216 bytes.');
   const notBefore=new Date(String(form.get('notBefore'))),expiresAt=new Date(String(form.get('expiresAt')));
   if(!Number.isFinite(notBefore.getTime())||!Number.isFinite(expiresAt.getTime())||notBefore.getTime()<Date.now()-300000||expiresAt.getTime()<=notBefore.getTime()||expiresAt.getTime()<=Date.now()||expiresAt.getTime()>Date.now()+31*86400000)throw new Error('Defina um período válido, com início há no máximo cinco minutos e término futuro em até 31 dias.');
   let allowedPorts:number[]|undefined;
   if(needsPorts){const parts=String(form.get('allowedPorts')??'').split(',').map(value=>value.trim());if(!parts.length||parts.length>16||parts.some(value=>!/^\d{1,5}$/.test(value)||Number(value)<1||Number(value)>65535))throw new Error('Informe entre uma e dezesseis portas TCP, de 1 a 65535, separadas por vírgula.');allowedPorts=parts.map(Number);if(new Set(allowedPorts).size!==allowedPorts.length)throw new Error('Não repita portas na autorização.');}
   let targetManifest:TargetManifest|undefined;
   if(needsPorts){
    const targets:TargetManifest['targets']=[];
    for(const assetId of assetIds){
     const lines=String(form.get(`targets:${assetId}`)??'').trim().split(/\r?\n/);
     for(const line of lines){
      const match=line.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*:\s*(\d{1,5}(?:\s*,\s*\d{1,5})*)$/);
      if(!match)throw new Error(`Informe os alvos de ${assetName(assetId)} no formato IPv4:porta,porta, um por linha.`);
      const ports=match[2].split(',').map(Number);
      if(ports.length>16||new Set(ports).size!==ports.length||ports.some(port=>!allowedPorts!.includes(port)))throw new Error('As portas de cada alvo devem ser únicas e constar nas portas TCP autorizadas.');
      targets.push({assetId,address:match[1],ports});
     }
    }
    const excluded=String(form.get('excludedAddresses')??'').split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
    if(targets.length>100||excluded.length>100)throw new Error('O manifesto aceita até 100 alvos e 100 exclusões.');
    targetManifest={version:1,targets,exclusions:excluded.map(address=>({address}))};
   }
   const file=form.get('evidence');if(!(file instanceof File)||!file.size||file.size>1048576)throw new Error('Selecione uma comprovação de autoridade de até 1 MiB.');
   const responsible={name:requiredText(form,'responsibleName','o nome do responsável'),role:requiredText(form,'responsibleRole','a função do responsável'),organization:requiredText(form,'responsibleOrganization','a empresa do responsável'),...(String(form.get('responsibleContact')??'').trim()?{contact:String(form.get('responsibleContact')).trim()}:{})};
   const purpose=requiredText(form,'purpose','a finalidade da avaliação'),reference=requiredText(form,'authorityReference','a referência da autorização');
   const data=new Uint8Array(await file.arrayBuffer());let binary='';for(let index=0;index<data.length;index+=32768)binary+=String.fromCharCode(...data.subarray(index,index+32768));if(!alive.current||scope!==context.current)return;
   const result=await request<AuthorizationRow>('/assessment-authorizations',{method:'POST',csrfToken:session.csrfToken,body:{projectId,assetIds,mode,risk,profiles,limits:{maxInputBytes,...(allowedPorts?{allowedPorts}:{})},...(targetManifest?{targetManifest}:{}),notBefore:notBefore.toISOString(),expiresAt:expiresAt.toISOString(),responsible,purpose,authority:{channel:form.get('authorityChannel'),reference,evidence:{name:file.name,mediaType:file.type||'application/octet-stream',contentBase64:btoa(binary)}}}});
   if(alive.current&&scope===context.current){formElement.reset();setAssetIds([]);setProfiles([]);setNotice('Rascunho preservado. Revise o responsável, a comprovação, os testes e os limites antes de aprovar.');await load();if(!alive.current||scope!==context.current)return;await inspect(result.id);if(alive.current&&scope===context.current)onChanged();}
  }catch(err){if(alive.current&&scope===context.current)setError(message(err));}
  finally{if(alive.current&&scope===context.current)setBusy(false);}
 }
 async function approve(){
  if(!detail||!reviewed)return;const id=detail.id,scope=context.current;setBusy(true);setError('');setNotice('');
  try{await request(`/assessment-authorizations/${encodeURIComponent(id)}/approve`,{method:'POST',csrfToken:session.csrfToken,body:{requestHash:detail.requestHash,attested:true}});
   if(alive.current&&scope===context.current){setNotice('Autorização aprovada. Os ativos selecionados passam a exigir os testes e limites deste registro.');await load();if(!alive.current||scope!==context.current)return;await inspect(id);if(alive.current&&scope===context.current)onChanged();}
  }catch(err){if(alive.current&&scope===context.current)setError(message(err));}
  finally{if(alive.current&&scope===context.current)setBusy(false);}
 }
 async function revoke(event:FormEvent<HTMLFormElement>){
  event.preventDefault();if(!detail)return;const id=detail.id,scope=context.current;setBusy(true);setError('');setNotice('');
  try{const trimmed=reason.trim();if(!trimmed)throw new Error('Informe o motivo da revogação.');await request(`/assessment-authorizations/${encodeURIComponent(id)}/revoke`,{method:'POST',csrfToken:session.csrfToken,body:{reason:trimmed}});
   if(alive.current&&scope===context.current){setNotice('Autorização revogada. Os escopos anteriores não são reativados.');await load();if(!alive.current||scope!==context.current)return;await inspect(id);if(alive.current&&scope===context.current)onChanged();}
  }catch(err){if(alive.current&&scope===context.current)setError(message(err));}
  finally{if(alive.current&&scope===context.current)setBusy(false);}
 }
 function download(){if(!detail)return;const url=URL.createObjectURL(new Blob([JSON.stringify(detail,null,2)],{type:'application/json'}));const anchor=document.createElement('a');anchor.href=url;anchor.download=`sentinel-authorization-${detail.id}.json`;anchor.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);}
 const activeScopes=detail?.scopes?.filter(scope=>!scope.revokedAt).length;
 const expired=detail?Date.parse(detail.expiresAt)<=Date.now():false;

 return <div className="authorization-view">
  <div className="info-strip"><span>Registre quem autorizou a avaliação, quais ativos podem ser avaliados e os limites de cada operação. Um rascunho preserva a comprovação; a aprovação explícita habilita somente os testes selecionados.</span></div>
  {error&&<p className="form-error" role="alert">{error}</p>}{notice&&<p className="authorization-notice" role="status">{notice}</p>}
  {admin&&<section className="panel section-gap"><div className="panel-header"><h2>Nova autorização de avaliação</h2><span className="badge">RASCUNHO E REVISÃO</span></div>
   <form className="module-form authorization-form" onSubmit={event=>void create(event)}><fieldset disabled={busy||loading} className="authorization-fields"><legend className="authorization-legend">Projeto, responsável e escopo</legend>
    <label>Projeto da autorização<select aria-label="Projeto da autorização" value={projectId} required onChange={event=>{setProjectId(event.target.value);setAssetIds([]);}}><option value="">Selecione um projeto</option>{projects.map(project=><option key={text(project,'id')} value={text(project,'id')}>{text(project,'name')}</option>)}</select></label>
    <div className="module-columns"><label>Modo da avaliação<select aria-label="Modo da avaliação" value={mode} onChange={event=>changeMode(event.target.value as 'lab'|'assessment')}><option value="lab">Laboratório</option><option value="assessment">Avaliação autorizada</option></select></label><label>Risco máximo autorizado<select aria-label="Risco máximo autorizado" value={risk} onChange={event=>changeRisk(event.target.value as 'low'|'moderate')}><option value="low">Baixo</option><option value="moderate">Moderado</option></select></label></div>
    <fieldset className="authorization-choices"><legend>Ativos autorizados · até 10</legend>{candidateAssets.map(asset=><label className="authorization-check" key={asset.id}><input aria-label={`Autorizar ativo ${asset.name}`} type="checkbox" checked={assetIds.includes(asset.id)} disabled={!assetIds.includes(asset.id)&&assetIds.length>=10} onChange={event=>setAssetIds(current=>event.target.checked?[...current,asset.id]:current.filter(id=>id!==asset.id))}/><span>{asset.name}<small>{environment[asset.environment]??asset.environment}</small></span></label>)}{!candidateAssets.length&&<p>{projectId?'Nenhum ativo deste projeto está disponível no modo selecionado.':'Selecione um projeto para consultar os ativos.'} Cadastre o projeto e associe os ativos na área Assets.</p>}</fieldset>
    <div className="module-columns"><label>Responsável pela autorização<input aria-label="Responsável pela autorização" name="responsibleName" required maxLength={120}/></label><label>Função do responsável<input aria-label="Função do responsável" name="responsibleRole" required maxLength={120}/></label></div>
    <div className="module-columns"><label>Empresa do responsável<input aria-label="Empresa do responsável" name="responsibleOrganization" required maxLength={120}/></label><label>Contato do responsável · opcional<input aria-label="Contato do responsável" name="responsibleContact" maxLength={200}/></label></div>
    <label>Finalidade da avaliação<textarea aria-label="Finalidade da avaliação" name="purpose" required maxLength={1000} placeholder="Descreva o objetivo e o contexto desta avaliação."/></label>
    <div className="module-columns"><label>Origem da autorização<select aria-label="Origem da autorização" name="authorityChannel" defaultValue="document">{Object.entries(channels).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label><label>Referência da autorização<input aria-label="Referência da autorização" name="authorityReference" required maxLength={300} placeholder="Contrato, termo ou mensagem identificável"/></label></div>
    <label>Comprovação de autoridade<input aria-label="Comprovação de autoridade" name="evidence" type="file" required aria-describedby="authorization-evidence-help"/></label><p id="authorization-evidence-help">Envie um arquivo de até 1 MiB que comprove a autorização. O original é preservado cifrado. O Sentinel não verifica automaticamente a identidade ou a autoridade jurídica do signatário.</p>
    <fieldset className="authorization-choices"><legend>Testes permitidos</legend>{catalog.map(profile=>{const unavailable=(profile.labOnly&&mode!=='lab')||(profile.minimumRisk==='moderate'&&risk!=='moderate');return <label className="authorization-check" key={profile.id}><input aria-label={`Permitir ${profile.label}`} type="checkbox" checked={profiles.includes(profile.id)} disabled={unavailable} onChange={event=>setProfiles(current=>event.target.checked?[...current,profile.id]:current.filter(id=>id!==profile.id))}/><span>{profile.label}<small>{profile.labOnly?'Somente laboratório. ':''}{profile.minimumRisk==='moderate'?'Exige risco moderado. ':''}{profile.maxInputBytes!==null?`Limite do executor: ${byteLabel(profile.maxInputBytes)}. `:''}{profile.timeoutSeconds!==null?`Prazo do executor: ${profile.timeoutSeconds}s.`:''}</small></span></label>;})}{!catalog.length&&<p>O catálogo precisa estar disponível antes de criar uma autorização.</p>}</fieldset>
    <label>Limite por entrada (bytes)<input aria-label="Limite por entrada (bytes)" name="maxInputBytes" type="number" required min={1} max={16777216} step={1} defaultValue={1048576}/></label><p>1 MiB = 1.048.576 bytes. O menor limite entre esta autorização e o executor será aplicado; esta escolha não aumenta a capacidade de uma ferramenta.</p>
    {needsPorts&&<label>Portas TCP autorizadas<input aria-label="Portas TCP autorizadas" name="allowedPorts" required maxLength={95} placeholder="22,80,443"/><small>Até 16 portas específicas. Não aceita intervalos ou portas repetidas.</small></label>}
    {needsPorts&&<fieldset className="authorization-choices"><legend>Alvos e exclusões do inventário</legend><p>Informe um IPv4 privado ou loopback e as portas de cada alvo, um por linha. Exemplo: 127.0.0.1:80,443. Cada endereço deve fazer parte da autorização; pertencer à rede local não comprova consentimento.</p>{assetIds.map(id=><label key={id}>Alvos de {assetName(id)}<textarea aria-label={`Alvos de ${assetName(id)}`} name={`targets:${id}`} required maxLength={12000} placeholder="127.0.0.1:80,443"/></label>)}<label>Endereços excluídos · opcional<textarea aria-label="Endereços excluídos" name="excludedAddresses" maxLength={1600} placeholder="Um IPv4 por linha"/></label><p>Uma exclusão bloqueia o endereço em todos os ativos deste pedido, mesmo que ele apareça na lista de alvos. Até 100 alvos e 100 exclusões. Alterar essas listas exige novo rascunho e aprovação.</p></fieldset>}
    <div className="module-columns"><label>Início da autorização · horário local<input aria-label="Início da autorização" name="notBefore" type="datetime-local" required defaultValue={localMinute(Date.now())}/></label><label>Fim da autorização · horário local<input aria-label="Fim da autorização" name="expiresAt" type="datetime-local" required defaultValue={localMinute(Date.now()+86400000)}/></label></div>
    <p>O início não pode estar há mais de cinco minutos no passado. O término deve estar no futuro e dentro de 31 dias. Alterar projeto, ativos, testes, risco ou limites exige um novo rascunho e outra aprovação.</p>
    <button className="button primary" disabled={busy||loading||!catalog.length||!projects.length}>{busy?'Processando…':'Salvar rascunho'}</button>
   </fieldset></form>
  </section>}
  <section className="panel section-gap"><div className="panel-header"><h2>Autorizações registradas</h2><button className="button secondary" disabled={busy||loading} onClick={()=>{setError('');void load();}}>{loading?'Consultando…':'Atualizar autorizações'}</button></div>
   <div className="table-scroll"><table><thead><tr><th>Projeto</th><th>Modo</th><th>Estado</th><th>Validade</th><th>Registro</th></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td>{projectName(row.projectId)??row.projectId}<small className="module-small">{row.assetIds.length} ativo(s) selecionado(s)</small></td><td>{row.mode==='lab'?'Laboratório':'Avaliação autorizada'}</td><td>{states[row.status]??row.status}{row.status==='approved'&&Date.parse(row.expiresAt)<=Date.now()&&<small className="module-small">Fora da validade</small>}</td><td>{date(row.notBefore)}<small className="module-small">até {date(row.expiresAt)}</small></td><td>{canReadDetail?<button className="text-button" disabled={busy} onClick={()=>void inspect(row.id)}>Abrir autorização</button>:<span>Metadados disponíveis</span>}</td></tr>)}</tbody></table>{!loading&&!rows.length&&<p className="plain-note">Nenhuma autorização de avaliação registrada nesta empresa.</p>}</div>
  </section>
  {detail&&<section className="panel section-gap" aria-label="Detalhes da autorização"><div className="panel-header"><h2>Revisar autorização</h2><button className="button secondary" onClick={download}>Baixar registro da autorização</button></div><div className="module-form authorization-review">
   <a className="button secondary" href={`/api/evidence/${encodeURIComponent(detail.authorityEvidenceId)}/download`} download>Baixar comprovação de autoridade</a><div className="authorization-summary"><span className="badge">{states[detail.status]??detail.status}</span><span>{detail.mode==='lab'?'Laboratório':'Avaliação autorizada'} · risco {detail.risk==='moderate'?'moderado':'baixo'}</span>{expired&&<strong>Período encerrado</strong>}</div>
   <dl><div><dt>Projeto</dt><dd>{projectName(detail.projectId)??detail.projectId}</dd></div><div><dt>Responsável</dt><dd>{detail.responsible.name} · {detail.responsible.role}<br/>{detail.responsible.organization}{detail.responsible.contact&&<><br/>{detail.responsible.contact}</>}</dd></div><div><dt>Finalidade</dt><dd>{detail.purpose}</dd></div><div><dt>Autoridade registrada</dt><dd>{channels[detail.authority.channel]??detail.authority.channel} · {detail.authority.reference}</dd></div><div><dt>Período</dt><dd>{date(detail.notBefore)} até {date(detail.expiresAt)}</dd></div><div><dt>Limite por entrada</dt><dd>{detail.limits.maxInputBytes.toLocaleString('pt-BR')} bytes · {byteLabel(detail.limits.maxInputBytes)}</dd></div>{detail.limits.allowedPorts&&<div><dt>Portas autorizadas</dt><dd>{detail.limits.allowedPorts.join(', ')}</dd></div>}</dl>
   <div className="module-columns"><div><h3>Ativos selecionados</h3><ul>{detail.assetIds.map(id=><li key={id}>{assetName(id)}</li>)}</ul></div><div><h3>Testes autorizados</h3><ul>{detail.profiles.map(id=><li key={id}>{profileName(id)}</li>)}</ul></div></div>
   {detail.targetManifest?<section aria-label="Manifesto de alvos revisado"><h3>Alvos e exclusões vinculados à aprovação</h3><div className="table-scroll"><table><thead><tr><th>Ativo</th><th>IPv4 exato</th><th>Portas TCP</th><th>Disponibilidade no escopo</th></tr></thead><tbody>{detail.targetManifest.targets.map(target=><tr key={`${target.assetId}:${target.address}`}><td>{assetName(target.assetId)}</td><td>{target.address}</td><td>{target.ports.join(', ')}</td><td>{detail.targetManifest!.exclusions.some(item=>item.address===target.address)?'Bloqueado por exclusão':'Incluído · depende de aprovação e vigência'}</td></tr>)}</tbody></table></div><h3>Exclusões que prevalecem sobre os alvos</h3>{detail.targetManifest.exclusions.length?<ul>{detail.targetManifest.exclusions.map(item=><li key={item.address}>{item.address}</li>)}</ul>:<p>Nenhum endereço explicitamente excluído. Endereços ausentes da lista de alvos continuam bloqueados.</p>}</section>:detail.profiles.includes('lab.inventory')&&<p role="status">Este registro histórico não contém manifesto de alvos. O inventário ativo exige uma nova autorização com endereços e portas revisados.</p>}
   <details><summary>Referências de integridade e histórico</summary><dl className="authorization-hashes"><div><dt>Registro</dt><dd>{detail.id}</dd></div><div><dt>Evidência de autoridade</dt><dd>{detail.authorityEvidenceId}</dd></div><div><dt>SHA-256 da evidência</dt><dd>{detail.authorityEvidenceHash}</dd></div><div><dt>Hash da solicitação revisada</dt><dd>{detail.requestHash}</dd></div><div><dt>Criada</dt><dd>{date(detail.createdAt)}</dd></div>{detail.approvedAt&&<div><dt>Aprovada</dt><dd>{date(detail.approvedAt)}</dd></div>}{detail.revokedAt&&<div><dt>Revogada</dt><dd>{date(detail.revokedAt)}</dd></div>}{detail.revocationReason&&<div><dt>Motivo da revogação</dt><dd>{detail.revocationReason}</dd></div>}</dl><p>O arquivo de comprovação fica preservado no EvidenceChain. O registro JSON exportado inclui os dados do responsável; compartilhe-o somente com destinatários autorizados.</p></details>
   {detail.reviewMessage&&<p>{detail.reviewMessage}</p>}
   {detail.status==='approved'&&<p>{activeScopes===undefined?'Consulte os escopos para verificar quais ativos permanecem autorizados.':`${activeScopes} ativo(s) com escopo não revogado neste registro.`} Vigência e limites continuam sendo verificados em cada operação.</p>}
   {admin&&detail.status==='draft'&&<div className="authorization-approval"><p><strong>Ao aprovar, os escopos anteriores dos ativos selecionados serão revogados.</strong> Esses ativos passarão a exigir uma autorização aprovada deste fluxo. Revogar este registro não reativa permissões anteriores.</p><label className="authorization-check"><input aria-label="Revisei a autoridade, os ativos, os testes e os limites desta autorização" type="checkbox" checked={reviewed} disabled={busy||expired} onChange={event=>setReviewed(event.target.checked)}/><span>Revisei a autoridade do responsável, os ativos, os testes, os limites e, quando aplicável, os endereços e exclusões. Confirmo a substituição dos escopos anteriores.</span></label><button className="button primary" disabled={busy||!reviewed||expired} onClick={()=>void approve()}>Aprovar autorização</button></div>}
   {admin&&detail.status!=='revoked'&&<form className="authorization-revoke" onSubmit={event=>void revoke(event)}><label>Motivo da revogação<textarea aria-label="Motivo da revogação" required maxLength={500} value={reason} disabled={busy} onChange={event=>setReason(event.target.value)}/></label><p>A revogação impede novas operações por este registro. Ela não representa cancelamento instantâneo de processos já iniciados.</p><button className="button secondary" disabled={busy||!reason.trim()}>Revogar autorização</button></form>}
  </div></section>}
 </div>;
}
