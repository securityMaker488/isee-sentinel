import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react';
import {date,message,request,text,type Asset,type RecordData,type Session} from './api';
import './operations-view.css';

interface Props {session:Session;assets:Asset[];incidents:RecordData[];onChanged:()=>void}
interface CaseDetail {incident:RecordData;notes:RecordData[];evidence:RecordData[];events:RecordData[];history:RecordData[]}
const names:Record<string,string>={open:'Aberto',investigating:'Em investigação',resolved:'Resolvido',closed:'Encerrado',proposed:'Proposta',approved:'Aprovada',applied:'Cópia atualizada',verified:'Cópia verificada',rolled_back:'Cópia restaurada',manual_review:'Revisão manual',no_change:'Sem alterações'};
const actions:Record<string,string>={'incident.note_added':'Nota registrada','incident.evidence_linked':'Evidência vinculada','incident.status_changed':'Estado alterado','incident.opened':'Incidente aberto'};
const nextStates:Record<string,string[]>={open:['investigating','closed'],investigating:['open','resolved'],resolved:['investigating','closed'],closed:['investigating']};
const records=(value:unknown):RecordData[]=>Array.isArray(value)?value.filter(v=>v&&typeof v==='object'&&!Array.isArray(v)) as RecordData[]:[];
function State({value}:{value:string}){return <span className={`badge ${value==='verified'||value==='rolled_back'?'positive':value==='manual_review'?'warning':'neutral'}`}>{names[value]??value}</span>;}

export function OperationsView({session,assets,incidents,onChanged}:Props) {
  const [section,setSection]=useState<'investigation'|'fix'>('investigation');
  const [plans,setPlans]=useState<RecordData[]>([]),[evidence,setEvidence]=useState<RecordData[]>([]);
  const [caseId,setCaseId]=useState(''),[caseDetail,setCaseDetail]=useState<CaseDetail|null>(null);
  const [plan,setPlan]=useState<RecordData|null>(null),[planId,setPlanId]=useState('');
  const [error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false),[loading,setLoading]=useState(false);
  const [note,setNote]=useState(''),[reviewed,setReviewed]=useState(false),[assetId,setAssetId]=useState('');
  const alive=useRef(true),caseGeneration=useRef(0),planGeneration=useRef(0);
  const admin=session.user.role==='admin',mayReadContent=session.user.role!=='viewer';
  const labAssets=assets.filter(a=>a.environment==='lab');
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;++caseGeneration.current;++planGeneration.current;};},[]);
  const refresh=useCallback(async()=>{
    const result=await Promise.allSettled([request<{items:RecordData[]}>('/remediations'),request<{items:RecordData[]}>('/evidence')]);
    if(!alive.current)return;
    if(result[0].status==='fulfilled')setPlans(result[0].value.items);else setError(message(result[0].reason));
    if(result[1].status==='fulfilled')setEvidence(result[1].value.items);else setError(message(result[1].reason));
  },[]);
  useEffect(()=>{void refresh();},[refresh]);
  async function openCase(id:string) {
    const generation=++caseGeneration.current;setCaseId(id);setCaseDetail(null);setNote('');setLoading(true);setError('');
    try {const value=await request<CaseDetail>(`/incidents/${encodeURIComponent(id)}/case`);if(alive.current&&generation===caseGeneration.current)setCaseDetail(value);}
    catch(err){if(alive.current&&generation===caseGeneration.current)setError(message(err));}
    finally{if(alive.current&&generation===caseGeneration.current)setLoading(false);}
  }
  async function openPlan(id:string) {
    const generation=++planGeneration.current;setPlanId(id);setPlan(null);setReviewed(false);setLoading(true);setError('');
    try {const value=await request<RecordData>(`/remediations/${encodeURIComponent(id)}`);if(alive.current&&generation===planGeneration.current)setPlan(value);}
    catch(err){if(alive.current&&generation===planGeneration.current)setError(message(err));}
    finally{if(alive.current&&generation===planGeneration.current)setLoading(false);}
  }
  async function mutate(path:string,body:unknown,success:string,after:()=>Promise<void>) {
    setBusy(true);setError('');setNotice('');
    try {await request(path,{method:'POST',csrfToken:session.csrfToken,...(body===undefined?{}:{body})});if(!alive.current)return;setNotice(success);await after();onChanged();}
    catch(err){if(alive.current)setError(message(err));}
    finally{if(alive.current)setBusy(false);}
  }
  function submitNote(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();void mutate(`/incidents/${caseId}/notes`,{body:note},'Nota preservada na investigação.',async()=>{await openCase(caseId);});
  }
  function linkEvidence(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();const form=new FormData(event.currentTarget);
    void mutate(`/incidents/${caseId}/evidence`,{evidenceId:form.get('evidenceId')},'Evidência vinculada ao incidente.',()=>openCase(caseId));
  }
  async function createPlan(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();const form=event.currentTarget,data=new FormData(form);setBusy(true);setError('');setNotice('');
    try {const result=await request<RecordData>('/remediations',{method:'POST',csrfToken:session.csrfToken,body:{assetId,name:data.get('name'),content:data.get('content')}});if(!alive.current)return;
      setNotice(text(result,'status')==='manual_review'?'Configuração preservada; a proposta exige revisão manual.':'Original e proposta preservados. Revise as alterações antes de aprovar.');
      form.reset();setAssetId('');await refresh();await openPlan(text(result,'id'));onChanged();
    } catch(err){if(alive.current)setError(message(err));}finally{if(alive.current)setBusy(false);}
  }
  async function downloadCase() {
    setBusy(true);setError('');
    try {
      const report=await request<RecordData>(`/reports/incident/${encodeURIComponent(caseId)}`);if(!alive.current)return;
      const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
      const link=document.createElement('a');link.href=url;link.download=`sentinel-incident-${caseId.replace(/[^a-zA-Z0-9-]/g,'')}.json`;link.click();
      window.setTimeout(()=>URL.revokeObjectURL(url),1000);setNotice('Relatório da investigação exportado.');
    }catch(err){if(alive.current)setError(message(err));}finally{if(alive.current)setBusy(false);}
  }
  const currentStatus=caseDetail?text(caseDetail.incident,'status'):'';
  const planStatus=plan?text(plan,'status'):'';
  const availableEvidence=caseDetail?evidence.filter(item=>text(item,'assetId')===text(caseDetail.incident,'assetId')&&!caseDetail.evidence.some(link=>text(link,'id')===text(item,'id'))):[];
  return <div className="ops-view">
    <div className="ops-tabs" aria-label="Áreas de resposta">
      <button className={`button ${section==='investigation'?'primary':'secondary'}`} aria-pressed={section==='investigation'} onClick={()=>setSection('investigation')}>Investigar incidentes</button>
      <button className={`button ${section==='fix'?'primary':'secondary'}`} aria-pressed={section==='fix'} onClick={()=>setSection('fix')}>SecureFix · cópias de laboratório</button>
    </div>
    {error&&<div className="error-banner" role="alert">{error}</div>}
    {notice&&<div className="info-strip" role="status">{notice}</div>}
    {section==='investigation'?<div className="ops-layout">
      <section className="panel ops-picker" aria-label="Incidentes disponíveis"><div className="panel-header"><h2>Incidentes da empresa</h2><span className="badge neutral">{incidents.length}</span></div>
        {!incidents.length?<div className="ops-empty">Os incidentes detectados aparecerão aqui para investigação.</div>:<div className="ops-selection-list">{incidents.map(item=><button key={text(item,'id')} type="button" className={caseId===text(item,'id')?'selected':''} aria-pressed={caseId===text(item,'id')} disabled={busy} onClick={()=>void openCase(text(item,'id'))}><strong>{text(item,'title')}</strong><span><State value={text(item,'status')}/>{item.synthetic===true&&<span className="badge warning">Simulação</span>}</span><small>{assets.find(a=>a.id===text(item,'assetId'))?.name??'Ativo'} · {date(item.createdAt)}</small></button>)}</div>}
      </section>
      <section className="panel ops-detail" aria-label="Investigação selecionada"><div className="panel-header"><h2>Registro da investigação</h2>{caseDetail&&<State value={currentStatus}/>}</div>
        {loading&&!caseDetail?<div className="ops-empty" role="status">Carregando investigação…</div>:!caseDetail?<div className="ops-empty">Selecione um incidente para consultar eventos, registrar notas e vincular evidências.</div>:<div className="ops-body">
          <h3>{text(caseDetail.incident,'title')}</h3><p className="ops-muted">Estado registrado pelo operador. Resolver o caso não confirma a eliminação da ameaça.</p><button className="button secondary ops-report-button" disabled={busy} onClick={()=>void downloadCase()}>Exportar relatório da investigação</button>
          {admin&&<div className="ops-actions">{(nextStates[currentStatus]??[]).map(status=><button key={status} className="button secondary" disabled={busy} onClick={()=>void mutate(`/incidents/${caseId}/status`,{status},'Estado da investigação atualizado.',()=>openCase(caseId))}>{status==='investigating'&&currentStatus==='closed'?'Reabrir investigação':`Marcar: ${names[status]}`}</button>)}</div>}
          <h3>Eventos de origem</h3>{!caseDetail.events.length?<p className="ops-muted">Nenhum evento original disponível neste registro.</p>:<ul className="ops-event-list">{caseDetail.events.map(item=><li key={text(item,'id')}><strong>{text(item,'type')}</strong><small>{text(item,'source')} · {date(item.occurredAt)}</small>{(item.data as RecordData|undefined)?.synthetic===true&&<span className="badge warning">Evento de simulação</span>}</li>)}</ul>}
          <h3>Notas preservadas</h3>{!caseDetail.notes.length?<p className="ops-muted">Nenhuma nota registrada.</p>:<ul className="ops-note-list">{caseDetail.notes.map(item=><li key={text(item,'id')}><p>{text(item,'body')}</p><small>{date(item.createdAt)}</small></li>)}</ul>}
          {admin&&<form className="ops-form" onSubmit={submitNote}><label htmlFor="ops-note">Nova nota da investigação<textarea id="ops-note" value={note} onChange={event=>setNote(event.target.value)} required maxLength={8000} rows={4} placeholder="Registre o que foi observado e os próximos passos."/></label><button className="button primary" disabled={busy||!note.trim()}>Preservar nota</button></form>}
          <h3>Evidências vinculadas</h3>{!caseDetail.evidence.length?<p className="ops-muted">Nenhuma evidência vinculada.</p>:<ul className="ops-event-list">{caseDetail.evidence.map(item=><li key={text(item,'id')}><strong>{text(item,'name')}</strong><small className="ops-hash" title={text(item,'sha256')}>SHA-256: {text(item,'sha256')}</small><small>Vinculada em {date(item.linkedAt)}</small></li>)}</ul>}
          {admin&&<form className="ops-form" onSubmit={linkEvidence}><label htmlFor="ops-evidence">Evidência do mesmo ativo<select aria-label="Evidência do mesmo ativo" id="ops-evidence" name="evidenceId" required disabled={!availableEvidence.length||busy}><option value="">{availableEvidence.length?'Selecione a evidência':'Nenhuma evidência disponível para vínculo'}</option>{availableEvidence.map(item=><option key={text(item,'id')} value={text(item,'id')}>{text(item,'name')} · {text(item,'sha256').slice(0,12)}</option>)}</select></label><button className="button secondary" disabled={busy||!availableEvidence.length}>Vincular evidência</button></form>}
          <details className="ops-disclosure"><summary>Histórico da investigação ({caseDetail.history.length})</summary><ol className="ops-event-list">{caseDetail.history.map(item=><li key={text(item,'id')}><strong>{actions[text(item,'action')]??text(item,'action')}</strong><small>{date(item.createdAt)}</small>{typeof (item.details as RecordData|undefined)?.status==='string'&&<small>Estado: {names[text(item.details as RecordData,'status')]??text(item.details as RecordData,'status')}</small>}</li>)}</ol></details>
        </div>}
      </section>
    </div>:<>
      <div className="info-strip">SecureFix trabalha com uma cópia de configuração SSH dentro do Sentinel. Aplicar e restaurar aqui não altera o computador nem reinicia o SSH.</div>
      <div className="ops-layout">
        <div className="ops-stack"><section className="panel"><div className="panel-header"><h2>Preparar correção da cópia</h2></div><div className="ops-body">
          {admin?<form className="ops-form" onSubmit={event=>void createPlan(event)}>
            <label htmlFor="ops-asset">Ativo de laboratório<select aria-label="Ativo de laboratório" id="ops-asset" value={assetId} onChange={event=>setAssetId(event.target.value)} required disabled={busy}><option value="">Selecione um ativo</option>{labAssets.map(asset=><option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></label>
            <label htmlFor="ops-name">Nome do artefato<input id="ops-name" name="name" defaultValue="sshd_config" required maxLength={120} pattern="[A-Za-z0-9][A-Za-z0-9._ \-]*" disabled={busy}/></label>
            <label htmlFor="ops-content">Conteúdo da configuração SSH<textarea id="ops-content" name="content" required maxLength={262144} rows={9} spellCheck={false} disabled={busy} placeholder={'Cole a configuração para preservar o original e gerar uma proposta.'}/></label>
            <p className="ops-muted">Exige autorização vigente de análise e importação de evidências. A proposta cobre PermitRootLogin e PasswordAuthentication explícitos. Match, Include e duplicatas exigem revisão manual.</p>
            <button className="button primary" disabled={busy||!labAssets.length}>{busy?'Processando…':'Gerar proposta de correção'}</button>
          </form>:<p className="ops-muted">A criação e aprovação de propostas exige administrador.</p>}
        </div></section>
        <section className="panel ops-picker"><div className="panel-header"><h2>Planos preservados</h2><button className="text-button" disabled={busy} onClick={()=>void refresh()}>Atualizar</button></div>{!plans.length?<div className="ops-empty">Nenhum plano criado nesta empresa.</div>:<div className="ops-selection-list">{plans.map(item=><button key={text(item,'id')} className={planId===text(item,'id')?'selected':''} aria-pressed={planId===text(item,'id')} disabled={busy||!mayReadContent} onClick={()=>void openPlan(text(item,'id'))}><strong>{text(item,'name')}</strong><span><State value={text(item,'status')}/></span><small>{assets.find(a=>a.id===text(item,'assetId'))?.name??'Ativo'} · {date(item.createdAt)}</small></button>)}</div>}</section></div>
        <section className="panel ops-detail" aria-label="Proposta selecionada"><div className="panel-header"><h2>Revisar alterações</h2>{plan&&<State value={planStatus}/>}</div>
          {loading&&!plan?<div className="ops-empty" role="status">Carregando proposta…</div>:!plan?<div className="ops-empty">Crie ou selecione um plano para revisar o patch, aprovar e verificar a cópia. O original permanece preservado para recuperação.</div>:<div className="ops-body">
            <h3>{text(plan,'name')}</h3><p className="ops-muted">{text(plan,'limitation')}</p>
            <div className="ops-hashes"><label>Original<span className="mono">{text(plan,'originalHash')}</span></label><label>Proposta<span className="mono">{text(plan,'proposedHash')}</span></label></div>
            {Array.isArray(plan.reasons)&&plan.reasons.length>0&&<div className="ops-review-notice"><strong>Revisão manual necessária</strong><ul>{plan.reasons.map((reason,index)=><li key={index}>{String(reason)}</li>)}</ul></div>}
            <h3>Alterações propostas</h3>{records(plan.changes).length?<ul className="ops-event-list">{records(plan.changes).map(change=><li key={text(change,'directive')}><strong>{text(change,'directive')}</strong><small>{text(change,'from')} → {text(change,'to')} · linha {text(change,'line')}</small></li>)}</ul>:<p className="ops-muted">Nenhuma alteração automática proposta.</p>}
            <details className="ops-disclosure" open><summary>Patch da configuração</summary><pre className="ops-code">{text(plan,'patch')||'Sem diferenças entre o original e a proposta.'}</pre></details>
            <details className="ops-disclosure"><summary>Conteúdo proposto</summary><pre className="ops-code">{text(plan,'proposedContent')}</pre></details>
            {admin&&<div className="ops-approval">
              {planStatus==='proposed'&&<><label className="ops-checkbox"><input type="checkbox" checked={reviewed} onChange={event=>setReviewed(event.target.checked)} disabled={busy}/> Revisei as alterações nesta cópia de laboratório.</label><button className="button primary" disabled={busy||!reviewed} onClick={()=>void mutate(`/remediations/${planId}/approve`,undefined,'Proposta aprovada para a cópia de laboratório.',async()=>{await refresh();await openPlan(planId);})}>Aprovar proposta</button></>}
              {planStatus==='approved'&&<button className="button primary" disabled={busy} onClick={()=>void mutate(`/remediations/${planId}/apply`,undefined,'Nova revisão criada na cópia de laboratório.',async()=>{await refresh();await openPlan(planId);})}>Aplicar à cópia</button>}
              {planStatus==='applied'&&<button className="button primary" disabled={busy} onClick={()=>void mutate(`/remediations/${planId}/verify`,undefined,'Hash e dois controles SSH verificados na cópia armazenada.',async()=>{await refresh();await openPlan(planId);})}>Verificar cópia</button>}
              {['applied','verified'].includes(planStatus)&&<button className="button secondary" disabled={busy} onClick={()=>void mutate(`/remediations/${planId}/rollback`,undefined,'Cópia restaurada com os bytes originais; histórico preservado.',async()=>{await refresh();await openPlan(planId);})}>Restaurar cópia original</button>}
              {planStatus==='verified'&&<p className="ops-muted">Verificação estática concluída para os dois controles SSH. Isso não confirma a segurança do sistema real nem ausência de outros achados.</p>}
              {planStatus==='rolled_back'&&<p className="ops-muted">O original foi recuperado como nova revisão. Para novas alterações, crie outro plano.</p>}
            </div>}
            <h3>Histórico de revisões</h3><ol className="ops-event-list">{records(plan.revisions).map(item=><li key={text(item,'revision')}><strong>Revisão {text(item,'revision')} · {{import:'Original preservado',apply:'Proposta aplicada à cópia',rollback:'Original recuperado'}[text(item,'action')]??text(item,'action')}</strong><small>{date(item.createdAt)}</small><small className="ops-hash">{text(item,'sha256')}</small></li>)}</ol>
          </div>}
        </section>
      </div>
    </>}
  </div>;
}
