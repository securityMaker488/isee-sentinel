import {useEffect,useRef,useState,type FormEvent} from 'react';
import {request,message,date,text,type Asset,type RecordData,type Session} from './api';
export default function ImportView({session,assets,onChanged}:{session:Session;assets:Asset[];onChanged:()=>void}){
 const [runs,setRuns]=useState<RecordData[]>([]),[result,setResult]=useState<RecordData|null>(null),[configured,setConfigured]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');const alive=useRef(true);
 async function load(){const [r,s]=await Promise.all([request<{items:RecordData[]}>('/imports'),request<{configured:boolean}>('/imports/status')]);if(alive.current){setRuns(r.items);setConfigured(s.configured);}}
 useEffect(()=>{alive.current=true;void load().catch(e=>{if(alive.current)setError(message(e));});return()=>{alive.current=false;};},[]);
 async function submit(e:FormEvent<HTMLFormElement>){e.preventDefault();setBusy(true);setError('');const f=new FormData(e.currentTarget);try{
  const file=f.get('file');if(!(file instanceof File)||!file.size||file.size>16777216)throw new Error('Escolha um ZIP de até 16 MiB.');const data=new Uint8Array(await file.arrayBuffer());let raw='';for(let i=0;i<data.length;i+=32768)raw+=String.fromCharCode(...data.subarray(i,i+32768));if(!alive.current)return;
  const r=await request<RecordData>('/imports',{method:'POST',csrfToken:session.csrfToken,timeoutMs:60000,body:{assetId:f.get('assetId'),format:'zip',name:file.name,contentBase64:btoa(raw)}});if(alive.current){setResult(r);onChanged();}
 }catch(e){if(alive.current)setError(message(e));}finally{if(alive.current){setBusy(false);await load().catch(e=>setError(message(e)));}}}
 async function inspect(id:string){try{const r=await request<RecordData>(`/imports/${encodeURIComponent(id)}`);if(alive.current)setResult(r);}catch(e){if(alive.current)setError(message(e));}}
 function download(){if(!result)return;const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`sentinel-import-${text(result,'id')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
 const report=result?.report as RecordData|undefined;
 return <><div className="info-strip"><span>Importação em quarentena · ZIP autorizado. O original permanece cifrado. Os arquivos são inspecionados em memória, sem extração, execução ou acesso à rede. Este passo identifica o conteúdo; não certifica a segurança da aplicação.</span></div>
 {error&&<p role="alert" className="form-error">{error}</p>}
 <section className="panel section-gap"><div className="panel-header"><h2>Importar projeto ZIP</h2><span className="badge">EXPERIMENTAL · QUARENTENA</span></div><form className="module-form" onSubmit={e=>void submit(e)}>
 <label>Ativo da importação<select aria-label="Ativo da importação" name="assetId" required><option value="">Selecione</option>{assets.map(a=><option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
 <label>Projeto ZIP<input aria-label="Projeto ZIP" type="file" accept=".zip,application/zip" name="file" required/></label>
 <p>Até 16 MiB recebidos, 512 entradas e 64 MiB descomprimidos. Exige escopos de importação de evidência e análise vigentes. O projeto é herdado do ativo cadastrado.</p>
 {!configured&&<p>Configure o Python local no servidor para habilitar a inspeção.</p>}
 <button className="button primary" disabled={busy||!configured}>{busy?'Inspecionando…':'Preservar e inspecionar ZIP'}</button></form></section>
 <section className="panel section-gap"><div className="panel-header"><h2>Histórico de importações</h2></div><div className="table-scroll"><table><thead><tr><th>Importação</th><th>Inspeção</th><th>Data</th><th>Registro</th></tr></thead><tbody>{runs.map(r=><tr key={text(r,'id')}><td className="mono">{text(r,'id').slice(0,12)}</td><td>{r.status==='completed'?'Inspecionada · em quarentena':r.status==='failed'?'Falhou · original preservado':text(r,'status')}</td><td>{date(r.createdAt)}</td><td><button className="text-button" onClick={()=>void inspect(text(r,'id'))}>Abrir importação</button></td></tr>)}</tbody></table>{!runs.length&&<p className="plain-note">Nenhum projeto importado nesta empresa.</p>}</div></section>
 {result&&<section className="panel section-gap"><div className="panel-header"><h2>Resultado da importação</h2><button className="button secondary" onClick={download}>Baixar registro da importação</button></div><div className="module-form"><p>Estado: quarentena. Nenhuma aplicação foi iniciada.</p>{!report&&<p>{text(result,'errorCode')||'Inspeção não concluída.'}</p>}{Array.isArray(report?.limitations)&&report.limitations.map((s,i)=><p key={i}>{String(s)}</p>)}</div><pre className="module-report">{JSON.stringify(result,null,2)}</pre></section>}
 <p className="plain-note">URLs, Git, TAR.GZ, instaladores, máquinas virtuais e execução de planos ainda não estão disponíveis neste módulo.</p></>;
}
