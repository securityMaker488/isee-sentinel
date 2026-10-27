import {execFile} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdtemp,writeFile,unlink,rmdir,stat,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,dirname,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import type {FastifyInstance} from 'fastify';
import type {Database} from './db.ts';
import {HttpError,object,str,uuid} from './auth.ts';
import {permit,scoped} from './policy.ts';
import {digest,encrypt} from './security.ts';
import {audit} from './audit.ts';

export type ForensicKind='pcap'|'sqlite'|'plist';
export type ForensicRunner=(options:{pythonPath:string;file:string;kind:ForensicKind;table?:string})=>Promise<Buffer>;
const worker=fileURLToPath(new URL('../../../workers/forensics/analyze_artifact.py',import.meta.url));
const limit=16*1024*1024,outputLimit=4*1024*1024;
export const runForensicWorker:ForensicRunner=async({pythonPath,file,kind,table})=>{
 if(!isAbsolute(pythonPath))throw new HttpError(503,'PYTHON_UNAVAILABLE','Configure o executável Python local.');
 // Resolve the operator-configured interpreter once, as the archive worker does.
 // Standard Linux Python installations commonly expose python3 through a symlink.
 let executable:string;try{executable=await realpath(pythonPath);if(!(await stat(executable)).isFile())throw new Error('invalid');}catch{throw new HttpError(503,'PYTHON_UNAVAILABLE','Executável Python local indisponível.');}
 const env:NodeJS.ProcessEnv={};for(const name of ['SystemRoot','WINDIR','TEMP','TMP','LANG','LC_ALL'])if(process.env[name])env[name]=process.env[name];
 const args=['-I','-B',worker,'--consent','--file',file,'--kind',kind,...(table?['--table',table]:[])];
 return new Promise((accept,reject)=>{const child=execFile(executable,args,{shell:false,windowsHide:true,timeout:60000,killSignal:'SIGKILL',maxBuffer:outputLimit,encoding:'buffer',cwd:dirname(worker),env},(error,stdout)=>{
  if(error){const e=error as any;reject(new HttpError(e.code==='ENOENT'?503:422,e.killed?'WORKER_TIMEOUT':'WORKER_REJECTED','O worker não concluiu a análise. Confira formato, tamanho e configuração; o original permanece preservado.'));return;}
  accept(Buffer.from(stdout));
 });child.stdin?.end();});
};

const select='SELECT r.id,r.asset_id AS "assetId",r.kind,r.evidence_id AS "evidenceId",r.created_at AS "createdAt",r.error_code AS "errorCode",j.status,j.completed_at AS "completedAt",r.report FROM forensic_runs r JOIN jobs j ON j.id=r.id';
export async function registerForensics(app:FastifyInstance,{db,masterKey,now=Date.now,pythonPath,runner=runForensicWorker}:{db:Database;masterKey:Buffer;now?:()=>number;pythonPath?:string;runner?:ForensicRunner}){
 let busy=false;
 app.get('/api/forensics/status',async request=>{permit(request,'findings.read');return {configured:!!pythonPath&&isAbsolute(pythonPath),maxBytes:limit,timeoutSeconds:60,kind:['pcap','sqlite','plist'],valuesExported:false};});
 app.get('/api/forensics',async request=>{permit(request,'findings.read');return {items:await db.query('SELECT r.id,r.asset_id AS "assetId",r.kind,r.evidence_id AS "evidenceId",r.created_at AS "createdAt",r.error_code AS "errorCode",j.status,r.report->>\'summary\' AS summary FROM forensic_runs r JOIN jobs j ON j.id=r.id WHERE r.organization_id=$1 ORDER BY r.created_at DESC LIMIT 100',[request.actor!.organizationId])};});
 app.get('/api/forensics/:id',{schema:{params:object({id:uuid})}},async request=>{permit(request,'reports.read');const a=request.actor!,id=(request.params as any).id;const [r]=await db.query(`${select} WHERE r.organization_id=$1 AND r.id=$2`,[a.organizationId,id]);if(!r)throw new HttpError(404,'NOT_FOUND','Análise forense não encontrada.');await db.transaction(tx=>audit(tx,a.organizationId,a.id,'forensic.report_viewed',id));return r;});
 app.post('/api/forensics',{bodyLimit:24*1024*1024,schema:{body:object({assetId:uuid,kind:{enum:['pcap','sqlite','plist']},name:str(240),table:str(240),contentBase64:{type:'string',minLength:4,maxLength:22369624}},['assetId','kind','name','contentBase64'])}},async request=>{
  const a=request.actor!,b=request.body as {assetId:string;kind:ForensicKind;name:string;table?:string;contentBase64:string};
  if(b.table&&b.kind!=='sqlite')throw new HttpError(400,'INVALID_TABLE','Tabela só se aplica a SQLite.');
  const bytes=Buffer.from(b.contentBase64,'base64');if(!bytes.length||bytes.length>limit||bytes.toString('base64')!==b.contentBase64)throw new HttpError(400,'INVALID_FILE','Arquivo base64 canônico de até 16 MiB obrigatório.');
  const execution={profile:'forensic.analyze',inputBytes:bytes.length};
  await scoped(db,request,'scan',b.assetId,now,execution);await scoped(db,request,'evidence.import',b.assetId,now,execution);
  if(!pythonPath||!isAbsolute(pythonPath))throw new HttpError(503,'PYTHON_UNAVAILABLE','Worker Python não configurado.');
  if(busy)throw new HttpError(409,'WORKER_BUSY','Há uma análise forense em andamento.');busy=true;
  const id=randomUUID(),evidenceId=randomUUID(),sha256=digest(bytes);let started=false,folder:string|undefined;
  try{
   await db.transaction(async tx=>{
    const [lock]=await tx.query('SELECT l.job_id,j.status FROM forensic_execution_lock l JOIN jobs j ON j.id=l.job_id WHERE l.slot=1 FOR UPDATE OF l');
    if(lock?.status==='running')throw new HttpError(409,'WORKER_BUSY','Há uma análise forense em andamento.');
    if(lock)await tx.query('DELETE FROM forensic_execution_lock WHERE slot=1 AND job_id=$1',[lock.job_id]);
    await tx.query("INSERT INTO jobs(id,organization_id,asset_id,kind,status) VALUES($1,$2,$3,'forensics','running')",[id,a.organizationId,b.assetId]);
    const acquired=await tx.query('INSERT INTO forensic_execution_lock(slot,job_id) VALUES(1,$1) ON CONFLICT DO NOTHING RETURNING slot',[id]);if(!acquired.length)throw new HttpError(409,'WORKER_BUSY','Há uma análise forense em andamento.');
    await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[evidenceId,a.organizationId,b.assetId,b.name,'application/octet-stream',sha256,bytes.length,encrypt(bytes,masterKey,`evidence:${a.organizationId}:${evidenceId}`),a.id,`forensics:${id}`]);
    await tx.query('INSERT INTO forensic_runs(id,organization_id,asset_id,kind,evidence_id) VALUES($1,$2,$3,$4,$5)',[id,a.organizationId,b.assetId,b.kind,evidenceId]);
    await audit(tx,a.organizationId,a.id,'forensic.started',id,{kind:b.kind,assetId:b.assetId,evidenceId,sha256,bytes:bytes.length});
   });started=true;
   folder=await mkdtemp(join(tmpdir(),'sentinel-forensic-'));const input=join(folder,`input.${b.kind}`);
   await writeFile(input,bytes,{flag:'wx',mode:0o600});
   await scoped(db,request,'scan',b.assetId,now,execution);await scoped(db,request,'evidence.import',b.assetId,now,execution);
   const output=await runner({pythonPath,file:input,kind:b.kind,table:b.table});if(output.length>outputLimit)throw new HttpError(422,'WORKER_OUTPUT_LIMIT','Resultado excede o limite.');
   let report:any;try{report=JSON.parse(output.toString('utf8'));}catch{throw new HttpError(422,'INVALID_WORKER_REPORT','Resultado do worker inválido.');}
   if(report?.schemaVersion!=='1.0'||report.kind!==b.kind||report.input?.sha256!==sha256||report.input?.bytes!==bytes.length||report.input?.unchanged!==true)throw new HttpError(409,'WORKER_INTEGRITY','O relatório não comprova os bytes recebidos.');
   report.input.name=b.name;
   await db.transaction(async tx=>{
    const [job]=await tx.query("SELECT id FROM jobs WHERE id=$1 AND status='running' FOR UPDATE",[id]);if(!job)throw new HttpError(409,'WORKER_INTERRUPTED','Execução interrompida.');
    await tx.query('UPDATE forensic_runs SET report=$2 WHERE id=$1',[id,JSON.stringify(report)]);await tx.query("UPDATE jobs SET status='completed',completed_at=$2 WHERE id=$1",[id,new Date(now())]);
    await audit(tx,a.organizationId,a.id,'forensic.completed',id,{evidenceId,sha256,kind:b.kind});
   });return {id,assetId:b.assetId,kind:b.kind,evidenceId,status:'completed',report};
  }catch(error){
   if(started)await db.transaction(async tx=>{const code=error instanceof HttpError?error.code:'WORKER_FAILED';await tx.query("UPDATE jobs SET status='failed',completed_at=$2 WHERE id=$1 AND status='running'",[id,new Date(now())]);await tx.query('UPDATE forensic_runs SET error_code=$2 WHERE id=$1',[id,code]);await audit(tx,a.organizationId,a.id,'forensic.failed',id,{code,evidenceId});});
   throw error;
  }finally{
   try{if(folder){const parent=resolve(tmpdir());if(dirname(resolve(folder))!==parent||!resolve(folder).startsWith(join(parent,'sentinel-forensic-')))throw new Error('Unexpected temporary path');await unlink(join(folder,`input.${b.kind}`)).catch(e=>{if(e.code!=='ENOENT')throw e;});await rmdir(folder);}}
   finally{try{if(started)await db.query('DELETE FROM forensic_execution_lock WHERE slot=1 AND job_id=$1',[id]);}finally{busy=false;}}
  }
 });
}
