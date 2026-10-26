import {execFile} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdtemp,writeFile,unlink,rmdir,stat,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname,isAbsolute,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import type {FastifyInstance} from 'fastify';
import type {Database} from './db.ts';
import {HttpError,object,str,uuid} from './auth.ts';
import {permit,scoped} from './policy.ts';
import {digest,encrypt} from './security.ts';
import {audit} from './audit.ts';

export type ImportRunner=(options:{pythonPath:string;file:string})=>Promise<Buffer>;
const worker=fileURLToPath(new URL('../../../workers/imports/inspect_archive.py',import.meta.url));
const maxBytes=16*1024*1024,maxOutput=2*1024*1024;
export const runImportWorker:ImportRunner=async({pythonPath,file})=>{
 if(!isAbsolute(pythonPath))throw new HttpError(503,'PYTHON_UNAVAILABLE','Configure o Python local.');
 let executable:string;try{executable=await realpath(pythonPath);if(!(await stat(executable)).isFile())throw new Error('invalid');}catch{throw new HttpError(503,'PYTHON_UNAVAILABLE','Python configurado indisponível.');}
 const env:NodeJS.ProcessEnv={};for(const k of ['SystemRoot','WINDIR','TEMP','TMP','LANG','LC_ALL'])if(process.env[k])env[k]=process.env[k];
 return new Promise((accept,reject)=>{const child=execFile(executable,['-I','-B',worker,'--consent','--file',file],{shell:false,windowsHide:true,timeout:45000,killSignal:'SIGKILL',maxBuffer:maxOutput,encoding:'buffer',env,cwd:dirname(worker)},(error,stdout)=>{
  if(error){reject(new HttpError(422,(error as any).killed?'IMPORT_TIMEOUT':'IMPORT_REJECTED','Inspeção não concluída: arquivo inválido, limite excedido ou worker indisponível. O original permanece em quarentena.'));return;}accept(Buffer.from(stdout));
 });child.stdin?.end();});
};
export async function registerImports(app:FastifyInstance,{db,masterKey,now=Date.now,pythonPath,runner=runImportWorker}:{db:Database;masterKey:Buffer;now?:()=>number;pythonPath?:string;runner?:ImportRunner}){
 let busy=false;
 app.get('/api/imports/status',async request=>{permit(request,'findings.read');return {configured:!!pythonPath&&isAbsolute(pythonPath),formats:['zip'],maxBytes,timeoutSeconds:45,quarantineOnly:true,executionAvailable:false,networkAccess:false};});
 app.get('/api/imports',async request=>{permit(request,'findings.read');return {items:await db.query('SELECT r.id,r.asset_id AS "assetId",r.project_id AS "projectId",r.evidence_id AS "evidenceId",r.created_at AS "createdAt",r.error_code AS "errorCode",j.status FROM import_runs r JOIN jobs j ON j.id=r.id WHERE r.organization_id=$1 ORDER BY r.created_at DESC LIMIT 100',[request.actor!.organizationId])};});
 app.get('/api/imports/:id',{schema:{params:object({id:uuid})}},async request=>{
  permit(request,'reports.read');const a=request.actor!,id=(request.params as any).id;
  return db.transaction(async tx=>{const [r]=await tx.query('SELECT r.id,r.asset_id AS "assetId",r.project_id AS "projectId",r.evidence_id AS "evidenceId",r.report,r.error_code AS "errorCode",r.created_at AS "createdAt",r.quarantine_only AS "quarantineOnly",j.status FROM import_runs r JOIN jobs j ON j.id=r.id WHERE r.organization_id=$1 AND r.id=$2',[a.organizationId,id]);if(!r)throw new HttpError(404,'NOT_FOUND','Importação não encontrada.');await audit(tx,a.organizationId,a.id,'import.viewed',id);return r;});
 });
 app.post('/api/imports',{bodyLimit:24*1024*1024,schema:{body:object({assetId:uuid,name:str(240),format:{const:'zip'},contentBase64:{type:'string',minLength:4,maxLength:22369624}})}},async request=>{
  const a=request.actor!,b=request.body as {assetId:string;name:string;contentBase64:string};
  const asset=await scoped(db,request,'evidence.import',b.assetId,now);await scoped(db,request,'scan',b.assetId,now);
  const bytes=Buffer.from(b.contentBase64,'base64');if(!bytes.length||bytes.length>maxBytes||bytes.toString('base64')!==b.contentBase64)throw new HttpError(400,'INVALID_FILE','Arquivo base64 canônico de até 16 MiB obrigatório.');
  if(!pythonPath||!isAbsolute(pythonPath))throw new HttpError(503,'PYTHON_UNAVAILABLE','Python local não configurado.');
  if(busy)throw new HttpError(409,'IMPORT_BUSY','Há uma inspeção em andamento.');busy=true;
  const id=randomUUID(),evidenceId=randomUUID(),sha256=digest(bytes);let started=false,folder:string|undefined;
  try{
   await db.transaction(async tx=>{
    const [lock]=await tx.query('SELECT l.job_id,j.status FROM import_execution_lock l JOIN jobs j ON j.id=l.job_id WHERE l.slot=1 FOR UPDATE OF l');
    if(lock?.status==='running')throw new HttpError(409,'IMPORT_BUSY','Há uma inspeção em andamento.');
    if(lock)await tx.query('DELETE FROM import_execution_lock WHERE slot=1 AND job_id=$1',[lock.job_id]);
    await tx.query("INSERT INTO jobs(id,organization_id,asset_id,kind,status) VALUES($1,$2,$3,'import.zip','running')",[id,a.organizationId,b.assetId]);
    if(!(await tx.query('INSERT INTO import_execution_lock(slot,job_id) VALUES(1,$1) ON CONFLICT DO NOTHING RETURNING slot',[id])).length)throw new HttpError(409,'IMPORT_BUSY','Há uma inspeção em andamento.');
    await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[evidenceId,a.organizationId,b.assetId,b.name,'application/zip',sha256,bytes.length,encrypt(bytes,masterKey,`evidence:${a.organizationId}:${evidenceId}`),a.id,`quarantine:${id}`]);
    await tx.query("INSERT INTO import_runs(id,organization_id,asset_id,project_id,evidence_id,format) VALUES($1,$2,$3,$4,$5,'zip')",[id,a.organizationId,b.assetId,asset.project_id??null,evidenceId]);
    await audit(tx,a.organizationId,a.id,'import.quarantined',id,{assetId:b.assetId,projectId:asset.project_id??null,evidenceId,sha256,bytes:bytes.length});
   });started=true;
   folder=await mkdtemp(join(tmpdir(),'sentinel-import-'));const file=join(folder,'input.zip');await writeFile(file,bytes,{flag:'wx',mode:0o600});
   const output=await runner({pythonPath,file});if(output.length>maxOutput)throw new HttpError(422,'IMPORT_OUTPUT_LIMIT','Resultado excede o limite.');
   let report:any;try{report=JSON.parse(output.toString('utf8'));}catch{throw new HttpError(422,'INVALID_IMPORT_REPORT','Relatório inválido.');}
   if(report?.schemaVersion!=='1.0'||report.engine!=='Sentinel Import Inspector'||report.quarantineOnly!==true||report.input?.sha256!==sha256||report.input?.bytes!==bytes.length||report.input?.unchanged!==true||!Array.isArray(report.entries)||report.entries.length>512)throw new HttpError(409,'IMPORT_INTEGRITY','Relatório não comprova a integridade da importação.');
   report.input.name=b.name;
   await db.transaction(async tx=>{
    if(!(await tx.query("SELECT id FROM jobs WHERE id=$1 AND status='running' FOR UPDATE",[id])).length)throw new HttpError(409,'IMPORT_INTERRUPTED','Importação interrompida.');
    await tx.query('UPDATE import_runs SET report=$2 WHERE id=$1',[id,JSON.stringify(report)]);await tx.query("UPDATE jobs SET status='completed',completed_at=$2 WHERE id=$1",[id,new Date(now())]);await audit(tx,a.organizationId,a.id,'import.inspected',id,{evidenceId,sha256,entries:report.entries.length,quarantineOnly:true});
   });return {id,assetId:b.assetId,projectId:asset.project_id??null,evidenceId,status:'completed',quarantineOnly:true,report};
  }catch(error){
   if(started)await db.transaction(async tx=>{const code=error instanceof HttpError?error.code:'IMPORT_FAILED';await tx.query("UPDATE jobs SET status='failed',completed_at=$2 WHERE id=$1 AND status='running'",[id,new Date(now())]);await tx.query('UPDATE import_runs SET error_code=$2 WHERE id=$1',[id,code]);await audit(tx,a.organizationId,a.id,'import.failed',id,{code,evidenceId});});throw error;
  }finally{
   try{if(folder){const parent=resolve(tmpdir());if(dirname(resolve(folder))!==parent||!resolve(folder).startsWith(join(parent,'sentinel-import-')))throw new Error('Unexpected temporary path');await unlink(join(folder,'input.zip')).catch(e=>{if(e.code!=='ENOENT')throw e;});await rmdir(folder);}}
   finally{try{if(started)await db.query('DELETE FROM import_execution_lock WHERE slot=1 AND job_id=$1',[id]);}finally{busy=false;}}
  }
 });
}
