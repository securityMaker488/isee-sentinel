import {spawn} from 'node:child_process';
import {stat,realpath,readFile} from 'node:fs/promises';
import {isAbsolute,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {HttpError} from './auth.ts';
import {digest} from './security.ts';
import type {ImportRunner} from './imports.ts';

const worker=fileURLToPath(new URL('../../../workers/imports/inspect_archive.py',import.meta.url));
const maxOutput=2*1024*1024;
export interface ExecutionReceipt {
 schemaVersion:1;engine:'Sentinel Execution';engineVersion:'0.1.1';containment:'windows_job'|'linux_parent_death';jobId:string;
 status:'completed'|'failed'|'cancelled'|'timed_out'|'output_limit'|'integrity_failed'|'invalid_output';
 exitCode:number|null;durationMs:number;inputSha256:string;workerSha256:string;
 stdoutSha256:string;stdoutBytes:number;stderrBytes:number;outputTruncated:boolean;
}
export type SupervisedOptions=Parameters<ImportRunner>[0]&{executionPath:string;workerPath?:string};
async function executable(path:string){
 if(!isAbsolute(path))throw new HttpError(503,'EXECUTION_UNAVAILABLE','Caminho absoluto do executável obrigatório.');
 try{const actual=await realpath(path);if(!(await stat(actual)).isFile())throw new Error();return actual;}
 catch{throw new HttpError(503,'EXECUTION_UNAVAILABLE','Executável configurado indisponível.');}
}

/** Only deployment configuration chooses executable/worker; HTTP data never supplies argv. */
export async function runSupervisedImport(options:SupervisedOptions):Promise<Buffer>{
 const {file,format,signal,onReceipt}=options;
 if(!['win32','linux'].includes(process.platform))throw new HttpError(503,'EXECUTION_UNAVAILABLE','Supervisor nativo requer Windows ou Linux.');
 if(!options.jobId)throw new HttpError(500,'EXECUTION_CONTEXT','Identidade da execução ausente.');
 const [native,python]=await Promise.all([executable(options.executionPath),executable(options.pythonPath)]);
 const workerPath=options.workerPath??worker;
 if(!isAbsolute(workerPath)||(await stat(workerPath)).size>1024*1024)throw new HttpError(503,'EXECUTION_UNAVAILABLE','Worker indisponível.');
 const workerHash=digest(await readFile(workerPath)),inputHash=options.inputSha256;
 if(!inputHash)throw new HttpError(500,'EXECUTION_CONTEXT','Hash da entrada ausente.');
 if(signal?.aborted)throw new HttpError(409,'IMPORT_CANCELLED','Inspeção cancelada antes do despacho.');
 const request={schemaVersion:1,operation:'archive.inspect',jobId:options.jobId,file,format,inputSha256:inputHash,maxInputBytes:16*1024*1024,maxOutputBytes:maxOutput,timeoutMs:45000};
 const env:NodeJS.ProcessEnv={};for(const key of ['SystemRoot','WINDIR','TEMP','TMP','LANG','LC_ALL'])if(process.env[key])env[key]=process.env[key];
 return new Promise((accept,reject)=>{
  const child=spawn(native,['--python',python,'--worker',workerPath],{shell:false,windowsHide:true,cwd:dirname(workerPath),env,stdio:['pipe','pipe','pipe']});
  let output=Buffer.alloc(0),stderrBytes=0,transportError=false,settled=false;
  const cancel=()=>{if(!child.stdin.destroyed)child.stdin.end();};
  // Closing stdin cancels/reaps the Python child before the supervisor exits.
  // A second deadline bounds a defective supervisor. OS lifetime controls protect
  // the trusted worker; Linux descendant trees still require separate containment.
  const deadline=setTimeout(cancel,46000),fallback=setTimeout(()=>{transportError=true;child.kill('SIGKILL');},50000);
  signal?.addEventListener('abort',cancel,{once:true});
  const finish=(error?:Error,bytes?:Buffer)=>{
   if(settled)return;settled=true;clearTimeout(deadline);clearTimeout(fallback);signal?.removeEventListener('abort',cancel);
   if(error)reject(error);else accept(bytes!);
  };
  child.on('error',()=>finish(new HttpError(503,'EXECUTION_UNAVAILABLE','Supervisor indisponível.')));
  child.stdin.on('error',()=>{transportError=true;});
  child.stderr.on('data',(chunk:Buffer)=>{stderrBytes+=chunk.length;if(stderrBytes>65536){transportError=true;cancel();}});
  child.stdout.on('data',(chunk:Buffer)=>{
   if(output.length+chunk.length>maxOutput*6+65536){transportError=true;cancel();return;}
   output=Buffer.concat([output,chunk]);
  });
  child.on('close',code=>{
   try{
    if(transportError)throw new HttpError(422,'EXECUTION_PROTOCOL','Falha no protocolo do supervisor.');
    let response:any;try{response=JSON.parse(output.toString('utf8'));}catch{throw new HttpError(422,'EXECUTION_PROTOCOL','Resposta do supervisor inválida.');}
    const r=response?.receipt as ExecutionReceipt;
    const statuses=['completed','failed','cancelled','timed_out','output_limit','integrity_failed','invalid_output'];
    if(!r||r.schemaVersion!==1||r.engine!=='Sentinel Execution'||r.engineVersion!=='0.1.1'||r.containment!==(process.platform==='win32'?'windows_job':'linux_parent_death')||r.jobId!==options.jobId||r.inputSha256!==inputHash||r.workerSha256!==workerHash||!statuses.includes(r.status)
       ||!Number.isSafeInteger(r.durationMs)||r.durationMs<0||!Number.isInteger(r.stdoutBytes)||r.stdoutBytes<0||r.stdoutBytes>maxOutput+1||!Number.isInteger(r.stderrBytes)||r.stderrBytes<0||r.stderrBytes>65537
       ||typeof r.outputTruncated!=='boolean'||!/^[0-9a-f]{64}$/.test(r.stdoutSha256)||!(r.exitCode===null||Number.isInteger(r.exitCode)))throw new HttpError(409,'EXECUTION_INTEGRITY','Recibo do supervisor não corresponde à execução.');
    if((r.status==='completed')!==(code===0)||(r.status==='completed'&&(r.exitCode!==0||r.outputTruncated)))throw new HttpError(409,'EXECUTION_INTEGRITY','Resultado e saída do processo divergem.');
    const bytes=typeof response.stdout==='string'?Buffer.from(response.stdout,'utf8'):undefined;
    if(r.status==='completed'&&(!bytes||bytes.length!==r.stdoutBytes||digest(bytes)!==r.stdoutSha256))throw new HttpError(409,'EXECUTION_INTEGRITY','Saída do processo não corresponde ao hash.');
    // Copy only schema fields; do not persist arbitrary fields from an external process.
    const receipt:ExecutionReceipt={schemaVersion:r.schemaVersion,engine:r.engine,engineVersion:r.engineVersion,containment:r.containment,jobId:r.jobId,status:r.status,exitCode:r.exitCode,durationMs:r.durationMs,inputSha256:r.inputSha256,workerSha256:r.workerSha256,stdoutSha256:r.stdoutSha256,stdoutBytes:r.stdoutBytes,stderrBytes:r.stderrBytes,outputTruncated:r.outputTruncated};
    onReceipt?.(receipt);
    if(signal?.aborted||r.status==='cancelled')throw new HttpError(409,'IMPORT_CANCELLED','Inspeção cancelada; original preservado.');
    if(r.status!=='completed')throw new HttpError(422,r.status==='timed_out'?'IMPORT_TIMEOUT':r.status==='output_limit'?'IMPORT_OUTPUT_LIMIT':'IMPORT_REJECTED','Worker não concluiu a inspeção; original preservado.');
    finish(undefined,bytes);
   }catch(error){finish(error instanceof Error?error:new Error('Execution failed'));}
  });
  child.stdin.write(JSON.stringify(request)+'\n');
  if(signal?.aborted)cancel();
 });
}
