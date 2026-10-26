import {execFile} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {access,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isIP} from 'node:net';
import {basename,dirname,isAbsolute} from 'node:path';
import type {FastifyInstance,FastifyRequest} from 'fastify';
import {analyzeArtifact,evaluatePolicy,type ArtifactAnalysisReport} from '@sentinel/core';
import type {Database} from './db.ts';
import {HttpError,object,str,uuid} from './auth.ts';
import {permit,scoped,scopeDto} from './policy.ts';
import {audit} from './audit.ts';
import {digest,encrypt} from './security.ts';

export const LAB_LIMITS=Object.freeze({ports:16,outputBytes:1024*1024,timeoutMs:40000,leaseMs:120000});
type FailureCode='NMAP_UNAVAILABLE'|'NMAP_TIMEOUT'|'NMAP_OUTPUT_LIMIT'|'NMAP_EXIT_FAILED'|'NMAP_EXECUTION_FAILED'|'NMAP_INVALID_OUTPUT';
export interface LabRunResult {stdout:Buffer;exitCode:number|null;failure?:FailureCode;}
export interface LabRunOptions {timeout:number;maxBuffer:number;shell:false;windowsHide:true;killSignal:'SIGKILL';cwd:string;env:NodeJS.ProcessEnv;}
export type LabRunner=(file:string,args:readonly string[],options:LabRunOptions)=>Promise<LabRunResult>;
export interface LabOptions {db:Database;masterKey:Buffer;now?:()=>number;nmapPath?:string;runner?:LabRunner;}

/** Exact IPv4 only. No DNS, octal notation, URI, CIDR, range or alternate family. */
export function isLabAddress(address:unknown):address is string {
  if(typeof address!=='string'||isIP(address)!==4)return false;
  const parts=address.split('.').map(Number);
  if(parts.join('.')!==address)return false;
  return parts[0]===127||parts[0]===10||(parts[0]===172&&parts[1]>=16&&parts[1]<=31)||(parts[0]===192&&parts[1]===168);
}

function configuredPath(path:unknown):path is string {
  return typeof path==='string'&&isAbsolute(path)&&!/[\x00-\x1f\x7f]/.test(path)
    &&(process.platform==='win32'?basename(path).toLowerCase()==='nmap.exe':basename(path)==='nmap');
}

export function nmapArguments(address:string,ports:readonly number[]):string[] {
  if(!isLabAddress(address)||!Array.isArray(ports)||ports.length<1||ports.length>LAB_LIMITS.ports
    ||new Set(ports).size!==ports.length||ports.some(port=>!Number.isInteger(port)||port<1||port>65535)) {
    throw new HttpError(400,'INVALID_LAB_TARGET','Informe um IPv4 privado/loopback e de 1 a 16 portas TCP únicas.');
  }
  return ['--unprivileged','--disable-arp-ping','-sT','-Pn','-n','--max-retries','1','--host-timeout','30s','-p',[...ports].sort((a,b)=>a-b).join(','),'-oX','-',address];
}

function childEnvironment():NodeJS.ProcessEnv {
  const env:NodeJS.ProcessEnv={LANG:'C',LC_ALL:'C',NMAP_UNPRIVILEGED:'1'};
  // Do not copy database, master-key or session configuration into the subprocess.
  if(process.platform==='win32')for(const key of ['SystemRoot','WINDIR','TEMP','TMP'])if(process.env[key])env[key]=process.env[key];
  return env;
}

/** The only production subprocess entrypoint. Test runners are trusted constructor injections. */
export const runNmap:LabRunner=async(file,args,options)=>{
  if(!configuredPath(file)||process.geteuid?.()===0)return {stdout:Buffer.alloc(0),exitCode:null,failure:'NMAP_UNAVAILABLE'};
  try {
    const metadata=await lstat(file);
    if(!metadata.isFile()||metadata.isSymbolicLink()||(process.platform!=='win32'&&(metadata.mode&0o6022)!==0)) {
      return {stdout:Buffer.alloc(0),exitCode:null,failure:'NMAP_UNAVAILABLE'};
    }
    await access(file,constants.X_OK);
  }catch{return {stdout:Buffer.alloc(0),exitCode:null,failure:'NMAP_UNAVAILABLE'};}
  return new Promise(resolve=>{
    const child=execFile(file,[...args],{...options,encoding:'buffer'},(error,stdout)=>{
      const output=Buffer.isBuffer(stdout)?stdout:Buffer.from(stdout??'');
      if(!error){resolve({stdout:output,exitCode:0});return;}
      const e=error as NodeJS.ErrnoException&{killed?:boolean;signal?:string;code?:string|number};
      const failure:FailureCode=e.code==='ENOENT'||e.code==='EACCES'?'NMAP_UNAVAILABLE'
        :e.code==='ERR_CHILD_PROCESS_STDIO_MAXBUFFER'?'NMAP_OUTPUT_LIMIT'
        :e.killed||e.signal==='SIGKILL'?'NMAP_TIMEOUT':'NMAP_EXIT_FAILED';
      resolve({stdout:output.subarray(0,LAB_LIMITS.outputBytes),exitCode:typeof e.code==='number'?e.code:null,failure});
    });
    child.stdin?.end();
  });
};

async function requireLabScope(db:Database,request:FastifyRequest,assetId:string,now:()=>number,remainingMs=0) {
  const asset=await scoped(db,request,'scan',assetId,now);
  if(asset.environment!=='lab')throw new HttpError(403,'LAB_ONLY','A execução nativa exige um ativo no ambiente lab.');
  if(remainingMs){
    const a=request.actor!,rows=await db.query('SELECT * FROM authorizations WHERE organization_id=$1 AND asset_id=$2 AND revoked_at IS NULL',[a.organizationId,assetId]);
    if(!rows.some(row=>evaluatePolicy({identity:a,operation:'scan',resource:{organizationId:a.organizationId,assetId,environment:'lab'},scope:scopeDto(row),now:new Date(now()+remainingMs)}).allowed)) {
      throw new HttpError(403,'SCOPE_TOO_SHORT','A autorização deve cobrir os próximos 40 segundos de execução.');
    }
  }
  return asset;
}

const selectScans=`SELECT s.id,s.asset_id AS "assetId",s.target_id AS "targetId",s.ports,s.evidence_id AS "evidenceId",s.analysis_id AS "analysisId",s.error_code AS "errorCode",j.status,s.created_at AS "createdAt",j.completed_at AS "completedAt",a.report->'summary' AS summary,jsonb_array_length(a.report->'findings') AS "findingCount" FROM lab_scans s JOIN jobs j ON j.id=s.id LEFT JOIN artifact_analyses a ON a.id=s.analysis_id`;

export async function registerLab(app:FastifyInstance,{db,masterKey,now=Date.now,nmapPath=process.env.SENTINEL_NMAP_PATH,runner=runNmap}:LabOptions) {
  // This also serializes slow injected runners within one process. The DB lock covers other workers.
  let busy=false;
  app.get('/api/lab/status',async request=>{
    permit(request,'assets.read');
    return {configured:configuredPath(nmapPath),pathConfigured:Boolean(nmapPath),adapter:'nmap',mode:'single_host_tcp_connect',maxPorts:LAB_LIMITS.ports,requiresEnvironment:'lab',versionVerified:false};
  });
  app.get('/api/lab/targets',async request=>{
    permit(request,'assets.read');
    return {items:await db.query('SELECT id,asset_id AS "assetId",address,name,created_at AS "createdAt" FROM lab_targets WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])};
  });
  app.post('/api/lab/targets',{schema:{body:object({assetId:uuid,address:str(15),name:str(120)})}},async request=>{
    permit(request,'assets.create');const a=request.actor!,b=request.body as {assetId:string;address:string;name:string};
    if(!isLabAddress(b.address))throw new HttpError(400,'INVALID_LAB_TARGET','Somente um IPv4 privado RFC1918 ou loopback literal é aceito.');
    await requireLabScope(db,request,b.assetId,now);
    const id=randomUUID();
    return db.transaction(async tx=>{
      const [target]=await tx.query('INSERT INTO lab_targets(id,organization_id,asset_id,address,name,created_by) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(organization_id,asset_id,address) DO NOTHING RETURNING id,asset_id AS "assetId",address,name,created_at AS "createdAt"',[id,a.organizationId,b.assetId,b.address,b.name,a.id]);
      if(!target)throw new HttpError(409,'TARGET_EXISTS','Este alvo já está cadastrado para o ativo.');
      await audit(tx,a.organizationId,a.id,'lab.target_registered',id,{assetId:b.assetId,address:b.address});return target;
    });
  });
  app.get('/api/lab/scans',async request=>{
    permit(request,'findings.read');return {items:await db.query(`${selectScans} WHERE s.organization_id=$1 ORDER BY s.created_at DESC LIMIT 100`,[request.actor!.organizationId])};
  });
  app.post('/api/lab/scans',{schema:{body:object({targetId:uuid,ports:{type:'array',minItems:1,maxItems:LAB_LIMITS.ports,uniqueItems:true,items:{type:'integer',minimum:1,maximum:65535}}})}},async request=>{
    const a=request.actor!,b=request.body as {targetId:string;ports:number[]};
    const [target]=await db.query('SELECT * FROM lab_targets WHERE id=$1 AND organization_id=$2',[b.targetId,a.organizationId]);
    if(!target)throw new HttpError(404,'NOT_FOUND','Alvo de laboratório não encontrado.');
    await requireLabScope(db,request,target.asset_id,now,LAB_LIMITS.timeoutMs);
    if(!configuredPath(nmapPath))throw new HttpError(503,'NMAP_UNAVAILABLE','Adaptador indisponível. Configure SENTINEL_NMAP_PATH com o caminho absoluto do Nmap instalado e licenciado.');
    if(busy)throw new HttpError(409,'LAB_BUSY','Já existe uma execução de laboratório em andamento.');
    const id=randomUUID(),ports=[...b.ports].sort((x,y)=>x-y),args=nmapArguments(target.address,ports);
    busy=true;
    let started=false;
    let output:Buffer=Buffer.alloc(0);
    let evidenceId:string|null=null;
    let failure:FailureCode='NMAP_EXECUTION_FAILED';
    try {
      await db.transaction(async tx=>{
        const [lock]=await tx.query('SELECT l.job_id,l.expires_at,j.status,j.organization_id FROM lab_execution_lock l JOIN jobs j ON j.id=l.job_id WHERE l.slot=1 FOR UPDATE OF l');
        if(lock&&lock.status==='running'&&new Date(lock.expires_at).getTime()>now())throw new HttpError(409,'LAB_BUSY','Já existe uma execução de laboratório em andamento.');
        if(lock){
          if(lock.status==='running'){
            await tx.query("UPDATE jobs SET status='interrupted',completed_at=$2 WHERE id=$1",[lock.job_id,new Date(now())]);
            await tx.query("UPDATE lab_scans SET error_code='LEASE_EXPIRED' WHERE id=$1",[lock.job_id]);
            await audit(tx,lock.organization_id,null,'lab.interrupted',lock.job_id,{reason:'lease_expired'});
          }
          await tx.query('DELETE FROM lab_execution_lock WHERE slot=1 AND job_id=$1',[lock.job_id]);
        }
        await tx.query("INSERT INTO jobs(id,organization_id,asset_id,kind,status) VALUES($1,$2,$3,'lab_nmap','running')",[id,a.organizationId,target.asset_id]);
        const acquired=await tx.query('INSERT INTO lab_execution_lock(slot,job_id,expires_at) VALUES(1,$1,$2) ON CONFLICT DO NOTHING RETURNING slot',[id,new Date(now()+LAB_LIMITS.leaseMs)]);
        if(!acquired.length)throw new HttpError(409,'LAB_BUSY','Já existe uma execução de laboratório em andamento.');
        await tx.query('INSERT INTO lab_scans(id,organization_id,asset_id,target_id,ports) VALUES($1,$2,$3,$4,$5)',[id,a.organizationId,target.asset_id,target.id,JSON.stringify(ports)]);
        await audit(tx,a.organizationId,a.id,'lab.started',id,{targetId:target.id,assetId:target.asset_id,ports,adapter:'nmap',mode:'tcp_connect'});
      });
      started=true;
      // Re-read scope immediately before invoking the fixed executable, after lock acquisition.
      await requireLabScope(db,request,target.asset_id,now,LAB_LIMITS.timeoutMs);
      const result=await runner(nmapPath,Object.freeze(args),{timeout:LAB_LIMITS.timeoutMs,maxBuffer:LAB_LIMITS.outputBytes,shell:false,windowsHide:true,killSignal:'SIGKILL',cwd:dirname(nmapPath),env:childEnvironment()});
      if(!Buffer.isBuffer(result.stdout))throw new Error('invalid runner output');
      output=result.stdout.subarray(0,LAB_LIMITS.outputBytes);
      if(result.stdout.length>LAB_LIMITS.outputBytes)failure='NMAP_OUTPUT_LIMIT';
      else if(result.failure)failure=result.failure;
      else if(result.exitCode!==0)failure='NMAP_EXIT_FAILED';
      else failure='NMAP_INVALID_OUTPUT';
      // Preserve even malformed/partial output, encrypted and bounded, before parsing.
      if(output.length){
        evidenceId=randomUUID();
        await db.transaction(async tx=>{
          await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[evidenceId,a.organizationId,target.asset_id,`lab-${id}.xml`,'application/xml',digest(output),output.length,encrypt(output,masterKey,`evidence:${a.organizationId}:${evidenceId}`),a.id,`lab:${id}`]);
          await tx.query('UPDATE lab_scans SET evidence_id=$2 WHERE id=$1',[id,evidenceId]);
          await audit(tx,a.organizationId,a.id,'lab.output_preserved',id,{evidenceId,sha256:digest(output),bytes:output.length,partial:Boolean(result.failure||result.exitCode!==0||result.stdout.length>LAB_LIMITS.outputBytes)});
        });
      }
      if(result.failure||result.exitCode!==0||result.stdout.length>LAB_LIMITS.outputBytes)throw new Error('execution failed');
      let report:ArtifactAnalysisReport;
      try {report=analyzeArtifact({kind:'network',name:`lab-${id}.xml`,mediaType:'application/xml',content:new TextDecoder('utf-8',{fatal:true}).decode(output)});}catch{throw new Error('invalid XML output');}
      if(report.format!=='nmap-xml')throw new Error('unexpected output format');
      report.limitations.push('XML produzido por execução local controlada: um alvo cadastrado, TCP connect e portas explícitas. O parser analisa o documento passivamente. Porta aberta não confirma exploração, vulnerabilidade ou identidade do serviço.');
      const analysisId=randomUUID();
      await db.transaction(async tx=>{
        const [active]=await tx.query('SELECT l.job_id,l.expires_at,j.status FROM lab_execution_lock l JOIN jobs j ON j.id=l.job_id WHERE l.slot=1 AND l.job_id=$1 FOR UPDATE OF l',[id]);
        if(!active||active.status!=='running'||new Date(active.expires_at).getTime()<=now())throw new HttpError(409,'LAB_INTERRUPTED','A execução perdeu sua autorização de processamento e não será publicada como concluída.');
        await tx.query("INSERT INTO artifact_analyses(id,organization_id,asset_id,kind,evidence_id,report) VALUES($1,$2,$3,'network',$4,$5)",[analysisId,a.organizationId,target.asset_id,evidenceId,JSON.stringify(report)]);
        await tx.query('UPDATE lab_scans SET analysis_id=$2 WHERE id=$1',[id,analysisId]);
        await tx.query("UPDATE jobs SET status='completed',completed_at=$2 WHERE id=$1",[id,new Date(now())]);
        await audit(tx,a.organizationId,a.id,'lab.completed',id,{targetId:target.id,evidenceId,analysisId,findings:report.findings.length});
      });
      const [scan]=await db.query(`${selectScans} WHERE s.id=$1 AND s.organization_id=$2`,[id,a.organizationId]);
      return {...scan,report};
    }catch(error){
      if(started){
        if(error instanceof HttpError)failure='NMAP_EXECUTION_FAILED';
        await db.transaction(async tx=>{
          await tx.query("UPDATE jobs SET status='failed',completed_at=$2 WHERE id=$1 AND status='running'",[id,new Date(now())]);
          await tx.query('UPDATE lab_scans SET error_code=$2 WHERE id=$1',[id,error instanceof HttpError?error.code:failure]);
          await audit(tx,a.organizationId,a.id,'lab.failed',id,{code:error instanceof HttpError?error.code:failure,evidenceId});
        });
      }
      if(error instanceof HttpError)throw error;
      throw new HttpError(failure==='NMAP_UNAVAILABLE'?503:502,failure,failure==='NMAP_UNAVAILABLE'?'Nmap indisponível: verifique instalação, licença, caminho e conta sem privilégios.':'Execução não concluída. Consulte o histórico e a evidência parcial disponível.');
    }finally{
      try{if(started)await db.query('DELETE FROM lab_execution_lock WHERE slot=1 AND job_id=$1',[id]);}finally{busy=false;}
    }
  });
}
