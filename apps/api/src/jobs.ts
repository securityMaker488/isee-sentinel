import type {FastifyInstance} from 'fastify';
import type {Operation} from '@sentinel/core';
import type {Database} from './db.ts';
import {HttpError,object,uuid} from './auth.ts';
import {scoped} from './policy.ts';
import {audit} from './audit.ts';

/**
 * Registro das execuções em andamento neste processo. Cada motor publica o
 * seu controlador de cancelamento; o painel solicita o cancelamento pelo job
 * e o motor em execução decide como encerrar. O registro é volátil por
 * desenho: o estado durável do cancelamento fica em jobs.cancel_requested_at,
 * e a recuperação de jobs órfãos acontece na inicialização do servidor.
 */
type Inflight={controller:AbortController;cancelRequested:boolean};
const inflight=new Map<string,Inflight>();

export function registerJobExecution(jobId:string,controller:AbortController):Inflight{
  const entry:Inflight={controller,cancelRequested:false};
  inflight.set(jobId,entry);
  return entry;
}
export function releaseJobExecution(jobId:string){inflight.delete(jobId);}
/** Sinaliza o cancelamento; devolve falso quando o job não roda neste processo. */
export function requestJobCancellation(jobId:string):boolean{
  const entry=inflight.get(jobId);
  if(!entry)return false;
  entry.cancelRequested=true;
  entry.controller.abort();
  return true;
}
export function jobCancellationRequested(jobId:string):boolean{return inflight.get(jobId)?.cancelRequested??false;}

/** Operações cujo escopo vigente autorizou o job; o cancelamento exige as mesmas. */
export function cancellationOperations(kind:string):Operation[]{
  if(kind.startsWith('import.')||kind==='forensics')return ['scan','evidence.import'];
  if(kind==='lab_nmap'||kind==='securebuild')return ['scan'];
  return ['scan'];
}

export async function registerJobs(app:FastifyInstance,{db,now=Date.now}:{db:Database;now?:()=>number}){
  app.post('/api/jobs/:id/cancel',{schema:{params:object({id:uuid})}},async request=>{
    const a=request.actor!,id=(request.params as any).id;
    const [job]=await db.query('SELECT id,asset_id AS "assetId",kind,status,cancel_requested_at AS "cancelRequestedAt" FROM jobs WHERE organization_id=$1 AND id=$2',[a.organizationId,id]);
    if(!job)throw new HttpError(404,'NOT_FOUND','Job não encontrado.');
    // Papel e escopo vigente: o cancelamento exige as mesmas operações que
    // autorizaram o job, avaliadas contra o ativo do job.
    for(const operation of cancellationOperations(job.kind))await scoped(db,request,operation,job.assetId,now);
    if(job.status!=='running')throw new HttpError(409,'JOB_NOT_RUNNING',job.status==='cancelled'?'O job já foi cancelado.':'O job não está em execução.');
    const requestedAt=new Date(now());
    await db.transaction(async tx=>{
      await tx.query("UPDATE jobs SET cancel_requested_at=$2,cancel_requested_by=$3 WHERE id=$1 AND status='running'",[id,requestedAt,a.id]);
      await audit(tx,a.organizationId,a.id,'job.cancel_requested',id,{assetId:job.assetId,kind:job.kind});
    });
    // O registro durável vem primeiro: se o processo morrer logo depois, a
    // inicialização seguinte encontra o job em execução e o marca interrompido.
    const signalled=requestJobCancellation(id);
    return {id,status:signalled?'cancelling':'cancel_requested',kind:job.kind,assetId:job.assetId,cancelRequestedAt:requestedAt.toISOString()};
  });
}
