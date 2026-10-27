import type { FastifyRequest } from 'fastify';
import { evaluatePolicy, evaluateManagedGrant, type Identity, type ManagedExecution, type Operation, type AuthorizationScope } from '@sentinel/core';
import type { Database,Sql } from './db.ts';
import { audit } from './audit.ts';
import { HttpError } from './auth.ts';

export function permit(request:FastifyRequest,operation:Operation) {
  const decision=evaluatePolicy({identity:request.actor!,operation,resource:{organizationId:request.actor!.organizationId}});
  if(!decision.allowed)throw new HttpError(403,decision.code,decision.reason);
}
/** Trusted executors supply their profile and actual input; a legacy row cannot bypass a managed asset. */
export async function storedScopeGrant(sql:Sql,identity:Identity,operation:Operation,asset:any,now:number,execution?:ManagedExecution):Promise<{scopeId:string;mandateId:string|null;requestHash:string|null}|null> {
  if(asset.organization_id!==identity.organizationId)return null;
  const rows=await sql.query(`SELECT s.*,m.status AS mandate_status,m.project_id AS mandate_project_id,m.mode AS mandate_mode,
    m.risk AS mandate_risk,m.profiles AS mandate_profiles,m.limits AS mandate_limits,
    m.target_manifest AS mandate_targets,m.request_hash AS mandate_request_hash
    FROM authorizations s LEFT JOIN authorization_mandates m ON m.id=s.mandate_id AND m.organization_id=s.organization_id
    WHERE s.organization_id=$1 AND s.asset_id=$2 AND s.revoked_at IS NULL`,[identity.organizationId,asset.id]);
  for(const row of rows){
    const base=evaluatePolicy({identity,operation,resource:{organizationId:asset.organization_id,assetId:asset.id,environment:asset.environment},scope:scopeDto(row),now:new Date(now)});
    if(!base.allowed)continue;
    if(asset.authorization_mode==='legacy'){
      if(row.mandate_id===null&&execution?.profile!=='lab.inventory')return {scopeId:row.id,mandateId:null,requestHash:null};
      continue;
    }
    if(asset.authorization_mode!=='managed'||!row.mandate_id)continue;
    if(evaluateManagedGrant({status:row.mandate_status,projectId:row.mandate_project_id,mode:row.mandate_mode,risk:row.mandate_risk,
      profiles:row.mandate_profiles,limits:row.mandate_limits,targetManifest:row.mandate_targets},{id:asset.id,projectId:asset.project_id,environment:asset.environment},operation,execution).allowed){
      return {scopeId:row.id,mandateId:row.mandate_id,requestHash:row.mandate_request_hash};
    }
  }
  return null;
}
export async function storedScopeAllowed(sql:Sql,identity:Identity,operation:Operation,asset:any,now:number,execution?:ManagedExecution):Promise<boolean> {
  return Boolean(await storedScopeGrant(sql,identity,operation,asset,now,execution));
}
export async function scoped(db:Database,request:FastifyRequest,operation:Operation,assetId:string,now:()=>number,execution?:ManagedExecution) {
  const a=request.actor!;
  const [asset]=await db.query('SELECT * FROM assets WHERE id=$1 AND organization_id=$2',[assetId,a.organizationId]);
  if(!asset)throw new HttpError(404,'NOT_FOUND','Ativo não encontrado.');
  if(!await storedScopeAllowed(db,a,operation,asset,now(),execution)) {
    await db.transaction(tx=>audit(tx,a.organizationId,a.id,'policy.denied',assetId,{operation,...(execution?{profile:execution.profile}:{})}));
    throw new HttpError(403,'SCOPE_REQUIRED','Operação exige papel, autorização vigente e limites compatíveis com o ativo e o perfil.');
  }
  return asset;
}
export function scopeDto(row:any):AuthorizationScope {return {id:row.id,organizationId:row.organization_id,assetId:row.asset_id,environment:row.environment,operations:row.operations,authorizationRef:row.authorization_ref,notBefore:new Date(row.not_before).toISOString(),expiresAt:new Date(row.expires_at).toISOString()};}
export const assetDto=(r:any)=>({id:r.id,name:r.name,kind:r.kind,environment:r.environment,criticality:r.criticality,projectId:r.project_id,authorizationMode:r.authorization_mode,createdAt:r.created_at});
