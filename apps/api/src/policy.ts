import type { FastifyRequest } from 'fastify';
import { evaluatePolicy, type Operation, type AuthorizationScope } from '@sentinel/core';
import type { Database,Sql } from './db.ts';
import { audit } from './audit.ts';
import { HttpError } from './auth.ts';

export function permit(request:FastifyRequest,operation:Operation) {
  const decision=evaluatePolicy({identity:request.actor!,operation,resource:{organizationId:request.actor!.organizationId}});
  if(!decision.allowed)throw new HttpError(403,decision.code,decision.reason);
}
export async function scoped(db:Database,request:FastifyRequest,operation:Operation,assetId:string,now:()=>number) {
  const a=request.actor!;
  const [asset]=await db.query('SELECT * FROM assets WHERE id=$1 AND organization_id=$2',[assetId,a.organizationId]);
  if(!asset)throw new HttpError(404,'NOT_FOUND','Ativo não encontrado.');
  const rows=await db.query('SELECT * FROM authorizations WHERE organization_id=$1 AND asset_id=$2 AND revoked_at IS NULL',[a.organizationId,assetId]);
  const resource={organizationId:a.organizationId,assetId,environment:asset.environment};
  const decisions=rows.map(row=>evaluatePolicy({identity:a,operation,resource,scope:scopeDto(row),now:new Date(now())}));
  if(!decisions.some(d=>d.allowed)) {
    await db.transaction(tx=>audit(tx,a.organizationId,a.id,'policy.denied',assetId,{operation}));
    throw new HttpError(403,'SCOPE_REQUIRED','Operação exige papel e autorização vigente para este ativo e ambiente.');
  }
  return asset;
}
export function scopeDto(row:any):AuthorizationScope {return {id:row.id,organizationId:row.organization_id,assetId:row.asset_id,environment:row.environment,operations:row.operations,authorizationRef:row.authorization_ref,notBefore:new Date(row.not_before).toISOString(),expiresAt:new Date(row.expires_at).toISOString()};}
export const assetDto=(r:any)=>({id:r.id,name:r.name,kind:r.kind,environment:r.environment,criticality:r.criticality,projectId:r.project_id,createdAt:r.created_at});
