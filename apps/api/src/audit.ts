import { randomUUID } from 'node:crypto';
import type { Sql } from './db.ts';
import { canonical,digest } from './security.ts';

export async function audit(tx: Sql, org: string, actor: string | null, action: string, resource: string | null, details: Record<string,unknown>={}) {
  // Serialize the chain within an organization, including concurrent PostgreSQL connections.
  await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[org]);
  const [previous]=await tx.query('SELECT hash FROM audit_events WHERE organization_id=$1 ORDER BY sequence DESC LIMIT 1',[org]);
  const record={id:randomUUID(),organizationId:org,actorId:actor,action,resourceId:resource,details,createdAt:new Date().toISOString(),previousHash:previous?.hash??'0'.repeat(64)};
  const hash=digest(canonical(record));
  await tx.query('INSERT INTO audit_events(id,organization_id,actor_id,action,resource_id,details,created_at,previous_hash,hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[record.id,org,actor,action,resource,JSON.stringify(details),record.createdAt,record.previousHash,hash]);
  return {...record,hash};
}
export function verifyAuditChain(rows: any[]) {
  let previous='0'.repeat(64);
  for(const row of rows) {
    const record={id:row.id,organizationId:row.organization_id,actorId:row.actor_id,action:row.action,resourceId:row.resource_id,details:row.details,createdAt:new Date(row.created_at).toISOString(),previousHash:row.previous_hash};
    if(row.previous_hash!==previous||digest(canonical(record))!==row.hash)return {valid:false,failedAt:row.id,checked:rows.indexOf(row)};
    previous=row.hash;
  }
  return {valid:true,checked:rows.length,head:previous};
}
