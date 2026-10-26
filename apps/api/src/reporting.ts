import type {FastifyInstance} from 'fastify';
import type {Database,Sql} from './db.ts';
import {HttpError,object,uuid} from './auth.ts';
import {permit} from './policy.ts';
import {decrypt,digest} from './security.ts';
import {audit} from './audit.ts';

async function context(tx:Sql,org:string,assetId:string){
 const [asset]=await tx.query('SELECT a.id,a.name,a.environment,a.criticality,p.id AS project_id,p.name AS project_name,p.contract_ref,o.name AS organization_name FROM assets a JOIN organizations o ON o.id=a.organization_id LEFT JOIN projects p ON p.id=a.project_id AND p.organization_id=a.organization_id WHERE a.id=$1 AND a.organization_id=$2',[assetId,org]);
 if(!asset)throw new HttpError(404,'NOT_FOUND','Ativo não encontrado.');
 return {organization:{id:org,name:asset.organization_name},project:asset.project_id?{id:asset.project_id,name:asset.project_name,contractRef:asset.contract_ref}:null,asset:{id:asset.id,name:asset.name,environment:asset.environment,criticality:asset.criticality},authorizations:await tx.query('SELECT id,authorization_ref AS reference,operations,not_before AS "notBefore",expires_at AS "expiresAt",revoked_at AS "revokedAt" FROM authorizations WHERE organization_id=$1 AND asset_id=$2 ORDER BY not_before DESC LIMIT 100',[org,assetId])};
}
async function evidence(tx:Sql,org:string,ids:string[],key:Buffer){
 const rows=await tx.query('SELECT * FROM evidence WHERE organization_id=$1 AND id=ANY($2::uuid[]) ORDER BY created_at,id',[org,ids]);
 if(rows.length!==new Set(ids).size)throw new HttpError(409,'EVIDENCE_MISSING','Evidência necessária não encontrada.');
 return rows.map(r=>{if(digest(decrypt(r.content_cipher,key,`evidence:${org}:${r.id}`))!==r.sha256)throw new HttpError(409,'INTEGRITY_FAILED','Integridade de evidência inválida.');return {id:r.id,name:r.name,source:r.source,sha256:r.sha256,sizeBytes:r.size_bytes,createdAt:r.created_at,integrityVerified:true};});
}
export async function registerReporting(app:FastifyInstance,{db,masterKey,now=Date.now}:{db:Database;masterKey:Buffer;now?:()=>number}){
 const params=object({id:uuid});
 for(const type of ['analysis','incident'] as const)app.get(`/api/reports/${type}/:id`,{schema:{params}},async(request,reply)=>{
  permit(request,'reports.read');const a=request.actor!,id=(request.params as any).id;
  const report=await db.transaction(async tx=>{
   const [row]=type==='analysis'?await tx.query('SELECT * FROM artifact_analyses WHERE id=$1 AND organization_id=$2',[id,a.organizationId]):await tx.query('SELECT * FROM incidents WHERE id=$1 AND organization_id=$2',[id,a.organizationId]);
   if(!row)throw new HttpError(404,'NOT_FOUND','Registro não encontrado.');
   const ctx=await context(tx,a.organizationId,row.asset_id),base={schemaVersion:'1.0',product:'I.See Sentinel',specification:'6.9',type,id,generatedAt:new Date(now()).toISOString(),timezone:'UTC',...ctx,
    scopeNote:'Autorizações listadas são registros históricos; consulte a vigência na data de cada operação. Datas da fonte não provam, isoladamente, a origem.',
    retest:{status:'not_recorded',results:[]},operatorId:a.id};
   let result;
   if(type==='analysis'){
    result={...base,objective:'Analisar o artefato fornecido e preservar os resultados observados.',methodology:'Regras locais versionadas ou achados importados, com procedência declarada.',tools:[{name:row.report.engine,version:row.report.ruleSetVersion}],status:'analysis_completed',observedAt:row.created_at,findings:row.report.findings,facts:row.report.facts,timeline:row.report.timeline??[],evidence:await evidence(tx,a.organizationId,[row.evidence_id],masterKey),limitations:row.report.limitations,executiveSummary:row.report.summary,technicalConclusion:'Os resultados se limitam aos dados fornecidos; o relatório não atesta segurança global.'};
   }else{
    const links=await tx.query('SELECT evidence_id FROM incident_evidence WHERE organization_id=$1 AND incident_id=$2 LIMIT 101',[a.organizationId,id]);
    if(links.length>100)throw new HttpError(409,'REPORT_LIMIT','Caso excede 100 evidências; exportação paginada ainda necessária.');
    const notes=await tx.query('SELECT * FROM incident_notes WHERE organization_id=$1 AND incident_id=$2 ORDER BY created_at,id LIMIT 101',[a.organizationId,id]);
    if(notes.length>100)throw new HttpError(409,'REPORT_LIMIT','Caso excede 100 notas; exportação paginada ainda necessária.');
    const events=await tx.query('SELECT id,type,source,occurred_at AS "occurredAt",data FROM security_events WHERE organization_id=$1 AND asset_id=$2 AND id=ANY($3::uuid[]) ORDER BY occurred_at',[a.organizationId,row.asset_id,row.event_ids]);
    const verifiedNotes=notes.map(n=>{const bytes=decrypt(n.body_cipher,masterKey,`incident-note:${a.organizationId}:${n.id}`);if(digest(bytes)!==n.sha256)throw new HttpError(409,'INTEGRITY_FAILED','Nota inválida.');return {id:n.id,body:bytes.toString(),createdAt:n.created_at,actorId:n.actor_id};});
    result={...base,objective:'Documentar o incidente, seus eventos, decisões e evidências vinculadas.',methodology:'Correlação registrada pelo motor e investigação documentada pelo operador.',tools:[{name:'Sentinel Detection / Case Engine',version:'1.0.0'}],status:row.status,observedAt:row.created_at,incident:{title:row.title,ruleId:row.rule_id},events,notes:verifiedNotes,alerts:await tx.query('SELECT rule_id,severity,confidence,status,synthetic FROM alerts WHERE organization_id=$1 AND incident_id=$2',[a.organizationId,id]),evidence:await evidence(tx,a.organizationId,links.map(l=>l.evidence_id),masterKey),history:await tx.query('SELECT action,details,created_at FROM audit_events WHERE organization_id=$1 AND resource_id=$2 ORDER BY sequence LIMIT 1000',[a.organizationId,id]),limitations:['Eventos sintéticos são identificados individualmente.','Estado do caso é uma decisão registrada, não comprovação automática de recuperação.','Histórico limitado a 1000 ações; reteste e impacto precisam de avaliação técnica.'],executiveSummary:`${row.title}. Estado registrado: ${row.status}. ${events.length} eventos e ${links.length} evidências vinculadas.`,technicalConclusion:'Consulte as notas do operador; a plataforma não presume causa raiz ou resolução.'};
   }
   await audit(tx,a.organizationId,a.id,'report.exported',id,{type});return result;
  });
  return reply.header('Content-Disposition',`attachment; filename="sentinel-${type}-${id}.json"`).send(report);
 });
}
