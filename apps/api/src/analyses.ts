import {randomUUID} from 'node:crypto';
import type {FastifyInstance} from 'fastify';
import {analyzeArtifact,ArtifactAnalysisError,ANALYSIS_KINDS} from '@sentinel/core';
import type {Database} from './db.ts';
import {HttpError,object,str,uuid} from './auth.ts';
import {permit,scoped} from './policy.ts';
import {audit} from './audit.ts';
import {digest,encrypt} from './security.ts';

export async function registerAnalyses(app:FastifyInstance,{db,masterKey,now=Date.now}:{db:Database;masterKey:Buffer;now?:()=>number}) {
  app.get('/api/analyses',async request=>{permit(request,'findings.read');return {items:await db.query('SELECT id,asset_id AS "assetId",kind,evidence_id AS "evidenceId",created_at AS "createdAt",report->\'summary\' AS summary,jsonb_array_length(report->\'findings\') AS "findingCount" FROM artifact_analyses WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.get('/api/analyses/:id',{schema:{params:object({id:uuid})}},async request=>{
    permit(request,'reports.read');const a=request.actor!,id=(request.params as any).id;
    return db.transaction(async tx=>{const [r]=await tx.query('SELECT id,asset_id AS "assetId",kind,evidence_id AS "evidenceId",created_at AS "createdAt",report FROM artifact_analyses WHERE id=$1 AND organization_id=$2',[id,a.organizationId]);if(!r)throw new HttpError(404,'NOT_FOUND','Análise não encontrada.');await audit(tx,a.organizationId,a.id,'analysis.viewed',id);return r;});
  });
  app.post('/api/analyses',{schema:{body:object({assetId:uuid,kind:{enum:[...ANALYSIS_KINDS]},name:str(240),mediaType:str(100),content:{type:'string',minLength:1,maxLength:1048576}})}},async request=>{
    const a=request.actor!,b=request.body as any;
    const execution={profile:'artifact.analyze',inputBytes:Buffer.byteLength(b.content,'utf8')};
    await scoped(db,request,'scan',b.assetId,now,execution);await scoped(db,request,'evidence.import',b.assetId,now,execution);
    let report;try{report=analyzeArtifact({kind:b.kind,name:b.name,mediaType:b.mediaType,content:b.content});}catch(error){if(error instanceof ArtifactAnalysisError)throw new HttpError(400,'INVALID_ARTIFACT',error.message);throw error;}
    const id=randomUUID(),evidenceId=randomUUID(),bytes=Buffer.from(b.content,'utf8'),sha256=digest(bytes);
    return db.transaction(async tx=>{
      await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[evidenceId,a.organizationId,b.assetId,b.name,b.mediaType,sha256,bytes.length,encrypt(bytes,masterKey,`evidence:${a.organizationId}:${evidenceId}`),a.id,`analysis:${id}`]);
      await tx.query('INSERT INTO artifact_analyses(id,organization_id,asset_id,kind,evidence_id,report) VALUES($1,$2,$3,$4,$5,$6)',[id,a.organizationId,b.assetId,b.kind,evidenceId,JSON.stringify(report)]);
      await audit(tx,a.organizationId,a.id,'analysis.completed',id,{assetId:b.assetId,kind:b.kind,evidenceId,inputHash:sha256,findings:report.findings.length});
      return {id,assetId:b.assetId,kind:b.kind,evidenceId,report};
    });
  });
}
