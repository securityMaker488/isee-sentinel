import {randomUUID} from 'node:crypto';
import type {FastifyInstance} from 'fastify';
import {EXECUTION_PROFILES,evaluateManagedGrant,validTargetManifest,normalizeTargetManifest,type ManagedGrant} from '@sentinel/core';
import type {Database,Sql} from './db.ts';
import {HttpError,object,str,uuid} from './auth.ts';
import {permit} from './policy.ts';
import {audit} from './audit.ts';
import {canonical,digest,encrypt,decrypt} from './security.ts';

const params=object({id:uuid}),oneMiB=1048576;
const evidenceSchema=object({name:str(240),mediaType:str(100),contentBase64:{type:'string',minLength:4,maxLength:1398104}});
const targetManifestSchema=object({version:{const:1},targets:{type:'array',minItems:1,maxItems:100,items:object({assetId:uuid,address:str(15),ports:{type:'array',minItems:1,maxItems:16,uniqueItems:true,items:{type:'integer',minimum:1,maximum:65535}}})},exclusions:{type:'array',maxItems:100,items:object({address:str(15)})}});
const bodySchema=object({projectId:uuid,assetIds:{type:'array',minItems:1,maxItems:10,uniqueItems:true,items:uuid},mode:{enum:['lab','assessment']},risk:{enum:['low','moderate']},
 profiles:{type:'array',minItems:1,maxItems:9,uniqueItems:true,items:{enum:EXECUTION_PROFILES.map(p=>p.id)}},
 limits:object({maxInputBytes:{type:'integer',minimum:1,maximum:16777216},allowedPorts:{type:'array',minItems:1,maxItems:16,uniqueItems:true,items:{type:'integer',minimum:1,maximum:65535}}},['maxInputBytes']),
 notBefore:{type:'string',format:'date-time'},expiresAt:{type:'string',format:'date-time'},
 responsible:object({name:str(120),role:str(120),organization:str(120),contact:str(200)},['name','role','organization']),purpose:str(1000),
 authority:object({channel:{enum:['document','email','whatsapp','internal']},reference:str(300),evidence:evidenceSchema}),targetManifest:targetManifestSchema},['projectId','assetIds','mode','risk','profiles','limits','notBefore','expiresAt','responsible','purpose','authority']);
const select=`SELECT m.*,ARRAY(SELECT a.asset_id FROM authorization_mandate_assets a WHERE a.mandate_id=m.id AND a.organization_id=m.organization_id ORDER BY a.asset_id) AS asset_ids FROM authorization_mandates m`;
const meta=(r:any)=>({id:r.id,projectId:r.project_id,assetIds:r.asset_ids,mode:r.mode,risk:r.risk,profiles:r.profiles,limits:r.limits,status:r.status,
 notBefore:new Date(r.not_before).toISOString(),expiresAt:new Date(r.expires_at).toISOString(),createdAt:r.created_at,approvedAt:r.approved_at,revokedAt:r.revoked_at,
 requestHash:r.request_hash,requestSchemaVersion:r.request_schema_version,targetManifest:r.target_manifest??null,authorityEvidenceId:r.authority_evidence_id,authorityEvidenceHash:r.authority_evidence_hash});
export function managedGrant(row:any):ManagedGrant{return {status:row.status,projectId:row.project_id,mode:row.mode,risk:row.risk,profiles:row.profiles,limits:row.limits,targetManifest:row.target_manifest};}

function details(row:any,key:Buffer){
 try{const bytes=decrypt(row.details_cipher,key,`authorization:${row.organization_id}:${row.id}`);if(digest(bytes)!==row.details_hash)throw new Error('hash');return JSON.parse(bytes.toString('utf8'));}
 catch{throw new HttpError(409,'AUTHORITY_INTEGRITY','Os dados da autorização não puderam ser verificados.');}
}
async function authorityIntegrity(tx:Sql,row:any,key:Buffer){
 const [e]=await tx.query('SELECT sha256,size_bytes,content_cipher FROM evidence WHERE id=$1 AND organization_id=$2',[row.authority_evidence_id,row.organization_id]);
 try{if(!e)throw new Error('missing');const bytes=decrypt(e.content_cipher,key,`evidence:${row.organization_id}:${row.authority_evidence_id}`);if(digest(bytes)!==e.sha256||e.sha256!==row.authority_evidence_hash||bytes.length!==e.size_bytes)throw new Error('hash');}
 catch{throw new HttpError(409,'AUTHORITY_INTEGRITY','A comprovação de autoridade não corresponde ao original preservado.');}
}
function requestHash(row:any,privateDetails:any,assets:Record<string,any>[]){return digest(canonical({schemaVersion:row.request_schema_version??1,...(row.request_schema_version===2?{targetManifest:row.target_manifest}:{}),organizationId:row.organization_id,projectId:row.project_id,assets:assets.map(a=>({id:a.id,environment:a.environment})).sort((a,b)=>a.id.localeCompare(b.id)),mode:row.mode,risk:row.risk,profiles:row.profiles,limits:row.limits,notBefore:new Date(row.not_before).toISOString(),expiresAt:new Date(row.expires_at).toISOString(),details:privateDetails,authorityEvidenceId:row.authority_evidence_id,authorityEvidenceHash:row.authority_evidence_hash}));}
function validateForAssets(row:any,assets:any[]){
 if(row.profiles.includes('lab.inventory')&&!row.target_manifest)throw new HttpError(400,'TARGET_MANIFEST_REQUIRED','Inventário ativo exige manifesto explícito de alvos e exclusões. Crie e revise uma nova autorização.');
 if(row.target_manifest!=null&&(!row.limits.allowedPorts||!validTargetManifest(row.target_manifest,assets.map(asset=>asset.id),row.limits.allowedPorts)))throw new HttpError(400,'INVALID_TARGET_MANIFEST','Manifesto inválido: use IPv4 privado/loopback literal, ativos selecionados e portas autorizadas.');
 for(const asset of assets)for(const profile of row.profiles){
  const definition=EXECUTION_PROFILES.find(p=>p.id===profile);
  if(!definition)throw new HttpError(400,'INVALID_AUTHORIZATION','Perfil não implementado.');
  const decision=evaluateManagedGrant({...managedGrant(row),status:'approved'},{id:asset.id,projectId:asset.project_id,environment:asset.environment},definition.operations[0],{profile,phase:'prepare'});
  if(!decision.allowed)throw new HttpError(400,'INVALID_AUTHORIZATION',decision.reason);
 }
}
async function getRow(tx:Sql,org:string,id:string){const [r]=await tx.query(`${select} WHERE m.organization_id=$1 AND m.id=$2`,[org,id]);if(!r)throw new HttpError(404,'NOT_FOUND','Autorização de avaliação não encontrada.');return r;}

export async function registerAuthorizationManager(app:FastifyInstance,{db,masterKey,now=Date.now}:{db:Database;masterKey:Buffer;now?:()=>number}){
 app.get('/api/assessment-authorizations/catalog',async request=>{permit(request,'scopes.read');return {schemaVersion:2,items:EXECUTION_PROFILES,targetManifest:{version:1,maxTargets:100,maxExclusions:100,addressKind:'private_or_loopback_ipv4_literal',requiredProfiles:['lab.inventory']},limitations:['Perfis correspondem somente a executores já implementados. Aprovação não certifica autoridade jurídica.','Limites de bytes aplicam-se por entrada, não a cota total. Timeouts/concorrência continuam fixos por executor.','Inventário ativo exige alvos e exclusões no hash aprovado. IP privado não comprova autorização nem isolamento.']};});
 app.get('/api/assessment-authorizations',async request=>{permit(request,'scopes.read');return {items:(await db.query(`${select} WHERE m.organization_id=$1 ORDER BY m.created_at DESC,m.id LIMIT 100`,[request.actor!.organizationId])).map(meta)};});
 app.get('/api/assessment-authorizations/:id',{schema:{params}},async request=>{
  permit(request,'scopes.read');const a=request.actor!,id=(request.params as any).id;if(a.role==='viewer')throw new HttpError(403,'ROLE_DENIED','O papel não permite consultar dados do responsável.');
  return db.transaction(async tx=>{const r=await getRow(tx,a.organizationId,id);const privateDetails=details(r,masterKey);await authorityIntegrity(tx,r,masterKey);
   const scopes=await tx.query('SELECT id,asset_id AS "assetId",revoked_at AS "revokedAt",not_before AS "notBefore",expires_at AS "expiresAt" FROM authorizations WHERE organization_id=$1 AND mandate_id=$2 ORDER BY asset_id',[a.organizationId,id]);
   await audit(tx,a.organizationId,a.id,'authorization.viewed',id);return {...meta(r),...privateDetails,scopes,revocationReason:r.revocation_cipher?decrypt(r.revocation_cipher,masterKey,`authorization-revocation:${a.organizationId}:${id}`).toString():null,reviewMessage:'Revise o responsável, a comprovação, o projeto, os ativos, os alvos, as exclusões e os limites. Aprovar substitui todos os escopos anteriores destes ativos e ativa controle por perfil. Revogar não restaura escopos antigos.'};
  });
 });
 app.post('/api/assessment-authorizations',{bodyLimit:2*1024*1024,schema:{body:bodySchema}},async request=>{
  permit(request,'scopes.create');const a=request.actor!,b=request.body as any,time=now();
  const start=Date.parse(b.notBefore),end=Date.parse(b.expiresAt);if(!Number.isFinite(start)||!Number.isFinite(end)||end<=time||end<=start||start<time-300000||end>time+31*86400000||end-start>31*86400000)throw new HttpError(400,'INVALID_PERIOD','Defina vigência de até 31 dias, sem início anterior a cinco minutos.');
  for(const value of [b.purpose,...Object.values(b.responsible),b.authority.reference,b.authority.evidence.name,b.authority.evidence.mediaType])if(typeof value!=='string'||!value.trim())throw new HttpError(400,'INVALID_DETAILS','Informe os dados do responsável e a comprovação.');
  const bytes=Buffer.from(b.authority.evidence.contentBase64,'base64');if(!bytes.length||bytes.length>oneMiB||bytes.toString('base64')!==b.authority.evidence.contentBase64)throw new HttpError(400,'INVALID_EVIDENCE','Comprovação deve ter base64 canônico e até 1 MiB.');
  if(b.targetManifest!==undefined&&!validTargetManifest(b.targetManifest,b.assetIds,b.limits.allowedPorts))throw new HttpError(400,'INVALID_TARGET_MANIFEST','Manifesto inválido: use IPv4 privado/loopback literal, ativos selecionados e portas autorizadas.');
  const id=randomUUID(),evidenceId=randomUUID(),evidenceHash=digest(bytes),privateDetails={responsible:b.responsible,purpose:b.purpose,authority:{channel:b.authority.channel,reference:b.authority.reference}};
  const draft={id,organization_id:a.organizationId,project_id:b.projectId,mode:b.mode,risk:b.risk,profiles:[...b.profiles].sort(),limits:{maxInputBytes:b.limits.maxInputBytes,...(b.limits.allowedPorts?{allowedPorts:[...b.limits.allowedPorts].sort((x:number,y:number)=>x-y)}:{})},not_before:new Date(start),expires_at:new Date(end),status:'draft',authority_evidence_id:evidenceId,authority_evidence_hash:evidenceHash,target_manifest:b.targetManifest?normalizeTargetManifest(b.targetManifest):null,request_schema_version:b.targetManifest?2:1};
  return db.transaction(async tx=>{
   await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);
   if(!(await tx.query('SELECT id FROM projects WHERE id=$1 AND organization_id=$2',[b.projectId,a.organizationId])).length)throw new HttpError(404,'NOT_FOUND','Projeto não encontrado.');
   const assets=await tx.query('SELECT * FROM assets WHERE organization_id=$1 AND project_id=$2 AND id=ANY($3::uuid[]) ORDER BY id FOR SHARE',[a.organizationId,b.projectId,b.assetIds]);if(assets.length!==b.assetIds.length)throw new HttpError(404,'NOT_FOUND','Os ativos devem pertencer à empresa e ao projeto selecionados.');validateForAssets(draft,assets);
   const hash=requestHash(draft,privateDetails,assets),serialized=canonical(privateDetails);
   await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[evidenceId,a.organizationId,assets[0].id,b.authority.evidence.name,b.authority.evidence.mediaType,evidenceHash,bytes.length,encrypt(bytes,masterKey,`evidence:${a.organizationId}:${evidenceId}`),a.id,`authority:${id}`]);
   await tx.query('INSERT INTO authorization_mandates(id,organization_id,project_id,mode,risk,profiles,limits,not_before,expires_at,details_cipher,details_hash,request_hash,authority_evidence_id,authority_evidence_hash,created_by,target_manifest,request_schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)',[id,a.organizationId,b.projectId,b.mode,b.risk,JSON.stringify(draft.profiles),JSON.stringify(draft.limits),draft.not_before,draft.expires_at,encrypt(serialized,masterKey,`authorization:${a.organizationId}:${id}`),digest(serialized),hash,evidenceId,evidenceHash,a.id,draft.target_manifest?JSON.stringify(draft.target_manifest):null,draft.request_schema_version]);
   for(const asset of assets)await tx.query('INSERT INTO authorization_mandate_assets(mandate_id,organization_id,asset_id,environment) VALUES($1,$2,$3,$4)',[id,a.organizationId,asset.id,asset.environment]);
   await audit(tx,a.organizationId,a.id,'authorization.drafted',id,{projectId:b.projectId,assetIds:assets.map(s=>s.id),requestHash:hash,evidenceId,evidenceHash});return meta(await getRow(tx,a.organizationId,id));
  });
 });
 app.post('/api/assessment-authorizations/:id/approve',{schema:{params,body:object({requestHash:{type:'string',pattern:'^[0-9a-f]{64}$'},attested:{const:true}})}},async request=>{
  permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id,b=request.body as any;
  return db.transaction(async tx=>{
   await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);const r=await getRow(tx,a.organizationId,id);
   if(r.status!=='draft')throw new HttpError(409,'INVALID_TRANSITION','Somente rascunhos podem ser aprovados.');
   if(b.requestHash!==r.request_hash)throw new HttpError(409,'REVIEW_MISMATCH','A aprovação deve corresponder ao rascunho revisado.');
   if(new Date(r.expires_at).getTime()<=now())throw new HttpError(409,'EXPIRED','O rascunho expirou. Crie uma nova autorização.');
   const assets=await tx.query('SELECT s.*,a.environment AS approved_environment FROM authorization_mandate_assets a JOIN assets s ON s.id=a.asset_id AND s.organization_id=a.organization_id WHERE a.mandate_id=$1 AND a.organization_id=$2 ORDER BY s.id FOR UPDATE OF s',[id,a.organizationId]);
   if(assets.length!==r.asset_ids.length||assets.some(s=>s.project_id!==r.project_id||s.environment!==s.approved_environment))throw new HttpError(409,'CONTEXT_CHANGED','O contexto dos ativos mudou; crie um novo rascunho.');
   const privateDetails=details(r,masterKey);await authorityIntegrity(tx,r,masterKey);
   if(requestHash(r,privateDetails,assets)!==r.request_hash)throw new HttpError(409,'AUTHORITY_INTEGRITY','O pedido não corresponde ao registro preservado.');validateForAssets(r,assets);
   const operations=[...new Set(r.profiles.flatMap((p:string)=>EXECUTION_PROFILES.find(d=>d.id===p)!.operations))];
   const replaced=await tx.query('UPDATE authorizations SET revoked_at=$3 WHERE organization_id=$1 AND asset_id=ANY($2::uuid[]) AND revoked_at IS NULL RETURNING id',[a.organizationId,r.asset_ids,new Date(now())]);
   await tx.query("UPDATE assets SET authorization_mode='managed' WHERE organization_id=$1 AND id=ANY($2::uuid[])",[a.organizationId,r.asset_ids]);
   await tx.query("UPDATE authorization_mandates SET status='approved',approved_by=$3,approved_at=$4 WHERE id=$1 AND organization_id=$2",[id,a.organizationId,a.id,new Date(now())]);
   for(const asset of assets)await tx.query('INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by,mandate_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[randomUUID(),a.organizationId,asset.id,asset.environment,JSON.stringify(operations),`Assessment:${id}`,r.not_before,r.expires_at,a.id,id]);
   await audit(tx,a.organizationId,a.id,'authorization.approved',id,{requestHash:r.request_hash,assetIds:r.asset_ids,replacedScopeIds:replaced.map(s=>s.id),profiles:r.profiles,limits:r.limits,attested:true});return meta(await getRow(tx,a.organizationId,id));
  });
 });
 app.post('/api/assessment-authorizations/:id/revoke',{schema:{params,body:object({reason:str(500)})}},async request=>{
  permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id,reason=(request.body as any).reason.trim();if(!reason)throw new HttpError(400,'INVALID_REASON','Informe o motivo da revogação.');
  return db.transaction(async tx=>{await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);const r=await getRow(tx,a.organizationId,id);if(r.status==='revoked')throw new HttpError(409,'INVALID_TRANSITION','Autorização já revogada.');
   await tx.query("UPDATE authorization_mandates SET status='revoked',revoked_at=$3,revocation_cipher=$4 WHERE id=$1 AND organization_id=$2",[id,a.organizationId,new Date(now()),encrypt(reason,masterKey,`authorization-revocation:${a.organizationId}:${id}`)]);
   await tx.query('UPDATE authorizations SET revoked_at=$3 WHERE organization_id=$1 AND mandate_id=$2 AND revoked_at IS NULL',[a.organizationId,id,new Date(now())]);
   await audit(tx,a.organizationId,a.id,'authorization.revoked',id,{reasonHash:digest(reason)});return meta(await getRow(tx,a.organizationId,id));
  });
 });
}
