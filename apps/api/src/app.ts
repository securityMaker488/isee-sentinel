import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import staticFiles from '@fastify/static';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import type { Database,Sql } from './db.ts';
import { registerAuth,HttpError,object,str,uuid } from './auth.ts';
import { permit,scoped,scopeDto,assetDto } from './policy.ts';
import { audit,verifyAuditChain } from './audit.ts';
import { encrypt,decrypt,digest,canonical,randomToken } from './security.ts';
import { scanFiles,evaluateBarrierMatrix,assessRisk,type ScanResult } from '@sentinel/core';
import {registerAgents} from './agents.ts';
import {registerOperations} from './operations.ts';
import {registerAnalyses} from './analyses.ts';
import portfolio from '../../../docs/portfolio-capabilities.json' with {type:'json'};
import {registerReporting} from './reporting.ts';
import {registerLab,type LabRunner} from './lab.ts';
import {registerForensics,type ForensicRunner} from './forensics.ts';
import {registerGraph} from './graph.ts';
import {registerImports,type ImportRunner} from './imports.ts';
import {registerAuthorizationManager} from './authorization-manager.ts';
import {registerAssessmentPlans,assessmentContextSchema,validateAssessmentExecution,recordAssessmentExecution,recordAssessmentEvidence} from './assessment-plans.ts';

export interface AppOptions {db:Database;masterKey:Buffer;origin?:string;secureCookie?:boolean;now?:()=>number;staticDir?:string;logger?:boolean;nmapPath?:string;labRunner?:LabRunner;pythonPath?:string;forensicRunner?:ForensicRunner;importRunner?:ImportRunner;}
export async function buildApp(options:AppOptions) {
  const {db,masterKey}=options,now=options.now??Date.now,origin=options.origin??'http://127.0.0.1:4310';
  const app=Fastify({bodyLimit:3*1024*1024,requestTimeout:30000,trustProxy:false,logger:options.logger?{level:'info',redact:['req.headers.cookie','req.headers.authorization','req.headers["x-csrf-token"]']}:false,disableRequestLogging:true,ajv:{customOptions:{removeAdditional:false,coerceTypes:false}}});
  await app.register(cookie);
  await app.register(helmet,{contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"],formAction:["'self'"],upgradeInsecureRequests:null}},hsts:origin.startsWith('https:')});
  // Dashboard refreshes fan out to several bounded reads; login retains its own 10/min ceiling.
  await app.register(rateLimit,{max:600,timeWindow:'1 minute'});
  await app.register(swagger,{openapi:{info:{title:'I.See Sentinel API',version:'0.1.0'},components:{securitySchemes:{session:{type:'apiKey',in:'cookie',name:'sentinel_session'}}},security:[{session:[]}]}});
  await registerAuth(app,db,masterKey,origin,options.secureCookie??origin.startsWith('https:'),now);
  app.setErrorHandler((error,request,reply)=>{
    const e=error as any,status=e.statusCode>=400&&e.statusCode<=599?e.statusCode:500;
    if(status>=500)request.log.error({code:e.code??'INTERNAL',requestId:request.id},'Request failed');
    reply.status(status).send({error:{code:e.validation?'INVALID_INPUT':e.code??'INTERNAL',message:status===500?'Erro interno. Consulte a auditoria operacional.':e.validation?'Dados inválidos ou campos não permitidos.':e.message}});
  });
  app.get('/health',async()=>({status:'ok',version:'0.1.0'}));
  app.get('/api/openapi.json',async request=>{permit(request,'overview.read');return app.swagger();});
  app.get('/api/capabilities',async request=>{permit(request,'overview.read');return portfolio;});
  app.get('/api/organizations',async request=>{permit(request,'overview.read');return {items:await db.query('SELECT o.id,o.name FROM organizations o JOIN operator_organizations access ON access.organization_id=o.id WHERE access.operator_id=$1 ORDER BY o.created_at',[request.actor!.id])};});
  app.post('/api/organizations',{schema:{body:object({name:str(120)})}},async request=>{
    permit(request,'assets.create');const a=request.actor!,id=randomUUID(),b=request.body as any;
    return db.transaction(async tx=>{await tx.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,b.name]);await tx.query('INSERT INTO operator_organizations(operator_id,organization_id) VALUES($1,$2)',[a.id,id]);await audit(tx,id,a.id,'organization.created',id);return {id,name:b.name};});
  });
  app.post('/api/context',{schema:{body:object({organizationId:uuid})}},async request=>{
    permit(request,'overview.read');const a=request.actor!,id=(request.body as any).organizationId;
    return db.transaction(async tx=>{
      const [organization]=await tx.query('SELECT o.id,o.name FROM organizations o JOIN operator_organizations access ON access.organization_id=o.id WHERE o.id=$1 AND access.operator_id=$2',[id,a.id]);
      if(!organization)throw new HttpError(404,'NOT_FOUND','Organização não autorizada.');
      const csrfToken=randomToken();await tx.query('UPDATE sessions SET active_organization_id=$2,csrf_token=$3 WHERE token_hash=$1',[a.sessionHash,id,csrfToken]);
      await audit(tx,a.organizationId,a.id,'context.changed',id,{previousOrganizationId:a.organizationId});
      return {user:{id:a.id,email:a.email,role:a.role,organizationId:id},csrfToken,activeOrganization:organization};
    });
  });
  app.get('/api/projects',async request=>{permit(request,'assets.read');return {items:await db.query('SELECT id,name,contract_ref AS "contractRef",organization_id AS "organizationId",created_at AS "createdAt" FROM projects WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.post('/api/projects',{schema:{body:object({name:str(120),contractRef:str(300)})}},async request=>{
    permit(request,'assets.create');const a=request.actor!,b=request.body as any,id=randomUUID();
    return db.transaction(async tx=>{await tx.query('INSERT INTO projects(id,organization_id,name,contract_ref) VALUES($1,$2,$3,$4)',[id,a.organizationId,b.name,b.contractRef]);await audit(tx,a.organizationId,a.id,'project.created',id);return {id,organizationId:a.organizationId,name:b.name,contractRef:b.contractRef};});
  });
  app.get('/api/overview',async request=>{
    permit(request,'overview.read');const org=request.actor!.organizationId;
    const [counts]=await db.query(`SELECT (SELECT count(*) FROM assets WHERE organization_id=$1)::int AS assets,
     (SELECT count(*) FROM findings WHERE organization_id=$1)::int AS findings,
     (SELECT count(*) FROM findings WHERE organization_id=$1 AND details->>'severity' IN ('high','critical'))::int AS high_findings,
     (SELECT count(*) FROM scans WHERE organization_id=$1)::int AS scans,
     (SELECT count(*) FROM evidence WHERE organization_id=$1)::int AS evidence,
     (SELECT count(*) FROM incidents WHERE organization_id=$1)::int AS incidents,
     (SELECT count(*) FROM alerts WHERE organization_id=$1)::int AS alerts`,[org]);
    return {assets:counts.assets,findings:counts.findings,evidence:counts.evidence,scans:counts.scans,highFindings:counts.high_findings,incidents:counts.incidents,alerts:counts.alerts,recentEvents:await db.query('SELECT id,type,source,data,occurred_at AS "occurredAt",received_at AS "receivedAt",asset_id AS "assetId" FROM security_events WHERE organization_id=$1 ORDER BY received_at DESC LIMIT 10',[org]),generatedAt:new Date(now()).toISOString(),source:db.engine,period:'Todo o histórico armazenado; achados incluem reavaliações.'};
  });
  app.get('/api/assets',async request=>{permit(request,'assets.read');return {items:(await db.query('SELECT * FROM assets WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])).map(assetDto)};});
  app.post('/api/assets',{schema:{body:object({name:str(120),kind:{enum:['application','server','repository']},environment:{enum:['lab','staging','production']},criticality:{type:'integer',minimum:1,maximum:5},projectId:uuid},['name','kind','environment','criticality'])}},async request=>{
    permit(request,'assets.create');const b=request.body as any,a=request.actor!,id=randomUUID();
    return db.transaction(async tx=>{if(b.projectId&&!(await tx.query('SELECT id FROM projects WHERE id=$1 AND organization_id=$2',[b.projectId,a.organizationId])).length)throw new HttpError(404,'NOT_FOUND','Projeto não encontrado.');const [r]=await tx.query('INSERT INTO assets(id,organization_id,name,kind,environment,criticality,project_id) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[id,a.organizationId,b.name,b.kind,b.environment,b.criticality,b.projectId??null]);await audit(tx,a.organizationId,a.id,'asset.created',id);return assetDto(r);});
  });
  app.get('/api/authorizations',{schema:{querystring:object({assetId:uuid},[])}},async request=>{
    permit(request,'scopes.read');const org=request.actor!.organizationId,assetId=(request.query as any).assetId;
    const rows=assetId?await db.query('SELECT * FROM authorizations WHERE organization_id=$1 AND asset_id=$2 ORDER BY not_before DESC LIMIT 100',[org,assetId]):await db.query('SELECT * FROM authorizations WHERE organization_id=$1 ORDER BY not_before DESC LIMIT 100',[org]);
    return {items:rows.map(r=>({...scopeDto(r),revokedAt:r.revoked_at}))};
  });
  app.post('/api/authorizations',{schema:{body:object({assetId:uuid,operations:{type:'array',minItems:1,maxItems:3,uniqueItems:true,items:{enum:['scan','evidence.import','event.ingest']}},authorizationRef:str(300),expiresAt:{type:'string',format:'date-time'}})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,b=request.body as any,time=now();
    if(new Date(b.expiresAt).getTime()<=time||new Date(b.expiresAt).getTime()>time+31*86400000)throw new HttpError(400,'INVALID_EXPIRY','Autorização deve expirar entre agora e 31 dias.');
    return db.transaction(async tx=>{
      await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);
      const [asset]=await tx.query('SELECT * FROM assets WHERE id=$1 AND organization_id=$2 FOR UPDATE',[b.assetId,a.organizationId]);if(!asset)throw new HttpError(404,'NOT_FOUND','Ativo não encontrado.');
      if(asset.authorization_mode!=='legacy')throw new HttpError(403,'MANAGED_AUTHORIZATION_REQUIRED','Este ativo exige autorização de avaliação revisada no Authorization Manager.');
      const [row]=await tx.query('INSERT INTO authorizations(id,organization_id,asset_id,environment,operations,authorization_ref,not_before,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',[randomUUID(),a.organizationId,b.assetId,asset.environment,JSON.stringify(b.operations),b.authorizationRef,new Date(time),b.expiresAt,a.id]);
      await audit(tx,a.organizationId,a.id,'scope.granted',row.id,{assetId:b.assetId,operations:b.operations,expiresAt:b.expiresAt});return scopeDto(row);
    });
  });
  app.post('/api/authorizations/:id/revoke',{schema:{params:object({id:uuid})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id;
    return db.transaction(async tx=>{await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);const rows=await tx.query('UPDATE authorizations SET revoked_at=$3 WHERE id=$1 AND organization_id=$2 AND revoked_at IS NULL RETURNING id',[id,a.organizationId,new Date(now())]);if(!rows.length)throw new HttpError(404,'NOT_FOUND','Autorização não encontrada.');await audit(tx,a.organizationId,a.id,'scope.revoked',id);return {ok:true};});
  });
  app.post('/api/scans',{schema:{body:object({assetId:uuid,files:{type:'array',minItems:1,maxItems:40,items:object({path:str(240),content:{type:'string',maxLength:262144}})},assessment:assessmentContextSchema},['assetId','files'])}},async request=>{
    const a=request.actor!,b=request.body as any;
    const execution={profile:'static.scan',inputBytes:b.files.reduce((sum:number,file:{content:string})=>sum+Buffer.byteLength(file.content,'utf8'),0)};
    await scoped(db,request,'scan',b.assetId,now,execution);
    const id=randomUUID();
    const analyze=()=>{try{return scanFiles(b.files);}catch{throw new HttpError(400,'INVALID_FILES','Arquivos inválidos. Use caminhos relativos, até 40 arquivos, 256 KiB por arquivo e 1 MiB total.');}};
    const start=async(tx:Sql)=>{await tx.query('INSERT INTO jobs(id,organization_id,asset_id,kind,status) VALUES($1,$2,$3,$4,$5)',[id,a.organizationId,b.assetId,'securebuild','running']);await audit(tx,a.organizationId,a.id,'scan.started',id,{assetId:b.assetId,fileCount:b.files.length});};
    const finish=async(tx:Sql,result:ScanResult)=>{
        const [row]=await tx.query('INSERT INTO scans(id,organization_id,asset_id,result) VALUES($1,$2,$3,$4) RETURNING *',[id,a.organizationId,b.assetId,JSON.stringify(result)]);
        const evidenceIds=new Map<string,string>();
        for(const file of b.files) {const ev=await preserve(tx,{organizationId:a.organizationId,actorId:a.id,assetId:b.assetId,name:file.path,mediaType:'text/plain; charset=utf-8',bytes:Buffer.from(file.content,'utf8'),source:`securebuild:${id}`},masterKey);evidenceIds.set(file.path,ev.id);}
        for(const finding of result.findings)await tx.query('INSERT INTO findings(id,organization_id,asset_id,scan_id,evidence_id,details) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),a.organizationId,b.assetId,id,evidenceIds.get(finding.path),JSON.stringify(finding)]);
        if(b.assessment)await recordAssessmentEvidence(tx,a.organizationId,b.assetId,id,[...evidenceIds.values()]);
        await tx.query('UPDATE jobs SET status=$2,completed_at=$3 WHERE id=$1',[id,'completed',new Date(now())]);
        await tx.query('INSERT INTO security_events(id,organization_id,asset_id,schema_version,type,source,occurred_at,data) VALUES($1,$2,$3,1,$4,$5,$6,$7)',[randomUUID(),a.organizationId,b.assetId,'scan.completed','securebuild',new Date(now()),JSON.stringify({scanId:id,findingCount:result.findings.length})]);
        await audit(tx,a.organizationId,a.id,'scan.completed',id,{assetId:b.assetId,findings:result.findings.length,inputHash:result.inputHash});return {...scanDto(row),...(b.assessment?{assessment:b.assessment}:{})};
    };
    if(b.assessment)return db.transaction(async tx=>{
      // The bounded, synchronous analyzer and its evidence commit share the scope lock.
      // A concurrent revocation/replacement cannot race between validation and dispatch.
      await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);
      await validateAssessmentExecution(tx,a,b.assessment,b.assetId,execution,now());
      const result=analyze();await start(tx);await recordAssessmentExecution(tx,a,b.assessment,b.assetId,id);
      return finish(tx,result);
    });
    const result=analyze();await db.transaction(start);
    try {
      return await db.transaction(tx=>finish(tx,result));
    }catch(error){await db.transaction(async tx=>{await tx.query('UPDATE jobs SET status=$2,completed_at=$3 WHERE id=$1',[id,'failed',new Date(now())]);await audit(tx,a.organizationId,a.id,'scan.failed',id);});throw error;}
  });
  app.get('/api/scans',async request=>{permit(request,'findings.read');return {items:(await db.query('SELECT * FROM scans WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])).map(scanDto)};});
  app.get('/api/jobs',async request=>{permit(request,'findings.read');return {items:await db.query('SELECT id,asset_id AS "assetId",kind,status,created_at AS "createdAt",completed_at AS "completedAt" FROM jobs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.get('/api/findings',async request=>{permit(request,'findings.read');return {items:(await db.query('SELECT * FROM findings WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])).map(r=>({...r.details,id:r.id,scanId:r.scan_id,assetId:r.asset_id,evidenceId:r.evidence_id,createdAt:r.created_at}))};});
  app.get('/api/barriers',async request=>{
    permit(request,'barriers.read');const scans=await db.query('SELECT DISTINCT ON (asset_id) * FROM scans WHERE organization_id=$1 ORDER BY asset_id,created_at DESC',[request.actor!.organizationId]);
    return {items:scans.length?scans.flatMap(s=>evaluateBarrierMatrix(s.result).map(b=>({...b,assetId:s.asset_id,scanId:s.id,evaluatedAt:s.created_at}))):evaluateBarrierMatrix(),basis:'Verificações estáticas de snapshots enviados. Não comprova controle ativo em runtime.'};
  });
  app.get('/api/evidence',async request=>{permit(request,'evidence.read');return db.transaction(async tx=>{const a=request.actor!;await audit(tx,a.organizationId,a.id,'evidence.listed',null);return {items:(await tx.query('SELECT id,asset_id,name,media_type,sha256,size_bytes,created_by,source,created_at FROM evidence WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[a.organizationId])).map(evidenceDto)};});});
  app.post('/api/evidence',{schema:{body:object({assetId:uuid,name:str(240),mediaType:str(100),contentBase64:{type:'string',minLength:4,maxLength:1398104}})}},async request=>{
    const a=request.actor!,b=request.body as any;
    const bytes=Buffer.from(b.contentBase64,'base64');
    if(bytes.length>1048576||bytes.length===0||bytes.toString('base64')!==b.contentBase64)throw new HttpError(400,'INVALID_EVIDENCE','Base64 canônico e conteúdo de até 1 MiB são obrigatórios.');
    await scoped(db,request,'evidence.import',b.assetId,now,{profile:'evidence.import',inputBytes:bytes.length});
    return db.transaction(tx=>preserve(tx,{organizationId:a.organizationId,actorId:a.id,assetId:b.assetId,name:b.name,mediaType:b.mediaType,bytes,source:'operator-import'},masterKey));
  });
  app.get('/api/evidence/:id',{schema:{params:object({id:uuid})}},async request=>{
    permit(request,'evidence.read');const a=request.actor!,id=(request.params as any).id;
    return db.transaction(async tx=>{const [row]=await tx.query('SELECT * FROM evidence WHERE id=$1 AND organization_id=$2',[id,a.organizationId]);if(!row)throw new HttpError(404,'NOT_FOUND','Evidência não encontrada.');const bytes=decrypt(row.content_cipher,masterKey,`evidence:${a.organizationId}:${id}`);await audit(tx,a.organizationId,a.id,'evidence.verified',id);return {...evidenceDto(row),integrityVerified:digest(bytes)===row.sha256};});
  });
  app.get('/api/evidence/:id/download',{schema:{params:object({id:uuid})}},async(request,reply)=>{
    permit(request,'evidence.read');if(request.actor!.role==='viewer')throw new HttpError(403,'ROLE_DENIED','Exportação de originais exige analista ou administrador.');
    const a=request.actor!,id=(request.params as any).id;
    const bytes=await db.transaction(async tx=>{const [row]=await tx.query('SELECT * FROM evidence WHERE id=$1 AND organization_id=$2',[id,a.organizationId]);if(!row)throw new HttpError(404,'NOT_FOUND','Evidência não encontrada.');const data=decrypt(row.content_cipher,masterKey,`evidence:${a.organizationId}:${id}`);if(digest(data)!==row.sha256)throw new HttpError(409,'INTEGRITY_FAILURE','Integridade divergente.');await audit(tx,a.organizationId,a.id,'evidence.exported',id,{sha256:row.sha256});return data;});
    return reply.header('Content-Disposition',`attachment; filename="evidence-${id}.bin"`).type('application/octet-stream').send(bytes);
  });
  app.get('/api/reports/:id',{schema:{params:object({id:uuid})}},async(request,reply)=>{
    permit(request,'reports.read');const a=request.actor!,id=(request.params as any).id;
    const report=await db.transaction(async tx=>{const [scan]=await tx.query('SELECT * FROM scans WHERE id=$1 AND organization_id=$2',[id,a.organizationId]);if(!scan)throw new HttpError(404,'NOT_FOUND','Relatório não encontrado.');const evidence=await tx.query('SELECT id,sha256,name,size_bytes FROM evidence WHERE organization_id=$1 AND source=$2',[a.organizationId,`securebuild:${id}`]);await audit(tx,a.organizationId,a.id,'report.exported',id);return {schemaVersion:1,product:'I.See Sentinel',generatedAt:new Date(now()).toISOString(),scan:scanDto(scan),evidence,barriers:evaluateBarrierMatrix(scan.result),risk:assessRisk(scan.result.findings),disclaimer:'Análise estática limitada dos arquivos fornecidos. Não atesta segurança integral ou conformidade.'};});
    return reply.header('Content-Disposition',`attachment; filename="sentinel-${id}.json"`).send(report);
  });
  app.get('/api/audit',async request=>{permit(request,'audit.read');return {items:(await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence DESC LIMIT 100',[request.actor!.organizationId])).map(r=>({id:r.id,action:r.action,actorId:r.actor_id,resourceId:r.resource_id,createdAt:r.created_at,hash:r.hash,previousHash:r.previous_hash,details:r.details}))};});
  app.get('/api/audit/verify',async request=>{permit(request,'audit.read');return verifyAuditChain(await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY sequence',[request.actor!.organizationId]));});
  app.post('/api/events',{schema:{body:object({assetId:uuid,externalId:uuid,schemaVersion:{const:1},type:{enum:['auth.failure','auth.success','configuration.change']},source:str(120),occurredAt:{type:'string',format:'date-time'},data:object({subject:str(120),synthetic:{type:'boolean'}})},['assetId','schemaVersion','type','source','occurredAt','data'])}},async request=>{
    const a=request.actor!,b=request.body as any,asset=await scoped(db,request,'event.ingest',b.assetId,now,{profile:'events.ingest',inputBytes:Buffer.byteLength(JSON.stringify(b),'utf8')});
    if(b.data.synthetic&&asset.environment!=='lab')throw new HttpError(403,'LAB_REQUIRED','Eventos de simulação exigem ativo de laboratório.');
    if(Math.abs(new Date(b.occurredAt).getTime()-now())>86400000)throw new HttpError(400,'EVENT_TIME','Evento deve estar na janela de 24 horas.');
    return db.transaction(async tx=>{
      await tx.query('SELECT id FROM assets WHERE id=$1 AND organization_id=$2 FOR UPDATE',[b.assetId,a.organizationId]);
      if(b.externalId) {
        const [existing]=await tx.query('SELECT id,type,occurred_at,data FROM security_events WHERE organization_id=$1 AND asset_id=$2 AND source=$3 AND external_id=$4',[a.organizationId,b.assetId,b.source,b.externalId]);
        if(existing){if(existing.type!==b.type||new Date(existing.occurred_at).toISOString()!==new Date(b.occurredAt).toISOString()||canonical(existing.data)!==canonical(b.data))throw new HttpError(409,'IDEMPOTENCY_CONFLICT','Identificador reutilizado com conteúdo diferente.');return {id:existing.id,alertId:null,incidentId:null,duplicate:true};}
      }
      const id=randomUUID();await tx.query('INSERT INTO security_events(id,organization_id,asset_id,schema_version,type,source,occurred_at,data,external_id) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8)',[id,a.organizationId,b.assetId,b.type,b.source,b.occurredAt,JSON.stringify(b.data),b.externalId??null]);
      let incidentId:string|null=null,alertId:string|null=null;
      if(b.type==='auth.failure') {
        const events=await tx.query(`SELECT id FROM security_events WHERE organization_id=$1 AND asset_id=$2 AND type='auth.failure' AND source=$3 AND data->>'subject'=$4 AND data->>'synthetic'=$5 AND received_at>$6 ORDER BY received_at DESC LIMIT 5`,[a.organizationId,b.assetId,b.source,b.data.subject,String(b.data.synthetic),new Date(now()-5*60000)]);
        const existing=await tx.query(`SELECT id FROM incidents WHERE organization_id=$1 AND asset_id=$2 AND rule_id=$3 AND created_at>$4`,[a.organizationId,b.assetId,`AUTH-FAIL-5:${digest(canonical([b.source,b.data.subject,b.data.synthetic])).slice(0,16)}`,new Date(now()-5*60000)]);
        if(events.length===5&&!existing.length) {
          incidentId=randomUUID();alertId=randomUUID();const eventIds=events.map(e=>e.id);
          await tx.query('INSERT INTO incidents(id,organization_id,asset_id,rule_id,title,event_ids) VALUES($1,$2,$3,$4,$5,$6)',[incidentId,a.organizationId,b.assetId,`AUTH-FAIL-5:${digest(canonical([b.source,b.data.subject,b.data.synthetic])).slice(0,16)}`,'Cinco falhas de autenticação em cinco minutos',JSON.stringify(eventIds)]);
          await tx.query('INSERT INTO alerts(id,organization_id,asset_id,incident_id,rule_id,rule_version,title,severity,confidence,synthetic,event_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[alertId,a.organizationId,b.assetId,incidentId,'AUTH-FAIL-5','1.0.0','Falhas de autenticação correlacionadas','medium','medium',b.data.synthetic,JSON.stringify(eventIds)]);
          await audit(tx,a.organizationId,a.id,'alert.created',alertId,{ruleId:'AUTH-FAIL-5',ruleVersion:'1.0.0',synthetic:b.data.synthetic,incidentId});await audit(tx,a.organizationId,a.id,'incident.opened',incidentId,{ruleVersion:'1.0.0',synthetic:b.data.synthetic});
        }
      }
      await audit(tx,a.organizationId,a.id,'event.ingested',id,{type:b.type,source:b.source,synthetic:b.data.synthetic});return {id,alertId,incidentId,duplicate:false};
    });
  });
  app.get('/api/events',async request=>{permit(request,'events.read');return {items:await db.query('SELECT id,asset_id AS "assetId",schema_version AS "schemaVersion",type,source,occurred_at AS "occurredAt",received_at AS "receivedAt",data FROM security_events WHERE organization_id=$1 ORDER BY received_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.get('/api/incidents',async request=>{permit(request,'events.read');return {items:await db.query('SELECT i.id,i.asset_id AS "assetId",i.rule_id AS "ruleId",i.title,i.status,i.event_ids AS "eventIds",i.created_at AS "createdAt",EXISTS(SELECT 1 FROM alerts a WHERE a.incident_id=i.id AND a.organization_id=i.organization_id AND a.synthetic) AS synthetic FROM incidents i WHERE i.organization_id=$1 ORDER BY i.created_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.get('/api/alerts',async request=>{permit(request,'events.read');return {items:await db.query('SELECT id,asset_id AS "assetId",incident_id AS "incidentId",rule_id AS "ruleId",rule_version AS "ruleVersion",title,severity,confidence,status,synthetic,event_ids AS "eventIds",created_at AS "createdAt" FROM alerts WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.post('/api/alerts/:id/status',{schema:{params:object({id:uuid}),body:object({status:{enum:['open','investigating','false_positive','closed']}})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id,status=(request.body as any).status;
    return db.transaction(async tx=>{const rows=await tx.query('UPDATE alerts SET status=$3 WHERE id=$1 AND organization_id=$2 RETURNING id',[id,a.organizationId,status]);if(!rows.length)throw new HttpError(404,'NOT_FOUND','Alerta não encontrado.');await audit(tx,a.organizationId,a.id,'alert.triaged',id,{status});return {id,status};});
  });
  await registerAgents(app,{db,masterKey,now});
  await registerAuthorizationManager(app,{db,masterKey,now});
  await registerAssessmentPlans(app,{db,now});
  await registerOperations(app,{db,masterKey,now});
  await registerAnalyses(app,{db,masterKey,now});
  await registerReporting(app,{db,masterKey,now});
  await registerLab(app,{db,masterKey,now,nmapPath:options.nmapPath??process.env.SENTINEL_NMAP_PATH,runner:options.labRunner});
  await registerForensics(app,{db,masterKey,now,pythonPath:options.pythonPath??process.env.SENTINEL_PYTHON_PATH,runner:options.forensicRunner});
  await registerGraph(app,{db});
  await registerImports(app,{db,masterKey,now,pythonPath:options.pythonPath??process.env.SENTINEL_PYTHON_PATH,runner:options.importRunner});
  if(options.staticDir&&existsSync(options.staticDir))await app.register(staticFiles,{root:options.staticDir,prefix:'/',index:['index.html']});
  await app.ready();return app;
}
function scanDto(r:any) {return {id:r.id,assetId:r.asset_id,status:'completed',createdAt:r.created_at,result:r.result};}
function evidenceDto(r:any) {return {id:r.id,assetId:r.asset_id,name:r.name,mediaType:r.media_type,sha256:r.sha256,sizeBytes:r.size_bytes,createdBy:r.created_by,source:r.source,createdAt:r.created_at};}
async function preserve(tx:Sql,input:{organizationId:string;actorId:string;assetId:string;name:string;mediaType:string;bytes:Buffer;source:string},key:Buffer) {
  const id=randomUUID(),sha256=digest(input.bytes),cipher=encrypt(input.bytes,key,`evidence:${input.organizationId}:${id}`);
  const [row]=await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',[id,input.organizationId,input.assetId,input.name,input.mediaType,sha256,input.bytes.length,cipher,input.actorId,input.source]);
  await audit(tx,input.organizationId,input.actorId,'evidence.preserved',id,{sha256,sizeBytes:input.bytes.length,source:input.source});return evidenceDto(row);
}
