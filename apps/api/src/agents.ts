import {createHmac,randomBytes,randomUUID} from 'node:crypto';
import type {FastifyInstance} from 'fastify';
import type {Database} from './db.ts';
import {HttpError,object,str,uuid} from './auth.ts';
import {permit,scoped,storedScopeAllowed} from './policy.ts';
import {encrypt,decrypt,digest,canonical,constantEqual} from './security.ts';
import {audit} from './audit.ts';

const hex={type:'string',pattern:'^[0-9a-f]{64}$'};
const observationSchema=object({schemaVersion:{const:1},observationId:hex,assetId:uuid,
  observedAtEpochMs:{type:'integer',minimum:0,maximum:Number.MAX_SAFE_INTEGER},source:{const:'sentinel-agent'},type:{const:'integrity.observation'},synthetic:{const:false},
  host:object({os:str(40),architecture:str(40),agentProcessId:{type:'integer',minimum:1,maximum:4294967295},agentVersion:str(40)}),
  file:object({pathId:hex,pathLabel:{type:'string',minLength:1,maxLength:240,pattern:'^[^\\x00-\\x1f\\x7f/\\\\:]+$'},bytes:{type:'integer',minimum:0,maximum:1048576},sha256:hex})});
const agentDto=(r:any,time:number)=>({id:r.id,assetId:r.asset_id,name:r.name,createdAt:r.created_at,expiresAt:r.expires_at,revokedAt:r.revoked_at,lastSeenAt:r.last_seen_at,
  status:r.revoked_at?'revoked':new Date(r.expires_at).getTime()<=time?'expired':!r.last_seen_at?'awaiting':time-new Date(r.last_seen_at).getTime()>120000?'stale':'recent',
  capability:'file_integrity_readonly'});

export async function registerAgents(app:FastifyInstance,{db,masterKey,now=Date.now}:{db:Database;masterKey:Buffer;now?:()=>number}) {
  // Preserve the exact bytes used by the sender. No cookie or browser identity is accepted here.
  app.addContentTypeParser('application/vnd.sentinel.agent+json',{parseAs:'buffer',bodyLimit:16384},(_request,body,done)=>done(null,body));
  app.get('/api/agents',async request=>{permit(request,'assets.read');return {items:(await db.query('SELECT id,asset_id,name,created_at,expires_at,revoked_at,last_seen_at FROM endpoint_agents WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])).map(r=>agentDto(r,now()))};});
  app.post('/api/agents',{schema:{body:object({assetId:uuid,name:str(120),expiresAt:{type:'string',format:'date-time'}})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,b=request.body as any,time=now();await scoped(db,request,'event.ingest',b.assetId,now,{profile:'agent.observe',phase:'prepare'});
    if(Date.parse(b.expiresAt)<=time||Date.parse(b.expiresAt)>time+31*86400000)throw new HttpError(400,'INVALID_EXPIRY','Credencial deve expirar em até 31 dias.');
    const id=randomUUID(),secret=randomBytes(32).toString('hex');
    return db.transaction(async tx=>{
      await tx.query('INSERT INTO endpoint_agents(id,organization_id,asset_id,name,secret_cipher,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,a.organizationId,b.assetId,b.name,encrypt(secret,masterKey,`agent:${a.organizationId}:${id}`),a.id,b.expiresAt]);
      await audit(tx,a.organizationId,a.id,'agent.enrolled',id,{assetId:b.assetId,expiresAt:b.expiresAt});
      return {id,assetId:b.assetId,name:b.name,expiresAt:b.expiresAt,credential:{agentId:id,secret},message:'Guarde a credencial agora. Ela não será exibida novamente.'};
    });
  });
  app.post('/api/agents/:id/revoke',{schema:{params:object({id:uuid})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id;
    return db.transaction(async tx=>{await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);const rows=await tx.query('UPDATE endpoint_agents SET revoked_at=$3 WHERE id=$1 AND organization_id=$2 AND revoked_at IS NULL RETURNING id',[id,a.organizationId,new Date(now())]);if(!rows.length)throw new HttpError(404,'NOT_FOUND','Agente não encontrado.');await audit(tx,a.organizationId,a.id,'agent.revoked',id);return {ok:true};});
  });
  app.get('/api/agents/observations',async request=>{permit(request,'events.read');return {items:await db.query('SELECT o.id,a.asset_id AS "assetId",o.agent_id AS "agentId",o.payload,o.result,o.evidence_id AS "evidenceId",o.incident_id AS "incidentId",o.received_at AS "receivedAt" FROM agent_observations o JOIN endpoint_agents a ON a.id=o.agent_id WHERE o.organization_id=$1 ORDER BY o.received_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.get('/api/agents/baselines',async request=>{permit(request,'events.read');return {items:await db.query('SELECT agent_id AS "agentId",path_id AS "pathId",path_label AS "pathLabel",sha256,observation_id AS "observationId",approved_at AS "approvedAt" FROM integrity_baselines WHERE organization_id=$1 ORDER BY approved_at DESC LIMIT 100',[request.actor!.organizationId])};});
  app.post('/api/agents/baselines',{schema:{body:object({observationId:uuid})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.body as any).observationId;
    return db.transaction(async tx=>{
      await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[a.organizationId]);
      const [o]=await tx.query('SELECT o.*,a.asset_id,a.revoked_at,a.expires_at FROM agent_observations o JOIN endpoint_agents a ON a.id=o.agent_id WHERE o.id=$1 AND o.organization_id=$2',[id,a.organizationId]);
      if(!o)throw new HttpError(404,'NOT_FOUND','Observação não encontrada.');
      if(o.revoked_at||Date.parse(o.expires_at)<=now())throw new HttpError(409,'AGENT_INACTIVE','Agente revogado ou expirado.');
      const [asset]=await tx.query('SELECT * FROM assets WHERE id=$1 AND organization_id=$2',[o.asset_id,a.organizationId]);
      if(!asset)throw new HttpError(404,'NOT_FOUND','Ativo não encontrado.');
      if(asset.authorization_mode==='managed'&&!await storedScopeAllowed(tx,a,'event.ingest',asset,now(),{profile:'agent.observe',phase:'prepare'}))throw new HttpError(403,'SCOPE_REQUIRED','A referência exige autorização vigente do perfil do agente.');
      const f=o.payload.file;
      await tx.query('INSERT INTO integrity_baselines(agent_id,organization_id,path_id,path_label,sha256,observation_id,approved_by,approved_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(agent_id,path_id) DO UPDATE SET sha256=EXCLUDED.sha256,path_label=EXCLUDED.path_label,observation_id=EXCLUDED.observation_id,approved_by=EXCLUDED.approved_by,approved_at=EXCLUDED.approved_at',[o.agent_id,a.organizationId,f.pathId,f.pathLabel,f.sha256,id,a.id,new Date(now())]);
      await audit(tx,a.organizationId,a.id,'integrity.baseline_approved',id,{agentId:o.agent_id,pathId:f.pathId,sha256:f.sha256});return {agentId:o.agent_id,pathId:f.pathId,sha256:f.sha256};
    });
  });
  app.post('/agent/v1/observations',{bodyLimit:16384,config:{rateLimit:{max:120,timeWindow:'1 minute'}}},async request=>{
    const h=request.headers,time=now(),id=h['x-sentinel-agent'],timestamp=h['x-sentinel-timestamp'],nonce=h['x-sentinel-nonce'],signature=h['x-sentinel-signature'];
    const unauth=()=>new HttpError(401,'AGENT_AUTH_FAILED','Assinatura, credencial ou validade do agente inválida.');
    if(request.url!=='/agent/v1/observations'||!Buffer.isBuffer(request.body)||typeof id!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)||typeof timestamp!=='string'||!/^\d{10,11}$/.test(timestamp)||Math.abs(time-Number(timestamp)*1000)>300000||typeof nonce!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(nonce)||typeof signature!=='string'||!/^[0-9a-f]{64}$/.test(signature))throw unauth();
    const [candidate]=await db.query('SELECT organization_id FROM endpoint_agents WHERE id=$1',[id]);if(!candidate)throw unauth();
    const raw=request.body,bodyHash=digest(raw);
    return db.transaction(async tx=>{
      await tx.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE',[candidate.organization_id]);
      const [agent]=await tx.query('SELECT a.*,s.environment,s.project_id,s.authorization_mode FROM endpoint_agents a JOIN assets s ON s.id=a.asset_id AND s.organization_id=a.organization_id WHERE a.id=$1 FOR UPDATE OF a',[id]);
      if(!agent||agent.revoked_at||new Date(agent.expires_at).getTime()<=time)throw unauth();
      const secret=decrypt(agent.secret_cipher,masterKey,`agent:${agent.organization_id}:${id}`).toString();
      const expected=createHmac('sha256',Buffer.from(secret,'hex')).update(`${timestamp}\n${nonce}\nPOST\n/agent/v1/observations\n${bodyHash}`).digest('hex');
      if(!constantEqual(expected,signature))throw unauth();
      let b:any;try {b=JSON.parse(raw.toString('utf8'));}catch {throw new HttpError(400,'INVALID_OBSERVATION','JSON inválido.');}
      if(!request.compileValidationSchema(observationSchema)(b))throw new HttpError(400,'INVALID_OBSERVATION','Observação inválida ou campos não permitidos.');
      if(b.assetId!==agent.asset_id)throw new HttpError(403,'ASSET_MISMATCH','A credencial está vinculada a outro ativo.');
      if(Math.abs(b.observedAtEpochMs-time)>300000)throw new HttpError(400,'OBSERVATION_TIME','Observação fora da janela de cinco minutos.');
      if(!await storedScopeAllowed(tx,{id,organizationId:agent.organization_id,role:'agent'},'event.ingest',{...agent,id:agent.asset_id},time,{profile:'agent.observe',inputBytes:raw.length}))throw new HttpError(403,'SCOPE_REQUIRED','Agente exige autorização vigente de ingestão para o ativo e tamanho da observação.');
      await tx.query('DELETE FROM agent_nonces WHERE agent_id=$1 AND received_at<$2',[id,new Date(time-600000)]);
      const inserted=await tx.query('INSERT INTO agent_nonces(agent_id,nonce,received_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING nonce',[id,nonce,new Date(time)]);
      if(!inserted.length)throw new HttpError(409,'NONCE_REPLAY','Requisição já recebida.');
      const [existing]=await tx.query('SELECT id,payload_hash,result,incident_id FROM agent_observations WHERE agent_id=$1 AND observation_id=$2',[id,b.observationId]);
      if(existing){if(existing.payload_hash!==bodyHash)throw new HttpError(409,'OBSERVATION_CONFLICT','Identificador reutilizado com conteúdo diferente.');return {id:existing.id,result:existing.result,incidentId:existing.incident_id,duplicate:true};}
      const [baseline]=await tx.query('SELECT * FROM integrity_baselines WHERE agent_id=$1 AND path_id=$2',[id,b.file.pathId]);
      const result=!baseline?'unbaselined':baseline.sha256===b.file.sha256?'unchanged':'changed';
      const observationId=randomUUID(),evidenceId=randomUUID(),eventId=randomUUID();let incidentId:string|null=null;
      await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[evidenceId,agent.organization_id,agent.asset_id,`observation-${observationId}.json`,'application/json',bodyHash,raw.length,encrypt(raw,masterKey,`evidence:${agent.organization_id}:${evidenceId}`),agent.created_by,`agent:${id}`]);
      await tx.query('INSERT INTO security_events(id,organization_id,asset_id,schema_version,type,source,occurred_at,received_at,data) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8)',[eventId,agent.organization_id,agent.asset_id,'integrity.observation',`agent:${id}`,new Date(b.observedAtEpochMs),new Date(time),JSON.stringify({agentId:id,pathId:b.file.pathId,pathLabel:b.file.pathLabel,sha256:b.file.sha256,baselineHash:baseline?.sha256??null,result,synthetic:false,evidenceId})]);
      if(result==='changed'){
        const ruleId=`FIM-CHANGE:${digest(canonical([id,b.file.pathId,baseline.sha256,b.file.sha256])).slice(0,32)}`;
        const [open]=await tx.query("SELECT id FROM incidents WHERE organization_id=$1 AND asset_id=$2 AND rule_id=$3 AND status IN ('open','investigating') ORDER BY created_at DESC LIMIT 1",[agent.organization_id,agent.asset_id,ruleId]);
        incidentId=open?.id??randomUUID();
        if(!open){
          await tx.query('INSERT INTO incidents(id,organization_id,asset_id,rule_id,title,event_ids) VALUES($1,$2,$3,$4,$5,$6)',[incidentId,agent.organization_id,agent.asset_id,ruleId,'Arquivo divergiu da referência aprovada',JSON.stringify([eventId])]);
          await tx.query('INSERT INTO alerts(id,organization_id,asset_id,incident_id,rule_id,rule_version,title,severity,confidence,synthetic,event_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,false,$10)',[randomUUID(),agent.organization_id,agent.asset_id,incidentId,'FIM-CHANGE','1.0.0','Alteração de integridade detectada','medium','high',JSON.stringify([eventId])]);
          await audit(tx,agent.organization_id,null,'incident.opened',incidentId,{agentId:id,ruleId:'FIM-CHANGE',evidenceId});
        }
      }
      await tx.query('INSERT INTO agent_observations(id,organization_id,agent_id,observation_id,payload_hash,payload,evidence_id,result,incident_id,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[observationId,agent.organization_id,id,b.observationId,bodyHash,JSON.stringify(b),evidenceId,result,incidentId,new Date(time)]);
      await tx.query('UPDATE endpoint_agents SET last_seen_at=$2 WHERE id=$1',[id,new Date(time)]);
      await audit(tx,agent.organization_id,null,'agent.observation_received',observationId,{agentId:id,result,evidenceId,sha256:bodyHash});
      return {id:observationId,result,incidentId,duplicate:false};
    });
  });
}
