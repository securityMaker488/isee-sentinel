import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { evaluatePolicy, scanFiles } from '@sentinel/core';
import type { Database, Sql } from './db.ts';
import { HttpError, object, str, uuid } from './auth.ts';
import { permit, scopeDto } from './policy.ts';
import { audit } from './audit.ts';
import { decrypt, digest, encrypt } from './security.ts';

const params = object({id:uuid});
const target = 'stored_lab_artifact';
const limitation = 'Altera somente uma cópia cifrada no laboratório do Sentinel. Não altera o host, não reinicia SSH e não comprova a configuração efetiva do sistema.';
type Change = {directive:string;from:string;to:'no';line:number};

/** Conservative text transformation. Ambiguity requires manual review; no host paths are opened. */
export function proposeSshArtifact(content:string) {
  if(Buffer.byteLength(content,'utf8')>256*1024 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(content))throw new HttpError(400,'INVALID_ARTIFACT','Envie texto UTF-8 de até 256 KiB sem caracteres de controle.');
  const endings=content.match(/\r\n|\n/g)??[],eol=endings[0]??'\n';
  const lines=content.split(/\r?\n/),output=[...lines],reasons:string[]=[],changes:Change[]=[];
  if(endings.some(value=>value!==eol)||content.replace(/\r\n/g,'').includes('\r'))reasons.push('Quebras de linha ambíguas exigem revisão.');
  const seen=new Set<string>();
  for(let index=0;index<lines.length;index++) {
    const line=lines[index].trim();if(!line||line.startsWith('#'))continue;
    const parsed=line.match(/^([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.+)$/);
    if(!parsed){reasons.push(`Linha ${index+1} não reconhecida.`);continue;}
    const directive=parsed[1].toLowerCase();
    if(directive==='match'||directive==='include'){reasons.push('Match ou Include exige avaliação da configuração completa.');continue;}
    if(directive!=='permitrootlogin'&&directive!=='passwordauthentication')continue;
    if(seen.has(directive)){reasons.push(`Diretiva ${parsed[1]} repetida.`);continue;}seen.add(directive);
    const value=parsed[2].match(/^([a-z-]+)(?:\s+(#.*))?$/i);
    const accepted=directive==='permitrootlogin'?['yes','no','prohibit-password','without-password','forced-commands-only']:['yes','no'];
    if(!value||!accepted.includes(value[1].toLowerCase())){reasons.push(`Valor não reconhecido em ${parsed[1]}.`);continue;}
    if(value[1].toLowerCase()!=='no') {
      const name=directive==='permitrootlogin'?'PermitRootLogin':'PasswordAuthentication';
      changes.push({directive:name,from:value[1].toLowerCase(),to:'no',line:index+1});
      output[index]=`${lines[index].match(/^\s*/)?.[0]??''}${name} no${value[2]?` ${value[2]}`:''}`;
    }
  }
  for(const directive of ['permitrootlogin','passwordauthentication'])if(!seen.has(directive))reasons.push(`Diretiva ${directive} ausente; valores herdados não são presumidos.`);
  const uniqueReasons=[...new Set(reasons)];
  return {status:uniqueReasons.length?'manual_review':changes.length?'proposed':'no_change',content:uniqueReasons.length?content:output.join(eol),changes:uniqueReasons.length?[]:changes,reasons:uniqueReasons};
}

function planDto(row:any) {
  return {id:row.id,assetId:row.asset_id,name:row.name,status:row.status,target,limitation,
    originalEvidenceId:row.original_evidence_id,proposedEvidenceId:row.proposed_evidence_id,
    originalHash:row.original_hash,proposedHash:row.proposed_hash,changes:row.changes,reasons:row.reasons,
    currentRevision:row.current_revision,createdAt:row.created_at,updatedAt:row.updated_at};
}
function unifiedPatch(original:string,proposed:string) {
  if(original===proposed)return '';
  const left=original.split('\n'),right=proposed.split('\n'),hasFinalNewline=original.endsWith('\n');
  if(hasFinalNewline){left.pop();right.pop();}
  const lines=['--- original/sshd_config','+++ proposed/sshd_config',`@@ -1,${left.length} +1,${right.length} @@`];
  left.forEach((line,index)=>{
    const lastUnterminated=index===left.length-1&&!hasFinalNewline;
    if(line===right[index])lines.push(` ${line}`);
    else {lines.push(`-${line}`);if(lastUnterminated)lines.push('\\ No newline at end of file');lines.push(`+${right[index]}`);}
    if(lastUnterminated)lines.push('\\ No newline at end of file');
  });
  return lines.join('\n')+'\n';
}
async function getCase(tx:Sql,id:string,organizationId:string,lock=false) {
  const [incident]=await tx.query(`SELECT * FROM incidents WHERE id=$1 AND organization_id=$2${lock?' FOR UPDATE':''}`,[id,organizationId]);
  if(!incident)throw new HttpError(404,'NOT_FOUND','Incidente não encontrado.');return incident;
}
async function requireLabScope(tx:Sql,request:FastifyRequest,assetId:string,now:()=>number) {
  const actor=request.actor!;
  const [asset]=await tx.query('SELECT * FROM assets WHERE id=$1 AND organization_id=$2 FOR SHARE',[assetId,actor.organizationId]);
  if(!asset)throw new HttpError(404,'NOT_FOUND','Ativo não encontrado.');
  if(asset.environment!=='lab')throw new HttpError(403,'LAB_REQUIRED','Este fluxo exige um ativo de laboratório.');
  const rows=await tx.query('SELECT * FROM authorizations WHERE organization_id=$1 AND asset_id=$2 AND revoked_at IS NULL FOR SHARE',[actor.organizationId,assetId]);
  for(const operation of ['scan','evidence.import'] as const) {
    if(!rows.some(row=>evaluatePolicy({identity:actor,operation,resource:{organizationId:actor.organizationId,assetId,environment:asset.environment},scope:scopeDto(row),now:new Date(now())}).allowed))throw new HttpError(403,'SCOPE_REQUIRED','Escopos vigentes scan e evidence.import são obrigatórios.');
  }
}
async function preserve(tx:Sql,request:FastifyRequest,assetId:string,name:string,content:string,key:Buffer) {
  const actor=request.actor!,id=randomUUID(),sha256=digest(content);
  await tx.query('INSERT INTO evidence(id,organization_id,asset_id,name,media_type,sha256,size_bytes,content_cipher,created_by,source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[id,actor.organizationId,assetId,name,'text/plain',sha256,Buffer.byteLength(content),encrypt(content,key,`evidence:${actor.organizationId}:${id}`),actor.id,'SecureFix stored lab artifact']);
  await audit(tx,actor.organizationId,actor.id,'evidence.preserved',id,{sha256,source:'SecureFix',target});return id;
}
async function evidenceContent(tx:Sql,org:string,id:string,key:Buffer,expectedHash:string) {
  const [row]=await tx.query('SELECT content_cipher,sha256 FROM evidence WHERE id=$1 AND organization_id=$2',[id,org]);
  if(!row)throw new HttpError(409,'EVIDENCE_MISSING','Evidência necessária não encontrada.');
  const bytes=decrypt(row.content_cipher,key,`evidence:${org}:${id}`);
  if(digest(bytes)!==row.sha256||row.sha256!==expectedHash)throw new HttpError(409,'INTEGRITY_FAILED','A evidência não corresponde ao hash esperado.');return bytes.toString('utf8');
}
async function revision(tx:Sql,request:FastifyRequest,planId:string,number:number,action:string,content:string,key:Buffer) {
  const a=request.actor!,id=randomUUID();
  await tx.query('INSERT INTO remediation_revisions(id,organization_id,plan_id,revision,action,sha256,content_cipher,actor_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[id,a.organizationId,planId,number,action,digest(content),encrypt(content,key,`remediation:${a.organizationId}:${planId}:${number}`),a.id]);
}

export async function registerOperations(app:FastifyInstance,options:{db:Database;masterKey:Buffer;now?:()=>number}) {
  const {db,masterKey}=options,now=options.now??Date.now;
  app.get('/api/incidents/:id/case',{schema:{params}},async request=>{
    permit(request,'events.read');const a=request.actor!,id=(request.params as any).id;
    const incident=await getCase(db,id,a.organizationId);
    const notes=await db.query('SELECT * FROM incident_notes WHERE organization_id=$1 AND incident_id=$2 ORDER BY created_at DESC,id DESC LIMIT 100',[a.organizationId,id]);
    const evidence=await db.query('SELECT e.id,e.name,e.sha256,e.size_bytes AS "sizeBytes",e.source,l.created_at AS "linkedAt" FROM incident_evidence l JOIN evidence e ON e.id=l.evidence_id AND e.organization_id=l.organization_id WHERE l.organization_id=$1 AND l.incident_id=$2 ORDER BY l.created_at DESC LIMIT 100',[a.organizationId,id]);
    const events=await db.query('SELECT id,type,source,occurred_at AS "occurredAt",data FROM security_events WHERE organization_id=$1 AND asset_id=$2 AND id=ANY($3::uuid[]) ORDER BY occurred_at LIMIT 100',[a.organizationId,incident.asset_id,incident.event_ids]);
    const history=await db.query('SELECT id,action,actor_id AS "actorId",details,created_at AS "createdAt" FROM audit_events WHERE organization_id=$1 AND resource_id=$2 ORDER BY sequence DESC LIMIT 100',[a.organizationId,id]);
    return {incident:{id,assetId:incident.asset_id,title:incident.title,status:incident.status,createdAt:incident.created_at},
      notes:notes.map(row=>{const bytes=decrypt(row.body_cipher,masterKey,`incident-note:${a.organizationId}:${row.id}`);if(digest(bytes)!==row.sha256)throw new HttpError(409,'INTEGRITY_FAILED','Nota com integridade inválida.');return {id:row.id,body:bytes.toString(),actorId:row.actor_id,createdAt:row.created_at};}),evidence,events,history,limit:100};
  });
  app.post('/api/incidents/:id/notes',{schema:{params,body:object({body:str(8000)})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id,body=(request.body as any).body.trim();
    if(!body)throw new HttpError(400,'INVALID_NOTE','A nota não pode estar vazia.');
    return db.transaction(async tx=>{await getCase(tx,id,a.organizationId,true);const noteId=randomUUID();
      await tx.query('INSERT INTO incident_notes(id,organization_id,incident_id,actor_id,body_cipher,sha256) VALUES($1,$2,$3,$4,$5,$6)',[noteId,a.organizationId,id,a.id,encrypt(body,masterKey,`incident-note:${a.organizationId}:${noteId}`),digest(body)]);
      await audit(tx,a.organizationId,a.id,'incident.note_added',id,{noteId,sha256:digest(body)});return {id:noteId};});
  });
  app.post('/api/incidents/:id/status',{schema:{params,body:object({status:{enum:['open','investigating','resolved','closed']}})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id,status=(request.body as any).status;
    return db.transaction(async tx=>{const incident=await getCase(tx,id,a.organizationId,true);
      const allowed:Record<string,string[]>={open:['investigating','closed'],investigating:['open','resolved'],resolved:['investigating','closed'],closed:['investigating']};
      if(!allowed[incident.status]?.includes(status))throw new HttpError(409,'INVALID_TRANSITION','Transição de investigação inválida.');
      await tx.query('UPDATE incidents SET status=$3 WHERE id=$1 AND organization_id=$2',[id,a.organizationId,status]);
      await audit(tx,a.organizationId,a.id,'incident.status_changed',id,{previous:incident.status,status});return {id,status};});
  });
  app.post('/api/incidents/:id/evidence',{schema:{params,body:object({evidenceId:uuid})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id,evidenceId=(request.body as any).evidenceId;
    return db.transaction(async tx=>{const incident=await getCase(tx,id,a.organizationId,true);
      const [evidence]=await tx.query('SELECT id FROM evidence WHERE id=$1 AND organization_id=$2 AND asset_id=$3',[evidenceId,a.organizationId,incident.asset_id]);
      if(!evidence)throw new HttpError(404,'NOT_FOUND','Evidência do mesmo ativo não encontrada.');
      const inserted=await tx.query('INSERT INTO incident_evidence(organization_id,incident_id,evidence_id,actor_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING evidence_id',[a.organizationId,id,evidenceId,a.id]);
      if(inserted.length)await audit(tx,a.organizationId,a.id,'incident.evidence_linked',id,{evidenceId});return {id,evidenceId,duplicate:!inserted.length};});
  });
  app.get('/api/remediations',async request=>{permit(request,'reports.read');return {items:(await db.query('SELECT * FROM remediation_plans WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[request.actor!.organizationId])).map(planDto)};});
  app.post('/api/remediations',{schema:{body:object({assetId:uuid,name:{...str(120),pattern:'^[A-Za-z0-9][A-Za-z0-9._ -]*$'},content:{type:'string',maxLength:262144}})}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,b=request.body as {assetId:string;name:string;content:string},proposal=proposeSshArtifact(b.content);
    return db.transaction(async tx=>{await requireLabScope(tx,request,b.assetId,now);
      const id=randomUUID(),original=await preserve(tx,request,b.assetId,`${b.name}.original`,b.content,masterKey),proposed=await preserve(tx,request,b.assetId,`${b.name}.proposed`,proposal.content,masterKey);
      const [row]=await tx.query('INSERT INTO remediation_plans(id,organization_id,asset_id,name,status,original_evidence_id,proposed_evidence_id,original_hash,proposed_hash,changes,reasons,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *',[id,a.organizationId,b.assetId,b.name,proposal.status,original,proposed,digest(b.content),digest(proposal.content),JSON.stringify(proposal.changes),JSON.stringify(proposal.reasons),a.id]);
      await revision(tx,request,id,1,'import',b.content,masterKey);await audit(tx,a.organizationId,a.id,'remediation.proposed',id,{target,status:proposal.status,originalHash:row.original_hash,proposedHash:row.proposed_hash});return planDto(row);});
  });
  app.get('/api/remediations/:id',{schema:{params}},async request=>{
    permit(request,'reports.read');const a=request.actor!,id=(request.params as any).id;
    if(a.role==='viewer')throw new HttpError(403,'ROLE_DENIED','Conteúdo de configuração exige analista ou administrador.');
    return db.transaction(async tx=>{const [row]=await tx.query('SELECT * FROM remediation_plans WHERE id=$1 AND organization_id=$2',[id,a.organizationId]);if(!row)throw new HttpError(404,'NOT_FOUND','Plano não encontrado.');
      const original=await evidenceContent(tx,a.organizationId,row.original_evidence_id,masterKey,row.original_hash),proposed=await evidenceContent(tx,a.organizationId,row.proposed_evidence_id,masterKey,row.proposed_hash);
      const revisions=await tx.query('SELECT revision,action,sha256,created_at AS "createdAt" FROM remediation_revisions WHERE organization_id=$1 AND plan_id=$2 ORDER BY revision',[a.organizationId,id]);
      await audit(tx,a.organizationId,a.id,'remediation.content_read',id,{target});return {...planDto(row),originalContent:original,proposedContent:proposed,patch:unifiedPatch(original,proposed),revisions};});
  });
  for(const action of ['approve','apply','verify','rollback'] as const)app.post(`/api/remediations/:id/${action}`,{schema:{params}},async request=>{
    permit(request,'scopes.create');const a=request.actor!,id=(request.params as any).id;
    return db.transaction(async tx=>{
      const [row]=await tx.query('SELECT * FROM remediation_plans WHERE id=$1 AND organization_id=$2 FOR UPDATE',[id,a.organizationId]);if(!row)throw new HttpError(404,'NOT_FOUND','Plano não encontrado.');
      await requireLabScope(tx,request,row.asset_id,now);
      const required:Record<string,string[]>={approve:['proposed'],apply:['approved'],verify:['applied'],rollback:['applied','verified']};
      if(!required[action].includes(row.status))throw new HttpError(409,'INVALID_TRANSITION','Etapa incompatível com o estado atual do plano.');
      const [current]=await tx.query('SELECT * FROM remediation_revisions WHERE organization_id=$1 AND plan_id=$2 AND revision=$3',[a.organizationId,id,row.current_revision]);
      if(!current)throw new HttpError(409,'REVISION_MISSING','Revisão atual ausente.');
      const bytes=decrypt(current.content_cipher,masterKey,`remediation:${a.organizationId}:${id}:${row.current_revision}`);
      const expected=['proposed','approved'].includes(row.status)?row.original_hash:row.proposed_hash;
      if(digest(bytes)!==current.sha256||current.sha256!==expected)throw new HttpError(409,'INTEGRITY_FAILED','Revisão atual não corresponde ao estado esperado.');
      let status=action==='approve'?'approved':action==='apply'?'applied':action==='verify'?'verified':'rolled_back';
      let currentRevision=row.current_revision,verification:unknown=null;
      if(action==='apply'||action==='rollback') {
        const restoring=action==='rollback',content=await evidenceContent(tx,a.organizationId,restoring?row.original_evidence_id:row.proposed_evidence_id,masterKey,restoring?row.original_hash:row.proposed_hash);
        currentRevision++;await revision(tx,request,id,currentRevision,action,content,masterKey);
      }
      if(action==='verify') {
        const result=scanFiles([{path:'sshd_config',content:bytes.toString('utf8')}]);
        const sshChecks=result.checks.filter(check=>['ssh.root_login','ssh.password_authentication'].includes(check.controlId));
        if(sshChecks.length!==2||sshChecks.some(check=>check.status!=='pass'))throw new HttpError(409,'VERIFICATION_FAILED','As duas verificações SSH não passaram.');
        verification={assurance:'static_configuration',sha256:current.sha256,checks:sshChecks,remainingFindings:result.findings,limitations:result.limitations};
      }
      const [updated]=await tx.query('UPDATE remediation_plans SET status=$3,current_revision=$4,updated_at=$5 WHERE id=$1 AND organization_id=$2 RETURNING *',[id,a.organizationId,status,currentRevision,new Date(now())]);
      await audit(tx,a.organizationId,a.id,`remediation.${action}`,id,{target,previous:row.status,status,revision:currentRevision,...(verification?{verification}:{} )});return {...planDto(updated),verification};
    });
  });
}
