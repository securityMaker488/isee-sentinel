import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { EXECUTION_PROFILES, ASSESSMENT_PLAN_LIMITS, ASSESSMENT_EXECUTION_PROFILES,
  normalizeAssessmentSteps, validAssessmentText, type AssessmentStep, type Identity, type ManagedExecution } from '@sentinel/core';
import type { Database, Sql } from './db.ts';
import { HttpError, object, str, uuid } from './auth.ts';
import { permit, storedScopeGrant } from './policy.ts';
import { audit } from './audit.ts';
import { canonical, digest } from './security.ts';

const hashSchema = { type: 'string', pattern: '^[0-9a-f]{64}$' };
const stepIdSchema = { type: 'string', pattern: '^[A-Za-z0-9_-]{1,64}$' };
const stepSchema = object({ id: stepIdSchema, name: str(160), assetId: uuid, profile: { enum: EXECUTION_PROFILES.map(p => p.id) },
  address: str(15), ports: { type: 'array', minItems: 1, maxItems: 16, uniqueItems: true, items: { type: 'integer', minimum: 1, maximum: 65535 } } }, ['id', 'name', 'assetId', 'profile']);
const revisionProperties = { mandateId: uuid, authorizationRequestHash: hashSchema, objective: str(2000),
  steps: { type: 'array', minItems: 1, maxItems: ASSESSMENT_PLAN_LIMITS.maxSteps, items: stepSchema } };
export const assessmentContextSchema = object({ planId: uuid, revisionId: uuid, revisionHash: hashSchema, stepId: stepIdSchema });
export interface AssessmentContext { planId: string; revisionId: string; revisionHash: string; stepId: string }
const limitations = [
  'Criar ou revisar um plano não executa testes e não concede autorização adicional.',
  'Análise estática e inspeção de arquivos integram execução e evidências ao plano. Os demais perfis são planejamento.',
  'Cada execução revalida a revisão exata e a autorização vigente. Uma nova revisão preserva o histórico anterior.',
  'Fila recuperável, cancelamento supervisionado e limites gerais de recursos continuam pendentes.',
];
const planMeta = (r: any) => ({ id: r.id, name: r.name, projectId: r.project_id, createdAt: r.created_at });
const stepDto = (r: any): AssessmentStep => ({ id: r.step_id, name: r.name, assetId: r.asset_id, profile: r.profile,
  ...(r.address === null ? {} : { address: r.address, ports: r.ports }) });
const revisionMeta = (r: any) => ({ id: r.id, number: r.revision, hash: r.revision_hash, parentHash: r.parent_hash,
  mandateId: r.mandate_id, authorizationRequestHash: r.authorization_request_hash, objective: r.objective, createdAt: r.created_at });
function revisionHash(row: any, steps: AssessmentStep[]) {
  return digest(canonical({ schemaVersion: 1, organizationId: row.organization_id, planId: row.plan_id, projectId: row.project_id,
    revisionId: row.id, number: row.revision, parentHash: row.parent_hash, mandateId: row.mandate_id,
    authorizationRequestHash: row.authorization_request_hash, objective: row.objective, steps }));
}
async function planRow(sql: Sql, org: string, id: string) {
  const [row] = await sql.query('SELECT * FROM assessment_plans WHERE organization_id=$1 AND id=$2', [org, id]);
  if (!row) throw new HttpError(404, 'NOT_FOUND', 'Plano de avaliação não encontrado.');
  return row;
}
function validRevision(input: any) {
  const steps = normalizeAssessmentSteps(input.steps);
  if (!steps || !validAssessmentText(input.objective, 2000)) throw new HttpError(400, 'INVALID_PLAN', 'Objetivo ou passos inválidos. Use apenas os perfis e alvos estruturados permitidos.');
  return { objective: input.objective.trim(), steps };
}
async function validateMandate(sql: Sql, actor: Identity, projectId: string, input: any, steps: AssessmentStep[], now: number) {
  const [mandate] = await sql.query('SELECT * FROM authorization_mandates WHERE organization_id=$1 AND id=$2', [actor.organizationId, input.mandateId]);
  if (!mandate) throw new HttpError(404, 'NOT_FOUND', 'Autorização de avaliação não encontrada.');
  if (mandate.project_id !== projectId) throw new HttpError(400, 'INVALID_PLAN', 'A autorização pertence a outro projeto.');
  if (mandate.request_hash !== input.authorizationRequestHash) throw new HttpError(409, 'REVIEW_MISMATCH', 'Use o hash da autorização revisada.');
  if (mandate.status !== 'approved' || new Date(mandate.not_before).getTime() > now || new Date(mandate.expires_at).getTime() <= now) {
    throw new HttpError(403, 'SCOPE_REQUIRED', 'O plano exige uma autorização aprovada e vigente.');
  }
  const assets = await sql.query('SELECT * FROM assets WHERE organization_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR UPDATE', [actor.organizationId, [...new Set(steps.map(step => step.assetId))]]);
  for (const step of steps) {
    const asset = assets.find(item => item.id === step.assetId);
    if (!asset) throw new HttpError(404, 'NOT_FOUND', 'Ativo do plano não encontrado.');
    if (asset.project_id !== projectId) throw new HttpError(400, 'INVALID_PLAN', 'Todos os passos devem pertencer ao projeto do plano.');
    const profile = EXECUTION_PROFILES.find(item => item.id === step.profile)!;
    const execution: ManagedExecution = step.profile === 'lab.inventory'
      ? { profile: step.profile, address: step.address, ports: step.ports }
      : { profile: step.profile, phase: 'prepare' };
    for (const operation of profile.operations) {
      const grant = await storedScopeGrant(sql, actor, operation, asset, now, execution);
      if (!grant || grant.mandateId !== mandate.id || grant.requestHash !== mandate.request_hash) {
        throw new HttpError(403, 'SCOPE_REQUIRED', 'Um passo não corresponde ao ativo, perfil, alvo ou autorização vigente revisada.');
      }
    }
  }
  return mandate;
}
async function addRevision(sql: Sql, actor: Identity, plan: any, input: any, number: number, parentHash: string | null, now: number) {
  const { objective, steps } = validRevision(input);
  const mandate = await validateMandate(sql, actor, plan.project_id, input, steps, now);
  const revision = { id: randomUUID(), organization_id: actor.organizationId, plan_id: plan.id, project_id: plan.project_id,
    revision: number, parent_hash: parentHash, mandate_id: mandate.id, authorization_request_hash: mandate.request_hash, objective };
  const hash = revisionHash(revision, steps);
  await sql.query(`INSERT INTO assessment_plan_revisions(id,organization_id,plan_id,project_id,revision,schema_version,parent_hash,revision_hash,mandate_id,authorization_request_hash,objective,created_by)
    VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11)`, [revision.id, actor.organizationId, plan.id, plan.project_id, number, parentHash, hash, revision.mandate_id, revision.authorization_request_hash, objective, actor.id]);
  for (let index = 0; index < steps.length; index++) {
    const step = steps[index];
    await sql.query(`INSERT INTO assessment_plan_steps(organization_id,revision_id,project_id,mandate_id,step_id,position,name,asset_id,profile,address,ports)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [actor.organizationId, revision.id, plan.project_id, revision.mandate_id, step.id, index, step.name, step.assetId, step.profile, step.address ?? null, step.ports ? JSON.stringify(step.ports) : null]);
  }
  await audit(sql, actor.organizationId, actor.id, 'assessment.revision.created', revision.id,
    { planId: plan.id, number, revisionHash: hash, parentHash, mandateId: revision.mandate_id, authorizationRequestHash: revision.authorization_request_hash, steps: steps.length });
}
async function detail(sql: Sql, org: string, plan: any) {
  const revisions = await sql.query('SELECT * FROM assessment_plan_revisions WHERE organization_id=$1 AND plan_id=$2 ORDER BY revision DESC', [org, plan.id]);
  const rows = await sql.query(`SELECT s.* FROM assessment_plan_steps s JOIN assessment_plan_revisions r ON r.id=s.revision_id AND r.organization_id=s.organization_id
    WHERE s.organization_id=$1 AND r.plan_id=$2 ORDER BY s.position`, [org, plan.id]);
  const items = revisions.map(revision => {
    const steps = rows.filter(row => row.revision_id === revision.id).map(stepDto);
    if (!normalizeAssessmentSteps(steps) || revisionHash(revision, steps) !== revision.revision_hash) throw new HttpError(409, 'PLAN_INTEGRITY', 'A revisão do plano não corresponde ao registro preservado.');
    return { ...revisionMeta(revision), steps };
  });
  const results = await sql.query(`SELECT x.revision_id AS "revisionId",x.step_id AS "stepId",x.job_id AS "jobId",j.kind,j.status,x.created_at AS "createdAt",j.completed_at AS "completedAt",
    ARRAY(SELECT e.evidence_id FROM assessment_execution_evidence e WHERE e.organization_id=x.organization_id AND e.job_id=x.job_id ORDER BY e.evidence_id) AS "evidenceIds"
    FROM assessment_executions x JOIN assessment_plan_revisions r ON r.id=x.revision_id AND r.organization_id=x.organization_id
    JOIN jobs j ON j.id=x.job_id AND j.organization_id=x.organization_id WHERE x.organization_id=$1 AND r.plan_id=$2
    ORDER BY x.created_at DESC,x.job_id LIMIT 101`, [org, plan.id]);
  return { ...planMeta(plan), revisions: items, results: results.slice(0, 100), resultsTruncated: results.length > 100, limitations };
}

export async function registerAssessmentPlans(app: FastifyInstance, { db, now = Date.now }: { db: Database; now?: () => number }) {
  app.get('/api/assessment-plans/catalog', async request => {
    permit(request, 'findings.read');
    return { schemaVersion: 1, profiles: EXECUTION_PROFILES.map(profile => ({ ...profile, planExecutionSupported: ASSESSMENT_EXECUTION_PROFILES.includes(profile.id) })), limits: ASSESSMENT_PLAN_LIMITS, limitations };
  });
  app.get('/api/assessment-plans', async request => {
    permit(request, 'findings.read');
    const rows = await db.query(`SELECT p.*,r.id AS revision_id,r.revision,r.revision_hash,r.mandate_id,r.authorization_request_hash FROM assessment_plans p
      JOIN assessment_plan_revisions r ON r.organization_id=p.organization_id AND r.plan_id=p.id
      WHERE p.organization_id=$1 AND r.revision=(SELECT max(v.revision) FROM assessment_plan_revisions v WHERE v.organization_id=p.organization_id AND v.plan_id=p.id)
      ORDER BY p.created_at DESC,p.id LIMIT 100`, [request.actor!.organizationId]);
    return { items: rows.map(row => ({ ...planMeta(row), latestRevision: { id: row.revision_id, number: row.revision, hash: row.revision_hash, mandateId: row.mandate_id, authorizationRequestHash: row.authorization_request_hash } })) };
  });
  app.get('/api/assessment-plans/:id', { schema: { params: object({ id: uuid }) } }, async request => {
    permit(request, 'findings.read');
    const actor = request.actor!, id = (request.params as any).id;
    return db.transaction(async sql => {
      // Audit acquires the same organization lock used by revisions and executions.
      // Read the history after that lock so results cannot race ahead of its revisions.
      await audit(sql, actor.organizationId, actor.id, 'assessment.viewed', id);
      return detail(sql, actor.organizationId, await planRow(sql, actor.organizationId, id));
    });
  });
  app.post('/api/assessment-plans', { schema: { body: object({ name: str(120), projectId: uuid, ...revisionProperties }) } }, async request => {
    permit(request, 'scopes.create');
    const actor = request.actor!, input = request.body as any;
    if (!validAssessmentText(input.name, 120)) throw new HttpError(400, 'INVALID_PLAN', 'Informe um nome válido para o plano.');
    return db.transaction(async sql => {
      await sql.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [actor.organizationId]);
      if (!(await sql.query('SELECT id FROM projects WHERE organization_id=$1 AND id=$2', [actor.organizationId, input.projectId])).length) throw new HttpError(404, 'NOT_FOUND', 'Projeto não encontrado.');
      const [plan] = await sql.query('INSERT INTO assessment_plans(id,organization_id,project_id,name,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *', [randomUUID(), actor.organizationId, input.projectId, input.name.trim(), actor.id]);
      await addRevision(sql, actor, plan, input, 1, null, now());
      return detail(sql, actor.organizationId, plan);
    });
  });
  app.post('/api/assessment-plans/:id/revisions', { schema: { params: object({ id: uuid }), body: object({ parentHash: hashSchema, ...revisionProperties }) } }, async request => {
    permit(request, 'scopes.create');
    const actor = request.actor!, input = request.body as any, id = (request.params as any).id;
    return db.transaction(async sql => {
      await sql.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [actor.organizationId]);
      const plan = await planRow(sql, actor.organizationId, id);
      const [latest] = await sql.query('SELECT revision,revision_hash FROM assessment_plan_revisions WHERE organization_id=$1 AND plan_id=$2 ORDER BY revision DESC LIMIT 1', [actor.organizationId, id]);
      if (!latest || latest.revision_hash !== input.parentHash) throw new HttpError(409, 'REVISION_CONFLICT', 'O plano mudou. Recarregue e revise a versão atual antes de salvar.');
      if (latest.revision >= ASSESSMENT_PLAN_LIMITS.maxRevisions) throw new HttpError(409, 'REVISION_LIMIT', 'O plano atingiu o limite de revisões.');
      await addRevision(sql, actor, plan, input, latest.revision + 1, latest.revision_hash, now());
      return detail(sql, actor.organizationId, plan);
    });
  });
}

/** Called under the organization's lock immediately before an implemented executor runs. */
export async function validateAssessmentExecution(sql: Sql, actor: Identity, context: AssessmentContext, assetId: string, execution: ManagedExecution, now: number) {
  const plan = await planRow(sql, actor.organizationId, context.planId);
  const [revision] = await sql.query('SELECT * FROM assessment_plan_revisions WHERE organization_id=$1 AND plan_id=$2 AND id=$3', [actor.organizationId, plan.id, context.revisionId]);
  if (!revision) throw new HttpError(404, 'NOT_FOUND', 'Revisão do plano não encontrada.');
  if (revision.revision_hash !== context.revisionHash) throw new HttpError(409, 'REVIEW_MISMATCH', 'A execução deve corresponder à revisão selecionada.');
  const rows = await sql.query('SELECT * FROM assessment_plan_steps WHERE organization_id=$1 AND revision_id=$2 ORDER BY position', [actor.organizationId, revision.id]);
  const steps = rows.map(stepDto);
  if (!normalizeAssessmentSteps(steps) || revisionHash(revision, steps) !== revision.revision_hash) throw new HttpError(409, 'PLAN_INTEGRITY', 'A revisão não corresponde ao registro preservado.');
  const step = steps.find(item => item.id === context.stepId);
  if (!step) throw new HttpError(404, 'NOT_FOUND', 'Passo do plano não encontrado.');
  if (step.assetId !== assetId.toLowerCase() || step.profile !== execution.profile || !ASSESSMENT_EXECUTION_PROFILES.includes(execution.profile)) throw new HttpError(403, 'PLAN_STEP_MISMATCH', 'O executor e o ativo não correspondem ao passo revisado.');
  const [asset] = await sql.query('SELECT * FROM assets WHERE organization_id=$1 AND id=$2 FOR UPDATE', [actor.organizationId, assetId]);
  if (!asset || asset.project_id !== plan.project_id) throw new HttpError(403, 'PLAN_STEP_MISMATCH', 'O contexto do ativo não corresponde ao plano.');
  const profile = EXECUTION_PROFILES.find(item => item.id === execution.profile)!;
  for (const operation of profile.operations) {
    const grant = await storedScopeGrant(sql, actor, operation, asset, now, execution);
    if (!grant || grant.mandateId !== revision.mandate_id || grant.requestHash !== revision.authorization_request_hash) throw new HttpError(403, 'SCOPE_REQUIRED', 'A autorização exata desta revisão não está vigente ou não cobre a entrada.');
  }
}
export async function recordAssessmentExecution(sql: Sql, actor: Identity, context: AssessmentContext, assetId: string, jobId: string, profile = 'static.scan') {
  await sql.query('INSERT INTO assessment_executions(job_id,organization_id,revision_id,revision_hash,step_id,asset_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)', [jobId, actor.organizationId, context.revisionId, context.revisionHash, context.stepId, assetId, actor.id]);
  await audit(sql, actor.organizationId, actor.id, 'assessment.execution.started', jobId, { planId: context.planId, revisionId: context.revisionId, revisionHash: context.revisionHash, stepId: context.stepId, assetId, profile });
}
export async function recordAssessmentEvidence(sql: Sql, org: string, assetId: string, jobId: string, evidenceIds: string[]) {
  for (const evidenceId of evidenceIds) await sql.query('INSERT INTO assessment_execution_evidence(organization_id,job_id,asset_id,evidence_id) VALUES($1,$2,$3,$4)', [org, jobId, assetId, evidenceId]);
}
