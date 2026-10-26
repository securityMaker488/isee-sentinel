import { createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { assessRisk, type Finding } from '@sentinel/core';
import type { Database, Sql } from './db.ts';
import { permit } from './policy.ts';

export interface GraphNode { id: string; type: string; label: string; assetId?: string; data: Record<string, unknown> }
export interface GraphEdge { id: string; from: string; to: string; relation: string }
export interface GraphResult { nodes: GraphNode[]; edges: GraphEdge[]; truncated: boolean; counts: { nodes: number; edges: number; byType: Record<string, number> }; limitations: string[] }
const MAX_NODES = 200, MAX_EDGES = 500;
const id = (type: string, value: string) => `${type}:${value}`;
const label = (value: unknown, fallback: string) => typeof value === 'string' && value ? value.slice(0, 240) : fallback;

/** Uses persisted, tenant-scoped relationships only; never infers a reachable attack path. */
export async function buildGraph(sql: Sql, organizationId: string): Promise<GraphResult> {
  const result: GraphResult = { nodes: [], edges: [], truncated: false, counts: { nodes: 0, edges: 0, byType: {} }, limitations: [
    'Grafo de relacionamentos registrados na empresa em contexto. Uma ligação não demonstra caminho explorável, acesso de rede ou propagação de ataque.',
    'Recorte limitado a até 200 nós e 500 ligações. Projetos/ativos são ordenados por nome e ID; registros operacionais pelos mais recentes, com ID para desempate. Limites por categoria podem produzir um recorte menor.',
    'Achados correspondem somente à última análise SecureBuild de cada ativo exibido. O risco estático só é calculado quando todos os achados dessa execução entraram no recorte; não incorpora risco global, rede, exploração ou eficácia de correções.',
    'Evidências são referências e hashes armazenados, sem descriptografia ou verificação nesta consulta. Planos de correção representam cópias de artefatos, sem presumir alteração do host.',
  ] };
  const nodes = new Map<string, GraphNode>(), edges = new Set<string>();
  function add(node: GraphNode, parent?: string, relation = 'contains'): boolean {
    if (nodes.has(node.id)) return true;
    if (nodes.size >= MAX_NODES || (parent && !nodes.has(parent))) { result.truncated = true; return false; }
    nodes.set(node.id, node); result.nodes.push(node);
    if (parent) link(parent, node.id, relation);
    return true;
  }
  function link(from: string, to: string, relation: string): void {
    if (!nodes.has(from) || !nodes.has(to)) return;
    const edgeId = createHash('sha256').update(JSON.stringify([from, to, relation])).digest('hex').slice(0, 32);
    if (edges.has(edgeId)) return;
    if (edges.size >= MAX_EDGES) { result.truncated = true; return; }
    edges.add(edgeId); result.edges.push({ id: edgeId, from, to, relation });
  }
  function bounded<T>(rows: T[], max: number): T[] { if (rows.length > max) result.truncated = true; return rows.slice(0, max); }
  const [organization] = await sql.query('SELECT id,name FROM organizations WHERE id=$1', [organizationId]);
  if (!organization) return result;
  const organizationNode = id('organization', organization.id);
  add({ id: organizationNode, type: 'organization', label: label(organization.name, 'Empresa'), data: {} });
  const projects = bounded(await sql.query('SELECT id,name FROM projects WHERE organization_id=$1 ORDER BY name,id LIMIT 21', [organizationId]), 20);
  for (const row of projects) add({ id: id('project', row.id), type: 'project', label: label(row.name, 'Projeto'), data: {} }, organizationNode, 'has_project');
  const assets = bounded(await sql.query('SELECT id,name,kind,environment,criticality,project_id FROM assets WHERE organization_id=$1 AND (project_id IS NULL OR project_id=ANY($2::uuid[])) ORDER BY name,id LIMIT 41', [organizationId, projects.map(row => row.id)]), 40);
  for (const row of assets) add({ id: id('asset', row.id), type: 'asset', label: label(row.name, 'Ativo'), assetId: row.id, data: { kind: row.kind, environment: row.environment, criticality: row.criticality, risk: { level: 'unknown', reason: 'Sem análise SecureBuild neste recorte.' } } }, row.project_id ? id('project', row.project_id) : organizationNode, 'has_asset');
  if (!assets.length) { result.counts = { nodes: nodes.size, edges: edges.size, byType: { organization: 1, ...(projects.length ? { project: projects.length } : {}) } }; return result; }
  const assetIds = assets.map(row => row.id);
  const scans = await sql.query('SELECT DISTINCT ON(asset_id) id,asset_id,created_at,jsonb_array_length(result->\'findings\') AS finding_count FROM scans WHERE organization_id=$1 AND asset_id=ANY($2::uuid[]) ORDER BY asset_id,created_at DESC,id DESC LIMIT 40', [organizationId, assetIds]);
  for (const row of scans) add({ id: id('scan', row.id), type: 'scan', label: 'Última análise SecureBuild', assetId: row.asset_id, data: { createdAt: row.created_at, findingCount: row.finding_count } }, id('asset', row.asset_id), 'latest_static_scan');
  const findings = bounded(await sql.query('SELECT id,asset_id,scan_id,evidence_id,details FROM findings WHERE organization_id=$1 AND scan_id=ANY($2::uuid[]) ORDER BY created_at DESC,id LIMIT 31', [organizationId, scans.map(row => row.id)]), 30);
  for (const row of findings) add({ id: id('finding', row.id), type: 'finding', label: label(row.details?.title, 'Achado'), assetId: row.asset_id, data: { ruleId: row.details?.ruleId, severity: row.details?.severity, confidence: row.details?.confidence } }, id('scan', row.scan_id), 'produced_finding');
  for (const row of scans) {
    const included = findings.filter(finding => finding.scan_id === row.id && nodes.has(id('finding', finding.id)));
    const asset = nodes.get(id('asset', row.asset_id))!;
    if (Number.isInteger(row.finding_count) && row.finding_count === included.length) {
      const risk = assessRisk(included.map(item => item.details as Finding));
      asset.data.risk = { score: risk.score, level: risk.level, findingCount: included.length, scanId: row.id, method: 'SecureBuild estático; somente a última execução', explanation: risk.explanation };
    } else asset.data.risk = { level: 'unknown', scanId: row.id, reason: 'Todos os achados da última execução não estão disponíveis neste recorte.' };
  }
  const incidents = bounded(await sql.query('SELECT id,asset_id,title,status,rule_id,created_at FROM incidents WHERE organization_id=$1 AND asset_id=ANY($2::uuid[]) ORDER BY created_at DESC,id LIMIT 11', [organizationId, assetIds]), 10);
  for (const row of incidents) add({ id: id('incident', row.id), type: 'incident', label: label(row.title, 'Incidente'), assetId: row.asset_id, data: { status: row.status, ruleId: row.rule_id, createdAt: row.created_at } }, id('asset', row.asset_id), 'has_incident');
  const alerts = bounded(await sql.query('SELECT id,asset_id,incident_id,title,status,severity,synthetic,created_at FROM alerts WHERE organization_id=$1 AND asset_id=ANY($2::uuid[]) AND incident_id=ANY($3::uuid[]) ORDER BY created_at DESC,id LIMIT 11', [organizationId, assetIds, incidents.map(row => row.id)]), 10);
  for (const row of alerts) add({ id: id('alert', row.id), type: 'alert', label: label(row.title, 'Alerta'), assetId: row.asset_id, data: { status: row.status, severity: row.severity, synthetic: row.synthetic, createdAt: row.created_at } }, id('incident', row.incident_id), 'has_alert');
  const analyses = bounded(await sql.query('SELECT id,asset_id,kind,evidence_id,created_at,jsonb_array_length(report->\'findings\') AS finding_count FROM artifact_analyses WHERE organization_id=$1 AND asset_id=ANY($2::uuid[]) ORDER BY created_at DESC,id LIMIT 11', [organizationId, assetIds]), 10);
  for (const row of analyses) add({ id: id('analysis', row.id), type: 'analysis', label: `Análise de artefato: ${label(row.kind, 'tipo não informado')}`, assetId: row.asset_id, data: { kind: row.kind, findingCount: row.finding_count, createdAt: row.created_at } }, id('asset', row.asset_id), 'has_artifact_analysis');
  const plans = bounded(await sql.query('SELECT id,asset_id,name,status,original_evidence_id,proposed_evidence_id,created_at FROM remediation_plans WHERE organization_id=$1 AND asset_id=ANY($2::uuid[]) ORDER BY created_at DESC,id LIMIT 11', [organizationId, assetIds]), 10);
  for (const row of plans) add({ id: id('remediation', row.id), type: 'remediation', label: label(row.name, 'Plano de correção'), assetId: row.asset_id, data: { status: row.status, target: 'stored_lab_artifact', createdAt: row.created_at } }, id('asset', row.asset_id), 'has_artifact_remediation');
  const caseLinks = bounded(await sql.query('SELECT incident_id,evidence_id FROM incident_evidence WHERE organization_id=$1 AND incident_id=ANY($2::uuid[]) ORDER BY incident_id,evidence_id LIMIT 51', [organizationId, incidents.map(row => row.id)]), 50);
  const referenced = [...findings.map(row => row.evidence_id), ...analyses.map(row => row.evidence_id), ...plans.flatMap(row => [row.original_evidence_id, row.proposed_evidence_id]), ...caseLinks.map(row => row.evidence_id)];
  const evidence = bounded(await sql.query('SELECT id,asset_id,name,sha256,media_type,size_bytes,created_at FROM evidence WHERE organization_id=$1 AND asset_id=ANY($2::uuid[]) ORDER BY CASE WHEN id=ANY($3::uuid[]) THEN 0 ELSE 1 END,created_at DESC,id LIMIT 31', [organizationId, assetIds, referenced]), 30);
  for (const row of evidence) add({ id: id('evidence', row.id), type: 'evidence', label: label(row.name, 'Evidência'), assetId: row.asset_id, data: { sha256: row.sha256, mediaType: row.media_type, bytes: row.size_bytes, createdAt: row.created_at } }, id('asset', row.asset_id), 'has_evidence');
  for (const row of findings) link(id('finding', row.id), id('evidence', row.evidence_id), 'supported_by');
  for (const row of analyses) link(id('analysis', row.id), id('evidence', row.evidence_id), 'analyzed_evidence');
  for (const row of plans) { link(id('remediation', row.id), id('evidence', row.original_evidence_id), 'original_evidence'); link(id('remediation', row.id), id('evidence', row.proposed_evidence_id), 'proposed_evidence'); }
  for (const row of caseLinks) link(id('incident', row.incident_id), id('evidence', row.evidence_id), 'case_evidence');
  result.counts.nodes = nodes.size; result.counts.edges = edges.size;
  for (const node of result.nodes) result.counts.byType[node.type] = (result.counts.byType[node.type] ?? 0) + 1;
  return result;
}

export async function registerGraph(app: FastifyInstance, { db }: { db: Database }): Promise<void> {
  app.get('/api/graph', async request => { permit(request, 'overview.read'); return buildGraph(db, request.actor!.organizationId); });
}
