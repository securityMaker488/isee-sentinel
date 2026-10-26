import { sha256 } from './scanner.js';
import { ARTIFACT_LIMITS, ArtifactAnalysisError, type ArtifactAnalysisReport, type ArtifactFinding } from './artifact-types.js';

export type JsonObject = Record<string, unknown>;
export function record(value: unknown, context = 'objeto'): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ArtifactAnalysisError(`Esperado ${context} JSON.`);
  return value as JsonObject;
}
export function list(value: unknown, context = 'lista', max: number = ARTIFACT_LIMITS.records): unknown[] {
  if (!Array.isArray(value) || value.length > max) throw new ArtifactAnalysisError(`${context} inválida ou acima do limite de ${max} registros.`);
  return value;
}
export function text(value: unknown, context = 'texto', max = 4096): string {
  if (typeof value !== 'string' || value.length > max || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) throw new ArtifactAnalysisError(`${context} inválido.`);
  return value;
}
export function boolean(value: unknown, context: string): boolean {
  if (typeof value !== 'boolean') throw new ArtifactAnalysisError(`${context} deve ser booleano explícito.`);
  return value;
}
export function strings(value: unknown, context: string): string[] {
  return (Array.isArray(value) ? list(value, context) : [value]).map(item => text(item, context));
}
export function isoDate(value: unknown): string {
  const raw = text(value, 'Data', 40);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(raw)) throw new ArtifactAnalysisError('Use uma data ISO 8601 UTC explícita.');
  const parsed = new Date(raw);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 19) !== raw.slice(0, 19)) throw new ArtifactAnalysisError('Data impossível.');
  return parsed.toISOString();
}

/** Bound the full tree, reject ambiguous duplicate decoded keys, never resolve references. */
export function parseJson(content: string): unknown {
  let result: unknown;
  try { result = JSON.parse(content); } catch { throw new ArtifactAnalysisError('JSON inválido.'); }
  const tokens = /"(?:\\[\s\S]|[^"\\])*"|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\]:,]/g;
  const stack: { object: boolean; key: boolean; keys: Set<string> }[] = [];
  let nodes = 0;
  for (const match of content.matchAll(tokens)) {
    if (++nodes > ARTIFACT_LIMITS.nodes) throw new ArtifactAnalysisError('Limite estrutural JSON excedido.');
    const token = match[0];
    const top = stack.at(-1);
    if (token === '{' || token === '[') {
      if (stack.length >= ARTIFACT_LIMITS.depth) throw new ArtifactAnalysisError('JSON profundo demais.');
      stack.push({ object: token === '{', key: true, keys: new Set() });
    } else if (token === '}' || token === ']') stack.pop();
    else if (top?.object) {
      if (token === ',') top.key = true;
      else if (token === ':') top.key = false;
      else if (top.key && token.startsWith('"')) {
        const key = JSON.parse(token) as string;
        if (top.keys.has(key)) throw new ArtifactAnalysisError('Chaves JSON duplicadas não são aceitas.');
        top.keys.add(key);
      }
    }
  }
  return result;
}

export function addFinding(report: ArtifactAnalysisReport, item: Omit<ArtifactFinding, 'id' | 'evidenceHash' | 'confidence' | 'provenance'> & Partial<Pick<ArtifactFinding, 'confidence' | 'provenance'>>, evidence: unknown): void {
  if (report.findings.length >= ARTIFACT_LIMITS.findings) throw new ArtifactAnalysisError(`Mais de ${ARTIFACT_LIMITS.findings} achados; divida o artefato para evitar perda de resultados.`);
  const evidenceHash = sha256(JSON.stringify(evidence));
  report.findings.push({ ...item, confidence: item.confidence ?? 'high', provenance: item.provenance ?? 'local_rule', evidenceHash,
    id: sha256(JSON.stringify([report.input.sha256, item.ruleId, item.location, evidenceHash])).slice(0, 32) });
}
export function fact(report: ArtifactAnalysisReport, label: string, value: string | number | boolean): void { report.facts.push({ label, value }); }
export function objectEntries(value: unknown, context: string): [string, unknown][] {
  const entries = Object.entries(record(value, context));
  if (entries.length > ARTIFACT_LIMITS.records) throw new ArtifactAnalysisError(`${context} excede ${ARTIFACT_LIMITS.records} registros.`);
  return entries;
}
