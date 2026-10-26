import { sha256 } from './scanner.js';
import { ANALYSIS_KINDS, ARTIFACT_LIMITS, ArtifactAnalysisError, type ArtifactAnalysisInput, type ArtifactAnalysisReport } from './artifact-types.js';
import { parseJson, record, text } from './artifact-support.js';
import { analyzeAi, analyzeCloud, analyzeDependencies, analyzeIdentities } from './artifact-config.js';
import { analyzeHar, analyzeNmap, importSarif } from './artifact-network.js';
import { analyzeBinary, analyzeScript, analyzeTimeline } from './artifact-forensics.js';
import {analyzeOpenApi} from './api-audit.js';

/** Offline: operates only on the explicitly supplied bytes. No filesystem, network or process APIs. */
export function analyzeArtifact(input: ArtifactAnalysisInput): ArtifactAnalysisReport {
  const value = record(input, 'entrada');
  if (Object.keys(value).some(key => !['kind', 'name', 'mediaType', 'content'].includes(key))) throw new ArtifactAnalysisError('Campos extras de entrada não são aceitos.');
  if (!ANALYSIS_KINDS.includes(value.kind as ArtifactAnalysisInput['kind'])) throw new ArtifactAnalysisError('Tipo de análise desconhecido.');
  const kind = value.kind as ArtifactAnalysisInput['kind'];
  const name = text(value.name, 'Nome', 240);
  if (!name.trim() || /[\r\n]/.test(name)) throw new ArtifactAnalysisError('Nome de artefato inválido.');
  const mediaType = text(value.mediaType, 'MIME', 120);
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(mediaType)) throw new ArtifactAnalysisError('MIME deve ser um tipo/subtipo sem parâmetros.');
  if (typeof value.content !== 'string') throw new ArtifactAnalysisError('content deve ser texto UTF-8 ou envelope JSON de binário.');
  const content = value.content;
  const bytes = Buffer.byteLength(content, 'utf8');
  if (bytes === 0 || bytes > ARTIFACT_LIMITS.bytes || content.includes('\0')) throw new ArtifactAnalysisError('Artefato vazio, com NUL ou acima de 1 MiB.');
  const report: ArtifactAnalysisReport = {
    schemaVersion: '1.0', engine: 'Sentinel Artifact Analysis', ruleSetVersion: '1.0.0', kind,
    input: { name, mediaType, bytes, sha256: sha256(content) }, format: '', summary: '', findings: [], facts: [],
    limitations: ['Resultado limitado ao artefato recebido; ausência de achados não comprova segurança. A análise não executa conteúdo nem altera o ativo.'],
  };
  if (kind === 'api') analyzeOpenApi(content,report);
  else if (kind === 'network' && content.trimStart().startsWith('<')) analyzeNmap(content, report);
  else if (kind === 'malware' && (mediaType.startsWith('text/') || !content.trimStart().startsWith('{'))) analyzeScript(content, report);
  else {
    const root = record(parseJson(content), 'raiz');
    if (root.version === '2.1.0' && root.runs !== undefined) importSarif(root, report);
    else switch (kind) {
      case 'dependency': analyzeDependencies(root, report); break;
      case 'network': analyzeHar(root, report); break;
      case 'identity': analyzeIdentities(root, report); break;
      case 'cloud': analyzeCloud(root, report); break;
      case 'ai': analyzeAi(root, report); break;
      case 'forensic': analyzeTimeline(root, report); break;
      case 'malware': analyzeBinary(root, report); break;
    }
  }
  report.summary = `${report.facts.length} métricas e ${report.findings.length} achados no artefato ${report.format}; ${report.findings.filter(item => item.provenance === 'imported_tool').length} achados vieram de ferramenta externa.`;
  return report;
}
