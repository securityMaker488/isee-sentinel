import type { ControlCheck, ControlStatus, Finding, RiskAssessment, ScanResult } from './types.js';

export interface BarrierDefinition { id: string; number: number; name: string; objective: string; controls: readonly string[] }
export interface BarrierEvaluation extends BarrierDefinition {
  status: ControlStatus;
  runtimeVerified: false;
  assurance: 'static_configuration_only' | 'not_evaluated';
  evaluatedControls: { controlId: string; status: ControlStatus; evidence: ControlCheck[] }[];
  explanation: string;
}

export const BARRIER_CATALOG: readonly BarrierDefinition[] = [
  { id: 'edge', number: 1, name: 'Edge Security', objective: 'Filtragem e controle de abuso no perímetro.', controls: ['edge.waf', 'edge.rate_limit'] },
  { id: 'network', number: 2, name: 'Network Segmentation', objective: 'Restringir comunicação e movimentação lateral.', controls: ['network.segmentation', 'network.egress'] },
  { id: 'identity', number: 3, name: 'Zero Trust Identity', objective: 'Identidade forte e menor privilégio.', controls: ['identity.mfa', 'identity.authorization'] },
  { id: 'application', number: 4, name: 'Application & API Security', objective: 'Verificar controles de aplicações e APIs.', controls: ['cors.origin_credentials', 'application.authorization'] },
  { id: 'database', number: 5, name: 'Database Security', objective: 'Proteger acesso e integridade dos dados.', controls: ['database.access', 'database.encryption'] },
  { id: 'cryptography', number: 6, name: 'Cryptography & Secret Protection', objective: 'Validar transporte e identificar exposição de segredos.', controls: ['tls.verification', 'secrets.private_key', 'secrets.cloud_key'] },
  { id: 'endpoint', number: 7, name: 'Endpoint & Server Hardening', objective: 'Avaliar configurações e proteção de hosts.', controls: ['ssh.root_login', 'ssh.password_authentication', 'endpoint.runtime'] },
  { id: 'supply_chain', number: 8, name: 'Software Supply Chain', objective: 'Verificar proveniência e dependências.', controls: ['supply_chain.dependencies', 'supply_chain.signatures'] },
  { id: 'ai', number: 9, name: 'AI & Agent Security', objective: 'Limitar ferramentas e dados acessíveis por agentes.', controls: ['ai.tool_policy', 'ai.prompt_injection'] },
  { id: 'intrusion', number: 10, name: 'Intrusion Detection', objective: 'Detectar padrões com fonte e evidência.', controls: ['intrusion.telemetry', 'intrusion.detection_validation'] },
  { id: 'containment', number: 11, name: 'Threat Containment', objective: 'Executar contenção autorizada e reversível.', controls: ['containment.authorization', 'containment.validation'] },
  { id: 'remediation', number: 12, name: 'Autonomous Remediation', objective: 'Validar correções e rollback controlado.', controls: ['remediation.tests', 'remediation.rollback'] },
  { id: 'recovery', number: 13, name: 'Recovery & Resilience', objective: 'Demonstrar restauração e continuidade.', controls: ['recovery.restore_test', 'recovery.rpo_rto'] },
  { id: 'evidence', number: 14, name: 'Audit, Forensics & Evidence', objective: 'Preservar rastreabilidade e cadeia de custódia.', controls: ['evidence.integrity', 'evidence.external_anchor'] },
];

/** Registration alone never enables a barrier. Pass is restricted to individual observed static controls. */
export function evaluateBarrierMatrix(scan?: ScanResult | null): BarrierEvaluation[] {
  return BARRIER_CATALOG.map(layer => {
    const evaluatedControls = layer.controls.map(controlId => {
      const evidence = (scan?.checks ?? []).filter(check => check.layerId === layer.id && check.controlId === controlId);
      const status: ControlStatus = evidence.some(check => check.status === 'fail') ? 'fail' : evidence.length ? 'pass' : 'not_evaluated';
      return { controlId, status, evidence };
    });
    const observed = evaluatedControls.some(control => control.status !== 'not_evaluated');
    // The baseline cannot attest runtime effectiveness of an entire defense layer.
    const status: ControlStatus = evaluatedControls.some(control => control.status === 'fail') ? 'fail' : 'not_evaluated';
    return { ...layer, status, runtimeVerified: false, assurance: observed ? 'static_configuration_only' : 'not_evaluated', evaluatedControls,
      explanation: observed ? 'Somente controles presentes nos arquivos enviados foram avaliados. A camada não foi validada em execução.' : 'Nenhuma evidência avaliável desta camada. Cadastro não comprova proteção.' };
  });
}

/** A triage index of observed findings, not a probability, CVSS score, or protection percentage. */
export function assessRisk(findings: readonly Finding[]): RiskAssessment {
  const weights = { critical: 40, high: 25, medium: 10, low: 3, info: 0 } as const;
  const unique = [...new Map(findings.map(finding => [finding.id, finding])).values()];
  const factors = unique.map(finding => ({ findingId: finding.id, severity: finding.severity, weight: weights[finding.severity], reason: `${finding.ruleId}: ${finding.title}` }));
  const score = Math.min(100, factors.reduce((total, factor) => total + factor.weight, 0));
  const level = !unique.length ? 'unknown' : unique.some(f => f.severity === 'critical') ? 'critical' : unique.some(f => f.severity === 'high') ? 'high' : unique.some(f => f.severity === 'medium') ? 'medium' : 'low';
  return { schemaVersion: '1.0', score, level, factors, explanation: 'Índice de triagem: soma dos pesos critical=40, high=25, medium=10, low=3, info=0, limitada a 100. Não mede probabilidade ou proteção; zero achados significa risco desconhecido.' };
}
