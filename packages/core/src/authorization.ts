import { OPERATIONS, type Operation } from './types.js';

export interface ExecutionProfile {
  id: string;
  label: string;
  operations: readonly Operation[];
  minimumRisk: 'low' | 'moderate';
  labOnly: boolean;
  inputKind: 'bytes' | 'ports';
  maxInputBytes: number | null;
  timeoutSeconds: number | null;
}

const MiB = 1024 * 1024;
/** Only implemented executors. These ceilings never expand the executor's own limits. */
export const EXECUTION_PROFILES: readonly ExecutionProfile[] = Object.freeze([
  { id: 'static.scan', label: 'SecureBuild estático', operations: ['scan'], minimumRisk: 'low', labOnly: false, inputKind: 'bytes', maxInputBytes: MiB, timeoutSeconds: null },
  { id: 'artifact.analyze', label: 'Análise offline de artefato', operations: ['scan', 'evidence.import'], minimumRisk: 'low', labOnly: false, inputKind: 'bytes', maxInputBytes: MiB, timeoutSeconds: null },
  { id: 'archive.inspect', label: 'Inspeção ZIP em quarentena', operations: ['scan', 'evidence.import'], minimumRisk: 'low', labOnly: false, inputKind: 'bytes', maxInputBytes: 16 * MiB, timeoutSeconds: 45 },
  { id: 'forensic.analyze', label: 'Perícia offline de arquivo', operations: ['scan', 'evidence.import'], minimumRisk: 'low', labOnly: false, inputKind: 'bytes', maxInputBytes: 16 * MiB, timeoutSeconds: 60 },
  { id: 'evidence.import', label: 'Importação de evidência', operations: ['evidence.import'], minimumRisk: 'low', labOnly: false, inputKind: 'bytes', maxInputBytes: MiB, timeoutSeconds: null },
  { id: 'events.ingest', label: 'Ingestão de eventos', operations: ['event.ingest'], minimumRisk: 'low', labOnly: false, inputKind: 'bytes', maxInputBytes: MiB, timeoutSeconds: null },
  { id: 'agent.observe', label: 'Recebimento de observação do agente', operations: ['event.ingest'], minimumRisk: 'low', labOnly: false, inputKind: 'bytes', maxInputBytes: 16384, timeoutSeconds: null },
  { id: 'lab.inventory', label: 'Inventário TCP de laboratório', operations: ['scan'], minimumRisk: 'moderate', labOnly: true, inputKind: 'ports', maxInputBytes: null, timeoutSeconds: 40 },
  { id: 'lab.remediate', label: 'Correção de cópia SSH no laboratório', operations: ['scan', 'evidence.import'], minimumRisk: 'low', labOnly: true, inputKind: 'bytes', maxInputBytes: 256 * 1024, timeoutSeconds: null },
].map(value => Object.freeze({ ...value, operations: Object.freeze([...value.operations]) })) as ExecutionProfile[]);

export interface ManagedGrant {
  status: string;
  projectId: string;
  mode: 'lab' | 'assessment';
  risk: 'low' | 'moderate';
  profiles: string[];
  limits: { maxInputBytes: number; allowedPorts?: number[] };
}

/** This context must be built by the trusted executor, never copied from user input. */
export interface ManagedExecution {
  profile: string;
  phase?: 'prepare' | 'execute';
  inputBytes?: number;
  ports?: number[];
}

export type ManagedDecisionCode = 'ALLOWED' | 'GRANT_INVALID' | 'GRANT_INACTIVE' | 'PROJECT_MISMATCH'
  | 'MODE_MISMATCH' | 'RISK_INSUFFICIENT' | 'EXECUTION_REQUIRED' | 'PROFILE_DENIED' | 'OPERATION_DENIED'
  | 'INPUT_LIMIT' | 'PORT_LIMIT';
export interface ManagedDecision { allowed: boolean; code: ManagedDecisionCode; reason: string }
const profiles = new Map(EXECUTION_PROFILES.map(profile => [profile.id, profile]));
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const projectId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
const portsValid = (value: unknown): value is number[] => Array.isArray(value) && value.length > 0 && value.length <= 16
  && new Set(value).size === value.length && value.every(port => Number.isInteger(port) && port >= 1 && port <= 65535);
const deny = (code: ManagedDecisionCode, reason: string): ManagedDecision => ({ allowed: false, code, reason });

/** Additional constraint only: base PolicyGate must still verify identity, organization, asset, operation and time. */
export function evaluateManagedGrant(
  grant: ManagedGrant,
  asset: { projectId?: string | null; environment: string },
  operation: Operation,
  execution?: ManagedExecution,
): ManagedDecision {
  if (!record(grant) || !record(asset) || !projectId(grant.projectId)
    || !['lab', 'assessment'].includes(grant.mode) || !['low', 'moderate'].includes(grant.risk)
    || !['development', 'lab', 'staging', 'production'].includes(asset.environment)
    || !Array.isArray(grant.profiles) || !grant.profiles.length || grant.profiles.length > EXECUTION_PROFILES.length
    || new Set(grant.profiles).size !== grant.profiles.length
    || grant.profiles.some(id => typeof id !== 'string' || !profiles.has(id))
    || !record(grant.limits) || Object.keys(grant.limits).some(key => !['maxInputBytes', 'allowedPorts'].includes(key))
    || !Number.isInteger(grant.limits.maxInputBytes) || grant.limits.maxInputBytes < 1 || grant.limits.maxInputBytes > 16 * MiB
    || (grant.limits.allowedPorts !== undefined && !portsValid(grant.limits.allowedPorts))) {
    return deny('GRANT_INVALID', 'Autorização estruturada ou limites inválidos; operação negada.');
  }
  if (grant.status !== 'approved') return deny('GRANT_INACTIVE', 'A autorização precisa estar aprovada.');
  if (!projectId(asset.projectId) || grant.projectId !== asset.projectId) {
    return deny('PROJECT_MISMATCH', 'O ativo não pertence ao projeto autorizado.');
  }
  const selectedProfiles = grant.profiles.map(id => profiles.get(id)!);
  if ((grant.mode === 'lab' && asset.environment !== 'lab')
    || selectedProfiles.some(profile => profile.labOnly && (grant.mode !== 'lab' || asset.environment !== 'lab'))) {
    return deny('MODE_MISMATCH', 'O modo ou ambiente não permite os perfis selecionados.');
  }
  if (grant.risk === 'low' && selectedProfiles.some(profile => profile.minimumRisk === 'moderate')) {
    return deny('RISK_INSUFFICIENT', 'O nível de risco aprovado não cobre os perfis selecionados.');
  }
  if (selectedProfiles.some(profile => profile.inputKind === 'ports') && !portsValid(grant.limits.allowedPorts)) {
    return deny('GRANT_INVALID', 'Inventário de laboratório exige portas explicitamente autorizadas.');
  }
  if (!record(execution) || typeof execution.profile !== 'string'
    || Object.keys(execution).some(key => !['profile', 'phase', 'inputBytes', 'ports'].includes(key))
    || (execution.phase !== undefined && execution.phase !== 'prepare' && execution.phase !== 'execute')) {
    return deny('EXECUTION_REQUIRED', 'Executor deve informar um contexto de operação válido.');
  }
  const profile = profiles.get(execution.profile);
  if (!profile || !grant.profiles.includes(profile.id)) return deny('PROFILE_DENIED', 'Este perfil não consta da autorização aprovada.');
  if (!(OPERATIONS as readonly unknown[]).includes(operation) || !profile.operations.includes(operation)) {
    return deny('OPERATION_DENIED', 'Operação não implementada ou incompatível com o perfil.');
  }
  if (execution.phase === 'prepare') {
    return { allowed: true, code: 'ALLOWED', reason: 'Preparação autorizada; a execução deve revalidar escopo e entrada.' };
  }
  if (profile.inputKind === 'bytes') {
    const size = execution.inputBytes;
    if (execution.ports !== undefined || typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0
      || size > Math.min(grant.limits.maxInputBytes, profile.maxInputBytes!)) {
      return deny('INPUT_LIMIT', 'Tamanho de entrada ausente, inválido ou superior ao limite autorizado.');
    }
  } else if (execution.inputBytes !== undefined || !portsValid(execution.ports)
    || execution.ports.some(port => !grant.limits.allowedPorts!.includes(port))) {
    return deny('PORT_LIMIT', 'Portas ausentes, inválidas ou fora do conjunto autorizado.');
  }
  return { allowed: true, code: 'ALLOWED', reason: 'Perfil, projeto, modo, risco e limites da entrada validados.' };
}
