import { OPERATIONS, type AuthorizationScope, type Identity, type Operation, type PolicyResource } from './types.js';

export interface PolicyRequest {
  identity: Identity;
  operation: Operation;
  resource: PolicyResource;
  scope?: AuthorizationScope;
  now?: Date;
}

export type PolicyCode = 'ALLOWED' | 'INVALID_REQUEST' | 'UNKNOWN_OPERATION' | 'CROSS_ORGANIZATION'
  | 'ROLE_DENIED' | 'EXECUTOR_UNAVAILABLE' | 'SCOPE_REQUIRED' | 'SCOPE_MISMATCH'
  | 'SCOPE_INVALID' | 'SCOPE_REVOKED' | 'SCOPE_NOT_STARTED' | 'SCOPE_EXPIRED';

export interface PolicyDecision {
  allowed: boolean;
  code: PolicyCode;
  reason: string;
}

const critical = new Set<Operation>(['response.execute', 'remediation.apply', 'recovery.execute']);
const scoped = new Set<Operation>(['scan', 'evidence.import', 'event.ingest']);
const adminOnly = new Set<Operation>(['assets.create', 'scopes.create']);
const environments = new Set(['development', 'lab', 'staging', 'production']);
const roles = new Set(['admin', 'analyst', 'viewer', 'agent']);
const validId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
const deny = (code: PolicyCode, reason: string): PolicyDecision => ({ allowed: false, code, reason });
const validInstant = (value: unknown): value is string => typeof value === 'string'
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  && Number.isFinite(Date.parse(value));

/** Called with server-authenticated identity and server-stored scope, never trusted request-body identity. */
export function evaluatePolicy(request: PolicyRequest): PolicyDecision {
  if (!request || typeof request !== 'object' || !request.identity || !request.resource) {
    return deny('INVALID_REQUEST', 'Identidade e recurso são obrigatórios.');
  }
  const { identity, operation, resource, scope } = request;
  if (!validId(identity.id) || !validId(identity.organizationId) || !roles.has(identity.role)
    || !validId(resource.organizationId)) {
    return deny('INVALID_REQUEST', 'Identidade, organização ou papel inválido.');
  }
  if (!(OPERATIONS as readonly unknown[]).includes(operation)) {
    return deny('UNKNOWN_OPERATION', 'Operação desconhecida; política padrão é negar.');
  }
  if (identity.organizationId !== resource.organizationId) {
    return deny('CROSS_ORGANIZATION', 'Recurso fora da organização autenticada.');
  }
  if (identity.role === 'agent' && operation !== 'event.ingest') {
    return deny('ROLE_DENIED', 'Identidade de agente permite somente ingestão no escopo vinculado.');
  }
  if (critical.has(operation)) {
    return deny('EXECUTOR_UNAVAILABLE', 'Executor de alto impacto não implementado; ação bloqueada para todos os papéis.');
  }
  if ((adminOnly.has(operation) && identity.role !== 'admin')
    || (scoped.has(operation) && identity.role === 'viewer')) {
    return deny('ROLE_DENIED', 'O papel autenticado não permite esta operação.');
  }
  if (!scoped.has(operation)) return { allowed: true, code: 'ALLOWED', reason: 'Organização e papel validados.' };
  if (!validId(resource.assetId) || !environments.has(resource.environment ?? '')) {
    return deny('INVALID_REQUEST', 'Operação exige ativo e ambiente explícitos.');
  }
  if (!scope) return deny('SCOPE_REQUIRED', 'Autorização registrada e vigente é obrigatória.');
  if (!validId(scope.id) || !validId(scope.organizationId) || !validId(scope.assetId)
    || !environments.has(scope.environment) || typeof scope.authorizationRef !== 'string'
    || scope.authorizationRef.trim().length < 3 || scope.authorizationRef.length > 512
    || !Array.isArray(scope.operations) || scope.operations.length === 0
    || scope.operations.some(op => !(OPERATIONS as readonly unknown[]).includes(op))
    || !validInstant(scope.notBefore) || !validInstant(scope.expiresAt)) {
    return deny('SCOPE_INVALID', 'Escopo incompleto ou inválido.');
  }
  if (scope.revokedAt !== undefined) return deny('SCOPE_REVOKED', 'Escopo revogado.');
  if (scope.organizationId !== identity.organizationId || scope.organizationId !== resource.organizationId
    || scope.assetId !== resource.assetId || scope.environment !== resource.environment
    || !scope.operations.includes(operation)) {
    return deny('SCOPE_MISMATCH', 'Escopo não autoriza esta organização, ativo, ambiente ou operação.');
  }
  const now = request.now === undefined ? Date.now() : request.now instanceof Date ? request.now.getTime() : NaN;
  const start = Date.parse(scope.notBefore);
  const end = Date.parse(scope.expiresAt);
  if (!Number.isFinite(now) || end <= start) return deny('SCOPE_INVALID', 'Intervalo de autorização inválido.');
  if (now < start) return deny('SCOPE_NOT_STARTED', 'Autorização ainda não iniciou.');
  if (now >= end) return deny('SCOPE_EXPIRED', 'Autorização expirada.');
  return { allowed: true, code: 'ALLOWED', reason: 'Papel, organização, ativo, ambiente, operação e vigência validados.' };
}
