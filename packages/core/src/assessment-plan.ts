import { EXECUTION_PROFILES } from './authorization.js';
import { isLabIPv4 } from './target-manifest.js';

export interface AssessmentStep {
  id: string;
  name: string;
  assetId: string;
  profile: string;
  address?: string;
  ports?: number[];
}
export const ASSESSMENT_PLAN_LIMITS = Object.freeze({ maxSteps: 25, maxRevisions: 100 });
/** Integration is explicit: an existing executor is not automatically an assessment executor. */
export const ASSESSMENT_EXECUTION_PROFILES: readonly string[] = Object.freeze(['static.scan']);
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function validAssessmentText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length <= max && value.trim().length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}
/** Pure, bounded contract normalization. Array order is the operator's planned order. */
export function normalizeAssessmentSteps(value: unknown): AssessmentStep[] | null {
  if (!Array.isArray(value) || !value.length || value.length > ASSESSMENT_PLAN_LIMITS.maxSteps) return null;
  const ids = new Set<string>(), output: AssessmentStep[] = [];
  for (const step of value) {
    if (!record(step) || Object.keys(step).some(key => !['id', 'name', 'assetId', 'profile', 'address', 'ports'].includes(key))
      || typeof step.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(step.id) || ids.has(step.id)
      || !validAssessmentText(step.name, 160) || typeof step.assetId !== 'string' || !uuid.test(step.assetId)
      || typeof step.profile !== 'string' || !EXECUTION_PROFILES.some(profile => profile.id === step.profile)) return null;
    ids.add(step.id);
    const result: AssessmentStep = { id: step.id, name: step.name.trim(), assetId: step.assetId.toLowerCase(), profile: step.profile };
    if (step.profile === 'lab.inventory') {
      if (typeof step.address !== 'string' || !isLabIPv4(step.address) || !Array.isArray(step.ports)
        || !step.ports.length || step.ports.length > 16 || new Set(step.ports).size !== step.ports.length
        || step.ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) return null;
      result.address = step.address;
      result.ports = [...step.ports].sort((a: number, b: number) => a - b);
    } else if (step.address !== undefined || step.ports !== undefined) return null;
    output.push(result);
  }
  return output;
}
