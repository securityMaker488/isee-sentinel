import type { SecurityEvent } from './types.js';
import { sha256 } from './scanner.js';

export const EVENT_SCHEMA_VERSION = 1 as const;
export const EVENT_TYPES = ['auth.failure', 'auth.success', 'configuration.change', 'scan.completed'] as const;

export function hashEvent(event: SecurityEvent): string {
  return sha256(JSON.stringify({ schemaVersion: event.schemaVersion, id: event.id, organizationId: event.organizationId,
    assetId: event.assetId, type: event.type, occurredAt: event.occurredAt, receivedAt: event.receivedAt,
    source: event.source, data: { subject: event.data.subject ?? null, synthetic: event.data.synthetic ?? false } }));
}

/** Validate the public normalized event shape; upstream ingestion must separately enforce PolicyGate. */
export function isSecurityEvent(value: unknown): value is SecurityEvent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const event = value as Record<string, unknown>;
  const id = (v: unknown) => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v);
  const instant = (v: unknown) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v));
  if (event.schemaVersion !== EVENT_SCHEMA_VERSION || !id(event.id) || !id(event.organizationId) || !id(event.assetId)
    || !(EVENT_TYPES as readonly unknown[]).includes(event.type) || !instant(event.occurredAt) || !instant(event.receivedAt)
    || typeof event.source !== 'string' || event.source.trim().length === 0 || event.source.length > 128
    || !event.data || typeof event.data !== 'object' || Array.isArray(event.data)) return false;
  const data = event.data as Record<string, unknown>;
  return Object.keys(data).every(key => ['subject', 'synthetic'].includes(key))
    && (data.subject === undefined || typeof data.subject === 'string' && data.subject.length > 0 && data.subject.length <= 128)
    && (data.synthetic === undefined || typeof data.synthetic === 'boolean');
}
