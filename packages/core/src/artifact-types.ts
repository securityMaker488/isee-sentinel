import type { Severity } from './types.js';

export const ANALYSIS_KINDS = ['dependency', 'network', 'malware', 'identity', 'cloud', 'ai', 'forensic', 'api'] as const;
export type AnalysisKind = typeof ANALYSIS_KINDS[number];
export interface ArtifactAnalysisInput { name: string; mediaType: string; content: string; kind: AnalysisKind }
export interface ArtifactFinding {
  id: string;
  ruleId: string;
  severity: Severity;
  title: string;
  location: string;
  recommendation: string;
  evidenceHash: string;
  confidence: 'high' | 'medium';
  provenance: 'local_rule' | 'imported_tool';
}
export interface ArtifactAnalysisReport {
  schemaVersion: '1.0';
  engine: 'Sentinel Artifact Analysis';
  ruleSetVersion: '1.0.0';
  kind: AnalysisKind;
  input: { name: string; mediaType: string; sha256: string; bytes: number };
  format: string;
  summary: string;
  findings: ArtifactFinding[];
  facts: { label: string; value: string | number | boolean }[];
  timeline?: { occurredAt: string; eventType: string; source: string; evidenceHash: string }[];
  limitations: string[];
}
export class ArtifactAnalysisError extends Error {
  readonly code = 'INVALID_ARTIFACT';
  constructor(message: string) { super(message); this.name = 'ArtifactAnalysisError'; }
}
export const ARTIFACT_LIMITS = Object.freeze({ bytes: 1024 * 1024, depth: 48, nodes: 50000, records: 2000, findings: 500, timeline: 2000 });
