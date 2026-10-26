export const OPERATIONS = [
  'overview.read', 'assets.read', 'assets.create', 'findings.read',
  'evidence.read', 'evidence.import', 'scopes.read', 'scopes.create',
  'scan', 'events.read', 'event.ingest', 'barriers.read', 'reports.read',
  'audit.read', 'response.execute', 'remediation.apply', 'recovery.execute',
] as const;

export type Operation = typeof OPERATIONS[number];
export type Role = 'admin' | 'analyst' | 'viewer' | 'agent';
export type Environment = 'development' | 'lab' | 'staging' | 'production';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ControlStatus = 'not_evaluated' | 'pass' | 'fail';

export interface Identity {
  id: string;
  organizationId: string;
  role: Role;
}

export interface PolicyResource {
  organizationId: string;
  assetId?: string;
  environment?: Environment;
}

export interface AuthorizationScope {
  id: string;
  organizationId: string;
  assetId: string;
  environment: Environment;
  operations: Operation[];
  notBefore: string;
  expiresAt: string;
  authorizationRef: string;
  revokedAt?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  ruleVersion: string;
  severity: Severity;
  path: string;
  line: number;
  title: string;
  recommendation: string;
  confidence: 'high' | 'medium';
  evidenceHash: string;
  layerId: string;
}

export interface UploadedFile {
  path: string;
  content: string;
}

export interface FileEvidence {
  path: string;
  sha256: string;
  bytes: number;
}

export interface ControlCheck {
  controlId: string;
  layerId: string;
  status: Exclude<ControlStatus, 'not_evaluated'>;
  path: string;
  line: number;
  evidenceHash: string;
  explanation: string;
  assurance: 'static_configuration';
}

export interface ScanResult {
  schemaVersion: '1.0';
  engine: 'SecureBuild Static Baseline';
  ruleSetVersion: string;
  inputHash: string;
  files: FileEvidence[];
  findings: Finding[];
  checks: ControlCheck[];
  limitations: string[];
}

export interface SecurityEvent {
  schemaVersion: 1;
  id: string;
  organizationId: string;
  assetId: string;
  occurredAt: string;
  receivedAt: string;
  source: string;
  type: 'auth.failure' | 'auth.success' | 'configuration.change' | 'scan.completed';
  data: { subject?: string; synthetic?: boolean };
}

export interface RiskAssessment {
  schemaVersion: '1.0';
  score: number;
  level: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  factors: { findingId: string; severity: Severity; weight: number; reason: string }[];
  explanation: string;
}
