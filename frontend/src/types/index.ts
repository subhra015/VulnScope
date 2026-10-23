/**
 * VulnScope Frontend – Domain & API Type Definitions
 * Phase 3: Real Security Scanner Engine
 */

export type SourceType = 'github' | 'zip';

export type ScanStatus = 'created' | 'queued' | 'running' | 'completed' | 'partial' | 'failed';

export type IntakeStatus = 'created' | 'ingesting' | 'ready' | 'failed';

export type ScannerStatus = 'pending' | 'running' | 'completed' | 'failed' | 'unavailable' | 'timed_out';

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  database: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  finding_fingerprint?: string | null;
  scanner_name: string;
  category?: 'code' | 'secret' | 'dependency' | string | null;
  rule_id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  confidence?: string | null;
  file_path?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  package_name?: string | null;
  package_version?: string | null;
  ecosystem?: string | null;
  fixed_version?: string | null;
  redacted_evidence?: string | null;
  remediation_guidance?: string | null;
  advisory_url?: string | null;
  created_at: string;
}

export interface ScannerRun {
  id: string;
  scan_id: string;
  scanner_name: string;
  status: ScannerStatus | string;
  scanner_version?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  findings_count: number;
  error_message?: string | null;
}

export interface FindingsSummary {
  total: number;
  code: number;
  secret: number;
  dependency: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
}

export interface Scan {
  id: string;
  project_name: string;
  source_type: SourceType;
  source_reference?: string | null;
  status: ScanStatus | string;
  intake_status?: IntakeStatus | string | null;
  workspace_id?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  error_summary?: string | null;
}

export interface ScanDetail extends Scan {
  repository_id?: string | null;
  findings: Finding[];
  scanner_runs?: ScannerRun[];
  findings_summary?: FindingsSummary | null;
}

export interface ScanRunResponse {
  scan_id: string;
  status: string;
  message: string;
}

export interface FindingsListResponse {
  total: number;
  items: Finding[];
  limit: number;
  offset: number;
}

export interface CreateScanPayload {
  project_name: string;
  source_type: SourceType;
  source_reference?: string;
}

export interface GithubIntakePayload {
  repo_url: string;
  project_name?: string;
  ref?: string;
}

export interface ApiValidationError {
  detail: string;
  errors?: Array<{
    field: string;
    message: string;
    type: string;
  }>;
}
