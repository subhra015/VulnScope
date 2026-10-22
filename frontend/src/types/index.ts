/**
 * VulnScope Frontend – Domain & API Type Definitions
 * Phase 1: Project Foundation
 */

export type SourceType = 'github' | 'zip';

export type ScanStatus = 'created' | 'queued' | 'running' | 'completed' | 'failed';

export type IntakeStatus = 'created' | 'ingesting' | 'ready' | 'failed';

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
  rule_id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence?: string | null;
  file_path?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  redacted_evidence?: string | null;
  remediation_guidance?: string | null;
  advisory_url?: string | null;
  created_at: string;
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
