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
  risk_score?: number | null;
  priority?: 'critical' | 'high' | 'medium' | 'low' | string | null;
  cvss_score?: number | null;
  lifecycle_status?: 'new' | 'recurring' | 'resolved' | 'changed' | 'unconfirmed' | string | null;
  created_at: string;
}

export interface ScoringFactor {
  name: string;
  weight: number;
  raw_score: number;
  contribution: number;
  description: string;
}

export interface RiskExplanation {
  score: number;
  priority: string;
  priority_label: string;
  factors: ScoringFactor[];
  evidence: Record<string, any>;
  reason: string;
  missing_evidence: string[];
}

export interface RemediationGuidance {
  category: string;
  summary: string;
  steps: string[];
  unsafe_pattern?: string | null;
  safer_alternative?: string | null;
  caveats: string[];
  references: string[];
  fixed_version?: string | null;
  package_ecosystem?: string | null;
}

export type ProposalStatus =
  | 'proposed'
  | 'reviewed'
  | 'rejected'
  | 'downloaded'
  | 'validation_failed'
  | 'verification_pending'
  | 'verified_by_rescan'
  | 'unconfirmed';

export interface RemediationProposal {
  id: string;
  scan_id: string;
  finding_id: string;
  finding_fingerprint?: string | null;
  status: ProposalStatus | string;
  provider: string;
  model_name: string;
  explanation: string;
  likely_root_cause: string;
  potential_impact: string;
  remediation_steps: string[];
  secure_coding_pattern?: string | null;
  testing_recommendations: string[];
  caveats_and_assumptions: string[];
  patch_appropriate: boolean;
  target_file_path?: string | null;
  change_summary?: string | null;
  diff_content?: string | null;
  validation_error?: string | null;
  user_notes?: string | null;
  is_ai_generated: boolean;
  disclaimer: string;
  created_at: string;
  updated_at: string;
}

export interface FindingDetail extends Finding {
  risk_explanation?: RiskExplanation | null;
  remediation?: RemediationGuidance | null;
  ai_proposal?: RemediationProposal | null;
}

export interface FindingChangeDetail {
  field: string;
  old_value: any;
  new_value: any;
}

export interface ComparisonFindingItem {
  finding_id: string;
  scan_id: string;
  scanner_name: string;
  category?: string | null;
  rule_id: string;
  title: string;
  severity: string;
  file_path?: string | null;
  start_line?: number | null;
  package_name?: string | null;
  package_version?: string | null;
  fixed_version?: string | null;
  lifecycle_status: 'new' | 'recurring' | 'resolved' | 'changed' | 'unconfirmed' | string;
  changes: FindingChangeDetail[];
  risk_score?: number | null;
  priority?: string | null;
}

export interface ScanComparisonResponse {
  scan_id: string;
  baseline_scan_id: string;
  repository_id?: string | null;
  summary: {
    new: number;
    recurring: number;
    resolved: number;
    changed: number;
    unconfirmed: number;
    total_target: number;
    total_baseline: number;
  };
  new_findings: ComparisonFindingItem[];
  recurring_findings: ComparisonFindingItem[];
  resolved_findings: ComparisonFindingItem[];
  changed_findings: ComparisonFindingItem[];
  unconfirmed_findings: ComparisonFindingItem[];
  comparability_notes: string[];
}

export interface RiskSummary {
  scan_id: string;
  total_findings: number;
  priority_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  category_distribution: Record<
    string,
    {
      count: number;
      total_score: number;
      avg_risk_score: number;
    }
  >;
  mean_risk_score: number;
  max_risk_score: number;
  scanner_coverage: Record<string, string>;
  coverage_notes: string[];
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
