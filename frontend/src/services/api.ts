/**
 * VulnScope Frontend – API Client Service
 * Centralizes all communication with the FastAPI backend.
 */

import {
  HealthResponse,
  Scan,
  ScanDetail,
  CreateScanPayload,
  GithubIntakePayload,
  ApiValidationError,
  FindingDetail,
  RiskSummary,
  ScanComparisonResponse,
  FindingsListResponse,
} from '../types';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/+$/, '');

class ApiError extends Error {
  statusCode?: number;
  validationErrors?: Array<{ field: string; message: string }>;

  constructor(message: string, statusCode?: number, validationErrors?: Array<{ field: string; message: string }>) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.validationErrors = validationErrors;
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;

  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...((options.headers as Record<string, string>) || {}),
  };

  let response: Response;
  try {
    response = await fetch(url, { ...options, headers });
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Network error';
    throw new ApiError(
      `Cannot connect to VulnScope backend at ${API_BASE_URL}. Ensure the FastAPI server is running. (${errorMsg})`
    );
  }

  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    let validationErrors: Array<{ field: string; message: string }> | undefined;

    try {
      const errorJson: ApiValidationError = await response.json();
      if (errorJson.errors && Array.isArray(errorJson.errors)) {
        validationErrors = errorJson.errors;
        errorDetail = errorJson.errors.map((e) => `${e.field}: ${e.message}`).join(', ');
      } else if (typeof errorJson.detail === 'string') {
        errorDetail = errorJson.detail;
      }
    } catch {
      // If error response is not JSON, retain fallback status text
      errorDetail = response.statusText || errorDetail;
    }

    throw new ApiError(errorDetail, response.status, validationErrors);
  }

  return response.json() as Promise<T>;
}

export const api = {
  /**
   * Health check to verify backend operational state and database connectivity.
   */
  async getHealth(): Promise<HealthResponse> {
    return request<HealthResponse>('/api/health');
  },

  /**
   * Retrieve list of scans ordered by creation time descending.
   */
  async getScans(): Promise<Scan[]> {
    return request<Scan[]>('/api/scans');
  },

  /**
   * Create a new scan record without source files (Phase 1 legacy compatibility).
   */
  async createScan(payload: CreateScanPayload): Promise<Scan> {
    return request<Scan>('/api/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /**
   * Phase 2: Upload and validate a ZIP archive.
   */
  async intakeZip(file: File, projectName?: string): Promise<Scan> {
    const formData = new FormData();
    formData.append('file', file);
    if (projectName && projectName.trim()) {
      formData.append('project_name', projectName.trim());
    }

    return request<Scan>('/api/intake/zip', {
      method: 'POST',
      body: formData,
    });
  },

  /**
   * Phase 2: Acquire and validate a public GitHub repository snapshot.
   */
  async intakeGithub(payload: GithubIntakePayload): Promise<Scan> {
    return request<Scan>('/api/intake/github', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /**
   * Retrieve single scan details including associated findings.
   */
  async getScan(scanId: string): Promise<ScanDetail> {
    return request<ScanDetail>(`/api/scans/${encodeURIComponent(scanId)}`);
  },

  /**
   * Phase 3: Trigger multi-engine security scanning (Semgrep, Gitleaks, OSV-Scanner).
   */
  async runScan(scanId: string): Promise<{ scan_id: string; status: string; message: string }> {
    return request<{ scan_id: string; status: string; message: string }>(
      `/api/scans/${encodeURIComponent(scanId)}/run`,
      { method: 'POST' }
    );
  },

  /**
   * Phase 3 & 4: Retrieve normalized findings with risk prioritization, filtering, and pagination.
   */
  async getScanFindings(
    scanId: string,
    params: {
      scanner?: string;
      category?: string;
      severity?: string;
      priority?: string;
      sortBy?: string;
      sortOrder?: string;
      baselineScanId?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<FindingsListResponse> {
    const q = new URLSearchParams();
    if (params.scanner) q.set('scanner', params.scanner);
    if (params.category) q.set('category', params.category);
    if (params.severity) q.set('severity', params.severity);
    if (params.priority) q.set('priority', params.priority);
    if (params.sortBy) q.set('sort_by', params.sortBy);
    if (params.sortOrder) q.set('sort_order', params.sortOrder);
    if (params.baselineScanId) q.set('baseline_scan_id', params.baselineScanId);
    if (params.limit !== undefined) q.set('limit', String(params.limit));
    if (params.offset !== undefined) q.set('offset', String(params.offset));
    const qs = q.toString();
    return request<FindingsListResponse>(
      `/api/scans/${encodeURIComponent(scanId)}/findings${qs ? `?${qs}` : ''}`
    );
  },

  /**
   * Phase 4: Retrieve single finding detail with score explanation and remediation guidance.
   */
  async getFindingDetail(scanId: string, findingId: string): Promise<FindingDetail> {
    return request<FindingDetail>(
      `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`
    );
  },

  /**
   * Phase 4: Retrieve risk summary metrics and priority distribution for a scan.
   */
  async getScanRiskSummary(scanId: string): Promise<RiskSummary> {
    return request<RiskSummary>(
      `/api/scans/${encodeURIComponent(scanId)}/risk-summary`
    );
  },

  /**
   * Phase 4: Compare findings between two scans of the same repository lineage.
   */
  async compareScans(scanId: string, baselineScanId: string): Promise<ScanComparisonResponse> {
    return request<ScanComparisonResponse>(
      `/api/scans/${encodeURIComponent(scanId)}/comparison/${encodeURIComponent(baselineScanId)}`
    );
  },
};

export { ApiError };
