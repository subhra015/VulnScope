/**
 * VulnScope Frontend – API Client Service
 * Centralizes all communication with the FastAPI backend.
 */

import {
  HealthResponse,
  Scan,
  ScanDetail,
  CreateScanPayload,
  ApiValidationError,
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
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...(options.headers || {}),
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
   * Create a new scan record (status 'created').
   */
  async createScan(payload: CreateScanPayload): Promise<Scan> {
    return request<Scan>('/api/scans', {
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
};

export { ApiError };
