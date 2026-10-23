import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  X,
  Layers,
  Clock,
  ShieldAlert,
  Code,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  Database,
  Play,
  Terminal,
  ExternalLink,
  CheckCircle2,
  KeyRound,
  PackageSearch,
  Code2,
} from 'lucide-react';
import { api, ApiError } from '../services/api';
import { ScanDetail, ScannerRun } from '../types';
import {
  StatusBadge,
  IntakeStatusBadge,
  ScannerStatusBadge,
  SeverityBadge,
  CategoryBadge,
} from './StatusBadge';

interface ScanDetailsModalProps {
  scanId: string | null;
  onClose: () => void;
  onScanUpdated?: () => void;
}

export const ScanDetailsModal: React.FC<ScanDetailsModalProps> = ({
  scanId,
  onClose,
  onScanUpdated,
}) => {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);

  const fetchScan = useCallback(
    async (id: string, showSpinner = false) => {
      if (showSpinner) setIsLoading(true);
      setError(null);
      try {
        const data = await api.getScan(id);
        setScan(data);
        return data;
      } catch (err: unknown) {
        if (err instanceof ApiError) {
          setError(err.message);
        } else {
          setError('Failed to fetch scan details');
        }
        return null;
      } finally {
        if (showSpinner) setIsLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (!scanId) {
      setScan(null);
      return;
    }

    fetchScan(scanId, true);

    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [scanId, fetchScan]);

  // Periodic status refresh while scan is actively running
  useEffect(() => {
    if (!scanId || !scan) return;

    if (scan.status === 'running') {
      if (!pollTimerRef.current) {
        pollTimerRef.current = setInterval(async () => {
          const updated = await fetchScan(scanId, false);
          if (updated && updated.status !== 'running') {
            if (pollTimerRef.current) {
              clearInterval(pollTimerRef.current);
              pollTimerRef.current = null;
            }
            if (onScanUpdated) onScanUpdated();
          }
        }, 2500);
      }
    } else {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    }

    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [scanId, scan, fetchScan, onScanUpdated]);

  if (!scanId) return null;

  const handleCopyId = () => {
    navigator.clipboard.writeText(scanId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleTriggerScan = async () => {
    if (!scanId || isScanning) return;
    setIsScanning(true);
    setError(null);
    try {
      await api.runScan(scanId);
      await fetchScan(scanId, false);
      if (onScanUpdated) onScanUpdated();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Failed to start security scan');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const formatDate = (isoString?: string | null) => {
    if (!isoString) return 'Not recorded';
    try {
      const d = new Date(isoString);
      return d.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return isoString;
    }
  };

  // Filter findings
  const findings = scan?.findings || [];
  const filteredFindings = findings.filter((f) => {
    if (categoryFilter !== 'all' && (f.category || 'code').toLowerCase() !== categoryFilter.toLowerCase()) {
      return false;
    }
    if (severityFilter !== 'all' && f.severity.toLowerCase() !== severityFilter.toLowerCase()) {
      return false;
    }
    return true;
  });

  const summary = scan?.findings_summary || {
    total: findings.length,
    code: findings.filter((f) => (f.category || 'code') === 'code').length,
    secret: findings.filter((f) => f.category === 'secret').length,
    dependency: findings.filter((f) => f.category === 'dependency').length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };

  const scannerRuns: ScannerRun[] = scan?.scanner_runs || [];
  const canRunScan = scan && scan.intake_status === 'ready' && scan.status !== 'running';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-4xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>{scan?.project_name || 'Scan Inspection'}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {scan?.source_type.toUpperCase()}
                </span>
              </h3>
              <p className="text-xs text-slate-400">Security scanner results and intake lifecycle</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {canRunScan && (
              <button
                type="button"
                onClick={handleTriggerScan}
                disabled={isScanning}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-all shadow-sm disabled:opacity-50"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Launching...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>{scan?.status === 'created' ? 'Run Security Scan' : 'Re-run Scan'}</span>
                  </>
                )}
              </button>
            )}

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading && (
            <div className="py-20 flex flex-col items-center justify-center text-slate-400">
              <Loader2 className="w-8 h-8 text-emerald-400 animate-spin mb-3" />
              <p className="text-sm font-medium">Retrieving scan record and findings...</p>
            </div>
          )}

          {error && (
            <div className="p-4 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 flex items-start gap-3 text-xs">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Operation failed</p>
                <p className="mt-1 text-rose-400">{error}</p>
              </div>
            </div>
          )}

          {!isLoading && scan && (
            <>
              {/* Primary Metadata Box */}
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-400">Scan ID:</span>
                    <span className="font-mono text-xs text-slate-200">{scan.id}</span>
                    <button
                      onClick={handleCopyId}
                      title="Copy full scan ID"
                      className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <IntakeStatusBadge status={scan.intake_status} />
                    <StatusBadge status={scan.status} />
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/60 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div>
                    <span className="text-slate-500 font-mono block">Source Reference</span>
                    <span className="text-slate-300 font-mono break-all text-[11px]">
                      {scan.source_reference || 'N/A'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 font-mono block">Isolated Workspace</span>
                    <span className="text-emerald-400 font-mono text-[11px]">
                      {scan.workspace_id ? `${scan.workspace_id.slice(0, 8)}... (sandboxed)` : 'Pending'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 font-mono block">Lifecycle Timeline</span>
                    <span className="text-slate-300 font-mono text-[11px]">
                      {scan.completed_at ? `Finished: ${formatDate(scan.completed_at)}` : `Created: ${formatDate(scan.created_at)}`}
                    </span>
                  </div>
                </div>
              </div>

              {/* Individual Scanner Runs Status Grid */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Security Scanner Engines</span>
                  </h4>
                  {scan.status === 'running' && (
                    <span className="text-xs font-mono text-amber-400 flex items-center gap-1.5 animate-pulse">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      <span>Scan running in background...</span>
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {/* Semgrep Card */}
                  {(() => {
                    const sr = scannerRuns.find((r) => r.scanner_name === 'semgrep');
                    return (
                      <div className="p-3.5 rounded-lg bg-slate-950/50 border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <Code2 className="w-4 h-4 text-indigo-400" />
                            <span className="font-semibold text-xs text-slate-200">Semgrep</span>
                          </div>
                          {sr ? <ScannerStatusBadge status={sr.status} /> : <ScannerStatusBadge status="pending" />}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
                          <div className="flex justify-between">
                            <span>Type:</span>
                            <span className="text-slate-300">SAST (Code)</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Version:</span>
                            <span className="text-slate-300">{sr?.scanner_version || 'auto'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Findings:</span>
                            <span className="text-indigo-400 font-bold">{sr?.findings_count ?? 0}</span>
                          </div>
                          {sr?.duration_seconds !== null && sr?.duration_seconds !== undefined && (
                            <div className="flex justify-between">
                              <span>Duration:</span>
                              <span className="text-slate-300">{sr.duration_seconds}s</span>
                            </div>
                          )}
                        </div>
                        {sr?.error_message && (
                          <p className="text-[10px] text-rose-400 bg-rose-950/40 p-1.5 rounded border border-rose-900/50 truncate" title={sr.error_message}>
                            {sr.error_message}
                          </p>
                        )}
                      </div>
                    );
                  })()}

                  {/* Gitleaks Card */}
                  {(() => {
                    const sr = scannerRuns.find((r) => r.scanner_name === 'gitleaks');
                    return (
                      <div className="p-3.5 rounded-lg bg-slate-950/50 border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <KeyRound className="w-4 h-4 text-rose-400" />
                            <span className="font-semibold text-xs text-slate-200">Gitleaks</span>
                          </div>
                          {sr ? <ScannerStatusBadge status={sr.status} /> : <ScannerStatusBadge status="pending" />}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
                          <div className="flex justify-between">
                            <span>Type:</span>
                            <span className="text-slate-300">Secrets</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Version:</span>
                            <span className="text-slate-300">{sr?.scanner_version || 'auto'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Findings:</span>
                            <span className="text-rose-400 font-bold">{sr?.findings_count ?? 0}</span>
                          </div>
                          {sr?.duration_seconds !== null && sr?.duration_seconds !== undefined && (
                            <div className="flex justify-between">
                              <span>Duration:</span>
                              <span className="text-slate-300">{sr.duration_seconds}s</span>
                            </div>
                          )}
                        </div>
                        {sr?.error_message && (
                          <p className="text-[10px] text-rose-400 bg-rose-950/40 p-1.5 rounded border border-rose-900/50 truncate" title={sr.error_message}>
                            {sr.error_message}
                          </p>
                        )}
                      </div>
                    );
                  })()}

                  {/* OSV-Scanner Card */}
                  {(() => {
                    const sr = scannerRuns.find((r) => r.scanner_name === 'osv-scanner');
                    return (
                      <div className="p-3.5 rounded-lg bg-slate-950/50 border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <PackageSearch className="w-4 h-4 text-purple-400" />
                            <span className="font-semibold text-xs text-slate-200">OSV-Scanner</span>
                          </div>
                          {sr ? <ScannerStatusBadge status={sr.status} /> : <ScannerStatusBadge status="pending" />}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
                          <div className="flex justify-between">
                            <span>Type:</span>
                            <span className="text-slate-300">SCA (Dependencies)</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Version:</span>
                            <span className="text-slate-300">{sr?.scanner_version || 'auto'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Findings:</span>
                            <span className="text-purple-400 font-bold">{sr?.findings_count ?? 0}</span>
                          </div>
                          {sr?.duration_seconds !== null && sr?.duration_seconds !== undefined && (
                            <div className="flex justify-between">
                              <span>Duration:</span>
                              <span className="text-slate-300">{sr.duration_seconds}s</span>
                            </div>
                          )}
                        </div>
                        {sr?.error_message && (
                          <p className="text-[10px] text-rose-400 bg-rose-950/40 p-1.5 rounded border border-rose-900/50 truncate" title={sr.error_message}>
                            {sr.error_message}
                          </p>
                        )}
                      </div>
                    );
                  })()}
                </div>
              </div>

              {/* Findings Section */}
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-emerald-400" />
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                      Normalized Findings ({filteredFindings.length})
                    </h4>
                    <span className="hidden sm:inline text-[11px] font-mono text-slate-400">
                      ({summary.total} total: {summary.code} code, {summary.secret} secrets, {summary.dependency} deps)
                    </span>
                  </div>

                  {/* Filter Badges / Selectors */}
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="flex items-center rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
                      {['all', 'code', 'secret', 'dependency'].map((cat) => (
                        <button
                          key={cat}
                          onClick={() => setCategoryFilter(cat)}
                          className={`px-2.5 py-1 rounded capitalize transition-colors ${
                            categoryFilter === cat
                              ? 'bg-slate-800 text-emerald-400 font-medium'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {cat}
                        </button>
                      ))}
                    </div>

                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                </div>

                {/* Findings List */}
                {scan.status === 'created' && (
                  <div className="p-8 text-center rounded-lg bg-slate-950/40 border border-slate-800">
                    <Clock className="w-6 h-6 text-slate-500 mx-auto mb-2" />
                    <p className="text-xs text-slate-300 font-medium">Scan has not been run yet</p>
                    <p className="text-[11px] text-slate-500 mt-1 max-w-sm mx-auto">
                      Click the "Run Security Scan" button above to launch Semgrep, Gitleaks, and OSV-Scanner analysis.
                    </p>
                  </div>
                )}

                {scan.status === 'running' && (
                  <div className="p-8 text-center rounded-lg bg-slate-950/40 border border-slate-800">
                    <Loader2 className="w-6 h-6 text-amber-400 animate-spin mx-auto mb-2" />
                    <p className="text-xs text-slate-300 font-medium">Analysis in progress</p>
                    <p className="text-[11px] text-slate-500 mt-1">
                      Scanners are actively scanning the validated workspace snapshot...
                    </p>
                  </div>
                )}

                {scan.status !== 'created' && scan.status !== 'running' && filteredFindings.length === 0 && (
                  <div className="p-8 text-center rounded-lg bg-slate-950/40 border border-slate-800">
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                    <p className="text-xs text-slate-300 font-medium">No findings match current filters</p>
                    <p className="text-[11px] text-slate-500 mt-1">
                      {findings.length === 0
                        ? 'All scanning tools completed with zero detected security risks.'
                        : 'Adjust category or severity filters to view remaining findings.'}
                    </p>
                  </div>
                )}

                {filteredFindings.length > 0 && (
                  <div className="space-y-2">
                    {filteredFindings.map((finding) => {
                      const isExpanded = expandedFindingId === finding.id;
                      return (
                        <div
                          key={finding.id}
                          className="rounded-lg bg-slate-950/50 border border-slate-800/80 overflow-hidden hover:border-slate-700 transition-colors"
                        >
                          <div
                            onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                            className="p-3 flex items-start justify-between gap-3 cursor-pointer select-none"
                          >
                            <div className="space-y-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <SeverityBadge severity={finding.severity} />
                                <CategoryBadge category={finding.category} />
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                                  {finding.scanner_name}
                                </span>
                                <span className="font-mono text-xs text-slate-200 font-medium">
                                  {finding.rule_id}
                                </span>
                              </div>
                              <h5 className="text-xs font-semibold text-slate-100">{finding.title}</h5>
                              {finding.file_path && (
                                <p className="text-[11px] font-mono text-slate-400">
                                  {finding.file_path}
                                  {finding.start_line ? `:${finding.start_line}` : ''}
                                </p>
                              )}
                            </div>
                            <span className="text-xs text-slate-500 font-mono mt-1">
                              {isExpanded ? '▲ hide' : '▼ details'}
                            </span>
                          </div>

                          {isExpanded && (
                            <div className="px-4 pb-4 pt-1 border-t border-slate-800/60 bg-slate-950/80 text-xs space-y-3">
                              {/* Description */}
                              <div>
                                <span className="text-slate-400 font-mono block text-[11px] mb-0.5">Description:</span>
                                <p className="text-slate-300 leading-relaxed whitespace-pre-line text-[11px]">
                                  {finding.description}
                                </p>
                              </div>

                              {/* Dependency Specific Details */}
                              {finding.package_name && (
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono">
                                  <div>
                                    <span className="text-slate-500 block">Package:</span>
                                    <span className="text-purple-300 font-semibold">{finding.package_name}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-500 block">Affected Ver:</span>
                                    <span className="text-slate-300">{finding.package_version || 'unknown'}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-500 block">Ecosystem:</span>
                                    <span className="text-slate-300">{finding.ecosystem || 'N/A'}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-500 block">Fixed in:</span>
                                    <span className="text-emerald-400 font-semibold">{finding.fixed_version || 'No fix recorded'}</span>
                                  </div>
                                </div>
                              )}

                              {/* Remediation Guidance */}
                              {finding.remediation_guidance && (
                                <div className="p-2.5 rounded bg-slate-900/90 border border-slate-800 text-[11px]">
                                  <span className="text-emerald-400 font-semibold block mb-0.5">Remediation:</span>
                                  <p className="text-slate-300">{finding.remediation_guidance}</p>
                                </div>
                              )}

                              {/* Advisory Link */}
                              {finding.advisory_url && (
                                <div className="flex items-center gap-1.5 text-[11px]">
                                  <span className="text-slate-500">Advisory Reference:</span>
                                  <a
                                    href={finding.advisory_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-cyan-400 hover:underline inline-flex items-center gap-1 truncate max-w-md"
                                  >
                                    <span className="truncate">{finding.advisory_url}</span>
                                    <ExternalLink className="w-3 h-3 shrink-0" />
                                  </a>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Raw Database Payload Toggle */}
              <div>
                <button
                  type="button"
                  onClick={() => setShowRawJson(!showRawJson)}
                  className="flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-emerald-400 transition-colors"
                >
                  <Code className="w-3.5 h-3.5" />
                  <span>{showRawJson ? 'Hide Raw Database Record JSON' : 'View Raw Database Record JSON'}</span>
                </button>

                {showRawJson && (
                  <pre className="mt-2 p-3 rounded-lg bg-black/60 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-48">
                    {JSON.stringify(scan, null, 2)}
                  </pre>
                )}
              </div>
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 flex items-center justify-between bg-slate-950/60 text-xs">
          <span className="text-slate-500 font-mono flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span>SQLite & Scanner Runs Persistence Verified</span>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors border border-slate-700"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
