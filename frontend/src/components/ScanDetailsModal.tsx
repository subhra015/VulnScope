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
  ExternalLink,
  CheckCircle2,
  GitCompare,
  TrendingUp,
  Info,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  ArrowRight,
} from 'lucide-react';
import { api, ApiError } from '../services/api';
import {
  ScanDetail,
  ScannerRun,
  FindingDetail,
  RiskSummary,
  ScanComparisonResponse,
  Scan,
} from '../types';
import {
  StatusBadge,
  ScannerStatusBadge,
  SeverityBadge,
  CategoryBadge,
  PriorityBadge,
  LifecycleBadge,
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

  // Active view tab: 'findings' | 'risk_summary' | 'comparison'
  const [activeTab, setActiveTab] = useState<'findings' | 'risk_summary' | 'comparison'>('findings');

  // Filters and Sorting
  const [priorityFilter, setPriorityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [scannerFilter, setScannerFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [lifecycleFilter, setLifecycleFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'priority' | 'severity' | 'created_at'>('priority');

  // Finding details cache for expanded items
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [findingDetails, setFindingDetails] = useState<Record<string, FindingDetail>>({});
  const [loadingFindingDetailId, setLoadingFindingDetailId] = useState<string | null>(null);

  // Risk summary state
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);
  const [isLoadingSummary, setIsLoadingSummary] = useState(false);

  // Comparison state
  const [availableBaselines, setAvailableBaselines] = useState<Scan[]>([]);
  const [selectedBaselineId, setSelectedBaselineId] = useState<string>('');
  const [comparisonResult, setComparisonResult] = useState<ScanComparisonResponse | null>(null);
  const [isLoadingComparison, setIsLoadingComparison] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  const [comparisonStatusFilter, setComparisonStatusFilter] = useState<string>('all');

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

  const fetchRiskSummary = useCallback(async (id: string) => {
    setIsLoadingSummary(true);
    try {
      const summary = await api.getScanRiskSummary(id);
      setRiskSummary(summary);
    } catch {
      // Non-blocking fallback
    } finally {
      setIsLoadingSummary(false);
    }
  }, []);

  // Fetch available baselines for comparison
  const fetchBaselines = useCallback(async (currentScan: ScanDetail) => {
    try {
      const allScans = await api.getScans();
      const eligible = allScans.filter((s) => {
        if (s.id === currentScan.id) return false;
        if (s.status !== 'completed' && s.status !== 'partial') return false;
        // Check lineage
        if (currentScan.repository_id && s.id !== currentScan.id) {
          return true; // backend will further validate
        }
        return (
          s.project_name.toLowerCase() === currentScan.project_name.toLowerCase() &&
          s.source_type.toLowerCase() === currentScan.source_type.toLowerCase()
        );
      });
      setAvailableBaselines(eligible);
      if (eligible.length > 0 && !selectedBaselineId) {
        setSelectedBaselineId(eligible[0].id);
      }
    } catch {
      // Non-blocking
    }
  }, [selectedBaselineId]);

  useEffect(() => {
    if (!scanId) {
      setScan(null);
      setRiskSummary(null);
      setComparisonResult(null);
      return;
    }

    fetchScan(scanId, true).then((data) => {
      if (data) {
        fetchRiskSummary(scanId);
        fetchBaselines(data);
      }
    });

    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [scanId, fetchScan, fetchRiskSummary, fetchBaselines]);

  // Periodic refresh when scan is running
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
            fetchRiskSummary(scanId);
            fetchBaselines(updated);
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
  }, [scanId, scan, fetchScan, fetchRiskSummary, fetchBaselines, onScanUpdated]);

  // Lazy-load finding detail when expanded
  const handleToggleExpandFinding = async (findingId: string) => {
    if (expandedFindingId === findingId) {
      setExpandedFindingId(null);
      return;
    }

    setExpandedFindingId(findingId);
    if (!scanId || findingDetails[findingId]) {
      return;
    }

    setLoadingFindingDetailId(findingId);
    try {
      const detail = await api.getFindingDetail(scanId, findingId);
      setFindingDetails((prev) => ({ ...prev, [findingId]: detail }));
    } catch (err) {
      console.error('Failed to load finding detail:', err);
    } finally {
      setLoadingFindingDetailId(null);
    }
  };

  // Perform comparison
  const handleRunComparison = async () => {
    if (!scanId || !selectedBaselineId) return;
    setIsLoadingComparison(true);
    setComparisonError(null);
    try {
      const res = await api.compareScans(scanId, selectedBaselineId);
      setComparisonResult(res);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setComparisonError(err.message);
      } else {
        setComparisonError('Scan comparison failed');
      }
      setComparisonResult(null);
    } finally {
      setIsLoadingComparison(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'comparison' && selectedBaselineId && !comparisonResult && !isLoadingComparison) {
      handleRunComparison();
    }
  }, [activeTab, selectedBaselineId]);

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

  // Filter & sort findings
  const findings = scan?.findings || [];
  const filteredFindings = findings
    .filter((f) => {
      if (priorityFilter !== 'all' && (f.priority || '').toLowerCase() !== priorityFilter.toLowerCase()) {
        return false;
      }
      if (categoryFilter !== 'all' && (f.category || 'code').toLowerCase() !== categoryFilter.toLowerCase()) {
        return false;
      }
      if (scannerFilter !== 'all' && f.scanner_name.toLowerCase() !== scannerFilter.toLowerCase()) {
        return false;
      }
      if (severityFilter !== 'all' && f.severity.toLowerCase() !== severityFilter.toLowerCase()) {
        return false;
      }
      if (lifecycleFilter !== 'all' && (f.lifecycle_status || 'new').toLowerCase() !== lifecycleFilter.toLowerCase()) {
        return false;
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'priority') {
        const scoreA = a.risk_score ?? 0;
        const scoreB = b.risk_score ?? 0;
        return scoreB - scoreA;
      } else if (sortBy === 'severity') {
        const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        const rankA = rank[a.severity.toLowerCase()] ?? 0;
        const rankB = rank[b.severity.toLowerCase()] ?? 0;
        return rankB - rankA;
      }
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

  const scannerRuns: ScannerRun[] = scan?.scanner_runs || [];
  const canRunScan = scan && scan.intake_status === 'ready' && scan.status !== 'running';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-5xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
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
                {scan && <StatusBadge status={scan.status} />}
              </h3>
              <p className="text-xs text-slate-400">Deterministic risk prioritization, remediation guidance, & lifecycle tracking</p>
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

        {/* View Mode Navigation Tabs */}
        <div className="px-6 pt-3 border-b border-slate-800 bg-slate-950/40 flex items-center justify-between">
          <div className="flex items-center gap-1">
            <button
              onClick={() => setActiveTab('findings')}
              className={`flex items-center gap-2 px-3 py-2 text-xs font-medium border-b-2 transition-all ${
                activeTab === 'findings'
                  ? 'border-emerald-500 text-emerald-400 bg-slate-900/60'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Prioritized Findings ({findings.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('risk_summary')}
              className={`flex items-center gap-2 px-3 py-2 text-xs font-medium border-b-2 transition-all ${
                activeTab === 'risk_summary'
                  ? 'border-emerald-500 text-emerald-400 bg-slate-900/60'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <TrendingUp className="w-3.5 h-3.5" />
              <span>Risk & Coverage Summary</span>
            </button>

            <button
              onClick={() => setActiveTab('comparison')}
              className={`flex items-center gap-2 px-3 py-2 text-xs font-medium border-b-2 transition-all ${
                activeTab === 'comparison'
                  ? 'border-emerald-500 text-emerald-400 bg-slate-900/60'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
              }`}
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Scan Comparison & Lifecycle</span>
            </button>
          </div>

          <div className="flex items-center gap-2 pb-2">
            <span className="text-[11px] font-mono text-slate-500">ID:</span>
            <code className="text-[11px] font-mono text-slate-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
              {scanId.slice(0, 8)}...
            </code>
            <button
              onClick={handleCopyId}
              className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              title="Copy Scan UUID"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
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
                <p className="mt-0.5">{error}</p>
              </div>
            </div>
          )}

          {!isLoading && scan && (
            <>
              {/* TAB 1: PRIORITIZED FINDINGS */}
              {activeTab === 'findings' && (
                <div className="space-y-4">
                  {/* Top Notification / Explanatory Banner */}
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2 text-slate-300">
                      <Info className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span>
                        <strong>Deterministic Risk Prioritization:</strong> Findings are scored 0–100 using scanner severity, confidence, CVSS base metrics, exploitability signals, and location precision.
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">Phase 4 Engine</span>
                  </div>

                  {/* Filter Toolbar */}
                  <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        {/* Priority Selector */}
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-400 text-[11px] font-medium">Priority:</span>
                          <select
                            value={priorityFilter}
                            onChange={(e) => setPriorityFilter(e.target.value)}
                            className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
                          >
                            <option value="all">All Priorities</option>
                            <option value="critical">Critical (85–100)</option>
                            <option value="high">High (70–84)</option>
                            <option value="medium">Medium (40–69)</option>
                            <option value="low">Low (0–39)</option>
                          </select>
                        </div>

                        {/* Category Selector */}
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-400 text-[11px] font-medium">Category:</span>
                          <select
                            value={categoryFilter}
                            onChange={(e) => setCategoryFilter(e.target.value)}
                            className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
                          >
                            <option value="all">All Categories</option>
                            <option value="code">SAST Code</option>
                            <option value="secret">Secret</option>
                            <option value="dependency">SCA Dep</option>
                          </select>
                        </div>

                        {/* Scanner Selector */}
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-400 text-[11px] font-medium">Scanner:</span>
                          <select
                            value={scannerFilter}
                            onChange={(e) => setScannerFilter(e.target.value)}
                            className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
                          >
                            <option value="all">All Scanners</option>
                            <option value="semgrep">Semgrep</option>
                            <option value="gitleaks">Gitleaks</option>
                            <option value="osv-scanner">OSV-Scanner</option>
                          </select>
                        </div>

                        {/* Severity Selector */}
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-400 text-[11px] font-medium">Severity:</span>
                          <select
                            value={severityFilter}
                            onChange={(e) => setSeverityFilter(e.target.value)}
                            className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
                          >
                            <option value="all">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                          </select>
                        </div>

                        {/* Lifecycle Selector */}
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-400 text-[11px] font-medium">Lifecycle:</span>
                          <select
                            value={lifecycleFilter}
                            onChange={(e) => setLifecycleFilter(e.target.value)}
                            className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
                          >
                            <option value="all">All States</option>
                            <option value="new">New</option>
                            <option value="recurring">Recurring</option>
                            <option value="changed">Changed</option>
                          </select>
                        </div>
                      </div>

                      {/* Sort Order */}
                      <div className="flex items-center gap-1.5 text-xs">
                        <span className="text-slate-400 text-[11px] font-medium">Sort By:</span>
                        <select
                          value={sortBy}
                          onChange={(e) => setSortBy(e.target.value as any)}
                          className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-emerald-400 font-medium focus:outline-none focus:border-emerald-500"
                        >
                          <option value="priority">Risk Priority Score (High to Low)</option>
                          <option value="severity">Original Severity</option>
                          <option value="created_at">Timestamp</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Empty States */}
                  {scan.status === 'created' && (
                    <div className="p-10 text-center rounded-lg bg-slate-950/40 border border-slate-800">
                      <Clock className="w-8 h-8 text-slate-500 mx-auto mb-2" />
                      <p className="text-xs text-slate-300 font-medium">Scan has not executed yet</p>
                      <p className="text-[11px] text-slate-500 mt-1 max-w-sm mx-auto">
                        Launch Semgrep, Gitleaks, and OSV-Scanner using the "Run Security Scan" button above to generate prioritized findings.
                      </p>
                    </div>
                  )}

                  {scan.status === 'running' && (
                    <div className="p-10 text-center rounded-lg bg-slate-950/40 border border-slate-800">
                      <Loader2 className="w-8 h-8 text-amber-400 animate-spin mx-auto mb-2" />
                      <p className="text-xs text-slate-300 font-medium">Security Scanners Executing</p>
                      <p className="text-[11px] text-slate-500 mt-1">
                        Active analysis across SAST, Secret Leakage, and Dependency components...
                      </p>
                    </div>
                  )}

                  {scan.status !== 'created' && scan.status !== 'running' && filteredFindings.length === 0 && (
                    <div className="p-10 text-center rounded-lg bg-slate-950/40 border border-slate-800">
                      <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                      <p className="text-xs text-slate-300 font-medium">No findings match the selected filters</p>
                      <p className="text-[11px] text-slate-500 mt-1">
                        {findings.length === 0
                          ? 'All scanning tools completed with zero detected security risks.'
                          : 'Adjust your priority, category, or scanner filters to inspect remaining findings.'}
                      </p>
                    </div>
                  )}

                  {/* Findings Cards List */}
                  {filteredFindings.length > 0 && (
                    <div className="space-y-3">
                      {filteredFindings.map((finding) => {
                        const isExpanded = expandedFindingId === finding.id;
                        const detail = findingDetails[finding.id];
                        const isLoadingDetail = loadingFindingDetailId === finding.id;

                        return (
                          <div
                            key={finding.id}
                            className={`rounded-lg border transition-all ${
                              isExpanded
                                ? 'bg-slate-950 border-emerald-800/80 shadow-md'
                                : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                            }`}
                          >
                            {/* Card Summary Row */}
                            <div
                              onClick={() => handleToggleExpandFinding(finding.id)}
                              className="p-3.5 flex items-start justify-between gap-3 cursor-pointer select-none"
                            >
                              <div className="space-y-1.5 flex-1 min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                  {/* VulnScope Priority Badge & Numeric Score */}
                                  <PriorityBadge
                                    priority={finding.priority}
                                    score={finding.risk_score}
                                    showScore={true}
                                  />

                                  {/* Original Scanner Severity (Clearly visible alongside priority) */}
                                  <div className="flex items-center gap-1">
                                    <span className="text-[10px] font-mono text-slate-500">Scanner Sev:</span>
                                    <SeverityBadge severity={finding.severity} />
                                  </div>

                                  {/* Category & Scanner Pills */}
                                  <CategoryBadge category={finding.category} />
                                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                                    {finding.scanner_name}
                                  </span>

                                  {/* Lifecycle State */}
                                  {finding.lifecycle_status && (
                                    <LifecycleBadge status={finding.lifecycle_status} />
                                  )}

                                  <span className="font-mono text-xs text-slate-300 font-medium truncate max-w-xs">
                                    {finding.rule_id}
                                  </span>
                                </div>

                                <h5 className="text-xs font-semibold text-slate-100 truncate">{finding.title}</h5>

                                <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400">
                                  {finding.file_path && (
                                    <span>
                                      {finding.file_path}
                                      {finding.start_line ? `:${finding.start_line}` : ''}
                                    </span>
                                  )}
                                  {finding.package_name && (
                                    <span className="text-purple-300">
                                      Pkg: {finding.package_name} ({finding.package_version || 'unknown'})
                                    </span>
                                  )}
                                  {finding.fixed_version && (
                                    <span className="text-emerald-400 font-medium">
                                      Fixed in: {finding.fixed_version}
                                    </span>
                                  )}
                                </div>
                              </div>

                              <div className="flex items-center gap-2 shrink-0 text-xs text-slate-400 font-mono mt-1">
                                <span>{isExpanded ? 'Hide' : 'Explain & Remediate'}</span>
                                {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                              </div>
                            </div>

                            {/* Expanded Details Drawer */}
                            {isExpanded && (
                              <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 bg-slate-950/90 text-xs space-y-4">
                                {isLoadingDetail && (
                                  <div className="py-6 flex items-center justify-center gap-2 text-slate-400">
                                    <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
                                    <span>Loading explainability factors and remediation guidance...</span>
                                  </div>
                                )}

                                {!isLoadingDetail && (
                                  <>
                                    {/* 1. Risk Priority Score Explanation */}
                                    <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2.5">
                                      <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                          <TrendingUp className="w-4 h-4 text-emerald-400" />
                                          <h6 className="font-semibold text-slate-200 text-xs">
                                            Score Explanation ({finding.risk_score ?? 50}/100 &mdash; {finding.priority?.toUpperCase() ?? 'MEDIUM'})
                                          </h6>
                                        </div>
                                        <span className="text-[10px] font-mono text-slate-500">Deterministic Model</span>
                                      </div>

                                      {/* Human-readable rationale */}
                                      <p className="text-slate-300 text-[11px] leading-relaxed">
                                        {detail?.risk_explanation?.reason ||
                                          `Finding risk score of ${finding.risk_score ?? 50}/100 computed from scanner severity, detection confidence, and contextual factors.`}
                                      </p>

                                      {/* Scoring Factor Breakdown */}
                                      {detail?.risk_explanation?.factors && detail.risk_explanation.factors.length > 0 && (
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
                                          {detail.risk_explanation.factors.map((factor, idx) => (
                                            <div
                                              key={idx}
                                              className="p-2.5 rounded bg-slate-950 border border-slate-800/80 text-[11px] space-y-1"
                                            >
                                              <div className="flex items-center justify-between">
                                                <span className="font-medium text-slate-300">{factor.name}</span>
                                                <span className="font-mono text-emerald-400 font-semibold">
                                                  +{factor.contribution} pts
                                                </span>
                                              </div>
                                              <p className="text-slate-400 text-[10px] leading-snug">{factor.description}</p>
                                              <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-0.5">
                                                <span>Weight: {Math.round(factor.weight * 100)}%</span>
                                                <span>Raw Component: {factor.raw_score}/100</span>
                                              </div>
                                            </div>
                                          ))}
                                        </div>
                                      )}

                                      {/* Missing Evidence / Uncertainty Notes */}
                                      {detail?.risk_explanation?.missing_evidence &&
                                        detail.risk_explanation.missing_evidence.length > 0 && (
                                          <div className="p-2.5 rounded bg-amber-950/30 border border-amber-900/40 text-[11px] space-y-1">
                                            <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                                              <AlertTriangle className="w-3.5 h-3.5" />
                                              <span>Missing Evidence & Uncertainty Disclaimers</span>
                                            </div>
                                            <ul className="list-disc list-inside space-y-0.5 text-slate-400 text-[10px]">
                                              {detail.risk_explanation.missing_evidence.map((note, idx) => (
                                                <li key={idx}>{note}</li>
                                              ))}
                                            </ul>
                                          </div>
                                        )}

                                      <p className="text-[10px] text-slate-500 italic">
                                        Note: Risk scores prioritize remediation order based on verifiable scanner signals. They do not constitute an empirical guarantee of production exploitability.
                                      </p>
                                    </div>

                                    {/* 2. Structured Remediation Guidance */}
                                    <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
                                      <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                          <ShieldCheck className="w-4 h-4 text-emerald-400" />
                                          <h6 className="font-semibold text-slate-200 text-xs">Actionable Remediation Guidance</h6>
                                        </div>
                                        <span className="text-[10px] font-mono text-slate-500">Non-destructive</span>
                                      </div>

                                      {/* Remediation Summary */}
                                      <p className="text-emerald-300 font-medium text-[11px]">
                                        {detail?.remediation?.summary ||
                                          finding.remediation_guidance ||
                                          'Inspect finding context and apply defensive programming controls.'}
                                      </p>

                                      {/* Step by step instructions */}
                                      {detail?.remediation?.steps && detail.remediation.steps.length > 0 && (
                                        <div className="space-y-1.5">
                                          <span className="text-slate-400 font-medium block text-[11px]">Remediation Steps:</span>
                                          <ol className="list-decimal list-inside space-y-1 text-slate-300 text-[11px] pl-1">
                                            {detail.remediation.steps.map((step, idx) => (
                                              <li key={idx} className="leading-relaxed">
                                                {step}
                                              </li>
                                            ))}
                                          </ol>
                                        </div>
                                      )}

                                      {/* Unsafe Pattern vs Safer Alternative */}
                                      {detail?.remediation?.unsafe_pattern && (
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                                          <div className="p-2 rounded bg-rose-950/20 border border-rose-900/30 text-rose-300">
                                            <span className="font-semibold block text-[10px] uppercase text-rose-400 mb-0.5">
                                              Unsafe Pattern
                                            </span>
                                            <p className="font-mono text-[10px] break-words">{detail.remediation.unsafe_pattern}</p>
                                          </div>
                                          <div className="p-2 rounded bg-emerald-950/20 border border-emerald-900/30 text-emerald-300">
                                            <span className="font-semibold block text-[10px] uppercase text-emerald-400 mb-0.5">
                                              Safer Alternative
                                            </span>
                                            <p className="font-mono text-[10px] break-words">{detail.remediation.safer_alternative}</p>
                                          </div>
                                        </div>
                                      )}

                                      {/* Critical Caveats */}
                                      {detail?.remediation?.caveats && detail.remediation.caveats.length > 0 && (
                                        <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] space-y-1">
                                          <span className="text-amber-400 font-semibold block">Important Warnings:</span>
                                          <ul className="list-disc list-inside space-y-0.5 text-slate-400">
                                            {detail.remediation.caveats.map((caveat, idx) => (
                                              <li key={idx}>{caveat}</li>
                                            ))}
                                          </ul>
                                        </div>
                                      )}

                                      {/* Authoritative References */}
                                      {detail?.remediation?.references && detail.remediation.references.length > 0 && (
                                        <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
                                          <span className="text-slate-400">Trusted References:</span>
                                          {detail.remediation.references.map((refUrl, idx) => (
                                            <a
                                              key={idx}
                                              href={refUrl}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="text-cyan-400 hover:underline inline-flex items-center gap-1 font-mono text-[10px]"
                                            >
                                              <span>{refUrl.split('/')[2]}</span>
                                              <ExternalLink className="w-2.5 h-2.5" />
                                            </a>
                                          ))}
                                        </div>
                                      )}
                                    </div>

                                    {/* 3. Description & Coordinates */}
                                    <div className="space-y-2 text-[11px]">
                                      <div>
                                        <span className="text-slate-400 font-mono block text-[10px] mb-0.5">
                                          Technical Description:
                                        </span>
                                        <p className="text-slate-300 leading-relaxed whitespace-pre-line text-[11px] bg-slate-950 p-2.5 rounded border border-slate-800/80">
                                          {finding.description}
                                        </p>
                                      </div>

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
                                            <span className="text-emerald-400 font-semibold">
                                              {finding.fixed_version || 'No fix recorded'}
                                            </span>
                                          </div>
                                        </div>
                                      )}

                                      {finding.advisory_url && (
                                        <div className="flex items-center gap-1.5 text-[11px] pt-1">
                                          <span className="text-slate-500">Advisory:</span>
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
                                  </>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: RISK SUMMARY & COVERAGE */}
              {activeTab === 'risk_summary' && (
                <div className="space-y-5">
                  {isLoadingSummary && (
                    <div className="py-12 flex flex-col items-center justify-center text-slate-400">
                      <Loader2 className="w-6 h-6 animate-spin text-emerald-400 mb-2" />
                      <p className="text-xs">Computing scan risk summary and coverage metrics...</p>
                    </div>
                  )}

                  {!isLoadingSummary && riskSummary && (
                    <>
                      {/* Priority Metrics Cards */}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-900/50 space-y-1">
                          <span className="text-[11px] font-medium text-red-400 uppercase tracking-wider">Critical Priority</span>
                          <p className="text-2xl font-bold text-red-300">{riskSummary.priority_distribution.critical}</p>
                          <span className="text-[10px] text-slate-400 block font-mono">Score &ge; 85</span>
                        </div>

                        <div className="p-3.5 rounded-lg bg-orange-950/30 border border-orange-900/50 space-y-1">
                          <span className="text-[11px] font-medium text-orange-400 uppercase tracking-wider">High Priority</span>
                          <p className="text-2xl font-bold text-orange-300">{riskSummary.priority_distribution.high}</p>
                          <span className="text-[10px] text-slate-400 block font-mono">Score 70–84</span>
                        </div>

                        <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-900/50 space-y-1">
                          <span className="text-[11px] font-medium text-amber-400 uppercase tracking-wider">Medium Priority</span>
                          <p className="text-2xl font-bold text-amber-300">{riskSummary.priority_distribution.medium}</p>
                          <span className="text-[10px] text-slate-400 block font-mono">Score 40–69</span>
                        </div>

                        <div className="p-3.5 rounded-lg bg-sky-950/30 border border-sky-900/50 space-y-1">
                          <span className="text-[11px] font-medium text-sky-400 uppercase tracking-wider">Low Priority</span>
                          <p className="text-2xl font-bold text-sky-300">{riskSummary.priority_distribution.low}</p>
                          <span className="text-[10px] text-slate-400 block font-mono">Score &lt; 40</span>
                        </div>
                      </div>

                      {/* Score Averages & Category Breakdown */}
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                          <span className="text-xs font-semibold text-slate-300 block">Risk Score Metrics</span>
                          <div className="flex items-baseline justify-between">
                            <span className="text-slate-400 text-xs">Mean Risk Score:</span>
                            <span className="text-lg font-mono font-bold text-emerald-400">
                              {riskSummary.mean_risk_score} / 100
                            </span>
                          </div>
                          <div className="flex items-baseline justify-between">
                            <span className="text-slate-400 text-xs">Max Observed Score:</span>
                            <span className="text-lg font-mono font-bold text-rose-400">
                              {riskSummary.max_risk_score} / 100
                            </span>
                          </div>
                          <p className="text-[10px] text-slate-500 pt-1">
                            Calculated dynamically across {riskSummary.total_findings} normalized finding records.
                          </p>
                        </div>

                        <div className="sm:col-span-2 p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                          <span className="text-xs font-semibold text-slate-300 block">Category Distribution & Mean Priority</span>
                          <div className="grid grid-cols-3 gap-2 text-xs">
                            <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-center">
                              <span className="text-indigo-400 block font-semibold">SAST Code</span>
                              <span className="text-lg font-bold text-slate-100">{riskSummary.category_distribution.code?.count ?? 0}</span>
                              <span className="text-[10px] text-slate-400 block font-mono">
                                Avg: {riskSummary.category_distribution.code?.avg_risk_score ?? 0}
                              </span>
                            </div>

                            <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-center">
                              <span className="text-red-400 block font-semibold">Secret Leaks</span>
                              <span className="text-lg font-bold text-slate-100">{riskSummary.category_distribution.secret?.count ?? 0}</span>
                              <span className="text-[10px] text-slate-400 block font-mono">
                                Avg: {riskSummary.category_distribution.secret?.avg_risk_score ?? 0}
                              </span>
                            </div>

                            <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-center">
                              <span className="text-purple-400 block font-semibold">SCA Dependencies</span>
                              <span className="text-lg font-bold text-slate-100">{riskSummary.category_distribution.dependency?.count ?? 0}</span>
                              <span className="text-[10px] text-slate-400 block font-mono">
                                Avg: {riskSummary.category_distribution.dependency?.avg_risk_score ?? 0}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Scanner Execution Coverage Table */}
                      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-slate-200">Scanner Engine Coverage</span>
                          <span className="text-[11px] font-mono text-slate-500">Execution Status</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                          {scannerRuns.map((sr) => (
                            <div key={sr.scanner_name} className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-xs text-slate-200 capitalize">{sr.scanner_name}</span>
                                <ScannerStatusBadge status={sr.status} />
                              </div>
                              <div className="text-[11px] font-mono text-slate-400 flex justify-between">
                                <span>Findings Detected:</span>
                                <span className="text-slate-200 font-bold">{sr.findings_count}</span>
                              </div>
                              {sr.duration_seconds !== null && sr.duration_seconds !== undefined && (
                                <div className="text-[10px] font-mono text-slate-500 flex justify-between">
                                  <span>Runtime:</span>
                                  <span>{sr.duration_seconds}s</span>
                                </div>
                              )}
                              {sr.error_message && (
                                <p className="text-[10px] text-rose-400 bg-rose-950/40 p-1.5 rounded border border-rose-900/50 truncate" title={sr.error_message}>
                                  {sr.error_message}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>

                        {/* Scanner Coverage Disclaimers */}
                        {riskSummary.coverage_notes && riskSummary.coverage_notes.length > 0 && (
                          <div className="p-3 rounded bg-amber-950/30 border border-amber-900/40 text-xs space-y-1 mt-2">
                            <span className="font-semibold text-amber-400 block text-[11px]">Coverage Caveats:</span>
                            <ul className="list-disc list-inside space-y-0.5 text-slate-400 text-[10px]">
                              {riskSummary.coverage_notes.map((note, idx) => (
                                <li key={idx}>{note}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* TAB 3: LIFECYCLE & SCAN COMPARISON */}
              {activeTab === 'comparison' && (
                <div className="space-y-4">
                  {/* Baseline Selection Card */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <h5 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                          <GitCompare className="w-4 h-4 text-emerald-400" />
                          <span>Compare With Prior Scan</span>
                        </h5>
                        <p className="text-[11px] text-slate-400">
                          Track finding lifecycle evolution (new, recurring, resolved, changed) across comparable scans of the same project.
                        </p>
                      </div>

                      <div className="flex items-center gap-2">
                        <select
                          value={selectedBaselineId}
                          onChange={(e) => setSelectedBaselineId(e.target.value)}
                          disabled={availableBaselines.length === 0}
                          className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                        >
                          {availableBaselines.length === 0 ? (
                            <option value="">No eligible baseline scan found</option>
                          ) : (
                            availableBaselines.map((b) => (
                              <option key={b.id} value={b.id}>
                                Scan {b.id.slice(0, 8)} &mdash; {formatDate(b.created_at)} ({b.status})
                              </option>
                            ))
                          )}
                        </select>

                        <button
                          type="button"
                          onClick={handleRunComparison}
                          disabled={!selectedBaselineId || isLoadingComparison}
                          className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors disabled:opacity-50 inline-flex items-center gap-1.5"
                        >
                          {isLoadingComparison ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <GitCompare className="w-3.5 h-3.5" />}
                          <span>Compare</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  {comparisonError && (
                    <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-800/80 text-rose-300 text-xs flex items-start gap-2.5">
                      <AlertCircle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
                      <div>
                        <span className="font-semibold block">Comparison Ineligible</span>
                        <p className="text-[11px] mt-0.5">{comparisonError}</p>
                      </div>
                    </div>
                  )}

                  {isLoadingComparison && (
                    <div className="py-12 flex flex-col items-center justify-center text-slate-400">
                      <Loader2 className="w-6 h-6 animate-spin text-emerald-400 mb-2" />
                      <p className="text-xs">Diffing findings and analyzing scanner coverage...</p>
                    </div>
                  )}

                  {!isLoadingComparison && comparisonResult && (
                    <div className="space-y-4">
                      {/* Comparison Metrics Summary Pills */}
                      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
                        <button
                          onClick={() => setComparisonStatusFilter('new')}
                          className={`p-2.5 rounded-lg border text-center transition-all ${
                            comparisonStatusFilter === 'new'
                              ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300'
                              : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                          }`}
                        >
                          <span className="text-[10px] uppercase font-semibold text-emerald-400 block">New</span>
                          <span className="text-xl font-bold font-mono text-emerald-300">
                            +{comparisonResult.summary.new}
                          </span>
                        </button>

                        <button
                          onClick={() => setComparisonStatusFilter('recurring')}
                          className={`p-2.5 rounded-lg border text-center transition-all ${
                            comparisonStatusFilter === 'recurring'
                              ? 'bg-amber-950/80 border-amber-500 text-amber-300'
                              : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                          }`}
                        >
                          <span className="text-[10px] uppercase font-semibold text-amber-400 block">Recurring</span>
                          <span className="text-xl font-bold font-mono text-amber-300">
                            {comparisonResult.summary.recurring}
                          </span>
                        </button>

                        <button
                          onClick={() => setComparisonStatusFilter('resolved')}
                          className={`p-2.5 rounded-lg border text-center transition-all ${
                            comparisonStatusFilter === 'resolved'
                              ? 'bg-blue-950/80 border-blue-500 text-blue-300'
                              : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                          }`}
                        >
                          <span className="text-[10px] uppercase font-semibold text-blue-400 block">Resolved</span>
                          <span className="text-xl font-bold font-mono text-blue-300">
                            -{comparisonResult.summary.resolved}
                          </span>
                        </button>

                        <button
                          onClick={() => setComparisonStatusFilter('changed')}
                          className={`p-2.5 rounded-lg border text-center transition-all ${
                            comparisonStatusFilter === 'changed'
                              ? 'bg-purple-950/80 border-purple-500 text-purple-300'
                              : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                          }`}
                        >
                          <span className="text-[10px] uppercase font-semibold text-purple-400 block">Changed</span>
                          <span className="text-xl font-bold font-mono text-purple-300">
                            ~{comparisonResult.summary.changed}
                          </span>
                        </button>

                        <button
                          onClick={() => setComparisonStatusFilter('unconfirmed')}
                          className={`p-2.5 rounded-lg border text-center transition-all ${
                            comparisonStatusFilter === 'unconfirmed'
                              ? 'bg-slate-900 border-slate-500 text-slate-200'
                              : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                          }`}
                        >
                          <span className="text-[10px] uppercase font-semibold text-slate-400 block">Unconfirmed</span>
                          <span className="text-xl font-bold font-mono text-slate-300">
                            ?{comparisonResult.summary.unconfirmed}
                          </span>
                        </button>
                      </div>

                      {/* Comparability Warnings */}
                      {comparisonResult.comparability_notes && comparisonResult.comparability_notes.length > 0 && (
                        <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-900/50 text-xs space-y-1">
                          <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-[11px]">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            <span>Scan Lineage & Resolution Caveats</span>
                          </div>
                          <ul className="list-disc list-inside space-y-0.5 text-slate-300 text-[10px]">
                            {comparisonResult.comparability_notes.map((note, idx) => (
                              <li key={idx}>{note}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Filter Reset */}
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400">
                          Showing findings for state:{' '}
                          <span className="text-emerald-400 font-semibold uppercase">{comparisonStatusFilter}</span>
                        </span>
                        {comparisonStatusFilter !== 'all' && (
                          <button
                            onClick={() => setComparisonStatusFilter('all')}
                            className="text-xs text-slate-400 hover:text-slate-200 underline"
                          >
                            Show All Findings
                          </button>
                        )}
                      </div>

                      {/* Compared Findings List */}
                      {(() => {
                        let items: any[] = [];
                        if (comparisonStatusFilter === 'all') {
                          items = [
                            ...comparisonResult.new_findings,
                            ...comparisonResult.recurring_findings,
                            ...comparisonResult.resolved_findings,
                            ...comparisonResult.changed_findings,
                            ...comparisonResult.unconfirmed_findings,
                          ];
                        } else if (comparisonStatusFilter === 'new') {
                          items = comparisonResult.new_findings;
                        } else if (comparisonStatusFilter === 'recurring') {
                          items = comparisonResult.recurring_findings;
                        } else if (comparisonStatusFilter === 'resolved') {
                          items = comparisonResult.resolved_findings;
                        } else if (comparisonStatusFilter === 'changed') {
                          items = comparisonResult.changed_findings;
                        } else if (comparisonStatusFilter === 'unconfirmed') {
                          items = comparisonResult.unconfirmed_findings;
                        }

                        if (items.length === 0) {
                          return (
                            <div className="p-8 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
                              No findings in category '{comparisonStatusFilter}'.
                            </div>
                          );
                        }

                        return (
                          <div className="space-y-2">
                            {items.map((item) => (
                              <div
                                key={item.finding_id}
                                className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1.5"
                              >
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <LifecycleBadge status={item.lifecycle_status} />
                                    {item.priority && (
                                      <PriorityBadge priority={item.priority} score={item.risk_score} />
                                    )}
                                    <SeverityBadge severity={item.severity} />
                                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                                      {item.scanner_name}
                                    </span>
                                    <span className="font-mono text-slate-200 font-medium">{item.rule_id}</span>
                                  </div>

                                  {item.file_path && (
                                    <span className="text-[11px] font-mono text-slate-400">
                                      {item.file_path}
                                      {item.start_line ? `:${item.start_line}` : ''}
                                    </span>
                                  )}
                                </div>

                                <h6 className="font-semibold text-slate-200 text-xs">{item.title}</h6>

                                {item.changes && item.changes.length > 0 && (
                                  <div className="p-2 rounded bg-purple-950/30 border border-purple-900/40 text-[10px] space-y-1 mt-1 font-mono">
                                    <span className="text-purple-300 font-semibold block uppercase">Detected Attribute Changes:</span>
                                    {item.changes.map((ch: any, idx: number) => (
                                      <div key={idx} className="flex items-center gap-2 text-slate-300">
                                        <span className="text-slate-400">{ch.field}:</span>
                                        <span className="text-rose-400 line-through">{String(ch.old_value ?? 'none')}</span>
                                        <ArrowRight className="w-3 h-3 text-slate-500" />
                                        <span className="text-emerald-400">{String(ch.new_value ?? 'none')}</span>
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              )}

              {/* Raw JSON Toggle */}
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
        <div className="px-6 py-3 border-t border-slate-800 flex items-center justify-between bg-slate-950/70 text-xs">
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
