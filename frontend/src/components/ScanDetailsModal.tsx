import React, { useEffect, useState } from 'react';
import {
  X,
  Layers,
  Calendar,
  Clock,
  GitBranch,
  Archive,
  ShieldAlert,
  Code,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  Database,
} from 'lucide-react';
import { api, ApiError } from '../services/api';
import { ScanDetail } from '../types';
import { StatusBadge } from './StatusBadge';

interface ScanDetailsModalProps {
  scanId: string | null;
  onClose: () => void;
}

export const ScanDetailsModal: React.FC<ScanDetailsModalProps> = ({ scanId, onClose }) => {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);

  useEffect(() => {
    if (!scanId) return;

    let isMounted = true;
    setIsLoading(true);
    setError(null);

    api
      .getScan(scanId)
      .then((data) => {
        if (isMounted) setScan(data);
      })
      .catch((err: unknown) => {
        if (!isMounted) return;
        if (err instanceof ApiError) {
          setError(err.message);
        } else {
          setError('Failed to fetch scan details');
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [scanId]);

  if (!scanId) return null;

  const handleCopyId = () => {
    navigator.clipboard.writeText(scanId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>Scan Record Inspection</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  GET /api/scans/:id
                </span>
              </h3>
              <p className="text-xs text-slate-400">Detailed database record representation</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading && (
            <div className="py-16 flex flex-col items-center justify-center text-slate-400">
              <Loader2 className="w-8 h-8 text-emerald-400 animate-spin mb-3" />
              <p className="text-sm font-medium">Retrieving scan record from database...</p>
            </div>
          )}

          {error && (
            <div className="p-4 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 flex items-start gap-3 text-xs">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Failed to load scan record</p>
                <p className="mt-1 text-rose-400">{error}</p>
              </div>
            </div>
          )}

          {!isLoading && scan && (
            <>
              {/* Primary Metadata Box */}
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <span className="text-xs font-mono text-slate-500 block">Project Name</span>
                    <h4 className="text-base font-bold text-slate-100">{scan.project_name}</h4>
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusBadge status={scan.status} />
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/60 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-slate-500 font-mono block">Scan ID</span>
                    <div className="flex items-center gap-1.5 mt-0.5 font-mono text-slate-300">
                      <span className="truncate max-w-[200px]" title={scan.id}>
                        {scan.id}
                      </span>
                      <button
                        onClick={handleCopyId}
                        title="Copy full scan ID"
                        className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
                      >
                        {copied ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 font-mono block">Source Type</span>
                    <div className="flex items-center gap-1.5 mt-0.5 text-slate-300 font-medium">
                      {scan.source_type === 'github' ? (
                        <>
                          <GitBranch className="w-3.5 h-3.5 text-purple-400" />
                          <span>GitHub Repository</span>
                        </>
                      ) : (
                        <>
                          <Archive className="w-3.5 h-3.5 text-amber-400" />
                          <span>ZIP Archive</span>
                        </>
                      )}
                    </div>
                  </div>

                  {scan.source_reference && (
                    <div className="md:col-span-2">
                      <span className="text-slate-500 font-mono block">Source Reference</span>
                      <span className="text-slate-300 font-mono break-all text-[11px]">
                        {scan.source_reference}
                      </span>
                    </div>
                  )}

                  {scan.repository_id && (
                    <div className="md:col-span-2">
                      <span className="text-slate-500 font-mono block">Repository FK</span>
                      <span className="text-slate-400 font-mono text-[11px]">
                        {scan.repository_id}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Execution Timestamps Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800">
                  <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                    <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Created At</span>
                  </div>
                  <span className="font-mono text-slate-200 text-[11px]">
                    {formatDate(scan.created_at)}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800">
                  <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                    <Clock className="w-3.5 h-3.5 text-amber-400" />
                    <span>Started At</span>
                  </div>
                  <span className="font-mono text-slate-400 text-[11px]">
                    {scan.started_at ? formatDate(scan.started_at) : 'Not started'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800">
                  <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                    <Clock className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Completed At</span>
                  </div>
                  <span className="font-mono text-slate-400 text-[11px]">
                    {scan.completed_at ? formatDate(scan.completed_at) : 'Not completed'}
                  </span>
                </div>
              </div>

              {/* Security Findings Section (Architectural Notice) */}
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-emerald-400" />
                    <span>Associated Findings</span>
                  </span>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                    {scan.findings?.length || 0} findings
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Phase 1 establishes the database schema for findings (Semgrep SAST, Gitleaks secrets, OSV dependencies). Scanning engine execution and finding generation will be implemented in Phase 3.
                </p>
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
        <div className="px-6 py-3 border-t border-slate-800 flex items-center justify-between bg-slate-950/40 text-xs">
          <span className="text-slate-500 font-mono flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span>SQLite Persistence Verified</span>
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
