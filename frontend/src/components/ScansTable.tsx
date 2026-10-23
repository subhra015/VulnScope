import React, { useState } from 'react';
import {
  GitBranch,
  Archive,
  ExternalLink,
  Shield,
  Clock,
  Layers,
  AlertTriangle,
  FolderGit2,
  Play,
  Loader2,
} from 'lucide-react';
import { Scan } from '../types';
import { StatusBadge, IntakeStatusBadge } from './StatusBadge';

interface ScansTableProps {
  scans: Scan[];
  isLoading: boolean;
  error: string | null;
  onSelectScan: (scanId: string) => void;
  onRunScan?: (scanId: string) => Promise<void> | void;
  onRetry: () => void;
}

export const ScansTable: React.FC<ScansTableProps> = ({
  scans,
  isLoading,
  error,
  onSelectScan,
  onRunScan,
  onRetry,
}) => {
  const [triggeringScanId, setTriggeringScanId] = useState<string | null>(null);

  const formatDate = (isoString: string) => {
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

  const handleRunClick = async (e: React.MouseEvent, scanId: string) => {
    e.stopPropagation();
    if (!onRunScan || triggeringScanId) return;
    try {
      setTriggeringScanId(scanId);
      await onRunScan(scanId);
    } finally {
      setTriggeringScanId(null);
    }
  };

  return (
    <div className="bg-slate-900/90 rounded-xl border border-slate-800 shadow-sm overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            <span>Recent Scans</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit history of registered security scans, intake lifecycle, and scanning actions.
          </p>
        </div>
        <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
          {scans.length} {scans.length === 1 ? 'record' : 'records'}
        </span>
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="py-16 flex flex-col items-center justify-center text-slate-400">
          <Clock className="w-8 h-8 text-emerald-400 animate-spin mb-3" />
          <p className="text-sm font-medium">Loading scan records from database...</p>
        </div>
      )}

      {/* Error state */}
      {!isLoading && error && (
        <div className="p-8 text-center">
          <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center mx-auto mb-3">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-semibold text-slate-200">Failed to load scan records</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 mb-4">{error}</p>
          <button
            onClick={onRetry}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !error && scans.length === 0 && (
        <div className="py-16 px-6 text-center">
          <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700/80 text-slate-400 flex items-center justify-center mx-auto mb-3.5 shadow-inner">
            <Shield className="w-6 h-6 text-emerald-400/70" />
          </div>
          <h3 className="text-sm font-semibold text-slate-200">No scan records recorded yet</h3>
          <p className="text-xs text-slate-400 max-w-sm mx-auto mt-1 leading-relaxed">
            Acquire a GitHub repository or upload a ZIP archive using the intake form. Once source is ready, run Semgrep, Gitleaks, and OSV-Scanner analysis.
          </p>
        </div>
      )}

      {/* Table view */}
      {!isLoading && !error && scans.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono tracking-wider border-b border-slate-800 text-[11px]">
              <tr>
                <th className="py-3 px-6">Project Name</th>
                <th className="py-3 px-6">Source Type</th>
                <th className="py-3 px-6">Source Intake</th>
                <th className="py-3 px-6">Security Scan</th>
                <th className="py-3 px-6">Created At (UTC)</th>
                <th className="py-3 px-6 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scans.map((scan) => {
                const canRun = scan.intake_status === 'ready' && scan.status !== 'running';
                const isRunning = scan.status === 'running' || triggeringScanId === scan.id;

                return (
                  <tr
                    key={scan.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectScan(scan.id)}
                  >
                    {/* Project Name */}
                    <td className="py-3.5 px-6 font-medium text-slate-200">
                      <div className="flex items-center gap-2.5">
                        <FolderGit2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        <div>
                          <span className="font-semibold block">{scan.project_name}</span>
                          <span className="text-[10px] font-mono text-slate-500">{scan.id.slice(0, 8)}...</span>
                        </div>
                      </div>
                    </td>

                    {/* Source Type Badge */}
                    <td className="py-3.5 px-6">
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
                        {scan.source_type === 'github' ? (
                          <>
                            <GitBranch className="w-3 h-3 text-purple-400" />
                            <span>GitHub</span>
                          </>
                        ) : (
                          <>
                            <Archive className="w-3 h-3 text-amber-400" />
                            <span>ZIP</span>
                          </>
                        )}
                      </span>
                    </td>

                    {/* Intake Status Badge */}
                    <td className="py-3.5 px-6">
                      <IntakeStatusBadge status={scan.intake_status || 'created'} />
                    </td>

                    {/* Scan Status Badge */}
                    <td className="py-3.5 px-6">
                      <StatusBadge status={scan.status} />
                    </td>

                    {/* Creation Timestamp */}
                    <td className="py-3.5 px-6 text-slate-400 font-mono text-[11px]">
                      {formatDate(scan.created_at)}
                    </td>

                    {/* Action */}
                    <td className="py-3.5 px-6 text-right space-x-2">
                      {canRun && onRunScan && (
                        <button
                          type="button"
                          onClick={(e) => handleRunClick(e, scan.id)}
                          disabled={isRunning}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-[11px] transition-all shadow-sm disabled:opacity-50"
                          title="Run Semgrep, Gitleaks, and OSV-Scanner"
                        >
                          <Play className="w-3 h-3 fill-current" />
                          <span>{scan.status === 'created' ? 'Run Scan' : 'Re-scan'}</span>
                        </button>
                      )}

                      {isRunning && (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950/60 text-amber-300 border border-amber-800 text-[11px] font-mono">
                          <Loader2 className="w-3 h-3 animate-spin text-amber-400" />
                          <span>Scanning...</span>
                        </span>
                      )}

                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectScan(scan.id);
                        }}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-600/20 hover:text-emerald-300 text-slate-300 border border-slate-700 hover:border-emerald-500/40 font-medium transition-all"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
