import React from 'react';
import { Layers, KeyRound, PackageSearch, Code2 } from 'lucide-react';
import { Scan } from '../types';

interface SummaryCardsProps {
  scans: Scan[];
  isLoading: boolean;
  activeScanSummary?: {
    total: number;
    code: number;
    secret: number;
    dependency: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    priority_critical?: number;
    priority_high?: number;
    priority_medium?: number;
    priority_low?: number;
  } | null;
}

export const SummaryCards: React.FC<SummaryCardsProps> = ({ scans, isLoading, activeScanSummary }) => {
  const totalScans = scans.length;
  const completedScans = scans.filter(
    (s) => s.status.toLowerCase() === 'completed' || s.status.toLowerCase() === 'partial'
  ).length;
  const runningScans = scans.filter((s) => s.status.toLowerCase() === 'running').length;

  const codeFindings = activeScanSummary ? activeScanSummary.code : 0;
  const secretFindings = activeScanSummary ? activeScanSummary.secret : 0;
  const depFindings = activeScanSummary ? activeScanSummary.dependency : 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Total Scans Card */}
      <div className="bg-slate-900/80 rounded-xl p-4 border border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Total Scans
          </span>
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Layers className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-slate-100">
            {isLoading ? '...' : totalScans}
          </span>
          <span className="text-xs text-slate-400">
            ({completedScans} completed{runningScans > 0 ? `, ${runningScans} running` : ''})
          </span>
        </div>
        <p className="mt-1 text-[11px] text-slate-500">
          Source repositories & archives ingested
        </p>
      </div>

      {/* Code Findings (Semgrep SAST) */}
      <div className="bg-slate-900/80 rounded-xl p-4 border border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Code SAST Issues
          </span>
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <Code2 className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-indigo-400">
            {isLoading ? '...' : codeFindings}
          </span>
          <span className="text-xs text-slate-400">Semgrep rules</span>
        </div>
        <p className="mt-1 text-[11px] text-slate-500">
          Static analysis security defects
        </p>
      </div>

      {/* Secret Findings (Gitleaks) */}
      <div className="bg-slate-900/80 rounded-xl p-4 border border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Exposed Secrets
          </span>
          <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <KeyRound className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-rose-400">
            {isLoading ? '...' : secretFindings}
          </span>
          <span className="text-xs text-slate-400">credentials</span>
        </div>
        <p className="mt-1 text-[11px] text-slate-500">
          Gitleaks secret detection results
        </p>
      </div>

      {/* Dependency Vulnerabilities (OSV) */}
      <div className="bg-slate-900/80 rounded-xl p-4 border border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Dependency CVEs
          </span>
          <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <PackageSearch className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-purple-400">
            {isLoading ? '...' : depFindings}
          </span>
          <span className="text-xs text-slate-400">SCA advisories</span>
        </div>
        <p className="mt-1 text-[11px] text-slate-500">
          OSV-Scanner known CVEs & fixes
        </p>
      </div>

      {/* Priority Distribution Banner if active scan summary is present */}
      {activeScanSummary && (
        <div className="col-span-1 sm:col-span-2 lg:col-span-4 bg-slate-900/60 rounded-xl p-3 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200">Latest Scan Risk Priorities:</span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800 font-mono font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
              Critical: {activeScanSummary.priority_critical ?? 0}
            </span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-orange-950/80 text-orange-300 border border-orange-800 font-mono font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-orange-400"></span>
              High: {activeScanSummary.priority_high ?? 0}
            </span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800 font-mono font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
              Medium: {activeScanSummary.priority_medium ?? 0}
            </span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-sky-950/80 text-sky-300 border border-sky-800 font-mono font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
              Low: {activeScanSummary.priority_low ?? 0}
            </span>
          </div>

          <span className="text-[11px] text-slate-500 italic">
            Deterministic prioritization &bull; Not a guarantee of production exploitability
          </span>
        </div>
      )}
    </div>
  );
};
