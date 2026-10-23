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
    </div>
  );
};
