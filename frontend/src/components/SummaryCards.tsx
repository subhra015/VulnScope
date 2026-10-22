import React from 'react';
import { Layers, CheckCircle2, ShieldAlert } from 'lucide-react';
import { Scan } from '../types';

interface SummaryCardsProps {
  scans: Scan[];
  isLoading: boolean;
}

export const SummaryCards: React.FC<SummaryCardsProps> = ({ scans, isLoading }) => {
  const totalScans = scans.length;
  const completedScans = scans.filter((s) => s.status.toLowerCase() === 'completed').length;
  // In Phase 1, scanner tools (Semgrep, Gitleaks, OSV) are not yet integrated,
  // so findings count is 0 based on real database records.
  const totalFindings = 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
      {/* Total Scan Records Card */}
      <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Total Scan Records
          </span>
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Layers className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-3xl font-bold font-mono text-slate-100">
            {isLoading ? '...' : totalScans}
          </span>
          <span className="text-xs text-slate-500">records in DB</span>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          Database records registered in SQLite storage.
        </p>
      </div>

      {/* Completed Scans Card */}
      <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Completed Scans
          </span>
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <CheckCircle2 className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-3xl font-bold font-mono text-slate-100">
            {isLoading ? '...' : completedScans}
          </span>
          <span className="text-xs text-slate-500">executed</span>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          Phase 1: scans initialize in <span className="text-cyan-400 font-mono">created</span> status.
        </p>
      </div>

      {/* Findings Card */}
      <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Security Findings
          </span>
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-3xl font-bold font-mono text-slate-100">
            {isLoading ? '...' : totalFindings}
          </span>
          <span className="text-xs text-slate-500">findings</span>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          Scanners (Semgrep, Gitleaks, OSV) activate in Phase 3.
        </p>
      </div>
    </div>
  );
};
