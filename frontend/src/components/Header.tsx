import React from 'react';
import { RefreshCw, Server, AlertCircle } from 'lucide-react';
import { HealthResponse } from '../types';

interface HeaderProps {
  health: HealthResponse | null;
  healthLoading: boolean;
  healthError: string | null;
  onRefresh: () => void;
  isRefreshing: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  healthLoading,
  healthError,
  onRefresh,
  isRefreshing,
}) => {
  const isHealthy = health?.status === 'healthy';

  return (
    <header className="h-16 bg-slate-900/60 backdrop-blur border-b border-slate-800 px-8 flex items-center justify-between sticky top-0 z-10">
      <div>
        <h1 className="text-lg font-semibold text-slate-100 flex items-center gap-2.5">
          <span>Security & Risk Dashboard</span>
          <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            Phase 1 Foundation
          </span>
        </h1>
        <p className="text-xs text-slate-400">
          Intelligent Application Security and Dependency Risk Analyzer
        </p>
      </div>

      <div className="flex items-center gap-4">
        {/* Backend Connectivity Status Indicator */}
        <div
          title={
            health
              ? `Backend Status: ${health.status} | Version: ${health.version} | Database: ${health.database}`
              : healthError || 'Connecting to backend...'
          }
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
            healthLoading
              ? 'bg-slate-800/60 border-slate-700 text-slate-400'
              : isHealthy
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
              : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
          }`}
        >
          {healthLoading ? (
            <Server className="w-3.5 h-3.5 animate-pulse text-slate-400" />
          ) : isHealthy ? (
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
          ) : (
            <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
          )}

          <span>
            {healthLoading
              ? 'Checking backend...'
              : isHealthy
              ? `API Online (v${health.version})`
              : 'Backend Offline'}
          </span>
        </div>

        {/* Manual Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Refresh dashboard data"
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700/80 text-slate-300 hover:text-slate-100 border border-slate-700/60 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-emerald-400' : ''}`} />
        </button>
      </div>
    </header>
  );
};
