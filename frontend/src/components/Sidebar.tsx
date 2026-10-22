import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Layers,
  FileText,
  Settings,
  AlertTriangle,
  Lock,
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onTabChange }) => {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard, implemented: true },
    { id: 'scans', label: 'Scans', icon: Layers, implemented: true },
    { id: 'findings', label: 'Findings', icon: AlertTriangle, implemented: false, phase: 'Phase 3' },
    { id: 'reports', label: 'Reports', icon: FileText, implemented: false, phase: 'Phase 4' },
    { id: 'settings', label: 'Settings', icon: Settings, implemented: false, phase: 'Phase 2' },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0 select-none">
      {/* Brand logo & wordmark */}
      <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-800">
        <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-lg text-slate-100 tracking-tight">VulnScope</span>
            <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              v0.1
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono">AppSec Analyzer</p>
        </div>
      </div>

      {/* Navigation list */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;

          if (item.implemented) {
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors text-left ${
                  isActive
                    ? 'bg-slate-800 text-emerald-400 shadow-sm border border-slate-700/60'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          }

          // Unimplemented items with explicit Phase badge
          return (
            <div
              key={item.id}
              title={`Coming in ${item.phase}: ${item.label} features will be enabled in future phases`}
              className="group flex items-center justify-between px-3 py-2.5 rounded-lg text-sm text-slate-500 cursor-not-allowed hover:bg-slate-800/20"
            >
              <div className="flex items-center gap-3">
                <Icon className="w-4 h-4 text-slate-600" />
                <span>{item.label}</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/50">
                {item.phase}
              </span>
            </div>
          );
        })}
      </nav>

      {/* System info badge in sidebar footer */}
      <div className="p-4 border-t border-slate-800/80">
        <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-400 space-y-1.5">
          <div className="flex items-center justify-between text-slate-300 font-medium">
            <span>Project Scope</span>
            <span className="text-[11px] text-emerald-400 font-mono">Phase 1</span>
          </div>
          <p className="text-[11px] leading-relaxed text-slate-400">
            Intelligent Application Security & Dependency Risk Analyzer foundation.
          </p>
          <div className="pt-1 flex items-center gap-1.5 text-[10px] text-slate-500 font-mono">
            <Lock className="w-3 h-3 text-emerald-400/80" />
            <span>SQLite • FastAPI • React</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
