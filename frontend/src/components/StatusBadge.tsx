import React from 'react';
import { ScanStatus, ScannerStatus } from '../types';
import { AlertTriangle, CheckCircle, Clock, XCircle, Slash } from 'lucide-react';

interface StatusBadgeProps {
  status: ScanStatus | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const normalized = status.toLowerCase();

  switch (normalized) {
    case 'created':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
          scan pending
        </span>
      );
    case 'queued':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-950/70 text-blue-300 border border-blue-800/60 animate-pulse">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
          queued
        </span>
      );
    case 'running':
    case 'scanning':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-950/70 text-amber-300 border border-amber-800/60 animate-pulse">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          scanning...
        </span>
      );
    case 'completed':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950/70 text-emerald-300 border border-emerald-800/60">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          completed
        </span>
      );
    case 'partial':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-950/70 text-amber-300 border border-amber-800/60">
          <AlertTriangle className="w-3 h-3 text-amber-400" />
          partial scan
        </span>
      );
    case 'failed':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-950/70 text-rose-300 border border-rose-800/60">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
          failed
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
          {status}
        </span>
      );
  }
};

interface IntakeStatusBadgeProps {
  status?: string | null;
}

export const IntakeStatusBadge: React.FC<IntakeStatusBadgeProps> = ({ status }) => {
  if (!status) return null;
  const normalized = status.toLowerCase();

  switch (normalized) {
    case 'ready':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950/70 text-emerald-300 border border-emerald-800/60">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          source ready
        </span>
      );
    case 'ingesting':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-950/70 text-amber-300 border border-amber-800/60 animate-pulse">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          ingesting...
        </span>
      );
    case 'failed':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-950/70 text-rose-300 border border-rose-800/60">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
          intake failed
        </span>
      );
    case 'created':
    default:
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-cyan-950/70 text-cyan-300 border border-cyan-800/60">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
          intake created
        </span>
      );
  }
};

interface ScannerStatusBadgeProps {
  status: ScannerStatus | string;
}

export const ScannerStatusBadge: React.FC<ScannerStatusBadgeProps> = ({ status }) => {
  const norm = status.toLowerCase();
  switch (norm) {
    case 'completed':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-950/70 text-emerald-300 border border-emerald-800/60">
          <CheckCircle className="w-3 h-3 text-emerald-400" />
          <span>completed</span>
        </span>
      );
    case 'failed':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-rose-950/70 text-rose-300 border border-rose-800/60">
          <XCircle className="w-3 h-3 text-rose-400" />
          <span>failed</span>
        </span>
      );
    case 'unavailable':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-400 border border-slate-700">
          <Slash className="w-3 h-3 text-slate-500" />
          <span>unavailable</span>
        </span>
      );
    case 'timed_out':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-950/70 text-amber-300 border border-amber-800/60">
          <Clock className="w-3 h-3 text-amber-400" />
          <span>timed out</span>
        </span>
      );
    case 'running':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-950/70 text-amber-300 border border-amber-800/60 animate-pulse">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          <span>running...</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-400 border border-slate-700">
          <span>{status}</span>
        </span>
      );
  }
};

interface SeverityBadgeProps {
  severity: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const norm = severity.toLowerCase();
  switch (norm) {
    case 'critical':
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-950/80 text-rose-300 border border-rose-800/80">
          Critical
        </span>
      );
    case 'high':
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-orange-950/80 text-orange-300 border border-orange-800/80">
          High
        </span>
      );
    case 'medium':
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-950/80 text-amber-300 border border-amber-800/80">
          Medium
        </span>
      );
    case 'low':
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-sky-950/80 text-sky-300 border border-sky-800/80">
          Low
        </span>
      );
    case 'info':
    default:
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-800 text-slate-400 border border-slate-700">
          {severity}
        </span>
      );
  }
};

interface CategoryBadgeProps {
  category?: string | null;
}

export const CategoryBadge: React.FC<CategoryBadgeProps> = ({ category }) => {
  const norm = (category || 'code').toLowerCase();
  switch (norm) {
    case 'code':
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-indigo-950/70 text-indigo-300 border border-indigo-800/60">
          SAST Code
        </span>
      );
    case 'secret':
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-red-950/70 text-red-300 border border-red-800/60">
          Secret
        </span>
      );
    case 'dependency':
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-purple-950/70 text-purple-300 border border-purple-800/60">
          SCA Dep
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
          {category}
        </span>
      );
  }
};

interface PriorityBadgeProps {
  priority?: string | null;
  score?: number | null;
  showScore?: boolean;
}

export const PriorityBadge: React.FC<PriorityBadgeProps> = ({ priority, score, showScore = true }) => {
  const norm = (priority || 'medium').toLowerCase();
  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  let label = 'Low Priority';

  if (norm === 'critical') {
    colorClasses = 'bg-red-950/90 text-red-300 border-red-700 shadow-sm shadow-red-950/50';
    label = 'Critical Priority';
  } else if (norm === 'high') {
    colorClasses = 'bg-orange-950/90 text-orange-300 border-orange-700';
    label = 'High Priority';
  } else if (norm === 'medium') {
    colorClasses = 'bg-amber-950/80 text-amber-300 border-amber-700';
    label = 'Medium Priority';
  } else if (norm === 'low') {
    colorClasses = 'bg-slate-900 text-sky-300 border-sky-800/70';
    label = 'Low Priority';
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${colorClasses}`}
      title={`VulnScope Deterministic Risk Priority: ${label}${score !== undefined && score !== null ? ` (Score: ${score}/100)` : ''}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80"></span>
      <span>{norm}</span>
      {showScore && score !== undefined && score !== null && (
        <span className="ml-0.5 px-1 py-px rounded bg-black/40 font-mono text-[9px] font-semibold text-slate-100">
          {score}
        </span>
      )}
    </span>
  );
};

interface LifecycleBadgeProps {
  status?: string | null;
}

export const LifecycleBadge: React.FC<LifecycleBadgeProps> = ({ status }) => {
  const norm = (status || 'new').toLowerCase();
  switch (norm) {
    case 'new':
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          new
        </span>
      );
    case 'recurring':
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950/70 text-amber-300 border border-amber-800/60">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          recurring
        </span>
      );
    case 'resolved':
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-950/80 text-blue-300 border border-blue-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
          resolved
        </span>
      );
    case 'changed':
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-purple-950/80 text-purple-300 border border-purple-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
          changed
        </span>
      );
    case 'unconfirmed':
      return (
        <span
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-900 text-slate-400 border border-slate-700"
          title="Scanner was unavailable or failed; resolution unverified"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
          unconfirmed
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-900 text-slate-400 border border-slate-800">
          {status}
        </span>
      );
  }
};

interface ProposalStatusBadgeProps {
  status?: string | null;
}

export const ProposalStatusBadge: React.FC<ProposalStatusBadgeProps> = ({ status }) => {
  if (!status) return null;
  const normalized = status.toLowerCase();

  switch (normalized) {
    case 'proposed':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-950/70 text-amber-300 border border-amber-800/60">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          Proposed Fix
        </span>
      );
    case 'reviewed':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-950/80 text-blue-300 border border-blue-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
          Reviewed
        </span>
      );
    case 'rejected':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
          Rejected
        </span>
      );
    case 'downloaded':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-cyan-950/80 text-cyan-300 border border-cyan-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
          Downloaded
        </span>
      );
    case 'validation_failed':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-rose-950/80 text-rose-300 border border-rose-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
          Validation Failed
        </span>
      );
    case 'verification_pending':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-purple-950/80 text-purple-300 border border-purple-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
          Pending Rescan
        </span>
      );
    case 'verified_by_rescan':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-950/80 text-emerald-300 border border-emerald-800/70">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          Verified by Rescan
        </span>
      );
    case 'unconfirmed':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-900 text-slate-400 border border-slate-800">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
          Unconfirmed
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-900 text-slate-400 border border-slate-800">
          {status}
        </span>
      );
  }
};
