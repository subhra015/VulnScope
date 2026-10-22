import React, { useState } from 'react';
import { PlusCircle, GitBranch, Archive, Info, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { api, ApiError } from '../services/api';
import { CreateScanPayload, SourceType } from '../types';

interface CreateScanFormProps {
  onScanCreated: () => void;
}

export const CreateScanForm: React.FC<CreateScanFormProps> = ({ onScanCreated }) => {
  const [projectName, setProjectName] = useState('');
  const [sourceType, setSourceType] = useState<SourceType>('github');
  const [sourceReference, setSourceReference] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Frontend validation
    const trimmedName = projectName.trim();
    if (!trimmedName) {
      setErrorMessage('Project or repository name is required.');
      return;
    }

    setErrorMessage(null);
    setSuccessMessage(null);
    setIsSubmitting(true);

    try {
      const payload: CreateScanPayload = {
        project_name: trimmedName,
        source_type: sourceType,
        source_reference: sourceReference.trim() || undefined,
      };

      const result = await api.createScan(payload);

      setSuccessMessage(`Scan record created successfully for "${result.project_name}" (ID: ${result.id.slice(0, 8)}...).`);
      setProjectName('');
      setSourceReference('');

      // Refresh recent scans table in parent
      onScanCreated();

      // Clear success message after 5 seconds
      setTimeout(() => {
        setSuccessMessage(null);
      }, 5000);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Failed to create scan record. Please check backend connection.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-slate-900/90 rounded-xl border border-slate-800 shadow-sm p-6">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <PlusCircle className="w-5 h-5 text-emerald-400" />
            <span>Create New Scan Record</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Register a repository or archive for vulnerability and risk evaluation.
          </p>
        </div>
      </div>

      {/* Mandatory Phase 1 architectural notice */}
      <div className="mb-5 p-3.5 rounded-lg bg-slate-950/70 border border-cyan-800/40 text-cyan-200/90 flex items-start gap-3 text-xs leading-relaxed">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-cyan-300">Phase 1 foundation:</span> this action creates a scan record only. Source acquisition and security scanning will be added in later phases.
        </div>
      </div>

      {/* Error alert banner */}
      {errorMessage && (
        <div className="mb-4 p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 flex items-start gap-2.5 text-xs">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">{errorMessage}</div>
        </div>
      )}

      {/* Success alert banner */}
      {successMessage && (
        <div className="mb-4 p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-300 flex items-start gap-2.5 text-xs">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div className="flex-1">{successMessage}</div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Project Name */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Project / Repository Name <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              disabled={isSubmitting}
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="e.g. auth-service or my-org/webapp"
              className="w-full px-3 py-2 bg-slate-950/80 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500 transition-colors disabled:opacity-50"
            />
          </div>

          {/* Source Type Selector */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Source Type <span className="text-rose-400">*</span>
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => setSourceType('github')}
                className={`flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-all ${
                  sourceType === 'github'
                    ? 'bg-emerald-500/10 border-emerald-500/60 text-emerald-300 shadow-sm'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                } disabled:opacity-50`}
              >
                <GitBranch className="w-3.5 h-3.5" />
                <span>GitHub</span>
              </button>
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => setSourceType('zip')}
                className={`flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-all ${
                  sourceType === 'zip'
                    ? 'bg-emerald-500/10 border-emerald-500/60 text-emerald-300 shadow-sm'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                } disabled:opacity-50`}
              >
                <Archive className="w-3.5 h-3.5" />
                <span>ZIP Archive</span>
              </button>
            </div>
          </div>
        </div>

        {/* Source Reference (Optional) */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            Source Reference <span className="text-slate-500 font-normal">(Optional metadata)</span>
          </label>
          <input
            type="text"
            disabled={isSubmitting}
            value={sourceReference}
            onChange={(e) => setSourceReference(e.target.value)}
            placeholder={
              sourceType === 'github'
                ? 'https://github.com/owner/repository'
                : 'filename.zip'
            }
            className="w-full px-3 py-2 bg-slate-950/80 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500 transition-colors disabled:opacity-50"
          />
          <p className="text-[11px] text-slate-500 mt-1">
            {sourceType === 'github'
              ? 'Non-sensitive GitHub repository URL or slug.'
              : 'Archive file descriptor name. (Actual file upload unlocks in Phase 2).'}
          </p>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Creating Scan Record...</span>
              </>
            ) : (
              <>
                <PlusCircle className="w-4 h-4" />
                <span>Create Scan Record</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
