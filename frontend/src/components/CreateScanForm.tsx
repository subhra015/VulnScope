import React, { useState, useRef } from 'react';
import {
  GitBranch,
  Archive,
  Info,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Upload,
  FileCheck,
  ShieldCheck,
} from 'lucide-react';
import { api, ApiError } from '../services/api';
import { SourceType } from '../types';

interface CreateScanFormProps {
  onScanCreated: () => void;
}

export const CreateScanForm: React.FC<CreateScanFormProps> = ({ onScanCreated }) => {
  const [sourceType, setSourceType] = useState<SourceType>('github');
  const [projectName, setProjectName] = useState('');
  
  // GitHub state
  const [githubUrl, setGithubUrl] = useState('');
  const [gitRef, setGitRef] = useState('');

  // ZIP state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      if (!file.name.toLowerCase().endsWith('.zip')) {
        setErrorMessage('Only ZIP archive files (.zip) are supported.');
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (sourceType === 'github') {
      const trimmedUrl = githubUrl.trim();
      if (!trimmedUrl) {
        setErrorMessage('GitHub repository URL is required.');
        return;
      }
      if (!trimmedUrl.startsWith('https://')) {
        setErrorMessage('Only secure HTTPS GitHub repository URLs are supported (e.g. https://github.com/owner/repo).');
        return;
      }

      setIsSubmitting(true);
      try {
        const result = await api.intakeGithub({
          repo_url: trimmedUrl,
          project_name: projectName.trim() || undefined,
          ref: gitRef.trim() || undefined,
        });

        setSuccessMessage(
          `Repository "${result.project_name}" acquired & validated successfully! Source is ready in an isolated workspace (ID: ${result.id.slice(0, 8)}...). Security scanning is pending.`
        );
        setGithubUrl('');
        setGitRef('');
        setProjectName('');
        onScanCreated();
      } catch (err: unknown) {
        if (err instanceof ApiError) {
          setErrorMessage(err.message);
        } else {
          setErrorMessage('Failed to acquire GitHub repository. Please verify connectivity.');
        }
      } finally {
        setIsSubmitting(false);
      }
    } else {
      // ZIP Intake
      if (!selectedFile) {
        setErrorMessage('Please select a ZIP archive file to upload.');
        return;
      }

      setIsSubmitting(true);
      try {
        const result = await api.intakeZip(selectedFile, projectName.trim() || undefined);

        setSuccessMessage(
          `Archive "${result.project_name}" uploaded & validated successfully! (Status: Source ready, Scan ID: ${result.id.slice(0, 8)}...). Security scanning is pending.`
        );
        setSelectedFile(null);
        setProjectName('');
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
        onScanCreated();
      } catch (err: unknown) {
        if (err instanceof ApiError) {
          setErrorMessage(err.message);
        } else {
          setErrorMessage('Failed to upload and validate ZIP archive.');
        }
      } finally {
        setIsSubmitting(false);
      }
    }
  };

  return (
    <div className="bg-slate-900/90 rounded-xl border border-slate-800 shadow-sm p-6">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>Secure Source Intake</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Acquire and validate source code into an isolated sandbox environment.
          </p>
        </div>
      </div>

      {/* Mandatory Phase 2 architectural notice */}
      <div className="mb-5 p-3.5 rounded-lg bg-slate-950/70 border border-cyan-800/40 text-cyan-200/90 flex items-start gap-3 text-xs leading-relaxed">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-cyan-300">Phase 2 secure intake:</span> source code is validated against path traversal, zip bombs, and SSRF before extraction into an isolated workspace. No submitted code is executed, and security scanning (Phase 3) has not yet occurred.
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
        {/* Source Type Selector Tabs */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            Source Intake Method <span className="text-rose-400">*</span>
          </label>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              disabled={isSubmitting}
              onClick={() => {
                setSourceType('github');
                setErrorMessage(null);
              }}
              className={`flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg text-xs font-medium border transition-all ${
                sourceType === 'github'
                  ? 'bg-emerald-500/10 border-emerald-500/60 text-emerald-300 shadow-sm'
                  : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              } disabled:opacity-50`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>GitHub Repository</span>
            </button>
            <button
              type="button"
              disabled={isSubmitting}
              onClick={() => {
                setSourceType('zip');
                setErrorMessage(null);
              }}
              className={`flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg text-xs font-medium border transition-all ${
                sourceType === 'zip'
                  ? 'bg-emerald-500/10 border-emerald-500/60 text-emerald-300 shadow-sm'
                  : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              } disabled:opacity-50`}
            >
              <Archive className="w-3.5 h-3.5" />
              <span>ZIP Archive Upload</span>
            </button>
          </div>
        </div>

        {/* Project Name (Optional for both) */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            Project Name <span className="text-slate-500 font-normal">(Optional — defaults to repo or archive name)</span>
          </label>
          <input
            type="text"
            disabled={isSubmitting}
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            placeholder={sourceType === 'github' ? 'e.g. auth-service' : 'e.g. backend-api'}
            className="w-full px-3 py-2 bg-slate-950/80 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500 transition-colors disabled:opacity-50"
          />
        </div>

        {/* GitHub Specific Fields */}
        {sourceType === 'github' && (
          <div className="space-y-3 pt-1">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                GitHub Repository URL <span className="text-rose-400">*</span>
              </label>
              <input
                type="url"
                required
                disabled={isSubmitting}
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                className="w-full px-3 py-2 bg-slate-950/80 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500 transition-colors disabled:opacity-50"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Public HTTPS repository URL only. Server applies SSRF protection and bounded acquisition.
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Branch, Tag, or Commit SHA <span className="text-slate-500 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                disabled={isSubmitting}
                value={gitRef}
                onChange={(e) => setGitRef(e.target.value)}
                placeholder="e.g. main, v1.0.0, or 7db19cc"
                className="w-full px-3 py-2 bg-slate-950/80 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500 transition-colors disabled:opacity-50"
              />
            </div>
          </div>
        )}

        {/* ZIP Upload Specific Fields */}
        {sourceType === 'zip' && (
          <div className="space-y-3 pt-1">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                ZIP Archive File <span className="text-rose-400">*</span>
              </label>
              <div className="border-2 border-dashed border-slate-700 hover:border-emerald-500/60 rounded-lg p-4 text-center bg-slate-950/50 transition-colors cursor-pointer"
                   onClick={() => fileInputRef.current?.click()}>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  disabled={isSubmitting}
                  onChange={handleFileChange}
                  className="hidden"
                />
                {selectedFile ? (
                  <div className="flex items-center justify-center gap-2 text-emerald-400 text-xs">
                    <FileCheck className="w-5 h-5 shrink-0" />
                    <div className="text-left overflow-hidden">
                      <p className="font-semibold truncate">{selectedFile.name}</p>
                      <p className="text-[10px] text-slate-400">
                        {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Ready for validation
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center gap-1.5 text-slate-400 text-xs">
                    <Upload className="w-5 h-5 text-slate-500 mb-0.5" />
                    <span className="font-medium text-slate-300">Click to select ZIP archive</span>
                    <span className="text-[11px] text-slate-500">Max upload: 50 MB compressed</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        <div className="pt-3 flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>
                  {sourceType === 'github' ? 'Acquiring Repository Snapshot...' : 'Validating & Extracting Archive...'}
                </span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>
                  {sourceType === 'github' ? 'Acquire & Ingest Repository' : 'Upload & Ingest Archive'}
                </span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
