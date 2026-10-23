import React, { useState, useEffect, useRef } from 'react';
import { SummaryCards } from '../components/SummaryCards';
import { CreateScanForm } from '../components/CreateScanForm';
import { ScansTable } from '../components/ScansTable';
import { ScanDetailsModal } from '../components/ScanDetailsModal';
import { Scan } from '../types';
import { api } from '../services/api';

interface DashboardProps {
  scans: Scan[];
  isLoading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  scans,
  isLoading,
  error,
  onRefresh,
}) => {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [scanSummary, setScanSummary] = useState<{
    total: number;
    code: number;
    secret: number;
    dependency: number;
  } | null>(null);

  // If any scan is currently running in the list, auto-refresh every 3s
  const hasRunningScan = scans.some((s) => s.status.toLowerCase() === 'running');
  const refreshTimerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (hasRunningScan) {
      refreshTimerRef.current = setInterval(() => {
        onRefresh();
      }, 3000);
    } else {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    }
    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
  }, [hasRunningScan, onRefresh]);

  // Fetch summary for latest completed scan if available
  useEffect(() => {
    const latestFinished = scans.find(
      (s) => s.status.toLowerCase() === 'completed' || s.status.toLowerCase() === 'partial'
    );
    if (latestFinished) {
      api.getScan(latestFinished.id).then((detail) => {
        if (detail.findings_summary) {
          setScanSummary(detail.findings_summary);
        } else if (detail.findings) {
          setScanSummary({
            total: detail.findings.length,
            code: detail.findings.filter((f) => (f.category || 'code') === 'code').length,
            secret: detail.findings.filter((f) => f.category === 'secret').length,
            dependency: detail.findings.filter((f) => f.category === 'dependency').length,
          });
        }
      }).catch(() => {});
    } else {
      setScanSummary(null);
    }
  }, [scans]);

  const handleRunScan = async (scanId: string) => {
    try {
      await api.runScan(scanId);
      onRefresh();
    } catch (err) {
      console.error('Failed to trigger scan:', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Metrics Summary Cards */}
      <SummaryCards
        scans={scans}
        isLoading={isLoading}
        activeScanSummary={scanSummary}
      />

      {/* Main Grid: Scan Creation Form & Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Column: Create Scan Form */}
        <div className="lg:col-span-1">
          <CreateScanForm onScanCreated={onRefresh} />
        </div>

        {/* Right Column: Recent Scans Audit Table */}
        <div className="lg:col-span-2">
          <ScansTable
            scans={scans}
            isLoading={isLoading}
            error={error}
            onSelectScan={(id) => setSelectedScanId(id)}
            onRunScan={handleRunScan}
            onRetry={onRefresh}
          />
        </div>
      </div>

      {/* Scan Details Inspection Modal */}
      <ScanDetailsModal
        scanId={selectedScanId}
        onClose={() => setSelectedScanId(null)}
        onScanUpdated={onRefresh}
      />
    </div>
  );
};
