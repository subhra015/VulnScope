import React, { useState } from 'react';
import { SummaryCards } from '../components/SummaryCards';
import { CreateScanForm } from '../components/CreateScanForm';
import { ScansTable } from '../components/ScansTable';
import { ScanDetailsModal } from '../components/ScanDetailsModal';
import { Scan } from '../types';

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

  return (
    <div className="space-y-6">
      {/* Metrics Summary Cards */}
      <SummaryCards scans={scans} isLoading={isLoading} />

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
            onRetry={onRefresh}
          />
        </div>
      </div>

      {/* Scan Details Inspection Modal */}
      <ScanDetailsModal
        scanId={selectedScanId}
        onClose={() => setSelectedScanId(null)}
      />
    </div>
  );
};
