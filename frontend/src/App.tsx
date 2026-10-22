import { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import { api } from './services/api';
import { HealthResponse, Scan } from './types';

export function App() {
  const [currentTab, setCurrentTab] = useState('overview');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);

  const [scans, setScans] = useState<Scan[]>([]);
  const [scansLoading, setScansLoading] = useState(true);
  const [scansError, setScansError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const checkHealth = useCallback(async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
      setHealthError(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Backend unreachable';
      setHealth(null);
      setHealthError(msg);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  const loadScans = useCallback(async () => {
    setScansLoading(true);
    setScansError(null);
    try {
      const data = await api.getScans();
      setScans(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load scans';
      setScansError(msg);
    } finally {
      setScansLoading(false);
    }
  }, []);

  const handleRefresh = useCallback(async () => {
    setIsRefreshing(true);
    await Promise.allSettled([checkHealth(), loadScans()]);
    setIsRefreshing(false);
  }, [checkHealth, loadScans]);

  useEffect(() => {
    checkHealth();
    loadScans();

    // Periodic health poll every 30 seconds
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, [checkHealth, loadScans]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100">
      {/* Fixed Left Sidebar */}
      <Sidebar currentTab={currentTab} onTabChange={setCurrentTab} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          health={health}
          healthLoading={healthLoading}
          healthError={healthError}
          onRefresh={handleRefresh}
          isRefreshing={isRefreshing}
        />

        <main className="flex-1 overflow-y-auto p-8">
          <div className="max-w-7xl mx-auto space-y-6">
            <Dashboard
              scans={scans}
              isLoading={scansLoading}
              error={scansError}
              onRefresh={loadScans}
            />
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
