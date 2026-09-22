import React, { useState, useEffect } from 'react';
import { Activity, Shield, Database, Terminal, Wifi, Cpu, HardDrive, Server } from 'lucide-react';
import { metricsService, threatsService, skillsService } from '../services/api';
import useWebSocket from '../hooks/useWebSocket';
import MetricCard from '../components/MetricCard';
import MetricsChart from '../components/MetricsChart';
import ThreatTable from '../components/ThreatTable';

const App = () => {
  const [metrics, setMetrics] = useState(null);
  const [metricsHistory, setMetricsHistory] = useState([]);
  const [threats, setThreats] = useState([]);
  const [threatStats, setThreatStats] = useState(null);
  const [skills, setSkills] = useState(null);
  const [loading, setLoading] = useState(true);

  // WebSocket for real-time metrics
  const { isConnected, lastMessage } = useWebSocket(`ws://${window.location.hostname}:8000/ws/metrics`);

  // Update metrics from WebSocket
  useEffect(() => {
    if (lastMessage) {
      setMetrics(lastMessage);
      setMetricsHistory(prev => [...prev.slice(-49), lastMessage]);
    }
  }, [lastMessage]);

  // Fetch initial data
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        const [metricsData, threatsData, threatStatsData, skillsData] = await Promise.all([
          metricsService.getCurrent().catch(() => null),
          threatsService.getRecent(10).catch(() => []),
          threatsService.getStats().catch(() => null),
          skillsService.getStats().catch(() => null),
        ]);

        if (metricsData) {
          setMetrics(metricsData);
          setMetricsHistory([metricsData]);
        }
        setThreats(threatsData);
        setThreatStats(threatStatsData);
        setSkills(skillsData);
      } catch (error) {
        console.error('Failed to fetch initial data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchInitialData();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-dark-bg grid-bg flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-16 h-16 text-cyber-400 mx-auto mb-4 animate-pulse" />
          <p className="text-cyber-400 font-mono">Initializing Security Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dark-bg grid-bg">
      {/* Header */}
      <header className="border-b border-dark-border bg-dark-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyber-500/20 rounded-lg cyber-glow">
                <Shield className="w-8 h-8 text-cyber-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">AI Security Intelligence Dashboard</h1>
                <p className="text-gray-500 text-sm">Real-time System Monitoring & Threat Detection</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full ${isConnected ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                <Wifi className="w-4 h-4" />
                <span className="text-sm font-medium">{isConnected ? 'Live' : 'Disconnected'}</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Metrics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <MetricCard
            title="CPU Usage"
            value={metrics ? `${metrics.cpu_percent}%` : '--'}
            unit="percent"
            icon={Cpu}
            color="bg-blue-500"
          />
          <MetricCard
            title="Memory Usage"
            value={metrics ? `${metrics.memory_percent}%` : '--'}
            unit="percent"
            icon={Server}
            color="bg-purple-500"
          />
          <MetricCard
            title="Disk Usage"
            value={metrics ? `${metrics.disk_percent}%` : '--'}
            unit="percent"
            icon={HardDrive}
            color="bg-orange-500"
          />
          <MetricCard
            title="Processes"
            value={metrics ? metrics.process_count : '--'}
            unit="running"
            icon={Terminal}
            color="bg-green-500"
          />
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <MetricsChart
            data={metricsHistory}
            dataKey="cpu_percent"
            color="#0ea5e9"
            title="CPU Usage Over Time"
          />
          <MetricsChart
            data={metricsHistory}
            dataKey="memory_percent"
            color="#a855f7"
            title="Memory Usage Over Time"
          />
        </div>

        {/* Threat Stats */}
        {threatStats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="bg-dark-card border border-dark-border rounded-xl p-4 text-center">
              <p className="text-gray-400 text-sm">Total Threats</p>
              <p className="text-2xl font-bold text-white mt-1">{threatStats.total || 0}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-xl p-4 text-center">
              <p className="text-gray-400 text-sm">Critical</p>
              <p className="text-2xl font-bold text-red-400 mt-1">{threatStats.by_severity?.CRITICAL || 0}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-xl p-4 text-center">
              <p className="text-gray-400 text-sm">High</p>
              <p className="text-2xl font-bold text-orange-400 mt-1">{threatStats.by_severity?.HIGH || 0}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-xl p-4 text-center">
              <p className="text-gray-400 text-sm">CVEs Tracked</p>
              <p className="text-2xl font-bold text-cyber-400 mt-1">{threatStats.cve_count || 0}</p>
            </div>
          </div>
        )}

        {/* Threat Table */}
        <div className="mb-8">
          <ThreatTable threats={threats} />
        </div>

        {/* Skills Section */}
        {skills && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-6 cyber-border">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 mb-4">
              <Database className="w-5 h-5 text-cyber-400" />
              Skill Repository
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-dark-bg rounded-lg">
                <p className="text-2xl font-bold text-cyber-400">{skills.total || 0}</p>
                <p className="text-gray-500 text-sm">Total Skills</p>
              </div>
              {Object.entries(skills.by_category || {}).map(([category, count]) => (
                <div key={category} className="text-center p-4 bg-dark-bg rounded-lg">
                  <p className="text-2xl font-bold text-purple-400">{count}</p>
                  <p className="text-gray-500 text-sm capitalize">{category}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-dark-border mt-8 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-gray-500 text-sm">
          <p>AI Security Intelligence Dashboard v1.0.0 | Real-time monitoring powered by FastAPI & React</p>
        </div>
      </footer>
    </div>
  );
};

export default App;
