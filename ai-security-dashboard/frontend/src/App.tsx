import React, { useState, useEffect, useCallback } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { 
  Activity, 
  Shield, 
  Cpu, 
  MemoryStick, 
  Network, 
  HardDrive, 
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Terminal,
  Server
} from 'lucide-react';

// Types
interface SystemMetrics {
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  memory_used_gb: number;
  memory_total_gb: number;
  network_sent_mb: number;
  network_recv_mb: number;
  disk_usage_percent: number;
  process_count: number;
}

interface ThreatAlert {
  id: number;
  title: string;
  source: string;
  severity: string;
  description: string;
  url: string;
  published_date: string;
  detected_at: string;
}

interface MCPToolResult {
  success: boolean;
  tool: string;
  timestamp: string;
  data: any;
}

// API Base URL
const API_BASE = 'http://localhost:8000';

function App() {
  // State
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [metricsHistory, setMetricsHistory] = useState<SystemMetrics[]>([]);
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [mcpResults, setMcpResults] = useState<MCPToolResult | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'threats' | 'tools'>('dashboard');

  // WebSocket connection for real-time metrics
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connectWebSocket = () => {
      try {
        ws = new WebSocket(`ws://${window.location.hostname}:8000/ws/metrics`);
        
        ws.onopen = () => {
          console.log('WebSocket connected');
          setIsConnected(true);
          setLoading(false);
        };

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            if (message.type === 'metrics' && message.data) {
              setMetrics(message.data);
              setMetricsHistory(prev => {
                const updated = [...prev, message.data];
                return updated.slice(-50); // Keep last 50 data points
              });
            }
          } catch (e) {
            console.error('Error parsing WebSocket message:', e);
          }
        };

        ws.onclose = () => {
          console.log('WebSocket disconnected, reconnecting...');
          setIsConnected(false);
          reconnectTimeout = setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
        };
      } catch (e) {
        console.error('Failed to connect WebSocket:', e);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      }
    };

    connectWebSocket();

    return () => {
      if (ws) ws.close();
      clearTimeout(reconnectTimeout);
    };
  }, []);

  // Fetch initial threats
  useEffect(() => {
    fetchThreats();
  }, []);

  const fetchThreats = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/threats`);
      if (response.ok) {
        const data = await response.json();
        setThreats(data);
      }
    } catch (e) {
      console.error('Error fetching threats:', e);
    }
  };

  const runMCPTool = async (toolName: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/mcp/${toolName}`);
      if (response.ok) {
        const data = await response.json();
        setMcpResults(data);
      }
    } catch (e) {
      console.error('Error running MCP tool:', e);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-cyber-danger bg-red-900/30 border-red-500/50';
      case 'high': return 'text-orange-400 bg-orange-900/30 border-orange-500/50';
      case 'medium': return 'text-cyber-warning bg-yellow-900/30 border-yellow-500/50';
      default: return 'text-cyber-info bg-blue-900/30 border-blue-500/50';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  return (
    <div className="min-h-screen bg-cyber-black text-gray-100">
      {/* Header */}
      <header className="border-b border-cyber-gray bg-cyber-dark/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyber-accent" />
              <div>
                <h1 className="text-xl font-bold text-cyber-accent">Sayanox Sentinel OS</h1>
                <p className="text-xs text-gray-400">Autonomous System Security & Threat Mitigation Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-cyber-accent live-indicator' : 'bg-cyber-danger'}`} />
                <span className="text-sm text-gray-400">{isConnected ? 'Live' : 'Disconnected'}</span>
              </div>
              <button 
                onClick={fetchThreats}
                className="p-2 hover:bg-cyber-gray rounded-lg transition-colors"
                title="Refresh Threats"
              >
                <RefreshCw className="w-5 h-5 text-gray-400" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="border-b border-cyber-gray bg-cyber-dark/50">
        <div className="container mx-auto px-4">
          <div className="flex gap-1">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === 'dashboard' 
                  ? 'text-cyber-accent border-cyber-accent' 
                  : 'text-gray-400 border-transparent hover:text-gray-200'
              }`}
            >
              <Activity className="w-4 h-4 inline mr-2" />
              Dashboard
            </button>
            <button
              onClick={() => setActiveTab('threats')}
              className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === 'threats' 
                  ? 'text-cyber-accent border-cyber-accent' 
                  : 'text-gray-400 border-transparent hover:text-gray-200'
              }`}
            >
              <AlertTriangle className="w-4 h-4 inline mr-2" />
              Threats
            </button>
            <button
              onClick={() => setActiveTab('tools')}
              className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === 'tools' 
                  ? 'text-cyber-accent border-cyber-accent' 
                  : 'text-gray-400 border-transparent hover:text-gray-200'
              }`}
            >
              <Terminal className="w-4 h-4 inline mr-2" />
              MCP Tools
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Metrics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* CPU Card */}
              <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-4 cyber-glow">
                <div className="flex items-center justify-between mb-2">
                  <Cpu className="w-5 h-5 text-cyber-info" />
                  <span className="text-xs text-gray-400">CPU Usage</span>
                </div>
                <div className="text-2xl font-bold text-cyber-info">
                  {metrics?.cpu_percent.toFixed(1) || '--'}%
                </div>
                <div className="mt-2 h-1 bg-cyber-gray rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-cyber-info transition-all duration-500"
                    style={{ width: `${metrics?.cpu_percent || 0}%` }}
                  />
                </div>
              </div>

              {/* Memory Card */}
              <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-4 cyber-glow">
                <div className="flex items-center justify-between mb-2">
                  <MemoryStick className="w-5 h-5 text-cyber-warning" />
                  <span className="text-xs text-gray-400">Memory</span>
                </div>
                <div className="text-2xl font-bold text-cyber-warning">
                  {metrics?.memory_percent.toFixed(1) || '--'}%
                </div>
                <div className="text-xs text-gray-400 mt-1">
                  {metrics?.memory_used_gb.toFixed(2) || '--'} / {metrics?.memory_total_gb.toFixed(2) || '--'} GB
                </div>
              </div>

              {/* Network Card */}
              <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-4 cyber-glow">
                <div className="flex items-center justify-between mb-2">
                  <Network className="w-5 h-5 text-cyber-accent" />
                  <span className="text-xs text-gray-400">Network I/O</span>
                </div>
                <div className="text-sm font-semibold text-cyber-accent">
                  ↑ {(metrics?.network_sent_mb || 0).toFixed(1)} MB
                </div>
                <div className="text-sm text-gray-400">
                  ↓ {(metrics?.network_recv_mb || 0).toFixed(1)} MB
                </div>
              </div>

              {/* Disk Card */}
              <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-4 cyber-glow">
                <div className="flex items-center justify-between mb-2">
                  <HardDrive className="w-5 h-5 text-purple-400" />
                  <span className="text-xs text-gray-400">Disk Usage</span>
                </div>
                <div className="text-2xl font-bold text-purple-400">
                  {metrics?.disk_usage_percent.toFixed(1) || '--'}%
                </div>
                <div className="text-xs text-gray-400 mt-1">
                  {metrics?.process_count || '--'} processes
                </div>
              </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* CPU History Chart */}
              <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-4">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-cyber-info" />
                  CPU History
                </h3>
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={metricsHistory}>
                    <defs>
                      <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00ccff" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#00ccff" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(t) => new Date(t).toLocaleTimeString()}
                      stroke="#666"
                      fontSize={12}
                    />
                    <YAxis stroke="#666" fontSize={12} domain={[0, 100]} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1e1e2a', border: '1px solid #333' }}
                      labelFormatter={(l) => new Date(l).toLocaleTimeString()}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="cpu_percent" 
                      stroke="#00ccff" 
                      fill="url(#cpuGradient)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Memory History Chart */}
              <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-4">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <MemoryStick className="w-5 h-5 text-cyber-warning" />
                  Memory History
                </h3>
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={metricsHistory}>
                    <defs>
                      <linearGradient id="memGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ffaa00" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#ffaa00" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(t) => new Date(t).toLocaleTimeString()}
                      stroke="#666"
                      fontSize={12}
                    />
                    <YAxis stroke="#666" fontSize={12} domain={[0, 100]} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1e1e2a', border: '1px solid #333' }}
                      labelFormatter={(l) => new Date(l).toLocaleTimeString()}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="memory_percent" 
                      stroke="#ffaa00" 
                      fill="url(#memGradient)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Recent Threats Summary */}
            <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-4">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-cyber-danger" />
                Recent Threat Alerts
              </h3>
              {threats.length === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No threats detected yet</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-cyber-gray">
                        <th className="text-left py-2 px-3 text-gray-400 font-medium">Severity</th>
                        <th className="text-left py-2 px-3 text-gray-400 font-medium">Title</th>
                        <th className="text-left py-2 px-3 text-gray-400 font-medium">Source</th>
                        <th className="text-left py-2 px-3 text-gray-400 font-medium">Detected</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threats.slice(0, 5).map((threat) => (
                        <tr key={threat.id} className="border-b border-cyber-gray/50 hover:bg-cyber-gray/30">
                          <td className="py-3 px-3">
                            <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(threat.severity)}`}>
                              {threat.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="py-3 px-3 text-gray-200">{threat.title}</td>
                          <td className="py-3 px-3 text-gray-400">{threat.source}</td>
                          <td className="py-3 px-3 text-gray-400">{formatTimestamp(threat.detected_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-6">
            <h2 className="text-xl font-bold mb-6 flex items-center gap-2">
              <AlertTriangle className="w-6 h-6 text-cyber-danger" />
              Security Threat Intelligence
            </h2>
            {threats.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <Shield className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg">No threats in database</p>
                <p className="text-sm mt-2">Threats will appear here after web scraping runs</p>
              </div>
            ) : (
              <div className="space-y-4">
                {threats.map((threat) => (
                  <div 
                    key={threat.id} 
                    className={`p-4 rounded-lg border ${getSeverityColor(threat.severity)}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="px-2 py-0.5 rounded text-xs font-bold uppercase border border-current">
                            {threat.severity}
                          </span>
                          <span className="text-xs text-gray-400">{threat.source}</span>
                        </div>
                        <h3 className="font-semibold text-lg mb-2">{threat.title}</h3>
                        <p className="text-gray-300 text-sm mb-3">{threat.description}</p>
                        <div className="flex items-center gap-4 text-xs text-gray-400">
                          <span>Published: {new Date(threat.published_date).toLocaleDateString()}</span>
                          <span>Detected: {formatTimestamp(threat.detected_at)}</span>
                        </div>
                      </div>
                      <a 
                        href={threat.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-4 px-3 py-2 bg-cyber-gray hover:bg-cyber-accent/20 rounded text-sm transition-colors"
                      >
                        View Details →
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'tools' && (
          <div className="space-y-6">
            <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-6">
              <h2 className="text-xl font-bold mb-6 flex items-center gap-2">
                <Terminal className="w-6 h-6 text-cyber-accent" />
                MCP System Tools
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <button
                  onClick={() => runMCPTool('system_check')}
                  className="p-4 bg-cyber-gray hover:bg-cyber-accent/10 border border-cyber-gray hover:border-cyber-accent/50 rounded-lg transition-all text-left"
                >
                  <Server className="w-6 h-6 text-cyber-info mb-2" />
                  <h3 className="font-semibold">System Check</h3>
                  <p className="text-sm text-gray-400 mt-1">Health check for CPU, memory, disk</p>
                </button>
                <button
                  onClick={() => runMCPTool('network_scan')}
                  className="p-4 bg-cyber-gray hover:bg-cyber-accent/10 border border-cyber-gray hover:border-cyber-accent/50 rounded-lg transition-all text-left"
                >
                  <Network className="w-6 h-6 text-cyber-accent mb-2" />
                  <h3 className="font-semibold">Network Scan</h3>
                  <p className="text-sm text-gray-400 mt-1">Active connections and ports</p>
                </button>
                <button
                  onClick={() => runMCPTool('process_list')}
                  className="p-4 bg-cyber-gray hover:bg-cyber-accent/10 border border-cyber-gray hover:border-cyber-accent/50 rounded-lg transition-all text-left"
                >
                  <Activity className="w-6 h-6 text-cyber-warning mb-2" />
                  <h3 className="font-semibold">Process List</h3>
                  <p className="text-sm text-gray-400 mt-1">Running processes with resources</p>
                </button>
                <button
                  onClick={() => runMCPTool('disk_analysis')}
                  className="p-4 bg-cyber-gray hover:bg-cyber-accent/10 border border-cyber-gray hover:border-cyber-accent/50 rounded-lg transition-all text-left"
                >
                  <HardDrive className="w-6 h-6 text-purple-400 mb-2" />
                  <h3 className="font-semibold">Disk Analysis</h3>
                  <p className="text-sm text-gray-400 mt-1">Partition usage and I/O stats</p>
                </button>
                <button
                  onClick={() => runMCPTool('security_audit')}
                  className="p-4 bg-cyber-gray hover:bg-cyber-accent/10 border border-cyber-gray hover:border-cyber-accent/50 rounded-lg transition-all text-left"
                >
                  <Shield className="w-6 h-6 text-cyber-danger mb-2" />
                  <h3 className="font-semibold">Security Audit</h3>
                  <p className="text-sm text-gray-400 mt-1">Basic security vulnerability scan</p>
                </button>
              </div>
            </div>

            {mcpResults && (
              <div className="bg-cyber-dark border border-cyber-gray rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold flex items-center gap-2">
                    <CheckCircle className={`w-5 h-5 ${mcpResults.success ? 'text-cyber-accent' : 'text-cyber-danger'}`} />
                    Tool Result: {mcpResults.tool}
                  </h3>
                  <span className="text-xs text-gray-400">{formatTimestamp(mcpResults.timestamp)}</span>
                </div>
                <pre className="bg-cyber-black p-4 rounded-lg overflow-x-auto text-sm font-mono">
                  {JSON.stringify(mcpResults.data, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-cyber-gray mt-8 py-4">
        <div className="container mx-auto px-4 text-center text-sm text-gray-500">
          Sayanox Sentinel OS v1.0.0 | Autonomous System Security Platform powered by FastAPI + React
        </div>
      </footer>
    </div>
  );
}

export default App;
