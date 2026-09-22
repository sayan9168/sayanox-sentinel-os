import React, { useState, useEffect } from 'react';
import { Activity, Shield, AlertTriangle, TrendingUp } from 'lucide-react';

const SecurityDashboard = () => {
  const [anomalyStatus, setAnomalyStatus] = useState(null);
  const [honeypotStats, setHoneypotStats] = useState(null);
  const [snifferStats, setSnifferStats] = useState(null);
  const [nmapStatus, setNmapStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSecurityStatus();
    const interval = setInterval(fetchSecurityStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchSecurityStatus = async () => {
    try {
      const token = localStorage.getItem('token');
      const headers = { 'Authorization': `Bearer ${token}` };

      const [anomalyRes, honeypotRes, snifferRes, nmapRes] = await Promise.all([
        fetch('/api/v1/security/anomaly/status', { headers }),
        fetch('/api/v1/security/honeypot/status', { headers }),
        fetch('/api/v1/security/sniffer/status', { headers }),
        fetch('/api/v1/security/nmap/status', { headers })
      ]);

      if (anomalyRes.ok) setAnomalyStatus(await anomalyRes.json());
      if (honeypotRes.ok) setHoneypotStats(await honeypotRes.json());
      if (snifferRes.ok) setSnifferStats(await snifferRes.json());
      if (nmapRes.ok) setNmapStatus(await nmapRes.json());
    } catch (error) {
      console.error('Error fetching security status:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleStartHoneypot = async () => {
    try {
      const token = localStorage.getItem('token');
      await fetch('/api/v1/security/honeypot/start', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      fetchSecurityStatus();
    } catch (error) {
      console.error('Error starting honeypot:', error);
    }
  };

  const handleStartSniffer = async () => {
    try {
      const token = localStorage.getItem('token');
      await fetch('/api/v1/security/sniffer/start', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      fetchSecurityStatus();
    } catch (error) {
      console.error('Error starting sniffer:', error);
    }
  };

  if (loading) {
    return <div className="text-gray-400">Loading security modules...</div>;
  }

  return (
    <div className="space-y-6">
      {/* ML Anomaly Detection */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold text-cyan-400 flex items-center">
            <TrendingUp className="w-6 h-6 mr-2" />
            ML Anomaly Detection
          </h3>
          <span className={`px-3 py-1 rounded-full text-sm ${
            anomalyStatus?.training?.is_trained 
              ? 'bg-green-900 text-green-400' 
              : 'bg-yellow-900 text-yellow-400'
          }`}>
            {anomalyStatus?.training?.is_trained ? 'Model Trained' : 'Training...'}
          </span>
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Samples Collected</div>
            <div className="text-2xl font-bold text-white">
              {anomalyStatus?.training?.samples_collected || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Training Progress</div>
            <div className="text-2xl font-bold text-cyan-400">
              {anomalyStatus?.training?.training_progress?.toFixed(1) || 0}%
            </div>
          </div>
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Anomalies Detected</div>
            <div className="text-2xl font-bold text-red-400">
              {anomalyStatus?.training?.anomalies_detected || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Min Samples Required</div>
            <div className="text-2xl font-bold text-white">
              {anomalyStatus?.training?.min_samples_required || 100}
            </div>
          </div>
        </div>

        {anomalyStatus?.recent_anomalies?.length > 0 && (
          <div className="mt-4">
            <h4 className="text-sm font-semibold text-gray-400 mb-2">Recent Anomalies</h4>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {anomalyStatus.recent_anomalies.map((anomaly, idx) => (
                <div key={idx} className="bg-red-900/20 border border-red-800 rounded p-2 text-sm">
                  <span className="text-red-400">{anomaly.timestamp}</span>
                  <span className="ml-4 text-gray-300">Score: {anomaly.score?.toFixed(4)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Honeypot Service */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold text-purple-400 flex items-center">
            <Shield className="w-6 h-6 mr-2" />
            Deception Honeypot
          </h3>
          <div className="flex items-center space-x-2">
            <span className={`px-3 py-1 rounded-full text-sm ${
              honeypotStats?.is_running 
                ? 'bg-green-900 text-green-400' 
                : 'bg-gray-700 text-gray-400'
            }`}>
              {honeypotStats?.is_running ? 'Active' : 'Stopped'}
            </span>
            {!honeypotStats?.is_running && (
              <button
                onClick={handleStartHoneypot}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded text-sm transition"
              >
                Start Honeypot
              </button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Total Connections</div>
            <div className="text-2xl font-bold text-white">
              {honeypotStats?.total_connections || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Unique IPs</div>
            <div className="text-2xl font-bold text-purple-400">
              {honeypotStats?.unique_ips || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Blocked IPs</div>
            <div className="text-2xl font-bold text-red-400">
              {honeypotStats?.blocked_ips || 0}
            </div>
          </div>
        </div>

        <div className="mt-4">
          <div className="text-sm text-gray-400 mb-2">Monitored Ports: {honeypotStats?.decoy_ports?.join(', ') || 'None'}</div>
        </div>
      </div>

      {/* Network Sniffer */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold text-blue-400 flex items-center">
            <Activity className="w-6 h-6 mr-2" />
            Packet Sniffer
          </h3>
          <div className="flex items-center space-x-2">
            <span className={`px-3 py-1 rounded-full text-sm ${
              snifferStats?.is_running 
                ? 'bg-green-900 text-green-400' 
                : 'bg-gray-700 text-gray-400'
            }`}>
              {snifferStats?.is_running ? 'Capturing' : 'Stopped'}
            </span>
            {!snifferStats?.is_running ? (
              <button
                onClick={handleStartSniffer}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-sm transition"
              >
                Start Capture
              </button>
            ) : (
              <button
                onClick={() => window.location.href = '/security/packets'}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-sm transition"
              >
                View Packets
              </button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-gray-900 rounded p-3">
            <div className="text-gray-400 text-xs">Total Packets</div>
            <div className="text-xl font-bold text-white">
              {snifferStats?.total_packets || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-3">
            <div className="text-gray-400 text-xs">TCP</div>
            <div className="text-xl font-bold text-blue-400">
              {snifferStats?.tcp_packets || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-3">
            <div className="text-gray-400 text-xs">UDP</div>
            <div className="text-xl font-bold text-green-400">
              {snifferStats?.udp_packets || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-3">
            <div className="text-gray-400 text-xs">ICMP</div>
            <div className="text-xl font-bold text-yellow-400">
              {snifferStats?.icmp_packets || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-3">
            <div className="text-gray-400 text-xs">Bytes</div>
            <div className="text-xl font-bold text-cyan-400">
              {(snifferStats?.bytes_captured / 1024).toFixed(1)} KB
            </div>
          </div>
        </div>
      </div>

      {/* Nmap Scanner */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold text-orange-400 flex items-center">
            <AlertTriangle className="w-6 h-6 mr-2" />
            Nmap Vulnerability Scanner
          </h3>
          <span className={`px-3 py-1 rounded-full text-sm ${
            nmapStatus?.nmap_available 
              ? 'bg-green-900 text-green-400' 
              : 'bg-red-900 text-red-400'
          }`}>
            {nmapStatus?.nmap_available ? 'Available' : 'Unavailable'}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Total Scans</div>
            <div className="text-2xl font-bold text-white">
              {nmapStatus?.total_scans || 0}
            </div>
          </div>
          <div className="bg-gray-900 rounded p-4">
            <div className="text-gray-400 text-sm">Recent Scans</div>
            <div className="text-2xl font-bold text-orange-400">
              {nmapStatus?.recent_scans || 0}
            </div>
          </div>
        </div>

        <div className="mt-4 flex space-x-2">
          <a
            href="/security/nmap"
            className="px-4 py-2 bg-orange-600 hover:bg-orange-700 rounded text-sm transition"
          >
            Open Scanner
          </a>
          <a
            href="/security/scan-history"
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm transition"
          >
            Scan History
          </a>
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
