import React from 'react';
import { AlertTriangle, Shield, Bug, ExternalLink } from 'lucide-react';

const ThreatTable = ({ threats }) => {
  const getSeverityBadge = (severity) => {
    const colors = {
      CRITICAL: 'severity-critical',
      HIGH: 'severity-high',
      MEDIUM: 'severity-medium',
      LOW: 'severity-low',
    };
    return colors[severity] || 'severity-medium';
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return <AlertTriangle className="w-4 h-4" />;
      case 'HIGH':
        return <Shield className="w-4 h-4" />;
      case 'MEDIUM':
        return <AlertTriangle className="w-4 h-4" />;
      case 'LOW':
        return <Bug className="w-4 h-4" />;
      default:
        return <Bug className="w-4 h-4" />;
    }
  };

  if (!threats || threats.length === 0) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-xl p-8 text-center">
        <Shield className="w-12 h-12 text-gray-600 mx-auto mb-4" />
        <p className="text-gray-400">No threats detected</p>
        <p className="text-gray-500 text-sm mt-2">System is secure</p>
      </div>
    );
  }

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden cyber-border">
      <div className="p-6 border-b border-dark-border">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-cyber-400" />
          Active Threats
        </h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-dark-bg">
            <tr>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Severity
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Title
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Source
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                CVE ID
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Date
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {threats.map((threat, index) => (
              <tr 
                key={threat.id || index} 
                className="hover:bg-dark-bg/50 transition-colors"
              >
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium text-white ${getSeverityBadge(threat.severity)}`}>
                    {getSeverityIcon(threat.severity)}
                    {threat.severity}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <p className="text-white font-medium max-w-md truncate">{threat.title}</p>
                  <p className="text-gray-500 text-sm mt-1 truncate">{threat.description}</p>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-cyber-400 text-sm">{threat.source}</span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {threat.cve_id ? (
                    <span className="text-gray-300 font-mono text-sm">{threat.cve_id}</span>
                  ) : (
                    <span className="text-gray-600 text-sm">-</span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-gray-400 text-sm">
                    {threat.published_date ? new Date(threat.published_date).toLocaleDateString() : '-'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {threat.url && (
                    <a
                      href={threat.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyber-400 hover:text-cyber-300 transition-colors inline-flex items-center gap-1 text-sm"
                    >
                      Details <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ThreatTable;
