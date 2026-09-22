import React from 'react';
import { Activity, Server, HardDrive, Network } from 'lucide-react';

const MetricCard = ({ title, value, unit, icon: Icon, color, trend }) => (
  <div className="bg-dark-card border border-dark-border rounded-xl p-6 cyber-border hover:cyber-glow transition-all duration-300">
    <div className="flex items-center justify-between mb-4">
      <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
      <div className={`p-2 rounded-lg ${color}`}>
        <Icon className="w-5 h-5 text-white" />
      </div>
    </div>
    <div className="flex items-end justify-between">
      <div>
        <p className="text-3xl font-bold text-white">{value}</p>
        <p className="text-gray-500 text-sm mt-1">{unit}</p>
      </div>
      {trend && (
        <div className={`text-sm ${trend > 0 ? 'text-red-400' : 'text-green-400'}`}>
          {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
        </div>
      )}
    </div>
  </div>
);

export default MetricCard;
