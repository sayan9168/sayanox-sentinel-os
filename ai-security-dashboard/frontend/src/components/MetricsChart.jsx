import React from 'react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const MetricsChart = ({ data, dataKey, color, title }) => {
  if (!data || data.length === 0) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-xl p-6 cyber-border">
        <h3 className="text-gray-400 text-sm font-medium mb-4">{title}</h3>
        <div className="h-64 flex items-center justify-center">
          <p className="text-gray-600">No data available</p>
        </div>
      </div>
    );
  }

  const chartData = data.map((item, index) => ({
    ...item,
    time: new Date(item.timestamp).toLocaleTimeString(),
  }));

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-6 cyber-border">
      <h3 className="text-gray-400 text-sm font-medium mb-4">{title}</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id={`gradient-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                <stop offset="95%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e1e2a" />
            <XAxis 
              dataKey="time" 
              stroke="#4b5563" 
              tick={{ fontSize: 12 }}
              tickFormatter={(value) => value.split(':')[0] + ':' + value.split(':')[1]}
            />
            <YAxis 
              stroke="#4b5563" 
              tick={{ fontSize: 12 }}
              domain={[0, 100]}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#12121a',
                border: '1px solid #1e1e2a',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelStyle={{ color: '#9ca3af' }}
            />
            <Area
              type="monotone"
              dataKey={dataKey}
              stroke={color}
              fillOpacity={1}
              fill={`url(#gradient-${dataKey})`}
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default MetricsChart;
