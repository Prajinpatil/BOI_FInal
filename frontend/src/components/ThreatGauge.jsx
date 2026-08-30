// src/components/ThreatGauge.jsx
// Interactive Recharts 180° Arc Threat Gauge displaying the 0-100 risk score
// with animated counter, tabular-nums monospace font, and severity color coding.
import React, { useEffect, useState } from 'react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#10b981',
  DEFAULT: '#22d3ee',
};

const SEVERITY_LABELS = {
  CRITICAL: 'CRITICAL THREAT',
  HIGH: 'HIGH RISK',
  MEDIUM: 'MEDIUM RISK',
  LOW: 'LOW RISK',
};

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    if (data.name === 'Empty') return null;
    return (
      <div className="p-2.5 rounded-lg bg-slate-900 border border-cyan-500/30 text-center shadow-xl">
        <p className="text-xs font-bold" style={{ color: data.color }}>
          {data.name}
        </p>
        <p className="text-xl font-black mono tabular-nums text-white mt-0.5">
          {data.value.toFixed(1)} / 100
        </p>
      </div>
    );
  }
  return null;
};

export default function ThreatGauge({ score = 0, severity = 'LOW', size = 220 }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.DEFAULT;
  const label = SEVERITY_LABELS[severity] || 'UNKNOWN';

  useEffect(() => {
    setAnimatedScore(0);
    const target = Math.max(0, Math.min(100, score));
    const duration = 1000;
    const startTime = performance.now();
    let animRef;

    const tick = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(eased * target);
      if (progress < 1) {
        animRef = requestAnimationFrame(tick);
      }
    };

    animRef = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef);
  }, [score]);

  const data = [
    { name: label, value: animatedScore, color: color },
    { name: 'Empty', value: 100 - animatedScore, color: 'rgba(30, 41, 59, 0.4)' },
  ];

  return (
    <div
      className="relative flex flex-col items-center justify-center select-none"
      style={{ width: size, height: size * 0.7 }}
    >
      {/* Glow Effect */}
      <div
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full blur-2xl pointer-events-none transition-all duration-700"
        style={{
          width: size * 0.55,
          height: size * 0.55,
          backgroundColor: color,
          opacity: severity === 'CRITICAL' ? 0.25 : 0.12,
        }}
      />

      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="70%"
            startAngle={180}
            endAngle={0}
            innerRadius="75%"
            outerRadius="95%"
            paddingAngle={0}
            dataKey="value"
            stroke="none"
            cornerRadius={4}
            isAnimationActive={false}
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.color}
                style={{
                  filter: index === 0 ? `drop-shadow(0 0 10px ${entry.color}80)` : 'none',
                }}
              />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'transparent' }} />
        </PieChart>
      </ResponsiveContainer>

      {/* Center Display Overlay */}
      <div className="absolute top-[62%] left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center pointer-events-none">
        <span
          className="text-4xl font-black mono tabular-nums tracking-tight"
          style={{ color: color, textShadow: `0 0 15px ${color}60` }}
        >
          {animatedScore.toFixed(1)}
        </span>
        <span
          className="text-[11px] font-bold uppercase tracking-widest mt-0.5 mono"
          style={{ color: color }}
        >
          {label}
        </span>
      </div>
    </div>
  );
}
