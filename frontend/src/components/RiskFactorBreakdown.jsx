// src/components/RiskFactorBreakdown.jsx
// Horizontal bar chart breaking down the final risk score into its 4 weighted contributions.
import React from 'react';
import { Activity, ShieldAlert, Sparkles, Terminal, Zap } from 'lucide-react';

export default function RiskFactorBreakdown({ factorBreakdown = {}, finalScore = 0 }) {
  const p_ml = Number(factorBreakdown?.p_ml ?? 0.0);
  const s_semantic = Number(factorBreakdown?.s_semantic ?? 0.0);
  const s_dynamic = Number(factorBreakdown?.s_dynamic ?? 0.0);
  const target_bonus = Number(factorBreakdown?.target_bonus ?? 0.0);

  // Compute weighted scores (out of max weights)
  const mlPoints = (p_ml * 35).toFixed(1);
  const semanticPoints = (s_semantic * 40).toFixed(1);
  const dynamicPoints = (s_dynamic * 25).toFixed(1);
  const bonusPoints = (target_bonus * 100).toFixed(1); // e.g. 0.15 -> +15.0 pts

  const factors = [
    {
      id: 'ml',
      label: 'ML / Static Analysis',
      weight: '35%',
      rawVal: p_ml.toFixed(2),
      points: `${mlPoints} pts`,
      maxPoints: 35,
      actualPoints: parseFloat(mlPoints),
      color: '#22d3ee', // cyan
      icon: Terminal,
    },
    {
      id: 'genai',
      label: 'GenAI Semantic (Groq)',
      weight: '40%',
      rawVal: s_semantic.toFixed(2),
      points: `${semanticPoints} pts`,
      maxPoints: 40,
      actualPoints: parseFloat(semanticPoints),
      color: '#a855f7', // purple
      icon: Sparkles,
    },
    {
      id: 'dynamic',
      label: 'Dynamic Sandbox (VirusTotal)',
      weight: '25%',
      rawVal: s_dynamic.toFixed(2),
      points: `${dynamicPoints} pts`,
      maxPoints: 25,
      actualPoints: parseFloat(dynamicPoints),
      color: '#eab308', // yellow
      icon: Activity,
    },
  ];

  if (target_bonus > 0) {
    factors.push({
      id: 'bonus',
      label: 'Indian Target Vector Bonus',
      weight: '+5%',
      rawVal: `+${target_bonus.toFixed(2)}`,
      points: `+${bonusPoints} pts`,
      maxPoints: 5,
      actualPoints: parseFloat(bonusPoints),
      color: '#ef4444', // red
      icon: ShieldAlert,
    });
  }

  return (
    <div className="w-full flex flex-col gap-3 p-4 rounded-xl glass-card">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap size={15} className="text-cyan-400" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
            5-Factor Risk Fusion Breakdown
          </span>
        </div>
        <span className="text-xs mono font-bold text-cyan-400">
          TOTAL: {finalScore.toFixed(1)} / 100
        </span>
      </div>

      <div className="flex flex-col gap-3 mt-1">
        {factors.map((factor) => {
          const percentage = Math.min(100, Math.max(0, (factor.actualPoints / factor.maxPoints) * 100));
          const FactorIcon = factor.icon;

          return (
            <div key={factor.id} className="flex flex-col gap-1 text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <FactorIcon size={12} style={{ color: factor.color }} />
                  <span className="font-semibold text-slate-200">{factor.label}</span>
                  <span className="text-[10px] mono text-slate-400">({factor.weight})</span>
                </div>
                <div className="flex items-center gap-2 mono">
                  <span className="text-slate-400 text-[11px]">raw: {factor.rawVal}</span>
                  <span className="font-bold text-[12px]" style={{ color: factor.color }}>
                    {factor.points}
                  </span>
                </div>
              </div>

              {/* Progress Bar Container */}
              <div className="w-full h-2 rounded-full bg-slate-800/80 overflow-hidden p-0.5 border border-slate-700/50">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${percentage}%`,
                    backgroundColor: factor.color,
                    boxShadow: `0 0 8px ${factor.color}60`,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
