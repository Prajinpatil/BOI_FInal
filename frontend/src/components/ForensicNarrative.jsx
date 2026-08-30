// src/components/ForensicNarrative.jsx
// Inset intelligence brief displaying LLM forensic narrative
import React from 'react';
import { Brain, Cpu } from 'lucide-react';

export default function ForensicNarrative({ narrative = '', confidence = 'HIGH' }) {
  if (!narrative) return null;

  const confStyles = {
    HIGH: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
    MEDIUM: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
    LOW: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  }[confidence] || { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' };

  return (
    <div className="w-full relative p-4 rounded-xl border border-cyan-500/20 bg-slate-900/90 backdrop-blur-md shadow-inner border-l-4 border-l-cyan-400">
      {/* Brief Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Cpu size={16} className="text-purple-400" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
            AI FORENSIC ANALYSIS (llama-3.3-70b)
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <Cpu size={12} className="text-slate-400" />
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border mono ${confStyles.bg} ${confStyles.text} ${confStyles.border}`}>
            {confidence} CONFIDENCE
          </span>
        </div>
      </div>

      {/* Brief Narrative Body */}
      <p className="text-xs leading-relaxed text-slate-300 font-normal selection:bg-cyan-500/30">
        {narrative}
      </p>

      {/* Footer Intel Note */}
      <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] mono text-slate-500">
        <span>AST Slicing + LLM Contextual Reasoning</span>
        <span>CONFIDENTIAL SOC BRIEF</span>
      </div>
    </div>
  );
}
