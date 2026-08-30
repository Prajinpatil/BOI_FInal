/* src/components/MitrePanel.jsx
   NIRIKSHAK-AI :: MITRE ATT&CK Mobile Technique Panel */
import React, { useState } from 'react';
import { Shield, ChevronDown, ChevronUp, Target } from 'lucide-react';

const SEVERITY_STYLES = {
  CRITICAL: { bg: 'bg-red-500/15', border: 'border-red-500/40', text: 'text-red-400', badge: 'bg-red-500/20 text-red-300' },
  HIGH:     { bg: 'bg-orange-500/15', border: 'border-orange-500/40', text: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-300' },
  MEDIUM:   { bg: 'bg-yellow-500/15', border: 'border-yellow-500/40', text: 'text-yellow-400', badge: 'bg-yellow-500/20 text-yellow-300' },
  LOW:      { bg: 'bg-emerald-500/15', border: 'border-emerald-500/40', text: 'text-emerald-400', badge: 'bg-emerald-500/20 text-emerald-300' },
};

const TACTIC_COLORS = {
  'Collection':         'text-cyan-400',
  'Persistence':        'text-purple-400',
  'Defense Evasion':    'text-orange-400',
  'Discovery':          'text-blue-400',
  'Command and Control':'text-red-400',
  'Privilege Escalation':'text-pink-400',
  'Impact':             'text-rose-400',
  'Execution':          'text-amber-400',
};

export default function MitrePanel({ techniques = [] }) {
  const [expanded, setExpanded] = useState(true);

  if (!techniques || techniques.length === 0) return null;

  const critCount = techniques.filter(t => t.severity === 'CRITICAL').length;
  const highCount = techniques.filter(t => t.severity === 'HIGH').length;

  return (
    <div className="glass-card rounded-xl overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center">
            <Target size={16} className="text-red-400" />
          </div>
          <div className="text-left">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              MITRE ATT&amp;CK® Mobile
              <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 text-[10px] font-bold">
                {techniques.length} TECHNIQUES
              </span>
            </div>
            <div className="text-[10px] text-slate-500 mono mt-0.5">
              {critCount > 0 && <span className="text-red-400 mr-2">● {critCount} CRITICAL</span>}
              {highCount > 0 && <span className="text-orange-400">● {highCount} HIGH</span>}
            </div>
          </div>
        </div>
        {expanded ? <ChevronUp size={16} className="text-slate-500" /> : <ChevronDown size={16} className="text-slate-500" />}
      </button>

      {/* Technique List */}
      {expanded && (
        <div className="px-4 pb-4 space-y-2">
          {techniques.map((tech, i) => {
            const style = SEVERITY_STYLES[tech.severity] || SEVERITY_STYLES.LOW;
            const tacticColor = TACTIC_COLORS[tech.tactic] || 'text-slate-400';
            return (
              <div
                key={`${tech.technique_id}-${i}`}
                className={`flex items-start gap-3 p-3 rounded-lg border ${style.bg} ${style.border}`}
              >
                <div className={`flex-shrink-0 px-2 py-0.5 rounded mono text-[10px] font-black ${style.badge} mt-0.5`}>
                  {tech.technique_id}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-semibold text-slate-200 leading-snug">
                    {tech.technique_name}
                  </div>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <span className={`text-[10px] font-medium ${tacticColor}`}>{tech.tactic}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-[10px] text-slate-500 mono">{tech.evidence}</span>
                    {tech.source === 'CODE_PATTERN' && (
                      <span className="text-[10px] px-1 rounded bg-purple-500/15 text-purple-400 border border-purple-500/20">
                        CODE
                      </span>
                    )}
                  </div>
                </div>
                <span className={`flex-shrink-0 text-[9px] font-black ${style.text} tracking-wider`}>
                  {tech.severity}
                </span>
              </div>
            );
          })}
          <p className="text-[10px] text-slate-600 text-right pt-1">
            Source: MITRE ATT&CK® for Mobile v14 · attack.mitre.org
          </p>
        </div>
      )}
    </div>
  );
}
