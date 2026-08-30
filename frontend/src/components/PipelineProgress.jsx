// src/components/PipelineProgress.jsx
// Live Pipeline Progress Indicator
// Stepper displaying the 5 real-time malware analysis stages with technical microcopy.
import React from 'react';
import {
  CheckCircle2,
  CircleDot,
  Code2,
  Cpu,
  FileSearch,
  Flame,
  Loader2,
  ShieldAlert,
  XCircle,
  Zap,
} from 'lucide-react';

export const PIPELINE_STAGES = [
  {
    id: 1,
    title: 'Static Analysis',
    subtitle: 'Androguard parsing & DEX extraction',
    activeCopy: 'Parsing AndroidManifest.xml & permissions…',
    icon: FileSearch,
    duration: 3000,
  },
  {
    id: 2,
    title: 'AST Code Slicing',
    subtitle: 'Decompiling bytecode for dangerous calls',
    activeCopy: 'Slicing AST paths & crypto reflection API calls…',
    icon: Code2,
    duration: 2500,
  },
  {
    id: 3,
    title: 'GenAI Semantic Analysis',
    subtitle: 'Groq AI llama-3.3-70b inference',
    activeCopy: 'Establishing Cloud LLM connection (Groq)…',
    icon: Cpu,
    duration: 6000,
  },
  {
    id: 4,
    title: 'Dynamic Sandbox',
    subtitle: 'VirusTotal Cloud AV Reputation Fallback',
    activeCopy: 'Querying VirusTotal behavior & engines…',
    icon: Flame,
    duration: 4000,
  },
  {
    id: 5,
    title: 'Risk Fusion & Compilation',
    subtitle: '5-factor XGBoost risk formula & PDF synthesis',
    activeCopy: 'Computing 5-factor risk fusion & generating RBI report…',
    icon: Zap,
    duration: 1500,
  },
];

export default function PipelineProgress({ currentStage = 1, isComplete = false, error = null }) {
  return (
    <div className="w-full flex flex-col gap-3 p-4 rounded-xl border border-cyan-500/20 bg-slate-900/80 backdrop-blur-md">
      {/* Stepper Header */}
      <div className="flex items-center justify-between pb-2 border-b border-cyan-500/10">
        <div className="flex items-center gap-2">
          {error ? (
            <ShieldAlert size={16} className="text-red-400" />
          ) : isComplete ? (
            <CheckCircle2 size={16} className="text-emerald-400" />
          ) : (
            <Loader2 size={16} className="text-cyan-400 animate-spin" />
          )}
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
            {error ? 'Pipeline Interrupted' : isComplete ? 'Analysis Completed' : 'Analysis Pipeline Active'}
          </span>
        </div>
        <span className="text-xs mono text-cyan-400/80">
          {isComplete ? 'STAGES 5/5' : error ? 'FAILED' : `STAGE ${Math.min(currentStage, 5)}/5`}
        </span>
      </div>

      {/* Stepper List */}
      <div className="flex flex-col gap-2">
        {PIPELINE_STAGES.map((stage) => {
          const isDone = isComplete || stage.id < currentStage;
          const isActive = !isComplete && !error && stage.id === currentStage;
          const isFailed = Boolean(error && stage.id === currentStage);
          const isPending = !isComplete && !error && stage.id > currentStage;

          const StageIcon = stage.icon;

          return (
            <div
              key={stage.id}
              className={`flex items-start gap-3 p-3 rounded-lg transition-all duration-300 border ${
                isDone
                  ? 'bg-emerald-500/5 border-emerald-500/20'
                  : isActive
                  ? 'bg-cyan-500/10 border-cyan-500/30 shadow-[0_0_15px_rgba(34,211,238,0.1)]'
                  : isFailed
                  ? 'bg-red-500/10 border-red-500/30'
                  : 'bg-slate-800/30 border-transparent opacity-60'
              }`}
            >
              {/* Status Indicator Icon */}
              <div className="mt-0.5 flex-shrink-0">
                {isDone ? (
                  <CheckCircle2 size={18} className="text-emerald-400" />
                ) : isActive ? (
                  <Loader2 size={18} className="text-cyan-400 animate-spin" />
                ) : isFailed ? (
                  <XCircle size={18} className="text-red-400" />
                ) : (
                  <CircleDot size={18} className="text-slate-600" />
                )}
              </div>

              {/* Text Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <StageIcon
                    size={14}
                    className={
                      isDone
                        ? 'text-emerald-400'
                        : isActive
                        ? 'text-cyan-400'
                        : isFailed
                        ? 'text-red-400'
                        : 'text-slate-500'
                    }
                  />
                  <span
                    className={`text-xs font-semibold tracking-wide truncate ${
                      isDone
                        ? 'text-emerald-300'
                        : isActive
                        ? 'text-cyan-300'
                        : isFailed
                        ? 'text-red-300'
                        : 'text-slate-400'
                    }`}
                  >
                    {stage.id}. {stage.title}
                  </span>
                </div>

                {/* Terse technical microcopy */}
                <p className="text-[11px] mt-0.5 mono text-slate-400 truncate">
                  {isActive ? stage.activeCopy : isDone ? `${stage.subtitle} [DONE]` : stage.subtitle}
                </p>
              </div>

              {/* Active Pulse indicator */}
              {isActive && (
                <div className="flex items-center gap-1 self-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                  <span className="text-[10px] mono font-bold text-cyan-400 uppercase">Processing</span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
