// src/components/IndianTargetBanner.jsx
// Threat-intel alert banner for flagged Indian financial banking targets (SBI, YONO, UPI overlays)
import React from 'react';
import { AlertOctagon, Flame, Landmark, ShieldAlert } from 'lucide-react';

export default function IndianTargetBanner({ targetDetected = false, flaggedTarget = '' }) {
  if (!targetDetected) return null;

  return (
    <div className="w-full relative overflow-hidden rounded-xl border border-red-500/40 bg-red-950/40 backdrop-blur-md p-4 shadow-[0_0_30px_rgba(239,68,68,0.2)]">
      {/* Background Red Accent Gradient */}
      <div className="absolute inset-0 bg-gradient-to-r from-red-500/10 via-transparent to-red-500/5 pointer-events-none" />

      <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        {/* Left Side: Alert Icon + Target Info */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-red-500/20 border border-red-500/40 text-red-400 flex-shrink-0 animate-pulse">
            <AlertOctagon size={22} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-widest text-red-400 mono flex items-center gap-1">
                <ShieldAlert size={13} /> CRITICAL THREAT INTEL — INDIAN TARGET FLAGGED
              </span>
            </div>
            <h3 className="text-base font-black text-white tracking-wide mt-0.5">
              {flaggedTarget || 'SBI YONO / BHIM UPI Banking Trojan Vector'}
            </h3>
            <p className="text-xs text-red-200/80 mt-0.5">
              Malware explicitly incorporates overlays or automated intercept mechanisms targeting Indian financial banking applications.
            </p>
          </div>
        </div>

        {/* Right Side: Regulatory Flag Badge */}
        <div className="flex items-center gap-2 flex-shrink-0 self-end md:self-center">
          <div className="px-3 py-1.5 rounded-lg bg-red-500/20 border border-red-500/50 text-red-300 mono text-xs font-bold flex items-center gap-1.5 shadow-inner">
            <Landmark size={14} className="text-red-400" />
            <span>RBI / CERT-In HIGH PRIORITY</span>
          </div>
        </div>
      </div>
    </div>
  );
}
