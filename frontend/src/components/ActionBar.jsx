// src/components/ActionBar.jsx
// Sticky Action Buttons Bar for PDF Compliance Report & STIX 2.1 Threat Intel Download
import React from 'react';
import { Download, FileJson, FileText, Loader2, ShieldCheck } from 'lucide-react';

export default function ActionBar({
  onDownloadReport = () => {},
  onDownloadSTIX = () => {},
  isDownloading = false,
  isComplete = false,
  severity = 'LOW',
}) {
  return (
    <div className="sticky bottom-0 z-40 w-full py-3 px-6 bg-slate-900/95 backdrop-blur-xl border-t border-cyan-500/20 shadow-[0_-5px_25px_rgba(0,0,0,0.5)]">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Status Text */}
        <div className="flex items-center gap-2 text-xs">
          <ShieldCheck size={16} className={isComplete ? 'text-emerald-400' : 'text-slate-500'} />
          <span className="text-slate-300 font-medium">
            {isComplete
              ? `Analysis Completed (${severity} Severity) — Forensic exports ready`
              : 'Submit APK analysis to generate regulatory compliance & STIX exports'}
          </span>
        </div>

        {/* Button Pair */}
        <div className="flex items-center gap-3 w-full sm:w-auto">
          {/* STIX 2.1 Download Button */}
          <button
            onClick={onDownloadSTIX}
            disabled={!isComplete}
            className="flex-1 sm:flex-initial btn-secondary border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed text-xs py-2.5 px-4"
            title={isComplete ? 'Download STIX 2.1 JSON Bundle' : 'Complete analysis to enable export'}
          >
            <FileJson size={15} />
            <span>Download STIX 2.1 Export</span>
          </button>

          {/* RBI / CERT-In PDF Download Button */}
          <button
            onClick={onDownloadReport}
            disabled={!isComplete || isDownloading}
            className="flex-1 sm:flex-initial btn-primary text-xs py-2.5 px-5 disabled:opacity-40 disabled:cursor-not-allowed"
            title={isComplete ? 'Download RBI / CERT-In PDF Compliance Report' : 'Complete analysis to enable export'}
          >
            {isDownloading ? (
              <Loader2 size={15} className="animate-spin" />
            ) : (
              <FileText size={15} />
            )}
            <span>{isDownloading ? 'Generating PDF…' : 'Download RBI/CERT-In Report'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
