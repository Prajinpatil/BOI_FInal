/* src/components/CertCard.jsx
   NIRIKSHAK-AI :: APK Certificate Analysis Card */
import React from 'react';
import { Lock, LockOpen, AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';

const FLAG_LABELS = {
  SELF_SIGNED:       { label: 'Self-Signed Certificate', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
  EXPIRED:           { label: 'Expired Certificate', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
  DEBUG_CERT:        { label: 'Debug / Test Certificate', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30' },
  SHORT_LIVED_CERT:  { label: 'Short-Lived Certificate (<30d)', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30' },
  NO_SIGNATURE_FILE: { label: 'No Signature File Found', color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30' },
  CERT_PARSE_FAILED: { label: 'Certificate Parse Failed', color: 'text-slate-400', bg: 'bg-slate-700/30 border-slate-600/30' },
  CERT_PARSE_SKIPPED:{ label: 'Parse Skipped (library unavailable)', color: 'text-slate-400', bg: 'bg-slate-700/30 border-slate-600/30' },
};

export default function CertCard({ certAnalysis = {} }) {
  const {
    cert_found,
    issuer,
    subject,
    is_self_signed,
    is_expired,
    valid_from,
    valid_to,
    days_valid,
    risk_flags = [],
    cert_risk_boost = 0,
  } = certAnalysis;

  if (!cert_found && risk_flags.length === 0) return null;

  const isClean = risk_flags.length === 0;
  const headerBorderColor = is_self_signed || is_expired
    ? 'border-red-500/30'
    : isClean
      ? 'border-emerald-500/30'
      : 'border-yellow-500/30';

  return (
    <div className={`glass-card rounded-xl overflow-hidden border ${headerBorderColor}`}>
      {/* Header */}
      <div className="flex items-center gap-2.5 p-4 border-b border-slate-700/50">
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
          isClean ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-red-500/10 border-red-500/30'
        }`}>
          {isClean
            ? <Lock size={16} className="text-emerald-400" />
            : <LockOpen size={16} className="text-red-400" />}
        </div>
        <div>
          <div className="text-xs font-bold uppercase tracking-wider text-slate-300">
            APK Signing Certificate
          </div>
          <div className="text-[10px] text-slate-500 mono mt-0.5">
            {isClean ? 'Certificate appears valid' : `${risk_flags.length} risk flag(s) detected`}
          </div>
        </div>
        {cert_risk_boost > 0 && (
          <span className="ml-auto px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 text-[10px] font-black mono">
            +{Math.round(cert_risk_boost * 100)}% RISK
          </span>
        )}
      </div>

      {/* Body */}
      <div className="p-4 space-y-3">
        {/* Risk Flags */}
        {risk_flags.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {risk_flags.map((flag) => {
              const fl = FLAG_LABELS[flag] || { label: flag, color: 'text-slate-400', bg: 'bg-slate-700/30 border-slate-600/30' };
              return (
                <span key={flag} className={`flex items-center gap-1 px-2 py-1 rounded border text-[10px] font-semibold ${fl.bg} ${fl.color}`}>
                  <AlertTriangle size={10} />
                  {fl.label}
                </span>
              );
            })}
          </div>
        )}

        {isClean && (
          <div className="flex items-center gap-2 text-emerald-400 text-xs">
            <CheckCircle2 size={14} />
            <span>Certificate is valid and properly signed</span>
          </div>
        )}

        {/* Cert Details Table */}
        {cert_found && issuer && issuer !== 'Unknown' && (
          <div className="space-y-1.5 pt-1">
            {[
              { label: 'Subject', value: subject },
              { label: 'Issuer', value: issuer },
              { label: 'Valid From', value: valid_from ? new Date(valid_from).toLocaleDateString() : '—' },
              { label: 'Valid To', value: valid_to ? new Date(valid_to).toLocaleDateString() : '—' },
              { label: 'Validity Period', value: days_valid ? `${days_valid} days` : '—' },
            ].map(({ label, value }) => (
              <div key={label} className="flex gap-2 text-[11px]">
                <span className="w-24 flex-shrink-0 text-slate-500 font-medium">{label}</span>
                <span className="text-slate-300 mono truncate" title={value}>{value}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
