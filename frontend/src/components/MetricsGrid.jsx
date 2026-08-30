// src/components/MetricsGrid.jsx
// Metrics grid displaying key threat indicators, severity tier, Indian target status, permissions, and hash
import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Flag,
  Hash,
  Lock,
  Package,
  ShieldOff,
  Terminal,
  Zap,
} from 'lucide-react';

const SEVERITY_CLASSES = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
};

const SEVERITY_ICONS = {
  CRITICAL: <ShieldOff size={14} className="text-red-400" />,
  HIGH: <AlertTriangle size={14} className="text-orange-400" />,
  MEDIUM: <Zap size={14} className="text-yellow-400" />,
  LOW: <CheckCircle2 size={14} className="text-emerald-400" />,
};

function MetricCard({ icon, title, value, subValue, accent = '#22d3ee' }) {
  return (
    <div className="p-3.5 rounded-xl glass-card flex flex-col justify-between gap-2 min-h-[96px]">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
          {title}
        </span>
        <div
          className="flex items-center justify-center w-6 h-6 rounded"
          style={{ backgroundColor: `${accent}15`, color: accent }}
        >
          {icon}
        </div>
      </div>
      <div>
        <div className="font-bold" style={{ color: accent }}>
          {value}
        </div>
        {subValue && <div className="text-[11px] text-slate-400 mt-0.5 truncate">{subValue}</div>}
      </div>
    </div>
  );
}

export default function MetricsGrid({ masterData = null }) {
  if (!masterData) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="p-3.5 rounded-xl glass-card h-24 animate-pulse bg-slate-800/40" />
        ))}
      </div>
    );
  }

  const {
    app_metadata = {},
    static_analysis = {},
    genai_forensics = {},
    risk_assessment = {},
  } = masterData;

  const finalScore = Number(risk_assessment.final_score ?? 0);
  const severityTier = risk_assessment.severity_tier || 'LOW';
  const targetDetected = Boolean(static_analysis.target_detected);
  const flaggedTarget = static_analysis.flagged_target || '';
  const dangerousPerms = static_analysis.dangerous_permissions || [];
  const totalPerms = static_analysis.permissions || [];
  const sha256 = app_metadata.sha256 || 'N/A';
  const shaShort = sha256.length > 16 ? `${sha256.slice(0, 8)}...${sha256.slice(-8)}` : sha256;

  const severityColor = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#10b981',
  }[severityTier] || '#10b981';

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
      {/* Threat Score */}
      <MetricCard
        icon={<AlertTriangle size={14} />}
        title="Threat Score"
        value={<span className="text-2xl font-black mono tabular-nums">{finalScore.toFixed(1)}</span>}
        subValue="Out of 100 max risk"
        accent={severityColor}
      />

      {/* Severity Tier */}
      <MetricCard
        icon={SEVERITY_ICONS[severityTier]}
        title="Severity Tier"
        value={
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold ${SEVERITY_CLASSES[severityTier]}`}>
            {SEVERITY_ICONS[severityTier]}
            {severityTier}
          </span>
        }
        subValue={`Confidence: ${genai_forensics.confidence || 'HIGH'}`}
        accent={severityColor}
      />

      {/* Indian Banking Target */}
      <MetricCard
        icon={<Flag size={14} />}
        title="Indian Target"
        value={
          targetDetected ? (
            <span className="text-red-400 font-bold text-sm flex items-center gap-1">
              <AlertTriangle size={13} /> DETECTED
            </span>
          ) : (
            <span className="text-emerald-400 font-bold text-sm flex items-center gap-1">
              <CheckCircle2 size={13} /> Clear
            </span>
          )
        }
        subValue={targetDetected ? (flaggedTarget || 'SBI/UPI Overlay Signature') : 'No Indian Banking overlay'}
        accent={targetDetected ? '#ef4444' : '#10b981'}
      />

      {/* Primary Exploit */}
      <MetricCard
        icon={<Terminal size={14} />}
        title="Primary Exploit"
        value={
          <span className="mono text-xs font-bold text-cyan-300 truncate block">
            {(genai_forensics.primary_exploit || 'UNKNOWN').replace(/_/g, ' ')}
          </span>
        }
        subValue={`Semantic Score: ${(genai_forensics.semantic_score ?? 0).toFixed(2)}`}
        accent="#22d3ee"
      />

      {/* Flagged Permissions */}
      <MetricCard
        icon={<Lock size={14} />}
        title="Dangerous Perms"
        value={
          <div className="flex items-baseline gap-1">
            <span className="text-xl font-black mono text-red-400">{dangerousPerms.length}</span>
            <span className="text-xs text-slate-400">/ {totalPerms.length} total</span>
          </div>
        }
        subValue="Flagged high-risk permissions"
        accent={dangerousPerms.length > 3 ? '#ef4444' : '#eab308'}
      />

      {/* SHA-256 Hash */}
      <MetricCard
        icon={<Hash size={14} />}
        title="SHA-256 Checksum"
        value={<span className="mono text-xs text-cyan-300 block truncate">{shaShort}</span>}
        subValue={app_metadata.package_name || 'N/A'}
        accent="#22d3ee"
      />
    </div>
  );
}
