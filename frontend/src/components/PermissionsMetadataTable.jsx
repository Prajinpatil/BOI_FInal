// src/components/PermissionsMetadataTable.jsx
// Detailed App Metadata & Permission Analysis Table Component
import React, { useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  FileCode,
  HardDrive,
  Info,
  Lock,
  Package,
  ShieldAlert,
} from 'lucide-react';

export default function PermissionsMetadataTable({ appMetadata = {}, staticAnalysis = {} }) {
  const [copied, setCopied] = useState(false);
  const [showAllPerms, setShowAllPerms] = useState(false);

  const {
    file_name = 'sample.apk',
    package_name = 'com.example.app',
    sha256 = '',
    timestamp = '',
    sdk_version = 'Android API 33',
    file_size = 0,
  } = appMetadata;

  const {
    permissions = [],
    dangerous_permissions = [],
    activities_count = 0,
    services_count = 0,
    receivers_count = 0,
    providers_count = 0,
  } = staticAnalysis;

  const dangerousSet = new Set(
    dangerous_permissions.length > 0
      ? dangerous_permissions
      : permissions.filter((p) =>
          p.includes('SMS') ||
          p.includes('ACCESSIBILITY') ||
          p.includes('ALERT') ||
          p.includes('RECORD') ||
          p.includes('INSTALL')
        )
  );

  const displayPermissions = showAllPerms ? permissions : permissions.slice(0, 8);

  const handleCopyHash = () => {
    if (!sha256) return;
    navigator.clipboard.writeText(sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return 'N/A';
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(2)} MB (${bytes.toLocaleString()} bytes)`;
  };

  return (
    <div className="w-full flex flex-col gap-4">
      {/* App Metadata Panel */}
      <div className="p-4 rounded-xl glass-card flex flex-col gap-3">
        <div className="flex items-center gap-2 pb-2 border-b border-cyan-500/10">
          <Package size={16} className="text-cyan-400" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
            APK Metadata & Manifest Profile
          </span>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="flex flex-col gap-1 p-2.5 rounded bg-slate-900/60 border border-cyan-500/10">
            <span className="text-slate-400 font-medium">Package Identifier</span>
            <span className="mono font-bold text-cyan-300 text-[12px] truncate">
              {package_name}
            </span>
          </div>

          <div className="flex flex-col gap-1 p-2.5 rounded bg-slate-900/60 border border-cyan-500/10">
            <span className="text-slate-400 font-medium">Target SDK / API Level</span>
            <span className="mono font-bold text-slate-200 text-[12px]">
              {sdk_version}
            </span>
          </div>

          {/* SHA-256 with Copy button */}
          <div className="md:col-span-2 flex flex-col gap-1 p-2.5 rounded bg-slate-900/60 border border-cyan-500/10">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-medium">SHA-256 Checksum</span>
              <button
                onClick={handleCopyHash}
                className="flex items-center gap-1 text-[10px] mono text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 px-2 py-0.5 rounded transition"
                title="Copy full SHA-256 hash"
              >
                {copied ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                <span>{copied ? 'COPIED!' : 'COPY HASH'}</span>
              </button>
            </div>
            <span className="mono font-bold text-cyan-400 text-[11px] break-all select-all">
              {sha256 || 'N/A'}
            </span>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-cyan-500/10">
            <span className="text-slate-400">File Size</span>
            <span className="mono font-bold text-slate-200">{formatFileSize(file_size)}</span>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-cyan-500/10">
            <span className="text-slate-400">Analysis Timestamp</span>
            <span className="mono font-bold text-slate-300 text-[11px]">{timestamp || 'N/A'}</span>
          </div>
        </div>

        {/* Manifest Component Counts */}
        <div className="grid grid-cols-4 gap-2 pt-2">
          {[
            { label: 'Activities', count: activities_count },
            { label: 'Services', count: services_count },
            { label: 'Receivers', count: receivers_count },
            { label: 'Providers', count: providers_count },
          ].map((item) => (
            <div
              key={item.label}
              className="flex flex-col items-center p-2 rounded bg-slate-900/80 border border-cyan-500/10"
            >
              <span className="text-sm font-black mono text-cyan-400">{item.count}</span>
              <span className="text-[10px] text-slate-400 uppercase tracking-tight">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Permissions Breakdown Panel */}
      <div className="p-4 rounded-xl glass-card flex flex-col gap-3">
        <div className="flex items-center justify-between pb-2 border-b border-cyan-500/10">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className="text-red-400" />
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Declared Permissions Analysis
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs mono">
            <span className="px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 font-bold">
              {dangerousSet.size} DANGEROUS
            </span>
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              {permissions.length} TOTAL
            </span>
          </div>
        </div>

        {permissions.length === 0 ? (
          <p className="text-xs text-slate-500 py-3 text-center mono">No permissions declared in manifest.</p>
        ) : (
          <div className="flex flex-col gap-1.5">
            {displayPermissions.map((perm, idx) => {
              const isDangerous = dangerousSet.has(perm);
              const cleanPerm = perm.replace('android.permission.', '');

              return (
                <div
                  key={idx}
                  className={`flex items-center justify-between p-2 rounded text-xs mono transition ${
                    isDangerous
                      ? 'bg-red-500/10 border border-red-500/30 text-red-300 shadow-[0_0_10px_rgba(239,68,68,0.08)]'
                      : 'bg-slate-900/60 border border-cyan-500/10 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    {isDangerous ? (
                      <AlertTriangle size={13} className="text-red-400 flex-shrink-0" />
                    ) : (
                      <CheckCircle2 size={13} className="text-slate-500 flex-shrink-0" />
                    )}
                    <span className="truncate">{cleanPerm}</span>
                  </div>
                  {isDangerous && (
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 uppercase tracking-wider flex-shrink-0">
                      FLAGGED
                    </span>
                  )}
                </div>
              );
            })}

            {permissions.length > 8 && (
              <button
                onClick={() => setShowAllPerms((prev) => !prev)}
                className="mt-1 self-center text-xs mono text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 px-3 py-1 rounded transition"
              >
                {showAllPerms ? 'Show Less' : `View All ${permissions.length} Permissions`}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
