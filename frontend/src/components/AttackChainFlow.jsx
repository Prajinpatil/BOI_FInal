// src/components/AttackChainFlow.jsx
// Dynamic Digital Twin / State-Machine Attack Chain Visualizer
// Data-driven execution flow based on genai_forensics and dynamic_analysis payload
import React from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Download,
  Key,
  Lock,
  MessageSquare,
  Network,
  Radio,
  Server,
  ShieldAlert,
  Smartphone,
  Terminal,
  Zap,
} from 'lucide-react';

/**
 * Builds data-driven chain nodes from master JSON response
 */
function buildDynamicNodes(masterData) {
  const exploit = masterData?.genai_forensics?.primary_exploit || 'TROJAN_OVERLAY';
  const runtimeEvents = masterData?.dynamic_analysis?.runtime_events || [];
  const networkIocs = masterData?.dynamic_analysis?.network_iocs || [];
  const dangerousPerms = masterData?.static_analysis?.dangerous_permissions || [];

  // Default fallback nodes if data is basic
  const nodes = [
    {
      id: 'install',
      icon: Smartphone,
      label: 'Sideload / Install',
      sublabel: masterData?.app_metadata?.file_name || 'Trojan APK',
      color: '#22d3ee',
      detail: `Sideloaded APK (${masterData?.app_metadata?.package_name || 'com.malware.app'})`,
    },
    {
      id: 'permission',
      icon: Key,
      label: 'Permission Grant',
      sublabel: `${dangerousPerms.length} Flagged`,
      color: '#eab308',
      detail: dangerousPerms.length > 0 ? dangerousPerms.slice(0, 2).map(p => p.replace('android.permission.', '')).join(', ') : 'Requested SMS & Accessibility privileges',
    },
    {
      id: 'intercept',
      icon: MessageSquare,
      label: 'OTP / Window Intercept',
      sublabel: exploit.replace(/_/g, ' '),
      color: '#f97316',
      detail: runtimeEvents.length > 0 ? runtimeEvents[0] : 'Real-time SMS broadcast & UI window scraping',
    },
    {
      id: 'c2',
      icon: Server,
      label: 'C2 Exfiltration',
      sublabel: networkIocs.length > 0 ? 'Active IOC' : 'Remote Gateway',
      color: '#ef4444',
      detail: networkIocs.length > 0 ? networkIocs[0] : 'Credentials & 2FA tokens transmitted over encrypted channel',
    },
  ];

  return nodes;
}

export default function AttackChainFlow({ masterData = null, activeTier = 'LOW' }) {
  const nodes = buildDynamicNodes(masterData);

  const activeStepCount = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
  }[activeTier] ?? 4;

  return (
    <div className="w-full flex flex-col gap-4 p-4 rounded-xl glass-card">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert size={16} className="text-orange-400" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Digital Twin / Attack Chain Flow Graph
          </span>
        </div>
        {masterData?.genai_forensics?.primary_exploit && (
          <span className="text-[10px] mono font-bold px-2 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/30">
            {masterData.genai_forensics.primary_exploit}
          </span>
        )}
      </div>

      {/* Nodes Stepper Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 py-2">
        {nodes.map((node, idx) => {
          const isActive = idx < activeStepCount;
          const NodeIcon = node.icon;

          return (
            <div
              key={node.id}
              className={`relative flex flex-col p-3 rounded-lg border transition-all duration-300 ${
                isActive
                  ? 'bg-slate-900/90 border-slate-700 shadow-md'
                  : 'bg-slate-900/40 border-slate-800 opacity-50'
              }`}
              style={{
                borderColor: isActive ? `${node.color}50` : 'transparent',
                boxShadow: isActive ? `0 0 15px ${node.color}15` : 'none',
              }}
            >
              {/* Step Number & Connector */}
              <div className="flex items-center justify-between mb-2">
                <div
                  className="flex items-center justify-center w-8 h-8 rounded-lg border"
                  style={{
                    backgroundColor: isActive ? `${node.color}15` : 'rgba(30,41,59,0.5)',
                    borderColor: isActive ? node.color : '#334155',
                    color: isActive ? node.color : '#64748b',
                  }}
                >
                  <NodeIcon size={16} />
                </div>
                <span
                  className="text-[10px] mono font-bold px-1.5 py-0.5 rounded"
                  style={{
                    backgroundColor: isActive ? node.color : '#334155',
                    color: isActive ? '#0f172a' : '#94a3b8',
                  }}
                >
                  STEP 0{idx + 1}
                </span>
              </div>

              {/* Node Title & Subtitle */}
              <h4 className="text-xs font-bold text-slate-200 truncate">{node.label}</h4>
              <p className="text-[10px] mono text-slate-400 truncate mt-0.5">{node.sublabel}</p>

              {/* Detail */}
              <p className="text-[11px] text-slate-300/80 mt-2 pt-2 border-t border-slate-800 leading-snug">
                {node.detail}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
