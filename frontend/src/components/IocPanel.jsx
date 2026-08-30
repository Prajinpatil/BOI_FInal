/* src/components/IocPanel.jsx
   NIRIKSHAK-AI :: Indicators of Compromise Panel */
import React, { useState } from 'react';
import { Globe, ChevronDown, ChevronUp, AlertTriangle, Copy, CheckCheck, FileText, X } from 'lucide-react';

const RISK_STYLES = {
  CRITICAL: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', badge: 'bg-red-500/20 text-red-300 border-red-500/30' },
  HIGH:     { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-300 border-orange-500/30' },
  MEDIUM:   { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30' },
};

const TYPE_ICONS = {
  IP_ADDRESS: '🌐',
  URL: '🔗',
  DOMAIN: '⚠️',
};

function CopyButton({ value }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={handleCopy}
      className="flex-shrink-0 p-1 rounded hover:bg-white/10 transition-colors text-slate-500 hover:text-slate-300"
      title="Copy IOC"
    >
      {copied ? <CheckCheck size={12} className="text-emerald-400" /> : <Copy size={12} />}
    </button>
  );
}

function TakedownModal({ ioc, onClose }) {
  const [copied, setCopied] = useState(false);
  
  const template = `SUBJECT: URGENT DMCA & Abuse Takedown Notice - Malicious Command & Control Server

To the Abuse / Legal Department,

We are reporting a critical cyber threat originating from your infrastructure. The following indicator has been confirmed by the NIRIKSHAK-AI Threat Intelligence Platform as an active Command & Control (C2) endpoint used by an Android Banking Trojan targeting financial institutions:

Malicious Indicator: ${ioc.value}
Indicator Type: ${ioc.type}
Risk Classification: ${ioc.risk_level} (${ioc.classification})
Timestamp (UTC): ${new Date().toISOString()}

This infrastructure is actively being used to intercept SMS OTPs, steal banking credentials, and facilitate unauthorized financial transactions.

We demand the immediate suspension of this service/domain to prevent further financial fraud, in accordance with international cybercrime laws and the IT Act 2000. 

Please confirm receipt of this notice and the action taken.

Sincerely,
NIRIKSHAK-AI Automated Response System
(Report to CERT-In / Cyber Cell India)`;

  const handleCopy = () => {
    navigator.clipboard.writeText(template).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 shadow-2xl rounded-xl overflow-hidden flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between p-4 border-b border-slate-700 bg-slate-800/50">
          <div className="flex items-center gap-2">
            <FileText size={18} className="text-red-400" />
            <span className="font-bold text-slate-200">Legal Takedown Notice Generator</span>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white rounded hover:bg-white/10 transition-colors">
            <X size={18} />
          </button>
        </div>
        
        <div className="p-4 flex-1 overflow-y-auto">
          <p className="text-xs text-slate-400 mb-3">
            Copy and send this template to the Domain Registrar or Hosting Provider (e.g. AWS, Cloudflare, GoDaddy) to request immediate infrastructure takedown.
          </p>
          <div className="relative">
            <textarea 
              readOnly
              value={template}
              className="w-full h-80 bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs mono text-slate-300 focus:outline-none focus:border-cyan-500/50 resize-none"
            />
          </div>
        </div>
        
        <div className="p-4 border-t border-slate-700 bg-slate-800/50 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white transition-colors">
            Cancel
          </button>
          <button 
            onClick={handleCopy}
            className="flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-xs font-bold rounded shadow-lg shadow-red-500/20 transition-all"
          >
            {copied ? <CheckCheck size={14} /> : <Copy size={14} />}
            {copied ? 'Copied to Clipboard!' : 'Copy Email Template'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function IocPanel({ iocs = [] }) {
  const [expanded, setExpanded] = useState(true);
  const [activeTakedown, setActiveTakedown] = useState(null);

  if (!iocs || iocs.length === 0) return null;

  const criticalCount = iocs.filter(i => i.risk_level === 'CRITICAL').length;
  const highCount = iocs.filter(i => i.risk_level === 'HIGH').length;

  return (
    <>
      <div className="glass-card rounded-xl overflow-hidden relative">
        {/* Header */}
        <button
          onClick={() => setExpanded(v => !v)}
          className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/30 flex items-center justify-center">
              <Globe size={16} className="text-orange-400" />
            </div>
            <div className="text-left">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                Indicators of Compromise
                <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-300 text-[10px] font-bold">
                  {iocs.length} IOCs
                </span>
              </div>
              <div className="text-[10px] text-slate-500 mono mt-0.5">
                {criticalCount > 0 && <span className="text-red-400 mr-2">● {criticalCount} C2 ENDPOINTS</span>}
                {highCount > 0 && <span className="text-orange-400">● {highCount} HIGH RISK</span>}
              </div>
            </div>
          </div>
          {expanded ? <ChevronUp size={16} className="text-slate-500" /> : <ChevronDown size={16} className="text-slate-500" />}
        </button>

        {/* IOC Table */}
        {expanded && (
          <div className="px-4 pb-4">
            <div className="rounded-lg border border-slate-700/50 overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-slate-800/60 border-b border-slate-700/50">
                    <th className="text-left px-3 py-2 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">Type</th>
                    <th className="text-left px-3 py-2 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">Indicator</th>
                    <th className="text-left px-3 py-2 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">Classification</th>
                    <th className="text-right px-3 py-2 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {iocs.map((ioc, i) => {
                    const style = RISK_STYLES[ioc.risk_level] || RISK_STYLES.MEDIUM;
                    return (
                      <tr key={i} className={`${style.bg} transition-colors hover:bg-white/5`}>
                        <td className="px-3 py-2 text-slate-400 mono">
                          <span className="mr-1">{TYPE_ICONS[ioc.type] || '·'}</span>
                          {ioc.type.replace('_', ' ')}
                        </td>
                        <td className="px-3 py-2 max-w-[200px]">
                          <div className="flex items-center gap-1">
                            <span className={`mono ${style.text} truncate text-[11px]`} title={ioc.value}>
                              {ioc.value}
                            </span>
                            <CopyButton value={ioc.value} />
                          </div>
                        </td>
                        <td className="px-3 py-2 text-slate-400">{ioc.classification}</td>
                        <td className="px-3 py-2 text-right">
                          {(ioc.type === 'IP_ADDRESS' || ioc.type === 'DOMAIN') ? (
                            <button 
                              onClick={() => setActiveTakedown(ioc)}
                              className="px-2 py-1 text-[9px] font-bold uppercase rounded bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/40 transition-colors flex items-center gap-1 ml-auto"
                            >
                              <FileText size={10} /> Takedown
                            </button>
                          ) : (
                            <span className={`px-1.5 py-0.5 rounded border text-[9px] font-black ${style.badge}`}>
                              {ioc.risk_level}
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <p className="text-[10px] text-slate-600 mt-2 text-right">
              Extracted from APK string constants · Issue Legal Takedowns directly
            </p>
          </div>
        )}
      </div>

      {activeTakedown && (
        <TakedownModal 
          ioc={activeTakedown} 
          onClose={() => setActiveTakedown(null)} 
        />
      )}
    </>
  );
}
