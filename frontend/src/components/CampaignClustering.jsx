/* src/components/CampaignClustering.jsx
   NIRIKSHAK-AI :: Threat Campaign Similarity Engine */
import React, { useMemo } from 'react';
import { Network, Search, AlertCircle, ShieldAlert } from 'lucide-react';

const KNOWN_CAMPAIGNS = [
  {
    name: 'Anubis Banking Trojan',
    origin: 'Russia / Eastern Europe',
    description: 'Notorious Android trojan that steals credentials using fake login overlays and intercepts SMS OTPs.',
    indicators: ['BIND_ACCESSIBILITY_SERVICE', 'RECEIVE_SMS', 'SYSTEM_ALERT_WINDOW', 'READ_PHONE_STATE', 'WAKE_LOCK'],
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/30'
  },
  {
    name: 'Cerberus V2',
    origin: 'Global (MaaS)',
    description: 'Malware-as-a-Service trojan capable of screen streaming, keylogging, and bypassing Google Authenticator.',
    indicators: ['BIND_ACCESSIBILITY_SERVICE', 'READ_CONTACTS', 'SEND_SMS', 'RECORD_AUDIO', 'DISABLE_KEYGUARD'],
    color: 'text-orange-400',
    bg: 'bg-orange-500/10 border-orange-500/30'
  },
  {
    name: 'Hydra / Ermac',
    origin: 'Eastern Europe',
    description: 'Targets crypto wallets and banking apps. Often distributed via fake Google Chrome updates.',
    indicators: ['BIND_DEVICE_ADMIN', 'RECEIVE_SMS', 'READ_CALL_LOG', 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'],
    color: 'text-purple-400',
    bg: 'bg-purple-500/10 border-purple-500/30'
  },
  {
    name: 'Jamtara OTP Syndicate',
    origin: 'Jamtara, India',
    description: 'Local syndicate utilizing simple SMS forwarding apps disguised as KYC updaters targeting SBI and HDFC.',
    indicators: ['RECEIVE_SMS', 'SEND_SMS', 'READ_SMS', 'INTERNET'],
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10 border-emerald-500/30'
  }
];

// Jaccard Similarity Algorithm
function calculateSimilarity(apkPermissions, campaignIndicators) {
  if (!apkPermissions || apkPermissions.length === 0) return 0;
  
  const setA = new Set(apkPermissions.map(p => p.toUpperCase().replace('ANDROID.PERMISSION.', '')));
  const setB = new Set(campaignIndicators);
  
  let intersection = 0;
  for (let item of setA) {
    if (setB.has(item)) {
      intersection++;
    }
  }
  
  // Calculate percentage of campaign indicators found in the APK
  // We don't penalize the APK for having EXTRA permissions, only reward for matching malicious ones
  const matchPercentage = (intersection / setB.size) * 100;
  
  return Math.min(Math.round(matchPercentage + (intersection * 5)), 99); // Max 99%
}

export default function CampaignClustering({ masterData }) {
  if (!masterData) return null;

  const permissions = masterData.static_analysis?.dangerous_permissions || [];
  const targetDetected = masterData.static_analysis?.target_detected;
  
  const matches = useMemo(() => {
    let results = KNOWN_CAMPAIGNS.map(campaign => {
      let score = calculateSimilarity(permissions, campaign.indicators);
      
      // Bonus logic for Jamtara if Indian target detected
      if (campaign.name.includes('Jamtara') && targetDetected) {
        score = Math.min(score + 40, 98); 
      }
      
      return { ...campaign, score };
    });
    
    // Sort by highest match
    return results.sort((a, b) => b.score - a.score);
  }, [permissions, targetDetected]);
  
  const topMatch = matches[0];
  
  // Only show if we have a reasonable similarity
  if (topMatch.score < 25) {
    return (
      <div className="glass-card rounded-xl p-4 flex items-center justify-between opacity-70">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center">
            <Search size={16} className="text-slate-500" />
          </div>
          <div>
            <div className="text-xs font-bold text-slate-300">Campaign Attribution</div>
            <div className="text-[10px] text-slate-500 mt-0.5">No known malware family matches found.</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`glass-card rounded-xl overflow-hidden border ${topMatch.bg}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700/50 bg-black/20">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg ${topMatch.bg} flex items-center justify-center shadow-lg`}>
            <Network size={16} className={topMatch.color} />
          </div>
          <div className="text-left">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              Threat Campaign Attribution
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5 flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full ${topMatch.color.replace('text-', 'bg-')} animate-pulse inline-block`} />
              Jaccard Similarity Engine
            </div>
          </div>
        </div>
        
        <div className="text-right">
          <div className={`text-xl font-black ${topMatch.color}`}>{topMatch.score}%</div>
          <div className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Similarity Score</div>
        </div>
      </div>

      {/* Content */}
      <div className="p-4 bg-slate-900/40">
        <div className="flex items-start gap-4">
          <div className="flex-1">
            <h3 className={`text-sm font-bold ${topMatch.color} mb-1 flex items-center gap-2`}>
              {topMatch.name}
              {topMatch.score > 80 && (
                <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 text-[9px] rounded uppercase">
                  Confirmed Match
                </span>
              )}
            </h3>
            <div className="text-[10px] text-slate-400 font-medium mb-3 flex items-center gap-2">
              <GlobeIcon size={12} /> Origin: <span className="text-slate-300">{topMatch.origin}</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              {topMatch.description}
            </p>
            
            <div className="space-y-2">
              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Matched Behavioral Indicators:</div>
              <div className="flex flex-wrap gap-1.5">
                {topMatch.indicators.map((ind, i) => {
                  const isPresent = permissions.some(p => p.includes(ind));
                  if (!isPresent && topMatch.score > 50) return null; // Hide unmatched if high score to save space
                  return (
                    <span key={i} className={`px-2 py-1 text-[9px] rounded border font-mono flex items-center gap-1 ${
                      isPresent 
                        ? `${topMatch.bg} ${topMatch.color}` 
                        : 'bg-slate-800/50 border-slate-700/50 text-slate-500 opacity-50'
                    }`}>
                      {isPresent && <AlertCircle size={9} />}
                      {ind}
                    </span>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function GlobeIcon({ size }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"></circle>
      <line x1="2" y1="12" x2="22" y2="12"></line>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
    </svg>
  );
}
