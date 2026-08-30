// src/App.jsx
// NIRIKSHAK-AI :: Mobile Banking Malware Analysis SOC Dashboard
import React, { useCallback, useRef, useState } from 'react';
import axios from 'axios';
import {
  Activity,
  AlertOctagon,
  Brain,
  CheckCircle2,
  CloudUpload,
  Eye,
  FileSearch,
  FileText,
  Fingerprint,
  Loader2,
  Mail,
  Phone,
  Play,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  Terminal,
  Zap,
} from 'lucide-react';

import ThreatGauge from './components/ThreatGauge.jsx';
import AttackChainFlow from './components/AttackChainFlow.jsx';
import MetricsGrid from './components/MetricsGrid.jsx';
import PipelineProgress, { PIPELINE_STAGES } from './components/PipelineProgress.jsx';
import RiskFactorBreakdown from './components/RiskFactorBreakdown.jsx';
import ForensicNarrative from './components/ForensicNarrative.jsx';
import PermissionsMetadataTable from './components/PermissionsMetadataTable.jsx';
import IndianTargetBanner from './components/IndianTargetBanner.jsx';
import ActionBar from './components/ActionBar.jsx';
import MitrePanel from './components/MitrePanel.jsx';
import IocPanel from './components/IocPanel.jsx';
import CertCard from './components/CertCard.jsx';
import ChatBot from './components/ChatBot.jsx';
import CampaignClustering from './components/CampaignClustering.jsx';

import { generateSTIX21Bundle, normalizeToMasterJSON } from './utils/dataNormalizer.js';

const API_BASE = 'http://localhost:8001';

const TICKER_ITEMS = [
  'RBI CSIR COMPLIANCE ACTIVE',
  'CERT-In GUIDELINES ALIGNED',
  'NPCI FRAUD VECTORS MONITORED',
  'UPI THREAT SIGNATURES UPDATED',
  'GROQ AI llama-3.3-70b ACTIVE',
  '5-FACTOR FUSION ENGINE READY',
  'ANDROGUARD STATIC ENGINE LOADED',
  'MITRE ATT&CK MOBILE MAPPED',
  'VIRUSTOTAL SANDBOX INTEGRATED',
  'IOC EXTRACTION ENGINE ONLINE',
  'CYBER CELL REPORTING READY',
];

function SeverityBadge({ tier }) {
  const configs = {
    CRITICAL: { cls: 'badge-critical', label: 'CRITICAL' },
    HIGH:     { cls: 'badge-high',     label: 'HIGH' },
    MEDIUM:   { cls: 'badge-medium',   label: 'MEDIUM' },
    LOW:      { cls: 'badge-low',      label: 'LOW' },
  };
  const cfg = configs[tier] || configs.LOW;
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold ${cfg.cls}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current inline-block animate-pulse" />
      {cfg.label}
    </span>
  );
}

export default function App() {
  const [dragActive, setDragActive]           = useState(false);
  const [selectedFile, setSelectedFile]       = useState(null);
  const [isAnalyzing, setIsAnalyzing]         = useState(false);
  const [currentStage, setCurrentStage]       = useState(1);
  const [pipelineComplete, setPipelineComplete] = useState(false);
  const [masterData, setMasterData]           = useState(null);
  const [error, setError]                     = useState(null);
  const [isDownloadingPDF, setIsDownloadingPDF] = useState(false);

  const fileInputRef  = useRef(null);
  const stageTimerRef = useRef(null);

  const tickerText = TICKER_ITEMS.join('   ◈   ');

  // ── File validation ────────────────────────────────────────────────
  const validateFile = (file) => {
    if (!file) return 'No file selected';
    if (!file.name.toLowerCase().endsWith('.apk')) return 'Only .apk files are accepted';
    if (file.size > 150 * 1024 * 1024) return 'File too large. Max limit is 150MB';
    if (file.size < 1024) return 'File too small — corrupted APK';
    return null;
  };

  // ── Drag & drop ────────────────────────────────────────────────────
  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(e.type === 'dragenter' || e.type === 'dragover');
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      const err = validateFile(file);
      if (err) { setError(err); return; }
      setSelectedFile(file);
      setError(null);
    }
  }, []);

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      const err = validateFile(file);
      if (err) { setError(err); return; }
      setSelectedFile(file);
      setError(null);
      setMasterData(null);
      setPipelineComplete(false);
    }
  };

  // ── Pipeline animation ─────────────────────────────────────────────
  const runPipelineAnimation = (onComplete) => {
    let stage = 1;
    setCurrentStage(1);
    const advance = () => {
      if (stage < PIPELINE_STAGES.length) {
        stage++;
        setCurrentStage(stage);
        stageTimerRef.current = setTimeout(advance, PIPELINE_STAGES[stage - 1].duration);
      } else {
        if (onComplete) onComplete();
      }
    };
    stageTimerRef.current = setTimeout(advance, PIPELINE_STAGES[0].duration);
  };

  // ── Analyze ────────────────────────────────────────────────────────
  const handleAnalyze = async () => {
    if (!selectedFile) return;
    setIsAnalyzing(true);
    setError(null);
    setMasterData(null);
    setPipelineComplete(false);

    runPipelineAnimation();

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      const response = await axios.post(`${API_BASE}/api/v1/analyze`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 900000, // 15 min — allows for huge APKs & VT sandbox polling
      });

      clearTimeout(stageTimerRef.current);
      setCurrentStage(5);
      await new Promise((r) => setTimeout(r, 500));

      const normalized = normalizeToMasterJSON(response.data?.analysis || response.data, selectedFile);
      setMasterData(normalized);
      setPipelineComplete(true);
    } catch (err) {
      clearTimeout(stageTimerRef.current);
      setPipelineComplete(false);

      if (err.code === 'ECONNREFUSED' || err.message?.includes('Network Error')) {
        setError('Cannot connect to NIRIKSHAK-AI backend at localhost:8001. Start backend server: python -m backend.main');
      } else if (err.response?.status === 400) {
        setError(`Invalid APK payload: ${err.response.data?.detail || 'Upload rejected'}`);
      } else if (err.response?.status === 413) {
        setError('APK file exceeds 150MB limit.');
      } else if (err.code === 'ECONNABORTED') {
        setError('Analysis timed out. The VirusTotal Sandbox may still be processing — try again shortly.');
      } else {
        setError(err.response?.data?.detail || err.message || 'Unknown analysis error');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  // ── PDF Download ───────────────────────────────────────────────────
  const handleDownloadPDF = async () => {
    if (!pipelineComplete && !masterData) return;
    setIsDownloadingPDF(true);
    try {
      const response = await axios.get(`${API_BASE}/api/v1/download-report`, {
        responseType: 'blob',
        timeout: 30000,
      });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url  = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href  = url;
      const disposition = response.headers['content-disposition'] || '';
      const match = disposition.match(/filename="?([^";\\n]+)"?/);
      link.download = match ? match[1] : `NIRIKSHAK_Report_${masterData?.app_metadata?.package_name || 'analysis'}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch {
      const txt = `NIRIKSHAK-AI FORENSIC REPORT\nFile: ${masterData?.app_metadata?.file_name}\nScore: ${masterData?.risk_assessment?.final_score}/100\nGenerated: ${new Date().toISOString()}`;
      const blob = new Blob([txt], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href  = url;
      link.download = `NIRIKSHAK_Report_${masterData?.app_metadata?.file_name || 'sample'}.txt`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } finally {
      setIsDownloadingPDF(false);
    }
  };

  // ── STIX Export ────────────────────────────────────────────────────
  const handleDownloadSTIX = () => {
    if (!masterData) return;
    const stixBundle = generateSTIX21Bundle(masterData);
    const jsonStr    = JSON.stringify(stixBundle, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href  = url;
    link.download = `STIX2.1_${masterData?.app_metadata?.package_name || 'malware'}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // ── Report to Cyber Cell India ─────────────────────────────────────
  const handleReportCyberCell = () => {
    if (!masterData) return;
    const ra  = masterData.risk_assessment  || {};
    const sa  = masterData.static_analysis  || {};
    const gf  = masterData.genai_forensics  || {};
    const meta = masterData.app_metadata    || {};

    const subject = encodeURIComponent(
      `[NIRIKSHAK-AI] Malicious APK Report — ${meta.file_name || 'Unknown'} — ${ra.severity_tier || 'HIGH'} Risk`
    );
    const iocList = (masterData.iocs || []).slice(0, 5).map(i => `  - [${i.type}] ${i.value} (${i.classification})`).join('\n');
    const mitreList = (masterData.mitre_techniques || []).slice(0, 5).map(t => `  - ${t.technique_id}: ${t.technique_name} (${t.tactic})`).join('\n');

    const body = encodeURIComponent(
`NIRIKSHAK-AI Automated Malware Analysis Report
================================================
Generated: ${new Date().toUTCString()}
Platform: NIRIKSHAK-AI — Generative AI-Based APK Analysis System

--- APPLICATION DETAILS ---
File Name:       ${meta.file_name || 'N/A'}
Package Name:    ${meta.package_name || 'N/A'}
SHA-256:         ${meta.sha256 || 'N/A'}
File Size:       ${meta.file_size ? (meta.file_size / 1024 / 1024).toFixed(2) + ' MB' : 'N/A'}
Analysis Date:   ${meta.timestamp || new Date().toUTCString()}

--- THREAT ASSESSMENT ---
Threat Score:    ${ra.final_score || 0}/100
Severity:        ${ra.severity_tier || 'UNKNOWN'}
Primary Exploit: ${gf.primary_exploit || 'UNKNOWN'}
AI Confidence:   ${gf.confidence || 'N/A'}
Indian Target:   ${sa.target_detected ? 'YES — ' + sa.flagged_target : 'Not detected'}

--- DANGEROUS PERMISSIONS ---
${(sa.dangerous_permissions || []).map(p => '  - ' + p).join('\n') || '  None detected'}

--- AI FORENSIC NARRATIVE ---
${gf.forensic_narrative || 'Not available'}

--- INDICATORS OF COMPROMISE (IOCs) ---
${iocList || '  None extracted'}

--- MITRE ATT&CK MOBILE TECHNIQUES ---
${mitreList || '  None mapped'}

--- RECOMMENDED ACTION ---
${ra.recommended_action || 'Manual review required'}

--- HOW TO REPORT ---
1. Visit: https://cybercrime.gov.in
2. Call: 1930 (National Cyber Crime Helpline)
3. Attach this email and the NIRIKSHAK-AI PDF report
4. Reference SHA-256: ${meta.sha256 || 'N/A'}

This report was auto-generated by NIRIKSHAK-AI.
`);

    window.open(`mailto:cybercell@nic.in?subject=${subject}&body=${body}`, '_blank');
  };

  // ── Reset ──────────────────────────────────────────────────────────
  const handleReset = () => {
    setSelectedFile(null);
    setMasterData(null);
    setError(null);
    setCurrentStage(1);
    setPipelineComplete(false);
    setIsAnalyzing(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const severity = masterData?.risk_assessment?.severity_tier || 'LOW';
  const isCriticalOrHigh = ['CRITICAL', 'HIGH'].includes(severity);

  return (
    <div className="min-h-screen cyber-grid flex flex-col justify-between text-slate-100">

      {/* ── Cyber Crime Helpline Banner ─────────────────────────────── */}
      <div className="bg-red-950/60 border-b border-red-500/20 px-6 py-1.5 flex items-center justify-center gap-6 text-[11px]">
        <span className="flex items-center gap-1.5 text-red-300 font-semibold mono">
          <Phone size={11} className="text-red-400" />
          CYBER CRIME HELPLINE: <a href="tel:1930" className="text-red-200 font-black underline hover:text-white">1930</a>
        </span>
        <span className="text-slate-600">|</span>
        <span className="flex items-center gap-1.5 text-slate-400">
          Report at:
          <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer"
            className="text-cyan-400 hover:text-cyan-300 underline">cybercrime.gov.in</a>
        </span>
        <span className="text-slate-600">|</span>
        <span className="text-slate-500">CERT-In · RBI CSIR · NPCI Compliant</span>
      </div>

      {/* ── Top Navigation Bar ──────────────────────────────────────── */}
      <nav className="sticky top-0 z-50 flex items-center justify-between px-6 py-3 bg-slate-950/90 backdrop-blur-xl border-b border-cyan-500/15 shadow-lg">
        {/* Brand Logo */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Shield size={20} />
          </div>
          <div>
            <div className="font-black text-sm tracking-widest text-cyan-400 mono">NIRIKSHAK-AI</div>
            <div className="text-[10px] text-slate-400 tracking-wider uppercase mono">
              MOBILE BANKING MALWARE ANALYSIS PLATFORM
            </div>
          </div>
        </div>

        {/* System Badges */}
        <div className="flex items-center gap-4 text-xs">
          <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-cyan-500/20">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="mono text-[11px] text-slate-300">SOC Engine Online</span>
          </div>

          <div className="hidden md:flex items-center gap-1.5 mono text-slate-400 text-[11px]">
            <Radio size={13} className="text-cyan-400 animate-pulse" />
            <span>Groq AI llama-3.3-70b</span>
          </div>

          {masterData && <SeverityBadge tier={severity} />}
        </div>
      </nav>

      {/* ── Security Intel Ticker ────────────────────────────────────── */}
      <div className="ticker-wrapper py-1.5 bg-cyan-500/5 border-b border-cyan-500/10">
        <div className="ticker-content text-xs mono text-cyan-400/80 tracking-widest">
          {`${tickerText}   ◈   ${tickerText}`}
        </div>
      </div>

      {/* ── Main Container ───────────────────────────────────────────── */}
      <main className="max-w-7xl w-full mx-auto px-4 py-6 space-y-6 flex-1">

        {/* Header Title Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black tracking-tight text-slate-100 flex items-center gap-2">
              Threat Intelligence Analysis Dashboard
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              GenAI-Powered APK Forensics · Static AST Slicing · MITRE ATT&amp;CK Mapping · 5-Factor Risk Fusion · Cloud Sandbox
            </p>
          </div>

          {/* Report to Cyber Cell Button */}
          {masterData && isCriticalOrHigh && (
            <button
              onClick={handleReportCyberCell}
              id="btn-report-cybercell"
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-bold hover:bg-red-500/25 transition-all hover:scale-105"
            >
              <Mail size={14} />
              Report to Cyber Cell India
            </button>
          )}

          {masterData && (
            <button onClick={handleReset} className="btn-secondary text-xs py-2 px-3" id="btn-reset">
              <RefreshCw size={13} />
              New Analysis
            </button>
          )}
        </div>

        {/* ── Two-Column Layout ────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

          {/* ── LEFT PANEL ──────────────────────────────────────────── */}
          <div className="lg:col-span-2 flex flex-col gap-4">

            {/* Upload Zone */}
            <div
              id="drop-zone"
              className={`drop-zone p-6 cursor-pointer text-center ${dragActive ? 'drag-active' : ''}`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => !isAnalyzing && fileInputRef.current?.click()}
              role="button"
              tabIndex={0}
              aria-label="Upload APK for security analysis"
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk,.zip,application/vnd.android.package-archive,*"
                className="hidden"
                id="apk-file-input"
                onChange={handleFileChange}
              />
              <div className="flex flex-col items-center gap-3">
                <div className="w-14 h-14 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  {selectedFile ? <FileText size={26} /> : <CloudUpload size={26} />}
                </div>
                {selectedFile ? (
                  <div>
                    <h3 className="font-bold text-sm text-slate-200 truncate max-w-xs">{selectedFile.name}</h3>
                    <p className="text-xs text-slate-400 mono mt-0.5">
                      {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                    </p>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleReset(); }}
                      className="mt-2 text-xs text-red-400 hover:text-red-300 underline"
                    >
                      Remove File
                    </button>
                  </div>
                ) : (
                  <div>
                    <h3 className="font-bold text-sm text-slate-200">Submit Android APK File</h3>
                    <p className="text-xs text-slate-400 mt-1">Drag &amp; drop suspicious .apk or click to browse</p>
                    <span className="inline-block mt-2 px-2.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 mono text-[10px]">
                      Max 150MB · Androguard + Groq AI + VirusTotal Sandbox
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Error Display */}
            {error && (
              <div className="glass-card-alert p-4 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-red-400 font-bold text-xs">
                  <AlertOctagon size={16} />
                  <span>ANALYSIS ERROR DETECTED</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">{error}</p>
                <button
                  onClick={handleReset}
                  className="btn-secondary text-xs py-1.5 px-3 border-red-500/30 text-red-300 hover:bg-red-500/10 self-start"
                >
                  <RefreshCw size={12} /> Retry Upload
                </button>
              </div>
            )}

            {/* Analyze Button */}
            {selectedFile && !isAnalyzing && !masterData && (
              <button
                id="btn-analyze"
                onClick={handleAnalyze}
                className="btn-primary w-full py-3 text-sm justify-center"
              >
                <Eye size={18} />
                <span>Execute APK Malware Analysis</span>
              </button>
            )}

            {/* Pipeline Stepper */}
            {(isAnalyzing || pipelineComplete) && (
              <PipelineProgress
                currentStage={currentStage}
                isComplete={pipelineComplete}
                error={error}
              />
            )}

            {/* Threat Gauge & Score Breakdown */}
            {masterData && (
              <>
                <div className="p-4 rounded-xl glass-card flex flex-col items-center gap-3">
                  <div className="w-full flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                      <Fingerprint size={15} className="text-cyan-400" /> Computed Threat Score
                    </span>
                    <SeverityBadge tier={severity} />
                  </div>
                  <ThreatGauge
                    score={masterData.risk_assessment.final_score}
                    severity={severity}
                    size={220}
                  />
                </div>

                <RiskFactorBreakdown
                  factorBreakdown={masterData.risk_assessment.factor_breakdown}
                  finalScore={masterData.risk_assessment.final_score}
                />

                {/* Certificate Card */}
                <CertCard certAnalysis={masterData.cert_analysis || {}} />
              </>
            )}
          </div>

          {/* ── RIGHT PANEL ─────────────────────────────────────────── */}
          <div className="lg:col-span-3 flex flex-col gap-4">

            {/* Empty State */}
            {!isAnalyzing && !masterData && (
              <div className="glass-card p-12 flex flex-col items-center justify-center text-center gap-6 min-h-[420px]">
                <div className="w-24 h-24 rounded-full bg-cyan-500/5 border border-cyan-500/20 flex items-center justify-center text-cyan-400/40">
                  <Shield size={48} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-slate-300">Awaiting Android APK Submission</h3>
                  <p className="text-xs text-slate-500 mt-2 max-w-md leading-relaxed">
                    Upload a suspicious APK to initiate multi-layer analysis: static code parsing, Groq AI semantic decompilation, XGBoost ML classification, VirusTotal cloud sandbox, IOC extraction, and MITRE ATT&amp;CK mapping.
                  </p>
                </div>
                <div className="flex flex-wrap justify-center gap-3 text-[11px] text-slate-500 mono">
                  {['Groq AI', 'XGBoost ML', 'Androguard', 'MITRE ATT&CK', 'VirusTotal'].map(label => (
                    <span key={label} className="px-2.5 py-1 rounded-full bg-slate-800/60 border border-slate-700/40 text-slate-400">
                      ● {label}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Results Display */}
            {masterData && (
              <>
                {/* Indian Target Banner */}
                <IndianTargetBanner
                  targetDetected={masterData.static_analysis.target_detected}
                  flaggedTarget={masterData.static_analysis.flagged_target}
                />

                {/* Metrics Grid */}
                <MetricsGrid masterData={masterData} />

                {/* Attack Chain Flow */}
                <AttackChainFlow masterData={masterData} activeTier={severity} />

                {/* Threat Campaign Attribution */}
                <CampaignClustering masterData={masterData} />

                {/* MITRE ATT&CK Panel */}
                <MitrePanel techniques={masterData.mitre_techniques || []} />

                {/* IOC Panel */}
                <IocPanel iocs={masterData.iocs || []} />

                {/* Forensic Narrative */}
                <ForensicNarrative
                  narrative={masterData.genai_forensics.forensic_narrative}
                  confidence={masterData.genai_forensics.confidence}
                />

                {/* Permissions & Metadata Table */}
                <PermissionsMetadataTable
                  appMetadata={masterData.app_metadata}
                  staticAnalysis={masterData.static_analysis}
                />
              </>
            )}
          </div>
        </div>
      </main>

      {/* ── Sticky Action Buttons Footer ───────────────────────────── */}
      <ActionBar
        onDownloadReport={handleDownloadPDF}
        onDownloadSTIX={handleDownloadSTIX}
        isDownloading={isDownloadingPDF}
        isComplete={pipelineComplete}
        severity={severity}
      />

      {/* ── Groq AI Security Chatbot ────────────────────────────────── */}
      <ChatBot masterData={masterData} />
    </div>
  );
}
