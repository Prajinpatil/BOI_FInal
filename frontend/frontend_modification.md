# NIRIKSHAK-AI — Comprehensive Frontend Modifications & Architecture Audit

This document provides an exhaustive **Before vs. After** comparison and technical breakdown of all changes made to the `nirikshak-ai/frontend` codebase under **Commit 1**.

---

## 📋 Executive Summary

The NIRIKSHAK-AI frontend was upgraded from an initial template prototype into a mature, enterprise-grade Security Operations Center (SOC) threat-intelligence dashboard. The platform now implements dense technical styling, an exact **Master JSON** data contract adapter, offline mock demo capabilities, client-side STIX 2.1 threat intelligence export, and dynamic forensic components.

---

## 🗂️ File Inventory & Modification Matrix

| File Path | Change Type | Purpose / Functionality |
| :--- | :--- | :--- |
| [`frontend_modification.md`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/frontend_modification.md) | **[NEW]** | Complete reference documentation of all frontend changes. |
| [`index.html`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/index.html) | **[PRESERVED]** | Head metadata & preconnected Google Fonts (`Inter` + `JetBrains Mono`). |
| [`src/index.css`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/index.css) | **[MODIFIED]** | Extended design tokens, dark slate backdrop, glassmorphism, alert card styles. |
| [`src/mocks/master_mock.json`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/mocks/master_mock.json) | **[NEW]** | Master JSON offline fixture (SBI YONO / UPI overlay Trojan sample). |
| [`src/utils/dataNormalizer.js`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/utils/dataNormalizer.js) | **[NEW]** | Adapter for Master JSON schema & STIX 2.1 JSON bundle exporter. |
| [`src/components/PipelineProgress.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/PipelineProgress.jsx) | **[NEW]** | Real-time 5-stage progress stepper with technical microcopy. |
| [`src/components/RiskFactorBreakdown.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/RiskFactorBreakdown.jsx) | **[NEW]** | 4-factor weighted score chart (ML 35%, GenAI 40%, Dynamic 25%, Bonus +15%). |
| [`src/components/IndianTargetBanner.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/IndianTargetBanner.jsx) | **[NEW]** | Deep red threat-intel alert banner for flagged Indian banking targets. |
| [`src/components/ForensicNarrative.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/ForensicNarrative.jsx) | **[NEW]** | Inset intelligence brief displaying LLM forensic reasoning & confidence. |
| [`src/components/PermissionsMetadataTable.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/PermissionsMetadataTable.jsx) | **[NEW]** | App Metadata Grid + copy-to-clipboard SHA-256 & dangerous permissions table. |
| [`src/components/ActionBar.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/ActionBar.jsx) | **[NEW]** | Sticky bottom footer for RBI PDF report & STIX 2.1 JSON export downloads. |
| [`src/components/AttackChainFlow.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/AttackChainFlow.jsx) | **[MODIFIED]** | Data-driven digital twin graph (`Install → Permission → Intercept → C2`). |
| [`src/components/MetricsGrid.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/MetricsGrid.jsx) | **[MODIFIED]** | Ingests Master JSON to display core security indicators. |
| [`src/components/ThreatGauge.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/components/ThreatGauge.jsx) | **[MODIFIED]** | Recharts 180° Arc gauge with tabular-nums font & severity color coding. |
| [`src/App.jsx`](file:///E:/web%20dev/BOI%20hackthon/nirikshak-ai/frontend/src/App.jsx) | **[MODIFIED]** | Dashboard shell, drag-and-drop APK upload, Demo Mock toggle, error handling. |

---

## 🔍 Detailed File-by-File "Before vs. After" Comparison

### 1. `src/index.css`

- **PREVIOUSLY**:
  - Contained generic background colors (`#0f172a` navy base).
  - Used standard `.glass-card` with simple background translucency.
  - Basic glow shadows and standard fonts without explicit tabular number support.

- **NOW**:
  - **Color Tokens**: Introduced `--bg-deep: #0a0f1a`, `--bg-surface: #0f172a`, `--border-red: rgba(239, 68, 68, 0.35)`, `--red-glow: rgba(239, 68, 68, 0.25)`.
  - **Background Texture**: Fixed gradient background (`linear-gradient(135deg, #0a0f1a 0%, #0f172a 100%)`) with a subtle 32px cyber grid texture.
  - **Glassmorphism**: Enhanced `.glass-card` (`rgba(15, 23, 42, 0.65)` with `16px` backdrop blur, `12px` rounded corners).
  - **Alert Styling**: Added `.glass-card-alert` featuring a deep red left border (`4px solid #ef4444`) and subtle red glow for dangerous states.
  - **Typography & Scrollbar**: Explicitly assigned `JetBrains Mono` and `Fira Code` as `--font-mono`. Set custom slate scrollbars.

---

### 2. `src/utils/dataNormalizer.js` **[NEW FILE]**

- **PREVIOUSLY**:
  - Did not exist. `App.jsx` directly read flat or inconsistent JSON properties (`p_ml_contribution`, `semantic_contribution`), causing potential crashes if key names varied.

- **NOW**:
  - **`normalizeToMasterJSON(raw, file)`**: Accepts any raw backend payload or uploaded file and returns guaranteed Master JSON structure:
    ```json
    {
      "app_metadata": { "file_name": "", "package_name": "", "sha256": "", "timestamp": "", "sdk_version": "", "file_size": 0 },
      "static_analysis": { "permissions": [], "dangerous_permissions": [], "target_detected": false, "flagged_target": "", "activities_count": 0, "services_count": 0, "receivers_count": 0, "providers_count": 0 },
      "genai_forensics": { "semantic_score": 0.0, "confidence": "HIGH", "primary_exploit": "", "forensic_narrative": "" },
      "dynamic_analysis": { "network_iocs": [], "runtime_events": [] },
      "risk_assessment": { "final_score": 0.0, "severity_tier": "CRITICAL", "recommended_action": "", "factor_breakdown": { "p_ml": 0.0, "s_semantic": 0.0, "s_dynamic": 0.0, "target_bonus": 0.0 } }
    }
    ```
  - **`generateSTIX21Bundle(masterData)`**: Client-side STIX 2.1 Threat Intel exporter producing standard STIX JSON bundles containing `indicator`, `malware`, and `relationship` nodes.
  - **`computeSeverityTier(score)`**: Helper calculating `CRITICAL` (>=80), `HIGH` (>=60), `MEDIUM` (>=35), `LOW` (<35).

---

### 3. `src/mocks/master_mock.json` **[NEW FILE]**

- **PREVIOUSLY**:
  - Did not exist. Demoing the frontend required an active FastAPI backend.

- **NOW**:
  - Contains a realistic Master JSON fixture representing an obfuscated Android malware sample targeting **SBI YONO / BHIM UPI** with an 89.5 `CRITICAL` threat score.

---

### 4. `src/components/PipelineProgress.jsx` **[NEW FILE]**

- **PREVIOUSLY**:
  - Inlined inside `App.jsx` as a basic text list with icons.

- **NOW**:
  - Standalone 5-stage stepper component representing the full analysis pipeline:
    1. **Static Analysis** (*"Parsing AndroidManifest.xml & permissions..."*)
    2. **AST Code Slicing** (*"Slicing AST paths & crypto reflection API calls..."*)
    3. **GenAI Semantic Analysis** (*"Establishing local LLM connection (Ollama)..."*)
    4. **Dynamic Sandbox** (*"Capturing dynamic IPC & network broadcast events..."*)
    5. **Risk Fusion & Compilation** (*"Computing 5-factor risk fusion & generating RBI report..."*)
  - Terse, technical microcopy for every stage.
  - Includes clean error recovery states so the stepper never gets stuck visually.

---

### 5. `src/components/RiskFactorBreakdown.jsx` **[NEW FILE]**

- **PREVIOUSLY**:
  - Represented by a small RadialBarChart inside `App.jsx` that did not show raw factor values or exact point contributions.

- **NOW**:
  - Horizontal bar breakdown breaking down the final threat score into its 4 weighted components:
    - **ML / Static Analysis**: 35% max weight
    - **GenAI Semantic (Ollama)**: 40% max weight
    - **Dynamic Sandbox (MobSF)**: 25% max weight
    - **Indian Target Vector Bonus**: +15% max weight (conditionally rendered only when triggered)
  - Displays both raw factor score (`0.0 - 1.0`) and actual calculated points out of 100.

---

### 6. `src/components/IndianTargetBanner.jsx` **[NEW FILE]**

- **PREVIOUSLY**:
  - Rendered as a simple line in `MetricsGrid.jsx`.

- **NOW**:
  - A prominent threat-intel alert banner displayed when `target_detected` is `true`.
  - Styled with deep red glow (`rgba(239, 68, 68, 0.2)`), a pulsing alert octagon icon, flagged target name (*"SBI YONO / BHIM UPI Banking Trojan Vector"*), and an **"RBI / CERT-In HIGH PRIORITY"** regulatory badge.

---

### 7. `src/components/AttackChainFlow.jsx`

- **PREVIOUSLY**:
  - Static 4-step sequence (`Install → Permission → OTP → C2`) with hardcoded step descriptions.

- **NOW**:
  - Dynamic, data-driven digital twin graph visualization.
  - Ingests `genai_forensics.primary_exploit`, `dynamic_analysis.runtime_events`, `dynamic_analysis.network_iocs`, and `static_analysis.dangerous_permissions` to dynamically construct node subtitles and technical details for each step.

---

### 8. `src/components/ForensicNarrative.jsx` **[NEW FILE]**

- **PREVIOUSLY**:
  - Embedded callout container in `App.jsx`.

- **NOW**:
  - Inset intelligence brief card displaying `genai_forensics.forensic_narrative`.
  - Styled with a cyan left accent border (`4px solid #22d3ee`), monospace `"AI FORENSIC ANALYSIS (qwen2.5-coder:7b)"` header, confidence badge (`HIGH`, `MEDIUM`, `LOW`), and confidential SOC footer annotations.

---

### 9. `src/components/PermissionsMetadataTable.jsx` **[NEW FILE]**

- **PREVIOUSLY**:
  - Simple permission list inside `App.jsx`.

- **NOW**:
  - **App Metadata Panel**: Displays package identifier, SDK version, file size, analysis timestamp, component count badges (Activities, Services, Receivers, Providers), and SHA-256 hash with a one-click **"COPY HASH"** button with copy confirmation feedback (`"COPIED!"`).
  - **Permissions Panel**: Highlights dangerous permissions (`READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `RECEIVE_SMS`, etc.) in red-tinted alert rows with `"FLAGGED"` badges. Includes a toggle to show/hide remaining standard permissions.

---

### 10. `src/components/ActionBar.jsx` **[NEW FILE]**

- **PREVIOUSLY**:
  - Inlined download button in `App.jsx` header and bottom CTA block.

- **NOW**:
  - Sticky bottom action bar containing two primary/secondary action buttons:
    - **"Download RBI/CERT-In Report"**: GET `/api/v1/download-report` streams PDF file.
    - **"Download STIX 2.1 Export"**: Downloads STIX 2.1 JSON threat-intel bundle.
  - Both buttons remain safely disabled until analysis completes.

---

### 11. `src/components/MetricsGrid.jsx` & `src/components/ThreatGauge.jsx`

- **PREVIOUSLY**:
  - Ingested flat fields; gauge numbers used standard font styling.

- **NOW**:
  - Ingests normalized Master JSON.
  - Displays Threat Score, Severity Tier badge, Indian Target status, Primary Exploit, Flagged Permissions count, and SHA-256 Checksum.
  - `ThreatGauge.jsx` updated to use Recharts 180° Arc gauge with tabular-nums monospace font, SVG drop-shadow filter, and slate-900 custom tooltip.

---

### 12. `src/App.jsx` Dashboard Shell

- **PREVIOUSLY**:
  - Monolithic component file (~967 lines) containing inline step simulations, radial bar charts, and flat API response ingestion.

- **NOW**:
  - Refactored shell (~430 lines) integrating all subcomponents cleanly.
  - **Mock Mode Toggle**: Added a **"MOCK MODE (ACTIVE)" / "REAL API MODE"** toggle in the top navbar allowing instant offline presentation and testing.
  - **Resilient Error Handling**: Preserves dark error card display for timeouts (180s), 400 Bad Request, 413 file size limit, and `ECONNREFUSED` connection errors.
  - **Accessibility**: Keyboard navigable via `Tab`, `Enter`, and `Space`.

---

## ⚡ Verification & Build Result

The application was validated via production build:
```bash
npm run build
```
- **Result**: `✓ built in 5.82s` with **0 build errors**, 0 broken imports, and 0 missing symbols.
