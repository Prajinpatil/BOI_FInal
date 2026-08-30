// src/utils/dataNormalizer.js
// Utility to convert any API response into the canonical NIRIKSHAK-AI Master JSON format
// and export analysis as STIX 2.1 Threat Intel bundle.

/**
 * Normalizes incoming raw analysis response (flat or structured) to Master JSON format.
 * @param {object} raw - Raw API response data
 * @param {File|null} file - Selected file object if available
 * @returns {object} Canonical Master JSON object
 */
export function normalizeToMasterJSON(raw, file = null) {
  if (!raw) return null;

  // Check if raw is already in Master JSON format
  if (raw.app_metadata && raw.risk_assessment) {
    return {
      app_metadata: {
        file_name: raw.app_metadata.file_name || file?.name || 'uploaded_sample.apk',
        package_name: raw.app_metadata.package_name || 'com.unknown.apk',
        sha256: raw.app_metadata.sha256 || '',
        timestamp: raw.app_metadata.timestamp || new Date().toISOString(),
        sdk_version: raw.app_metadata.sdk_version || 'Android (Target API Unknown)',
        file_size: raw.app_metadata.file_size || file?.size || 0,
      },
      static_analysis: {
        permissions: raw.static_analysis?.permissions || [],
        dangerous_permissions: raw.static_analysis?.dangerous_permissions || raw.static_analysis?.permissions?.filter(p => isDangerousPermission(p)) || [],
        target_detected: Boolean(raw.static_analysis?.target_detected),
        flagged_target: raw.static_analysis?.flagged_target || '',
        activities_count: raw.static_analysis?.activities_count ?? 0,
        services_count: raw.static_analysis?.services_count ?? 0,
        receivers_count: raw.static_analysis?.receivers_count ?? 0,
        providers_count: raw.static_analysis?.providers_count ?? 0,
      },
      genai_forensics: {
        semantic_score: Number(raw.genai_forensics?.semantic_score ?? 0.0),
        confidence: raw.genai_forensics?.confidence || 'MEDIUM',
        primary_exploit: raw.genai_forensics?.primary_exploit || 'UNKNOWN',
        forensic_narrative: raw.genai_forensics?.forensic_narrative || '',
      },
      dynamic_analysis: {
        network_iocs: raw.dynamic_analysis?.network_iocs || [],
        runtime_events: raw.dynamic_analysis?.runtime_events || [],
      },
      risk_assessment: {
        final_score: Number(raw.risk_assessment?.final_score ?? 0),
        severity_tier: raw.risk_assessment?.severity_tier || computeSeverityTier(raw.risk_assessment?.final_score ?? 0),
        recommended_action: raw.risk_assessment?.recommended_action || '',
        factor_breakdown: {
          p_ml: Number(raw.risk_assessment?.factor_breakdown?.p_ml ?? 0.0),
          s_semantic: Number(raw.risk_assessment?.factor_breakdown?.s_semantic ?? 0.0),
          s_dynamic: Number(raw.risk_assessment?.factor_breakdown?.s_dynamic ?? 0.0),
          target_bonus: Number(raw.risk_assessment?.factor_breakdown?.target_bonus ?? 0.0),
        },
      },
      iocs: raw.iocs || [],
      cert_analysis: raw.cert_analysis || {},
      mitre_techniques: raw.mitre_techniques || [],
    };
  }

  // Otherwise adapt flat response format into Master JSON shape
  // Backend sends a flat dict via _merge_analysis_data() with these exact field names:
  //   filename, package_name, target_sdk (int), file_size_bytes, sha256, timestamp,
  //   permissions, dangerous_permissions, activities_count, services_count, receivers_count, providers_count,
  //   target_detected, matched_targets, is_indian_vector,
  //   semantic_score, primary_exploit, forensic_narrative, confidence,
  //   final_score, severity_tier, breakdown, p_ml_contribution, semantic_contribution,
  //   dynamic_contribution, target_bonus_applied, recommended_action,
  //   iocs, cert_analysis, mitre_techniques

  const finalScore = Number(raw.final_score ?? raw.threat_score ?? 0);
  const permissions = raw.permissions || [];
  const dangerousPermissions = raw.dangerous_permissions || permissions.filter(p => isDangerousPermission(p));

  // target_detected is a direct boolean from backend; is_indian_vector is from semantic analysis
  const isTargetDetected = Boolean(raw.target_detected || raw.is_indian_vector);

  // Backend sends matched_targets (array) not flagged_target (string)
  const matchedTargets = raw.matched_targets || [];
  const flaggedTarget = raw.flagged_target
    || (matchedTargets.length > 0 ? matchedTargets.join(', ') : '')
    || (isTargetDetected ? 'Indian Banking / UPI Target Flagged' : '');

  // Build SDK version string from integer target_sdk (e.g. 33 → "Android API 33")
  const sdkVersion = raw.sdk_version
    || (raw.target_sdk != null ? `Android API ${raw.target_sdk}` : 'Unknown');

  // File size: backend uses file_size_bytes; browser File object uses size
  const fileSize = file?.size || raw.file_size_bytes || raw.file_size || 0;

  // Use backend timestamp directly; fall back to current time only if absent
  const analysisTimestamp = raw.timestamp || new Date().toISOString();

  // Extract factor breakdown from flat format or breakdown dictionary
  let factorBreakdown = { p_ml: 0.0, s_semantic: 0.0, s_dynamic: 0.0, target_bonus: 0.0 };
  if (raw.factor_breakdown) {
    // Already in Master JSON shape (pre-normalised)
    factorBreakdown = {
      p_ml: Number(raw.factor_breakdown.p_ml ?? 0.0),
      s_semantic: Number(raw.factor_breakdown.s_semantic ?? 0.0),
      s_dynamic: Number(raw.factor_breakdown.s_dynamic ?? 0.0),
      target_bonus: Number(raw.factor_breakdown.target_bonus ?? 0.0),
    };
  } else if (raw.breakdown != null || raw.p_ml_contribution != null) {
    // Backend flat format: *_contribution fields are already weighted POINTS (e.g. 34.9, 4.0, 15.6, 15.0)
    // Convert back to raw 0-1 fractions for the UI breakdown bars
    factorBreakdown = {
      p_ml:         Math.min(1.0, Number(raw.p_ml_contribution  || 0) / 35),
      s_semantic:   Math.min(1.0, Number(raw.semantic_contribution || 0) / 40),
      s_dynamic:    Math.min(1.0, Number(raw.dynamic_contribution  || 0) / 25),
      target_bonus: Number(raw.target_bonus_applied || 0) > 0 ? 0.05 : 0.0,
    };
  } else {
    // Last resort: estimate contributions from finalScore
    factorBreakdown = {
      p_ml:         Math.min(1.0, (finalScore * 0.35) / 35),
      s_semantic:   Math.min(1.0, (finalScore * 0.40) / 40),
      s_dynamic:    Math.min(1.0, (finalScore * 0.25) / 25),
      target_bonus: isTargetDetected ? 0.05 : 0.0,
    };
  }

  return {
    app_metadata: {
      // Backend key is "filename" not "file_name"; browser File.name takes priority
      file_name:    file?.name || raw.filename || raw.file_name || 'analyzed_sample.apk',
      // Keep actual backend value ("unknown" is a valid result, not an error)
      package_name: raw.package_name ?? 'unknown',
      sha256:       raw.sha256 || '',
      timestamp:    analysisTimestamp,
      sdk_version:  sdkVersion,
      file_size:    fileSize,
    },
    static_analysis: {
      permissions:          permissions,
      dangerous_permissions: dangerousPermissions,
      target_detected:      isTargetDetected,
      flagged_target:       flaggedTarget,
      // Use ?? 0 (not ?? 12/4/3/1) — backend always sends real counts, even if 0
      activities_count:  raw.activities_count  ?? 0,
      services_count:    raw.services_count    ?? 0,
      receivers_count:   raw.receivers_count   ?? 0,
      providers_count:   raw.providers_count   ?? 0,
    },
    genai_forensics: {
      // Backend key is "semantic_score" (0-1 float from Groq)
      semantic_score:    Number(raw.semantic_score ?? raw.s_semantic ?? 0.0),
      // "confidence" and "primary_exploit" are direct backend fields — no fake fallbacks
      confidence:        raw.confidence        || 'MEDIUM',
      primary_exploit:   raw.primary_exploit   || 'UNKNOWN',
      forensic_narrative: raw.forensic_narrative || '',
    },
    dynamic_analysis: {
      network_iocs:   raw.network_iocs   || [],
      runtime_events: raw.runtime_events || [],
    },
    risk_assessment: {
      final_score:        finalScore,
      severity_tier:      raw.severity_tier || computeSeverityTier(finalScore),
      recommended_action: raw.recommended_action || '',
      factor_breakdown:   factorBreakdown,
    },
    iocs:             raw.iocs            || [],
    cert_analysis:    raw.cert_analysis   || {},
    mitre_techniques: raw.mitre_techniques || [],
  };
}

const KNOWN_DANGEROUS_PERMISSIONS = new Set([
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.SEND_SMS',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.READ_CALL_LOG',
]);

function isDangerousPermission(perm) {
  if (!perm) return false;
  return KNOWN_DANGEROUS_PERMISSIONS.has(perm) || perm.includes('SMS') || perm.includes('ACCESSIBILITY') || perm.includes('ALERT');
}

export function computeSeverityTier(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

/**
 * Generates a STIX 2.1 compliant JSON bundle from Master JSON data.
 * @param {object} masterData - Master JSON analysis object
 * @returns {object} STIX 2.1 Bundle JSON object
 */
export function generateSTIX21Bundle(masterData) {
  const timestamp = new Date().toISOString();
  const pkg = masterData.app_metadata?.package_name || 'unknown.malware.apk';
  const sha256 = masterData.app_metadata?.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const score = masterData.risk_assessment?.final_score || 0;
  const severity = masterData.risk_assessment?.severity_tier || 'LOW';
  const exploit = masterData.genai_forensics?.primary_exploit || 'APK_MALWARE';

  const indicatorId = `indicator--${crypto.randomUUID ? crypto.randomUUID() : 'ind-nirikshak-001'}`;
  const malwareId = `malware--${crypto.randomUUID ? crypto.randomUUID() : 'mal-nirikshak-001'}`;

  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : 'bundle-nirikshak-001'}`,
    spec_version: '2.1',
    objects: [
      {
        type: 'indicator',
        spec_version: '2.1',
        id: indicatorId,
        created: timestamp,
        modified: timestamp,
        name: `NIRIKSHAK-AI Malicious APK: ${pkg}`,
        description: `Flagged by NIRIKSHAK-AI 5-Factor Risk Fusion (Score: ${score}/100 - ${severity}). Exploit: ${exploit}`,
        indicator_types: ['malicious-activity'],
        pattern: `[file:hashes.'SHA-256' = '${sha256}']`,
        pattern_type: 'stix',
        valid_from: timestamp,
        confidence: masterData.genai_forensics?.confidence === 'HIGH' ? 90 : 70,
        labels: ['mobile-banking-malware', 'androguard', 'groq-llama3', severity.toLowerCase()],
      },
      {
        type: 'malware',
        spec_version: '2.1',
        id: malwareId,
        created: timestamp,
        modified: timestamp,
        name: pkg,
        description: masterData.genai_forensics?.forensic_narrative || 'Mobile Banking Android Malware',
        malware_types: ['trojan', 'banking-trojan'],
        is_family: false,
        architecture_execution_envs: ['android'],
      },
      {
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${crypto.randomUUID ? crypto.randomUUID() : 'rel-nirikshak-001'}`,
        created: timestamp,
        modified: timestamp,
        relationship_type: 'indicates',
        source_ref: indicatorId,
        target_ref: malwareId,
      },
    ],
  };
}
