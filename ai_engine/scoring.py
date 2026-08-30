# ai_engine/scoring.py
"""
NIRIKSHAK-AI :: 5-Factor Risk Fusion Engine
Implements the deterministic weighted scoring formula to compute a final
0–100 threat score from static, semantic, and dynamic analysis signals.

Formula:
  Final Score = min(100, 100 * (0.35 * P_ML + 0.40 * S_semantic + 0.25 * S_dynamic + Target_Bonus))
  Target_Bonus = 0.15 if target_detected is True, else 0.0
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
import json
import os
import math
from threading import Lock

try:
    import numpy as np
except Exception:
    np = None

try:
    import xgboost as xgb
except Exception:
    xgb = None

# Model & metadata cache (thread-safe)
_MODEL_LOCK = Lock()
_XGB_MODEL = None
_MODEL_METADATA = None
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "xgb_cicmaldroid.json")
_METADATA_PATH = os.path.join(os.path.dirname(__file__), "models", "xgb_cicmaldroid_metadata.json")


def _load_model_and_metadata():
    """Load XGBoost model and metadata (cached). Returns (booster, metadata_dict) or (None, None) on failure."""
    global _XGB_MODEL, _MODEL_METADATA
    if _XGB_MODEL is not None and _MODEL_METADATA is not None:
        return _XGB_MODEL, _MODEL_METADATA

    with _MODEL_LOCK:
        if _XGB_MODEL is not None and _MODEL_METADATA is not None:
            return _XGB_MODEL, _MODEL_METADATA

        # Load metadata first
        try:
            with open(_METADATA_PATH, "r", encoding="utf-8") as fh:
                metadata = json.load(fh)
        except Exception as exc:
            logger.error("Failed to load model metadata: %s", exc)
            _MODEL_METADATA = None
            _XGB_MODEL = None
            return None, None

        # Load model
        if xgb is None:
            logger.error("xgboost package not available; cannot perform ML inference.")
            _MODEL_METADATA = None
            _XGB_MODEL = None
            return None, None

        try:
            booster = xgb.Booster()
            booster.load_model(_MODEL_PATH)
            _XGB_MODEL = booster
            _MODEL_METADATA = metadata
            return _XGB_MODEL, _MODEL_METADATA
        except Exception as exc:
            logger.error("Failed to load XGBoost model from %s: %s", _MODEL_PATH, exc)
            _XGB_MODEL = None
            _MODEL_METADATA = None
            return None, None


def pml_from_cicmaldroid_features(feature_values: dict, min_coverage: float = 0.8) -> dict:
    """
    Predict PML (probability of malware) from a CICMalDroid feature dictionary.

    Args:
        feature_values: dict mapping original feature names or model feature keys (e.g., 'f0') to numeric values.
        min_coverage: minimum fraction of expected features that must be present (0-1). Below this, no inference is performed.

    Returns:
        dict with keys:
          - PML: float or None
          - expected_features: int
          - provided_features: int
          - coverage: float
          - missing_features: list
          - invalid_features: list
          - used_imputed: int
          - error: str or None
    """
    model, metadata = _load_model_and_metadata()
    result = {
        "PML": None,
        "expected_features": 0,
        "provided_features": 0,
        "coverage": 0.0,
        "missing_features": [],
        "invalid_features": [],
        "used_imputed": 0,
        "error": None,
    }

    if model is None or metadata is None:
        result["error"] = "Model or metadata unavailable"
        return result

    feature_names_model = metadata.get("feature_names_model")
    original_to_model = metadata.get("original_to_model_feature", {})
    medians = metadata.get("training_feature_medians", {})

    if not feature_names_model or not isinstance(feature_names_model, list):
        result["error"] = "Invalid metadata: missing feature_names_model"
        return result

    expected = len(feature_names_model)
    result["expected_features"] = expected

    # Build reverse map model_feature -> original_name
    model_to_original = {v: k for k, v in original_to_model.items()}

    provided = 0
    invalid = []
    missing = []
    vector = []
    used_imputed = 0
    unexpected = []

    # Detect unexpected keys (neither model keys nor original feature names)
    allowed_keys = set(feature_names_model) | set(original_to_model.keys())
    for k in feature_values.keys():
        if k not in allowed_keys:
            unexpected.append(k)

    for mf in feature_names_model:
        orig = model_to_original.get(mf)
        val = None
        # Check if user supplied model key directly
        if mf in feature_values:
            val = feature_values.get(mf)
        # Else check original feature name
        elif orig and orig in feature_values:
            val = feature_values.get(orig)

        if val is None:
            # Use training median if available
            med = medians.get(orig, None) if orig else None
            if med is None:
                missing.append(mf)
                vector.append(0.0)
                used_imputed += 1
            else:
                vector.append(float(med))
                used_imputed += 1
        else:
            # Try to coerce to float
            try:
                num = float(val)
                # Reject non-finite numbers
                if not math.isfinite(num):
                    invalid.append(mf)
                    med = medians.get(orig, None) if orig else None
                    if med is not None:
                        vector.append(float(med))
                        used_imputed += 1
                    else:
                        vector.append(0.0)
                        used_imputed += 1
                else:
                    vector.append(num)
                    provided += 1
            except Exception:
                invalid.append(mf)
                # use median if available, else zero
                med = medians.get(orig, None) if orig else None
                if med is not None:
                    vector.append(float(med))
                    used_imputed += 1
                else:
                    vector.append(0.0)
                    used_imputed += 1

    result["provided_features"] = provided
    result["invalid_features"] = invalid
    result["missing_features"] = missing
    result["used_imputed"] = used_imputed
    result["unexpected_features"] = unexpected
    coverage = provided / float(expected) if expected > 0 else 0.0
    result["coverage"] = round(coverage, 4)

    if coverage < float(min_coverage):
        result["error"] = f"Insufficient feature coverage: {coverage:.2f} < {min_coverage:.2f}"
        result["PML"] = None
        return result

    # Prepare DMatrix and predict
    try:
        if np is None:
            result["error"] = "numpy not available"
            return result

        arr = np.array([vector], dtype=float)
        dmat = xgb.DMatrix(arr, feature_names=feature_names_model)
        preds = model.predict(dmat)
        # xgboost returns array-like
        if hasattr(preds, "tolist"):
            p = float(preds.tolist()[0])
        else:
            p = float(preds[0])

        # Clamp
        p = max(0.0, min(1.0, p))
        result["PML"] = round(p, 6)
        return result
    except Exception as exc:
        logger.exception("XGBoost prediction failed: %s", exc)
        result["error"] = f"XGBoost prediction failed: {exc}"
        result["PML"] = None
        return result


def final_fusion_from_components(PML: Optional[float], Ssem: float, Sdyn: float, target_detected: bool) -> dict:
    """
    Compute final fused score from individual components.

    Args:
        PML: probability from ML model (0-1) or None (treated as 0)
        Ssem: semantic score (0-1)
        Sdyn: dynamic score (0-1)
        target_detected: boolean

    Returns:
        dict with keys: PML, Ssem, Sdyn, target_detected, target_bonus, final_score, severity
    """
    # Clamp inputs
    pml_val = float(PML) if (PML is not None) else 0.0
    pml_val = max(0.0, min(1.0, pml_val))
    ssem = max(0.0, min(1.0, float(Ssem)))
    sdyn = max(0.0, min(1.0, float(Sdyn)))

    target_bonus = TARGET_BONUS if bool(target_detected) else 0.0

    raw = WEIGHT_ML_PERMISSION * pml_val + WEIGHT_SEMANTIC * ssem + WEIGHT_DYNAMIC * sdyn + target_bonus
    final_score = round(min(100.0, 100.0 * raw), 2)

    # Severity mapping
    if 0 <= final_score <= 30:
        severity = "LOW"
    elif 30 < final_score <= 60:
        severity = "MEDIUM"
    elif 60 < final_score <= 80:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    return {
        "PML": round(pml_val, 6),
        "Ssem": round(ssem, 4),
        "Sdyn": round(sdyn, 4),
        "target_detected": bool(target_detected),
        "target_bonus": round(target_bonus, 4),
        "final_score": final_score,
        "severity": severity,
    }


logger = logging.getLogger("nirikshak.scoring")

# ─── Severity Tier Thresholds ────────────────────────────────────────────────
SEVERITY_TIERS = [
    (81, 100, "CRITICAL"),
    (61, 80,  "HIGH"),
    (31, 60,  "MEDIUM"),
    (0,  30,  "LOW"),
]

# ─── Factor Weights ───────────────────────────────────────────────────────────
WEIGHT_ML_PERMISSION   = 0.35   # P_ML  — derived from static permission analysis
WEIGHT_SEMANTIC        = 0.40   # S_semantic — from LLM semantic analysis
WEIGHT_DYNAMIC         = 0.25   # S_dynamic  — from Frida dynamic analysis hooks
TARGET_BONUS           = 0.05   # Added if Indian banking targets are detected and app is malicious


@dataclass
class RiskFactors:
    """Container for the five input factors to the risk fusion engine."""

    # Factor 1 & 2: ML-Based Permission Score (from static analysis)
    # Derived from the density of dangerous permissions, obfuscation signals,
    # component count anomalies, and hardcoded IP/string heuristics.
    p_ml: float = 0.0                   # Range: 0.0–1.0

    # Factor 3: Semantic Score (from Ollama LLM analysis)
    s_semantic: float = 0.0             # Range: 0.0–1.0

    # Factor 4: Dynamic Analysis Score (from Frida hooks / MobSF runtime)
    s_dynamic: float = 0.0              # Range: 0.0–1.0

    # Factor 5: Indian Banking Target Detection (from static string analysis)
    target_detected: bool = False       # Boolean from static_parser

    # Optional enrichment from static analysis
    permission_count: int = 0
    dangerous_permission_count: int = 0
    suspicious_pattern_count: int = 0
    activities_count: int = 0
    services_count: int = 0
    receivers_count: int = 0
    matched_targets: list = field(default_factory=list)
    primary_exploit: str = "UNKNOWN"
    is_indian_vector: bool = False
    forensic_narrative: str = ""
    confidence: str = "LOW"


@dataclass
class RiskScore:
    """Complete risk assessment output from the fusion engine."""
    final_score: float = 0.0            # 0–100 normalized score
    severity_tier: str = "LOW"          # LOW | MEDIUM | HIGH | CRITICAL
    severity_color: str = "#10B981"     # Hex color for UI display

    # Component breakdown (for transparency/audit)
    p_ml_contribution: float = 0.0
    semantic_contribution: float = 0.0
    dynamic_contribution: float = 0.0
    target_bonus_applied: float = 0.0

    # Enriched metadata passed through
    primary_exploit: str = "UNKNOWN"
    is_indian_vector: bool = False
    forensic_narrative: str = ""
    confidence: str = "LOW"
    matched_targets: list = field(default_factory=list)

    # Risk breakdown percentages (for UI gauge)
    breakdown: dict = field(default_factory=dict)

    # Human-readable risk summary
    risk_summary: str = ""
    recommended_action: str = ""
    # Analysis status: OK | DEGRADED | FALLBACK
    analysis_ok: bool = True
    analysis_status: str = "OK"
    analysis_error: Optional[str] = None


# ─── Severity Tier Mappings ───────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",   # Red
    "HIGH":     "#F97316",   # Orange
    "MEDIUM":   "#EAB308",   # Yellow
    "LOW":      "#10B981",   # Green
}

SEVERITY_ACTIONS = {
    "CRITICAL": (
        "IMMEDIATE CONTAINMENT REQUIRED. Block this APK from all enterprise devices. "
        "File an incident report with CERT-In under IT Act Section 70B. "
        "Notify affected banking partners and initiate forensic preservation."
    ),
    "HIGH": (
        "HIGH PRIORITY REVIEW. Quarantine the APK and submit to MobSF sandbox. "
        "Alert the security operations team. Notify relevant banking institutions "
        "if Indian financial targets are confirmed."
    ),
    "MEDIUM": (
        "ELEVATED RISK. Conduct full dynamic analysis in isolated sandbox environment. "
        "Review decompiled code manually for confirmed malicious logic. "
        "Monitor for related C2 infrastructure indicators."
    ),
    "LOW": (
        "STANDARD MONITORING. Archive for behavioral baseline tracking. "
        "Rescan with updated signatures in 30 days. "
        "No immediate action required unless dynamic analysis reveals new indicators."
    ),
}

SEVERITY_SUMMARIES = {
    "CRITICAL": (
        "This application exhibits multiple overlapping indicators of a sophisticated "
        "mobile banking trojan. Confirmed targeting of Indian UPI/banking infrastructure "
        "with high-confidence attack chain identification. Immediate response required."
    ),
    "HIGH": (
        "The application demonstrates strong behavioral indicators consistent with "
        "mobile banking malware. Multiple dangerous permission combinations and suspicious "
        "code patterns detected. Manual forensic review is strongly recommended."
    ),
    "MEDIUM": (
        "The application exhibits moderate risk indicators including elevated permission "
        "requests and potentially suspicious code patterns. Cannot conclusively confirm "
        "malicious intent without dynamic analysis confirmation."
    ),
    "LOW": (
        "The application presents minimal static risk indicators. Standard permission "
        "profile observed with no confirmed banking target signatures. "
        "Routine monitoring recommended."
    ),
}


# ─── Supplementary ML Score Derivation ───────────────────────────────────────

def _derive_p_ml_from_static(factors: RiskFactors) -> float:
    """
    Derive the P_ML machine learning score from static analysis signals.
    If p_ml is already set (e.g., from XGBoost), it is returned directly.
    Otherwise, compute a heuristic P_ML from permission and component signals.

    Heuristic sub-components:
      - Permission danger ratio (40% weight)
      - Suspicious pattern density (30% weight)
      - Abnormal component profile (15% weight)
      - Indian target flag pre-boost (15% weight)
    """
    if factors.p_ml > 0.0:
        return min(1.0, factors.p_ml)

    # Component 1: Dangerous permission ratio
    if factors.permission_count > 0:
        danger_ratio = min(1.0, factors.dangerous_permission_count / max(factors.permission_count, 1))
    else:
        danger_ratio = 0.0

    # Component 2: Suspicious string/pattern density (normalized to 10 patterns = score 1.0)
    pattern_score = min(1.0, factors.suspicious_pattern_count / 10.0)

    # Component 3: Abnormal component profile
    # Legitimate banking apps rarely need >10 receivers or >15 services
    component_score = 0.0
    if factors.receivers_count > 8:
        component_score += 0.4
    if factors.services_count > 10:
        component_score += 0.3
    if factors.activities_count > 25:
        component_score += 0.3
    component_score = min(1.0, component_score)

    # Component 4: Target flag
    target_score = 0.8 if factors.target_detected else 0.0

    # Weighted combination
    p_ml = (
        0.40 * danger_ratio +
        0.30 * pattern_score +
        0.15 * component_score +
        0.15 * target_score
    )

    return round(min(1.0, max(0.0, p_ml)), 4)


# ─── Core Fusion Formula ─────────────────────────────────────────────────────

def compute_risk_score(factors: RiskFactors, allow_fallback: bool = False) -> RiskScore:
    """
    Apply the 5-Factor Risk Fusion formula to compute the final threat score.

    Formula:
      Final Score = min(100, 100 * (0.35 * P_ML + 0.40 * S_semantic + 0.25 * S_dynamic + Target_Bonus))

    Args:
        factors: RiskFactors dataclass populated by the analysis pipeline.

    Returns:
        RiskScore: Complete risk assessment with score, tier, contributions, and metadata.
    """
    # Use provided ML PML as authoritative. Do NOT derive from static heuristics
    p_ml = factors.p_ml

    # If PML missing and fallback allowed, explicitly derive from static heuristics
    analysis_ok = True
    analysis_status = "OK"
    analysis_error = None
    if p_ml is None:
        if allow_fallback:
            p_ml = _derive_p_ml_from_static(factors)
            analysis_status = "FALLBACK_STATIC"
        else:
            analysis_ok = False
            analysis_status = "DEGRADED_ML_MISSING"
            analysis_error = "PML unavailable; evaluation is degraded. Provide XGBoost PML or enable fallback."

    # ── Clamp all inputs to [0.0, 1.0] ────────────────────────────────────
    s_semantic = round(max(0.0, min(1.0, factors.s_semantic)), 4)
    s_dynamic = round(max(0.0, min(1.0, factors.s_dynamic)), 4)

    # Treat missing p_ml as 0 for numeric calculation but keep analysis_ok flag
    p_ml_val = float(p_ml) if (p_ml is not None) else 0.0

    # ── Compute Base Score (Before Bonus) ─────────────────────────────────
    base_raw = (
        WEIGHT_ML_PERMISSION * p_ml_val +
        WEIGHT_SEMANTIC * s_semantic +
        WEIGHT_DYNAMIC * s_dynamic
    )
    base_final_score = round(min(100.0, 100.0 * base_raw), 2)

    # ── Compute Target Bonus (Threshold Guard) ────────────────────────────
    # Apply bonus ONLY if static/semantic flagged an Indian target AND base score >= 40 (malicious)
    if (factors.target_detected or factors.is_indian_vector) and base_final_score >= 40.0:
        bonus = TARGET_BONUS
    else:
        bonus = 0.0

    # ── Apply Fusion Formula ───────────────────────────────────────────────
    raw_score = base_raw + bonus
    final_score = round(min(100.0, 100.0 * raw_score), 2)

    # ── Compute Individual Contributions (for breakdown display) ───────────
    ml_contrib = round(100.0 * WEIGHT_ML_PERMISSION * p_ml_val, 2)
    semantic_contrib = round(100.0 * WEIGHT_SEMANTIC * s_semantic, 2)
    dynamic_contrib = round(100.0 * WEIGHT_DYNAMIC * s_dynamic, 2)
    bonus_contrib = round(100.0 * bonus, 2)

    # ── Determine Severity Tier with explicit boundaries ───────────────────
    if final_score <= 30:
        severity_tier = "LOW"
    elif final_score <= 60:
        severity_tier = "MEDIUM"
    elif final_score <= 80:
        severity_tier = "HIGH"
    else:
        severity_tier = "CRITICAL"

    severity_color = SEVERITY_COLORS.get(severity_tier, "#10B981")

    # ── Percentage Breakdown normalized by actual contribution sum ──────────
    total_contrib = ml_contrib + semantic_contrib + dynamic_contrib + bonus_contrib
    if total_contrib <= 0:
        breakdown = {
            "ML Permission Analysis": 0.0,
            "Semantic AI Analysis": 0.0,
            "Dynamic Behavior": 0.0,
            "Indian Target Bonus": 0.0,
        }
    else:
        breakdown = {
            "ML Permission Analysis": round((ml_contrib / total_contrib) * 100, 1),
            "Semantic AI Analysis": round((semantic_contrib / total_contrib) * 100, 1),
            "Dynamic Behavior": round((dynamic_contrib / total_contrib) * 100, 1),
            "Indian Target Bonus": round((bonus_contrib / total_contrib) * 100, 1),
        }

    result = RiskScore(
        final_score=final_score,
        severity_tier=severity_tier,
        severity_color=severity_color,
        p_ml_contribution=ml_contrib,
        semantic_contribution=semantic_contrib,
        dynamic_contribution=dynamic_contrib,
        target_bonus_applied=bonus_contrib,
        primary_exploit=factors.primary_exploit,
        is_indian_vector=factors.is_indian_vector,
        forensic_narrative=factors.forensic_narrative,
        confidence=factors.confidence,
        matched_targets=factors.matched_targets,
        breakdown=breakdown,
        risk_summary=SEVERITY_SUMMARIES.get(severity_tier, ""),
        recommended_action=SEVERITY_ACTIONS.get(severity_tier, ""),
        analysis_ok=analysis_ok,
        analysis_status=analysis_status,
        analysis_error=analysis_error,
    )

    logger.info(
        "Risk fusion complete | score=%.2f | tier=%s | ML=%.2f | Sem=%.2f | Dyn=%.2f | Bonus=%.2f",
        final_score, severity_tier, ml_contrib, semantic_contrib, dynamic_contrib, bonus_contrib,
    )

    return result


# ─── Factory: Build RiskFactors from Pipeline Output ────────────────────────

def build_risk_factors(
    static_result: dict,
    semantic_result: dict,
    dynamic_score: float = 0.0,
    p_ml: Optional[float] = None,
) -> RiskFactors:
    """
    Construct a RiskFactors instance from the outputs of each analysis stage.

    Args:
        static_result: Dict from backend.static_parser.parse_apk()
        semantic_result: Dict from ai_engine.semantic_analyzer.analyze_code_semantics()
        dynamic_score: Optional float from Frida/dynamic hook analysis (0.0–1.0)

    Returns:
        RiskFactors: Populated dataclass ready for compute_risk_score()
    """
    target_det = static_result.get("target_detection", {})

    return RiskFactors(
        p_ml=p_ml,
        s_semantic=semantic_result.get("semantic_score", 0.5),
        s_dynamic=max(0.0, min(1.0, dynamic_score)),
        target_detected=target_det.get("target_detected", False),
        permission_count=len(static_result.get("permissions", [])),
        dangerous_permission_count=len(static_result.get("dangerous_permissions", [])),
        suspicious_pattern_count=len(target_det.get("suspicious_patterns", [])),
        activities_count=static_result.get("activities_count", 0),
        services_count=static_result.get("services_count", 0),
        receivers_count=static_result.get("receivers_count", 0),
        matched_targets=target_det.get("matched_targets", []),
        primary_exploit=semantic_result.get("primary_exploit", "UNKNOWN"),
        is_indian_vector=semantic_result.get("is_indian_vector", False),
        forensic_narrative=semantic_result.get("forensic_narrative", ""),
        confidence=semantic_result.get("confidence", "LOW"),
    )


def score_to_dict(risk_score: RiskScore) -> dict:
    """Convert a RiskScore dataclass to a JSON-serializable dictionary."""
    return asdict(risk_score)
