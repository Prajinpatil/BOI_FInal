# ai_engine/semantic_analyzer.py
"""
NIRIKSHAK-AI :: Semantic Code Analysis Engine (Hardened)
Performs AST-level code slicing on decompiled Java methods and routes
suspicious code slices to a local Ollama LLM (qwen2.5-coder:7b) for
semantic threat assessment and forensic narrative generation.

Hardening improvements:
  - Precision AST slicer with method-body, annotation, inheritance, and
    field-initializer detection for AccessibilityService & SmsManager
  - Strict system-prompt-level JSON enforcement for Ollama
  - 7-strategy JSON repair pipeline with regex, brace-matching, and
    key-value reconstruction as a last resort
"""

import json
import logging
import re
import time
from typing import Optional

import requests
import os
try:
    from openai import OpenAI
except Exception:
    OpenAI = None

logger = logging.getLogger("nirikshak.semantic_analyzer")

# ─── Configuration ───────────────────────────────────────────────────────────
OLLAMA_BASE_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:7b"
OLLAMA_TIMEOUT_SECONDS = 120
OLLAMA_MAX_RETRIES = 2
# OpenAI config (preferred when OPENAI_API_KEY present)
OPENAI_MODEL = "gpt-4o-mini"
OPENAI_TIMEOUT_SECONDS = 120
OPENAI_MAX_RETRIES = 2
# Groq config (free cloud alternative — replaces Ollama)
GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_MAX_RETRIES = 2

# ─── Sensitive API Surface Filters (Expanded) ────────────────────────────────
# Methods touching these APIs are high-priority for semantic review.
# Patterns are ordered from highest to lowest banking-malware relevance.
SENSITIVE_API_PATTERNS: list[tuple[str, str]] = [
    # ── TIER 1: Critical Banking Malware APIs ───────────────────────────────
    # AccessibilityService — full coverage of A11y attack surface
    (
        r"AccessibilityService"                       # Base class / service binding
        r"|AccessibilityNodeInfo"                     # Node info tree traversal
        r"|AccessibilityEvent"                        # Accessibility event dispatch
        r"|getAccessibilityNodeInfoList"              # Child node enumeration
        r"|performAction\s*\("                        # UI action injection (clicks, fills)
        r"|performGlobalAction"                       # Global actions (back, home, recents)
        r"|findAccessibilityNodeInfosByViewId"        # Targeted view ID lookup
        r"|findAccessibilityNodeInfosByText"          # Text-based UI node search
        r"|onAccessibilityEvent"                      # Event handler (malware entry point)
        r"|onServiceConnected"                        # Service activation callback
        r"|getServiceInfo"                            # Service capability query
        r"|setServiceInfo"                            # Dynamic capability modification
        r"|TYPE_VIEW_TEXT_CHANGED"                     # Keylogging trigger event
        r"|TYPE_WINDOW_STATE_CHANGED"                 # Overlay timing trigger
        r"|TYPE_NOTIFICATION_STATE_CHANGED"           # Notification interception
        r"|TYPE_VIEW_CLICKED"                         # Click event interception
        r"|ACTION_CLICK"                              # Programmatic UI clicking
        r"|ACTION_SET_TEXT"                            # Injecting text into fields
        r"|ACTION_PASTE"                              # Clipboard paste injection
        r"|BIND_ACCESSIBILITY_SERVICE",               # Permission-level intent filter
        "ACCESSIBILITY_ABUSE",
    ),
    # SmsManager — full coverage of SMS exfiltration surface
    (
        r"SmsManager"                                 # Manager class reference
        r"|android\.telephony\.SmsManager"            # Fully qualified class
        r"|getDefault\s*\(\s*\)\s*\.send"             # SmsManager.getDefault().send*
        r"|sendTextMessage\s*\("                      # Single SMS send
        r"|sendMultipartTextMessage\s*\("             # Multi-part SMS send
        r"|sendDataMessage\s*\("                      # Binary data SMS
        r"|divideMessage\s*\("                        # Message splitting for multi-part
        r"|SmsMessage\.createFromPdu"                 # PDU parsing (incoming SMS intercept)
        r"|pdus"                                      # Raw PDU key in SMS broadcast intent
        r"|sms_body"                                  # SMS content URI column
        r"|SMS_RECEIVED"                              # Broadcast receiver action
        r"|SMS_DELIVER"                               # Delivered SMS action
        r"|WAP_PUSH_RECEIVED"                         # WAP push interception
        r"|content://sms"                             # SMS content provider query
        r"|abortBroadcast\s*\("                       # Suppress SMS notification
        r"|setPriority\s*\(\s*999",                   # High-priority SMS receiver
        "SMS_EXFILTRATION",
    ),
    # ── TIER 2: Dynamic Code Loading ────────────────────────────────────────
    (
        r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|loadDex"
        r"|BaseDexClassLoader|dalvik\.system\.DexFile"
        r"|openDexFile|loadClass\s*\(",
        "DYNAMIC_CODE_LOADING",
    ),
    # ── TIER 3: Device Fingerprinting ───────────────────────────────────────
    (
        r"TelephonyManager|getDeviceId|getImei|getSubscriberId|getSimSerialNumber"
        r"|getLine1Number|getNetworkOperator|getSimOperator|Build\.SERIAL"
        r"|Settings\.Secure\.ANDROID_ID|getMacAddress",
        "DEVICE_FINGERPRINTING",
    ),
    # ── TIER 4: Process & Service Enumeration ───────────────────────────────
    (
        r"getRunningServices|getRunningAppProcesses|ActivityManager"
        r"|getRunningTasks|getRecentTasks|killBackgroundProcesses",
        "PROCESS_ENUMERATION",
    ),
    # ── TIER 5: Crypto Operations ───────────────────────────────────────────
    (
        r"KeyStore|KeyGenerator|Cipher\.getInstance|SecretKeySpec"
        r"|Mac\.getInstance|IvParameterSpec|AEADParameterSpec",
        "CRYPTO_OPERATIONS",
    ),
    # ── TIER 6: Contact & Call Log Harvesting ───────────────────────────────
    (
        r"ContentResolver\.query|ContactsContract|CallLog"
        r"|content://call_log|content://contacts"
        r"|content://com\.android\.contacts",
        "CONTACT_HARVESTING",
    ),
    # ── TIER 7: Shell Execution ─────────────────────────────────────────────
    (
        r"Runtime\.exec|ProcessBuilder|su\b|superuser"
        r"|/system/bin/sh|chmod\s+\d{3,4}",
        "SHELL_EXECUTION",
    ),
    # ── TIER 8: Network Communication ───────────────────────────────────────
    (
        r"HttpURLConnection|OkHttpClient|Retrofit|volley"
        r"|WebSocket|SSLSocket|SSLContext",
        "NETWORK_COMMUNICATION",
    ),
    # ── TIER 9: Data Persistence ────────────────────────────────────────────
    (
        r"SharedPreferences|SQLiteDatabase|FileOutputStream"
        r"|getSharedPreferences|openFileOutput",
        "DATA_PERSISTENCE",
    ),
    # ── TIER 10: Media Capture ──────────────────────────────────────────────
    (r"Camera|MediaRecorder|AudioRecord|ImageReader|SurfaceTexture", "MEDIA_CAPTURE"),
    # ── TIER 11: Location Tracking ──────────────────────────────────────────
    (
        r"LocationManager|getLastKnownLocation|requestLocationUpdates"
        r"|FusedLocationProviderClient|LocationRequest",
        "LOCATION_TRACKING",
    ),
    # ── TIER 12: Device Admin Abuse ─────────────────────────────────────────
    (
        r"DevicePolicyManager|setGlobalProxy|lockNow|wipeData"
        r"|resetPassword|BIND_DEVICE_ADMIN",
        "DEVICE_ADMIN_ABUSE",
    ),
    # ── TIER 13: Notification Snooping ──────────────────────────────────────
    (
        r"NotificationListenerService|getActiveNotifications"
        r"|StatusBarNotification|BIND_NOTIFICATION_LISTENER",
        "NOTIFICATION_SNOOPING",
    ),
    # ── TIER 14: Clipboard Hijacking ────────────────────────────────────────
    (
        r"ClipboardManager|getPrimaryClip|setPrimaryClip"
        r"|addPrimaryClipChangedListener|ClipData",
        "CLIPBOARD_HIJACKING",
    ),
    # ── TIER 15: Overlay / Phishing UI ──────────────────────────────────────
    (
        r"SYSTEM_ALERT_WINDOW|TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT"
        r"|WindowManager\.LayoutParams|addView\s*\(\s*.*LayoutParams",
        "OVERLAY_ATTACK",
    ),
    # ── TIER 16: Call Forwarding ────────────────────────────────────────────
    (
        r"CALL_PHONE|ACTION_CALL|tel:|callForward"
        r"|\*21\*|\*\*21\*|\*62\*|\*67\*|##002#",
        "CALL_FORWARDING",
    ),
]

# ─── Pre-compiled Patterns for Performance ───────────────────────────────────
_COMPILED_API_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(pattern_str, re.IGNORECASE | re.DOTALL), label)
    for pattern_str, label in SENSITIVE_API_PATTERNS
]


# ─── Strict LLM System Prompt ────────────────────────────────────────────────
# Separated from the user prompt for Ollama's system+prompt architecture.
# The system prompt establishes unbreakable output rules.
OLLAMA_SYSTEM_PROMPT = """\
You are a JSON-only response API for Android malware forensic analysis. You specialize in Indian mobile banking threats targeting UPI, NPCI, SBI, PhonePe, and Paytm infrastructure.

ABSOLUTE RULES:
1. You MUST respond with ONLY a raw JSON object. Nothing else.
2. Do NOT wrap the JSON in markdown code fences (```).
3. Do NOT include ANY text before or after the JSON object.
4. Do NOT add comments inside the JSON.
5. Do NOT use trailing commas.
6. ALL string values must use double quotes.
7. Boolean values must be lowercase: true or false (not True/False).
8. The response must be parseable by Python's json.loads() without modification.

You are not a chatbot. You are a structured data endpoint. Emit only valid JSON."""

# ─── User Prompt Template ────────────────────────────────────────────────────
ANALYSIS_PROMPT_TEMPLATE = """\
Analyze the following decompiled Android Java code for malicious intent targeting Indian mobile banking infrastructure (UPI, NPCI BHIM, SBI YONO, PhonePe, Google Pay India, Paytm).

FLAGGED SENSITIVE APIS DETECTED: {flagged_apis}

DECOMPILED CODE:
{code_slice}

Produce a forensic assessment as a single JSON object with this exact schema:

{{"semantic_score": <float 0.0 to 1.0 where 1.0 means definitely malicious>, "primary_exploit": "<exactly one of: OTP_INTERCEPTION, OVERLAY_ATTACK, SMS_THEFT, ACCESSIBILITY_KEYLOGGING, DYNAMIC_LOADING, CREDENTIAL_HARVESTING, CALL_FORWARDING, CLIPBOARD_HIJACKING, BENIGN, UNKNOWN>", "is_indian_vector": <boolean true if targeting Indian UPI/banking, false otherwise>, "forensic_narrative": "<2-3 sentence technical forensic analysis of the attack chain and impact on Indian banking users>", "confidence": "<exactly one of: LOW, MEDIUM, HIGH>"}}

Respond with ONLY the JSON object — no markdown, no explanation, no code fences:"""

# ─── Fallback / Default Response ─────────────────────────────────────────────
DEFAULT_SEMANTIC_RESPONSE = {
    "semantic_score": 0.5,
    "primary_exploit": "UNKNOWN",
    "is_indian_vector": False,
    "forensic_narrative": (
        "Automated semantic analysis could not reach the local LLM instance. "
        "The code slice contains patterns flagged by static heuristics but requires "
        "manual review to confirm malicious intent. Treat as MEDIUM risk pending analyst review."
    ),
    "confidence": "LOW",
}


# ═══════════════════════════════════════════════════════════════════════════════
# JSON Repair Pipeline — 7 Strategies
# ═══════════════════════════════════════════════════════════════════════════════

def _strip_markdown_fences(text: str) -> str:
    """
    Remove ```json ... ``` or ``` ... ``` wrapping from LLM output.
    Handles multi-level nesting and various fence styles (```, ~~~).
    """
    # Strip leading/trailing whitespace first
    text = text.strip()
    # Remove opening fence with optional language tag (```json, ```JSON, ~~~json, etc.)
    text = re.sub(r"^(?:```|~~~)(?:json|JSON|Json)?\s*\n?", "", text, count=1)
    # Remove closing fence
    text = re.sub(r"\n?\s*(?:```|~~~)\s*$", "", text, count=1)
    return text.strip()


def _remove_trailing_commas(text: str) -> str:
    """
    Remove trailing commas before closing braces/brackets (invalid JSON).
    Handles multiple occurrences and whitespace variations.
    """
    # Remove trailing comma before } or ] (with optional whitespace/newlines)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


def _fix_single_quotes(text: str) -> str:
    """
    Replace single-quoted JSON keys/values with double quotes.
    Only operates on text that looks like it uses single quotes for JSON strings.
    """
    # Only apply if the text contains single-quoted patterns and few double quotes
    if text.count("'") > text.count('"') and text.count("'") >= 4:
        # Replace ' with " but be careful not to break apostrophes in prose
        # Strategy: replace only when single quotes wrap JSON keys or values
        text = re.sub(r"'(semantic_score|primary_exploit|is_indian_vector|forensic_narrative|confidence)'", r'"\1"', text)
        text = re.sub(r":\s*'([^']{0,500}?)'", r': "\1"', text)
    return text


def _fix_python_booleans(text: str) -> str:
    """Replace Python-style True/False/None with JSON true/false/null."""
    text = re.sub(r'\bTrue\b', 'true', text)
    text = re.sub(r'\bFalse\b', 'false', text)
    text = re.sub(r'\bNone\b', 'null', text)
    return text


def _extract_json_object(text: str) -> str:
    """
    Extract the first complete, brace-balanced JSON object from a text string.
    Handles nested braces correctly. Ignores braces inside quoted strings.
    """
    depth = 0
    start_idx = None
    in_string = False
    escape_next = False

    for i, char in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if char == '\\' and in_string:
            escape_next = True
            continue
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue

        if char == "{":
            if start_idx is None:
                start_idx = i
            depth += 1
        elif char == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start_idx is not None:
                return text[start_idx:i + 1]

    # If we found an opening brace but no matching close, return from start to end
    if start_idx is not None:
        return text[start_idx:] + "}"
    return text


def _reconstruct_from_keys(text: str) -> Optional[dict]:
    """
    Last-resort reconstruction: extract individual key-value pairs by regex
    when the JSON structure is too damaged for standard parsing.
    """
    result = {}

    # semantic_score
    score_match = re.search(r'"?semantic_score"?\s*:\s*([0-9]*\.?[0-9]+)', text)
    if score_match:
        try:
            result["semantic_score"] = float(score_match.group(1))
        except ValueError:
            pass

    # primary_exploit
    exploit_match = re.search(
        r'"?primary_exploit"?\s*:\s*"?([A-Z_]+)"?', text, re.IGNORECASE
    )
    if exploit_match:
        result["primary_exploit"] = exploit_match.group(1).upper()

    # is_indian_vector
    indian_match = re.search(r'"?is_indian_vector"?\s*:\s*(true|false|True|False)', text, re.IGNORECASE)
    if indian_match:
        result["is_indian_vector"] = indian_match.group(1).lower() == "true"

    # forensic_narrative
    narrative_match = re.search(r'"?forensic_narrative"?\s*:\s*"((?:[^"\\]|\\.){10,})"', text, re.DOTALL)
    if narrative_match:
        result["forensic_narrative"] = narrative_match.group(1).replace('\\"', '"')

    # confidence
    conf_match = re.search(r'"?confidence"?\s*:\s*"?(LOW|MEDIUM|HIGH)"?', text, re.IGNORECASE)
    if conf_match:
        result["confidence"] = conf_match.group(1).upper()

    # Only return if we got at least semantic_score and one other field
    if "semantic_score" in result and len(result) >= 2:
        return result
    return None


def _repair_and_parse_json(raw_text: str) -> Optional[dict]:
    """
    Attempt 7 progressive repair strategies to parse LLM JSON output.
    Each strategy is tried in order of aggressiveness. The first successful
    parse is returned.

    Strategy chain:
      1. Direct parse (already valid JSON)
      2. Strip markdown fences, then parse
      3. Strip fences + remove trailing commas, then parse
      4. Strip fences + fix Python booleans + remove trailing commas, then parse
      5. Extract first brace-balanced JSON object, then parse
      6. Full cleanup (fences + commas + booleans + single quotes), then extract & parse
      7. Last-resort regex key-value reconstruction

    Returns parsed dict or None if ALL strategies fail.
    """
    if not raw_text or not raw_text.strip():
        logger.warning("Received empty LLM output — nothing to repair.")
        return None

    # Build the strategy pipeline
    strategies: list[tuple[str, str]] = [
        # (candidate_text, label)
        (raw_text.strip(), "RAW"),
        (_strip_markdown_fences(raw_text), "STRIP_FENCES"),
        (
            _remove_trailing_commas(_strip_markdown_fences(raw_text)),
            "STRIP_FENCES+TRAILING_COMMAS",
        ),
        (
            _remove_trailing_commas(
                _fix_python_booleans(_strip_markdown_fences(raw_text))
            ),
            "STRIP_FENCES+BOOLEANS+TRAILING_COMMAS",
        ),
        (
            _extract_json_object(raw_text),
            "EXTRACT_JSON_OBJECT",
        ),
        (
            _remove_trailing_commas(
                _fix_python_booleans(
                    _fix_single_quotes(
                        _extract_json_object(_strip_markdown_fences(raw_text))
                    )
                )
            ),
            "FULL_CLEANUP+EXTRACT",
        ),
    ]

    for candidate, label in strategies:
        if not candidate or not candidate.strip():
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                logger.debug("JSON parsed successfully with strategy: %s", label)
                return parsed
        except (json.JSONDecodeError, TypeError, ValueError):
            continue

    # Strategy 7: Last-resort regex reconstruction
    logger.warning("Standard JSON strategies exhausted. Attempting regex key-value reconstruction.")
    reconstructed = _reconstruct_from_keys(raw_text)
    if reconstructed:
        logger.info("JSON reconstructed from regex key-value extraction (%d keys).", len(reconstructed))
        return reconstructed

    logger.error(
        "All 7 JSON repair strategies failed. Raw LLM output (first 400 chars): %s",
        raw_text[:400],
    )
    return None


def _validate_semantic_response(parsed: dict) -> dict:
    """
    Validate and sanitize the parsed LLM response, filling missing fields
    with safe defaults and clamping numeric values.
    """
    validated = {}

    # semantic_score: float 0.0–1.0
    try:
        score = float(parsed.get("semantic_score", 0.5))
        validated["semantic_score"] = round(max(0.0, min(1.0, score)), 4)
    except (TypeError, ValueError):
        validated["semantic_score"] = 0.5

    # primary_exploit: string from allowed set or any reasonable string
    exploit = str(parsed.get("primary_exploit", "UNKNOWN")).upper().strip().replace(" ", "_")
    if len(exploit) > 3 and exploit != "NONE" and exploit != "NULL":
        validated["primary_exploit"] = exploit
    else:
        validated["primary_exploit"] = "UNKNOWN"

    # is_indian_vector: boolean
    raw_vector = parsed.get("is_indian_vector", False)
    if isinstance(raw_vector, bool):
        validated["is_indian_vector"] = raw_vector
    elif isinstance(raw_vector, str):
        validated["is_indian_vector"] = raw_vector.lower().strip() in ("true", "yes", "1")
    else:
        validated["is_indian_vector"] = bool(raw_vector)

    # forensic_narrative: string, safe length
    narrative = str(parsed.get("forensic_narrative", DEFAULT_SEMANTIC_RESPONSE["forensic_narrative"]))
    # Remove any accidental JSON or code artifacts from the narrative
    narrative = narrative.replace("\\n", " ").replace("\\t", " ")
    validated["forensic_narrative"] = narrative[:1000]  # Cap to 1000 chars

    # confidence: LOW|MEDIUM|HIGH
    confidence_raw = str(parsed.get("confidence", "LOW")).upper().strip()
    validated["confidence"] = confidence_raw if confidence_raw in ("LOW", "MEDIUM", "HIGH") else "LOW"

    return validated


# ═══════════════════════════════════════════════════════════════════════════════
# AST Code Slicer — Precision Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def _compute_method_sensitivity_score(source: str, matched_labels: list[str]) -> float:
    """
    Compute a heuristic sensitivity score for a method based on:
      - Number of distinct sensitive API categories matched
      - Presence of TIER 1 (ACCESSIBILITY_ABUSE, SMS_EXFILTRATION) APIs
      - Density of suspicious tokens relative to method length
    Returns a float 0.0–1.0 used for prioritizing which methods get LLM time.
    """
    score = 0.0

    # Base: number of distinct categories
    score += min(0.4, len(set(matched_labels)) * 0.1)

    # TIER 1 bonus
    if "ACCESSIBILITY_ABUSE" in matched_labels:
        score += 0.3
    if "SMS_EXFILTRATION" in matched_labels:
        score += 0.3

    # Overlay + SMS combo (common in Indian banking trojans)
    if "OVERLAY_ATTACK" in matched_labels and "SMS_EXFILTRATION" in matched_labels:
        score += 0.2

    return min(1.0, score)


def slice_sensitive_methods(decompiled_methods: list[dict]) -> list[dict]:
    """
    Precision AST code slicer — filters decompiled method dicts to extract
    only those that reference sensitive Android APIs relevant to banking malware.

    Detection strategies:
      1. Regex body scan: Match API patterns against method source code
      2. Class inheritance: Detect classes that extend AccessibilityService/
         BroadcastReceiver/DeviceAdminReceiver
      3. Annotation detection: Spot @Override methods on sensitive base classes
      4. Field initializer: Detect SmsManager.getDefault() at field-init level
      5. Inner class reference: Flag if method references inner classes
         commonly used in malware (e.g., anonymous BroadcastReceiver)

    Args:
        decompiled_methods: List of dicts with keys:
            - 'class_name' (str)
            - 'method_name' (str)
            - 'source_code' (str): Decompiled Java source for this method

    Returns:
        List of flagged method dicts, sorted by sensitivity score (highest first).
        Each dict has added keys: 'flagged_apis', 'sensitivity_score'.
    """
    flagged: list[dict] = []

    # Pre-compile class-level inheritance patterns for A11y and SMS
    CLASS_INHERITANCE_PATTERNS = [
        (re.compile(r"extends\s+AccessibilityService\b", re.IGNORECASE), "ACCESSIBILITY_ABUSE"),
        (re.compile(r"extends\s+BroadcastReceiver\b", re.IGNORECASE), "SMS_EXFILTRATION"),
        (re.compile(r"extends\s+DeviceAdminReceiver\b", re.IGNORECASE), "DEVICE_ADMIN_ABUSE"),
        (re.compile(r"extends\s+NotificationListenerService\b", re.IGNORECASE), "NOTIFICATION_SNOOPING"),
        (re.compile(r"implements\s+.*AccessibilityEventListener", re.IGNORECASE), "ACCESSIBILITY_ABUSE"),
    ]

    # Method-name patterns that are inherently suspicious
    SUSPICIOUS_METHOD_NAMES = {
        "onAccessibilityEvent":  "ACCESSIBILITY_ABUSE",
        "onServiceConnected":    "ACCESSIBILITY_ABUSE",
        "onReceive":             "SMS_EXFILTRATION",   # BroadcastReceiver.onReceive
        "onEnabled":             "DEVICE_ADMIN_ABUSE",  # DeviceAdminReceiver
        "onNotificationPosted":  "NOTIFICATION_SNOOPING",
    }

    for method in decompiled_methods:
        source = method.get("source_code", "")
        if not source or not isinstance(source, str):
            continue

        class_name = method.get("class_name", "")
        method_name = method.get("method_name", "")

        matched_labels: list[str] = []

        # ── Strategy 1: Regex body scan ────────────────────────────────────
        for compiled_pattern, label in _COMPILED_API_PATTERNS:
            if compiled_pattern.search(source):
                matched_labels.append(label)

        # ── Strategy 2: Class inheritance detection ────────────────────────
        for cls_pattern, label in CLASS_INHERITANCE_PATTERNS:
            if cls_pattern.search(source):
                if label not in matched_labels:
                    matched_labels.append(label)

        # ── Strategy 3: Suspicious method name matching ────────────────────
        if method_name in SUSPICIOUS_METHOD_NAMES:
            label = SUSPICIOUS_METHOD_NAMES[method_name]
            if label not in matched_labels:
                matched_labels.append(label)

        # ── Strategy 4: Field initializer detection ────────────────────────
        # Catches: SmsManager sms = SmsManager.getDefault();
        if re.search(r"SmsManager\s*(?:\.\s*getDefault\s*\(\s*\)|\s+\w+\s*=)", source, re.IGNORECASE):
            if "SMS_EXFILTRATION" not in matched_labels:
                matched_labels.append("SMS_EXFILTRATION")

        # AccessibilityService binding in manifest-like strings
        if re.search(r"accessibility[_-]?service|a11y[_-]?config", source, re.IGNORECASE):
            if "ACCESSIBILITY_ABUSE" not in matched_labels:
                matched_labels.append("ACCESSIBILITY_ABUSE")

        # ── Strategy 5: Inner class reference for anonymous receivers ──────
        if re.search(r"new\s+BroadcastReceiver\s*\(\s*\)", source, re.IGNORECASE):
            if "SMS_EXFILTRATION" not in matched_labels:
                matched_labels.append("SMS_EXFILTRATION")

        # ── Emit if any labels matched ─────────────────────────────────────
        if matched_labels:
            unique_labels = list(dict.fromkeys(matched_labels))  # Preserve order, deduplicate
            sensitivity = _compute_method_sensitivity_score(source, unique_labels)

            flagged.append({
                **method,
                "flagged_apis": unique_labels,
                "sensitivity_score": sensitivity,
            })

    # Sort by sensitivity score (highest first) so the most dangerous methods
    # get priority in the LLM context window
    flagged.sort(key=lambda m: m.get("sensitivity_score", 0.0), reverse=True)

    logger.info(
        "AST slicer: %d/%d methods flagged as sensitive (top risk: %s).",
        len(flagged),
        len(decompiled_methods),
        flagged[0]["flagged_apis"] if flagged else "none",
    )
    return flagged


def _build_combined_code_slice(flagged_methods: list[dict], max_chars: int = 4000) -> tuple[str, list[str]]:
    """
    Concatenates flagged method source code into a single slice for LLM analysis.
    Methods are already sorted by sensitivity_score (highest first).
    Respects a character limit to stay within LLM context windows.
    Returns (combined_code, all_flagged_api_labels).
    """
    combined_parts: list[str] = []
    all_labels: set[str] = set()
    total_chars = 0

    for method in flagged_methods:
        class_name = method.get("class_name", "Unknown")
        method_name = method.get("method_name", "unknown")
        source = method.get("source_code", "")
        labels = method.get("flagged_apis", [])
        sensitivity = method.get("sensitivity_score", 0.0)
        all_labels.update(labels)

        header = (
            f"// [RISK:{sensitivity:.2f}] Class: {class_name} "
            f"| Method: {method_name} | Flags: {', '.join(labels)}\n"
        )
        snippet = header + source + "\n\n"

        if total_chars + len(snippet) > max_chars:
            remaining = max_chars - total_chars
            if remaining > 100:
                combined_parts.append(snippet[:remaining] + "\n// [TRUNCATED — context window limit]")
            break

        combined_parts.append(snippet)
        total_chars += len(snippet)

    return "".join(combined_parts), list(all_labels)


# ═══════════════════════════════════════════════════════════════════════════════
# Ollama LLM Interface (with system prompt enforcement)
# ═══════════════════════════════════════════════════════════════════════════════

def _call_ollama(prompt: str) -> Optional[str]:
    """
    Make a request to the local Ollama API with strict system prompt.
    Uses the system+prompt separation to enforce JSON-only output at the
    model's instruction-following level.
    Returns the raw response text or None on failure.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "system": OLLAMA_SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "format": "json",   # Ollama native JSON mode (constrains output grammar)
        "options": {
            "temperature": 0.05,   # Near-zero for deterministic JSON
            "top_p": 0.85,
            "top_k": 20,           # Narrow token selection
            "repeat_penalty": 1.2, # Discourage repetitive token sequences
            "num_predict": 512,    # Sufficient for target JSON structure
            "stop": ["\n\n\n"],    # Stop on triple newline (after JSON closes)
        },
    }

    for attempt in range(1, OLLAMA_MAX_RETRIES + 1):
        try:
            logger.info("Ollama API call attempt %d/%d (model=%s)", attempt, OLLAMA_MAX_RETRIES, OLLAMA_MODEL)
            response = requests.post(
                OLLAMA_BASE_URL,
                json=payload,
                timeout=OLLAMA_TIMEOUT_SECONDS,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            raw_text = data.get("response", "").strip()
            if raw_text:
                logger.debug("Ollama raw response (first 200 chars): %s", raw_text[:200])
                return raw_text
            logger.warning("Ollama returned empty response on attempt %d", attempt)

        except requests.exceptions.ConnectionError:
            logger.error(
                "Cannot connect to Ollama at %s. Ensure Ollama is running with: ollama serve",
                OLLAMA_BASE_URL,
            )
            break
        except requests.exceptions.Timeout:
            logger.warning("Ollama request timed out on attempt %d (timeout=%ds)", attempt, OLLAMA_TIMEOUT_SECONDS)
            if attempt < OLLAMA_MAX_RETRIES:
                time.sleep(2)
        except requests.exceptions.HTTPError as exc:
            logger.error("Ollama HTTP error: %s", exc)
            # If Ollama rejects the "format":"json" param, retry without it
            if "format" in payload and attempt < OLLAMA_MAX_RETRIES:
                logger.info("Retrying without 'format: json' constraint...")
                del payload["format"]
                continue
            break
        except Exception as exc:
            logger.error("Unexpected Ollama error: %s", exc)
            break

    return None


def _call_openai(prompt: str) -> Optional[str]:
    """
    Call OpenAI Responses API with system+user separation.
    Returns raw text or None on failure.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.debug("OPENAI_API_KEY not set; skipping OpenAI provider.")
        return None

    if OpenAI is None:
        logger.error("openai package not available; cannot call OpenAI API.")
        return None

    # Instantiate client using the environment key
    try:
        client = OpenAI(api_key=api_key)
    except Exception:
        try:
            # Fallback: let the SDK read env var
            client = OpenAI()
        except Exception:
            logger.exception("Failed to instantiate OpenAI client")
            return None

    for attempt in range(1, OPENAI_MAX_RETRIES + 1):
        try:
            logger.info("OpenAI API call attempt %d/%d (model=%s)", attempt, OPENAI_MAX_RETRIES, OPENAI_MODEL)
            # Use the official SDK Responses API with instructions and input
            resp = client.responses.create(
                model=OPENAI_MODEL,
                instructions=OLLAMA_SYSTEM_PROMPT,
                input=prompt,
                temperature=0.05,
                max_output_tokens=512,
            )

            raw_text = None
            # Prefer output_text when present
            try:
                raw_text = getattr(resp, "output_text", None)
            except Exception:
                raw_text = None

            # Fallback parsing of response object
            if not raw_text:
                try:
                    out = getattr(resp, "output", None) or resp.get("output") if isinstance(resp, dict) else None
                    if out and isinstance(out, list) and len(out) > 0:
                        first = out[0]
                        if isinstance(first, dict) and "content" in first:
                            items = first["content"]
                            if isinstance(items, list) and len(items) > 0:
                                for it in items:
                                    if isinstance(it, dict) and it.get("type") == "output_text":
                                        raw_text = it.get("text")
                                        break
                            elif isinstance(items, str):
                                raw_text = items
                except Exception:
                    raw_text = None

            if raw_text:
                logger.debug("OpenAI raw response (first 200 chars): %s", raw_text[:200])
                return raw_text.strip()

            logger.warning("OpenAI returned empty response on attempt %d", attempt)

        except Exception as exc:
            logger.warning("OpenAI request failed on attempt %d: %s", attempt, exc)
            time.sleep(1)
            continue

    return None


def _call_groq(prompt: str) -> Optional[str]:
    """
    Call Groq API using the OpenAI SDK compatibility layer.
    Groq is a free cloud provider running Llama 3.1 70B — replaces Ollama.
    Returns raw response text or None on failure.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        logger.warning("GROQ_API_KEY not set; skipping Groq provider.")
        return None

    if OpenAI is None:
        logger.error("openai package not available; cannot call Groq API.")
        return None

    try:
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    except Exception:
        logger.exception("Failed to instantiate Groq client")
        return None

    for attempt in range(1, GROQ_MAX_RETRIES + 1):
        try:
            logger.info("Groq API call attempt %d/%d (model=%s)", attempt, GROQ_MAX_RETRIES, GROQ_MODEL)
            resp = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": OLLAMA_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.05,
                max_tokens=512,
            )
            raw_text = resp.choices[0].message.content
            if raw_text:
                logger.debug("Groq raw response (first 200 chars): %s", raw_text[:200])
                return raw_text.strip()
            logger.warning("Groq returned empty response on attempt %d", attempt)
        except Exception as exc:
            logger.warning("Groq request failed on attempt %d: %s", attempt, exc)
            time.sleep(1)
            continue

    return None


def _call_llm(prompt: str) -> tuple[Optional[str], str, Optional[str]]:
    """
    Provider selection wrapper. Tries OpenAI if OPENAI_API_KEY is present,
    otherwise falls back to Groq (GROQ_API_KEY). Returns tuple:
      (raw_text_or_None, provider_name, model_name_or_None)
    """
    # 1) OpenAI if key is present
    if os.environ.get("OPENAI_API_KEY"):
        try:
            raw = _call_openai(prompt)
            if raw is not None:
                return raw, "openai", OPENAI_MODEL
        except Exception as exc:
            logger.error("OpenAI provider error: %s", exc)

    # 2) Groq fallback (replaces Ollama)
    try:
        raw = _call_groq(prompt)
        if raw is not None:
            return raw, "groq", GROQ_MODEL
    except Exception as exc:
        logger.error("Groq provider error: %s", exc)

    # 3) No provider available — heuristic fallback will be used
    return None, "none", None


# ═══════════════════════════════════════════════════════════════════════════════
# Main Analysis Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_code_semantics(
    decompiled_methods: list[dict],
    static_metadata: Optional[dict] = None,
) -> dict:
    """
    Full semantic analysis pipeline:
      1. Slice methods for sensitive API access (precision AST slicer)
      2. Build a consolidated code slice (sorted by sensitivity)
      3. Query Ollama LLM with strict system prompt + JSON format constraint
      4. 7-strategy JSON repair pipeline
      5. Validate & sanitize response
      6. Return validated analysis dict

    Args:
        decompiled_methods: List of method dicts from Androguard DEX parsing.
        static_metadata: Optional dict with package_name, permissions, etc. for context.

    Returns:
        dict: Validated semantic analysis with semantic_score, primary_exploit,
              is_indian_vector, forensic_narrative, and confidence.
    """
    # Step 1: Filter sensitive methods via precision slicer
    flagged_methods = slice_sensitive_methods(decompiled_methods)

    if not flagged_methods:
        logger.info("No sensitive API methods detected. Returning benign score.")
        return {
            **DEFAULT_SEMANTIC_RESPONSE,
            "semantic_score": 0.05,
            "primary_exploit": "BENIGN",
            "forensic_narrative": (
                "No sensitive API access patterns detected in the decompiled code. "
                "The application does not appear to interact with banking, SMS, accessibility, "
                "or dynamic code loading APIs. Risk profile is LOW pending dynamic analysis."
            ),
            "confidence": "HIGH",
        }

    # Step 2: Build combined code slice (highest sensitivity first)
    code_slice, flagged_api_labels = _build_combined_code_slice(flagged_methods, max_chars=4000)

    if not code_slice.strip():
        logger.warning("Code slice was empty after building. Using defaults.")
        return {**DEFAULT_SEMANTIC_RESPONSE}

    # Step 3: Format the prompt
    prompt = ANALYSIS_PROMPT_TEMPLATE.format(
        flagged_apis=", ".join(flagged_api_labels),
        code_slice=code_slice,
    )

    # Step 4: Call LLM provider (OpenAI preferred, then Ollama)
    raw_llm_output, provider, model = _call_llm(prompt)

    if raw_llm_output is None:
        logger.warning("No LLM provider available or all providers failed. Using heuristic fallback scores.")
        # Derive a heuristic score from flagged API severity
        heuristic_score = min(0.9, 0.3 + (len(flagged_methods) * 0.08))
        # Boost if TIER 1 APIs were found
        if any("ACCESSIBILITY_ABUSE" in m.get("flagged_apis", []) for m in flagged_methods):
            heuristic_score = min(0.95, heuristic_score + 0.15)
        if any("SMS_EXFILTRATION" in m.get("flagged_apis", []) for m in flagged_methods):
            heuristic_score = min(0.95, heuristic_score + 0.12)

        # Map slicer labels to public primary_exploit schema
        label_map = {
            "ACCESSIBILITY_ABUSE": "ACCESSIBILITY_KEYLOGGING",
            "SMS_EXFILTRATION": "SMS_THEFT",
            "DYNAMIC_CODE_LOADING": "DYNAMIC_LOADING",
            "OVERLAY_ATTACK": "OVERLAY_ATTACK",
            "CALL_FORWARDING": "CALL_FORWARDING",
            "CLIPBOARD_HIJACKING": "CLIPBOARD_HIJACKING",
        }

        primary = "UNKNOWN"
        for lbl in flagged_api_labels:
            mapped = label_map.get(lbl.upper())
            if mapped:
                primary = mapped
                break

        fallback = {
            **DEFAULT_SEMANTIC_RESPONSE,
            "semantic_score": round(heuristic_score, 4),
            "primary_exploit": primary,
            "provider": provider,
            "model": model,
            "fallback": True,
        }
        return fallback

    # Step 5: 7-strategy JSON repair pipeline
    parsed = _repair_and_parse_json(raw_llm_output)

    if parsed is None:
        logger.error("All JSON repair strategies failed. Raw LLM output snippet: %s", raw_llm_output[:300])
        return {
            **DEFAULT_SEMANTIC_RESPONSE,
            "provider": provider,
            "model": model,
            "fallback": True,
        }

    # Step 6: Validate and return
    validated = _validate_semantic_response(parsed)
    # Attach provider/model metadata and fallback flag
    validated["provider"] = provider
    validated["model"] = model
    validated["fallback"] = False
    logger.info(
        "Semantic analysis complete: score=%.4f, exploit=%s, indian=%s, confidence=%s",
        validated["semantic_score"],
        validated["primary_exploit"],
        validated["is_indian_vector"],
        validated["confidence"],
    )
    return validated


# ═══════════════════════════════════════════════════════════════════════════════
# Androguard Method Extractor (Integration Helper)
# ═══════════════════════════════════════════════════════════════════════════════

def extract_methods_from_dex(apk_path: str, max_methods: int = 200) -> list[dict]:
    """
    Extract decompiled method data from an APK using Androguard.
    Returns a list of method dicts for use with analyze_code_semantics().

    Wrapped in comprehensive try-except to handle corrupt DEX data, truncated
    files, and Androguard internal errors without crashing.

    Args:
        apk_path: Path to the APK file.
        max_methods: Maximum number of methods to extract (performance cap).

    Returns:
        List of method dicts with class_name, method_name, source_code.
    """
    methods: list[dict] = []

    try:
        from androguard.misc import AnalyzeAPK  # type: ignore
    except ImportError:
        logger.error("Androguard not installed. Cannot extract DEX methods.")
        return methods

    try:
        logger.info("Extracting DEX methods from APK: %s", apk_path)
        _, dex_list, _ = AnalyzeAPK(apk_path)
    except Exception as exc:
        logger.error("AnalyzeAPK failed (corrupt DEX or packed APK): %s | %s", exc, apk_path)
        return methods

    if not dex_list:
        logger.warning("No DEX files found in APK: %s", apk_path)
        return methods

    # Framework class prefixes to skip (not malware code)
    SKIP_PREFIXES = (
        "Landroid/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",
        "Lcom/google/android/", "Landroidx/", "Lcom/squareup/",
        "Lcom/google/protobuf/", "Lcom/google/gson/",
        "Lokhttp3/", "Lretrofit2/", "Lcom/bumptech/glide/",
        "Lorg/apache/", "Lorg/json/", "Lcom/facebook/",
    )

    for dex in dex_list:
        if len(methods) >= max_methods:
            break
        try:
            classes = dex.get_classes()
        except Exception as exc:
            logger.warning("get_classes() failed on DEX segment: %s", exc)
            continue

        for cls in classes:
            if len(methods) >= max_methods:
                break
            try:
                class_name = cls.get_name()
            except Exception:
                continue

            # Skip framework classes
            if any(class_name.startswith(prefix) for prefix in SKIP_PREFIXES):
                continue

            try:
                cls_methods = cls.get_methods()
            except Exception as exc:
                logger.debug("get_methods() failed for class %s: %s", class_name, exc)
                continue

            for method in cls_methods:
                if len(methods) >= max_methods:
                    break
                try:
                    source = method.get_source()
                    if source and isinstance(source, str) and len(source.strip()) > 30:
                        methods.append({
                            "class_name": class_name,
                            "method_name": method.get_name(),
                            "source_code": source[:2000],  # Cap per-method
                        })
                except Exception:
                    # Individual method decompilation can fail (obfuscated bytecode)
                    continue

    logger.info("Extracted %d methods from APK.", len(methods))
    return methods


def analyze_code_with_llm(decompiled_code: str) -> dict:
    """
    Public convenience wrapper for semantic analysis when only a single
    decompiled source blob is available (e.g., a full Java file or
    concatenated decompiled output).

    This function constructs a minimal per-method structure, runs the
    existing slicing + Ollama pipeline, and returns a JSON-serializable
    dict that includes at minimum:
      - `Ssem`: semantic severity score (0.0-1.0)
      - `semantic_score`, `primary_exploit`, `is_indian_vector`, `forensic_narrative`, `confidence`
      - `findings`: list of flagged methods with `class_name`, `method_name`, `flagged_apis`, `sensitivity_score`
      - `suspicious_apis`: list of unique suspicious API labels discovered by the slicer

    The function is defensive: it never raises on LLM failures and will
    return a deterministic fallback response if Ollama is unreachable or
    the LLM output cannot be repaired.
    """
    try:
        if not decompiled_code or not isinstance(decompiled_code, str):
            logger.warning("Empty or invalid decompiled_code provided to analyze_code_with_llm.")
            base = {**DEFAULT_SEMANTIC_RESPONSE}
            base["Ssem"] = float(base.get("semantic_score", 0.5))
            base["findings"] = []
            base["suspicious_apis"] = []
            return base

        # Build a single pseudo-method so the existing slicer can operate.
        # The slicer will identify sensitive regions and _build_combined_code_slice
        # will ensure we do NOT send unbounded source to the LLM.
        decompiled_methods = [{
            "class_name": "Unknown",
            "method_name": "full_file",
            "source_code": decompiled_code,
        }]

        # Run the main semantic analysis pipeline (this will call Ollama).
        analysis = analyze_code_semantics(decompiled_methods, static_metadata=None)

        # Independently run the slicer to produce structured findings and
        # suspicious API labels for inclusion in the returned payload.
        flagged = slice_sensitive_methods(decompiled_methods)
        findings = []
        for m in flagged:
            findings.append({
                "class_name": m.get("class_name", "Unknown"),
                "method_name": m.get("method_name", "unknown"),
                "flagged_apis": m.get("flagged_apis", []),
                "sensitivity_score": float(m.get("sensitivity_score", 0.0)),
            })

        # Aggregate suspicious API labels
        try:
            _, api_labels = _build_combined_code_slice(flagged, max_chars=4000)
            suspicious_apis = sorted(set(api_labels))
        except Exception:
            suspicious_apis = []

        # Ensure we always include Ssem (clamped) and mirror semantic_score
        semantic_score = float(analysis.get("semantic_score", analysis.get("Ssem", 0.5)))
        semantic_score = max(0.0, min(1.0, semantic_score))

        result = {
            "Ssem": round(semantic_score, 4),
            **{k: analysis.get(k) for k in ("semantic_score", "primary_exploit", "is_indian_vector", "forensic_narrative", "confidence")},
            "provider": analysis.get("provider", "none"),
            "model": analysis.get("model", None),
            "fallback": bool(analysis.get("fallback", False)),
            "findings": findings,
            "suspicious_apis": suspicious_apis,
        }

        # Guarantee JSON-serializable types
        try:
            json.dumps(result)
        except TypeError:
            # Coerce any non-serializable items to strings as a last resort
            for k, v in list(result.items()):
                try:
                    json.dumps({k: v})
                except TypeError:
                    result[k] = str(v)

        return result

    except Exception as exc:
        logger.exception("analyze_code_with_llm failed unexpectedly: %s", exc)
        fallback = {**DEFAULT_SEMANTIC_RESPONSE}
        fallback["Ssem"] = float(fallback.get("semantic_score", 0.5))
        fallback["findings"] = []
        fallback["suspicious_apis"] = []
        return fallback
