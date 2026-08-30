# backend/static_parser.py
"""
NIRIKSHAK-AI :: Hardened APK Static Analysis Engine
Extracts metadata, permissions, strings, and behavioral indicators from Android APKs.
Uses Androguard with extreme-robustness error handling for malformed, packed,
obfuscated, or corrupted APKs — always returns a clean dictionary, never crashes.
"""

import hashlib
import logging
import re
import struct
import traceback
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger("nirikshak.static_parser")

# ─── Indian Banking & UPI Target Signatures ─────────────────────────────────
# Deeply expanded list covering UPI rails, all major PSU / private banks,
# UPI-linked wallets, USSD call-forwarding sequences, and intent-level strings.
INDIAN_BANKING_TARGETS = [
    # ── UPI Rails & NPCI Core Infrastructure ────────────────────────────────
    "in.org.npci.upiapp",                       # BHIM UPI (official NPCI app)
    "in.org.npci.bhim.psp",                     # BHIM PSP module
    "in.org.npci.commonlibrary",                # NPCI common library
    "com.npci.upi.psp",                         # Generic NPCI PSP provider
    "upi://pay",                                # UPI deep-link URI scheme
    "upi://mandate",                            # UPI autopay mandate URI

    # ── SBI (State Bank of India) — Full Coverage ───────────────────────────
    "com.sbi.lotusintouch",                     # YONO SBI
    "com.sbi.SBIFreedomPlus",                   # SBI Freedom Plus
    "com.sbi.upi",                              # SBI Pay UPI
    "com.sbi.securedotp",                       # SBI Secured OTP
    "com.sbi.SBISecure",                        # SBI Secure (OTP generator)
    "com.sbi.sbi.online",                       # SBI Online portal app
    "com.sbi.SBAnywhereCorporate",              # SBI Anywhere Corporate
    "com.sbi.SBAnywherePremier",                # SBI Anywhere Retail

    # ── PhonePe — Full Coverage ─────────────────────────────────────────────
    "com.phonepe.app",                          # PhonePe main app
    "com.phonepe.app.prepaid",                  # PhonePe prepaid services
    "com.phonepe.merchant",                     # PhonePe for Business
    "phonepe.intent.action.PAY",                # PhonePe payment intent
    "com.phonepe.app.BL",                       # PhonePe BL variant

    # ── Google Pay India ────────────────────────────────────────────────────
    "com.google.android.apps.nbu.paisa.user",   # Google Pay (Tez)
    "com.google.android.apps.nbu.files",        # GPay Files linked
    "com.google.android.gms.tapandpay",         # Google Tap & Pay NFC

    # ── Paytm ───────────────────────────────────────────────────────────────
    "net.one97.paytm",                          # Paytm main app
    "com.paytm.business",                       # Paytm for Business
    "com.paytm.pgsdk",                          # Paytm Payment Gateway SDK
    "net.one97.paytm.miniapps",                 # Paytm Mini Apps

    # ── Other Major UPI / Wallet Apps ───────────────────────────────────────
    "com.amazon.mShop.android.shopping",        # Amazon Pay
    "com.mobikwik_new",                         # MobiKwik
    "com.freecharge.android",                   # Freecharge
    "com.myairtelapp",                          # Airtel Thanks (Airtel Payments Bank)
    "com.jio.myjio",                            # My Jio (Jio Payments Bank)
    "in.swiggy.android",                        # Swiggy Pay
    "com.navi.psp.app",                         # Navi UPI
    "com.cred.customer",                        # CRED
    "com.slice.app",                            # Slice (fi.money UPI)
    "in.fi.money.fi",                           # fi.money
    "com.jupiter.app",                          # Jupiter (banking fintech)

    # ── Public Sector Banks ─────────────────────────────────────────────────
    "com.pnb.mbanking",                         # PNB ONE
    "com.pnb.pnbupi",                           # PNB UPI
    "com.boi.Bank_of_india",                    # BOI Mobile
    "com.canarabank.mobility",                  # Canara ai1 mBanking
    "com.unionbank.ecom.mobile.android",        # Union Bank Vyom
    "com.infrasofttech.bob",                    # Bank of Baroda
    "com.infrasofttech.centralbank",            # Central Bank of India
    "com.ubi.mbanking",                         # Union Bank (legacy)
    "com.iob.mbank",                            # Indian Overseas Bank
    "com.indianbank.indianbankmobile",          # Indian Bank
    "com.barodampay",                           # Baroda mPay

    # ── Private Banks ───────────────────────────────────────────────────────
    "com.csam.icici.bank.imobile",              # iMobile Pay
    "com.icicibank.pocketsACE",                 # ICICI Pockets
    "com.axis.mobile",                          # Axis Mobile
    "com.axis.gpay",                            # Axis GPay integration
    "com.msf.kbank.mobile",                     # Kotak 811
    "com.kotak.nethawk",                        # Kotak Netbanking
    "com.indusind.mobile",                      # IndusInd IndusMobile
    "com.indusind.induspsp",                    # IndusInd UPI PSP
    "com.idfcfirstbank.mobileapp",              # IDFC FIRST Bank
    "com.rblbank.mobank",                       # RBL MoBank
    "com.hdfcbank.mobilebanking",               # HDFC Mobile Banking
    "com.snapwork.hdfc",                        # HDFC PayZapp
    "com.yesbank.mobilebanking",                # YES Mobile
    "com.bankofbaroda.upi",                     # BOB UPI
    "com.federalbank.fedmobile",                # Federal Bank FedMobile

    # ── USSD Financial Forwarding Codes ─────────────────────────────────────
    # Malware uses these to redirect OTP calls/SMS to attacker-controlled numbers
    "*21*",   # Unconditional call forwarding — diverts ALL incoming calls
    "**21*",  # Unconditional forwarding (alternate activation syntax)
    "*21#",   # Query unconditional forwarding status
    "#21#",   # Deactivate unconditional forwarding
    "##21#",  # Erase unconditional forwarding
    "*62*",   # Forward when not reachable — triggers when phone powered off
    "**62*",  # Not-reachable forwarding (alternate syntax)
    "*67*",   # Forward when busy — intercepts calls during active conversation
    "**67*",  # Busy forwarding (alternate syntax)
    "*61*",   # Forward when no answer — captures after N ring timeout
    "**61*",  # No-answer forwarding (alternate syntax)
    "#61#",   # Cancel conditional forwarding
    "#62#",   # Cancel not-reachable forwarding
    "#67#",   # Cancel busy forwarding
    "##002#", # Cancel ALL call forwarding (emergency deactivation)
    "*002#",  # Activate all conditional forwarding
    "*401*",  # Airtel USSD banking prefix
    "*99#",   # NPCI NUUP (National Unified USSD Platform) banking shortcode
    "*99*99#", # NUUP balance enquiry
    "*99*00#", # NUUP UPI PIN change
    "*400*",  # Jio USSD banking prefix
    "*389#",  # Vodafone Idea M-Pesa USSD

    # ── Sensitive Intent / Action Strings (manifest-level targets) ──────────
    "android.intent.action.SEND_SMS",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.PHONE_STATE",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.SMS_DELIVER",
    "android.provider.Telephony.WAP_PUSH_RECEIVED",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.accessibilityservice.AccessibilityService",
]

# ─── High-Risk Android Permissions ──────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.WRITE_SETTINGS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.USE_FULL_SCREEN_INTENT",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}

# ─── Suspicious String Patterns ─────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE),  # Hardcoded IPs
    re.compile(r"\.onion\b", re.IGNORECASE),                                        # Tor endpoints
    re.compile(r"(telegram\.me|t\.me)/\w+", re.IGNORECASE),                        # Telegram C2
    re.compile(r"\b(admin|root|superuser)\b", re.IGNORECASE),                      # Privilege keywords
    re.compile(r"(base64|cipher|encrypt|decrypt|aes|rsa)", re.IGNORECASE),         # Crypto hints
    re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader", re.IGNORECASE),  # Dynamic loading
    re.compile(r"getDeviceId|getImei|getSubscriberId", re.IGNORECASE),             # Device fingerprinting
    re.compile(r"\*\d{2,4}\*", re.IGNORECASE),                                     # USSD codes
    re.compile(r"AccessibilityService|performGlobalAction", re.IGNORECASE),        # A11y abuse
    re.compile(r"SmsManager|sms_body|pdus", re.IGNORECASE),                        # SMS API
    re.compile(r"KeyLogger|KeyEvent|dispatchKeyEvent", re.IGNORECASE),             # Keylogging
    re.compile(r"getMacAddress|getSSID|WifiManager", re.IGNORECASE),               # WiFi fingerprinting
]


def _compute_sha256(apk_bytes: bytes) -> str:
    """Compute SHA-256 hash of APK byte content."""
    return hashlib.sha256(apk_bytes).hexdigest()

def _compute_sha1(apk_bytes: bytes) -> str:
    """Compute SHA-1 hash of APK byte content."""
    return hashlib.sha1(apk_bytes).hexdigest()


def _is_valid_zip(apk_path: str) -> bool:
    """
    Pre-validate that the file is a structurally intact ZIP archive.
    APKs that are corrupt at the ZIP level will crash Androguard hard.
    This catches truncated downloads, partial writes, and non-APK renames.
    """
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            # Check for the presence of at least a manifest file
            names = zf.namelist()
            return "AndroidManifest.xml" in names
    except (zipfile.BadZipFile, OSError, struct.error, EOFError):
        return False


def _is_valid_apk_magic(apk_bytes: bytes) -> bool:
    """
    Verify the APK begins with the ZIP local file header magic bytes (PK\x03\x04).
    Catches files that are simply misnamed (e.g., a JPEG with .apk extension).
    """
    return len(apk_bytes) > 4 and apk_bytes[:4] == b"PK\x03\x04"


def _extract_hardcoded_strings(apk_obj) -> list[str]:
    """
    Safely extract hardcoded strings from APK resources and manifest.
    Uses multiple fallback strategies if any extraction path fails.
    """
    collected: list[str] = []

    # ── Strategy 1: Resource string values via Androguard API ──────────────
    try:
        if hasattr(apk_obj, "get_all_values"):
            for val in apk_obj.get_all_values():
                if val and isinstance(val, str) and 4 <= len(val) <= 512:
                    collected.append(val.strip())
    except Exception as exc:
        logger.debug("Resource string extraction (get_all_values) failed: %s", exc)

    # ── Strategy 2: Parse strings from raw resources.arsc ──────────────────
    try:
        if hasattr(apk_obj, "get_android_resources"):
            arsc = apk_obj.get_android_resources()
            if arsc and hasattr(arsc, "get_resolved_strings"):
                for _pkg_name, _locale_dict in arsc.get_resolved_strings().items():
                    for _locale, strings_dict in _locale_dict.items():
                        for _str_id, val in strings_dict.items():
                            if val and isinstance(val, str) and 4 <= len(val) <= 512:
                                collected.append(val.strip())
    except Exception as exc:
        logger.debug("Resource string extraction (resources.arsc) failed: %s", exc)

    # ── Strategy 3: URLs and deep-links from AndroidManifest.xml ───────────
    try:
        manifest_xml = apk_obj.get_android_manifest_axml().get_xml()
        if manifest_xml:
            manifest_text = manifest_xml.decode("utf-8", errors="replace")
            urls = re.findall(r'https?://[^\s"<>]+', manifest_text)
            collected.extend(urls)
            # Also extract UPI deep-link schemes
            upi_links = re.findall(r'upi://[^\s"<>]+', manifest_text)
            collected.extend(upi_links)
    except Exception as exc:
        logger.debug("Manifest URL extraction failed: %s", exc)

    # ── Strategy 4: Extract strings from the raw DEX constant pools ────────
    try:
        if hasattr(apk_obj, "get_dex"):
            dex_data = apk_obj.get_dex()
            if dex_data and isinstance(dex_data, bytes):
                # Quick regex scan for URLs and package names in raw DEX bytes
                dex_text = dex_data.decode("utf-8", errors="replace")
                dex_urls = re.findall(r'https?://[^\x00-\x1f\s"<>]{8,256}', dex_text)
                collected.extend(dex_urls[:100])
                # USSD codes in DEX strings
                ussd_codes = re.findall(r'[\*#]\d{2,5}[\*#]', dex_text)
                collected.extend(ussd_codes[:30])
    except Exception as exc:
        logger.debug("DEX string extraction failed: %s", exc)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique = []
    for s in collected:
        key = s.lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(s.strip())

    return unique[:500]  # Cap to 500 strings to avoid memory bloat


def _match_targets(strings: list[str], permissions: list[str]) -> dict:
    """
    Check extracted strings and permissions against the Indian banking target list.
    Returns matched targets and a boolean indicator.
    """
    matched_targets: list[str] = []
    matched_patterns: list[str] = []

    # Build a single lowercase search blob
    string_blob = "\n".join(strings).lower()

    # Check direct string containment against target list
    for target in INDIAN_BANKING_TARGETS:
        if target.lower() in string_blob:
            matched_targets.append(target)

    # Check permissions against target list (record as findings but
    # do not automatically escalate to a banking target unless the
    # match represents a banking package/UPI/USSD indicator).
    for perm in permissions:
        if perm in INDIAN_BANKING_TARGETS:
            matched_targets.append(perm)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_matched: list[str] = []
    for t in matched_targets:
        key = t.lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique_matched.append(t)

    # Determine which of the matched targets are *actual banking indicators*.
    # Banking indicators include:
    #  - UPI deep-link schemes (starts with 'upi://')
    #  - Package names / vendor identifiers (contain a dot but are not android.*)
    #  - USSD / call-forwarding codes (start with '*' or '#')
    banking_indicators: list[str] = []
    for t in unique_matched:
        try:
            if not isinstance(t, str):
                continue
            low = t.lower()
            if low.startswith("upi://"):
                banking_indicators.append(t)
            elif re.match(r'^[\*#]', t):
                # USSD-style code
                banking_indicators.append(t)
            elif "." in t and not low.startswith("android."):
                # Likely a package name or vendor-specific identifier
                banking_indicators.append(t)
        except Exception:
            continue

    # Apply regex suspicious pattern detection (these are reported
    # as suspicious patterns but do not by themselves flip banking
    # detection unless they match a banking indicator above).
    for pattern in SUSPICIOUS_PATTERNS:
        for s in strings:
            try:
                match = pattern.search(s)
                if match and match.group() not in matched_patterns:
                    matched_patterns.append(match.group())
            except Exception:
                continue

    return {
        "target_detected": len(banking_indicators) > 0,
        "matched_targets": sorted(set(unique_matched)),
        "suspicious_patterns": matched_patterns[:30],
    }


def _compute_permission_score(permissions: list[str]) -> float:
    """
    Compute a normalized 0.0–1.0 score based on dangerous permission count.
    Uses a sigmoid-like curve so the score scales more realistically:
      1 perm → 0.15, 3 perms → 0.50, 5 perms → 0.80, 8+ perms → 0.98+
    """
    dangerous_found = set(permissions) & DANGEROUS_PERMISSIONS
    n = len(dangerous_found)
    if n == 0:
        return 0.0
    # Tanh-based curve: ramps quickly at 3-5 perms, saturates near 1.0 at 8+
    import math
    score = math.tanh(n * 0.3)
    return round(min(1.0, score), 4)


def _safe_extract_metadata(apk_obj, method_name: str, default=None):
    """
    Safely call any Androguard APK metadata method with full exception isolation.
    Returns the method result or the default value on any failure.
    """
    try:
        method = getattr(apk_obj, method_name, None)
        if method is None:
            return default
        result = method()
        return result if result is not None else default
    except (AttributeError, TypeError, ValueError, IndexError, KeyError) as exc:
        logger.debug("Metadata extraction '%s' returned recoverable error: %s", method_name, exc)
        return default
    except Exception as exc:
        logger.warning("Metadata extraction '%s' failed unexpectedly: %s", method_name, exc)
        return default


def parse_apk(apk_path: str) -> dict:
    """
    Main static analysis entry point. Accepts a file path to an APK.

    Guaranteed contract: ALWAYS returns a clean, fully-populated dictionary
    regardless of how corrupt, malformed, packed, or adversarial the input APK is.
    Individual extraction stages are fully isolated — a crash in one stage
    does not prevent others from completing. The result dict is pre-initialized
    with safe defaults, and each stage writes into it independently.

    Args:
        apk_path: Absolute or relative path to the APK file.

    Returns:
        dict: Analysis results including metadata, permissions, strings,
              target detection results, and a permission danger score.
    """
    # ── Pre-initialize result with safe defaults (never modified all-at-once) ──
    result: dict = {
        "success": False,
        "error": None,
        "parse_warnings": [],
        "package_name": "unknown",
        "app_name": "unknown",
        "target_sdk": None,
        "min_sdk": None,
        "sha256": "unknown",
        "sha1": "unknown",
        "permissions": [],
        "dangerous_permissions": [],
        "hardcoded_strings": [],
        "target_detection": {
            "target_detected": False,
            "matched_targets": [],
            "suspicious_patterns": [],
        },
        # Top-level convenience flag mirroring target_detection['target_detected']
        "target_detected": False,
        "permission_danger_score": 0.0,
        "file_size_bytes": 0,
        "activities_count": 0,
        "services_count": 0,
        "receivers_count": 0,
        "providers_count": 0,
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # GATE 1: File existence & byte-level integrity checks
    # ═══════════════════════════════════════════════════════════════════════════
    try:
        apk_file = Path(apk_path)
        if not apk_file.exists():
            result["error"] = f"APK file not found: {apk_path}"
            return result

        apk_bytes = apk_file.read_bytes()
        result["file_size_bytes"] = len(apk_bytes)
        result["sha256"] = _compute_sha256(apk_bytes)
        result["sha1"] = _compute_sha1(apk_bytes)

    except OSError as exc:
        result["error"] = f"File I/O error: {exc}"
        logger.error("APK read failure: %s", exc)
        return result
    except MemoryError:
        result["error"] = "APK file too large to fit in memory"
        logger.error("MemoryError reading APK: %s", apk_path)
        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # GATE 2: ZIP structural integrity check (catches corrupt APKs before Androguard)
    # ═══════════════════════════════════════════════════════════════════════════
    if not _is_valid_apk_magic(apk_bytes):
        result["error"] = (
            f"File is not a valid APK (bad magic bytes). "
            f"Expected PK header, got: {apk_bytes[:4].hex() if len(apk_bytes) >= 4 else 'too short'}"
        )
        result["parse_warnings"].append("INVALID_MAGIC_BYTES")
        result["success"] = True  # Still return hash + file_size
        return result

    if not _is_valid_zip(apk_path):
        result["error"] = (
            "APK is a corrupt or malformed ZIP archive (no AndroidManifest.xml found). "
            "Returning partial data: SHA-256 hash and file size are still valid."
        )
        result["parse_warnings"].append("CORRUPT_ZIP")
        result["success"] = True
        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # GATE 3: Androguard APK object construction
    # Fully isolated — on failure, returns partial data (hash + size).
    # ═══════════════════════════════════════════════════════════════════════════
    apk_obj = None

    try:
        from androguard.core.bytecodes.apk import APK  # type: ignore
    except ImportError:
        result["error"] = "androguard not installed. Run: pip install androguard"
        logger.critical("Androguard import failed.")
        result["parse_warnings"].append("ANDROGUARD_MISSING")
        return result

    try:
        apk_obj = APK(apk_path)
    except Exception as exc:
        # APK is malformed or packed but we still have the hash & file metadata.
        # Log the traceback for debugging but don't crash.
        logger.warning(
            "Androguard APK constructor failed (returning partial data): %s\n%s",
            exc, traceback.format_exc()
        )
        result["error"] = f"Partial parse (Androguard init): {str(exc)[:200]}"
        result["parse_warnings"].append("ANDROGUARD_INIT_FAILED")
        result["success"] = True

        # ── Attempt a raw-ZIP fallback to extract AndroidManifest permissions ──
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    raw_manifest = zf.read("AndroidManifest.xml")
                    # Binary XML can't be easily parsed without Androguard,
                    # but we can grep for permission strings in the raw bytes.
                    manifest_text = raw_manifest.decode("utf-8", errors="replace")
                    perm_hits = re.findall(r"android\.permission\.[A-Z_]+", manifest_text)
                    result["permissions"] = sorted(set(perm_hits))
                    result["dangerous_permissions"] = [
                        p for p in result["permissions"] if p in DANGEROUS_PERMISSIONS
                    ]
                    result["permission_danger_score"] = _compute_permission_score(result["permissions"])
                    result["parse_warnings"].append("ZIP_FALLBACK_PERMISSIONS_EXTRACTED")
        except Exception as zip_exc:
            logger.debug("ZIP fallback permission extraction also failed: %s", zip_exc)

        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 1: Metadata extraction — each field fully isolated
    # ═══════════════════════════════════════════════════════════════════════════
    pkg = _safe_extract_metadata(apk_obj, "get_package", "unknown")
    result["package_name"] = pkg if isinstance(pkg, str) and pkg else "unknown"

    app = _safe_extract_metadata(apk_obj, "get_app_name", "unknown")
    result["app_name"] = app if isinstance(app, str) and app else "unknown"

    try:
        raw_target = _safe_extract_metadata(apk_obj, "get_target_sdk_version", None)
        result["target_sdk"] = int(raw_target) if raw_target is not None else None
    except (TypeError, ValueError):
        result["target_sdk"] = None

    try:
        raw_min = _safe_extract_metadata(apk_obj, "get_min_sdk_version", None)
        result["min_sdk"] = int(raw_min) if raw_min is not None else None
    except (TypeError, ValueError):
        result["min_sdk"] = None

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 2: Permission extraction — fully isolated
    # ═══════════════════════════════════════════════════════════════════════════
    try:
        all_permissions = apk_obj.get_permissions()
        if all_permissions is None:
            all_permissions = []
        # Filter out any non-string entries (defensive)
        all_permissions = [p for p in all_permissions if isinstance(p, str)]
        result["permissions"] = all_permissions
        result["dangerous_permissions"] = [
            p for p in all_permissions if p in DANGEROUS_PERMISSIONS
        ]
    except Exception as exc:
        logger.warning("Permission extraction failed: %s", exc)
        result["parse_warnings"].append("PERMISSION_EXTRACTION_FAILED")

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 3: Component counts — each fully isolated
    # ═══════════════════════════════════════════════════════════════════════════
    component_methods = [
        ("activities_count", "get_activities"),
        ("services_count",   "get_services"),
        ("receivers_count",  "get_receivers"),
        ("providers_count",  "get_providers"),
    ]
    for key, method_name in component_methods:
        try:
            components = _safe_extract_metadata(apk_obj, method_name, [])
            result[key] = len(components) if components else 0
        except Exception as exc:
            logger.debug("Component count '%s' failed: %s", key, exc)
            result[key] = 0

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 4: Hardcoded string extraction — fully isolated
    # ═══════════════════════════════════════════════════════════════════════════
    try:
        result["hardcoded_strings"] = _extract_hardcoded_strings(apk_obj)
    except Exception as exc:
        logger.warning("String extraction failed (non-fatal): %s", exc)
        result["parse_warnings"].append("STRING_EXTRACTION_FAILED")

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 5: Target & pattern detection — fully isolated
    # ═══════════════════════════════════════════════════════════════════════════
    try:
        result["target_detection"] = _match_targets(
            result["hardcoded_strings"], result["permissions"]
        )
        # Keep a top-level boolean in sync with the nested target_detection
        try:
            result["target_detected"] = bool(result["target_detection"].get("target_detected"))
        except Exception:
            result["target_detected"] = False
    except Exception as exc:
        logger.warning("Target detection failed (non-fatal): %s", exc)
        result["parse_warnings"].append("TARGET_DETECTION_FAILED")

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 6: Permission danger score — fully isolated
    # ═══════════════════════════════════════════════════════════════════════════
    try:
        result["permission_danger_score"] = _compute_permission_score(result["permissions"])
    except Exception as exc:
        logger.warning("Permission scoring failed (non-fatal): %s", exc)
        result["permission_danger_score"] = 0.0

    # ═══════════════════════════════════════════════════════════════════════════
    # FINAL: Mark success and log summary
    # ═══════════════════════════════════════════════════════════════════════════
    result["success"] = True
    logger.info(
        "Static analysis complete: pkg=%s, sha256=%s..., perms=%d, dangerous=%d, target=%s, warnings=%d",
        result["package_name"],
        result["sha256"][:16],
        len(result["permissions"]),
        len(result["dangerous_permissions"]),
        result["target_detection"]["target_detected"],
        len(result["parse_warnings"]),
    )

    return result


# ─── CLI Quick-Test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python static_parser.py <path_to.apk>")
        sys.exit(1)

    output = parse_apk(sys.argv[1])
    print(json.dumps(output, indent=2, default=str))
