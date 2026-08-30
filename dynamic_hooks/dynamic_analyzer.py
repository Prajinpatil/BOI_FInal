"""
NIRIKSHAK-AI :: Dynamic Sandbox Telemetry Parser & Risk Evaluator
==================================================================

Module   : dynamic_hooks/dynamic_analyzer.py
Role     : Member B — Dynamic Sandbox & Anti-Evasion Engine
Purpose  : Parse raw sandbox output (MobSF JSON report + PCAP) and compute
           the Dynamic Risk Factor (S_dyn) used by scoring.py.

Public API
----------
    evaluate_dynamic_telemetry(report_data, pcap_path) -> dict

Return contract
---------------
    {
        "s_dynamic":         float,   # 0.0 – 1.0 (bounded, used by scoring.py)
        "c2_indicators":     list,    # Detected C2 IPs / domains
        "sms_intercepted":   bool,    # SMS exfiltration detected
        "evasion_techniques":list,    # Bypassed / detected anti-analysis methods
        "runtime_events":    list,    # Ordered timeline events for React frontend
    }

Architecture notes
------------------
*   No network call or live Docker dependency is required; the module is fully
    self-contained and falls back gracefully to a deterministic simulation mode
    when no sandbox data is available.
*   PCAP parsing uses scapy (optional) and degrades silently to stub mode if
    scapy / libpcap is unavailable in the analysis environment.
*   All weights and thresholds are tunable through the MODULE_CONFIG dict at
    the top of this file.

Author  : NIRIKSHAK-AI — Member B
Version : 2.0.0
Updated : 2026-08-14
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

# ── Optional heavy imports (graceful fallback) ────────────────────────────────
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

# ── Logger ────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NIRIKSHAK-DYN] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ═══════════════════════════════════════════════════════════════════════════════
# § 0 — MODULE CONFIGURATION  (tune without touching logic)
# ═══════════════════════════════════════════════════════════════════════════════
MODULE_CONFIG: dict = {
    # ── Score weights (must sum to ≤ 1.0) ────────────────────────────────────
    "weight_c2_connections":       0.25,   # Confirmed C2 / malicious IPs
    "weight_suspicious_ports":     0.15,   # Traffic on non-standard ports
    "weight_sms_exfiltration":     0.20,   # SMS read / send APIs called at runtime
    "weight_overlay_abuse":        0.15,   # Overlay / screen draw-over detected
    "weight_accessibility_abuse":  0.10,   # Accessibility service abused
    "weight_ussd_strings":         0.10,   # USSD codes in network payload
    "weight_evasion_detected":     0.05,   # Confirmed anti-analysis behaviour

    # ── Thresholds ────────────────────────────────────────────────────────────
    "suspicious_port_min":         1024,   # Ports < this are considered standard
    "c2_connection_count_cap":     10,     # Above this, full weight is applied
    "suspicious_port_count_cap":   5,

    # ── Known malicious IP ranges (CIDR) — extend as threat intel grows ───────
    "known_malicious_cidrs": [
        "185.220.0.0/16",    # Common C2 / bulletproof hosting bloc
        "45.142.0.0/16",
        "91.108.4.0/22",     # Telegram (used by some RATs as C2)
        "194.165.0.0/16",
        "5.188.0.0/16",      # Frantech / BuyVM bulletproof range
    ],

    # ── Known C2 domain TLD / keyword patterns ────────────────────────────────
    # NOTE: Only use keywords specific enough to NOT match legitimate service
    # subdomains (e.g. avoid 'api', 'cdn', 'update' — too generic).
    # Dynamic-DNS service names are handled by the hard-coded allowlist inside
    # _looks_like_c2_domain() to avoid false-positives on real domains.
    "c2_domain_keywords": [
        "ddns", "duckdns", "no-ip", "ngrok", "serveo", "pagekite",
        "hopto", "zapto", "changeip", "redirectme", "myq-see",
    ],

    # ── Standard ports — traffic to these is NOT flagged suspicious ───────────
    "standard_ports": {
        20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
        3306, 5432, 6379, 8080, 8443,
    },

    # ── USSD regex patterns (e.g. *121#, *99#, *123*1#) ──────────────────────
    "ussd_pattern": r"\*[0-9*#]+#",

    # ── MobSF report JSON keys of interest ───────────────────────────────────
    "mobsf_network_key":   "network_security",
    "mobsf_activity_key":  "activities",
    "mobsf_api_key":       "android_api",
}

# ═══════════════════════════════════════════════════════════════════════════════
# § 1 — DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkIndicator:
    """Represents a single suspicious network endpoint identified at runtime."""
    host:        str
    port:        int
    proto:       str              # "TCP" | "UDP" | "DNS"
    direction:   str              # "OUTBOUND" | "INBOUND"
    is_c2:       bool   = False
    is_suspicious_port: bool = False
    raw_payload: bytes  = field(default_factory=bytes, repr=False)


@dataclass
class RuntimeEvent:
    """Single event on the dynamic analysis timeline (used by React frontend)."""
    timestamp:   float
    category:    str              # "network" | "sms" | "overlay" | "evasion" | "file"
    severity:    str              # "low" | "medium" | "high" | "critical"
    description: str
    metadata:    dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp":   self.timestamp,
            "category":    self.category,
            "severity":    self.severity,
            "description": self.description,
            "metadata":    self.metadata,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# § 2 — IP / DOMAIN HELPER UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is RFC-1918 / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _is_malicious_ip(ip_str: str, cidrs: list[str]) -> bool:
    """Return True if the IP falls within a known malicious CIDR range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for cidr in cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def _looks_like_c2_domain(domain: str, keywords: list[str]) -> bool:
    """
    Heuristic: a domain is C2-like if it uses dynamic-DNS / tunnel-service
    keywords that appear as a *whole label* in the domain hierarchy, or
    has a DGA-like structure (many subdomains / low vowel ratio).

    Matching is done at the DNS label level, not as a plain substring, to
    avoid false-positives on legitimate domains like ``api.paytm.com`` which
    contain "api" only as the SLD subdomain (not a dynamic-DNS service name).
    """
    domain_lower = domain.lower().strip(".")
    labels = domain_lower.split(".")

    # Build the set of labels that form the *registrable* part and below,
    # i.e. everything except the public suffix (last 1-2 labels).
    # We check whether any keyword equals a full label OR forms the
    # second-level domain (SLD) exactly — this prevents "api.paytm.com"
    # from matching the keyword "api" which is only its subdomain label.
    #
    # Exception: a small set of well-known dynamic-DNS *TLD-equivalent*
    # strings (duckdns.org, no-ip.biz, ngrok.io, …) are matched against
    # the *registered domain* (labels[-2] + '.' + labels[-1]).
    dynamic_dns_registered_domains = {
        "duckdns.org", "no-ip.biz", "no-ip.org", "no-ip.info",
        "no-ip.com", "hopto.org", "zapto.org", "myftp.biz",
        "ngrok.io", "ngrok-free.app", "serveo.net", "pagekite.me",
        "changeip.com", "redirectme.net", "myq-see.com", "ddns.net",
    }
    # Check if the domain ends with a known dynamic-DNS registered domain
    for dyn in dynamic_dns_registered_domains:
        if domain_lower == dyn or domain_lower.endswith("." + dyn):
            return True

    # For other keywords, match only when the keyword equals a full
    # *non-TLD* label in the domain (not just a substring of any label).
    label_set = set(labels[:-1]) if len(labels) > 1 else set(labels)
    for kw in keywords:
        if kw in label_set:
            return True

    # DGA heuristic: ≥ 5 labels (very deep subdomain nesting)
    if len(labels) >= 5:
        return True

    # High consonant-to-vowel ratio in second-level domain suggests DGA
    sld = labels[0] if labels else ""
    vowels = sum(1 for c in sld if c in "aeiou")
    if len(sld) > 8 and vowels / max(len(sld), 1) < 0.2:
        return True

    return False


def _extract_domains_from_report(report_data: dict) -> list[str]:
    """
    Walk a MobSF-style JSON report and extract all hostnames / domain strings
    found in network_security, URL lists, or any deeply nested string values.
    """
    domains: set[str] = set()
    url_pattern = re.compile(
        r"(?:https?://|ftp://|wss?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)",
        re.IGNORECASE,
    )

    def _walk(obj: object) -> None:
        if isinstance(obj, str):
            for match in url_pattern.finditer(obj):
                candidate = match.group(1).lower()
                # Exclude numeric-only labels (plain IPs handled separately)
                if not re.fullmatch(r"[\d.]+", candidate):
                    domains.add(candidate)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item)

    _walk(report_data)
    return list(domains)


def _extract_ips_from_report(report_data: dict) -> list[str]:
    """Extract all IPv4 address strings from a MobSF report dict."""
    raw_json = json.dumps(report_data)
    candidates = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_json)
    return list({ip for ip in candidates if not _is_private_ip(ip)})


# ═══════════════════════════════════════════════════════════════════════════════
# § 3 — PCAP ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_pcap(pcap_path: str) -> tuple[list[NetworkIndicator], list[RuntimeEvent]]:
    """
    Parse a PCAP file and return (indicators, events).

    Requires scapy; returns empty lists if scapy is unavailable or the file
    is missing / unreadable.
    """
    indicators: list[NetworkIndicator] = []
    events: list[RuntimeEvent] = []

    if not _SCAPY_AVAILABLE:
        logger.warning("scapy not available — PCAP analysis skipped (stub mode).")
        return indicators, events

    if not os.path.isfile(pcap_path):
        logger.warning("PCAP not found: %s — skipping.", pcap_path)
        return indicators, events

    try:
        packets = rdpcap(pcap_path)
        logger.info("Loaded %d packets from %s", len(packets), pcap_path)
    except Exception as exc:
        logger.error("PCAP read error: %s", exc)
        return indicators, events

    seen_endpoints: set[tuple] = set()
    cfg = MODULE_CONFIG

    for pkt in packets:
        try:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip   = ip_layer.src
            dst_ip   = ip_layer.dst
            ts       = float(pkt.time)

            # ── TCP / UDP layer extraction ────────────────────────────────────
            proto = "OTHER"
            dst_port = 0
            payload_bytes = b""

            if pkt.haslayer(TCP):
                proto    = "TCP"
                dst_port = pkt[TCP].dport
                if pkt[TCP].payload:
                    payload_bytes = bytes(pkt[TCP].payload)
            elif pkt.haslayer(UDP):
                proto    = "UDP"
                dst_port = pkt[UDP].dport
                if pkt[UDP].payload:
                    payload_bytes = bytes(pkt[UDP].payload)

            # ── DNS query extraction ──────────────────────────────────────────
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    queried_name = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                    if _looks_like_c2_domain(queried_name, cfg["c2_domain_keywords"]):
                        key = ("dns", queried_name)
                        if key not in seen_endpoints:
                            seen_endpoints.add(key)
                            ind = NetworkIndicator(
                                host=queried_name, port=53, proto="DNS",
                                direction="OUTBOUND", is_c2=True,
                            )
                            indicators.append(ind)
                            events.append(RuntimeEvent(
                                timestamp=ts,
                                category="network",
                                severity="high",
                                description=f"Suspicious DNS query: {queried_name}",
                                metadata={"domain": queried_name, "src": src_ip},
                            ))
                except Exception:
                    pass

            # ── Skip private / internal destinations ──────────────────────────
            if _is_private_ip(dst_ip):
                continue

            # ── Non-standard port detection ───────────────────────────────────
            is_suspicious_port = (
                dst_port > 0
                and dst_port not in cfg["standard_ports"]
                and dst_port < 65535
            )

            # ── Known malicious IP range check ────────────────────────────────
            is_c2 = _is_malicious_ip(dst_ip, cfg["known_malicious_cidrs"])

            # ── USSD code in TCP payload ──────────────────────────────────────
            if payload_bytes:
                try:
                    decoded = payload_bytes.decode("utf-8", errors="replace")
                    ussd_matches = re.findall(cfg["ussd_pattern"], decoded)
                    for ussd in ussd_matches:
                        events.append(RuntimeEvent(
                            timestamp=ts,
                            category="network",
                            severity="critical",
                            description=f"USSD code detected in network payload: {ussd}",
                            metadata={"ussd": ussd, "dst_ip": dst_ip, "port": dst_port},
                        ))
                except Exception:
                    pass

            endpoint_key = (dst_ip, dst_port, proto)
            if endpoint_key not in seen_endpoints and (is_c2 or is_suspicious_port):
                seen_endpoints.add(endpoint_key)
                ind = NetworkIndicator(
                    host=dst_ip, port=dst_port, proto=proto,
                    direction="OUTBOUND",
                    is_c2=is_c2,
                    is_suspicious_port=is_suspicious_port,
                    raw_payload=payload_bytes[:256],
                )
                indicators.append(ind)

                if is_c2:
                    events.append(RuntimeEvent(
                        timestamp=ts,
                        category="network",
                        severity="critical",
                        description=f"Outbound connection to known malicious IP: {dst_ip}:{dst_port}",
                        metadata={"ip": dst_ip, "port": dst_port, "proto": proto},
                    ))
                elif is_suspicious_port:
                    events.append(RuntimeEvent(
                        timestamp=ts,
                        category="network",
                        severity="medium",
                        description=f"Non-standard port used: {dst_ip}:{dst_port}/{proto}",
                        metadata={"ip": dst_ip, "port": dst_port, "proto": proto},
                    ))

        except Exception as pkt_err:
            logger.debug("Packet parse error: %s", pkt_err)
            continue

    logger.info(
        "PCAP analysis complete — %d indicators, %d events",
        len(indicators), len(events),
    )
    return indicators, events


# ═══════════════════════════════════════════════════════════════════════════════
# § 4 — MOBSF REPORT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_mobsf_report(report_data: dict) -> dict:
    """
    Extract dynamic analysis signals from a MobSF JSON report.

    Returns a dict with boolean / list fields:
        sms_intercepted, overlay_detected, accessibility_abused,
        ussd_detected, evasion_techniques, raw_events, c2_hosts, c2_domains
    """
    cfg = MODULE_CONFIG
    result = {
        "sms_intercepted":      False,
        "overlay_detected":     False,
        "accessibility_abused": False,
        "ussd_detected":        False,
        "evasion_techniques":   [],
        "raw_events":           [],
        "c2_hosts":             [],
        "c2_domains":           [],
    }

    if not report_data:
        return result

    raw_json_str = json.dumps(report_data).lower()

    # ── SMS exfiltration detection ─────────────────────────────────────────────
    sms_keywords = [
        "sms_received", "smsmanager", "sendtextmessage", "readsmsmessages",
        "android.permission.read_sms", "android.permission.send_sms",
        "smsretriever", "smslistener",
    ]
    if any(kw in raw_json_str for kw in sms_keywords):
        result["sms_intercepted"] = True
        result["raw_events"].append(RuntimeEvent(
            timestamp=time.time(),
            category="sms",
            severity="critical",
            description="SMS read/send API invoked at runtime — possible OTP interception",
            metadata={"source": "mobsf_report"},
        ))

    # ── Screen overlay / draw-over detection ──────────────────────────────────
    overlay_keywords = [
        "system_alert_window", "type_application_overlay",
        "draw over other apps", "overlayservice", "windowmanager.layoutparams",
    ]
    if any(kw in raw_json_str for kw in overlay_keywords):
        result["overlay_detected"] = True
        result["raw_events"].append(RuntimeEvent(
            timestamp=time.time(),
            category="overlay",
            severity="high",
            description="Screen overlay / TYPE_APPLICATION_OVERLAY usage detected",
            metadata={"source": "mobsf_report"},
        ))

    # ── Accessibility service abuse ────────────────────────────────────────────
    a11y_keywords = [
        "accessibilityservice", "onAccessibilityEvent", "performAction",
        "android.permission.bind_accessibility_service",
    ]
    if any(kw in json.dumps(report_data) for kw in a11y_keywords):
        result["accessibility_abused"] = True
        result["raw_events"].append(RuntimeEvent(
            timestamp=time.time(),
            category="network",
            severity="high",
            description="Accessibility service binding detected at runtime (potential keylogger/RAT)",
            metadata={"source": "mobsf_report"},
        ))

    # ── USSD string in report ─────────────────────────────────────────────────
    ussd_matches = re.findall(cfg["ussd_pattern"], json.dumps(report_data))
    if ussd_matches:
        result["ussd_detected"] = True
        result["raw_events"].append(RuntimeEvent(
            timestamp=time.time(),
            category="network",
            severity="critical",
            description=f"USSD strings detected: {ussd_matches[:5]}",
            metadata={"ussd_codes": ussd_matches[:5]},
        ))

    # ── Evasion technique detection ───────────────────────────────────────────
    evasion_map = {
        # Key: lowercase substring to search in the raw JSON string
        # Value: human-readable description shown in UI / report
        "reflect.method":            "Java Reflection API used (possible dynamic class loading)",
        "dexclassloader":            "DexClassLoader detected (runtime code loading)",
        "emulatordetect":            "Emulator detection code present",
        "isemulator":                "isEmulator() check found",
        "ro.kernel.qemu":            "QEMU property read detected",
        "anti-debug":                "Anti-debug routine detected",
        "isrooted":                  "Root-check function detected",
        "checkrootmethod":           "CheckRootMethod() call detected",
        "nativelibrarydir":          "Native library inspection (possible JNI evasion)",
        "getinstallerpackagename":   "Installer package check detected (Play Store verification)",
        "build.fingerprint":         "Build fingerprint read at runtime (emulator check)",
    }
    for keyword, description in evasion_map.items():
        if keyword in raw_json_str:
            result["evasion_techniques"].append(description)

    # ── Network indicator extraction ──────────────────────────────────────────
    all_ips     = _extract_ips_from_report(report_data)
    all_domains = _extract_domains_from_report(report_data)

    c2_ips = [
        ip for ip in all_ips
        if _is_malicious_ip(ip, cfg["known_malicious_cidrs"])
    ]
    c2_domains = [
        d for d in all_domains
        if _looks_like_c2_domain(d, cfg["c2_domain_keywords"])
    ]

    result["c2_hosts"]   = c2_ips
    result["c2_domains"] = c2_domains

    if c2_ips or c2_domains:
        result["raw_events"].append(RuntimeEvent(
            timestamp=time.time(),
            category="network",
            severity="critical",
            description=(
                f"C2 indicators extracted from report: "
                f"{len(c2_ips)} IPs, {len(c2_domains)} domains"
            ),
            metadata={"c2_ips": c2_ips, "c2_domains": c2_domains},
        ))

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# § 5 — SCORE COMPUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _compute_s_dynamic(
    pcap_indicators:    list[NetworkIndicator],
    report_signals:     dict,
) -> float:
    """
    Compute S_dyn ∈ [0.0, 1.0] from all collected signals.

    Scoring formula (additive with diminishing returns capped per signal):
        S_dyn = Σ weight_i * min(1.0, signal_intensity_i)
    """
    cfg     = MODULE_CONFIG
    score   = 0.0

    # ── C2 / malicious IP connections ─────────────────────────────────────────
    c2_count = (
        sum(1 for ind in pcap_indicators if ind.is_c2)
        + len(report_signals.get("c2_hosts",   []))
        + len(report_signals.get("c2_domains", []))
    )
    c2_ratio = min(1.0, c2_count / max(cfg["c2_connection_count_cap"], 1))
    score += cfg["weight_c2_connections"] * c2_ratio
    logger.debug("C2 count=%d → contribution=%.4f", c2_count,
                 cfg["weight_c2_connections"] * c2_ratio)

    # ── Suspicious non-standard ports ─────────────────────────────────────────
    suspicious_port_count = sum(1 for ind in pcap_indicators if ind.is_suspicious_port)
    port_ratio = min(1.0, suspicious_port_count / max(cfg["suspicious_port_count_cap"], 1))
    score += cfg["weight_suspicious_ports"] * port_ratio
    logger.debug("Suspicious ports=%d → contribution=%.4f", suspicious_port_count,
                 cfg["weight_suspicious_ports"] * port_ratio)

    # ── SMS exfiltration ──────────────────────────────────────────────────────
    if report_signals.get("sms_intercepted"):
        score += cfg["weight_sms_exfiltration"]
        logger.debug("SMS intercepted → +%.4f", cfg["weight_sms_exfiltration"])

    # ── Overlay abuse ─────────────────────────────────────────────────────────
    if report_signals.get("overlay_detected"):
        score += cfg["weight_overlay_abuse"]
        logger.debug("Overlay detected → +%.4f", cfg["weight_overlay_abuse"])

    # ── Accessibility abuse ───────────────────────────────────────────────────
    if report_signals.get("accessibility_abused"):
        score += cfg["weight_accessibility_abuse"]
        logger.debug("Accessibility abused → +%.4f", cfg["weight_accessibility_abuse"])

    # ── USSD codes in network traffic ─────────────────────────────────────────
    if report_signals.get("ussd_detected"):
        score += cfg["weight_ussd_strings"]
        logger.debug("USSD detected → +%.4f", cfg["weight_ussd_strings"])

    # ── Evasion techniques found ──────────────────────────────────────────────
    evasion_count = len(report_signals.get("evasion_techniques", []))
    if evasion_count > 0:
        evasion_ratio = min(1.0, evasion_count / 5.0)   # 5+ techniques = full weight
        score += cfg["weight_evasion_detected"] * evasion_ratio
        logger.debug("Evasion techniques=%d → contribution=%.4f", evasion_count,
                     cfg["weight_evasion_detected"] * evasion_ratio)

    # ── Hard clamp to [0.0, 1.0] ─────────────────────────────────────────────
    s_dyn = round(max(0.0, min(1.0, score)), 4)
    logger.info("S_dyn computed: %.4f", s_dyn)
    return s_dyn


# ═══════════════════════════════════════════════════════════════════════════════
# § 6 — OFFLINE SIMULATION FALLBACK
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_simulated_telemetry() -> dict:
    """
    Produce a plausible but deterministic simulated telemetry result when no
    live sandbox or PCAP data is available.

    Uses a seeded PRNG so the output is reproducible for unit tests.
    The seed is derived from today's date, ensuring day-level variation
    without full randomness.
    """
    rng = random.Random(int(time.time() // 86400))   # Seed changes daily

    # Simulated C2 IPs from known suspicious ranges
    fake_c2_pool = [
        "185.220.101.47", "45.142.212.100", "91.108.4.15",
        "194.165.16.78",  "5.188.86.172",   "45.142.211.33",
        "185.220.103.5",  "91.108.56.12",
    ]
    num_c2 = rng.randint(1, 4)
    c2_ips = rng.sample(fake_c2_pool, k=num_c2)

    fake_c2_domains = [
        "update-service.duckdns.org",
        "cdn-analytics.no-ip.biz",
        "api.mytelemetry.hopto.org",
        "logs.mobiletracker.zapto.org",
    ]
    num_domains = rng.randint(0, 2)
    c2_domains = rng.sample(fake_c2_domains, k=num_domains)

    sms_intercepted = rng.random() > 0.4         # ~60% chance
    overlay_detected = rng.random() > 0.5        # ~50% chance
    accessibility_abused = rng.random() > 0.6    # ~40% chance
    ussd_detected = rng.random() > 0.7           # ~30% chance

    evasion_pool = [
        "Java Reflection API used (possible dynamic class loading)",
        "DexClassLoader detected (runtime code loading)",
        "Emulator detection code present",
        "Root-check function detected",
        "Build fingerprint read at runtime (emulator check)",
        "Installer package check detected (Play Store verification)",
        "isEmulator() check found",
    ]
    num_evasions = rng.randint(2, 5)
    evasion_techniques = rng.sample(evasion_pool, k=num_evasions)

    t0 = time.time() - 300   # Simulate a 5-minute session

    runtime_events = [
        RuntimeEvent(
            timestamp=t0 + rng.uniform(0, 10),
            category="network",
            severity="critical",
            description=f"[SIMULATED] Outbound connection to C2 host: {rng.choice(c2_ips)}:443",
            metadata={"ip": rng.choice(c2_ips), "port": 443, "simulated": True},
        ),
    ]
    if sms_intercepted:
        runtime_events.append(RuntimeEvent(
            timestamp=t0 + rng.uniform(10, 60),
            category="sms",
            severity="critical",
            description="[SIMULATED] SMS READ_SMS API invoked — potential OTP harvest",
            metadata={"simulated": True},
        ))
    if overlay_detected:
        runtime_events.append(RuntimeEvent(
            timestamp=t0 + rng.uniform(60, 120),
            category="overlay",
            severity="high",
            description="[SIMULATED] Screen overlay TYPE_APPLICATION_OVERLAY used",
            metadata={"simulated": True},
        ))
    if accessibility_abused:
        runtime_events.append(RuntimeEvent(
            timestamp=t0 + rng.uniform(120, 180),
            category="network",
            severity="high",
            description="[SIMULATED] Accessibility service onAccessibilityEvent captured",
            metadata={"simulated": True},
        ))
    if ussd_detected:
        ussd_code = rng.choice(["*99#", "*121#", "*123*1#"])
        runtime_events.append(RuntimeEvent(
            timestamp=t0 + rng.uniform(180, 250),
            category="network",
            severity="critical",
            description=f"[SIMULATED] USSD code in network payload: {ussd_code}",
            metadata={"ussd": ussd_code, "simulated": True},
        ))

    runtime_events.sort(key=lambda e: e.timestamp)

    # Build synthetic report_signals to feed into scorer
    report_signals = {
        "sms_intercepted":      sms_intercepted,
        "overlay_detected":     overlay_detected,
        "accessibility_abused": accessibility_abused,
        "ussd_detected":        ussd_detected,
        "evasion_techniques":   evasion_techniques,
        "c2_hosts":             c2_ips,
        "c2_domains":           c2_domains,
    }

    s_dyn = _compute_s_dynamic([], report_signals)

    return {
        "s_dynamic":         s_dyn,
        "c2_indicators":     c2_ips + c2_domains,
        "sms_intercepted":   sms_intercepted,
        "evasion_techniques": evasion_techniques,
        "runtime_events":    [e.to_dict() for e in runtime_events],
        "_source":           "simulated",   # Internal marker — stripped by scoring.py
    }


# ═══════════════════════════════════════════════════════════════════════════════
# § 7 — PRIMARY PUBLIC FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_dynamic_telemetry(
    report_data: Optional[dict] = None,
    pcap_path:   Optional[str]  = None,
) -> dict:
    """
    Parse sandbox telemetry and compute the Dynamic Risk Factor S_dyn.

    Parameters
    ----------
    report_data : dict, optional
        A MobSF JSON dynamic analysis report (or any compatible dict).
        When None, the module falls back to simulated data.
    pcap_path : str, optional
        Absolute path to a PCAP file captured during the sandbox session.
        Requires scapy to be installed; silently ignored otherwise.

    Returns
    -------
    dict
        {
            "s_dynamic":          float   [0.0 – 1.0],
            "c2_indicators":      list[str],
            "sms_intercepted":    bool,
            "evasion_techniques": list[str],
            "runtime_events":     list[dict],
        }

    Notes
    -----
    *   This function is **pure** and side-effect-free with respect to the
        filesystem (it only reads, never writes).
    *   It never raises an exception to the caller; all errors are logged and
        the function returns the best partial result available.
    """
    logger.info(
        "evaluate_dynamic_telemetry() called — report_data=%s, pcap_path=%s",
        "provided" if report_data else "None",
        pcap_path or "None",
    )

    # ── Offline / no-data fallback ────────────────────────────────────────────
    if not report_data and not pcap_path:
        logger.warning("No report_data or pcap_path provided — returning simulated telemetry.")
        result = _generate_simulated_telemetry()
        result.pop("_source", None)
        return result

    # ── Initialise accumulation structures ────────────────────────────────────
    all_pcap_indicators: list[NetworkIndicator] = []
    all_events:          list[RuntimeEvent]     = []
    all_c2_indicators:   list[str]              = []
    evasion_techniques:  list[str]              = []
    sms_intercepted                             = False

    # ── Stage A: PCAP analysis ────────────────────────────────────────────────
    if pcap_path:
        try:
            pcap_indicators, pcap_events = _parse_pcap(pcap_path)
            all_pcap_indicators.extend(pcap_indicators)
            all_events.extend(pcap_events)
            all_c2_indicators.extend(
                ind.host for ind in pcap_indicators if ind.is_c2
            )
        except Exception as pcap_err:
            logger.error("PCAP analysis raised an unexpected error: %s", pcap_err)

    # ── Stage B: MobSF report parsing ────────────────────────────────────────
    report_signals: dict = {}
    if report_data:
        try:
            report_signals = _parse_mobsf_report(report_data)
            all_events.extend(report_signals.get("raw_events", []))
            evasion_techniques = report_signals.get("evasion_techniques", [])
            sms_intercepted    = report_signals.get("sms_intercepted", False)
            all_c2_indicators.extend(report_signals.get("c2_hosts",   []))
            all_c2_indicators.extend(report_signals.get("c2_domains", []))
        except Exception as rep_err:
            logger.error("MobSF report parse raised an unexpected error: %s", rep_err)

    # ── Stage C: Deduplicate C2 indicators ───────────────────────────────────
    seen: set[str] = set()
    deduped_c2: list[str] = []
    for indicator in all_c2_indicators:
        if indicator not in seen:
            seen.add(indicator)
            deduped_c2.append(indicator)

    # ── Stage D: Score computation ────────────────────────────────────────────
    try:
        s_dyn = _compute_s_dynamic(all_pcap_indicators, report_signals)
    except Exception as score_err:
        logger.error("Score computation failed: %s — defaulting to 0.5", score_err)
        s_dyn = 0.5

    # ── Stage E: Sort events by timestamp ────────────────────────────────────
    all_events.sort(key=lambda e: e.timestamp)

    # ── Stage F: Build return payload ─────────────────────────────────────────
    return {
        "s_dynamic":          s_dyn,
        "c2_indicators":      deduped_c2,
        "sms_intercepted":    sms_intercepted,
        "evasion_techniques": evasion_techniques,
        "runtime_events":     [e.to_dict() for e in all_events],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# § 8 — CLI ENTRY POINT  (python dynamic_analyzer.py [report.json] [capture.pcap])
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    _report_path = sys.argv[1] if len(sys.argv) > 1 else None
    _pcap_path   = sys.argv[2] if len(sys.argv) > 2 else None

    _report_data: Optional[dict] = None
    if _report_path:
        try:
            with open(_report_path, "r", encoding="utf-8") as fh:
                _report_data = json.load(fh)
            print(f"[+] Loaded report: {_report_path}")
        except Exception as e:
            print(f"[!] Could not load report: {e}")

    result = evaluate_dynamic_telemetry(report_data=_report_data, pcap_path=_pcap_path)

    print("\n" + "═" * 70)
    print("  NIRIKSHAK-AI :: Dynamic Telemetry Evaluation")
    print("═" * 70)
    print(f"  S_dyn              : {result['s_dynamic']:.4f}")
    print(f"  SMS Intercepted    : {result['sms_intercepted']}")
    print(f"  C2 Indicators      : {len(result['c2_indicators'])}")
    for ind in result["c2_indicators"]:
        print(f"                       → {ind}")
    print(f"  Evasion Techniques : {len(result['evasion_techniques'])}")
    for et in result["evasion_techniques"]:
        print(f"                       → {et}")
    print(f"  Runtime Events     : {len(result['runtime_events'])}")
    for ev in result["runtime_events"]:
        sev = ev.get("severity", "?").upper()
        print(f"                       [{sev:8s}] {ev.get('description', '')}")
    print("═" * 70 + "\n")
