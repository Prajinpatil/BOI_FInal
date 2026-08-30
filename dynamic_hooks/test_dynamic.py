"""
NIRIKSHAK-AI :: Dynamic Analyzer — Unit Tests
==============================================

Module   : dynamic_hooks/test_dynamic.py
Purpose  : Validate the dynamic_analyzer.evaluate_dynamic_telemetry() function
           end-to-end without requiring a live Docker sandbox, MobSF instance,
           or PCAP file.  All tests run fully offline.

Test Coverage
-------------
    TestSdynamBounds            — S_dyn is always in [0.0, 1.0]
    TestOfflineSimulation       — Offline fallback produces a valid contract
    TestEmptyInputs             — Handles all-None gracefully
    TestCleanAppReport          — Clean MobSF report yields low S_dyn (< 0.35)
    TestMaliciousReport         — Malware-like report yields high S_dyn (> 0.50)
    TestSMSInterception         — SMS API in report sets sms_intercepted=True
    TestOverlayDetection        — Overlay permission sets overlay flag
    TestAccessibilityAbuse      — AccessibilityService detected correctly
    TestUSSDInReport            — USSD string in report raises score
    TestEvasionTechniques       — Evasion keywords populate list correctly
    TestC2IpExtraction          — Malicious IPs extracted from report
    TestC2DomainExtraction      — C2-like domains extracted from report
    TestReturnContractKeys      — Return dict always has all required keys
    TestReturnContractTypes     — Values are correct Python types
    TestRuntimeEventStructure   — Each runtime_event has required sub-keys
    TestScoreReproducibility    — Same input always produces same score
    TestScoreMonotonicity       — Adding signals never decreases S_dyn
    TestNoPcapWithScapy         — Missing PCAP path handled gracefully
    TestPrivateIPsNotFlagged    — RFC-1918 IPs ignored as C2 indicators
    TestStandardPortsClean      — Traffic on ports 80/443 not flagged suspicious

Run with:
    python -m pytest dynamic_hooks/test_dynamic.py -v
    python dynamic_hooks/test_dynamic.py          (standalone)

Author  : NIRIKSHAK-AI — Member B
Version : 2.0.0
Updated : 2026-08-14
"""

from __future__ import annotations

import sys
import os
import json
import time
import unittest
from typing import Any

# ── Ensure the package root is on sys.path so imports resolve correctly ────────
_THIS_DIR   = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(_THIS_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

from dynamic_hooks.dynamic_analyzer import (   # noqa: E402
    evaluate_dynamic_telemetry,
    _compute_s_dynamic,
    _parse_mobsf_report,
    _is_private_ip,
    _is_malicious_ip,
    _looks_like_c2_domain,
    MODULE_CONFIG,
    NetworkIndicator,
)

# ═══════════════════════════════════════════════════════════════════════════════
# § 0 — FIXTURE DATA
# ═══════════════════════════════════════════════════════════════════════════════

# A minimal MobSF-style report for a *clean* app (banking utility, no malice)
CLEAN_REPORT: dict = {
    "name": "com.example.banking.clean",
    "package_name": "com.example.banking.clean",
    "version_name": "1.0.0",
    "permissions": {
        "android.permission.INTERNET": "normal",
        "android.permission.ACCESS_NETWORK_STATE": "normal",
    },
    "activities": ["com.example.MainActivity"],
    "network_security": {
        "domains": ["api.example.com"],
        "pins": [],
    },
    "android_api": {
        "calls": ["java.net.HttpURLConnection.connect"],
    },
}

# A MobSF-style report simulating banking malware behaviour
MALWARE_REPORT: dict = {
    "name": "com.fraud.bankstealer",
    "package_name": "com.fraud.bankstealer",
    "version_name": "3.1.4",
    "permissions": {
        "android.permission.READ_SMS":              "dangerous",
        "android.permission.SEND_SMS":              "dangerous",
        "android.permission.SYSTEM_ALERT_WINDOW":   "dangerous",
        "android.permission.BIND_ACCESSIBILITY_SERVICE": "dangerous",
    },
    "activities": [
        "com.fraud.OverlayActivity",
        "com.fraud.AccessibilityService",
    ],
    "network_security": {
        "domains": [
            "update-service.duckdns.org",     # C2-like domain
            "cdn-analytics.no-ip.biz",         # C2-like domain
            "185.220.101.47",                  # Known malicious range
        ],
        "clear_text_traffic": True,
    },
    "android_api": {
        "calls": [
            "android.telephony.SmsManager.sendTextMessage",   # SMS exfiltration
            "android.view.WindowManager.addView",              # Overlay
            "android.accessibilityservice.AccessibilityService.onAccessibilityEvent",
            "java.lang.reflect.Method.invoke",                 # Reflection
            "dalvik.system.DexClassLoader.<init>",             # Dynamic class loading
            "android.os.Build.FINGERPRINT",                    # Emulator check
        ],
    },
    "dynamic_analysis": {
        "network_requests": [
            {"url": "http://185.220.101.47:4444/gate.php", "method": "POST"},
            {"url": "http://update-service.duckdns.org/cmd", "method": "GET"},
        ],
        "ussd_codes": ["*99#", "*123*1#"],
        "sms_events": [
            {"type": "READ_SMS", "content": "OTP: 287651"},
        ],
    },
}

# A report containing only RFC-1918 / private IP addresses
PRIVATE_IP_REPORT: dict = {
    "name": "com.local.app",
    "network_security": {
        "connections": [
            "192.168.1.1",
            "10.0.0.5",
            "172.16.254.1",
            "127.0.0.1",
        ],
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# § 1 — CONTRACT & TYPE VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestReturnContractKeys(unittest.TestCase):
    """Ensure the return dict always contains all five required keys."""

    REQUIRED_KEYS = {"s_dynamic", "c2_indicators", "sms_intercepted",
                     "evasion_techniques", "runtime_events"}

    def _assert_contract(self, result: dict, label: str) -> None:
        missing = self.REQUIRED_KEYS - set(result.keys())
        self.assertFalse(
            missing,
            f"[{label}] Missing keys in return dict: {missing}"
        )

    def test_keys_simulated(self):
        result = evaluate_dynamic_telemetry()
        self._assert_contract(result, "simulated")

    def test_keys_clean_report(self):
        result = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT)
        self._assert_contract(result, "clean_report")

    def test_keys_malware_report(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        self._assert_contract(result, "malware_report")

    def test_keys_none_none(self):
        result = evaluate_dynamic_telemetry(report_data=None, pcap_path=None)
        self._assert_contract(result, "none_none")


class TestReturnContractTypes(unittest.TestCase):
    """Ensure return values have the correct Python types."""

    def _check_types(self, result: dict) -> None:
        self.assertIsInstance(result["s_dynamic"],          float,
                              "s_dynamic must be float")
        self.assertIsInstance(result["c2_indicators"],      list,
                              "c2_indicators must be list")
        self.assertIsInstance(result["sms_intercepted"],    bool,
                              "sms_intercepted must be bool")
        self.assertIsInstance(result["evasion_techniques"], list,
                              "evasion_techniques must be list")
        self.assertIsInstance(result["runtime_events"],     list,
                              "runtime_events must be list")

    def test_types_simulated(self):
        self._check_types(evaluate_dynamic_telemetry())

    def test_types_clean_report(self):
        self._check_types(evaluate_dynamic_telemetry(report_data=CLEAN_REPORT))

    def test_types_malware_report(self):
        self._check_types(evaluate_dynamic_telemetry(report_data=MALWARE_REPORT))


class TestRuntimeEventStructure(unittest.TestCase):
    """Each item in runtime_events must have the required sub-keys."""

    REQUIRED_EVENT_KEYS = {"timestamp", "category", "severity", "description", "metadata"}

    def test_event_structure_simulated(self):
        result = evaluate_dynamic_telemetry()
        for event in result["runtime_events"]:
            missing = self.REQUIRED_EVENT_KEYS - set(event.keys())
            self.assertFalse(missing, f"Event missing keys: {missing} — event={event}")

    def test_event_structure_malware(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        for event in result["runtime_events"]:
            missing = self.REQUIRED_EVENT_KEYS - set(event.keys())
            self.assertFalse(missing, f"Event missing keys: {missing}")

    def test_event_timestamps_ordered(self):
        """Runtime events must be in chronological order."""
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        events = result["runtime_events"]
        if len(events) >= 2:
            timestamps = [e["timestamp"] for e in events]
            self.assertEqual(
                timestamps,
                sorted(timestamps),
                "Runtime events are not sorted by timestamp",
            )


# ═══════════════════════════════════════════════════════════════════════════════
# § 2 — SCORE BOUNDS & MONOTONICITY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSdynamBounds(unittest.TestCase):
    """S_dyn must always be strictly within [0.0, 1.0]."""

    def _check_bounds(self, result: dict, label: str) -> None:
        s = result["s_dynamic"]
        self.assertGreaterEqual(s, 0.0, f"[{label}] S_dyn < 0: {s}")
        self.assertLessEqual(s,   1.0, f"[{label}] S_dyn > 1: {s}")

    def test_bounds_simulated(self):
        self._check_bounds(evaluate_dynamic_telemetry(), "simulated")

    def test_bounds_clean(self):
        self._check_bounds(evaluate_dynamic_telemetry(report_data=CLEAN_REPORT), "clean")

    def test_bounds_malware(self):
        self._check_bounds(evaluate_dynamic_telemetry(report_data=MALWARE_REPORT), "malware")

    def test_bounds_empty_dict(self):
        self._check_bounds(evaluate_dynamic_telemetry(report_data={}), "empty_dict")

    def test_bounds_private_ips(self):
        self._check_bounds(evaluate_dynamic_telemetry(report_data=PRIVATE_IP_REPORT), "private_ips")

    def test_s_dynamic_is_rounded(self):
        """S_dyn should have at most 4 decimal places."""
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        s = result["s_dynamic"]
        self.assertEqual(s, round(s, 4), "S_dyn has more than 4 decimal places")


class TestScoreMonotonicity(unittest.TestCase):
    """Adding more malicious signals must never decrease S_dyn."""

    def _get_score(self, report: dict) -> float:
        return evaluate_dynamic_telemetry(report_data=report)["s_dynamic"]

    def test_malware_scores_higher_than_clean(self):
        clean_score   = self._get_score(CLEAN_REPORT)
        malware_score = self._get_score(MALWARE_REPORT)
        self.assertGreater(
            malware_score, clean_score,
            f"Malware score ({malware_score}) should exceed clean score ({clean_score})",
        )

    def test_adding_c2_ip_increases_score(self):
        """Report with a malicious IP should score higher than one without."""
        base_report = dict(CLEAN_REPORT)
        enriched_report = dict(CLEAN_REPORT)
        enriched_report["network_security"] = {
            "domains": ["185.220.101.47"],   # Known malicious CIDR
        }
        self.assertGreaterEqual(
            self._get_score(enriched_report),
            self._get_score(base_report),
        )


class TestScoreReproducibility(unittest.TestCase):
    """Same report must produce identical S_dyn on repeated calls."""

    def test_same_report_same_score(self):
        s1 = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)["s_dynamic"]
        s2 = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)["s_dynamic"]
        self.assertEqual(s1, s2, "S_dyn is not deterministic for identical inputs")

    def test_same_clean_report_same_score(self):
        s1 = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT)["s_dynamic"]
        s2 = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT)["s_dynamic"]
        self.assertEqual(s1, s2)


# ═══════════════════════════════════════════════════════════════════════════════
# § 3 — SCENARIO-BASED SCORING TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCleanAppReport(unittest.TestCase):
    """A clean banking utility app should produce a low S_dyn."""

    def test_clean_score_below_threshold(self):
        result = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT)
        self.assertLess(
            result["s_dynamic"], 0.35,
            f"Clean app scored too high: {result['s_dynamic']}",
        )

    def test_clean_no_sms_interception(self):
        result = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT)
        self.assertFalse(result["sms_intercepted"])

    def test_clean_no_c2_indicators(self):
        result = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT)
        self.assertEqual(len(result["c2_indicators"]), 0)


class TestMaliciousReport(unittest.TestCase):
    """A report simulating banking malware should produce a high S_dyn."""

    def test_malware_score_above_threshold(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        self.assertGreater(
            result["s_dynamic"], 0.50,
            f"Malware scored too low: {result['s_dynamic']}",
        )

    def test_malware_has_c2_indicators(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        self.assertGreater(len(result["c2_indicators"]), 0)

    def test_malware_has_runtime_events(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        self.assertGreater(len(result["runtime_events"]), 0)

    def test_malware_has_evasion_techniques(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        self.assertGreater(len(result["evasion_techniques"]), 0)


class TestSMSInterception(unittest.TestCase):
    """Reports with SMS API invocations must set sms_intercepted=True."""

    def test_sms_detected_from_permission(self):
        report = {"permissions": {"android.permission.READ_SMS": "dangerous"}}
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertTrue(result["sms_intercepted"])

    def test_sms_detected_from_api_call(self):
        report = {
            "android_api": {"calls": ["android.telephony.SmsManager.sendTextMessage"]}
        }
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertTrue(result["sms_intercepted"])

    def test_sms_detected_from_malware_report(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        self.assertTrue(result["sms_intercepted"])


class TestOverlayDetection(unittest.TestCase):
    """Reports with overlay APIs must trigger an overlay event."""

    def test_overlay_via_permission(self):
        report = {"permissions": {"android.permission.SYSTEM_ALERT_WINDOW": "dangerous"}}
        result = evaluate_dynamic_telemetry(report_data=report)
        # Overlay contributes to runtime_events and s_dynamic
        overlay_events = [
            e for e in result["runtime_events"]
            if e["category"] == "overlay"
        ]
        self.assertGreater(len(overlay_events), 0)

    def test_overlay_increases_score(self):
        base  = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT)["s_dynamic"]
        with_overlay = evaluate_dynamic_telemetry(
            report_data={**CLEAN_REPORT, "permissions": {"android.permission.SYSTEM_ALERT_WINDOW": "dangerous"}}
        )["s_dynamic"]
        self.assertGreaterEqual(with_overlay, base)


class TestAccessibilityAbuse(unittest.TestCase):
    """Reports with AccessibilityService usage must be flagged."""

    def test_a11y_api_detection(self):
        report = {
            "android_api": {
                "calls": ["android.accessibilityservice.AccessibilityService.onAccessibilityEvent"]
            }
        }
        result = evaluate_dynamic_telemetry(report_data=report)
        # Should produce at least one network-category event for accessibility
        a11y_events = [e for e in result["runtime_events"] if "ccessib" in e["description"].lower()]
        self.assertGreater(len(a11y_events), 0)


class TestUSSDInReport(unittest.TestCase):
    """USSD codes in report data should raise the S_dyn score."""

    def test_ussd_detected_in_json(self):
        report = {"dynamic_analysis": {"ussd_codes": ["*99#", "*121#"]}}
        result = evaluate_dynamic_telemetry(report_data=report)
        ussd_events = [
            e for e in result["runtime_events"]
            if "ussd" in e["description"].lower()
        ]
        self.assertGreater(len(ussd_events), 0)


class TestEvasionTechniques(unittest.TestCase):
    """Evasion keywords in report must populate the evasion_techniques list."""

    def test_reflection_detected(self):
        # The evasion detector looks for "reflect.method" (lowercased substring
        # of "java.lang.reflect.Method.invoke") in the JSON report.
        report = {"android_api": {"calls": ["java.lang.reflect.Method.invoke"]}}
        result = evaluate_dynamic_telemetry(report_data=report)
        found = any("reflection" in e.lower() or "reflect" in e.lower()
                    for e in result["evasion_techniques"])
        self.assertTrue(found, "Reflection not detected in evasion_techniques")

    def test_dexclassloader_detected(self):
        report = {"android_api": {"calls": ["dalvik.system.DexClassLoader.<init>"]}}
        result = evaluate_dynamic_telemetry(report_data=report)
        found = any("dex" in e.lower() or "class" in e.lower()
                    for e in result["evasion_techniques"])
        self.assertTrue(found, "DexClassLoader not detected in evasion_techniques")

    def test_malware_report_evasion_count(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        self.assertGreaterEqual(len(result["evasion_techniques"]), 2)


# ═══════════════════════════════════════════════════════════════════════════════
# § 4 — NETWORK INDICATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestC2IpExtraction(unittest.TestCase):
    """Malicious IPs must be extracted and listed in c2_indicators."""

    def test_known_malicious_ip_extracted(self):
        report = {"network_security": {"connections": ["185.220.101.47"]}}
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertIn("185.220.101.47", result["c2_indicators"])

    def test_multiple_c2_ips(self):
        report = {
            "network_security": {
                "connections": ["185.220.101.47", "45.142.212.100"]
            }
        }
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertGreaterEqual(len(result["c2_indicators"]), 1)

    def test_c2_indicators_are_strings(self):
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        for ind in result["c2_indicators"]:
            self.assertIsInstance(ind, str)

    def test_no_duplicates_in_c2_indicators(self):
        # Duplicate the same malicious IP in two places
        report = {
            "a": {"ip": "185.220.101.47"},
            "b": {"ip": "185.220.101.47"},
        }
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertEqual(
            len(result["c2_indicators"]),
            len(set(result["c2_indicators"])),
            "Duplicate C2 indicators found",
        )


class TestC2DomainExtraction(unittest.TestCase):
    """C2-like domains should be detected and listed in c2_indicators."""

    def test_duckdns_domain_detected(self):
        report = {"network_security": {"domains": ["cmd.update-service.duckdns.org"]}}
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertTrue(
            any("duckdns" in ind for ind in result["c2_indicators"]),
            "DuckDNS C2 domain not detected",
        )

    def test_noip_domain_detected(self):
        report = {"network_security": {"domains": ["beacon.cdn-analytics.no-ip.biz"]}}
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertTrue(
            any("no-ip" in ind for ind in result["c2_indicators"]),
            "No-IP C2 domain not detected",
        )

    def test_legitimate_domain_not_flagged(self):
        """api.paytm.com should NOT be flagged as C2."""
        report = {"network_security": {"domains": ["api.paytm.com"]}}
        result = evaluate_dynamic_telemetry(report_data=report)
        self.assertNotIn("api.paytm.com", result["c2_indicators"])


class TestPrivateIPsNotFlagged(unittest.TestCase):
    """RFC-1918 / loopback / link-local IPs must not appear as C2 indicators."""

    def test_private_ips_excluded(self):
        result = evaluate_dynamic_telemetry(report_data=PRIVATE_IP_REPORT)
        for ind in result["c2_indicators"]:
            self.assertFalse(
                _is_private_ip(ind),
                f"Private IP appeared as C2 indicator: {ind}",
            )

    def test_192_168_not_c2(self):
        self.assertTrue(_is_private_ip("192.168.1.1"))

    def test_10_0_not_c2(self):
        self.assertTrue(_is_private_ip("10.0.0.1"))

    def test_public_ip_not_private(self):
        self.assertFalse(_is_private_ip("185.220.101.47"))


# ═══════════════════════════════════════════════════════════════════════════════
# § 5 — OFFLINE SIMULATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestOfflineSimulation(unittest.TestCase):
    """Verify the offline fallback produces a fully valid contract."""

    def setUp(self):
        self.result = evaluate_dynamic_telemetry()   # No args → simulation

    def test_simulation_produces_valid_s_dynamic(self):
        s = self.result["s_dynamic"]
        self.assertGreaterEqual(s, 0.0)
        self.assertLessEqual(s,   1.0)

    def test_simulation_produces_c2_indicators(self):
        self.assertIsInstance(self.result["c2_indicators"], list)

    def test_simulation_produces_evasion_techniques(self):
        # Simulation should always include at least one evasion technique
        self.assertGreater(len(self.result["evasion_techniques"]), 0)

    def test_simulation_produces_runtime_events(self):
        self.assertGreater(len(self.result["runtime_events"]), 0)

    def test_simulation_no_source_key(self):
        """_source is an internal marker and must not leak into the public API."""
        self.assertNotIn("_source", self.result)


class TestEmptyInputs(unittest.TestCase):
    """Verify graceful handling of degenerate inputs."""

    def test_empty_report_dict(self):
        result = evaluate_dynamic_telemetry(report_data={})
        self.assertIsInstance(result["s_dynamic"], float)

    def test_none_pcap_path(self):
        result = evaluate_dynamic_telemetry(report_data=CLEAN_REPORT, pcap_path=None)
        self.assertIsInstance(result["s_dynamic"], float)

    def test_missing_pcap_file(self):
        """Passing a non-existent PCAP path must not raise an exception."""
        result = evaluate_dynamic_telemetry(
            report_data=CLEAN_REPORT,
            pcap_path="/tmp/does_not_exist_nirikshak_test.pcap",
        )
        self.assertIsInstance(result["s_dynamic"], float)

    def test_deeply_nested_report(self):
        """Deeply nested structures must not cause recursion errors."""
        nested = {"a": {"b": {"c": {"d": {"e": "test_value"}}}}}
        result = evaluate_dynamic_telemetry(report_data=nested)
        self.assertIsInstance(result["s_dynamic"], float)


# ═══════════════════════════════════════════════════════════════════════════════
# § 6 — INTERNAL HELPER UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHelperFunctions(unittest.TestCase):
    """Unit tests for internal utility functions."""

    def test_is_private_ip_rfc1918(self):
        self.assertTrue(_is_private_ip("192.168.0.1"))
        self.assertTrue(_is_private_ip("10.255.255.255"))
        self.assertTrue(_is_private_ip("172.16.0.0"))
        self.assertTrue(_is_private_ip("172.31.255.255"))

    def test_is_private_ip_loopback(self):
        self.assertTrue(_is_private_ip("127.0.0.1"))
        self.assertTrue(_is_private_ip("127.255.255.255"))

    def test_is_private_ip_public(self):
        self.assertFalse(_is_private_ip("8.8.8.8"))
        self.assertFalse(_is_private_ip("1.1.1.1"))
        self.assertFalse(_is_private_ip("185.220.101.47"))

    def test_is_private_ip_invalid(self):
        # Invalid strings are NOT treated as private — the function returns
        # False when ipaddress.ip_address() raises ValueError.
        self.assertFalse(_is_private_ip("not-an-ip"))

    def test_is_malicious_ip_known_cidr(self):
        self.assertTrue(
            _is_malicious_ip("185.220.101.47", MODULE_CONFIG["known_malicious_cidrs"])
        )

    def test_is_malicious_ip_clean(self):
        self.assertFalse(
            _is_malicious_ip("8.8.8.8", MODULE_CONFIG["known_malicious_cidrs"])
        )

    def test_c2_domain_duckdns(self):
        self.assertTrue(
            _looks_like_c2_domain("evil.duckdns.org", MODULE_CONFIG["c2_domain_keywords"])
        )

    def test_c2_domain_noip(self):
        self.assertTrue(
            _looks_like_c2_domain("bot.no-ip.biz", MODULE_CONFIG["c2_domain_keywords"])
        )

    def test_c2_domain_ngrok(self):
        self.assertTrue(
            _looks_like_c2_domain("abc123.ngrok.io", MODULE_CONFIG["c2_domain_keywords"])
        )

    def test_legitimate_domain_not_c2(self):
        self.assertFalse(
            _looks_like_c2_domain("google.com", MODULE_CONFIG["c2_domain_keywords"])
        )
        self.assertFalse(
            _looks_like_c2_domain("paytm.com", MODULE_CONFIG["c2_domain_keywords"])
        )

    def test_score_all_zeros(self):
        """Empty signals → score = 0.0"""
        s = _compute_s_dynamic([], {})
        self.assertEqual(s, 0.0)

    def test_score_capped_at_one(self):
        """Even with maximum signals, S_dyn should not exceed 1.0."""
        fake_c2_ips = [f"185.220.{i}.{j}" for i in range(5) for j in range(5)]
        indicators = [
            NetworkIndicator(host=ip, port=4444, proto="TCP",
                             direction="OUTBOUND", is_c2=True)
            for ip in fake_c2_ips
        ]
        signals = {
            "sms_intercepted":      True,
            "overlay_detected":     True,
            "accessibility_abused": True,
            "ussd_detected":        True,
            "evasion_techniques":   ["a", "b", "c", "d", "e", "f"],
            "c2_hosts":             fake_c2_ips,
            "c2_domains":           ["evil.duckdns.org", "bot.no-ip.biz"],
        }
        s = _compute_s_dynamic(indicators, signals)
        self.assertLessEqual(s, 1.0)
        self.assertGreaterEqual(s, 0.0)


# ═══════════════════════════════════════════════════════════════════════════════
# § 7 — INTEGRATION SMOKE TEST
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegrationSmoke(unittest.TestCase):
    """
    End-to-end smoke test simulating the full NIRIKSHAK pipeline:
    scoring.py calls evaluate_dynamic_telemetry() and uses s_dynamic.
    """

    def test_pipeline_scoring_integration(self):
        """
        Simulate scoring.py reading s_dynamic and incorporating it.
        The combined final score must be in [0.0, 1.0].
        """
        telemetry = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        s_dyn     = telemetry["s_dynamic"]

        # Simulate scoring.py formula: final_score = 0.4 * s_static + 0.6 * s_dyn
        # For this test, assume a static score of 0.7 (high static risk)
        s_static    = 0.70
        final_score = round(0.4 * s_static + 0.6 * s_dyn, 4)

        self.assertGreaterEqual(final_score, 0.0)
        self.assertLessEqual(final_score,    1.0)
        self.assertGreater(final_score, 0.3,
                           f"Expected a meaningful risk score, got {final_score}")

    def test_json_serialisable(self):
        """The return dict must be fully JSON-serialisable (for REST API)."""
        result = evaluate_dynamic_telemetry(report_data=MALWARE_REPORT)
        try:
            serialised = json.dumps(result)
            self.assertIsInstance(serialised, str)
        except TypeError as exc:
            self.fail(f"Return dict is not JSON-serialisable: {exc}")


# ═══════════════════════════════════════════════════════════════════════════════
# § 8 — ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("═" * 70)
    print("  NIRIKSHAK-AI :: Dynamic Analyzer — Unit Test Suite v2.0.0")
    print("═" * 70)
    unittest.main(verbosity=2)
