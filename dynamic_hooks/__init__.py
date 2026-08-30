"""
NIRIKSHAK-AI :: dynamic_hooks package
======================================

Exports the primary public function for dynamic sandbox telemetry evaluation.
Importing from this package directly avoids requiring callers to know the
internal module structure.

Usage:
    from dynamic_hooks import evaluate_dynamic_telemetry

    result = evaluate_dynamic_telemetry(
        report_data = mobsf_json_dict,
        pcap_path   = "/path/to/capture.pcap",
    )
    s_dyn = result["s_dynamic"]   # 0.0 – 1.0
"""

from dynamic_hooks.dynamic_analyzer import evaluate_dynamic_telemetry  # noqa: F401

__all__ = ["evaluate_dynamic_telemetry"]
__version__ = "2.0.0"
__author__  = "NIRIKSHAK-AI — Member B (Dynamic Sandbox & Anti-Evasion Engine)"
