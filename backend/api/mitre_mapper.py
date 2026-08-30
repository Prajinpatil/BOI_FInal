"""
NIRIKSHAK-AI :: MITRE ATT&CK Mobile Framework Mapper
Maps detected permissions, APIs, and behaviors to MITRE ATT&CK Mobile techniques.
Ref: https://attack.mitre.org/matrices/mobile/
"""
import logging
from typing import List, Dict

logger = logging.getLogger("nirikshak.mitre")

# Permission → MITRE ATT&CK Mobile technique mapping
_PERMISSION_MAP: Dict[str, Dict] = {
    "android.permission.READ_SMS": {
        "id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection",
        "severity": "CRITICAL"
    },
    "android.permission.RECEIVE_SMS": {
        "id": "T1412", "name": "Capture SMS Messages", "tactic": "Collection",
        "severity": "CRITICAL"
    },
    "android.permission.SEND_SMS": {
        "id": "T1582", "name": "SMS Control", "tactic": "Impact",
        "severity": "HIGH"
    },
    "android.permission.READ_CONTACTS": {
        "id": "T1432", "name": "Access Contact List", "tactic": "Collection",
        "severity": "HIGH"
    },
    "android.permission.RECORD_AUDIO": {
        "id": "T1429", "name": "Capture Audio", "tactic": "Collection",
        "severity": "HIGH"
    },
    "android.permission.CAMERA": {
        "id": "T1512", "name": "Capture Camera", "tactic": "Collection",
        "severity": "HIGH"
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "id": "T1430", "name": "Location Tracking", "tactic": "Collection",
        "severity": "MEDIUM"
    },
    "android.permission.READ_CALL_LOG": {
        "id": "T1433", "name": "Access Call Log", "tactic": "Collection",
        "severity": "HIGH"
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "id": "T1433", "name": "Access Call Log", "tactic": "Collection",
        "severity": "HIGH"
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "id": "T1541", "name": "Foreground Persistence", "tactic": "Persistence",
        "severity": "HIGH"
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "id": "T1417", "name": "Input Capture via Accessibility", "tactic": "Collection",
        "severity": "CRITICAL"
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "id": "T1407", "name": "Download New Code at Runtime", "tactic": "Defense Evasion",
        "severity": "HIGH"
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "id": "T1402", "name": "Boot or Logon Initialization", "tactic": "Persistence",
        "severity": "MEDIUM"
    },
    "android.permission.GET_ACCOUNTS": {
        "id": "T1592", "name": "Account Discovery", "tactic": "Discovery",
        "severity": "MEDIUM"
    },
    "android.permission.READ_PHONE_STATE": {
        "id": "T1421", "name": "System Network Connections Discovery", "tactic": "Discovery",
        "severity": "MEDIUM"
    },
    "android.permission.INTERNET": {
        "id": "T1437", "name": "Standard Application Layer Protocol", "tactic": "Command and Control",
        "severity": "LOW"
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "id": "T1533", "name": "Data from Local System", "tactic": "Collection",
        "severity": "MEDIUM"
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "id": "T1533", "name": "Data from Local System", "tactic": "Collection",
        "severity": "MEDIUM"
    },
    "android.permission.FOREGROUND_SERVICE": {
        "id": "T1541", "name": "Foreground Persistence", "tactic": "Persistence",
        "severity": "MEDIUM"
    },
}

# Suspicious string patterns → MITRE techniques
_PATTERN_MAP: List[Dict] = [
    {"pattern": "DexClassLoader", "id": "T1407", "name": "Download New Code at Runtime",
     "tactic": "Defense Evasion", "severity": "HIGH"},
    {"pattern": "getDeviceId", "id": "T1422", "name": "System Information Discovery",
     "tactic": "Discovery", "severity": "MEDIUM"},
    {"pattern": "getSubscriberId", "id": "T1422", "name": "System Information Discovery",
     "tactic": "Discovery", "severity": "MEDIUM"},
    {"pattern": "execve", "id": "T1603", "name": "Scheduled Task/Job",
     "tactic": "Execution", "severity": "HIGH"},
    {"pattern": "ptrace", "id": "T1629", "name": "Impair Defenses",
     "tactic": "Defense Evasion", "severity": "HIGH"},
    {"pattern": "su ", "id": "T1404", "name": "Exploit for Privilege Escalation",
     "tactic": "Privilege Escalation", "severity": "CRITICAL"},
    {"pattern": "getLastLocation", "id": "T1430", "name": "Location Tracking",
     "tactic": "Collection", "severity": "HIGH"},
]


def map_to_mitre(permissions: List[str], hardcoded_strings: List[str]) -> List[Dict]:
    """
    Map permissions and string patterns to MITRE ATT&CK Mobile techniques.
    Returns deduplicated list of technique dicts sorted by severity.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    seen_ids = set()
    techniques = []

    # Permission-based mapping
    for perm in permissions:
        entry = _PERMISSION_MAP.get(perm)
        if entry and entry["id"] not in seen_ids:
            seen_ids.add(entry["id"])
            techniques.append({
                "technique_id": entry["id"],
                "technique_name": entry["name"],
                "tactic": entry["tactic"],
                "severity": entry["severity"],
                "source": "PERMISSION",
                "evidence": perm.split(".")[-1]
            })

    # String pattern-based mapping
    strings_blob = " ".join(s for s in hardcoded_strings if isinstance(s, str))
    for p in _PATTERN_MAP:
        if p["pattern"] in strings_blob and p["id"] not in seen_ids:
            seen_ids.add(p["id"])
            techniques.append({
                "technique_id": p["id"],
                "technique_name": p["name"],
                "tactic": p["tactic"],
                "severity": p["severity"],
                "source": "CODE_PATTERN",
                "evidence": p["pattern"]
            })

    techniques.sort(key=lambda x: severity_order.get(x["severity"], 99))
    logger.info("MITRE ATT&CK mapping: %d techniques identified", len(techniques))
    return techniques
