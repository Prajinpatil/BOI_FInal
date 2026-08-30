"""
NIRIKSHAK-AI :: IOC (Indicators of Compromise) Extractor
Extracts hardcoded IPs, URLs, and C2 domains from APK string constants.
"""
import re
import logging
from typing import List, Dict

logger = logging.getLogger("nirikshak.ioc")

# Regex patterns for IOC extraction
_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_URL_RE = re.compile(
    r'https?://[\w\-\.]+(?:\.[a-z]{2,})+(?:/[^\s\"\'>]*)?',
    re.IGNORECASE
)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9\-]+\.)+(?:ru|cn|tk|ml|ga|cf|gq|xyz|top|pw|cc|info|biz|su|ws)\b',
    re.IGNORECASE
)

# Private/localhost IPs to exclude
_PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '127.', '0.', '255.')

# Benign domains to exclude
_WHITELIST = {
    'google.com', 'googleapis.com', 'android.com', 'gstatic.com',
    'mozilla.org', 'w3.org', 'schema.org', 'example.com', 'localhost'
}


def extract_iocs(strings: List[str]) -> List[Dict]:
    """
    Extract Indicators of Compromise from a list of APK string constants.
    Returns a list of IOC dicts with keys: type, value, risk_level.
    """
    iocs = []
    seen = set()

    for s in strings:
        if not isinstance(s, str):
            continue

        # Extract IPs
        for match in _IP_RE.findall(s):
            if match not in seen and not any(match.startswith(p) for p in _PRIVATE_PREFIXES):
                seen.add(match)
                iocs.append({
                    "type": "IP_ADDRESS",
                    "value": match,
                    "classification": "Potential C2 Server",
                    "risk_level": "HIGH"
                })

        # Extract URLs
        for match in _URL_RE.findall(s):
            domain = re.sub(r'https?://', '', match).split('/')[0].lower()
            if match not in seen and not any(w in domain for w in _WHITELIST):
                seen.add(match)
                risk = "CRITICAL" if _DOMAIN_RE.search(domain) else "MEDIUM"
                iocs.append({
                    "type": "URL",
                    "value": match[:120],
                    "classification": "C2 Endpoint" if risk == "CRITICAL" else "Suspicious URL",
                    "risk_level": risk
                })

        # Extract suspicious TLD domains
        for match in _DOMAIN_RE.findall(s):
            if match not in seen and match.lower() not in _WHITELIST:
                seen.add(match)
                iocs.append({
                    "type": "DOMAIN",
                    "value": match,
                    "classification": "High-Risk TLD Domain",
                    "risk_level": "HIGH"
                })

    logger.info("IOC extraction complete: %d indicators found", len(iocs))
    return iocs[:30]  # cap to 30 IOCs
