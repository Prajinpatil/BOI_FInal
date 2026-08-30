"""
NIRIKSHAK-AI :: APK Certificate Analyzer
Parses APK signing certificate for forensic indicators.
"""
import zipfile
import logging
import datetime
from typing import Optional, Dict

logger = logging.getLogger("nirikshak.cert")


def analyze_certificate(apk_path: str) -> Dict:
    """
    Extract and analyze the APK signing certificate.
    Returns dict with cert details and risk flags.
    """
    result = {
        "cert_found": False,
        "issuer": "Unknown",
        "subject": "Unknown",
        "is_self_signed": False,
        "is_expired": False,
        "valid_from": None,
        "valid_to": None,
        "days_valid": None,
        "risk_flags": [],
        "cert_risk_boost": 0.0,
    }

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            # Find META-INF cert files
            cert_files = [f for f in zf.namelist()
                          if f.startswith('META-INF/') and
                          (f.endswith('.RSA') or f.endswith('.DSA') or f.endswith('.EC'))]

            if not cert_files:
                result["risk_flags"].append("NO_SIGNATURE_FILE")
                result["cert_risk_boost"] = 0.1
                return result

            result["cert_found"] = True
            cert_data = zf.read(cert_files[0])

            # Try to parse with cryptography library
            try:
                from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
                from cryptography import x509

                certs = load_der_pkcs7_certificates(cert_data)
                if certs:
                    cert = certs[0]
                    result["issuer"] = cert.issuer.rfc4514_string()
                    result["subject"] = cert.subject.rfc4514_string()
                    result["valid_from"] = cert.not_valid_before_utc.isoformat()
                    result["valid_to"] = cert.not_valid_after_utc.isoformat()

                    now = datetime.datetime.now(datetime.timezone.utc)
                    result["is_expired"] = cert.not_valid_after_utc < now
                    result["days_valid"] = (cert.not_valid_after_utc - cert.not_valid_before_utc).days

                    # Self-signed: issuer == subject
                    result["is_self_signed"] = cert.issuer == cert.subject

                    if result["is_self_signed"]:
                        result["risk_flags"].append("SELF_SIGNED")
                        result["cert_risk_boost"] += 0.25

                    if result["is_expired"]:
                        result["risk_flags"].append("EXPIRED")
                        result["cert_risk_boost"] += 0.15

                    # Very short-lived cert (< 30 days) is suspicious
                    if result["days_valid"] and result["days_valid"] < 30:
                        result["risk_flags"].append("SHORT_LIVED_CERT")
                        result["cert_risk_boost"] += 0.1

                    # Debug/test subject names
                    subj_lower = result["subject"].lower()
                    if any(k in subj_lower for k in ["android debug", "unknown", "test", "example"]):
                        result["risk_flags"].append("DEBUG_CERT")
                        result["cert_risk_boost"] += 0.2

            except ImportError:
                result["issuer"] = "cryptography library not installed"
                result["risk_flags"].append("CERT_PARSE_SKIPPED")
            except Exception as parse_exc:
                logger.debug("PKCS7 parse failed: %s", parse_exc)
                result["risk_flags"].append("CERT_PARSE_FAILED")

    except zipfile.BadZipFile:
        result["risk_flags"].append("INVALID_ZIP")
    except Exception as exc:
        logger.error("Certificate analysis error: %s", exc)

    result["cert_risk_boost"] = round(min(0.5, result["cert_risk_boost"]), 4)
    logger.info("Cert analysis: self_signed=%s, expired=%s, flags=%s, boost=%.2f",
                result["is_self_signed"], result["is_expired"],
                result["risk_flags"], result["cert_risk_boost"])
    return result
