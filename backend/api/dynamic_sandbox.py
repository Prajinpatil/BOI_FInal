import os
import time
import logging
import requests

logger = logging.getLogger("nirikshak.sandbox")

VT_API_URL = "https://www.virustotal.com/api/v3"


def get_vt_reputation_score(sha256: str, api_key: str) -> float:
    """
    Fallback: Query VirusTotal AV reputation (70+ engines).
    Used when sandbox yields no behavior (sandbox evasion detected).
    Returns 0.0 - 1.0 based on how many AV engines flagged the file.
    """
    headers = {"x-apikey": api_key}
    try:
        res = requests.get(f"{VT_API_URL}/files/{sha256}", headers=headers, timeout=15)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            if total == 0:
                return 0.0
            flagged = malicious + suspicious
            score = min(1.0, flagged / max(total * 0.15, 1))  # 15%+ detections = max score
            logger.info("VT Reputation Fallback: %d/%d engines flagged -> score=%.3f", flagged, total, score)
            return round(score, 4)
        elif res.status_code == 404:
            logger.info("VT Reputation: File not yet in VT database. Score=0.0")
            return 0.0
        else:
            logger.warning("VT Reputation API error: %s", res.status_code)
            return 0.0
    except Exception as exc:
        logger.error("VT Reputation request failed: %s", exc)
        return 0.0


def run_cloud_sandbox(apk_path: str, sha256: str, api_key: str) -> float:
    """
    Submit or retrieve dynamic behavior analysis from VirusTotal.
    If sandbox returns no behavior (sandbox evasion), automatically falls back
    to VT AV Reputation score from 70+ antivirus engines.
    Returns a dynamic_score between 0.0 and 1.0.
    """
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    logger.info("Checking VirusTotal Sandbox for existing behavior report...")

    # 1. Try to get behavior summary directly
    behav_res = requests.get(
        f"{VT_API_URL}/files/{sha256}/behavior_summary",
        headers=headers, timeout=30
    )
    if behav_res.status_code == 200:
        score = _score_vt_behavior(behav_res.json())
        if score > 0.0:
            logger.info("Sandbox behavior report found. Dynamic score=%.3f", score)
            return score

    # 2. If no behavior summary, check if the file is known to VT at all
    file_res = requests.get(
        f"{VT_API_URL}/files/{sha256}",
        headers=headers, timeout=30
    )
    if file_res.status_code == 200:
        logger.warning("File exists on VT but lacks behavior report (sandbox evasion). Triggering VT Reputation Fallback...")
        return get_vt_reputation_score(sha256, api_key)

    # 3. If file is totally unknown (404), upload it
    if file_res.status_code == 404:
        file_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
        logger.info("File completely unknown to VT. Uploading (%.1fMB) for analysis...", file_size_mb)
        try:
            with open(apk_path, "rb") as f:
                files = {"file": (os.path.basename(apk_path), f, "application/vnd.android.package-archive")}
                # Large files (>32MB) need a higher upload timeout
                upload_timeout = 180 if file_size_mb > 32 else 60
                upload_res = requests.post(
                    f"{VT_API_URL}/files",
                    headers=headers, files=files, timeout=upload_timeout
                )

            if upload_res.status_code != 200:
                logger.error("Failed to upload to VT: %s", upload_res.text)
                return 0.0

            analysis_id = upload_res.json().get("data", {}).get("id")

            # Poll for completion — large files need more time
            max_retries = 40  # Increased from 20 → 40 (10 minutes total)
            poll_interval = 15
            for i in range(max_retries):
                logger.info("Polling Sandbox status (Attempt %d/%d)...", i + 1, max_retries)
                time.sleep(poll_interval)
                poll_res = requests.get(
                    f"{VT_API_URL}/analyses/{analysis_id}",
                    headers=headers, timeout=30
                )
                if poll_res.status_code == 200:
                    status = poll_res.json().get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        logger.info("Sandbox AV analysis completed!")
                        logger.warning("Sandbox behavior not ready yet. Using AV Reputation from analysis...")
                        stats = poll_res.json().get("data", {}).get("attributes", {}).get("stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        total = sum(stats.values())
                        if total > 0:
                            flagged = malicious + suspicious
                            score = min(1.0, flagged / max(total * 0.15, 1))
                            logger.info("New File VT Reputation: %d/%d engines flagged -> score=%.3f", flagged, total, score)
                            return round(score, 4)
                        return 0.0

            logger.warning("Sandbox analysis timed out after %d attempts. Triggering VT Reputation Fallback...", max_retries)
            return get_vt_reputation_score(sha256, api_key)

        except Exception as exc:
            logger.error("Sandbox upload/polling error: %s", exc)
            return get_vt_reputation_score(sha256, api_key)

    logger.warning("VT API error: %s %s", file_res.status_code, file_res.text[:100])
    return 0.0


def _score_vt_behavior(vt_data: dict) -> float:
    """
    Score dynamic behavior based on VT sandbox tags and network activity.
    """
    try:
        data = vt_data.get("data", {})
        tags = data.get("tags", [])

        score = 0.0
        bad_tags = [
            "persistence", "stealth", "network-communication", "exploits",
            "evasion", "crypto", "obfuscated", "telemetry", "infostealer",
            "ransomware", "spyware", "banker"
        ]
        for tag in tags:
            if tag in bad_tags:
                score += 0.3

        http_requests = data.get("http_conversations", [])
        dns_lookups = data.get("dns_lookups", [])
        if len(http_requests) > 0:
            score += 0.2
        if len(dns_lookups) > 2:
            score += 0.2

        final_score = min(1.0, max(0.0, score))
        logger.info("Sandbox behavior score=%.3f (tags=%s)", final_score, tags)
        return final_score
    except Exception as exc:
        logger.error("Error parsing VT behavior: %s", exc)
        return 0.0
