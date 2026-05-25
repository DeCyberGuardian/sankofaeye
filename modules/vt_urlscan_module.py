"""
SankofahEye — VirusTotal + URLScan.io Module
AfriWealth Cyber Intelligence

VirusTotal: domain reputation, malware/phishing flags from 70+ vendors
URLScan.io: passive web scan — technologies, links, screenshots
"""

import os
import time
import requests
from utils.logger import SankofahLogger

log = SankofahLogger("vt_urlscan")

VT_BASE     = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"


# ── VirusTotal ────────────────────────────────────────────────

def query_virustotal(domain: str, api_key: str, timeout: int = 30) -> dict:
    headers = {"x-apikey": api_key}
    vt_result = {
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 0,
        "categories": [],
        "last_analysis_date": "",
        "flagged_vendors": [],
        "status": "ok",
        "error": None,
    }

    try:
        resp = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            results = data.get("last_analysis_results", {})
            cats = data.get("categories", {})

            vt_result["malicious_votes"]   = stats.get("malicious", 0)
            vt_result["suspicious_votes"]  = stats.get("suspicious", 0)
            vt_result["harmless_votes"]    = stats.get("harmless", 0)
            vt_result["categories"]        = list(set(cats.values()))
            vt_result["last_analysis_date"] = data.get("last_analysis_date", "")

            vt_result["flagged_vendors"] = [
                {"vendor": vendor, "result": res.get("result", "")}
                for vendor, res in results.items()
                if res.get("category") in ("malicious", "suspicious")
            ]
        elif resp.status_code == 404:
            vt_result["status"] = "not_found"
        else:
            vt_result["status"] = "error"
            vt_result["error"] = f"VT HTTP {resp.status_code}"
    except requests.RequestException as e:
        vt_result["status"] = "error"
        vt_result["error"] = str(e)

    return vt_result


# ── URLScan.io ────────────────────────────────────────────────

def query_urlscan(domain: str, api_key: str, timeout: int = 30) -> dict:
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    urlscan_result = {
        "scans": [],
        "technologies": [],
        "malicious_score": 0,
        "screenshot_url": "",
        "status": "ok",
        "error": None,
    }

    try:
        # Search existing scans (passive — we do NOT submit a new scan)
        resp = requests.get(
            f"{URLSCAN_BASE}/search/",
            params={"q": f"domain:{domain}", "size": 5},
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            tech_set = set()

            for scan in results:
                page   = scan.get("page", {})
                task   = scan.get("task", {})
                stats  = scan.get("stats", {})
                meta   = scan.get("meta", {})

                # Technologies
                for t in scan.get("page", {}).get("tlsIssuer", "").split(","):
                    tech_set.add(t.strip())

                scan_entry = {
                    "scan_id": task.get("uuid", ""),
                    "url": page.get("url", ""),
                    "ip": page.get("ip", ""),
                    "country": page.get("country", ""),
                    "server": page.get("server", ""),
                    "date": task.get("time", ""),
                    "malicious": stats.get("malicious", 0),
                }
                urlscan_result["scans"].append(scan_entry)

                if stats.get("malicious", 0) > 0:
                    urlscan_result["malicious_score"] += stats["malicious"]

                # Grab screenshot from most recent scan
                if not urlscan_result["screenshot_url"] and task.get("uuid"):
                    urlscan_result["screenshot_url"] = (
                        f"https://urlscan.io/screenshots/{task['uuid']}.png"
                    )

            urlscan_result["technologies"] = [t for t in tech_set if t]
        elif resp.status_code == 429:
            urlscan_result["status"] = "rate_limited"
            urlscan_result["error"] = "URLScan rate limited"
        else:
            urlscan_result["status"] = "error"
            urlscan_result["error"] = f"URLScan HTTP {resp.status_code}"

    except requests.RequestException as e:
        urlscan_result["status"] = "error"
        urlscan_result["error"] = str(e)

    return urlscan_result


# ── Combined runner ───────────────────────────────────────────

def run(domain: str, timeout: int = 30) -> dict:
    result = {
        "module": "vt_urlscan",
        "target": domain,
        "virustotal": {},
        "urlscan": {},
        "status": "ok",
        "error": None,
    }

    vt_key      = os.getenv("VIRUSTOTAL_API_KEY")
    urlscan_key = os.getenv("URLSCAN_API_KEY")

    if vt_key:
        log.info(f"[VirusTotal] Checking reputation of {domain}...")
        result["virustotal"] = query_virustotal(domain, vt_key, timeout)
        vt = result["virustotal"]
        log.info(
            f"[VirusTotal] Malicious: {vt.get('malicious_votes')} | "
            f"Suspicious: {vt.get('suspicious_votes')} | "
            f"Flagged vendors: {len(vt.get('flagged_vendors', []))}"
        )
    else:
        log.warning("[VirusTotal] VIRUSTOTAL_API_KEY not set — skipping")
        result["virustotal"] = {"status": "skipped", "error": "No API key"}

    if urlscan_key:
        log.info(f"[URLScan] Searching passive scans for {domain}...")
        result["urlscan"] = query_urlscan(domain, urlscan_key, timeout)
        log.info(f"[URLScan] Found {len(result['urlscan'].get('scans', []))} scans")
    else:
        log.warning("[URLScan] URLSCAN_API_KEY not set — skipping")
        result["urlscan"] = {"status": "skipped", "error": "No API key"}

    return result
