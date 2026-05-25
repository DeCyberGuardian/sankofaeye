"""
SankofahEye — theHarvester Module
AfriWealth Cyber Intelligence

Wraps theHarvester to collect emails, hostnames, and DNS records.
Install: pip install theHarvester  OR  clone from github.com/laramies/theHarvester
"""

import subprocess
import shutil
import json
import re
from utils.logger import SankofahLogger

log = SankofahLogger("harvester")


def run(domain: str, timeout: int = 60) -> dict:
    result = {
        "module": "theharvester",
        "target": domain,
        "emails": [],
        "hosts": [],
        "ips": [],
        "status": "ok",
        "error": None,
    }

    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    if not binary:
        msg = "theHarvester not found. Install: pip install theHarvester"
        log.warning(msg)
        result["status"] = "skipped"
        result["error"] = msg
        return result

    log.info(f"[theHarvester] Harvesting emails and hosts for {domain}...")

    try:
        proc = subprocess.run(
            [binary, "-d", domain, "-b", "bing,certspotter,crtsh,dnsdumpster,duckduckgo", "-f", "/tmp/harvester_out"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = proc.stdout + proc.stderr

        # Parse emails
        emails = list(set(re.findall(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', output
        )))
        # Parse hosts (lines ending in domain)
        hosts = list(set(re.findall(
            rf'[\w\-\.]+\.{re.escape(domain)}', output
        )))
        # Parse IPs
        ips = list(set(re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output
        )))

        result["emails"] = sorted(emails)
        result["hosts"] = sorted(hosts)
        result["ips"] = sorted(ips)
        log.info(f"[theHarvester] Emails: {len(emails)}, Hosts: {len(hosts)}, IPs: {len(ips)}")

    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = f"theHarvester timed out after {timeout}s"
        log.warning(result["error"])
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log.error(f"[theHarvester] {e}")

    return result
