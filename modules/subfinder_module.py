"""
SankofahEye — Subfinder Module
AfriWealth Cyber Intelligence

Wraps the Subfinder binary to passively enumerate subdomains.
Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
"""

import subprocess
import shutil
from utils.logger import SankofahLogger

log = SankofahLogger("subfinder")


def run(domain: str, timeout: int = 60) -> dict:
    """
    Run subfinder against the target domain.
    Returns a dict with subdomains list and metadata.
    """
    result = {
        "module": "subfinder",
        "target": domain,
        "subdomains": [],
        "count": 0,
        "status": "ok",
        "error": None,
    }

    if not shutil.which("subfinder"):
        msg = "subfinder binary not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        log.warning(msg)
        result["status"] = "skipped"
        result["error"] = msg
        return result

    log.info(f"[Subfinder] Enumerating subdomains for {domain}...")

    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        subdomains = [
            line.strip()
            for line in proc.stdout.splitlines()
            if line.strip()
        ]
        result["subdomains"] = sorted(set(subdomains))
        result["count"] = len(result["subdomains"])
        log.info(f"[Subfinder] Found {result['count']} subdomains.")
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = f"Subfinder timed out after {timeout}s"
        log.warning(result["error"])
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log.error(f"[Subfinder] {e}")

    return result
