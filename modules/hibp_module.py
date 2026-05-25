"""
SankofahEye — Have I Been Pwned Module
AfriWealth Cyber Intelligence

Checks whether email addresses associated with the target domain
appear in known data breaches.
API docs: https://haveibeenpwned.com/API/v3
Requires a paid HIBP API key.
"""

import os
import time
import requests
from utils.logger import SankofahLogger

log = SankofahLogger("hibp")

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
HEADERS_TEMPLATE = {
    "User-Agent": "SankofahEye-AfriWealthCI/1.0",
    "hibp-api-key": "",
}


def check_email(email: str, api_key: str, timeout: int = 20) -> list:
    """Check a single email against HIBP. Returns list of breaches."""
    headers = {**HEADERS_TEMPLATE, "hibp-api-key": api_key}
    try:
        resp = requests.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            headers=headers,
            params={"truncateResponse": "false"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return []  # Not found in any breach — good news
        elif resp.status_code == 429:
            log.warning(f"[HIBP] Rate limited — backing off 2s")
            time.sleep(2)
            return []
        elif resp.status_code == 401:
            log.warning(f"[HIBP] API key not authorised for breach lookup — upgrade to paid plan at haveibeenpwned.com/API/Key")
            return []
        else:
            log.warning(f"[HIBP] Unexpected status {resp.status_code} for {email}")
            return []
    except requests.RequestException as e:
        log.error(f"[HIBP] Request error for {email}: {e}")
        return []


def run(domain: str, emails: list = None, timeout: int = 20) -> dict:
    """
    Check all harvested emails (or a test set) against HIBP.
    emails: list from theHarvester module. If empty, constructs common patterns.
    """
    result = {
        "module": "hibp",
        "target": domain,
        "emails_checked": [],
        "breached_accounts": [],
        "total_breaches": 0,
        "breach_summary": [],
        "status": "ok",
        "error": None,
    }

    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        msg = "HIBP_API_KEY not set in .env"
        log.warning(msg)
        result["status"] = "skipped"
        result["error"] = msg
        return result

    # If no harvested emails, build common patterns to check
    if not emails:
        prefixes = ["info", "admin", "contact", "support", "security", "it", "hr"]
        emails = [f"{p}@{domain}" for p in prefixes]
        log.info(f"[HIBP] No harvested emails — checking {len(emails)} common patterns")
    else:
        # Filter to target domain only
        emails = [e for e in emails if domain in e]
        log.info(f"[HIBP] Checking {len(emails)} harvested emails for {domain}")

    result["emails_checked"] = emails
    all_breach_names = set()

    for email in emails:
        breaches = check_email(email, api_key, timeout)
        if breaches:
            entry = {
                "email": email,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses", []),
                        "pwn_count": b.get("PwnCount", 0),
                    }
                    for b in breaches
                ],
            }
            result["breached_accounts"].append(entry)
            for b in breaches:
                all_breach_names.add(b.get("Name"))
        time.sleep(1.6)  # HIBP rate limit: max 1 req/1.5s

    result["total_breaches"] = len(result["breached_accounts"])
    result["breach_summary"] = list(all_breach_names)

    log.info(
        f"[HIBP] {result['total_breaches']} breached accounts found "
        f"across {len(all_breach_names)} unique breaches"
    )
    return result
