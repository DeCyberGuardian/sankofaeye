"""
SankofahEye — HudsonRock Cavalier Module
AfriWealth Cyber Intelligence

Checks if the target domain appears in infostealer malware logs.
No API key required — free public endpoint.

Data source: Raccoon, Redline, Vidar and other infostealer logs
aggregated by HudsonRock's threat intelligence platform.
"""

import requests
from utils.logger import SankofahLogger

log = SankofahLogger("hudsonrock")

HUDSONROCK_BASE = "https://cavalier.hudsonrock.com/api/json/v2"


def run(domain: str, timeout: int = 30) -> dict:
    result = {
        "module":                "hudsonrock",
        "target":                domain,
        "compromised_employees": [],
        "compromised_users":     [],
        "stealer_families":      [],
        "total_employees":       0,
        "total_users":           0,
        "status":                "ok",
        "error":                 None,
    }

    log.info(f"[HudsonRock] Checking infostealer logs for {domain}...")

    try:
        resp = requests.get(
            f"{HUDSONROCK_BASE}/osint-tools/urls-by-domain",
            params={"domain": domain},
            headers={"User-Agent": "SankofahEye-AfriWealthCI/1.0"},
            timeout=timeout,
        )

        if resp.status_code == 200:
            data      = resp.json()
            employees = data.get("employees", [])
            users     = data.get("users", [])
            stealers  = set()

            for emp in employees:
                stealers.add(emp.get("stealer_family", "unknown"))
                result["compromised_employees"].append({
                    "email":            emp.get("email", ""),
                    "stealer_family":   emp.get("stealer_family", ""),
                    "date_uploaded":    emp.get("date_uploaded", ""),
                    "computer_name":    emp.get("computer_name", ""),
                    "operating_system": emp.get("operating_system", ""),
                })

            for usr in users[:20]:
                stealers.add(usr.get("stealer_family", "unknown"))
                result["compromised_users"].append({
                    "email":          usr.get("email", ""),
                    "stealer_family": usr.get("stealer_family", ""),
                    "date_uploaded":  usr.get("date_uploaded", ""),
                })

            result["total_employees"]  = len(employees)
            result["total_users"]      = len(users)
            result["stealer_families"] = list(stealers)

            log.info(
                f"[HudsonRock] Compromised employees: {len(employees)} | "
                f"Compromised users: {len(users)} | "
                f"Stealers: {list(stealers)}"
            )

        elif resp.status_code == 429:
            result["status"] = "rate_limited"
            result["error"]  = "HudsonRock rate limited — try again later"
            log.warning("[HudsonRock] Rate limited")
        else:
            result["status"] = "error"
            result["error"]  = f"HudsonRock HTTP {resp.status_code}"
            log.warning(f"[HudsonRock] HTTP {resp.status_code}")

    except requests.RequestException as e:
        result["status"] = "error"
        result["error"]  = str(e)
        log.error(f"[HudsonRock] {e}")

    return result