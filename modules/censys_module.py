"""
SankofahEye — Censys Module
AfriWealth Cyber Intelligence

Queries Censys API for exposed services, open ports, and certificates.
Sign up free at search.censys.io/register
"""

import os
import requests
from utils.logger import SankofahLogger

log = SankofahLogger("censys")

CENSYS_BASE = "https://search.censys.io/api/v2"

HIGH_RISK_PORTS = {
    21:    "FTP — unencrypted, data exfiltration risk",
    22:    "SSH — brute-force target",
    23:    "Telnet — unencrypted remote access",
    25:    "SMTP — mail relay abuse risk",
    445:   "SMB — ransomware / EternalBlue",
    1433:  "MSSQL — database exposed to internet",
    1521:  "Oracle DB — database exposed to internet",
    3306:  "MySQL — database exposed to internet",
    3389:  "RDP — ransomware entry point",
    4444:  "Metasploit default listener",
    5432:  "PostgreSQL — database exposed to internet",
    5900:  "VNC — often unauthenticated",
    6379:  "Redis — often no-auth",
    8080:  "HTTP alternate — admin panels",
    8443:  "HTTPS alternate — admin panels",
    27017: "MongoDB — often no-auth",
}


def run(domain: str, timeout: int = 30) -> dict:
    result = {
        "module":          "censys",
        "target":          domain,
        "hosts":           [],
        "open_ports":      [],
        "high_risk_ports": [],
        "cves":            [],
        "banners":         [],
        "total_results":   0,
        "status":          "ok",
        "error":           None,
    }

    api_token = os.getenv("CENSYS_API_TOKEN")
    org_id    = os.getenv("CENSYS_ORG_ID")

    if not api_token:
        msg = "CENSYS_API_TOKEN not set in .env — sign up free at search.censys.io/register"
        log.warning(msg)
        result["status"] = "skipped"
        result["error"]  = msg
        return result

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Censys-Org-Id":  org_id if org_id else "",
        "Content-Type":   "application/json",
        "User-Agent":     "SankofahEye-AfriWealthCI/1.0",
    }

    log.info(f"[Censys] Querying exposed services for {domain}...")

    try:
        resp = requests.post(
            f"{CENSYS_BASE}/hosts/search",
            headers=headers,
            json={
                "q":        f"dns.names: {domain}",
                "per_page": 50,
            },
            timeout=timeout,
        )

        if resp.status_code == 401:
            result["status"] = "error"
            result["error"]  = "Censys authentication failed — check CENSYS_API_TOKEN"
            log.error("[Censys] Authentication failed")
            return result

        if resp.status_code == 429:
            result["status"] = "rate_limited"
            result["error"]  = "Censys rate limit reached — free tier allows 250 queries/month"
            log.warning("[Censys] Rate limited")
            return result

        if resp.status_code != 200:
            result["status"] = "error"
            result["error"]  = f"Censys HTTP {resp.status_code}: {resp.text[:200]}"
            log.error(f"[Censys] HTTP {resp.status_code}")
            return result

        data  = resp.json()
        hits  = data.get("result", {}).get("hits", [])
        result["total_results"] = data.get("result", {}).get("total", 0)

        all_ports = set()
        risky     = []
        banners   = []

        for hit in hits:
            ip       = hit.get("ip", "")
            services = hit.get("services", [])
            location = hit.get("location", {})
            asn_info = hit.get("autonomous_system", {})

            for svc in services:
                port      = svc.get("port", 0)
                transport = svc.get("transport_protocol", "TCP")
                svc_name  = svc.get("service_name", "")
                banner    = svc.get("banner", "")[:200]

                all_ports.add(port)

                result["hosts"].append({
                    "ip":        ip,
                    "port":      port,
                    "transport": transport,
                    "product":   svc_name,
                    "version":   svc.get("software", [{}])[0].get("version", "") if svc.get("software") else "",
                    "org":       asn_info.get("name", ""),
                    "country":   location.get("country", ""),
                })

                if port in HIGH_RISK_PORTS:
                    risky.append({
                        "ip":     ip,
                        "port":   port,
                        "reason": HIGH_RISK_PORTS[port],
                    })

                if banner:
                    banners.append({"ip": ip, "port": port, "banner": banner})

        result["open_ports"]      = sorted(list(all_ports))
        result["high_risk_ports"] = risky
        result["banners"]         = banners[:10]

        log.info(
            f"[Censys] Hosts: {len(result['hosts'])} | "
            f"High-risk ports: {len(risky)} | "
            f"Open ports: {sorted(list(all_ports))}"
        )

    except requests.RequestException as e:
        result["status"] = "error"
        result["error"]  = str(e)
        log.error(f"[Censys] {e}")

    return result