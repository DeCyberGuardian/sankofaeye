"""
SankofahEye — Data Aggregator
AfriWealth Cyber Intelligence

Normalises and merges raw output from all recon modules
into a single structured findings object.
"""

from utils.logger import SankofahLogger

log = SankofahLogger("aggregator")


def aggregate(
    subfinder,
    harvester,
    shodan,
    hibp,
    vt_urlscan,
    darkweb,
    hudsonrock,
    dns,
    ssl,
    target,
) -> dict:
    """
    Merge all module results into a unified findings dict.
    Cross-references findings where possible.
    """
    log.info("[Aggregator] Normalising and merging findings...")

    # ── Subdomains (merged from subfinder + harvester) ────────
    subfinder_subs  = set(subfinder.get("subdomains", []))
    harvester_hosts = set(harvester.get("hosts", []))
    all_subdomains  = sorted(subfinder_subs | harvester_hosts)

    # ── Emails ────────────────────────────────────────────────
    all_emails = sorted(set(harvester.get("emails", [])))

    # ── IPs ───────────────────────────────────────────────────
    all_ips = sorted(set(harvester.get("ips", [])))

    # ── Exposed services (Censys) ─────────────────────────────
    shodan_hosts    = shodan.get("hosts", [])
    high_risk_ports = shodan.get("high_risk_ports", [])
    cves            = shodan.get("cves", [])
    open_ports      = shodan.get("open_ports", [])

    # ── Credential leaks (HIBP) ───────────────────────────────
    breached_accounts = hibp.get("breached_accounts", [])
    breach_names      = hibp.get("breach_summary", [])

    # ── Reputation (VirusTotal + URLScan) ─────────────────────
    vt_data      = vt_urlscan.get("virustotal", {})
    urlscan_data = vt_urlscan.get("urlscan", {})

    malicious_votes  = vt_data.get("malicious_votes", 0)
    suspicious_votes = vt_data.get("suspicious_votes", 0)
    flagged_vendors  = vt_data.get("flagged_vendors", [])
    categories       = vt_data.get("categories", [])

    # ── Dark web ──────────────────────────────────────────────
    dw_mentions  = darkweb.get("mentions", [])
    dw_high_risk = darkweb.get("high_risk_mentions", 0)

    # ── Infostealer exposure (HudsonRock) ─────────────────────
    compromised_employees = hudsonrock.get("compromised_employees", [])
    compromised_users     = hudsonrock.get("compromised_users", [])
    stealer_families      = hudsonrock.get("stealer_families", [])

    # ── DNS security ──────────────────────────────────────────
    dns_issues = dns.get("issues", [])
    spf_data   = dns.get("spf", {})
    dmarc_data = dns.get("dmarc", {})
    dkim_data  = dns.get("dkim", {})
    mx_data    = dns.get("mx", {})
    ns_data    = dns.get("ns", {})

    # ── SSL/TLS certificates ──────────────────────────────────
    ssl_expired       = ssl.get("expired", [])
    ssl_expiring      = ssl.get("expiring_soon", [])
    ssl_self_signed   = ssl.get("self_signed", [])
    ssl_weak_protocol = ssl.get("weak_protocol", [])
    ssl_total_issues  = ssl.get("total_issues", 0)

    # ── Module status summary ─────────────────────────────────
    module_statuses = {
        "subfinder":    subfinder.get("status",  "unknown"),
        "theharvester": harvester.get("status",  "unknown"),
        "censys":       shodan.get("status",     "unknown"),
        "hibp":         hibp.get("status",       "unknown"),
        "vt_urlscan":   vt_urlscan.get("status", "unknown"),
        "darkweb":      darkweb.get("status",    "unknown"),
        "hudsonrock":   hudsonrock.get("status", "unknown"),
        "dns":          dns.get("status",        "unknown"),
        "ssl":          ssl.get("status",        "unknown"),
    }

    findings = {
        "target":          target,
        "module_statuses": module_statuses,
        "subdomains": {
            "list":  all_subdomains,
            "count": len(all_subdomains),
        },
        "emails": {
            "list":  all_emails,
            "count": len(all_emails),
        },
        "ips": {
            "list":  all_ips,
            "count": len(all_ips),
        },
        "exposed_services": {
            "hosts":           shodan_hosts,
            "open_ports":      open_ports,
            "high_risk_ports": high_risk_ports,
            "cves":            cves,
            "total_hosts":     len(shodan_hosts),
        },
        "credential_exposure": {
            "breached_accounts": breached_accounts,
            "breach_names":      breach_names,
            "total_breached":    len(breached_accounts),
        },
        "reputation": {
            "malicious_votes":  malicious_votes,
            "suspicious_votes": suspicious_votes,
            "flagged_vendors":  flagged_vendors,
            "categories":       categories,
            "urlscan_scans":    urlscan_data.get("scans", []),
            "screenshot_url":   urlscan_data.get("screenshot_url", ""),
        },
        "dark_web": {
            "mentions":           dw_mentions,
            "total_mentions":     len(dw_mentions),
            "high_risk_mentions": dw_high_risk,
        },
        "infostealer_exposure": {
            "compromised_employees": compromised_employees,
            "compromised_users":     compromised_users,
            "stealer_families":      stealer_families,
            "total_employees":       len(compromised_employees),
            "total_users":           len(compromised_users),
        },
        "dns_security": {
            "spf":         spf_data,
            "dmarc":       dmarc_data,
            "dkim":        dkim_data,
            "mx":          mx_data,
            "ns":          ns_data,
            "issues":      dns_issues,
            "issue_count": len(dns_issues),
        },
        "ssl_certificates": {
            "certificates":      ssl.get("certificates", []),
            "expired":           ssl_expired,
            "expiring_soon":     ssl_expiring,
            "self_signed":       ssl_self_signed,
            "weak_protocol":     ssl_weak_protocol,
            "total_checked":     ssl.get("total_checked", 0),
            "total_issues":      ssl_total_issues,
        },
    }

    log.info(
        f"[Aggregator] Subdomains: {len(all_subdomains)} | "
        f"Emails: {len(all_emails)} | "
        f"Exposed hosts: {len(shodan_hosts)} | "
        f"Breached accounts: {len(breached_accounts)} | "
        f"Infostealer hits: {len(compromised_employees)} employees | "
        f"Dark web mentions: {len(dw_mentions)} | "
        f"DNS issues: {len(dns_issues)} | SSL issues: {ssl_total_issues}"
    )

    return findings