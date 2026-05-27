"""
SankofahEye — Regulatory Compliance Mapper
AfriWealth Cyber Intelligence

Maps passive scan findings to three Ghana regulatory frameworks:

  1. Bank of Ghana Cyber and Information Security Directive (2018)
     - Applies to: banks, savings & loans, payment service providers
     - Key areas: email security, access control, encryption, monitoring

  2. National Communications Authority (NCA) Cybersecurity Guidelines
     - Applies to: telecoms, ISPs, electronic communications operators
     - Key areas: network security, encryption, incident reporting

  3. Ghana Data Protection Act 2012 (Act 843) — DPC Requirements
     - Applies to: all organisations processing personal data of Ghanaians
     - Key areas: data security, breach notification, access control

For each framework, produces:
  - Compliance score (0–100%)
  - List of specific control gaps with severity
  - Remediation guidance referencing the actual directive section

This is intelligence — not legal advice.
"""

from utils.logger import SankofahLogger

log = SankofahLogger("compliance_mapper")


# ─── Framework definitions ─────────────────────────────────────────────────────
# Each control:
#   id, section, requirement, how_to_check (maps to finding patterns), severity

BOG_CONTROLS = [
    {
        "id": "BOG-01",
        "section": "Section 4.2 — Email Security",
        "requirement": "Organisations must implement SPF, DKIM, and DMARC on all mail domains to prevent email spoofing and phishing.",
        "checks": ["spf_missing", "spf_weak", "dmarc_missing", "dmarc_not_enforced", "dkim_missing"],
        "severity": "critical",
        "remediation": "Deploy SPF with -all hardfail, DKIM signing on all selectors, and DMARC with p=reject. Reference: BoG CISD Section 4.2 — Email Authentication Controls.",
    },
    {
        "id": "BOG-02",
        "section": "Section 4.3 — Encryption in Transit",
        "requirement": "All internet-facing services must use current encryption protocols. TLS 1.0 and TLS 1.1 are deprecated and must not be used.",
        "checks": ["weak_tls"],
        "severity": "high",
        "remediation": "Disable TLS 1.0 and 1.1 on all servers. Enforce TLS 1.2 minimum, TLS 1.3 preferred. Reference: BoG CISD Section 4.3 — Cryptographic Controls.",
    },
    {
        "id": "BOG-03",
        "section": "Section 4.5 — Access Control",
        "requirement": "Webmail and administrative portals must be protected with multi-factor authentication. Direct internet exposure of admin interfaces is prohibited.",
        "checks": ["webmail_exposed", "admin_portal_exposed", "cpanel_exposed"],
        "severity": "high",
        "remediation": "Enforce MFA on all webmail and administrative portals. Implement geo-blocking on login interfaces. Reference: BoG CISD Section 4.5 — Access Control.",
    },
    {
        "id": "BOG-04",
        "section": "Section 4.6 — Attack Surface Management",
        "requirement": "Organisations must maintain an inventory of all internet-facing assets and decommission unused systems.",
        "checks": ["large_subdomain_footprint", "ftp_exposed"],
        "severity": "medium",
        "remediation": "Audit all subdomains and internet-facing assets quarterly. Decommission unused subdomains. Reference: BoG CISD Section 4.6 — Asset Management.",
    },
    {
        "id": "BOG-05",
        "section": "Section 4.8 — Certificate Management",
        "requirement": "All TLS certificates must be valid and renewed before expiry. Expired certificates on production systems are a compliance failure.",
        "checks": ["expired_cert", "expiring_cert"],
        "severity": "high",
        "remediation": "Renew expiring certificates immediately. Implement automated renewal (Let's Encrypt or similar). Reference: BoG CISD Section 4.8 — PKI and Certificate Management.",
    },
    {
        "id": "BOG-06",
        "section": "Section 5.1 — Credential Exposure Monitoring",
        "requirement": "Organisations must monitor for credential leaks and respond to breached accounts within 24 hours.",
        "checks": ["breached_credentials"],
        "severity": "critical",
        "remediation": "Reset all breached credentials immediately. Enable HIBP monitoring. Reference: BoG CISD Section 5.1 — Incident Response.",
    },
    {
        "id": "BOG-07",
        "section": "Section 5.3 — Dark Web Monitoring",
        "requirement": "Regulated institutions must implement threat intelligence monitoring including dark web surveillance for organisation-related data.",
        "checks": ["dark_web_mentions"],
        "severity": "high",
        "remediation": "Investigate dark web mentions immediately. Engage threat intelligence provider for ongoing monitoring. Reference: BoG CISD Section 5.3 — Threat Intelligence.",
    },
    {
        "id": "BOG-08",
        "section": "Section 6.2 — Vulnerability Management",
        "requirement": "Known vulnerable software versions must be patched within 30 days of disclosure. Critical patches within 72 hours.",
        "checks": ["vulnerable_tech"],
        "severity": "high",
        "remediation": "Update all detected software to current supported versions. Implement a patch management programme. Reference: BoG CISD Section 6.2 — Vulnerability Management.",
    },
]

NCA_CONTROLS = [
    {
        "id": "NCA-01",
        "section": "Section 3.1 — Network Encryption",
        "requirement": "Electronic communications operators must encrypt all customer-facing traffic using current TLS standards. Deprecated protocols are non-compliant.",
        "checks": ["weak_tls"],
        "severity": "high",
        "remediation": "Enforce TLS 1.2+ across all customer-facing endpoints. Disable deprecated SSL/TLS versions. Reference: NCA Cybersecurity Guidelines Section 3.1.",
    },
    {
        "id": "NCA-02",
        "section": "Section 3.3 — Email Domain Security",
        "requirement": "Licensed operators must implement email authentication controls to protect their brand domains from impersonation.",
        "checks": ["spf_missing", "spf_weak", "dmarc_missing", "dmarc_not_enforced", "dkim_missing"],
        "severity": "high",
        "remediation": "Deploy full email authentication stack (SPF, DKIM, DMARC p=reject). Reference: NCA Guidelines Section 3.3 — Brand Protection.",
    },
    {
        "id": "NCA-03",
        "section": "Section 4.1 — Internet-Facing Asset Inventory",
        "requirement": "Operators must maintain and regularly review a registry of all internet-facing systems and services.",
        "checks": ["large_subdomain_footprint"],
        "severity": "medium",
        "remediation": "Maintain a current asset inventory. Review and decommission unused subdomains quarterly. Reference: NCA Guidelines Section 4.1.",
    },
    {
        "id": "NCA-04",
        "section": "Section 4.4 — Insecure Service Exposure",
        "requirement": "Unencrypted protocols (FTP, Telnet) must not be exposed to the internet. All file transfer must use encrypted alternatives.",
        "checks": ["ftp_exposed"],
        "severity": "high",
        "remediation": "Replace FTP with SFTP or FTPS. Block port 21 at perimeter. Reference: NCA Guidelines Section 4.4 — Secure Service Configuration.",
    },
    {
        "id": "NCA-05",
        "section": "Section 5.2 — Certificate Validity",
        "requirement": "All operator web services must maintain valid TLS certificates. Expired certificates must be renewed within 24 hours.",
        "checks": ["expired_cert", "expiring_cert"],
        "severity": "medium",
        "remediation": "Renew all expiring certificates. Implement certificate monitoring and automated renewal. Reference: NCA Guidelines Section 5.2.",
    },
    {
        "id": "NCA-06",
        "section": "Section 6.1 — Vulnerability Disclosure",
        "requirement": "Known software vulnerabilities must be remediated according to severity timelines. Critical: 72 hours. High: 30 days.",
        "checks": ["vulnerable_tech"],
        "severity": "high",
        "remediation": "Apply patches according to NCA timelines. Document remediation in your vulnerability register. Reference: NCA Guidelines Section 6.1.",
    },
]

DPC_CONTROLS = [
    {
        "id": "DPC-01",
        "section": "Act 843 Section 28 — Data Security",
        "requirement": "Data controllers must implement appropriate technical measures to protect personal data. This includes encryption of data in transit using current standards.",
        "checks": ["weak_tls", "ftp_exposed"],
        "severity": "high",
        "remediation": "Enforce TLS 1.2+ on all systems handling personal data. Disable unencrypted protocols. Reference: Data Protection Act 2012, Section 28 — Security of Personal Data.",
    },
    {
        "id": "DPC-02",
        "section": "Act 843 Section 29 — Breach Notification",
        "requirement": "Data controllers must notify the Data Protection Commission within 72 hours of discovering a personal data breach.",
        "checks": ["breached_credentials", "dark_web_mentions"],
        "severity": "critical",
        "remediation": "If credential exposure is confirmed, notify DPC within 72 hours. Conduct a breach impact assessment. Reference: DPC Act 843 Section 29.",
    },
    {
        "id": "DPC-03",
        "section": "Act 843 Section 30 — Access Controls",
        "requirement": "Access to systems containing personal data must be restricted to authorised individuals. Exposed administrative interfaces are a non-compliance risk.",
        "checks": ["webmail_exposed", "admin_portal_exposed", "cpanel_exposed"],
        "severity": "high",
        "remediation": "Restrict access to data systems. Implement MFA on all interfaces accessing personal data. Reference: DPC Act 843 Section 30 — Access Control.",
    },
    {
        "id": "DPC-04",
        "section": "Act 843 Section 17 — Data Minimisation",
        "requirement": "Organisations must not retain or expose more data than necessary. Excessive subdomain footprint may indicate uncontrolled data processing environments.",
        "checks": ["large_subdomain_footprint"],
        "severity": "low",
        "remediation": "Audit all subdomains. Decommission systems not actively processing data. Reference: DPC Act 843 Section 17 — Purpose Limitation.",
    },
    {
        "id": "DPC-05",
        "section": "Act 843 Section 31 — Infostealer / Credential Compromise",
        "requirement": "Discovery of employee credentials in infostealer logs constitutes a potential personal data breach and must be investigated immediately.",
        "checks": ["infostealer_exposure"],
        "severity": "critical",
        "remediation": "Treat infostealer exposure as a breach. Reset all affected credentials. Notify DPC if personal data was accessed. Reference: DPC Act 843 Section 31.",
    },
]

FRAMEWORKS = {
    "bog": {
        "name":        "Bank of Ghana — Cyber & Information Security Directive",
        "short":       "BoG CISD",
        "applies_to":  "Banks, savings & loans, payment service providers, fintechs under BoG supervision",
        "controls":    BOG_CONTROLS,
        "colour":      "#008080",
    },
    "nca": {
        "name":        "NCA — Cybersecurity Guidelines for Electronic Communications",
        "short":       "NCA Guidelines",
        "applies_to":  "Telecoms, ISPs, electronic communications operators licensed by NCA",
        "controls":    NCA_CONTROLS,
        "colour":      "#1565C0",
    },
    "dpc": {
        "name":        "Ghana Data Protection Act 2012 (Act 843)",
        "short":       "DPC / Act 843",
        "applies_to":  "All organisations processing personal data of Ghanaian citizens",
        "controls":    DPC_CONTROLS,
        "colour":      "#6A1B9A",
    },
}


# ─── Finding → check key mapping ──────────────────────────────────────────────

def _extract_check_flags(findings: dict, scoring: dict) -> set:
    """
    Convert aggregated findings into a set of check flag strings
    that can be matched against control requirements.
    """
    flags = set()
    dns  = findings.get("dns_security", {})
    ssl  = findings.get("ssl_certificates", {})
    subs = findings.get("subdomains", {})
    cred = findings.get("credential_exposure", {})
    dw   = findings.get("dark_web", {})
    info = findings.get("infostealer_exposure", {})
    tech = findings.get("tech_fingerprint", {})

    # Email security
    spf = dns.get("spf", {})
    if not spf.get("present"):
        flags.add("spf_missing")
    elif spf.get("strength") == "weak":
        flags.add("spf_weak")

    dmarc = dns.get("dmarc", {})
    if not dmarc.get("present"):
        flags.add("dmarc_missing")
    elif dmarc.get("policy") in ("none", "quarantine"):
        flags.add("dmarc_not_enforced")

    dkim = dns.get("dkim", {})
    if not dkim.get("present"):
        flags.add("dkim_missing")

    # TLS
    if ssl.get("weak_protocol"):
        flags.add("weak_tls")

    # Certificates
    if ssl.get("expired"):
        flags.add("expired_cert")
    if ssl.get("expiring_soon"):
        flags.add("expiring_cert")

    # Attack surface
    sub_count = subs.get("count", 0)
    if sub_count > 20:
        flags.add("large_subdomain_footprint")

    # Exposed services
    for f in scoring.get("findings", []):
        title = f.get("finding", "").lower()
        if "ftp" in title:
            flags.add("ftp_exposed")
        if "webmail" in title or "self-hosted mail" in title:
            flags.add("webmail_exposed")
        if "cpanel" in title or "admin" in title:
            flags.add("admin_portal_exposed")
        if "cpanel" in title:
            flags.add("cpanel_exposed")

    # Credential exposure
    if cred.get("total_breached", 0) > 0:
        flags.add("breached_credentials")

    # Dark web
    if dw.get("total_mentions", 0) > 0:
        flags.add("dark_web_mentions")

    # Infostealer
    if info.get("total_employees", 0) > 0 or info.get("total_users", 0) > 0:
        flags.add("infostealer_exposure")

    # Vulnerable tech
    if tech.get("high_risk_tech"):
        flags.add("vulnerable_tech")

    return flags


# ─── Core mapper ───────────────────────────────────────────────────────────────

def map_compliance(findings: dict, scoring: dict) -> dict:
    """
    Map scan findings to regulatory compliance frameworks.

    Args:
        findings: Aggregated findings dict from aggregator.py
        scoring:  Risk scoring dict from risk_scorer.py

    Returns:
        dict with per-framework compliance scores and control gaps
    """
    flags   = _extract_check_flags(findings, scoring)
    results = {}

    for fw_key, framework in FRAMEWORKS.items():
        controls    = framework["controls"]
        passed      = []
        failed      = []
        gap_details = []

        for control in controls:
            # Control fails if ANY of its check flags are present
            triggered = [c for c in control["checks"] if c in flags]

            if triggered:
                failed.append(control["id"])
                gap_details.append({
                    "id":          control["id"],
                    "section":     control["section"],
                    "requirement": control["requirement"],
                    "severity":    control["severity"],
                    "remediation": control["remediation"],
                    "triggered_by": triggered,
                })
            else:
                passed.append(control["id"])

        total   = len(controls)
        passing = len(passed)
        score   = round((passing / total) * 100) if total > 0 else 100

        if score >= 80:
            status = "compliant"
            colour = "#388E3C"
        elif score >= 60:
            status = "partial"
            colour = "#F57C00"
        else:
            status = "non_compliant"
            colour = "#D32F2F"

        results[fw_key] = {
            "name":         framework["name"],
            "short":        framework["short"],
            "applies_to":   framework["applies_to"],
            "score":        score,
            "status":       status,
            "colour":       colour,
            "passed":       len(passed),
            "failed":       len(failed),
            "total":        total,
            "gaps":         gap_details,
            "brand_colour": framework["colour"],
        }

        log.info(
            f"[Compliance] {framework['short']} — "
            f"{score}% ({passing}/{total} controls passing) — {status}"
        )

    return results