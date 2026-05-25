"""
SankofahEye — DNS Security Module
AfriWealth Cyber Intelligence

Passive DNS analysis — checks SPF, DMARC, DKIM, MX, NS records
and identifies email security misconfigurations.
No API keys required — pure DNS lookups only.
"""

import dns.resolver
import dns.exception
from utils.logger import SankofahLogger

log = SankofahLogger("dns")

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "mail", "email", "dkim",
    "selector1", "selector2", "k1", "s1", "s2",
    "mailjet", "sendgrid", "smtp", "mta",
]


def query_dns(domain: str, record_type: str) -> list:
    """Safe DNS query — returns list of record strings or empty list."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=10)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def check_spf(domain: str) -> dict:
    """Check SPF record existence and configuration."""
    result = {
        "record":   None,
        "present":  False,
        "valid":    False,
        "issues":   [],
        "strength": "none",
    }

    txt_records = query_dns(domain, "TXT")
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]

    if not spf_records:
        result["issues"].append("No SPF record found — domain can be used to spoof emails")
        return result

    if len(spf_records) > 1:
        result["issues"].append("Multiple SPF records found — only one is allowed, may cause delivery failures")

    spf = spf_records[0].strip('"')
    result["record"]  = spf
    result["present"] = True

    if spf.endswith("-all"):
        result["valid"]    = True
        result["strength"] = "strong"
    elif spf.endswith("~all"):
        result["valid"]    = True
        result["strength"] = "weak"
        result["issues"].append("SPF uses ~all (softfail) instead of -all (hardfail) — spoofed emails may still be delivered")
    elif spf.endswith("?all") or spf.endswith("+all"):
        result["valid"]    = False
        result["strength"] = "none"
        result["issues"].append("SPF uses ?all or +all — provides no protection, spoofing is permitted")
    else:
        result["valid"]    = True
        result["strength"] = "unknown"

    if "+all" in spf:
        result["issues"].append("CRITICAL: SPF contains +all — allows any server to send as this domain")

    return result


def check_dmarc(domain: str) -> dict:
    """Check DMARC record existence and policy strength."""
    result = {
        "record":  None,
        "present": False,
        "policy":  "none",
        "pct":     100,
        "rua":     None,
        "issues":  [],
    }

    records = query_dns(f"_dmarc.{domain}", "TXT")
    dmarc_records = [r for r in records if "v=dmarc1" in r.lower()]

    if not dmarc_records:
        result["issues"].append("No DMARC record found — phishing emails spoofing this domain will not be rejected")
        return result

    dmarc = dmarc_records[0].strip('"')
    result["record"]  = dmarc
    result["present"] = True

    # Parse policy
    for tag in dmarc.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("p="):
            result["policy"] = tag.split("=")[1].strip().lower()
        elif tag.lower().startswith("pct="):
            try:
                result["pct"] = int(tag.split("=")[1].strip())
            except ValueError:
                pass
        elif tag.lower().startswith("rua="):
            result["rua"] = tag.split("=")[1].strip()

    if result["policy"] == "none":
        result["issues"].append("DMARC policy is 'none' — monitoring only, no enforcement. Spoofed emails are not blocked.")
    elif result["policy"] == "quarantine":
        result["issues"].append("DMARC policy is 'quarantine' — spoofed emails go to spam but are not rejected outright.")
    elif result["policy"] == "reject":
        pass  # Best practice — no issue

    if result["pct"] < 100 and result["policy"] != "none":
        result["issues"].append(f"DMARC pct={result['pct']}% — policy only applies to {result['pct']}% of emails, remainder unprotected.")

    if not result["rua"]:
        result["issues"].append("No DMARC reporting address (rua) configured — blind to spoofing attempts.")

    return result


def check_dkim(domain: str) -> dict:
    """Probe common DKIM selectors."""
    result = {
        "found_selectors": [],
        "present":         False,
        "issues":          [],
    }

    for selector in DKIM_SELECTORS:
        records = query_dns(f"{selector}._domainkey.{domain}", "TXT")
        if records:
            for r in records:
                if "v=dkim1" in r.lower() or "p=" in r.lower():
                    result["found_selectors"].append({
                        "selector": selector,
                        "record":   r[:120],
                    })
                    result["present"] = True
                    break

    if not result["present"]:
        result["issues"].append("No DKIM records found on common selectors — emails lack cryptographic signing.")

    return result


def check_mx(domain: str) -> dict:
    """Check MX records and mail provider."""
    result = {
        "records":      [],
        "provider":     "unknown",
        "self_hosted":  False,
        "issues":       [],
    }

    mx_records = query_dns(domain, "MX")
    if not mx_records:
        result["issues"].append("No MX records found — domain may not receive email.")
        return result

    result["records"] = mx_records

    # Detect provider
    mx_str = " ".join(mx_records).lower()
    if "google" in mx_str or "googlemail" in mx_str or "aspmx" in mx_str:
        result["provider"] = "Google Workspace"
    elif "outlook" in mx_str or "protection.outlook" in mx_str or "mail.protection" in mx_str:
        result["provider"] = "Microsoft 365"
    elif "mimecast" in mx_str:
        result["provider"] = "Mimecast"
    elif "proofpoint" in mx_str:
        result["provider"] = "Proofpoint"
    elif "mailgun" in mx_str:
        result["provider"] = "Mailgun"
    elif "sendgrid" in mx_str:
        result["provider"] = "SendGrid"
    elif "amazonses" in mx_str or "amazonaws" in mx_str:
        result["provider"] = "Amazon SES"
    else:
        result["provider"]    = "Self-hosted / Unknown"
        result["self_hosted"] = True
        result["issues"].append(
            "MX records point to a self-hosted or unknown mail server — "
            "self-hosted servers require careful security hardening."
        )

    return result


def check_ns(domain: str) -> dict:
    """Check nameservers and identify DNS provider."""
    result = {
        "records":  [],
        "provider": "unknown",
        "issues":   [],
    }

    ns_records = query_dns(domain, "NS")
    if not ns_records:
        result["issues"].append("No NS records resolved — DNS may be misconfigured.")
        return result

    result["records"] = ns_records
    ns_str = " ".join(ns_records).lower()

    if "cloudflare" in ns_str:
        result["provider"] = "Cloudflare"
    elif "amazonaws" in ns_str or "awsdns" in ns_str:
        result["provider"] = "AWS Route53"
    elif "azure" in ns_str or "microsoftdns" in ns_str:
        result["provider"] = "Azure DNS"
    elif "google" in ns_str:
        result["provider"] = "Google Cloud DNS"
    elif "godaddy" in ns_str:
        result["provider"] = "GoDaddy"
    else:
        result["provider"] = "Custom / ISP"

    return result


def run(domain: str, timeout: int = 30) -> dict:
    """
    Run full passive DNS security assessment.
    Returns structured findings for SPF, DMARC, DKIM, MX, NS.
    """
    result = {
        "module":  "dns",
        "target":  domain,
        "spf":     {},
        "dmarc":   {},
        "dkim":    {},
        "mx":      {},
        "ns":      {},
        "issues":  [],
        "status":  "ok",
        "error":   None,
    }

    log.info(f"[DNS] Running passive DNS security checks for {domain}...")

    try:
        result["spf"]   = check_spf(domain)
        result["dmarc"] = check_dmarc(domain)
        result["dkim"]  = check_dkim(domain)
        result["mx"]    = check_mx(domain)
        result["ns"]    = check_ns(domain)

        # Collect all issues into top-level list
        all_issues = (
            result["spf"]["issues"]   +
            result["dmarc"]["issues"] +
            result["dkim"]["issues"]  +
            result["mx"]["issues"]    +
            result["ns"]["issues"]
        )
        result["issues"] = all_issues

        log.info(
            f"[DNS] SPF: {result['spf'].get('strength','none')} | "
            f"DMARC policy: {result['dmarc'].get('policy','none')} | "
            f"DKIM selectors: {len(result['dkim'].get('found_selectors',[]))} | "
            f"MX provider: {result['mx'].get('provider','unknown')} | "
            f"Issues: {len(all_issues)}"
        )

    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)
        log.error(f"[DNS] {e}")

    return result