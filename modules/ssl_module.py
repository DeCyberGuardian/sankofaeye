"""
SankofahEye — SSL/TLS Certificate Module
AfriWealth Cyber Intelligence

Passively checks SSL/TLS certificate validity, expiry, and configuration
across the target domain and all discovered subdomains.
No API keys required — direct certificate inspection only.
"""

import ssl
import socket
import concurrent.futures
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend  # type: ignore
from utils.logger import SankofahLogger

log = SankofahLogger("ssl")

# Days before expiry to flag as warning vs critical
EXPIRY_CRITICAL_DAYS = 14
EXPIRY_WARNING_DAYS  = 30

# Weak protocols to flag
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def get_certificate(hostname: str, port: int = 443, timeout: int = 8) -> dict:
    """
    Retrieve and parse SSL/TLS certificate for a given hostname.
    Returns structured cert data or error info.
    """
    result = {
        "hostname":        hostname,
        "port":            port,
        "reachable":       False,
        "has_ssl":         False,
        "subject":         "",
        "issuer":          "",
        "issued_date":     "",
        "expiry_date":     "",
        "days_remaining":  None,
        "is_expired":      False,
        "is_self_signed":  False,
        "is_wildcard":     False,
        "san_domains":     [],
        "protocol":        "",
        "weak_protocol":   False,
        "issues":          [],
        "error":           None,
    }

    try:
        # First check if host is reachable on port 443
        sock = socket.create_connection((hostname, port), timeout=timeout)
        result["reachable"] = True

        # Wrap with SSL
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            result["has_ssl"]   = True
            result["protocol"]  = ssock.version() or ""

            # Check for weak protocol
            if any(w in result["protocol"] for w in WEAK_PROTOCOLS):
                result["weak_protocol"] = True
                result["issues"].append(
                    f"Weak protocol in use: {result['protocol']} — "
                    f"vulnerable to known downgrade attacks"
                )

            # Get raw cert bytes
            der_cert = ssock.getpeercert(binary_form=True)

        # Parse with cryptography library
        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Subject
        try:
            result["subject"] = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
        except Exception:
            result["subject"] = str(cert.subject)

        # Issuer
        try:
            result["issuer"] = cert.issuer.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
        except Exception:
            result["issuer"] = str(cert.issuer)

        # Dates
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") \
                     else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc") \
                     else cert.not_valid_after.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        result["issued_date"]    = not_before.strftime("%Y-%m-%d")
        result["expiry_date"]    = not_after.strftime("%Y-%m-%d")
        result["days_remaining"] = (not_after - now).days
        result["is_expired"]     = result["days_remaining"] < 0

        # Self-signed check
        result["is_self_signed"] = cert.issuer == cert.subject

        # Wildcard check
        result["is_wildcard"] = result["subject"].startswith("*.")

        # SAN domains
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            result["san_domains"] = [
                str(name.value)
                for name in san_ext.value
                if isinstance(name, x509.DNSName)
            ]
        except x509.ExtensionNotFound:
            result["san_domains"] = []

        # ── Flag issues ───────────────────────────────────────
        if result["is_expired"]:
            result["issues"].append(
                f"Certificate EXPIRED {abs(result['days_remaining'])} days ago "
                f"(expired: {result['expiry_date']}) — browsers show security warnings, "
                f"legitimate users cannot connect safely"
            )

        elif result["days_remaining"] <= EXPIRY_CRITICAL_DAYS:
            result["issues"].append(
                f"Certificate expires in {result['days_remaining']} days "
                f"({result['expiry_date']}) — CRITICAL: imminent service disruption"
            )

        elif result["days_remaining"] <= EXPIRY_WARNING_DAYS:
            result["issues"].append(
                f"Certificate expires in {result['days_remaining']} days "
                f"({result['expiry_date']}) — renew immediately to avoid disruption"
            )

        if result["is_self_signed"]:
            result["issues"].append(
                f"Self-signed certificate on {hostname} — "
                f"not trusted by browsers, indicates misconfiguration or test environment"
            )

    except socket.timeout:
        result["error"] = f"Connection timeout on {hostname}:443"
    except ConnectionRefusedError:
        result["error"] = f"Port 443 closed on {hostname}"
    except socket.gaierror:
        result["error"] = f"DNS resolution failed for {hostname}"
    except ssl.SSLError as e:
        result["has_ssl"] = True
        result["issues"].append(f"SSL error: {str(e)[:100]}")
        result["error"] = str(e)[:100]
    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def run(domain: str, subdomains: list = None, timeout: int = 30) -> dict:
    """
    Check SSL/TLS certificates for the target domain and all subdomains.
    Runs checks concurrently for speed.
    """
    result = {
        "module":           "ssl",
        "target":           domain,
        "certificates":     [],
        "expired":          [],
        "expiring_soon":    [],
        "self_signed":      [],
        "weak_protocol":    [],
        "unreachable_https": [],
        "total_checked":    0,
        "total_issues":     0,
        "status":           "ok",
        "error":            None,
    }

    # Build target list — domain + all subdomains
    targets = [domain]
    if subdomains:
        # Skip subdomains that are clearly not web-facing
        skip_prefixes = {
            "ns1", "ns2", "ns3", "ns4", "ns5",
            "mx", "mx1", "mx2", "mx01", "mx-pr",
            "smtp", "imap", "pop", "pop3",
            "autodiscover", "lyncdiscover",
            "sip", "voip", "ftp",
        }
        for sub in subdomains:
            prefix = sub.split(".")[0].lower()
            if prefix not in skip_prefixes:
                targets.append(sub)

    # Deduplicate
    targets = list(dict.fromkeys(targets))[:50]

    log.info(f"[SSL] Checking certificates for {len(targets)} host(s)...")

    # Run concurrently
    per_host_timeout = min(6, timeout // max(len(targets), 1) + 4)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(get_certificate, host, 443, per_host_timeout): host
            for host in targets
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                cert_data = future.result()
                result["certificates"].append(cert_data)

                if cert_data.get("is_expired"):
                    result["expired"].append(cert_data["hostname"])

                elif cert_data.get("days_remaining") is not None:
                    if cert_data["days_remaining"] <= EXPIRY_WARNING_DAYS:
                        result["expiring_soon"].append({
                            "hostname":       cert_data["hostname"],
                            "days_remaining": cert_data["days_remaining"],
                            "expiry_date":    cert_data["expiry_date"],
                        })

                if cert_data.get("is_self_signed"):
                    result["self_signed"].append(cert_data["hostname"])

                if cert_data.get("weak_protocol"):
                    result["weak_protocol"].append(cert_data["hostname"])

                if cert_data.get("reachable") and not cert_data.get("has_ssl"):
                    result["unreachable_https"].append(cert_data["hostname"])

            except Exception as e:
                log.error(f"[SSL] Error processing {futures[future]}: {e}")

    result["total_checked"] = len(result["certificates"])
    result["total_issues"]  = (
        len(result["expired"]) +
        len(result["expiring_soon"]) +
        len(result["self_signed"]) +
        len(result["weak_protocol"])
    )

    log.info(
        f"[SSL] Checked: {result['total_checked']} | "
        f"Expired: {len(result['expired'])} | "
        f"Expiring soon: {len(result['expiring_soon'])} | "
        f"Self-signed: {len(result['self_signed'])} | "
        f"Weak protocol: {len(result['weak_protocol'])}"
    )

    return result