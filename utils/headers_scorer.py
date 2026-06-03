"""
SankofaEye — HTTP Security Headers Scorecard
AfriWealth Cyber Intelligence

Grades a domain's HTTP response security headers A–F, the way
securityheaders.com does — but by fetching the headers directly rather than
depending on that third-party site (no public API; scraping is brittle).

⚠️  NON-INTRUSIVE ACTIVE MODULE
Unlike the rest of SankofaEye (pure third-party OSINT), this module makes a
single HTTP GET to the target's own web server to read the headers it returns
to every visitor. This is an ordinary web request — the same thing any browser
or crawler does — but it WILL appear in the target's access logs. It performs
no authentication, sends no unusual payloads, and tests no vulnerabilities.
Reports label this module as "non-intrusive active" so the one direct request
is always disclosed. Controlled by `modules.security_headers` in config.

Returns a HeaderScorecard with the same attribute shape as the Email
Scorecard, so it drops into the same report/widget patterns.
"""

import ssl
import socket
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from utils.logger import SankofaLogger

log = SankofaLogger("headers_scorer")

# Header weightings (max points). Total = 100.
# Mirrors the relative emphasis securityheaders.com applies.
_HEADER_WEIGHTS = {
    "strict-transport-security": 25,   # HSTS — forces HTTPS
    "content-security-policy":   30,   # CSP — strongest XSS/injection control
    "x-frame-options":           15,   # clickjacking
    "x-content-type-options":    10,   # MIME sniffing
    "referrer-policy":           10,   # referrer leakage
    "permissions-policy":        10,   # feature/permissions control
}

# Friendly names + MITRE mapping + remediation for each header.
_HEADER_META = {
    "strict-transport-security": {
        "name": "HSTS (Strict-Transport-Security)",
        "severity": "medium",
        "mitre": {"id": "T1557", "name": "Adversary-in-the-Middle"},
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; "
                       "includeSubDomains' to force HTTPS and prevent SSL-strip "
                       "downgrade attacks.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "medium",
        "mitre": {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
        "remediation": "Define a Content-Security-Policy to restrict which "
                       "scripts/resources can load. Even a baseline policy "
                       "(default-src 'self') significantly reduces XSS impact.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "low",
        "mitre": {"id": "T1185", "name": "Browser Session Hijacking"},
        "remediation": "Add 'X-Frame-Options: SAMEORIGIN' (or a frame-ancestors "
                       "CSP directive) to prevent clickjacking via iframes.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "mitre": {"id": "T1036", "name": "Masquerading"},
        "remediation": "Add 'X-Content-Type-Options: nosniff' to stop browsers "
                       "MIME-sniffing responses away from the declared type.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "mitre": {"id": "T1592", "name": "Gather Victim Host Information"},
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' "
                       "to avoid leaking full URLs to third-party sites.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "mitre": {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
        "remediation": "Add a 'Permissions-Policy' header to disable unused "
                       "browser features (camera, microphone, geolocation, etc.).",
    },
}

_GRADE_BANDS = [
    (90, "A", "excellent", "#388E3C"),
    (75, "B", "good",      "#689F38"),
    (60, "C", "fair",      "#FBC02D"),
    (40, "D", "poor",      "#F57C00"),
    (0,  "F", "critical",  "#D32F2F"),
]


class HeaderScorecard:
    """Mirrors the Email Scorecard attribute shape for drop-in reuse."""
    def __init__(self):
        self.reachable   = False
        self.final_url   = ""
        self.score       = 0
        self.max_score   = 100
        self.grade       = "F"
        self.rating      = "critical"
        self.colour_hex  = "#D32F2F"
        self.present     = {}     # header -> bool
        self.missing     = []     # list of missing header keys
        self.findings    = []     # list of finding dicts for the pipeline
        self.note        = ""     # status / disclosure note


def _fetch_headers(domain: str, timeout: int = 15):
    """
    Single GET to the target over HTTPS (fallback HTTP). Returns
    (headers_dict_lowercased, final_url) or (None, "") if unreachable.

    NON-INTRUSIVE ACTIVE: this is the one direct request to the target.
    """
    headers_out = None
    final_url = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            req = Request(url, method="GET", headers={
                "User-Agent": "SankofaEye/1.0 (+https://afriwealthci.com; passive-assessment)"
            })
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # we only read headers, not trust content
            with urlopen(req, timeout=timeout, context=ctx) as resp:
                headers_out = {k.lower(): v for k, v in resp.headers.items()}
                final_url = resp.geturl()
                break
        except (HTTPError,) as e:
            # An HTTP error still carries response headers — grade them.
            try:
                headers_out = {k.lower(): v for k, v in e.headers.items()}
                final_url = url
                break
            except Exception:
                continue
        except (URLError, socket.timeout, ssl.SSLError, ConnectionError, Exception):
            continue
    return headers_out, final_url


def _grade(score: int):
    for threshold, grade, rating, colour in _GRADE_BANDS:
        if score >= threshold:
            return grade, rating, colour
    return "F", "critical", "#D32F2F"


def score_security_headers(domain: str, timeout: int = 15) -> HeaderScorecard:
    """
    Fetch and grade the target's HTTP security headers.

    Returns a HeaderScorecard. If the host is unreachable, returns a card
    with reachable=False and no penalising findings (absence of a web server
    is not a headers failure).
    """
    card = HeaderScorecard()
    log.info(f"[Headers] Non-intrusive active check (single GET) for {domain}")

    headers, final_url = _fetch_headers(domain, timeout=timeout)
    if headers is None:
        card.reachable = False
        card.note = ("Target did not return an HTTP response (no reachable web "
                     "server on https/http). No header grade assigned.")
        log.info(f"[Headers] {domain} unreachable — skipping grade")
        return card

    card.reachable = True
    card.final_url = final_url

    earned = 0
    for header, weight in _HEADER_WEIGHTS.items():
        present = header in headers
        card.present[header] = present
        if present:
            earned += weight
        else:
            card.missing.append(header)
            meta = _HEADER_META[header]
            card.findings.append({
                "finding": f"Missing HTTP security header: {meta['name']}",
                "severity": meta["severity"],
                "detail": f"The response from {final_url} does not set the "
                          f"{meta['name']} header.",
                "recommendation": meta["remediation"],
                "mitre": meta["mitre"],
                "source": "security_headers (non-intrusive active)",
            })

    card.score = earned
    card.grade, card.rating, card.colour_hex = _grade(earned)
    card.note = ("Non-intrusive active check: one direct HTTP GET was made to "
                 "the target to read response headers. No authentication, "
                 "payloads, or vulnerability tests were performed.")

    log.info(f"[Headers] {domain} graded {card.grade} ({card.score}/100); "
             f"{len(card.missing)} header(s) missing")
    return card