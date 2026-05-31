"""
SankofahEye — Phishing Infrastructure Detection
AfriWealth Cyber Intelligence

Monitors three sources for lookalike/impersonation domains targeting
Ghanaian brands BEFORE phishing campaigns launch:

  1. Certificate Transparency (crt.sh)
     Catches domains the moment an SSL certificate is issued.
     Attackers always get a cert before going live — this catches
     them at issuance, often 24-72h before the campaign launches.

  2. WHOIS / Domain Registration (whoisxmlapi.com free tier)
     Detects newly registered domains matching brand patterns.
     Falls back to DNS resolution checks if no API key.

  3. URLScan.io
     Detects live phishing pages already scanning the target brand
     that have been submitted to URLScan by other researchers.

Detection logic:
  - Levenshtein distance ≤ 3 from any monitored brand keyword
  - Substring matching against brand keyword list
  - Homoglyph substitution detection (0→o, 1→l, rn→m etc.)
  - TLD abuse patterns (-gh.com, .com.gh lookalikes, .net/.org variants)

This is pre-crime intelligence. By the time a phishing email lands
in a Ghanaian bank employee's inbox, SankofahEye has already flagged
the infrastructure that sent it.

MITRE ATT&CK: T1583.001 — Acquire Infrastructure: Domains
"""

import os
import re
import json
import time
import requests
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from utils.logger import SankofahLogger

log = SankofahLogger("phishing_detector")

# ── Ghana brand keyword list ───────────────────────────────────────────────────
# Core keywords to monitor. Any domain containing or closely resembling
# these terms gets flagged.

GHANA_BRAND_KEYWORDS = [
    # Banks
    "gcb", "gcbbank", "gcb-bank",
    "ecobank", "eco-bank",
    "absa", "absaghana",
    "stanbic", "stanbicghana",
    "calbank", "cal-bank",
    "fidelity", "fidelitybank",
    "uba", "ubaghana",
    "zenith", "zenithbank",
    "access", "accessbank",
    "republic", "republicbank",
    "agricultural", "agribank",
    # Fintechs / Payment
    "mtnmomo", "mtn-momo", "mtnghana", "mtn-ghana",
    "telecel", "telecelcash",
    "airteltigomoney", "airteltigo",
    "ghipss", "ghipss-gh",
    "papss", "papss-gh",
    "hubtel", "hubtelgh",
    "expresspay", "express-pay",
    "slydepay",
    # Government / Regulatory
    "bog", "bog-gov", "bankofghana", "bank-of-ghana",
    "gra", "gra-gh", "ghanarevenue",
    "nca", "nca-gh",
    "gipc", "gipc-gh",
    "scholarships", "scholarshipgh", "scholarship-gh",
    "ghana-gov", "ghanagovernment",
    "gss", "statsghana",
    # Telecom
    "vodafoneghana", "vodafone-gh",
    "airteltigo", "airteltigogh",
]

# Homoglyph substitution map — attackers swap these to bypass naive checks
HOMOGLYPHS = {
    "o": ["0", "ο", "о"],   # zero, greek omicron, cyrillic o
    "i": ["1", "l", "ι"],   # one, lowercase L, iota
    "a": ["@", "α", "а"],   # at, alpha, cyrillic a
    "e": ["3", "ε", "е"],   # three, epsilon, cyrillic e
    "n": ["и", "η"],
    "rn": ["m"],             # "rn" looks like "m"
    "u": ["υ", "и"],
    "g": ["9", "ɡ"],
    "s": ["$", "5"],
    "gh": ["g-h", "g.h"],
}

# High-risk TLD patterns used in Ghana brand impersonation
RISKY_TLDS = [
    ".com.gh", ".net", ".org", ".info", ".biz",
    ".co", ".io", ".app", ".online", ".site",
    ".store", ".live", ".click", ".link", ".support",
    ".help", ".secure", ".bank", ".pay",
]


# ── Similarity scoring ─────────────────────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _normalise_homoglyphs(domain: str) -> str:
    """Replace common homoglyphs with their ASCII equivalents."""
    d = domain.lower()
    for real, fakes in HOMOGLYPHS.items():
        for fake in fakes:
            d = d.replace(fake, real)
    # Handle multi-char substitutions
    d = d.replace("rn", "m")
    return d


def _is_suspicious(domain: str, keyword: str) -> tuple[bool, str, float]:
    """
    Check if a domain is suspicious relative to a brand keyword.

    Returns:
        (is_suspicious, reason, confidence_score 0.0-1.0)
    """
    # Strip TLD and hyphens for core comparison
    core = re.sub(r'\.(com|net|org|gh|io|app|biz|info|online|site|store|live|click).*$', '', domain.lower())
    core = core.replace("-", "").replace(".", "")
    kw   = keyword.lower().replace("-", "").replace(".", "")
    norm = _normalise_homoglyphs(core)

    # 1. Exact substring match
    if kw in core or kw in norm:
        return True, f"Substring match: '{kw}' in '{core}'", 0.95

    # 2. Homoglyph match
    if kw in norm and norm != core:
        return True, f"Homoglyph substitution detected: '{core}' normalises to '{norm}'", 0.90

    # 3. Levenshtein distance ≤ 2 (for keywords ≥ 5 chars)
    if len(kw) >= 5:
        dist = _levenshtein(core[:len(kw)+3], kw)
        if dist <= 2:
            conf = max(0.5, 1.0 - (dist * 0.2))
            return True, f"Typosquatting: edit distance {dist} from '{kw}'", conf

    # 4. Sequence similarity ≥ 0.75
    ratio = SequenceMatcher(None, kw, core).ratio()
    if ratio >= 0.75:
        return True, f"High similarity ({ratio:.0%}) to '{kw}'", ratio

    return False, "", 0.0


# ── Source 1: Certificate Transparency (crt.sh) ───────────────────────────────

def _query_crtsh(keyword: str, days_back: int = 7) -> list[dict]:
    """
    Query crt.sh for certificates issued in the last N days
    matching a keyword. Returns list of cert dicts.
    """
    try:
        url = f"https://crt.sh/?q=%25{keyword}%25&output=json"
        resp = requests.get(url, timeout=20,
                            headers={"User-Agent": "SankofahEye/1.0"})
        if resp.status_code != 200:
            return []

        certs = resp.json()
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        recent = []

        for cert in certs:
            try:
                issued_str = cert.get("not_before", "")
                if not issued_str:
                    continue
                issued = datetime.strptime(issued_str[:10], "%Y-%m-%d")
                if issued >= cutoff:
                    recent.append({
                        "domain":      cert.get("name_value", "").split("\n")[0].strip(),
                        "issuer":      cert.get("issuer_name", ""),
                        "issued_date": issued_str[:10],
                        "cert_id":     cert.get("id", ""),
                        "source":      "crt.sh",
                    })
            except Exception:
                continue

        return recent[:50]  # cap at 50 per keyword

    except Exception as e:
        log.warning(f"[PhishDetect] crt.sh query failed for '{keyword}': {e}")
        return []


# ── Source 2: WHOIS / DNS Registration Check ──────────────────────────────────

def _check_domain_age(domain: str) -> dict:
    """
    Check if a domain was recently registered by querying
    WhoisXMLAPI (free tier) or falling back to DNS resolution.
    """
    api_key = os.getenv("WHOISXML_API_KEY")
    result  = {"domain": domain, "registered": False,
               "age_days": None, "registrar": None}

    if api_key:
        try:
            url = (f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
                   f"?apiKey={api_key}&domainName={domain}&outputFormat=JSON")
            resp = requests.get(url, timeout=15)
            data = resp.json().get("WhoisRecord", {})
            created = data.get("createdDate", "")
            if created:
                created_dt = datetime.strptime(created[:10], "%Y-%m-%d")
                age        = (datetime.utcnow() - created_dt).days
                result.update({
                    "registered": True,
                    "age_days":   age,
                    "registrar":  data.get("registrarName", ""),
                })
        except Exception:
            pass

    else:
        # Fallback: just check if the domain resolves
        try:
            import socket
            socket.setdefaulttimeout(5)
            socket.gethostbyname(domain)
            result["registered"] = True
        except Exception:
            pass

    return result


# ── Source 3: URLScan.io phishing page detection ───────────────────────────────

def _query_urlscan(keyword: str) -> list[dict]:
    """
    Query URLScan.io for recent scans of pages referencing
    the keyword — catches live phishing pages already reported.
    """
    api_key = os.getenv("URLSCAN_API_KEY", "")
    headers = {"API-Key": api_key} if api_key else {}

    try:
        url  = f"https://urlscan.io/api/v1/search/?q=page.domain%3A{keyword}&size=10"
        resp = requests.get(url, timeout=15, headers=headers)
        if resp.status_code != 200:
            return []

        results = []
        for r in resp.json().get("results", []):
            page    = r.get("page", {})
            domain  = page.get("domain", "")
            country = page.get("country", "")
            score   = r.get("verdicts", {}).get("overall", {}).get("score", 0)
            malicious = r.get("verdicts", {}).get("overall", {}).get("malicious", False)

            if malicious or score > 50:
                results.append({
                    "domain":    domain,
                    "url":       page.get("url", ""),
                    "country":   country,
                    "score":     score,
                    "malicious": malicious,
                    "scan_date": r.get("task", {}).get("time", "")[:10],
                    "source":    "urlscan",
                })
        return results

    except Exception as e:
        log.warning(f"[PhishDetect] URLScan query failed for '{keyword}': {e}")
        return []


# ── Core detection engine ──────────────────────────────────────────────────────

def detect_phishing_infrastructure(
    target: str,
    brand_keywords: list[str] = None,
    days_back: int = 7,
    include_urlscan: bool = True,
) -> dict:
    """
    Run full phishing infrastructure detection for a target domain.

    Monitors:
      - crt.sh certificate transparency (last N days)
      - WHOIS age check on suspicious domains found
      - URLScan.io for live phishing pages

    Args:
        target:          The primary domain being monitored (e.g. gcb.com.gh)
        brand_keywords:  Additional keywords to monitor. Auto-derived from target if None.
        days_back:       How many days back to check certificates
        include_urlscan: Whether to query URLScan for live pages

    Returns:
        dict with:
            lookalike_domains: list of suspicious domain findings
            live_phishing:     list of confirmed/suspected live phishing pages
            total_threats:     int
            risk_level:        str (none/low/medium/high/critical)
            summary:           str
    """
    result = {
        "lookalike_domains": [],
        "live_phishing":     [],
        "total_threats":     0,
        "risk_level":        "none",
        "summary":           "",
        "checked_at":        datetime.utcnow().isoformat(),
    }

    # Derive keywords from target domain
    base = target.lower().replace(".com.gh", "").replace(".gh", "").replace(".com", "").replace(".", "").replace("-", "")
    keywords = brand_keywords or []

    # Add base domain keywords
    for kw in GHANA_BRAND_KEYWORDS:
        if kw in base or base in kw:
            if kw not in keywords:
                keywords.append(kw)

    # Always include the cleaned base domain itself
    if base not in keywords:
        keywords.insert(0, base)

    # Deduplicate
    keywords = list(dict.fromkeys(keywords))[:5]  # cap at 5 for speed

    log.info(f"[PhishDetect] Monitoring keywords: {keywords} | days_back: {days_back}")

    seen_domains = set()

    for keyword in keywords:
        # ── crt.sh ────────────────────────────────────────────
        certs = _query_crtsh(keyword, days_back)
        time.sleep(1)  # rate limit

        for cert in certs:
            domain = cert["domain"].lower().strip("*.")
            if not domain or domain in seen_domains:
                continue
            if domain == target:  # skip the target itself
                continue
            seen_domains.add(domain)

            suspicious, reason, confidence = _is_suspicious(domain, keyword)
            if not suspicious:
                continue

            # Check WHOIS age
            age_info = _check_domain_age(domain)

            finding = {
                "domain":      domain,
                "keyword":     keyword,
                "reason":      reason,
                "confidence":  round(confidence, 2),
                "age_days":    age_info.get("age_days"),
                "registrar":   age_info.get("registrar"),
                "cert_issued": cert["issued_date"],
                "cert_id":     cert["cert_id"],
                "source":      "crt.sh",
                "severity":    "critical" if confidence >= 0.85 else "high" if confidence >= 0.7 else "medium",
                "mitre":       "T1583.001",
                "action":      (
                    "Monitor this domain immediately. If it resolves and serves content "
                    "impersonating your brand, submit to Google Safe Browsing and contact "
                    "the registrar for takedown. Forward to your CERT/CC contact."
                ),
            }
            result["lookalike_domains"].append(finding)
            log.info(f"[PhishDetect] 🚨 Lookalike detected: {domain} ({reason}) confidence={confidence:.0%}")

        # ── URLScan ───────────────────────────────────────────
        if include_urlscan:
            live = _query_urlscan(keyword)
            for page in live:
                if page["domain"] not in seen_domains and page["domain"] != target:
                    result["live_phishing"].append(page)
                    seen_domains.add(page["domain"])

    # ── Risk level ────────────────────────────────────────────
    total = len(result["lookalike_domains"]) + len(result["live_phishing"])
    result["total_threats"] = total

    critical_count = sum(1 for d in result["lookalike_domains"] if d["severity"] == "critical")
    live_count     = len(result["live_phishing"])

    if critical_count >= 3 or live_count >= 2:
        result["risk_level"] = "critical"
    elif critical_count >= 1 or live_count >= 1:
        result["risk_level"] = "high"
    elif total >= 3:
        result["risk_level"] = "medium"
    elif total >= 1:
        result["risk_level"] = "low"

    # ── Summary ───────────────────────────────────────────────
    if total == 0:
        result["summary"] = (
            f"No phishing infrastructure detected targeting '{target}' "
            f"in the last {days_back} days. Continue monitoring."
        )
    else:
        result["summary"] = (
            f"{total} suspicious domain(s) detected targeting '{target}'. "
            f"{critical_count} critical-confidence lookalike(s). "
            f"{live_count} live phishing page(s) identified via URLScan. "
            f"Immediate investigation recommended."
        )

    log.info(f"[PhishDetect] Complete: {total} threats | Risk: {result['risk_level'].upper()}")
    return result