"""
SankofaEye — Dark Web Persona Monitoring (Phase 5F)
AfriWealth Cyber Intelligence

Targeted monitoring of named executives and brand terms across the
dark web and fraud forums, via the Ahmia clearnet search gateway.

Unlike the broad `darkweb_module` (which searches the target domain),
this module hunts for *people* and *brand identity* being discussed in
adversarial contexts — the leading indicator of:
  - CEO-fraud / BEC impersonation campaign staging
  - brand abuse and counterfeit-service fraud
  - insider-recruitment threads naming the organisation

Reads the `personas:` block from config.yaml.

Returns the `persona_monitoring` key for the findings dict:
  {
    "hits": [
        {"subject": str, "type": "executive|brand",
         "source": str, "url": str, "snippet": str,
         "query": str, "severity": "critical|high"},
        ...
    ],
    "executives_found": [str, ...],   # distinct exec names with ≥1 hit
    "brand_hits": [str, ...],         # distinct brand terms with ≥1 hit
    "total": int,
    "status": "ok|skipped|error",
}
"""

import os
import time
import requests
from urllib.parse import quote_plus

from utils.logger import SankofaLogger

log = SankofaLogger("persona_monitor")

AHMIA_SEARCH = "https://ahmia.fi/search/?q={}"

# Fraud/financial keywords that elevate a persona mention to a real signal.
_FRAUD_KEYWORDS = [
    "fraud", "scam", "bec", "wire transfer", "invoice",
    "mobile money", "momo", "account takeover", "phishing",
    "credentials", "leak", "insider",
]

_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; SankofaEye/1.0; "
        "+https://afriwealthci.com)"
    )
}


def _ahmia_query(query: str, timeout: int = 45) -> list:
    """
    Run a single Ahmia search. Returns a list of result dicts:
    {"title", "url", "snippet"}. Failures degrade to [] (passive, best-effort).
    """
    try:
        resp = requests.get(
            AHMIA_SEARCH.format(quote_plus(query)),
            headers=_DEFAULT_HEADERS,
            timeout=timeout,
        )
        if resp.status_code != 200:
            log.warning(f"[Persona] Ahmia returned {resp.status_code} for '{query}'")
            return []
        return _parse_ahmia(resp.text)
    except requests.RequestException as e:
        log.warning(f"[Persona] Ahmia request failed for '{query}': {e}")
        return []


def _parse_ahmia(html: str) -> list:
    """
    Lightweight extraction of Ahmia result blocks. Ahmia wraps each result
    in <li class="result">…<a href="...">title</a>…<p>snippet</p>. We parse
    with BeautifulSoup if available, else fall back to a tolerant regex.
    """
    results = []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for li in soup.select("li.result"):
            a = li.find("a")
            p = li.find("p")
            title = a.get_text(strip=True) if a else ""
            url   = a.get("href", "") if a else ""
            snippet = p.get_text(strip=True) if p else ""
            if title or snippet:
                results.append({"title": title, "url": url, "snippet": snippet})
    except ImportError:
        import re
        for m in re.finditer(
            r'<li class="result".*?<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>'
            r'.*?<p>(.*?)</p>', html, re.DOTALL):
            url, title, snippet = m.groups()
            clean = lambda s: re.sub(r"<[^>]+>", "", s).strip()
            results.append({
                "title": clean(title), "url": url,
                "snippet": clean(snippet),
            })
    return results


def monitor_personas(config: dict, target: str = "") -> dict:
    """
    Run dark-web persona & brand monitoring from the config `personas:` block.

    Args:
        config: full SankofaEye config dict
        target: scan target domain (for logging/context only)

    Returns:
        persona_monitoring dict (see module docstring)
    """
    personas = (config or {}).get("personas", {}) or {}
    executives = personas.get("executives", []) or []
    brand_terms = personas.get("brand_terms", []) or []
    timeout = (config or {}).get("timeouts", {}).get("darkweb", 45)

    if not executives and not brand_terms:
        log.info("[Persona] No personas configured — skipping.")
        return {
            "hits": [], "executives_found": [], "brand_hits": [],
            "total": 0, "status": "skipped",
        }

    log.info(
        f"[Persona] Monitoring {len(executives)} executive(s) and "
        f"{len(brand_terms)} brand term(s)..."
    )

    hits = []
    execs_found = set()
    brand_found = set()
    fraud_clause = " OR ".join(_FRAUD_KEYWORDS[:6])

    try:
        # ── Executive monitoring ──────────────────────────────
        for exe in executives:
            name = exe.get("name", "").strip()
            if not name:
                continue
            # name + ghana + financial-fraud context
            query = f'"{name}" ghana ({fraud_clause})'
            for r in _ahmia_query(query, timeout=timeout):
                blob = f"{r.get('title','')} {r.get('snippet','')}".lower()
                if name.lower() in blob and any(k in blob for k in _FRAUD_KEYWORDS):
                    hits.append({
                        "subject": name,
                        "type": "executive",
                        "source": r.get("title", "")[:80],
                        "url": r.get("url", ""),
                        "snippet": r.get("snippet", "")[:200],
                        "query": query,
                        "severity": "critical",
                    })
                    execs_found.add(name)
            time.sleep(1)  # polite rate-limit between persona queries

        # ── Brand-term monitoring ─────────────────────────────
        for term in brand_terms:
            term = str(term).strip()
            if not term:
                continue
            query = f'"{term}" ({fraud_clause})'
            for r in _ahmia_query(query, timeout=timeout):
                blob = f"{r.get('title','')} {r.get('snippet','')}".lower()
                if term.lower() in blob:
                    hits.append({
                        "subject": term,
                        "type": "brand",
                        "source": r.get("title", "")[:80],
                        "url": r.get("url", ""),
                        "snippet": r.get("snippet", "")[:200],
                        "query": query,
                        "severity": "high",
                    })
                    brand_found.add(term)
            time.sleep(1)

        status = "ok"
    except Exception as e:
        log.error(f"[Persona] Monitoring error: {e}")
        status = "error"

    result = {
        "hits": hits,
        "executives_found": sorted(execs_found),
        "brand_hits": sorted(brand_found),
        "total": len(hits),
        "status": status,
    }

    if hits:
        log.warning(
            f"[Persona] 🎭 {len(hits)} hit(s) — "
            f"{len(execs_found)} exec, {len(brand_found)} brand"
        )
    else:
        log.info("[Persona] No persona/brand hits found.")

    return result