"""
SankofahEye — Dark Web Search Module
AfriWealth Cyber Intelligence

Passively searches dark web indexes for mentions of the target domain.
Sources: Ahmia.fi (indexed Tor search engine) + OnionSearch library.

IMPORTANT: This module queries indexed dark web search APIs only.
No direct Tor connections are made. All searches are passive.
"""

import os
import time
import requests
from utils.logger import SankofahLogger

log = SankofahLogger("darkweb")

AHMIA_BASE = "https://ahmia.fi/search/"

# Categories of dark web mentions that elevate risk
HIGH_RISK_KEYWORDS = [
    "database", "dump", "leak", "password", "credential", "breach",
    "access", "login", "shell", "backdoor", "ransomware", "sale",
    "exploit", "combo", "stealer", "logs",
]


def search_ahmia(domain: str, timeout: int = 45) -> list:
    """
    Query Ahmia.fi — a publicly accessible Tor search index.
    Returns a list of result entries.
    """
    results = []
    try:
        resp = requests.get(
            AHMIA_BASE,
            params={"q": domain},
            headers={"User-Agent": "SankofahEye-AfriWealthCI/1.0"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            log.warning(f"[DarkWeb/Ahmia] HTTP {resp.status_code}")
            return results

        # Parse plain-text search results (Ahmia returns HTML — basic parse)
        from html.parser import HTMLParser

        class AhmiaParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.results = []
                self._in_result = False
                self._current = {}

            def handle_starttag(self, tag, attrs):
                attrs_dict = dict(attrs)
                if tag == "h4":
                    self._in_result = True
                if tag == "a" and self._in_result:
                    self._current["url"] = attrs_dict.get("href", "")
                if tag == "p" and self._in_result:
                    self._in_snippet = True

            def handle_data(self, data):
                data = data.strip()
                if self._in_result and data:
                    if "title" not in self._current:
                        self._current["title"] = data
                    elif "snippet" not in self._current:
                        self._current["snippet"] = data

            def handle_endtag(self, tag):
                if tag == "h4":
                    self._in_result = False
                    if self._current:
                        self.results.append(self._current)
                        self._current = {}

        parser = AhmiaParser()
        parser.feed(resp.text)
        results = parser.results[:20]  # Cap at 20

    except requests.RequestException as e:
        log.error(f"[DarkWeb/Ahmia] {e}")

    return results


def classify_risk(results: list) -> list:
    """Tag each result with a risk level based on keyword presence."""
    classified = []
    for r in results:
        text = f"{r.get('title','')} {r.get('snippet','')}".lower()
        matched_keywords = [kw for kw in HIGH_RISK_KEYWORDS if kw in text]
        risk = "high" if matched_keywords else "informational"
        classified.append({
            **r,
            "risk": risk,
            "matched_keywords": matched_keywords,
        })
    return classified


def run(domain: str, timeout: int = 45) -> dict:
    result = {
        "module": "darkweb",
        "target": domain,
        "sources_queried": ["ahmia.fi"],
        "mentions": [],
        "high_risk_mentions": 0,
        "total_mentions": 0,
        "status": "ok",
        "error": None,
    }

    log.info(f"[DarkWeb] Searching indexed dark web sources for {domain}...")

    try:
        ahmia_results = search_ahmia(domain, timeout)
        classified = classify_risk(ahmia_results)

        result["mentions"] = classified
        result["total_mentions"] = len(classified)
        result["high_risk_mentions"] = sum(
            1 for r in classified if r.get("risk") == "high"
        )

        log.info(
            f"[DarkWeb] Total mentions: {result['total_mentions']} | "
            f"High-risk: {result['high_risk_mentions']}"
        )

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log.error(f"[DarkWeb] {e}")

    return result
