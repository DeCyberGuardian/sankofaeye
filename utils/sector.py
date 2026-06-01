"""
SankofaEye — Sector Taxonomy & Detection
AfriWealth Cyber Intelligence

Single source of truth for sector classification. Every sector-aware
behaviour — which compliance frameworks apply, how findings are framed,
which report sections show — reads from here so the logic lives in one
place instead of being scattered across modules.

Usage:
    from utils.sector import detect_sector, get_sector_profile, SECTORS

    key = detect_sector("ghipss.com")            # -> "financial"
    profile = get_sector_profile(key)            # -> full dict
    profile["frameworks"]                        # -> ["bog", "dpc"]
    profile["is_regulated"]                      # -> True
"""

import re

# ── Sector definitions ────────────────────────────────────────────
# Each sector declares:
#   label        human-readable name (scan form + reports)
#   is_regulated regulated entity (banking/telecom/gov/health/edu) vs not
#   frameworks   compliance frameworks that legitimately apply
#                (keys: "bog", "nca", "dpc")  — DPC applies to ALL
#   framing      "public" | "commercial" — drives narrative language
#   sections     report sections to emphasise for this sector
SECTORS = {
    "government": {
        "label": "Government / Public Sector",
        "is_regulated": True,
        "frameworks": ["dpc"],          # + public-sector security guidance
        "framing": "public",
        "sections": ["compliance", "wa_intel", "attack_path", "persona"],
    },
    "financial": {
        "label": "Financial / Fintech",
        "is_regulated": True,
        "frameworks": ["bog", "dpc"],
        "framing": "public",
        "sections": ["compliance", "wa_intel", "momo", "supplier",
                     "attack_path", "persona"],
    },
    "telecom": {
        "label": "Telecom / ISP",
        "is_regulated": True,
        "frameworks": ["nca", "dpc"],
        "framing": "public",
        "sections": ["compliance", "wa_intel", "attack_path", "persona"],
    },
    "healthcare": {
        "label": "Healthcare",
        "is_regulated": True,
        "frameworks": ["dpc"],          # heightened — sensitive personal data
        "framing": "public",
        "sections": ["compliance", "wa_intel", "attack_path", "persona"],
    },
    "education": {
        "label": "Education",
        "is_regulated": True,
        "frameworks": ["dpc"],
        "framing": "public",
        "sections": ["compliance", "wa_intel", "attack_path", "persona"],
    },
    "commercial": {
        "label": "Commercial / General",
        "is_regulated": False,
        "frameworks": ["dpc"],          # DPC Act 843 applies to everyone
        "framing": "commercial",
        "sections": ["brand_protection", "compliance", "attack_path",
                     "persona"],
    },
}

DEFAULT_SECTOR = "commercial"

# ── Detection heuristics ──────────────────────────────────────────
# Ordered most-specific first. TLD signals are strongest; keyword
# signals are a softer hint. A miss falls through to DEFAULT_SECTOR,
# which the user can override on the scan form.

_TLD_RULES = [
    (r"\.gov\.gh$",  "government"),
    (r"\.gov$",      "government"),
    (r"\.mil\.gh$",  "government"),
    (r"\.edu\.gh$",  "education"),
    (r"\.edu$",      "education"),
    (r"\.ac\.gh$",   "education"),
    (r"\.sch\.gh$",  "education"),
]

_KEYWORD_RULES = [
    ("financial", [
        "bank", " banc", "fintech", "pay", "momo", "mobilemoney",
        "wallet", "cedi", "loan", "credit", "savings", "insurance",
        "capital", "invest", "finance", "ghipss", "ecobank", "fidelity",
        "absa", "stanbic", "cal", "gtbank", "zenith", "access",
    ]),
    ("telecom", [
        "telecom", "telco", "mtn", "vodafone", "telecel", "airteltigo",
        "isp", "network", "fibre", "fiber", "broadband", "comms",
    ]),
    ("healthcare", [
        "hospital", "clinic", "health", "medic", "pharma", "care",
        "dental", "diagnostic", "lab",
    ]),
    ("education", [
        "school", "college", "university", "academy", "institute",
        "education", "campus", "training",
    ]),
    ("government", [
        "ministry", "authority", "commission", "agency", "council",
        "assembly", "municipal", "district", "parliament", "service.gov",
    ]),
]


def detect_sector(domain: str) -> str:
    """
    Best-effort sector guess from a domain. Returns a sector key.

    Detection is intentionally conservative: a confident TLD match wins,
    otherwise keyword hints, otherwise the commercial default. The result
    is a *suggestion* — the scan form lets the user override it.
    """
    if not domain:
        return DEFAULT_SECTOR
    d = domain.strip().lower()

    # 1. TLD rules (strongest signal)
    for pattern, sector in _TLD_RULES:
        if re.search(pattern, d):
            return sector

    # 2. Keyword rules (softer; check the registrable label)
    label = d.split(".")[0]
    for sector, keywords in _KEYWORD_RULES:
        for kw in keywords:
            kw = kw.strip()
            if kw and (kw in label or kw in d):
                return sector

    # 3. Fallback
    return DEFAULT_SECTOR


def get_sector_profile(sector_key: str) -> dict:
    """Return the full profile dict for a sector key (safe fallback)."""
    profile = dict(SECTORS.get(sector_key, SECTORS[DEFAULT_SECTOR]))
    profile["key"] = sector_key if sector_key in SECTORS else DEFAULT_SECTOR
    return profile


def applies_framework(sector_key: str, framework: str) -> bool:
    """True if the given framework ('bog'|'nca'|'dpc') applies to the sector."""
    return framework in get_sector_profile(sector_key)["frameworks"]


def is_regulated(sector_key: str) -> bool:
    return get_sector_profile(sector_key)["is_regulated"]


def sector_choices():
    """[(key, label), ...] for rendering a scan-form dropdown."""
    return [(k, v["label"]) for k, v in SECTORS.items()]


# ── Commercial framing rewriter ───────────────────────────────────
# The risk_scorer attack-scenario text is written with public-sector /
# government framing ("citizens", "government domain", ".gov.gh"). For
# non-regulated commercial targets that language is inaccurate and hurts
# credibility. Rather than fork 15 scenario templates, we post-process the
# finding text with targeted, order-sensitive phrase substitutions.
#
# Only applied when framing == "commercial". Public-sector targets are
# left untouched.

# Order matters: longer / more-specific phrases first so they win before
# their shorter substrings are rewritten.
_COMMERCIAL_SUBS = [
    ("Ghana's banking and government context",
     "Ghana's commercial and customer-facing context"),
    ("a government or financial domain in Ghana",
     "a trusted brand domain in Ghana"),
    ("In Ghana's public sector, BEC attacks",
     "In the West African commercial sector, BEC attacks"),
    ("In Ghana's public sector context", "In the commercial context"),
    ("In the Ghanaian public sector context", "In the commercial context"),
    ("African government institutions", "West African businesses"),
    ("compromised government subdomains", "compromised brand subdomains"),
    ("a compromised government email account",
     "a compromised corporate email account"),
    ("A compromised government email account",
     "A compromised corporate email account"),
    ("government credentials", "corporate credentials"),
    ("leaked government", "leaked corporate"),
    ("government infrastructure", "corporate infrastructure"),
    ("government records", "business records"),
    ("government communications", "business communications"),
    ("BEC groups targeting .gov.gh domains", "BEC groups targeting commercial brands"),
    ("initial access brokers selling .gov.gh access",
     "initial access brokers selling corporate network access"),
    ("targeting citizens applying for services",
     "targeting the brand's customers"),
    ("fraudulent communications to citizens",
     "fraudulent communications to customers"),
    ("fraudulent citizen communications",
     "fraudulent customer communications"),
    ("citizen data", "customer data"),
    ("citizen trust", "customer trust"),
    ("against Ghanaian citizens", "against the brand's customers"),
    ("staff, citizens, and partners", "staff, customers, and partners"),
    ("citizens, partner agencies, and financial institutions",
     "customers, partners, and financial institutions"),
    ("public sector attacks", "commercial-sector attacks"),
    # Catch-all singulars last (after the multi-word phrases above).
    ("government domain", "brand domain"),
    ("a government", "a commercial"),
    (" citizens", " customers"),
    (" citizen ", " customer "),
]


def _reframe_text(text: str) -> str:
    if not text:
        return text
    for old, new in _COMMERCIAL_SUBS:
        text = text.replace(old, new)
    return text


def apply_sector_framing(scoring: dict, sector_key: str) -> dict:
    """
    Rewrite finding narrative text to match the sector's framing.

    For non-regulated (commercial) sectors, replaces public-sector/government
    phrasing with commercial/customer phrasing across each finding's
    detail, recommendation, scenario, impact, likelihood and threat_actors.

    Public-sector targets are returned unchanged. Mutates and returns scoring.
    """
    if not scoring:
        return scoring
    profile = get_sector_profile(sector_key)
    if profile.get("framing") != "commercial":
        return scoring

    for f in scoring.get("findings", []):
        for field in ("detail", "recommendation", "impact", "scenario",
                      "likelihood", "threat_actors"):
            if field in f and isinstance(f[field], str):
                f[field] = _reframe_text(f[field])
        # Some scorers nest scenario text under an "attack_scenario" dict.
        sc = f.get("attack_scenario")
        if isinstance(sc, dict):
            for k, v in sc.items():
                if isinstance(v, str):
                    sc[k] = _reframe_text(v)
    return scoring


def filter_compliance(compliance: dict, sector_key: str) -> dict:
    """
    Drop compliance frameworks that don't apply to the sector.

    Keeps only frameworks in the sector profile (e.g. commercial keeps DPC
    only; financial keeps BoG + DPC). Mutates-safe: returns a new dict.
    """
    if not compliance:
        return compliance
    allowed = set(get_sector_profile(sector_key)["frameworks"])
    return {k: v for k, v in compliance.items() if k in allowed}