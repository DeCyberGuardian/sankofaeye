"""
SankofaEye — West Africa Threat Intelligence Cross-Reference
AfriWealth Cyber Intelligence

Loads wa_threatdb.json and cross-references scan findings against:
  - Known threat actors likely to target this domain/sector
  - Historical incidents relevant to the target
  - Regional IOC patterns (lookalike domains, email patterns)

This is SankofaEye's competitive moat — no Western tool has this context.
Output is appended to the findings dict and rendered in both PDFs.
"""

import os
import json
from utils.logger import SankofaLogger

log = SankofaLogger("wa_threatdb")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "intel", "wa_threatdb.json")


def _load_db() -> dict:
    if not os.path.exists(DB_PATH):
        log.warning(f"[WA ThreatDB] Database not found at {DB_PATH}")
        return {}
    with open(DB_PATH, "r") as f:
        return json.load(f)


def _detect_sector(target: str, findings: dict) -> list:
    """
    Infer likely sector from domain TLD and subdomain patterns.
    Returns list of sector strings.
    """
    sectors = []
    t = target.lower()

    if any(x in t for x in ["bank", "gcb", "ecobank", "absa", "stanbic", "cal", "uba", "fidelity"]):
        sectors.append("Banking")
    if any(x in t for x in ["mtn", "telecel", "airtel", "tigo", "vodafone", "telco"]):
        sectors.append("Telecom")
        sectors.append("Mobile Money")
    if any(x in t for x in ["momo", "money", "pay", "fintech", "wallet"]):
        sectors.append("Mobile Money")
        sectors.append("Fintech")
    if ".gov.gh" in t or any(x in t for x in ["ghipss", "bog", "boa", "sec", "nca", "gipc"]):
        sectors.append("Government")
        sectors.append("Financial Infrastructure")
    if any(x in t for x in ["insurance", "sic", "enterprise"]):
        sectors.append("Insurance")
    if any(x in t for x in ["scholar", "edu", "university", "school", "college"]):
        sectors.append("Education")
        sectors.append("Government")

    # Check subdomain patterns for additional signals
    subs = [s.lower() for s in findings.get("subdomains", {}).get("list", [])]
    if any("swift" in s or "papss" in s or "eps" in s for s in subs):
        sectors.append("Financial Infrastructure")
    if any("momo" in s or "mfs" in s for s in subs):
        sectors.append("Mobile Money")

    return list(set(sectors)) if sectors else ["General"]


def _sector_key_to_vocab(sector_key: str) -> list:
    """
    Map a SankofaEye sector key (from utils.sector) to the threat-DB's own
    sector vocabulary used in actor target_sectors.
    """
    mapping = {
        "financial":  ["Banking", "Fintech", "Mobile Money", "Financial Infrastructure"],
        "telecom":    ["Telecom", "Mobile Money"],
        "government": ["Government", "Financial Infrastructure"],
        "healthcare": ["Healthcare"],
        "education":  ["Education", "Government"],
        "commercial": ["General", "Commercial"],
    }
    return mapping.get(sector_key, ["General"])


def cross_reference(target: str, findings: dict, sector_key: str = None) -> dict:
    """
    Cross-reference scan findings against West Africa threat intelligence.

    Args:
        target:     The scanned domain
        findings:   Full aggregated findings dict
        sector_key: Optional resolved sector key from utils.sector
                    (government/financial/telecom/healthcare/education/
                    commercial). When provided it overrides the module's own
                    heuristic detection, so the actor lineup and framing match
                    the rest of the report. For non-regulated (commercial)
                    targets the bank/government-only actors are de-emphasised.

    Returns:
        dict with relevant_actors, relevant_incidents, ioc_matches,
        risk_context, sector, status
    """
    result = {
        "relevant_actors":    [],
        "relevant_incidents": [],
        "ioc_matches":        [],
        "risk_context":       "",
        "sector":             [],
        "status":             "ok",
    }

    db = _load_db()
    if not db:
        result["status"] = "db_unavailable"
        return result

    # Prefer the resolved sector from the pipeline; fall back to heuristic.
    is_commercial = False
    if sector_key:
        sector = _sector_key_to_vocab(sector_key)
        is_commercial = (sector_key == "commercial")
    else:
        sector = _detect_sector(target, findings)
    result["sector"] = sector

    # ── Match threat actors ────────────────────────────────────
    # For commercial (non-regulated) targets, the bank/government-specific
    # actors (e.g. OPERA1ER targeting SWIFT, Scattered Spider hitting MoMo)
    # are not a credible fit. We include an actor for a commercial target only
    # when it genuinely threatens general brands — i.e. it explicitly targets a
    # commercial/general sector, OR its motivation is brand impersonation /
    # phishing-as-a-service / opportunistic fraud rather than bank-specific.
    _COMMERCIAL_RELEVANT_TTPS = ("phishing", "impersonation", "brand",
                                 "spoof", "social engineering", "opportunistic")

    def _actor_card(actor, relevance):
        return {
            "id":             actor["id"],
            "name":           actor["name"],
            "relevance":      relevance,
            "motivation":     actor["motivation"],
            "sophistication": actor["sophistication"],
            "primary_ttps":   actor["primary_ttps"],
            "ghana_notes":    actor.get("ghana_notes", ""),
            "malware":        actor.get("indicators", {}).get("malware", []),
        }

    def _commercial_fit(actor, sector_match) -> bool:
        if sector_match:
            return True
        # Brand/phishing-oriented actors threaten any commercial domain.
        haystack = " ".join([
            str(actor.get("motivation", "")),
            " ".join(actor.get("primary_ttps", [])),
            str(actor.get("ghana_notes", "")),
        ]).lower()
        return any(term in haystack for term in _COMMERCIAL_RELEVANT_TTPS)

    actors = db.get("threat_actors", [])
    for actor in actors:
        relevance = actor.get("ghana_relevance", "LOW")
        actor_sectors = actor.get("target_sectors", [])
        sector_match  = any(s in actor_sectors for s in sector)
        countries = actor.get("target_countries", [])
        country_match = "Ghana" in countries or "West Africa" in countries

        # Decide inclusion.
        include = False
        if is_commercial:
            # Commercial: ignore the blanket "all CRITICAL Ghana actors" rule;
            # require genuine commercial fit. Keep CRITICAL/HIGH that fit.
            if relevance in ("CRITICAL", "HIGH") and _commercial_fit(actor, sector_match):
                include = True
        else:
            if relevance == "CRITICAL" and country_match:
                include = True
            elif relevance == "HIGH" and (sector_match or country_match):
                include = True
            elif relevance == "MEDIUM" and sector_match and country_match:
                include = True

        if include:
            result["relevant_actors"].append(_actor_card(actor, relevance))

    # Sort by relevance
    relevance_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    result["relevant_actors"].sort(
        key=lambda x: relevance_order.get(x["relevance"], 99)
    )

    # ── Match incidents ────────────────────────────────────────
    incidents = db.get("incident_history", [])
    for inc in incidents:
        inc_sectors   = [inc.get("sector", "")]
        inc_countries = [inc.get("country", "")]
        if (any(s in inc_sectors for s in sector) or
                "Ghana" in inc_countries[0] or "West Africa" in inc_countries[0]):
            result["relevant_incidents"].append({
                "id":          inc["id"],
                "date":        inc["date"],
                "type":        inc["type"],
                "description": inc["description"],
                "lessons":     inc["lessons"],
                "impact":      inc["impact"],
            })

    # ── IOC pattern matching ───────────────────────────────────
    ioc_patterns = db.get("ioc_patterns", {}).get("domain_patterns", [])
    for ioc in ioc_patterns:
        pattern = ioc["pattern"].lower()
        if pattern in target.lower():
            result["ioc_matches"].append({
                "pattern":  ioc["pattern"],
                "target":   ioc["target"],
                "type":     ioc["type"],
                "note":     f"Domain '{target}' matches a known lookalike pattern "
                            f"for {ioc['target']}. Verify this is a legitimate domain.",
            })

    # ── Build risk context paragraph ───────────────────────────
    actor_names  = [a["name"] for a in result["relevant_actors"][:3]]
    if is_commercial:
        sector_str = "Commercial / General"
    else:
        sector_str = " / ".join(sector[:2]) if sector else "General"
    incident_cnt = len(result["relevant_incidents"])

    if result["relevant_actors"]:
        if is_commercial:
            closing = (
                "The findings in this report should be prioritised with these "
                "threat actors in mind — particularly email authentication gaps "
                "(T1566) which enable brand impersonation and customer-directed "
                "phishing, the primary fraud vectors against commercial brands "
                "in this region."
            )
        else:
            closing = (
                "The findings in this report should be prioritised with these "
                "threat actors in mind — particularly email authentication gaps "
                "(T1566) and exposed administrative interfaces (T1078) which are "
                "primary initial access vectors for BEC and financial fraud "
                "groups operating in this region."
            )
        result["risk_context"] = (
            f"Based on the target domain and detected sector ({sector_str}), "
            f"AfriWealth CI's West Africa threat intelligence identifies "
            f"{len(result['relevant_actors'])} threat actor(s) with known "
            f"targeting interest in this profile: "
            f"{', '.join(actor_names)}{'...' if len(result['relevant_actors']) > 3 else ''}. "
            f"There are {incident_cnt} historical incident(s) relevant to this sector "
            f"in the Ghana/West Africa threat landscape. " + closing
        )
    else:
        result["risk_context"] = (
            f"No specific threat actors from the AfriWealth CI West Africa database "
            f"were matched to this target's profile ({sector_str}). "
            f"General hygiene recommendations apply."
        )

    log.info(
        f"[WA ThreatDB] {target} | Sector: {sector_str} | "
        f"Actors: {len(result['relevant_actors'])} | "
        f"Incidents: {len(result['relevant_incidents'])} | "
        f"IOC matches: {len(result['ioc_matches'])}"
    )

    return result