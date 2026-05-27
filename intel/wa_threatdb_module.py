"""
SankofahEye — West Africa Threat Intelligence Cross-Reference
AfriWealth Cyber Intelligence

Loads wa_threatdb.json and cross-references scan findings against:
  - Known threat actors likely to target this domain/sector
  - Historical incidents relevant to the target
  - Regional IOC patterns (lookalike domains, email patterns)

This is SankofahEye's competitive moat — no Western tool has this context.
Output is appended to the findings dict and rendered in both PDFs.
"""

import os
import json
from utils.logger import SankofahLogger

log = SankofahLogger("wa_threatdb")

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


def cross_reference(target: str, findings: dict) -> dict:
    """
    Cross-reference scan findings against West Africa threat intelligence.

    Args:
        target:   The scanned domain
        findings: Full aggregated findings dict

    Returns:
        dict with:
            relevant_actors:  list of threat actors likely targeting this domain
            relevant_incidents: list of historical incidents relevant to sector
            ioc_matches:      list of IOC pattern matches
            risk_context:     plain-English threat context paragraph
            sector:           detected sector(s)
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

    sector = _detect_sector(target, findings)
    result["sector"] = sector

    # ── Match threat actors ────────────────────────────────────
    actors = db.get("threat_actors", [])
    for actor in actors:
        relevance = actor.get("ghana_relevance", "LOW")

        # Check sector overlap
        actor_sectors = actor.get("target_sectors", [])
        sector_match  = any(s in actor_sectors for s in sector)

        # Check country — Ghana or West Africa targeting
        countries = actor.get("target_countries", [])
        country_match = "Ghana" in countries or "West Africa" in countries

        # Always include CRITICAL Ghana relevance actors
        if relevance == "CRITICAL" and country_match:
            result["relevant_actors"].append({
                "id":           actor["id"],
                "name":         actor["name"],
                "relevance":    relevance,
                "motivation":   actor["motivation"],
                "sophistication": actor["sophistication"],
                "primary_ttps": actor["primary_ttps"],
                "ghana_notes":  actor.get("ghana_notes", ""),
                "malware":      actor.get("indicators", {}).get("malware", []),
            })
        elif relevance == "HIGH" and (sector_match or country_match):
            result["relevant_actors"].append({
                "id":           actor["id"],
                "name":         actor["name"],
                "relevance":    relevance,
                "motivation":   actor["motivation"],
                "sophistication": actor["sophistication"],
                "primary_ttps": actor["primary_ttps"],
                "ghana_notes":  actor.get("ghana_notes", ""),
                "malware":      actor.get("indicators", {}).get("malware", []),
            })
        elif relevance == "MEDIUM" and sector_match and country_match:
            result["relevant_actors"].append({
                "id":           actor["id"],
                "name":         actor["name"],
                "relevance":    relevance,
                "motivation":   actor["motivation"],
                "sophistication": actor["sophistication"],
                "primary_ttps": actor["primary_ttps"],
                "ghana_notes":  actor.get("ghana_notes", ""),
                "malware":      actor.get("indicators", {}).get("malware", []),
            })

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
    sector_str   = " / ".join(sector[:2]) if sector else "General"
    incident_cnt = len(result["relevant_incidents"])

    if result["relevant_actors"]:
        result["risk_context"] = (
            f"Based on the target domain and detected sector ({sector_str}), "
            f"AfriWealth CI's West Africa threat intelligence identifies "
            f"{len(result['relevant_actors'])} threat actor(s) with known "
            f"targeting interest in this profile: "
            f"{', '.join(actor_names)}{'...' if len(result['relevant_actors']) > 3 else ''}. "
            f"There are {incident_cnt} historical incident(s) relevant to this sector "
            f"in the Ghana/West Africa threat landscape. "
            f"The findings in this report should be prioritised with these threat actors "
            f"in mind — particularly email authentication gaps (T1566) and exposed "
            f"administrative interfaces (T1078) which are primary initial access vectors "
            f"for BEC and financial fraud groups operating in this region."
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
