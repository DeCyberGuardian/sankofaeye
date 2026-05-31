"""
SankofahEye — Peer Benchmarking Database
AfriWealth Cyber Intelligence

Maintains an anonymised benchmark database of risk scores
across Ghanaian institutions by sector. Every completed scan
contributes anonymised data, and every report shows where the
target ranks within its peer group.

"Your DMARC score is 0/50 — the lowest among the top 10
Ghanaian banks we've assessed" changes the budget conversation.

Sectors tracked:
  - Banking (commercial banks under BoG supervision)
  - Fintech (payment service providers, digital lenders)
  - Telecom (MTN, Telecel, AirtelTigo and ISPs)
  - Government (.gov.gh domains)
  - Insurance
  - Education

Data stored:
  - Risk score (0-100)
  - Email security score (0-100)
  - Subdomain count
  - Compliance scores per framework
  - No domain names — only sector + score + date
"""

import os
import json
import statistics
from datetime import datetime
from utils.logger import SankofahLogger

log = SankofahLogger("benchmarking")

BENCHMARK_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "intel", "benchmark_db.json"
)

# ── Sector detection ───────────────────────────────────────────────────────────

def detect_sector(target: str, findings: dict) -> str:
    """Infer sector from domain and subdomain patterns."""
    t    = target.lower()
    subs = " ".join(findings.get("subdomains", {}).get("list", [])).lower()

    if any(x in t for x in ["bank", "gcb", "ecobank", "absa", "stanbic", "cal", "uba", "fidelity", "zenith", "access", "republic"]):
        return "Banking"
    if any(x in t for x in ["mtn", "telecel", "airtel", "tigo", "vodafone"]):
        return "Telecom"
    if any(x in t for x in ["momo", "pay", "fintech", "wallet", "hubtel", "slyde", "expresspay"]):
        return "Fintech"
    if ".gov.gh" in t or any(x in t for x in ["ghipss", "bog", "gra", "nca", "gipc", "scholarships"]):
        return "Government"
    if any(x in t for x in ["insurance", "sic", "enterprise", "ais"]):
        return "Insurance"
    if any(x in t for x in ["university", "college", "school", "edu", "knust", "ug.edu"]):
        return "Education"
    if any(x in subs for x in ["momo", "mfs", "wallet", "payment", "gateway"]):
        return "Fintech"
    return "General"


# ── DB operations ──────────────────────────────────────────────────────────────

def _load_db() -> dict:
    if os.path.exists(BENCHMARK_DB_PATH):
        try:
            with open(BENCHMARK_DB_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "version": "1.0",
        "last_updated": "",
        "sectors": {},
        "total_entries": 0
    }


def _save_db(db: dict):
    os.makedirs(os.path.dirname(BENCHMARK_DB_PATH), exist_ok=True)
    db["last_updated"] = datetime.utcnow().isoformat()
    with open(BENCHMARK_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


def contribute_scan(target: str, findings: dict, scoring: dict, compliance: dict):
    """
    Add anonymised scan data to the benchmark database.
    Called automatically after every completed scan.
    No domain name stored — only sector + metrics + date.
    """
    sector = detect_sector(target, findings)
    db     = _load_db()

    if sector not in db["sectors"]:
        db["sectors"][sector] = {"entries": []}

    email_score = findings.get("dns_security", {}).get("email_score", None)
    bog_score   = compliance.get("bog", {}).get("score") if compliance else None
    nca_score   = compliance.get("nca", {}).get("score") if compliance else None
    dpc_score   = compliance.get("dpc", {}).get("score") if compliance else None

    entry = {
        "date":          datetime.utcnow().strftime("%Y-%m"),
        "risk_score":    scoring.get("score", 0),
        "rating":        scoring.get("rating", ""),
        "finding_count": scoring.get("finding_count", 0),
        "subdomain_count": findings.get("subdomains", {}).get("count", 0),
        "email_score":   email_score,
        "bog_score":     bog_score,
        "nca_score":     nca_score,
        "dpc_score":     dpc_score,
        "breached_accounts": findings.get("credential_exposure", {}).get("total_breached", 0),
    }

    db["sectors"][sector]["entries"].append(entry)
    db["total_entries"] = sum(
        len(s["entries"]) for s in db["sectors"].values()
    )

    _save_db(db)
    log.info(f"[Benchmark] Contributed scan to sector '{sector}' — total entries: {db['total_entries']}")


def get_percentile(value: float, values: list) -> int:
    """Return percentile rank of value within a list (higher = better exposed = worse)."""
    if not values or value is None:
        return None
    below = sum(1 for v in values if v < value)
    return round((below / len(values)) * 100)


def get_benchmark(target: str, findings: dict, scoring: dict, compliance: dict) -> dict:
    """
    Generate a peer benchmarking report for a scan result.

    Returns:
        dict with sector comparison, percentile ranks, and peer summary
    """
    sector = detect_sector(target, findings)
    db     = _load_db()

    result = {
        "sector":          sector,
        "peer_count":      0,
        "risk_percentile": None,
        "email_percentile": None,
        "bog_percentile":  None,
        "summary":         "",
        "peer_stats":      {},
        "rankings":        [],
    }

    sector_data = db.get("sectors", {}).get(sector, {}).get("entries", [])

    # Need at least 3 entries for meaningful comparison
    if len(sector_data) < 3:
        result["summary"] = (
            f"Benchmarking data for the '{sector}' sector is building. "
            f"Currently {len(sector_data)} scan(s) on record. "
            f"Check back after more organisations in your sector have been assessed."
        )
        return result

    result["peer_count"] = len(sector_data)

    # Extract peer metrics
    risk_scores   = [e["risk_score"]  for e in sector_data if e["risk_score"]  is not None]
    email_scores  = [e["email_score"] for e in sector_data if e["email_score"] is not None]
    bog_scores    = [e["bog_score"]   for e in sector_data if e["bog_score"]   is not None]

    current_risk  = scoring.get("score", 0)
    current_email = findings.get("dns_security", {}).get("email_score")
    current_bog   = compliance.get("bog", {}).get("score") if compliance else None

    # Compute stats
    if risk_scores:
        result["peer_stats"]["risk"] = {
            "mean":   round(statistics.mean(risk_scores)),
            "median": round(statistics.median(risk_scores)),
            "min":    min(risk_scores),
            "max":    max(risk_scores),
        }
        # Higher risk score = worse. So percentile of "worse than peers"
        result["risk_percentile"] = get_percentile(current_risk, risk_scores)

    if email_scores:
        result["peer_stats"]["email"] = {
            "mean":   round(statistics.mean(email_scores)),
            "median": round(statistics.median(email_scores)),
        }
        # Lower email score = worse
        below = sum(1 for v in email_scores if v > (current_email or 0))
        result["email_percentile"] = round((below / len(email_scores)) * 100)

    if bog_scores:
        result["peer_stats"]["bog_compliance"] = {
            "mean":   round(statistics.mean(bog_scores)),
            "median": round(statistics.median(bog_scores)),
        }
        below = sum(1 for v in bog_scores if v > (current_bog or 0))
        result["bog_percentile"] = round((below / len(bog_scores)) * 100)

    # Build rankings list for PDF
    rankings = []
    if result["risk_percentile"] is not None:
        pct = result["risk_percentile"]
        if pct >= 75:
            tier, label = "bottom", "higher risk than most peers"
        elif pct >= 50:
            tier, label = "below_avg", "above sector average risk"
        elif pct >= 25:
            tier, label = "above_avg", "below sector average risk"
        else:
            tier, label = "top", "among the lowest-risk in sector"

        rankings.append({
            "metric":     "Overall Risk Score",
            "value":      current_risk,
            "sector_avg": result["peer_stats"].get("risk", {}).get("mean"),
            "percentile": pct,
            "tier":       tier,
            "label":      label,
        })

    if result["email_percentile"] is not None:
        pct = result["email_percentile"]
        rankings.append({
            "metric":     "Email Security Score",
            "value":      current_email,
            "sector_avg": result["peer_stats"].get("email", {}).get("mean"),
            "percentile": pct,
            "tier":       "top" if pct >= 75 else "bottom" if pct < 25 else "avg",
            "label":      "better email security than most peers" if pct >= 75 else "email security below sector average",
        })

    result["rankings"] = rankings

    # Build summary sentence
    if result["risk_percentile"] is not None:
        pct = result["risk_percentile"]
        peer_avg = result["peer_stats"].get("risk", {}).get("mean", "N/A")
        result["summary"] = (
            f"Among {result['peer_count']} {sector} organisations assessed by AfriWealth CI, "
            f"this domain's risk score ({current_risk}/100) is "
            f"{'higher than' if pct >= 50 else 'lower than'} "
            f"{pct if pct >= 50 else 100 - pct}% of sector peers. "
            f"Sector average: {peer_avg}/100."
        )

    log.info(f"[Benchmark] {target} | Sector: {sector} | Peers: {result['peer_count']} | "
             f"Risk percentile: {result['risk_percentile']}")

    return result