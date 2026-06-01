"""
SankofaEye — Supplier / Third-Party Risk Scoring (Phase 5G)
AfriWealth Cyber Intelligence

Runs a *lightweight* passive posture check on each configured vendor
domain — DNS email-auth, SSL/TLS, and subdomain footprint only. This is
deliberately fast: no full 10-module scan, no credential/dark-web lookups.

The goal is supply-chain visibility: a bank's own posture means little if
its core-banking provider or payment switch is the weakest link. This maps
directly to BoG CISD Section 6 (Third-Party / Supplier Risk Management).

Reads the `suppliers:` block from config.yaml:
    suppliers:
      - domain: "vendor-example.com"
        name: "Core Banking Provider"
        criticality: high      # low | medium | high | critical

Returns the `supplier_risk` key for the findings dict:
  {
    "vendors": [
        {"domain", "name", "criticality",
         "risk_score": int,            # 0-100, higher = riskier
         "severity": "critical|high|medium|low",
         "issues": [str, ...],
         "signals": {"dns": bool, "ssl": bool, "subdomains": int},
         "status": "ok|partial|error"},
        ...
    ],
    "weakest_link": {...},             # vendor dict with highest risk
    "high_risk_count": int,            # vendors at high/critical severity
    "total_vendors": int,
    "status": "ok|skipped",
  }

Also exposes apply_bog_supplier_hook() to inject a Section 6 gap into the
compliance dict when a high-risk vendor is present.
"""

from utils.logger import SankofaLogger

log = SankofaLogger("supplier_risk")

# Defensive imports — these recon modules may not be present in every
# deployment. Missing modules degrade the relevant signal to "skipped".
try:
    import modules.dns_module as _dns_mod
except Exception:
    _dns_mod = None

try:
    import modules.ssl_module as _ssl_mod
except Exception:
    _ssl_mod = None

try:
    import modules.subfinder_module as _subfinder_mod
except Exception:
    _subfinder_mod = None


# Risk weight per signal (sums toward a 0-100 score, capped at 100).
_W_SPF_WEAK      = 25
_W_DMARC_WEAK    = 30
_W_DKIM_MISSING  = 15
_W_SSL_EXPIRED   = 15
_W_SSL_WEAK_PROT = 10
_W_LARGE_FOOTPRINT = 5

# Criticality multiplier — a weak vendor that is business-critical is
# materially worse than a weak peripheral vendor.
_CRIT_MULT = {"low": 0.85, "medium": 1.0, "high": 1.15, "critical": 1.3}


def _severity_from_score(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _dmarc_is_weak(dmarc: dict) -> bool:
    if not dmarc:
        return True
    if not dmarc.get("present", dmarc.get("record")):
        return True
    policy = str(dmarc.get("policy", "")).lower().replace("p=", "")
    return policy in ("", "none")


def _spf_is_weak(spf: dict) -> bool:
    if not spf:
        return True
    return not spf.get("present", spf.get("record"))


def _dkim_is_missing(dkim: dict) -> bool:
    if not dkim:
        return True
    return not dkim.get("present", dkim.get("found", dkim.get("records")))


def _scan_vendor(vendor: dict, timeouts: dict) -> dict:
    """Run the lightweight DNS + SSL + subdomain-count check on one vendor."""
    domain = vendor.get("domain", "").strip().lower()
    name = vendor.get("name", domain)
    criticality = str(vendor.get("criticality", "medium")).lower()

    issues = []
    raw_score = 0
    signals = {"dns": False, "ssl": False, "subdomains": 0}
    statuses = []

    # ── DNS / email-auth posture ──────────────────────────────
    if _dns_mod:
        try:
            dns_res = _dns_mod.run(domain, timeout=timeouts.get("dns", 20))
            signals["dns"] = True
            if _spf_is_weak(dns_res.get("spf", {})):
                raw_score += _W_SPF_WEAK
                issues.append("SPF missing or unenforced")
            if _dmarc_is_weak(dns_res.get("dmarc", {})):
                raw_score += _W_DMARC_WEAK
                issues.append("DMARC absent or p=none — spoofable")
            if _dkim_is_missing(dns_res.get("dkim", {})):
                raw_score += _W_DKIM_MISSING
                issues.append("DKIM not configured")
            statuses.append("ok")
        except Exception as e:
            log.warning(f"[Supplier] DNS check failed for {domain}: {e}")
            statuses.append("error")
    else:
        statuses.append("skipped")

    # ── SSL / TLS posture ─────────────────────────────────────
    if _ssl_mod:
        try:
            ssl_res = _ssl_mod.run(domain, subdomains=[],
                                   timeout=timeouts.get("ssl", 20))
            signals["ssl"] = True
            if ssl_res.get("expired"):
                raw_score += _W_SSL_EXPIRED
                issues.append("Expired TLS certificate(s)")
            if ssl_res.get("weak_protocol"):
                raw_score += _W_SSL_WEAK_PROT
                issues.append("Deprecated TLS protocol in use")
            statuses.append("ok")
        except Exception as e:
            log.warning(f"[Supplier] SSL check failed for {domain}: {e}")
            statuses.append("error")
    else:
        statuses.append("skipped")

    # ── Subdomain footprint (attack surface) ──────────────────
    if _subfinder_mod:
        try:
            sub_res = _subfinder_mod.run(domain, timeout=timeouts.get("subfinder", 30))
            count = sub_res.get("count", len(sub_res.get("subdomains", [])))
            signals["subdomains"] = count
            if count > 20:
                raw_score += _W_LARGE_FOOTPRINT
                issues.append(f"Large external footprint ({count} subdomains)")
            statuses.append("ok")
        except Exception as e:
            log.warning(f"[Supplier] Subfinder failed for {domain}: {e}")
            statuses.append("error")
    else:
        statuses.append("skipped")

    # Apply criticality weighting and cap at 100.
    mult = _CRIT_MULT.get(criticality, 1.0)
    risk_score = min(100, int(round(raw_score * mult)))

    if "ok" in statuses:
        vstatus = "ok" if "error" not in statuses else "partial"
    else:
        vstatus = "error" if "error" in statuses else "partial"

    if not issues:
        issues.append("No passive posture weaknesses detected")

    return {
        "domain": domain,
        "name": name,
        "criticality": criticality,
        "risk_score": risk_score,
        "severity": _severity_from_score(risk_score),
        "issues": issues,
        "signals": signals,
        "status": vstatus,
    }


def assess_suppliers(config: dict) -> dict:
    """
    Score every vendor in the config `suppliers:` block.

    Args:
        config: full SankofaEye config dict

    Returns:
        supplier_risk dict (see module docstring)
    """
    suppliers = (config or {}).get("suppliers", []) or []
    timeouts = (config or {}).get("timeouts", {})

    if not suppliers:
        log.info("[Supplier] No suppliers configured — skipping.")
        return {
            "vendors": [], "weakest_link": {}, "high_risk_count": 0,
            "total_vendors": 0, "status": "skipped",
        }

    log.info(f"[Supplier] Assessing {len(suppliers)} vendor(s)...")

    vendors = []
    for v in suppliers:
        if not v.get("domain"):
            continue
        vendors.append(_scan_vendor(v, timeouts))

    # Weakest link: highest risk_score, tie-broken by criticality weight.
    weakest = {}
    if vendors:
        weakest = max(
            vendors,
            key=lambda x: (x["risk_score"], _CRIT_MULT.get(x["criticality"], 1.0)),
        )

    high_risk_count = sum(
        1 for v in vendors if v["severity"] in ("high", "critical")
    )

    result = {
        "vendors": vendors,
        "weakest_link": weakest,
        "high_risk_count": high_risk_count,
        "total_vendors": len(vendors),
        "status": "ok",
    }

    if high_risk_count:
        log.warning(
            f"[Supplier] ⚠️ {high_risk_count} high-risk vendor(s). "
            f"Weakest link: {weakest.get('name')} "
            f"({weakest.get('risk_score')}/100)"
        )
    else:
        log.info("[Supplier] No high-risk vendors detected.")

    return result


def apply_bog_supplier_hook(compliance: dict, supplier_risk: dict) -> dict:
    """
    BoG CISD Section 6 (Third-Party Risk) compliance hook.

    If any high/critical-risk vendor is present, inject a Section 6 gap into
    the BoG framework within the compliance dict and recompute its score.
    Mutates and returns the compliance dict. No-op when there is no BoG
    framework or no high-risk vendor.
    """
    compliance = compliance or {}
    if not supplier_risk or supplier_risk.get("high_risk_count", 0) <= 0:
        return compliance

    # Locate the BoG framework by key or short-name.
    bog_key = None
    for k, fw in compliance.items():
        if not isinstance(fw, dict):
            continue
        if "bog" in str(k).lower() or "bog" in str(fw.get("short", "")).lower():
            bog_key = k
            break
    if bog_key is None:
        return compliance

    fw = compliance[bog_key]
    weakest = supplier_risk.get("weakest_link", {})
    sev = "critical" if (weakest.get("severity") == "critical") else "high"

    gap = {
        "id": "BOG-06",
        "section": "Section 6 — Third-Party / Supplier Risk Management",
        "severity": sev,
        "remediation": (
            f"Assess and remediate high-risk supplier(s) — weakest link: "
            f"{weakest.get('name', 'unknown')} "
            f"({weakest.get('risk_score', 0)}/100, {weakest.get('criticality','')}). "
            f"Establish contractual security requirements, periodic vendor "
            f"posture reviews, and right-to-audit clauses. "
            f"Reference: BoG CISD Section 6 — Third-Party Risk Management."
        ),
    }

    gaps = fw.setdefault("gaps", [])
    if not any(g.get("id") == "BOG-06" for g in gaps):
        gaps.append(gap)
        # Recompute: one additional control assessed and failed.
        total = fw.get("total", 0) + 1
        passed = fw.get("passed", 0)  # control failed, so passed unchanged
        fw["total"] = total
        fw["passed"] = passed
        if total > 0:
            fw["score"] = int(round(passed / total * 100))
        score = fw.get("score", 0)
        if score >= 80:
            fw["status"], fw["colour"] = "compliant", "#388E3C"
        elif score >= 50:
            fw["status"], fw["colour"] = "partial", "#F57C00"
        else:
            fw["status"], fw["colour"] = "non_compliant", "#D32F2F"
        log.info("[Supplier] BoG CISD Section 6 gap injected (BOG-06).")

    return compliance