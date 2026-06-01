"""
SankofaEye — Attack Path Reconstruction (Phase 5E)
AfriWealth Cyber Intelligence

Reconstructs the most plausible adversary kill-chain from passive
findings, mapped to MITRE ATT&CK tactics. Purely inferential — built
from exposure signals already surfaced by the scan. No active testing.

Returns a dict consumed by:
  - reports/pdf_generator.py   (Attack Path section)
  - templates/attack_path_widget.html (dashboard / findings widget)

Shape:
  {
    "has_path": bool,
    "summary": str,
    "stages": [
        {"tactic": "Reconnaissance", "mitre_tactic": "TA0043",
         "step": int, "title": str, "detail": str,
         "severity": "critical|high|medium|low",
         "techniques": [{"id": "T1590", "name": "..."}],
         "evidence": [str, ...]},
        ...
    ],
    "entry_point": str,
    "crown_jewel_risk": str,
    "stage_count": int,
}
"""

from utils.logger import SankofaLogger

log = SankofaLogger("attack_path")

# MITRE ATT&CK Enterprise tactic ordering (kill-chain sequence)
_TACTIC_ORDER = [
    ("Reconnaissance",      "TA0043"),
    ("Resource Development", "TA0042"),
    ("Initial Access",      "TA0001"),
    ("Credential Access",   "TA0006"),
    ("Lateral Movement",    "TA0008"),
    ("Impact",              "TA0040"),
]

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _max_sev(severities):
    if not severities:
        return "low"
    return max(severities, key=lambda s: _SEV_RANK.get(s, 0))


def build_attack_path(findings: dict, scoring: dict) -> dict:
    """
    Build an inferred adversary kill-chain from passive findings.

    Args:
        findings: aggregated findings dict (see FINDINGS DICT KEY STRUCTURE)
        scoring:  risk_scorer output — {score, rating, findings:[...], ...}

    Returns:
        attack_path dict (see module docstring)
    """
    findings = findings or {}
    scoring  = scoring or {}

    target        = findings.get("target", "the target")
    scored        = scoring.get("findings", [])
    subdomains    = findings.get("subdomains", {}) or {}
    exposed       = findings.get("exposed_services", {}) or {}
    creds         = findings.get("credential_exposure", {}) or {}
    darkweb       = findings.get("dark_web", {}) or {}
    infostealer   = findings.get("infostealer_exposure", {}) or {}
    dns_sec       = findings.get("dns_security", {}) or {}
    momo          = findings.get("momo_exposure", {}) or {}

    stages = []
    step = 0

    # ── Stage: Reconnaissance ─────────────────────────────────
    recon_evidence = []
    recon_sev = []
    sub_count = subdomains.get("count", 0)
    if sub_count:
        recon_evidence.append(f"{sub_count} subdomain(s) enumerable from public sources")
        recon_sev.append("medium" if sub_count > 20 else "low")
    email_count = (findings.get("emails", {}) or {}).get("count", 0)
    if email_count:
        recon_evidence.append(f"{email_count} corporate email(s) harvestable for targeting")
        recon_sev.append("medium")
    if recon_evidence:
        step += 1
        stages.append({
            "tactic": "Reconnaissance",
            "mitre_tactic": "TA0043",
            "step": step,
            "title": "Attack surface mapping",
            "detail": (
                f"An adversary can passively map {target}'s footprint — "
                f"subdomains, hosts and staff emails — with zero direct contact, "
                "building a target list for follow-on phishing or service abuse."
            ),
            "severity": _max_sev(recon_sev),
            "techniques": [
                {"id": "T1590", "name": "Gather Victim Network Information"},
                {"id": "T1589", "name": "Gather Victim Identity Information"},
            ],
            "evidence": recon_evidence,
        })

    # ── Stage: Resource Development (phishing infra / lookalikes) ─
    phishing = findings.get("phishing_intel", {}) or {}
    lookalikes = phishing.get("lookalike_domains", []) or []
    dmarc = dns_sec.get("dmarc", {}) or {}
    dmarc_weak = (not dmarc.get("present")) or (dmarc.get("policy") in (None, "none", "p=none"))
    if lookalikes or dmarc_weak:
        step += 1
        ev = []
        sev = []
        if lookalikes:
            ev.append(f"{len(lookalikes)} lookalike/typosquat domain(s) registered")
            sev.append("high")
        if dmarc_weak:
            ev.append("DMARC absent or set to p=none — spoofed mail not rejected")
            sev.append("high")
        stages.append({
            "tactic": "Resource Development",
            "mitre_tactic": "TA0042",
            "step": step,
            "title": "Phishing infrastructure & domain spoofing",
            "detail": (
                "Weak email authentication combined with lookalike domains lets an "
                "adversary impersonate the brand in BEC and credential-harvesting "
                "campaigns — the dominant initial-access vector across West African "
                "financial targets."
            ),
            "severity": _max_sev(sev),
            "techniques": [
                {"id": "T1583.001", "name": "Acquire Infrastructure: Domains"},
                {"id": "T1656", "name": "Impersonation"},
            ],
            "evidence": ev,
        })

    # ── Stage: Initial Access ─────────────────────────────────
    high_risk_ports = exposed.get("high_risk_ports", []) or []
    cves = exposed.get("cves", []) or []
    momo_services = momo.get("exposed_services", []) or []
    if high_risk_ports or cves or momo_services:
        step += 1
        ev = []
        sev = []
        if high_risk_ports:
            ports = ", ".join(str(p) for p in high_risk_ports[:6])
            ev.append(f"High-risk service port(s) exposed: {ports}")
            sev.append("critical")
        if cves:
            ev.append(f"{len(cves)} known CVE(s) on internet-facing services")
            sev.append("critical")
        if momo_services:
            crit = [s for s in momo_services
                    if str(s.get("severity", "")).upper() in ("CRITICAL", "HIGH")]
            ev.append(f"{len(momo_services)} exposed Mobile Money service(s) "
                      f"({len(crit)} high/critical)")
            sev.append("critical" if crit else "high")
        stages.append({
            "tactic": "Initial Access",
            "mitre_tactic": "TA0001",
            "step": step,
            "title": "Exploitation of exposed services",
            "detail": (
                "Internet-facing services with known vulnerabilities or risky open "
                "ports provide a direct foothold. Exposed Mobile Money infrastructure "
                "is especially attractive given direct monetisation paths."
            ),
            "severity": _max_sev(sev),
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "T1133", "name": "External Remote Services"},
            ],
            "evidence": ev,
        })

    # ── Stage: Credential Access ──────────────────────────────
    breached = creds.get("total_breached", 0)
    stealer_emp = infostealer.get("total_employees", 0)
    if breached or stealer_emp:
        step += 1
        ev = []
        sev = []
        if breached:
            ev.append(f"{breached} credential(s) exposed in known breaches")
            sev.append("high")
        if stealer_emp:
            ev.append(f"{stealer_emp} employee(s) with infostealer-harvested credentials")
            sev.append("critical")
        stages.append({
            "tactic": "Credential Access",
            "mitre_tactic": "TA0006",
            "step": step,
            "title": "Valid account compromise",
            "detail": (
                "Breached and infostealer-harvested credentials enable login as a "
                "legitimate user — bypassing perimeter controls entirely. Infostealer "
                "logs frequently include active session cookies, defeating MFA."
            ),
            "severity": _max_sev(sev),
            "techniques": [
                {"id": "T1078", "name": "Valid Accounts"},
                {"id": "T1539", "name": "Steal Web Session Cookie"},
            ],
            "evidence": ev,
        })

    # ── Stage: Impact ─────────────────────────────────────────
    dw_mentions = darkweb.get("total_mentions", 0)
    impact_ev = []
    impact_sev = []
    if dw_mentions:
        impact_ev.append(f"{dw_mentions} dark-web mention(s) — active adversary interest")
        impact_sev.append("high")
    if momo_services:
        impact_ev.append("Mobile Money exposure creates direct financial-fraud path")
        impact_sev.append("critical")
    if breached or stealer_emp:
        impact_ev.append("Compromised accounts enable fraudulent transactions / data theft")
        impact_sev.append("high")
    if impact_ev:
        step += 1
        stages.append({
            "tactic": "Impact",
            "mitre_tactic": "TA0040",
            "step": step,
            "title": "Financial fraud & data exfiltration",
            "detail": (
                "The combined exposure supports the adversary's end goal: fraudulent "
                "transactions, Mobile Money diversion, and exfiltration of customer "
                "data — the documented objective of OPERA1ER-class actors in the region."
            ),
            "severity": _max_sev(impact_sev),
            "techniques": [
                {"id": "T1657", "name": "Financial Theft"},
                {"id": "T1567", "name": "Exfiltration Over Web Service"},
            ],
            "evidence": impact_ev,
        })

    # ── Summary derivation ────────────────────────────────────
    has_path = len(stages) >= 2
    entry_point = stages[0]["title"] if stages else "No clear entry point identified"

    if not stages:
        summary = (
            f"No coherent attack path could be reconstructed for {target} from "
            "passive findings. This is a positive signal, not a guarantee of safety."
        )
        crown = "Low — minimal externally-observable attack surface."
    else:
        tactics_hit = " → ".join(s["tactic"] for s in stages)
        chain_sev = _max_sev([s["severity"] for s in stages])
        summary = (
            f"A {chain_sev.upper()}-severity attack path spanning {len(stages)} "
            f"ATT&CK stage(s) was reconstructed for {target}: {tactics_hit}. "
            f"Likely entry point: {entry_point.lower()}."
        )
        if any(s["tactic"] == "Impact" for s in stages):
            crown = ("HIGH — a complete chain to financial impact is inferable from "
                     "current exposure. Prioritise breaking the chain at initial access "
                     "and credential stages.")
        elif any(s["tactic"] in ("Initial Access", "Credential Access") for s in stages):
            crown = ("MEDIUM — adversary can plausibly gain a foothold; impact stage "
                     "not yet directly supported by findings.")
        else:
            crown = "LOW–MEDIUM — reconnaissance/staging signals only."

    result = {
        "has_path": has_path,
        "summary": summary,
        "stages": stages,
        "entry_point": entry_point,
        "crown_jewel_risk": crown,
        "stage_count": len(stages),
    }

    log.info(f"[AttackPath] {len(stages)} stage(s) reconstructed for {target}")
    return result


# ── PDF rendering helper ──────────────────────────────────────────
# pdf_generator.py imports get_killchain_flowable and renders it in the
# "Visualized Threat Killchain Flow" section. Returns a reportlab Flowable
# (a horizontal stage-chain diagram) or None when there is no path.

def get_killchain_flowable(attack_path: dict):
    """
    Build a compact horizontal kill-chain diagram as a reportlab Flowable.

    Args:
        attack_path: dict returned by build_attack_path()

    Returns:
        A reportlab Drawing flowable, or None if reportlab is unavailable
        or there is no reconstructable path.
    """
    if not attack_path or not attack_path.get("has_path"):
        return None

    try:
        from reportlab.graphics.shapes import Drawing, Rect, String, Polygon
        from reportlab.lib import colors
        from reportlab.lib.units import mm
    except ImportError:
        return None

    sev_colours = {
        "critical": colors.HexColor("#D32F2F"),
        "high":     colors.HexColor("#F57C00"),
        "medium":   colors.HexColor("#FBC02D"),
        "low":      colors.HexColor("#388E3C"),
    }

    stages = attack_path.get("stages", [])
    n = len(stages)
    if n == 0:
        return None

    # Layout: boxes laid left-to-right with arrow connectors, wrapping
    # is avoided by sizing to fit within the A4 content width (~170mm).
    box_w   = 30 * mm
    box_h   = 16 * mm
    gap     = 6 * mm
    total_w = n * box_w + (n - 1) * gap
    d = Drawing(total_w, box_h + 8 * mm)

    x = 0
    y = 4 * mm
    for i, st in enumerate(stages):
        sev = str(st.get("severity", "low")).lower()
        col = sev_colours.get(sev, colors.HexColor("#757575"))

        d.add(Rect(x, y, box_w, box_h, fillColor=col, strokeColor=col,
                   rx=2, ry=2))
        # Step number (top-left)
        d.add(String(x + 3, y + box_h - 9, str(st.get("step", i + 1)),
                     fontName="Helvetica-Bold", fontSize=8,
                     fillColor=colors.white))
        # Tactic label (centred, wrapped to 2 short lines)
        tactic = st.get("tactic", "")
        words = tactic.split()
        if len(words) > 1 and len(tactic) > 11:
            mid = len(words) // 2
            line1 = " ".join(words[:mid])
            line2 = " ".join(words[mid:])
        else:
            line1, line2 = tactic, ""
        d.add(String(x + box_w / 2, y + box_h / 2 + 1, line1,
                     fontName="Helvetica-Bold", fontSize=7,
                     fillColor=colors.white, textAnchor="middle"))
        if line2:
            d.add(String(x + box_w / 2, y + box_h / 2 - 7, line2,
                         fontName="Helvetica-Bold", fontSize=7,
                         fillColor=colors.white, textAnchor="middle"))
        # MITRE tactic id (bottom)
        d.add(String(x + box_w / 2, y + 2, st.get("mitre_tactic", ""),
                     fontName="Courier", fontSize=6,
                     fillColor=colors.white, textAnchor="middle"))

        # Arrow connector to next box
        if i < n - 1:
            ax = x + box_w
            ay = y + box_h / 2
            d.add(Polygon([ax, ay - 3, ax + gap, ay, ax, ay + 3],
                          fillColor=colors.HexColor("#757575"),
                          strokeColor=colors.HexColor("#757575")))
        x += box_w + gap

    return d