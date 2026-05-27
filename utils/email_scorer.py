"""
SankofahEye — Email Security Scorecard
AfriWealth Cyber Intelligence

Produces an A–F letter grade from SPF, DMARC, and DKIM findings
collected by the DNS module. No additional API calls required.

Scoring model
─────────────
SPF
  present + -all hardfail  → 25 pts
  present + ~all softfail  → 12 pts
  present + ?all / +all    →  0 pts
  missing                  →  0 pts

DMARC
  p=reject                 → 35 pts
  p=quarantine             → 18 pts
  p=none                   →  5 pts
  missing                  →  0 pts
  rua reporting addr set   → +10 pts bonus
  pct=100 (full coverage)  →  +5 pts bonus

DKIM
  1+ valid selectors found → 25 pts
  missing                  →  0 pts

Max base score: 85 pts
Max with bonuses: 100 pts

Grade thresholds
────────────────
  A  90–100   Strong — industry best practice met
  B  75–89    Good — minor gaps, low spoofing risk
  C  55–74    Fair — partial controls, moderate risk
  D  35–54    Poor — significant gaps, high spoofing risk
  F   0–34    Critical — domain can be freely spoofed
"""

from dataclasses import dataclass, field
from typing import Optional


# ─── Grade thresholds ──────────────────────────────────────────────────────────

GRADE_THRESHOLDS = [
    (90, "A", "Strong",   "Email authentication meets industry best practice. "
                           "Spoofing risk is low."),
    (75, "B", "Good",     "Most controls are in place. Minor gaps should be addressed "
                           "to reach full enforcement."),
    (55, "C", "Fair",     "Partial controls only. Spoofed emails may reach inboxes. "
                           "Priority remediation recommended."),
    (35, "D", "Poor",     "Significant email security gaps. Domain spoofing is likely "
                           "possible. Immediate action required."),
    ( 0, "F", "Critical", "Email domain has minimal or no anti-spoofing controls. "
                           "Any attacker can impersonate this domain. Critical risk."),
]


# ─── Colour mapping for PDF rendering ─────────────────────────────────────────

GRADE_COLOURS = {
    "A": "#388E3C",   # Green
    "B": "#2E7D32",   # Dark green
    "C": "#FBC02D",   # Amber
    "D": "#F57C00",   # Orange
    "F": "#D32F2F",   # Red
}


# ─── Scorecard data class ──────────────────────────────────────────────────────

@dataclass
class EmailScorecard:
    score:          int
    grade:          str
    rating:         str
    summary:        str
    colour_hex:     str

    spf_score:      int = 0
    spf_label:      str = ""
    spf_max:        int = 25

    dmarc_score:    int = 0
    dmarc_label:    str = ""
    dmarc_max:      int = 50   # 35 base + 15 bonus

    dkim_score:     int = 0
    dkim_label:     str = ""
    dkim_max:       int = 25

    breakdown:      list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


# ─── Core scoring logic ────────────────────────────────────────────────────────

def score_email_security(dns_result: dict) -> EmailScorecard:
    """
    Takes the full dns_module result dict and returns an EmailScorecard.

    Args:
        dns_result: The dict returned by dns_module.run(domain)

    Returns:
        EmailScorecard with letter grade, score breakdown, and recommendations
    """
    spf   = dns_result.get("spf",   {})
    dmarc = dns_result.get("dmarc", {})
    dkim  = dns_result.get("dkim",  {})

    breakdown      = []
    recommendations = []
    total          = 0

    # ── SPF ──────────────────────────────────────────────────────────────────
    spf_score = 0
    spf_strength = spf.get("strength", "none")

    if spf_strength == "strong":
        spf_score  = 25
        spf_label  = "SPF (-all hardfail)"
        breakdown.append(("SPF", "+25", "Present with -all hardfail"))
    elif spf_strength == "weak":
        spf_score  = 12
        spf_label  = "SPF (~all softfail)"
        breakdown.append(("SPF", "+12", "Present but ~all softfail — spoofed emails may still be delivered"))
        recommendations.append(
            "Upgrade SPF from ~all (softfail) to -all (hardfail) to fully block "
            "unauthorised senders. Update: change ~all to -all at the end of your SPF record."
        )
    elif spf.get("present"):
        spf_score  = 0
        spf_label  = "SPF (ineffective)"
        breakdown.append(("SPF", "+0", "Present but ?all or +all — provides no protection"))
        recommendations.append(
            "SPF record exists but uses ?all or +all, which offers no protection. "
            "Replace the qualifier with -all to enforce sender restrictions."
        )
    else:
        spf_score  = 0
        spf_label  = "SPF (missing)"
        breakdown.append(("SPF", "+0", "No SPF record found — any server can send as this domain"))
        recommendations.append(
            "Create an SPF record immediately. Example: "
            "v=spf1 include:_spf.yourmailprovider.com -all"
        )

    total += spf_score

    # ── DMARC ─────────────────────────────────────────────────────────────────
    dmarc_score  = 0
    dmarc_policy = dmarc.get("policy", "none") if dmarc.get("present") else "missing"
    dmarc_bonus  = 0

    if dmarc_policy == "reject":
        dmarc_score = 35
        dmarc_label = "DMARC (p=reject)"
        breakdown.append(("DMARC", "+35", "p=reject — spoofed emails fully blocked"))
    elif dmarc_policy == "quarantine":
        dmarc_score = 18
        dmarc_label = "DMARC (p=quarantine)"
        breakdown.append(("DMARC", "+18", "p=quarantine — spoofed emails go to spam but not rejected"))
        recommendations.append(
            "Upgrade DMARC from p=quarantine to p=reject to fully block spoofed emails. "
            "Sequence: p=none → p=quarantine → p=reject."
        )
    elif dmarc_policy == "none":
        dmarc_score = 5
        dmarc_label = "DMARC (p=none)"
        breakdown.append(("DMARC", "+5", "p=none — monitoring only, spoofed emails not blocked"))
        recommendations.append(
            "DMARC policy is set to 'none' (monitoring only). Spoofed emails are not blocked. "
            "Move to p=quarantine, then p=reject. Add rua= reporting address to gain visibility."
        )
    else:
        dmarc_score = 0
        dmarc_label = "DMARC (missing)"
        breakdown.append(("DMARC", "+0", "No DMARC record — domain spoofing completely unrestricted"))
        recommendations.append(
            "No DMARC record found. Create one immediately: "
            "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com"
        )

    # Bonus: rua reporting address
    if dmarc.get("rua"):
        dmarc_bonus += 10
        breakdown.append(("DMARC bonus", "+10", "rua reporting address configured — spoofing attempts are visible"))
    else:
        if dmarc.get("present"):
            recommendations.append(
                "Add a rua= reporting address to your DMARC record to receive reports "
                "about spoofing attempts: rua=mailto:dmarc-reports@yourdomain.com"
            )

    # Bonus: pct=100
    if dmarc.get("pct", 100) == 100 and dmarc_policy in ("quarantine", "reject"):
        dmarc_bonus += 5
        breakdown.append(("DMARC bonus", "+5", "pct=100 — policy applies to 100% of email"))
    elif dmarc.get("pct", 100) < 100 and dmarc.get("present"):
        pct = dmarc.get("pct", 0)
        recommendations.append(
            f"DMARC pct={pct}% means policy only applies to {pct}% of email. "
            "Set pct=100 for full enforcement."
        )

    total += dmarc_score + dmarc_bonus

    # ── DKIM ──────────────────────────────────────────────────────────────────
    dkim_score     = 0
    selector_count = len(dkim.get("found_selectors", []))

    if dkim.get("present") and selector_count > 0:
        dkim_score = 25
        dkim_label = f"DKIM ({selector_count} selector{'s' if selector_count > 1 else ''})"
        breakdown.append(("DKIM", "+25", f"{selector_count} valid selector(s) found — emails are cryptographically signed"))
    else:
        dkim_score = 0
        dkim_label = "DKIM (not found)"
        breakdown.append(("DKIM", "+0", "No DKIM selectors found — emails cannot be cryptographically verified"))
        recommendations.append(
            "Configure DKIM signing on your mail server. Generate a key pair and publish "
            "the public key as a TXT record at: selector._domainkey.yourdomain.com"
        )

    total += dkim_score

    # ── Cap at 100 ────────────────────────────────────────────────────────────
    total = min(total, 100)

    # ── Determine grade ───────────────────────────────────────────────────────
    grade   = "F"
    rating  = "Critical"
    summary = GRADE_THRESHOLDS[-1][3]

    for threshold, g, r, s in GRADE_THRESHOLDS:
        if total >= threshold:
            grade   = g
            rating  = r
            summary = s
            break

    colour = GRADE_COLOURS.get(grade, "#757575")

    return EmailScorecard(
        score        = total,
        grade        = grade,
        rating       = rating,
        summary      = summary,
        colour_hex   = colour,
        spf_score    = spf_score,
        spf_label    = spf_label,
        spf_max      = 25,
        dmarc_score  = dmarc_score + dmarc_bonus,
        dmarc_label  = dmarc_label,
        dmarc_max    = 50,
        dkim_score   = dkim_score,
        dkim_label   = dkim_label,
        dkim_max     = 25,
        breakdown    = breakdown,
        recommendations = recommendations,
    )