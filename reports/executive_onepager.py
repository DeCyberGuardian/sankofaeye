"""
SankofahEye — Executive One-Pager
AfriWealth Cyber Intelligence

Generates a single-page C-suite PDF from the same scan data as the
full technical report. Written entirely in plain English — no MITRE IDs,
no technical jargon, no analyst assumptions.

Audience: CISO, CEO, Board, Risk Committee, non-technical decision-makers.

Purpose: answer three questions in under 60 seconds —
  1. How exposed are we?
  2. What are the three most important things we found?
  3. What do we do next and who owns it?

Layout (single A4 page):
  ┌──────────────────────────────────────────────────────────┐
  │ HEADER: AfriWealth CI brand, target, date, analyst       │
  ├──────────────┬───────────────────────────────────────────┤
  │ RISK GAUGE   │ KEY METRICS (5 stats)                     │
  ├──────────────┴───────────────────────────────────────────┤
  │ WHAT WE FOUND — top 3 findings in plain English          │
  ├──────────────────────────────────────────────────────────┤
  │ WHAT TO DO — 3-column action tracks (72h / 30d / 90d)    │
  ├──────────────────────────────────────────────────────────┤
  │ EMAIL SECURITY SCORECARD (A–F visual)                    │
  ├──────────────────────────────────────────────────────────┤
  │ FOOTER: CTA + confidentiality notice                     │
  └──────────────────────────────────────────────────────────┘
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable,
)
from reportlab.graphics.shapes import Drawing, Wedge, Rect, String
from reportlab.platypus import Image as RLImage

from utils.logger import SankofahLogger
from utils.email_scorer import score_email_security

log = SankofahLogger("exec_onepager")

# ── Brand colours ──────────────────────────────────────────────────────────────
C_PRIMARY  = colors.HexColor("#008080")
C_DARK     = colors.HexColor("#005F5F")
C_ACCENT   = colors.HexColor("#FFD700")
C_CRITICAL = colors.HexColor("#D32F2F")
C_HIGH     = colors.HexColor("#F57C00")
C_MEDIUM   = colors.HexColor("#FBC02D")
C_LOW      = colors.HexColor("#388E3C")
C_BG_LIGHT = colors.HexColor("#F5F5F5")
C_BORDER   = colors.HexColor("#E0E0E0")
C_TEXT     = colors.HexColor("#212121")
C_MUTED    = colors.HexColor("#757575")
C_WHITE    = colors.white

RATING_COLOURS = {
    "critical": C_CRITICAL,
    "high":     C_HIGH,
    "medium":   C_MEDIUM,
    "low":      C_LOW,
}

PAGE_W, PAGE_H = A4
MARGIN = 14 * mm


# ── Plain-English finding summaries ────────────────────────────────────────────
# Maps technical finding titles → one sentence a non-technical exec understands.

_PLAIN_ENGLISH = {
    "self-hosted mail infrastructure exposed":
        "Your email server is directly reachable from the internet. Criminals can "
        "attempt to break in with stolen passwords and then impersonate your staff.",

    "dmarc not fully enforced":
        "Anyone on the internet can send emails pretending to be your organisation. "
        "No technical skill is needed — your trusted domain name can be used to "
        "defraud customers, partners, and staff.",

    "weak tls protocol":
        "Your servers accept old, broken encryption. An attacker who intercepts "
        "your network traffic can decode it — exposing passwords and session data.",

    "external subdomain footprint":
        "A complete map of your internet-facing systems is publicly available. "
        "Attackers use this to find forgotten entry points that are easier to break into.",

    "staff credentials found in breach":
        "Staff login details have leaked in third-party data breaches and are now "
        "available to criminals, who can use them to log into your systems.",

    "spf record missing":
        "There is no control preventing any server in the world from sending emails "
        "as your domain. This is the technical foundation for email fraud.",

    "spf record weak":
        "Your email sender controls exist but are not fully enforced — spoofed emails "
        "can still reach recipients' inboxes.",

    "dkim not configured":
        "Emails sent from your domain cannot be verified as authentic. "
        "Attackers can alter email content in transit without detection.",

    "certificate":
        "One or more security certificates are expired or about to expire. "
        "This creates warnings for users and opportunities for attackers to intercept traffic.",

    "dark web mentions":
        "Your organisation appears on dark web forums — possibly in discussions "
        "about your infrastructure or in listings selling access to your systems.",

    "rdp exposed":
        "Remote desktop access is open to the internet — the single most common "
        "entry point for ransomware attacks. Attackers scan for this continuously.",

    "database port":
        "One or more databases are directly reachable from the internet, allowing "
        "an attacker to extract all stored data without breaching any other system.",

    "ftp":
        "An unencrypted file transfer service is internet-accessible. Passwords "
        "sent over FTP are transmitted in plain text and easily intercepted.",

    "malicious":
        "Your domain has been flagged by security vendors, indicating past or "
        "current association with malicious activity.",
}


def _plain_english(finding_title: str) -> str:
    """Match finding title to a plain English summary."""
    title_lower = finding_title.lower()
    for key, summary in _PLAIN_ENGLISH.items():
        if key in title_lower:
            return summary
    # Fallback: trim the technical detail, return the title as-is
    return finding_title


# ── Risk context sentences ──────────────────────────────────────────────────────
# Translates a score + rating into a single sentence a board member understands.

def _risk_context(score: int, rating: str) -> str:
    if rating == "critical":
        return (
            f"A score of {score}/100 indicates critical exposure. "
            "Attackers can likely access or impersonate your organisation using "
            "publicly available information right now."
        )
    elif rating == "high":
        return (
            f"A score of {score}/100 indicates high exposure. "
            "Multiple significant gaps exist that a motivated attacker could exploit "
            "with minimal effort or cost."
        )
    elif rating == "medium":
        return (
            f"A score of {score}/100 indicates moderate exposure. "
            "Some important controls are missing or misconfigured. "
            "These should be addressed before they are exploited."
        )
    else:
        return (
            f"A score of {score}/100 indicates low overall exposure. "
            "The organisation maintains reasonable controls, "
            "but the findings below should still be addressed."
        )


# ── Drawings ───────────────────────────────────────────────────────────────────

def _gauge(score: int, rating: str) -> Drawing:
    d  = Drawing(100, 100)
    rc = RATING_COLOURS.get(rating.lower(), C_MUTED)
    bg = colors.HexColor("#E8E8E8")
    d.add(Wedge(50, 50, 40, 0, 360, fillColor=bg, strokeColor=None))
    d.add(Wedge(50, 50, 28, 0, 360, fillColor=C_WHITE, strokeColor=None))
    angle = max(score * 3.6, 0.01)
    d.add(Wedge(50, 50, 40, 90, 90 + angle, fillColor=rc, strokeColor=None))
    d.add(Wedge(50, 50, 28, 0, 360, fillColor=C_WHITE, strokeColor=None))
    d.add(String(50, 46, str(score), fontSize=18, fontName="Helvetica-Bold",
                 fillColor=rc, textAnchor="middle"))
    d.add(String(50, 32, "/100", fontSize=7, fontName="Helvetica",
                 fillColor=C_MUTED, textAnchor="middle"))
    d.add(String(50, 20, rating.upper(), fontSize=7, fontName="Helvetica-Bold",
                 fillColor=rc, textAnchor="middle"))
    return d


def _scorecard_compact(scorecard) -> Drawing:
    """Compact email scorecard for the one-pager."""
    W, H = PAGE_W - 2 * MARGIN - 2, 50
    d    = Drawing(W, H)
    gc   = colors.HexColor(scorecard.colour_hex)
    teal = colors.HexColor("#008080")

    d.add(Rect(0, 0, W, H, fillColor=C_BG_LIGHT,
               strokeColor=C_BORDER, strokeWidth=0.5))
    # Grade badge
    d.add(Rect(0, 0, 55, H, fillColor=gc, strokeColor=None))
    d.add(String(27, H - 32, scorecard.grade, fontSize=24,
                 fontName="Helvetica-Bold", fillColor=C_WHITE, textAnchor="middle"))
    d.add(String(27, 7, f"{scorecard.score}/100", fontSize=7,
                 fontName="Helvetica", fillColor=colors.HexColor("#EEEEEE"),
                 textAnchor="middle"))
    # Label
    d.add(String(27, H - 10, "EMAIL", fontSize=6, fontName="Helvetica-Bold",
                 fillColor=colors.HexColor("#EEEEEE"), textAnchor="middle"))

    # Three component bars
    bar_start = 65
    slot_w    = (W - bar_start - 8) / 3
    bar_h     = 11
    bar_y     = H / 2 - bar_h / 2
    components = [
        ("SPF",   scorecard.spf_score,   scorecard.spf_max),
        ("DMARC", scorecard.dmarc_score, scorecard.dmarc_max),
        ("DKIM",  scorecard.dkim_score,  scorecard.dkim_max),
    ]
    for i, (name, pts, max_pts) in enumerate(components):
        x      = bar_start + i * slot_w
        bar_w  = slot_w - 6
        fill_p = pts / max_pts if max_pts > 0 else 0
        d.add(String(x + bar_w / 2, bar_y + bar_h + 5, name, fontSize=7,
                     fontName="Helvetica-Bold", fillColor=C_TEXT,
                     textAnchor="middle"))
        d.add(Rect(x, bar_y, bar_w, bar_h,
                   fillColor=C_BORDER, strokeColor=None))
        if fill_p > 0:
            fc = gc if fill_p >= 1.0 else teal
            d.add(Rect(x, bar_y, bar_w * fill_p, bar_h,
                       fillColor=fc, strokeColor=None))
        d.add(String(x + bar_w / 2, bar_y - 9, f"{pts}/{max_pts}", fontSize=6.5,
                     fontName="Helvetica", fillColor=C_MUTED, textAnchor="middle"))

    # Rating
    d.add(String(W - 4, H / 2 - 3, scorecard.rating, fontSize=7.5,
                 fontName="Helvetica-Bold", fillColor=gc, textAnchor="end"))
    # Gold strip
    d.add(Rect(0, H - 2, W, 2, fillColor=C_ACCENT, strokeColor=None))
    return d


# ── Styles ─────────────────────────────────────────────────────────────────────

def _S():
    return {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold",
                                fontSize=16, textColor=C_WHITE, leading=20),
        "sub":   ParagraphStyle("sub",   fontName="Helvetica",
                                fontSize=9,  textColor=C_ACCENT, leading=12),
        "meta":  ParagraphStyle("meta",  fontName="Helvetica",
                                fontSize=7.5, textColor=colors.HexColor("#CCCCCC"),
                                leading=11),
        "h2":    ParagraphStyle("h2",    fontName="Helvetica-Bold",
                                fontSize=10, textColor=C_PRIMARY,
                                spaceBefore=4, spaceAfter=2),
        "body":  ParagraphStyle("body",  fontName="Helvetica",
                                fontSize=8.5, textColor=C_TEXT, leading=12),
        "small": ParagraphStyle("small", fontName="Helvetica",
                                fontSize=7.5, textColor=C_TEXT, leading=11),
        "muted": ParagraphStyle("muted", fontName="Helvetica",
                                fontSize=7,   textColor=C_MUTED, leading=10),
        "metric_v": ParagraphStyle("mv",  fontName="Helvetica-Bold",
                                   fontSize=16, textColor=C_PRIMARY,
                                   alignment=TA_CENTER, leading=20),
        "metric_l": ParagraphStyle("ml",  fontName="Helvetica",
                                   fontSize=6.5, textColor=C_MUTED,
                                   alignment=TA_CENTER, leading=9),
        "track_hdr": ParagraphStyle("th", fontName="Helvetica-Bold",
                                    fontSize=7.5, textColor=C_WHITE,
                                    alignment=TA_CENTER, leading=10),
        "track_body": ParagraphStyle("tb", fontName="Helvetica",
                                     fontSize=7.5, textColor=C_TEXT, leading=11),
        "finding_no": ParagraphStyle("fn", fontName="Helvetica-Bold",
                                     fontSize=14, textColor=C_WHITE,
                                     alignment=TA_CENTER, leading=18),
        "finding_title": ParagraphStyle("ft", fontName="Helvetica-Bold",
                                        fontSize=8.5, textColor=C_TEXT, leading=12),
        "finding_body": ParagraphStyle("fb", fontName="Helvetica",
                                       fontSize=8, textColor=C_TEXT, leading=12),
        "cta": ParagraphStyle("cta", fontName="Helvetica",
                               fontSize=8, textColor=colors.HexColor("#004D40"),
                               leading=12),
    }


# ── Header / footer ────────────────────────────────────────────────────────────

def _hf(canvas, doc, target: str, date_str: str, config: dict):
    canvas.saveState()
    w, h = A4

    # Header
    canvas.setFillColor(C_DARK)
    canvas.rect(0, h - 15 * mm, w, 15 * mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, h - 15 * mm, 3 * mm, 15 * mm, fill=1, stroke=0)

    logo_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "assets", "afriwealth_logo.png"
    )
    if os.path.exists(logo_path):
        canvas.drawImage(logo_path, MARGIN, h - 13 * mm,
                         width=22 * mm, height=7 * mm,
                         preserveAspectRatio=True, mask="auto")
    else:
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C_WHITE)
        canvas.drawString(MARGIN, h - 8 * mm, config["brand"]["name"])

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#AAAAAA"))
    canvas.drawString(MARGIN + 60, h - 8 * mm,
                      "| SankofahEye — Executive Security Briefing")
    canvas.drawRightString(w - MARGIN, h - 8 * mm,
                           f"Target: {target}   |   {date_str}")

    # Footer
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, w, 9 * mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, 0, 3 * mm, 9 * mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 6.5)
    canvas.setFillColor(colors.HexColor("#AAAAAA"))
    canvas.drawString(MARGIN, 4 * mm,
                      "CONFIDENTIAL — For authorised recipients only — "
                      "Passive reconnaissance only — No active exploitation performed")
    canvas.drawRightString(w - MARGIN, 4 * mm,
                           f"AfriWealth Cyber Intelligence  |  "
                           f"{config['brand'].get('website', 'afriwealthci.com')}")
    canvas.restoreState()


# ── Remediation track builder ───────────────────────────────────────────────────

def _plain_action(recommendation: str) -> str:
    """
    Strip technical jargon from recommendation text for exec audience.
    Returns a concise plain-English action.
    """
    # Truncate long recommendations
    if len(recommendation) > 130:
        recommendation = recommendation[:128] + "…"
    return recommendation


def _build_tracks(findings: list) -> tuple:
    """Returns (track_72h, track_30d, track_90d) as lists of plain-English strings."""
    track_72h, track_30d, track_90d = [], [], []
    sev_map = {"critical": track_72h, "high": track_72h,
               "medium": track_30d,   "low": track_90d}

    for f in findings[:10]:
        sev   = f.get("severity", "low")
        track = sev_map.get(sev, track_90d)
        rec   = _plain_action(f.get("recommendation", ""))
        if rec and len(track) < 4:
            track.append(rec)

    # Always ensure track 3 has the ongoing monitoring item
    track_90d.append(
        "Schedule quarterly passive exposure assessments to track "
        "risk score trends over time. Report findings to board."
    )
    return track_72h[:4], track_30d[:4], track_90d[:3]


# ── Main generator ──────────────────────────────────────────────────────────────

def generate(
    findings: dict,
    scoring:  dict,
    config:   dict,
    output_dir: str,
) -> str:
    """
    Generate the executive one-pager PDF.
    Called automatically by sankofaeye.py after the main report.

    Args:
        findings:   Full aggregated findings dict
        scoring:    Risk scoring dict
        config:     SankofahEye config dict
        output_dir: Directory to write the PDF

    Returns:
        Path to the generated PDF
    """
    os.makedirs(output_dir, exist_ok=True)
    target    = findings.get("target", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"SankofahEye_{target}_executive_summary_{timestamp}.pdf"
    filepath  = os.path.join(output_dir, filename)

    log.info(f"[ExecOnePager] Generating → {filepath}")

    date_str = datetime.now().strftime("%d %B %Y")
    analyst  = config.get("brand", {}).get("analyst", "DeCyberGuardian")
    S        = _S()

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=19 * mm,
        bottomMargin=13 * mm,
        title=f"SankofahEye Executive Summary — {target}",
        author=config.get("brand", {}).get("name", "AfriWealth Cyber Intelligence"),
    )

    story = []

    # ── TITLE BLOCK ─────────────────────────────────────────────────────────
    logo_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "assets", "afriwealth_logo.png"
    )
    logo_cell = (RLImage(logo_path, width=30 * mm, height=10 * mm)
                 if os.path.exists(logo_path)
                 else Paragraph(config.get("brand", {}).get("name", ""), S["sub"]))

    title_row = Table(
        [[logo_cell,
          Paragraph("EXECUTIVE SECURITY BRIEFING", S["title"]),
          ""]],
        colWidths=[35 * mm, PAGE_W - 2 * MARGIN - 50 * mm, 15 * mm],
    )
    title_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("LINEABOVE",     (0, 0), (-1,  0), 3, C_ACCENT),
    ]))
    story.append(title_row)

    meta_row = Table(
        [[Paragraph(
            f"Target: <b>{target}</b>   |   Date: {date_str}   |   "
            f"Analyst: {analyst}   |   "
            f"Prepared by: {config.get('brand', {}).get('name', 'AfriWealth Cyber Intelligence')}",
            S["meta"]
        )]],
        colWidths=[PAGE_W - 2 * MARGIN],
    )
    meta_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(meta_row)
    story.append(Spacer(1, 3 * mm))

    # ── RISK SCORE + METRICS ─────────────────────────────────────────────────
    score  = scoring.get("score",  0)
    rating = scoring.get("rating", "low")

    sub_count   = findings.get("subdomains",           {}).get("count",           0)
    host_count  = findings.get("exposed_services",     {}).get("total_hosts",     0)
    breach_cnt  = findings.get("credential_exposure",  {}).get("total_breached",  0)
    dw_cnt      = findings.get("dark_web",             {}).get("total_mentions",  0)
    finding_cnt = scoring.get("finding_count", 0)

    def _metric(val, label):
        return [Paragraph(str(val), S["metric_v"]),
                Paragraph(label,   S["metric_l"])]

    gauge = _gauge(score, rating)

    metrics_row = [
        [gauge],
        _metric(sub_count,   "Subdomains\nMapped"),
        _metric(host_count,  "Exposed\nHosts"),
        _metric(breach_cnt,  "Breached\nAccounts"),
        _metric(dw_cnt,      "Dark Web\nMentions"),
        _metric(finding_cnt, "Total\nFindings"),
    ]
    gauge_w  = 26 * mm
    metric_w = (PAGE_W - 2 * MARGIN - gauge_w) / 5

    metrics_table = Table(
        [metrics_row],
        colWidths=[gauge_w] + [metric_w] * 5,
        rowHeights=[26 * mm],
    )
    metrics_table.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",    (0, 0), (0,  0),  C_BG_LIGHT),
        ("BACKGROUND",    (1, 0), (-1, 0),  C_WHITE),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(metrics_table)

    # Risk context sentence
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(_risk_context(score, rating), S["muted"]))
    story.append(Spacer(1, 3 * mm))

    # ── WHAT WE FOUND ────────────────────────────────────────────────────────
    story.append(Paragraph("What We Found", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=C_PRIMARY, spaceAfter=3))

    top_findings = scoring.get("findings", [])[:3]

    if top_findings:
        finding_cells = []
        for i, f in enumerate(top_findings, 1):
            sev     = f.get("severity", "low")
            sev_col = RATING_COLOURS.get(sev.lower(), C_MUTED)
            title   = f.get("finding", "")
            plain   = _plain_english(title)

            # Number badge + title + plain description in one cell
            inner = Table(
                [[Paragraph(str(i), S["finding_no"]),
                  Table(
                      [[Paragraph(title, S["finding_title"])],
                       [Paragraph(plain, S["finding_body"])]],
                      colWidths=[(PAGE_W - 2 * MARGIN) / 3 - 18 * mm],
                  )]],
                colWidths=[10 * mm,
                           (PAGE_W - 2 * MARGIN) / 3 - 18 * mm],
            )
            inner.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (0, 0),   sev_col),
                ("BACKGROUND",    (1, 0), (1, 0),   C_WHITE),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (0,  0),  0),
                ("LEFTPADDING",   (1, 0), (1,  0),  5),
                ("BOX",           (0, 0), (-1, -1), 0.5, sev_col),
            ]))
            finding_cells.append(inner)

        # Pad to 3 if fewer findings
        while len(finding_cells) < 3:
            finding_cells.append(Paragraph("", S["body"]))

        findings_row = Table(
            [finding_cells],
            colWidths=[(PAGE_W - 2 * MARGIN) / 3] * 3,
        )
        findings_row.setStyle(TableStyle([
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 2),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(findings_row)
    else:
        story.append(Paragraph(
            "No significant findings detected.", S["body"]))

    story.append(Spacer(1, 3 * mm))

    # ── WHAT TO DO NEXT ──────────────────────────────────────────────────────
    story.append(Paragraph("What To Do Next", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=C_PRIMARY, spaceAfter=3))

    track_72h, track_30d, track_90d = _build_tracks(
        scoring.get("findings", []))

    track_col_w = (PAGE_W - 2 * MARGIN) / 3

    def _track_table(label, col, items):
        rows = [[Paragraph(label, S["track_hdr"])]]
        for item in items:
            rows.append([Paragraph(f"• {item}", S["track_body"])])
        if not items:
            rows.append([Paragraph("No actions required.", S["muted"])])
        t = Table(rows, colWidths=[track_col_w - 4])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0),   col),
            ("BACKGROUND",    (0, 1), (0, -1),  C_WHITE),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ]))
        return t

    tracks_table = Table(
        [[_track_table("WITHIN 72 HOURS",  C_CRITICAL, track_72h),
          _track_table("WITHIN 30 DAYS",   C_HIGH,     track_30d),
          _track_table("WITHIN 90 DAYS",   C_PRIMARY,  track_90d)]],
        colWidths=[track_col_w] * 3,
    )
    tracks_table.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(tracks_table)
    story.append(Spacer(1, 3 * mm))

    # ── EMAIL SECURITY SCORECARD ─────────────────────────────────────────────
    story.append(Paragraph("Email Security Scorecard", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=C_PRIMARY, spaceAfter=3))

    dns_sec = findings.get("dns_security", {})
    try:
        scorecard = score_email_security(dns_sec)
        story.append(_scorecard_compact(scorecard))
        story.append(Spacer(1, 2 * mm))
        # One plain-English sentence about email security posture
        if scorecard.grade in ("F", "D"):
            story.append(Paragraph(
                "Email authentication controls are critically insufficient. "
                "Your domain can be impersonated by anyone — no technical skill required.",
                S["muted"]
            ))
        elif scorecard.grade == "C":
            story.append(Paragraph(
                "Email security controls are partially in place but not fully enforced. "
                "Spoofed emails may still reach your staff or customers.",
                S["muted"]
            ))
        elif scorecard.grade == "B":
            story.append(Paragraph(
                "Email security is mostly in place. Minor gaps remain that should be "
                "resolved to reach full protection.",
                S["muted"]
            ))
        else:
            story.append(Paragraph(
                "Email authentication meets best practice. "
                "Domain spoofing risk is well controlled.",
                S["muted"]
            ))
    except Exception as e:
        log.warning(f"[ExecOnePager] Scorecard skipped: {e}")
        story.append(Paragraph("Email security data unavailable.", S["muted"]))

    story.append(Spacer(1, 3 * mm))

    # ── CTA BOX ──────────────────────────────────────────────────────────────
    cta = Table(
        [[Paragraph(
            "<b>Need help acting on these findings?</b> AfriWealth Cyber Intelligence "
            "provides hands-on remediation support, ongoing passive monitoring, and "
            "threat-informed advisory services for organisations across Ghana and West Africa. "
            f"Contact: <b>{config.get('brand', {}).get('website', 'afriwealthci.com')}</b>",
            S["cta"]
        )]],
        colWidths=[PAGE_W - 2 * MARGIN - 2],
    )
    cta.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#E8F5E9")),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_LOW),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(cta)

    # ── BUILD ────────────────────────────────────────────────────────────────
    doc.build(
        story,
        onFirstPage=lambda c, d: _hf(c, d, target, date_str, config),
        onLaterPages=lambda c, d: _hf(c, d, target, date_str, config),
    )

    log.info(f"[ExecOnePager] Saved → {filepath}")
    return filepath