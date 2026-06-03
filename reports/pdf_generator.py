"""
SankofaEye — PDF Report Generator
AfriWealth Cyber Intelligence

Generates a branded Exposure Report in PDF format using ReportLab.
"""

from logging import config
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Wedge, Circle, String, Rect
from reportlab.graphics import renderPDF
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from utils.logger import SankofaLogger
from utils.email_scorer import score_email_security

# Correctly integrated modular attack path utils
from utils.attack_path import build_attack_path, get_killchain_flowable
from reportlab.platypus import Image as RLImage


log = SankofaLogger("pdf_generator")

# ── Brand colours ─────────────────────────────────────────────
C_DARK       = colors.HexColor("#005F5F")
C_PRIMARY    = colors.HexColor("#008080")
C_ACCENT     = colors.HexColor("#FFD700")
C_CRITICAL   = colors.HexColor("#D32F2F")
C_HIGH       = colors.HexColor("#F57C00")
C_MEDIUM     = colors.HexColor("#FBC02D")
C_LOW        = colors.HexColor("#388E3C")
C_INFO       = colors.HexColor("#1565C0")
C_BG_LIGHT   = colors.HexColor("#F5F5F5")
C_BORDER     = colors.HexColor("#E0E0E0")
C_WHITE      = colors.white
C_TEXT       = colors.HexColor("#212121")
C_MUTED      = colors.HexColor("#757575")

SEVERITY_COLOURS = {
    "critical": C_CRITICAL,
    "high":     C_HIGH,
    "medium":   C_MEDIUM,
    "low":      C_LOW,
    "informational": C_INFO,
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


def build_styles():
    styles = getSampleStyleSheet()
    custom = {
        "Cover_Title": ParagraphStyle("Cover_Title", fontName="Helvetica-Bold",
            fontSize=28, textColor=C_WHITE, leading=34, alignment=TA_LEFT),
        "Cover_Sub": ParagraphStyle("Cover_Sub", fontName="Helvetica",
            fontSize=13, textColor=C_ACCENT, leading=18, alignment=TA_LEFT),
        "Cover_Meta": ParagraphStyle("Cover_Meta", fontName="Helvetica",
            fontSize=10, textColor=colors.HexColor("#CCCCCC"), leading=14, alignment=TA_LEFT),
        "Section_H": ParagraphStyle("Section_H", fontName="Helvetica-Bold",
            fontSize=14, textColor=C_PRIMARY, leading=20, spaceBefore=12, spaceAfter=6),
        "Body": ParagraphStyle("Body", fontName="Helvetica",
            fontSize=9, textColor=C_TEXT, leading=13, spaceAfter=4),
        "Body_Bold": ParagraphStyle("Body_Bold", fontName="Helvetica-Bold",
            fontSize=9, textColor=C_TEXT, leading=13),
        "Small": ParagraphStyle("Small", fontName="Helvetica",
            fontSize=8, textColor=C_MUTED, leading=11),
        "Finding_Title": ParagraphStyle("Finding_Title", fontName="Helvetica-Bold",
            fontSize=10, textColor=C_TEXT, leading=14),
        "Code": ParagraphStyle("Code", fontName="Courier",
            fontSize=8, textColor=C_TEXT, leading=11, backColor=C_BG_LIGHT),
        "Footer": ParagraphStyle("Footer", fontName="Helvetica",
            fontSize=7, textColor=C_MUTED, alignment=TA_CENTER),
        "Right": ParagraphStyle("Right", fontName="Helvetica",
            fontSize=9, textColor=C_TEXT, alignment=TA_RIGHT),
        "Mitre": ParagraphStyle("Mitre", fontName="Courier",
            fontSize=8, textColor=C_INFO, leading=11),
    }
    return custom


def severity_badge(severity: str) -> str:
    labels = {
        "critical": "● CRITICAL",
        "high":     "● HIGH",
        "medium":   "● MEDIUM",
        "low":      "● LOW",
        "informational": "● INFO",
    }
    return labels.get(severity.lower(), severity.upper())


def draw_risk_gauge(score: int, rating: str) -> Drawing:
    d = Drawing(160, 160)
    colour_map = {
        "critical": C_CRITICAL, "high": C_HIGH,
        "medium": C_MEDIUM, "low": C_LOW,
    }
    ring_colour = colour_map.get(rating, C_INFO)
    bg_colour   = colors.HexColor("#E8E8E8")
    d.add(Wedge(80, 80, 60, 0, 360, fillColor=bg_colour, strokeColor=None))
    d.add(Wedge(80, 80, 45, 0, 360, fillColor=C_WHITE, strokeColor=None))
    angle = max(score * 3.6, 0.01)
    d.add(Wedge(80, 80, 60, 90, 90 + angle, fillColor=ring_colour, strokeColor=None))
    d.add(Wedge(80, 80, 45, 0, 360, fillColor=C_WHITE, strokeColor=None))
    d.add(String(80, 78, str(score), fontSize=22, fontName="Helvetica-Bold",
                 fillColor=ring_colour, textAnchor="middle"))
    d.add(String(80, 60, "/100", fontSize=9, fontName="Helvetica",
                 fillColor=C_MUTED, textAnchor="middle"))
    d.add(String(80, 44, rating.upper(), fontSize=9, fontName="Helvetica-Bold",
                 fillColor=ring_colour, textAnchor="middle"))
    return d


def draw_email_scorecard(scorecard) -> Drawing:
    """
    Full-width email security scorecard visual.
    Shows A-F grade badge + SPF/DMARC/DKIM component bars.
    """
    W, H = 480, 110
    d = Drawing(W, H)

    gc      = colors.HexColor(scorecard.colour_hex)
    muted   = colors.HexColor("#757575")
    dark    = colors.HexColor("#212121")
    bg      = colors.HexColor("#F5F5F5")
    gold    = colors.HexColor("#FFD700")
    teal    = colors.HexColor("#008080")

    d.add(Rect(0, 0, W, H, fillColor=bg,
               strokeColor=colors.HexColor("#E0E0E0"), strokeWidth=0.5))

    d.add(Rect(0, 0, 110, H, fillColor=gc, strokeColor=None))
    d.add(String(55, 54, scorecard.grade, fontSize=46, fontName="Helvetica-Bold",
                 fillColor=colors.white, textAnchor="middle"))
    d.add(String(55, 36, scorecard.rating.upper(), fontSize=9,
                 fontName="Helvetica-Bold", fillColor=colors.white,
                 textAnchor="middle"))
    d.add(String(55, 20, f"{scorecard.score}/100", fontSize=9,
                 fontName="Helvetica", fillColor=colors.HexColor("#EEEEEE"),
                 textAnchor="middle"))
    d.add(String(55, H - 16, "EMAIL SECURITY", fontSize=7,
                 fontName="Helvetica-Bold",
                 fillColor=colors.HexColor("#EEEEEE"), textAnchor="middle"))

    bar_x     = 125
    bar_w_max = 290
    bar_h     = 14
    score_x   = bar_x + bar_w_max + 8
    components = [
        ("SPF",   scorecard.spf_score,   scorecard.spf_max,   scorecard.spf_label),
        ("DMARC", scorecard.dmarc_score, scorecard.dmarc_max, scorecard.dmarc_label),
        ("DKIM",  scorecard.dkim_score,  scorecard.dkim_max,  scorecard.dkim_label),
    ]
    row_y_start = H - 28
    row_gap     = 24

    for i, (name, pts, max_pts, label) in enumerate(components):
        y = row_y_start - i * row_gap
        d.add(String(bar_x - 5, y - 4, name, fontSize=8,
                     fontName="Helvetica-Bold", fillColor=dark, textAnchor="end"))
        d.add(Rect(bar_x, y - bar_h + 2, bar_w_max, bar_h,
                   fillColor=colors.HexColor("#E0E0E0"), strokeColor=None))
        fill_w = int((pts / max_pts) * bar_w_max) if max_pts > 0 else 0
        bar_fill = gc if pts >= max_pts else (
            teal if pts > 0 else colors.HexColor("#D32F2F")
        )
        if fill_w > 0:
            d.add(Rect(bar_x, y - bar_h + 2, fill_w, bar_h,
                       fillColor=bar_fill, strokeColor=None))
        d.add(String(score_x, y - 4, f"{pts}/{max_pts}", fontSize=8,
                     fontName="Helvetica", fillColor=muted, textAnchor="start"))
        short = label if len(label) <= 32 else label[:30] + "..."
        txt_c = colors.white if fill_w > 70 else dark
        d.add(String(bar_x + 4, y - 4, short, fontSize=7,
                     fontName="Helvetica", fillColor=txt_c, textAnchor="start"))

    summary_y = row_y_start - 3 * row_gap + 4
    summary   = scorecard.summary[:92] + ("..." if len(scorecard.summary) > 92 else "")
    d.add(String(bar_x, summary_y, summary, fontSize=7,
                 fontName="Helvetica", fillColor=muted, textAnchor="start"))

    d.add(Rect(0, H - 3, W, 3, fillColor=gold, strokeColor=None))
    return d


def header_footer(canvas, doc, config: dict, target: str):
    """Draw header and footer on every page."""
    canvas.saveState()
    w, h = A4

    canvas.setFillColor(C_DARK)
    canvas.rect(0, h - 18*mm, w, 18*mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, h - 18*mm, 3*mm, 18*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(C_WHITE)
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "assets", "afriwealth_logo.png")
    if os.path.exists(logo_path):
        canvas.drawImage(logo_path, MARGIN, h - 16*mm, width=28*mm, height=10*mm,
                         preserveAspectRatio=True, mask="auto")
    else:
        canvas.drawString(MARGIN, h - 11*mm, config["brand"]["tool"])
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#AAAAAA"))
    canvas.drawString(MARGIN + 70, h - 11*mm, f"| {config['brand']['name']}")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - MARGIN, h - 11*mm, f"Target: {target}")

    canvas.setFillColor(C_BG_LIGHT)
    canvas.rect(0, 0, w, 12*mm, fill=1, stroke=0)
    canvas.setFillColor(C_BORDER)
    canvas.rect(0, 12*mm, w, 0.3*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(MARGIN, 5*mm,
        f"{config['brand']['name']} — {config['brand']['tool']} "
        f"v{config['brand']['version']} — "
        f"CONFIDENTIAL — Passive reconnaissance only — Not for public distribution"
    )
    canvas.drawRightString(w - MARGIN, 5*mm, f"Page {doc.page}")
    canvas.restoreState()


def generate(findings: dict, scoring: dict, config: dict, output_dir: str) -> str:
    """
    Main entry point. Generates the branded PDF report.
    Returns the output file path.
    """
    os.makedirs(output_dir, exist_ok=True)
    target    = findings["target"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"SankofaEye_{target}_{timestamp}.pdf"
    filepath  = os.path.join(output_dir, filename)

    log.info(f"[PDF] Generating report → {filepath}")

    # Process and build attack path structures locally
    attack_path = build_attack_path(findings, scoring) if findings else None

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=22*mm, bottomMargin=16*mm,
    )

    S = build_styles()
    story = []

    # ── COVER PAGE ────────────────────────────────────────────
    story.append(Spacer(1, 30*mm))

    logo_path = os.path.join(os.path.dirname(__file__), "..", "assets",
                             "afriwealth_logo.png")
    logo_cell = (RLImage(logo_path, width=60*mm, height=20*mm)
                 if os.path.exists(logo_path)
                 else Paragraph("AfriWealth Cyber Intelligence", S["Cover_Sub"]))

    cover_header = Table(
        [[logo_cell],
         [Spacer(1, 3*mm)],
         [Paragraph(config["brand"]["tool"], S["Cover_Title"])],
         [Paragraph("Passive Exposure Intelligence Report", S["Cover_Sub"])],
         [Spacer(1, 4*mm)],
         [Paragraph(f"<b>Target:</b>  {target}", S["Cover_Meta"])],
         [Paragraph(f"<b>Date:</b>    {datetime.now().strftime('%d %B %Y, %H:%M UTC')}",
                    S["Cover_Meta"])],
         [Paragraph(f"<b>Analyst:</b> {config['brand'].get('analyst', 'DeCyberGuardian')}",
                    S["Cover_Meta"])],
         [Paragraph(f"<b>Prepared by:</b> {config['brand']['name']}", S["Cover_Meta"])],
        ],
        colWidths=[PAGE_W - 2*MARGIN],
    )
    cover_header.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("LINEABOVE",     (0, 0), (-1,  0), 3, C_ACCENT),
    ]))
    story.append(cover_header)
    story.append(Spacer(1, 8*mm))

    gauge = draw_risk_gauge(scoring["score"], scoring["rating"])
    cover_score_table = Table(
        [[gauge, Table(
            [[Paragraph("Overall Risk Score", S["Section_H"])],
             [Paragraph(
                f"<b>{scoring['score']}/100</b> — "
                f"<font color='#{scoring['colour'][1:]}'>"
                f"{scoring['rating'].upper()}</font>",
                S["Body"])],
             [Spacer(1, 2*mm)],
             [Paragraph(f"Total findings: <b>{scoring['finding_count']}</b>",
                        S["Body"])],
             [Paragraph(
                f"MITRE techniques: <b>{len(scoring.get('mitre_techniques', []))}</b>",
                S["Body"])],
            ],
            colWidths=[PAGE_W - 2*MARGIN - 175],
        )]],
        colWidths=[175, PAGE_W - 2*MARGIN - 175],
    )
    cover_score_table.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",   (0, 0), (-1, -1), C_BG_LIGHT),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(cover_score_table)
    story.append(Spacer(1, 6*mm))

    disclaimer = Table(
        [[Paragraph(
            "⚠ CONFIDENTIAL — This report contains sensitive security information. "
            "Distribute only to authorised personnel. Passive reconnaissance only — "
            "no active exploitation was performed.",
            ParagraphStyle("disc", fontName="Helvetica", fontSize=8,
                           textColor=colors.HexColor("#7B3F00"), leading=11)
        )]],
        colWidths=[PAGE_W - 2*MARGIN],
    )
    disclaimer.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FFF8E1")),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_MEDIUM),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(disclaimer)
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    sub_count    = findings["subdomains"]["count"]
    email_count  = findings["emails"]["count"]
    breach_count = findings["credential_exposure"]["total_breached"]
    host_count   = findings["exposed_services"]["total_hosts"]
    dw_count     = findings["dark_web"]["total_mentions"]

    for line in [
        f"SankofaEye conducted a passive reconnaissance assessment of <b>{target}</b> on "
        f"{datetime.now().strftime('%d %B %Y')}. The scan leveraged open-source intelligence "
        f"(OSINT) sources including Subfinder, theHarvester, Shodan, Have I Been Pwned, "
        f"VirusTotal, URLScan.io, and dark web indexed search. No active exploitation was performed.",
        "",
        f"The assessment identified <b>{sub_count} subdomains</b>, "
        f"<b>{email_count} email addresses</b>, "
        f"<b>{host_count} internet-facing hosts</b>, and "
        f"<b>{breach_count} breached account(s)</b>. "
        f"Dark web monitoring returned <b>{dw_count} mention(s)</b> of the target domain.",
        "",
        f"The overall exposure risk is rated "
        f"<b>{scoring['rating'].upper()} ({scoring['score']}/100)</b>. "
        f"Immediate remediation is recommended for all Critical and High severity "
        f"findings listed in this report.",
    ]:
        story.append(Paragraph(line, S["Body"]))
    story.append(Spacer(1, 4*mm))

    stats_data = [
        [Paragraph(f"<b>{sub_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{host_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{breach_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{dw_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{len(findings['exposed_services']['cves'])}</b>",
                   S["Section_H"])],
        [Paragraph("Subdomains",       S["Small"]),
         Paragraph("Exposed Hosts",    S["Small"]),
         Paragraph("Breached Accounts",S["Small"]),
         Paragraph("Dark Web Mentions",S["Small"]),
         Paragraph("CVEs Detected",    S["Small"])],
    ]
    col_w = (PAGE_W - 2*MARGIN) / 5
    stats_table = Table(stats_data, colWidths=[col_w]*5)
    stats_table.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",    (0, 0), (-1,  0), C_DARK),
        ("TEXTCOLOR",     (0, 0), (-1,  0), C_WHITE),
        ("BACKGROUND",    (0, 1), (-1, -1), C_BG_LIGHT),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.25, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 6*mm))

    # ── VISUAL ATTACK PATH INJECTION ──────────────────────────
    _has_kc = bool(attack_path) and (
        attack_path.get("has_path")
        or attack_path.get("stages")
        or attack_path.get("path")
    )
    if _has_kc:
        killchain_flowable = get_killchain_flowable(attack_path)
        if killchain_flowable:
            story.append(Paragraph("Visualized Threat Killchain Flow", S["Section_H"]))
            story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=4))
            story.append(killchain_flowable)
            story.append(Spacer(1, 6*mm))

    # ── FINDINGS ──────────────────────────────────────────────
    story.append(Paragraph("Findings & Risk Analysis", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    for i, finding in enumerate(scoring["findings"], 1):
        sev        = finding["severity"].lower()
        sev_colour = SEVERITY_COLOURS.get(sev, C_INFO)

        badge_style = ParagraphStyle(
            f"badge_{i}", fontName="Helvetica-Bold",
            fontSize=8, textColor=C_WHITE,
        )

        finding_table = Table(
            [[Paragraph(severity_badge(sev), badge_style),
              Paragraph(f"<b>{i}. {finding['finding']}</b>", S["Finding_Title"])]],
            colWidths=[22*mm, PAGE_W - 2*MARGIN - 22*mm],
        )
        finding_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), sev_colour),
            ("BACKGROUND",    (1, 0), (1, 0), colors.HexColor("#FAFAFA")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (0, 0), (0,  0), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("BOX",           (0, 0), (-1, -1), 0.5, sev_colour),
        ]))

        detail_table = Table(
            [[Paragraph("Detail:", S["Body_Bold"]),
              Paragraph(finding["detail"], S["Body"])],
             [Paragraph("Recommendation:", S["Body_Bold"]),
              Paragraph(finding["recommendation"], S["Body"])],
             [Paragraph("MITRE ATT&CK:", S["Body_Bold"]),
              Paragraph(
                  f"{finding['mitre']['id']} — {finding['mitre']['name']}",
                  S["Mitre"])]],
            colWidths=[32*mm, PAGE_W - 2*MARGIN - 32*mm],
        )
        detail_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))

        atk = finding.get("attack_scenario", {})
        scenario_elements = []
        if atk:
            scenario_header = Table(
                [[Paragraph("⚠ Attack Scenario & Threat Impact",
                    ParagraphStyle("atk_hdr", fontName="Helvetica-Bold",
                                   fontSize=9, textColor=C_WHITE))]],
                colWidths=[PAGE_W - 2*MARGIN],
            )
            scenario_header.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#B71C1C")),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            scenario_body = Table(
                [[Paragraph("How it would be exploited:", S["Body_Bold"]),
                  Paragraph(atk.get("scenario", ""), S["Body"])],
                 [Paragraph("Potential impact:", S["Body_Bold"]),
                  Paragraph(atk.get("impact", ""), S["Body"])],
                 [Paragraph("Likelihood:", S["Body_Bold"]),
                  Paragraph(atk.get("likelihood", ""), S["Body"])],
                 [Paragraph("Threat actors:", S["Body_Bold"]),
                  Paragraph(atk.get("threat_actors", ""), S["Body"])]],
                colWidths=[32*mm, PAGE_W - 2*MARGIN - 32*mm],
            )
            scenario_body.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FFEBEE")),
                ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#FFCDD2")),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            scenario_elements = [scenario_header, scenario_body]

        story.append(KeepTogether(
            [finding_table, detail_table] + scenario_elements + [Spacer(1, 6*mm)]
        ))

    story.append(PageBreak())

    # ── MOBILE MONEY EXPOSURE ────────────────────────────────
    momo = findings.get("momo_exposure", {})
    if momo.get("exposed_services"):
        story.append(Paragraph("Mobile Money Exposure Analysis", S["Section_H"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

        operator = momo.get("operator", "Unknown")
        story.append(Paragraph(
            f"<b>Operator detected:</b> {operator}  |  "
            f"<b>Exposed MoMo services:</b> {momo.get('total_exposed', 0)}  |  "
            f"<b>Findings:</b> {len(momo.get('findings', []))}",
            S["Body"]
        ))
        story.append(Spacer(1, 3*mm))

        svc_data = [[
            Paragraph("Subdomain",    S["Body_Bold"]),
            Paragraph("Service Type", S["Body_Bold"]),
            Paragraph("Severity",     S["Body_Bold"]),
            Paragraph("MITRE",        S["Body_Bold"]),
        ]]
        sev_colours = {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
                       "MEDIUM": C_MEDIUM, "LOW": C_LOW}
        for svc in momo.get("exposed_services", [])[:15]:
            sev = svc.get("severity", "LOW")
            svc_data.append([
                Paragraph(svc.get("subdomain", "")[:45], S["Code"]),
                Paragraph(svc.get("service_name", ""), S["Body"]),
                Paragraph(sev, ParagraphStyle("ms", fontName="Helvetica-Bold",
                                              fontSize=8,
                                              textColor=sev_colours.get(sev, C_MUTED))),
                Paragraph(svc.get("mitre", ""), S["Mitre"]),
            ])

        svc_table = Table(svc_data,
                          colWidths=[65*mm, 45*mm, 22*mm, 22*mm])
        svc_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1,  0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1,  0), C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(svc_table)
        story.append(Spacer(1, 4*mm))
        story.append(PageBreak())

    # ── REGULATORY COMPLIANCE ────────────────────────────────
    compliance = findings.get("compliance", {})
    if compliance:
        story.append(Paragraph("Regulatory Compliance Assessment", S["Section_H"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))
        sector_info = findings.get("sector", {})
        sector_line = ""
        if sector_info.get("label"):
            reg = "regulated" if sector_info.get("is_regulated") else "non-regulated"
            sector_line = (
                f" Target assessed as <b>{sector_info['label']}</b> ({reg}); "
                f"only frameworks applicable to this sector are shown."
            )
        story.append(Paragraph(
            "The following assessment maps passive scan findings to Ghana regulatory "
            "frameworks. This is intelligence-led guidance — not legal advice." + sector_line,
            S["Body"]
        ))
        story.append(Spacer(1, 4*mm))

        fw_summary = [[
            Paragraph("Framework", S["Body_Bold"]),
            Paragraph("Score",     S["Body_Bold"]),
            Paragraph("Status",    S["Body_Bold"]),
            Paragraph("Controls Passing", S["Body_Bold"]),
            Paragraph("Applies To", S["Body_Bold"]),
        ]]
        status_labels = {
            "compliant":     "COMPLIANT",
            "partial":       "PARTIAL",
            "non_compliant": "NON-COMPLIANT",
        }
        for fw_key, fw in compliance.items():
            sc = fw["score"]
            col = colors.HexColor(fw["colour"])
            fw_summary.append([
                Paragraph(fw["short"], S["Body_Bold"]),
                Paragraph(f"{sc}%",
                    ParagraphStyle("fws", fontName="Helvetica-Bold",
                                   fontSize=10, textColor=col)),
                Paragraph(status_labels.get(fw["status"], fw["status"]),
                    ParagraphStyle("fwst", fontName="Helvetica-Bold",
                                   fontSize=8, textColor=col)),
                Paragraph(f"{fw['passed']}/{fw['total']}", S["Body"]),
                Paragraph(fw["applies_to"][:60], S["Small"]),
            ])

        fw_table = Table(fw_summary,
                         colWidths=[38*mm, 18*mm, 32*mm, 28*mm,
                                    PAGE_W - 2*MARGIN - 116*mm])
        fw_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1,  0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1,  0), C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(fw_table)
        story.append(Spacer(1, 5*mm))

        for fw_key, fw in compliance.items():
            gaps = fw.get("gaps", [])
            if not gaps:
                continue

            story.append(Paragraph(
                f"{fw['short']} — Control Gaps ({len(gaps)} of {fw['total']} controls failing)",
                S["Body_Bold"]
            ))
            story.append(Spacer(1, 2*mm))

            gap_data = [[
                Paragraph("Control",     S["Body_Bold"]),
                Paragraph("Section",     S["Body_Bold"]),
                Paragraph("Severity",    S["Body_Bold"]),
                Paragraph("Remediation", S["Body_Bold"]),
            ]]
            sev_colours = {"critical": C_CRITICAL, "high": C_HIGH,
                           "medium": C_MEDIUM, "low": C_LOW}
            for gap in gaps:
                sev = gap.get("severity", "low")
                gap_data.append([
                    Paragraph(gap["id"], S["Code"]),
                    Paragraph(gap["section"][:45], S["Small"]),
                    Paragraph(sev.upper(),
                        ParagraphStyle("gs", fontName="Helvetica-Bold",
                                       fontSize=8,
                                       textColor=sev_colours.get(sev, C_MUTED))),
                    Paragraph(gap["remediation"][:140], S["Small"]),
                ])

            gap_table = Table(gap_data,
                              colWidths=[18*mm, 50*mm, 18*mm,
                                         PAGE_W - 2*MARGIN - 86*mm])
            gap_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1,  0), colors.HexColor("#F0F0F0")),
                ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(gap_table)
            story.append(Spacer(1, 4*mm))

        story.append(PageBreak())

    # ── WEST AFRICA THREAT INTELLIGENCE ─────────────────────
    wa_intel = findings.get("wa_intel", {})
    actors   = wa_intel.get("relevant_actors", [])
    incidents= wa_intel.get("relevant_incidents", [])
    ioc_hits = wa_intel.get("ioc_matches", [])

    # ── HTTP Security Headers (non-intrusive active) ──────────
    sh = findings.get("security_headers", {})
    if sh and sh.get("reachable"):
        story.append(Paragraph("HTTP Security Headers", S["Section_H"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))
        story.append(Paragraph(
            "<b>Non-intrusive active check.</b> Unlike SankofaEye's passive OSINT "
            "modules, this grade comes from a single direct HTTP request to the "
            "target's web server, reading the security headers it returns to every "
            "visitor. No authentication, payloads, or vulnerability tests were "
            "performed.", S["Body"]))
        story.append(Spacer(1, 3*mm))

        grade_col = colors.HexColor(sh.get("colour_hex", "#D32F2F"))
        story.append(Paragraph(
            f"Grade: <b><font color='{sh.get('colour_hex', '#D32F2F')}'>"
            f"{sh.get('grade', 'F')}</font></b> "
            f"({sh.get('score', 0)}/{sh.get('max_score', 100)}) — "
            f"{sh.get('rating', 'critical').upper()}", S["Body"]))
        story.append(Spacer(1, 2*mm))

        _HDR_LABELS = {
            "strict-transport-security": "HSTS",
            "content-security-policy":   "Content-Security-Policy",
            "x-frame-options":           "X-Frame-Options",
            "x-content-type-options":    "X-Content-Type-Options",
            "referrer-policy":           "Referrer-Policy",
            "permissions-policy":        "Permissions-Policy",
        }
        rows = [[Paragraph("<b>Header</b>", S["Body"]),
                 Paragraph("<b>Status</b>", S["Body"])]]
        for key, label in _HDR_LABELS.items():
            present = sh.get("present", {}).get(key, False)
            mark = ("<font color='#388E3C'>Present</font>" if present
                    else "<font color='#D32F2F'>Missing</font>")
            rows.append([Paragraph(label, S["Body"]),
                         Paragraph(mark, S["Body"])])
        t = Table(rows, colWidths=[PAGE_W - 2*MARGIN - 40*mm, 40*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",      (0, 0), (-1, 0), C_WHITE),
            ("GRID",           (0, 0), (-1, -1), 0.25, C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",     (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 6*mm))

    if actors or incidents or ioc_hits:
        story.append(Paragraph("West Africa Threat Intelligence Context", S["Section_H"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

        ctx = wa_intel.get("risk_context", "")
        if ctx:
            story.append(Paragraph(ctx, S["Body"]))
            story.append(Spacer(1, 4*mm))

        if actors:
            story.append(Paragraph("Threat Actors — Likely to Target This Profile:", S["Body_Bold"]))
            story.append(Spacer(1, 2*mm))

            rel_colours = {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
                           "MEDIUM": C_MEDIUM, "LOW": C_LOW}
            actor_data = [[
                Paragraph("Actor",          S["Body_Bold"]),
                Paragraph("Relevance",      S["Body_Bold"]),
                Paragraph("Motivation",     S["Body_Bold"]),
                Paragraph("Sophistication", S["Body_Bold"]),
                Paragraph("Ghana Context",  S["Body_Bold"]),
            ]]
            for actor in actors:
                rel  = actor.get("relevance", "LOW")
                rcol = rel_colours.get(rel, C_MUTED)
                actor_data.append([
                    Paragraph(f"<b>{actor['name']}</b>", S["Body"]),
                    Paragraph(rel, ParagraphStyle("ar", fontName="Helvetica-Bold",
                                                  fontSize=8, textColor=rcol)),
                    Paragraph(actor.get("motivation", ""), S["Small"]),
                    Paragraph(actor.get("sophistication", ""), S["Small"]),
                    Paragraph(actor.get("ghana_notes", "")[:120], S["Small"]),
                ])

            at = Table(actor_data,
                       colWidths=[38*mm, 22*mm, 24*mm, 24*mm,
                                  PAGE_W - 2*MARGIN - 108*mm])
            at.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1,  0), C_DARK),
                ("TEXTCOLOR",     (0, 0), (-1,  0), C_WHITE),
                ("GRID",          (0, 0), (-1, -1), 0.25, C_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(at)
            story.append(Spacer(1, 6*mm))

        # Completed layout for IOC Matches & Observed Incidents
        if ioc_hits:
            story.append(Paragraph("Active IOC Indicators & Threat Matches:", S["Body_Bold"]))
            story.append(Spacer(1, 2*mm))
            
            ioc_data = [[
                Paragraph("Indicator", S["Body_Bold"]),
                Paragraph("Type", S["Body_Bold"]),
                Paragraph("Observed Campaign / Cluster", S["Body_Bold"])
            ]]
            for ioc in ioc_hits:
                ioc_data.append([
                    Paragraph(ioc.get("value", ""), S["Code"]),
                    Paragraph(ioc.get("type", ""), S["Small"]),
                    Paragraph(ioc.get("campaign", ""), S["Body"])
                ])
                
            ioct = Table(ioc_data, colWidths=[60*mm, 30*mm, PAGE_W - 2*MARGIN - 90*mm])
            ioct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
                ("GRID", (0, 0), (-1, -1), 0.25, C_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ioct)

    # ── Phase 5E: Inferred Attack Path (detailed breakdown) ───
    # Reuses the `attack_path` built earlier; falls back to findings if unset.
    if not attack_path:
        attack_path = findings.get("attack_path", {})
    if attack_path and attack_path.get("has_path"):
        story.append(PageBreak())
        story.append(Paragraph("Inferred Attack Path", S["Section_H"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))
        story.append(Paragraph(
            "Reconstructed adversary kill-chain mapped to MITRE ATT&CK tactics. "
            "Inferential only — derived from passive exposure signals surfaced above, "
            "not from active testing.", S["Small"]))
        story.append(Spacer(1, 3*mm))

        summary = attack_path.get("summary", "")
        if summary:
            story.append(Paragraph(summary, S["Body"]))
            story.append(Spacer(1, 2*mm))

        crown = attack_path.get("crown_jewel_risk", "")
        if crown:
            cj_col = (C_CRITICAL if crown.startswith("HIGH")
                      else C_HIGH if crown.startswith(("MEDIUM", "LOW–MEDIUM"))
                      else C_LOW)
            story.append(Paragraph(
                f"<b>Crown-Jewel Risk:</b> {crown}",
                ParagraphStyle("cj", parent=S["Body"], textColor=cj_col,
                               fontName="Helvetica-Bold", fontSize=9)))
            story.append(Spacer(1, 4*mm))

        ap_data = [[
            Paragraph("#",          S["Body_Bold"]),
            Paragraph("Tactic",     S["Body_Bold"]),
            Paragraph("Stage",      S["Body_Bold"]),
            Paragraph("Sev",        S["Body_Bold"]),
            Paragraph("Techniques & Evidence", S["Body_Bold"]),
        ]]
        for st in attack_path.get("stages", []):
            sev = str(st.get("severity", "low")).lower()
            scol = SEVERITY_COLOURS.get(sev, C_MUTED)
            techs = "<br/>".join(
                f"{t['id']} · {t['name']}" for t in st.get("techniques", []))
            evid = "<br/>".join(f"• {e}" for e in st.get("evidence", []))
            cell = techs
            if evid:
                cell = f"{techs}<br/><br/>{evid}" if techs else evid
            ap_data.append([
                Paragraph(f"<b>{st.get('step','')}</b>", S["Body"]),
                Paragraph(f"<b>{st.get('tactic','')}</b><br/>"
                          f"<font size=7 color='#757575'>{st.get('mitre_tactic','')}</font>",
                          S["Small"]),
                Paragraph(st.get("title", ""), S["Body"]),
                Paragraph(sev.upper(), ParagraphStyle("aps", fontName="Helvetica-Bold",
                                                      fontSize=8, textColor=scol)),
                Paragraph(cell, S["Small"]),
            ])
        apt = Table(ap_data,
                    colWidths=[8*mm, 30*mm, 36*mm, 18*mm,
                               PAGE_W - 2*MARGIN - 92*mm])
        apt.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1,  0), C_DARK),
            ("TEXTCOLOR",      (0, 0), (-1,  0), C_WHITE),
            ("GRID",           (0, 0), (-1, -1), 0.25, C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(apt)
        story.append(Spacer(1, 6*mm))

    # ── Phase 5F: Dark Web Persona Monitoring ─────────────────
    persona = findings.get("persona_monitoring", {})
    if persona and persona.get("total", 0) > 0:
        story.append(PageBreak())
        story.append(Paragraph("Dark Web Persona Monitoring", S["Section_H"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))
        story.append(Paragraph(
            "Targeted dark-web and fraud-forum monitoring for named executives and "
            "brand terms. Hits indicate the organisation or its leadership is being "
            "discussed in adversarial contexts — an early-warning signal for "
            "impersonation, BEC, or insider-recruitment activity.", S["Small"]))
        story.append(Spacer(1, 3*mm))

        execs_found = persona.get("executives_found", [])
        brand_hits  = persona.get("brand_hits", [])
        story.append(Paragraph(
            f"<b>{persona.get('total', 0)}</b> total hit(s) — "
            f"<b>{len(execs_found)}</b> executive match(es), "
            f"<b>{len(brand_hits)}</b> brand-term match(es).", S["Body"]))
        story.append(Spacer(1, 3*mm))

        hits = persona.get("hits", [])
        if hits:
            p_data = [[
                Paragraph("Subject",  S["Body_Bold"]),
                Paragraph("Type",     S["Body_Bold"]),
                Paragraph("Source / Context", S["Body_Bold"]),
                Paragraph("Snippet",  S["Body_Bold"]),
            ]]
            for h in hits[:25]:
                htype = str(h.get("type", "")).upper()
                tcol = C_CRITICAL if htype == "EXECUTIVE" else C_HIGH
                p_data.append([
                    Paragraph(f"<b>{h.get('subject','')}</b>", S["Body"]),
                    Paragraph(htype, ParagraphStyle("pt", fontName="Helvetica-Bold",
                                                    fontSize=8, textColor=tcol)),
                    Paragraph(h.get("source", "")[:60], S["Small"]),
                    Paragraph(h.get("snippet", "")[:140], S["Small"]),
                ])
            pt = Table(p_data,
                       colWidths=[34*mm, 22*mm, 40*mm,
                                  PAGE_W - 2*MARGIN - 96*mm])
            pt.setStyle(TableStyle([
                ("BACKGROUND",     (0, 0), (-1,  0), colors.HexColor("#333333")),
                ("TEXTCOLOR",      (0, 0), (-1,  0), C_WHITE),
                ("GRID",           (0, 0), (-1, -1), 0.25, C_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
                ("TOPPADDING",     (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
                ("LEFTPADDING",    (0, 0), (-1, -1), 6),
                ("VALIGN",         (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(pt)
            story.append(Spacer(1, 6*mm))

    # ── Phase 5G: Supplier / Third-Party Risk ─────────────────
    supplier_risk = findings.get("supplier_risk", {})
    if supplier_risk and supplier_risk.get("total_vendors", 0) > 0:
        story.append(PageBreak())
        story.append(Paragraph("Supplier / Third-Party Risk", S["Section_H"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))
        story.append(Paragraph(
            "Lightweight passive posture assessment of configured vendors "
            "(DNS email-authentication, TLS, and external footprint only). "
            "A supply chain is only as strong as its weakest link — this maps "
            "to BoG CISD Section 6, Third-Party Risk Management.", S["Small"]))
        story.append(Spacer(1, 3*mm))

        weakest = supplier_risk.get("weakest_link", {})
        hr = supplier_risk.get("high_risk_count", 0)
        if weakest:
            wl_col = SEVERITY_COLOURS.get(weakest.get("severity", "low"), C_MUTED)
            story.append(Paragraph(
                f"<b>{supplier_risk.get('total_vendors', 0)}</b> vendor(s) assessed — "
                f"<b>{hr}</b> at high/critical risk. "
                f"Weakest link: <b>{weakest.get('name','')}</b> "
                f"(<font color='#{wl_col.hexval()[2:]}'>"
                f"{weakest.get('risk_score',0)}/100 {weakest.get('severity','').upper()}</font>).",
                S["Body"]))
            story.append(Spacer(1, 4*mm))

        v_data = [[
            Paragraph("Vendor",      S["Body_Bold"]),
            Paragraph("Criticality", S["Body_Bold"]),
            Paragraph("Risk",        S["Body_Bold"]),
            Paragraph("Findings",    S["Body_Bold"]),
        ]]
        for v in supplier_risk.get("vendors", []):
            vsev = str(v.get("severity", "low")).lower()
            vcol = SEVERITY_COLOURS.get(vsev, C_MUTED)
            issues = "<br/>".join(f"• {i}" for i in v.get("issues", []))
            v_data.append([
                Paragraph(f"<b>{v.get('name','')}</b><br/>"
                          f"<font size=7 color='#757575'>{v.get('domain','')}</font>",
                          S["Small"]),
                Paragraph(str(v.get("criticality", "")).upper(), S["Small"]),
                Paragraph(f"{v.get('risk_score',0)}/100<br/>{vsev.upper()}",
                          ParagraphStyle("vr", fontName="Helvetica-Bold",
                                         fontSize=8, textColor=vcol)),
                Paragraph(issues, S["Small"]),
            ])
        vt = Table(v_data,
                   colWidths=[42*mm, 24*mm, 22*mm,
                              PAGE_W - 2*MARGIN - 88*mm])
        vt.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1,  0), C_DARK),
            ("TEXTCOLOR",      (0, 0), (-1,  0), C_WHITE),
            ("GRID",           (0, 0), (-1, -1), 0.25, C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(vt)
        story.append(Spacer(1, 6*mm))

    # Build document canvas with custom callback structure
    doc.build(story, onFirstPage=lambda c, d: header_footer(c, d, config, target),
                     onLaterPages=lambda c, d: header_footer(c, d, config, target))
    
    return filepath