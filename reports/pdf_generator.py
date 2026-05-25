"""
SankofahEye — PDF Report Generator
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
from reportlab.graphics.shapes import Drawing, Wedge, Circle, String
from reportlab.graphics import renderPDF
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from utils.logger import SankofahLogger
from reportlab.lib.units import mm
from reportlab.platypus import Image as RLImage

log = SankofahLogger("pdf_generator")

# ── Brand colours ─────────────────────────────────────────────
C_DARK       = colors.HexColor("#005F5F")
C_PRIMARY    = colors.HexColor("#008080")   # AfriWealth Teal Blue
C_ACCENT     = colors.HexColor("#FFD700")   # AfriWealth Gold
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
    """Return a coloured HTML-like string for severity."""
    labels = {
        "critical": "● CRITICAL",
        "high":     "● HIGH",
        "medium":   "● MEDIUM",
        "low":      "● LOW",
        "informational": "● INFO",
    }
    return labels.get(severity.lower(), severity.upper())


def draw_risk_gauge(score: int, rating: str) -> Drawing:
    """Draw a simple risk score circle gauge."""
    d = Drawing(160, 160)
    colour_map = {
        "critical": C_CRITICAL, "high": C_HIGH,
        "medium": C_MEDIUM, "low": C_LOW,
    }
    ring_colour = colour_map.get(rating, C_INFO)
    bg_colour   = colors.HexColor("#E8E8E8")

    # Background ring
    d.add(Wedge(80, 80, 60, 0, 360, fillColor=bg_colour, strokeColor=None))
    d.add(Wedge(80, 80, 45, 0, 360, fillColor=C_WHITE, strokeColor=None))

    # Score arc (0-100 → 0-360 degrees)
    angle = max(score * 3.6, 0.01)
    d.add(Wedge(80, 80, 60, 90, 90 + angle, fillColor=ring_colour, strokeColor=None))
    d.add(Wedge(80, 80, 45, 0, 360, fillColor=C_WHITE, strokeColor=None))

    # Score text
    d.add(String(80, 78, str(score), fontSize=22, fontName="Helvetica-Bold",
                 fillColor=ring_colour, textAnchor="middle"))
    d.add(String(80, 60, "/100", fontSize=9, fontName="Helvetica",
                 fillColor=C_MUTED, textAnchor="middle"))
    d.add(String(80, 44, rating.upper(), fontSize=9, fontName="Helvetica-Bold",
                 fillColor=ring_colour, textAnchor="middle"))
    return d


def header_footer(canvas, doc, config: dict, target: str):
    """Draw header and footer on every page."""
    canvas.saveState()
    w, h = A4

    # Header bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, h - 18*mm, w, 18*mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, h - 18*mm, 3*mm, 18*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(C_WHITE)
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "afriwealth_logo.png")
    if os.path.exists(logo_path):
        canvas.drawImage(logo_path, MARGIN, h - 16*mm, width=28*mm, height=10*mm, preserveAspectRatio=True, mask="auto")
    else:
        canvas.drawString(MARGIN, h - 11*mm, config["brand"]["tool"])
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#AAAAAA"))
    canvas.drawString(MARGIN + 70, h - 11*mm, f"| {config['brand']['name']}")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - MARGIN, h - 11*mm, f"Target: {target}")

    # Footer bar
    canvas.setFillColor(C_BG_LIGHT)
    canvas.rect(0, 0, w, 12*mm, fill=1, stroke=0)
    canvas.setFillColor(C_BORDER)
    canvas.rect(0, 12*mm, w, 0.3*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(MARGIN, 5*mm,
        f"{config['brand']['name']} — {config['brand']['tool']} v{config['brand']['version']} — "
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
    filename  = f"SankofahEye_{target}_{timestamp}.pdf"
    filepath  = os.path.join(output_dir, filename)

    log.info(f"[PDF] Generating report → {filepath}")

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

    # Brand block
    logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "afriwealth_logo.png")

    logo_cell = RLImage(logo_path, width=60*mm, height=20*mm) if os.path.exists(logo_path) else Paragraph("AfriWealth Cyber Intelligence", S["Cover_Sub"])

    cover_header = Table(
    [[logo_cell],
     [Spacer(1, 3*mm)],
     [Paragraph(config["brand"]["tool"], S["Cover_Title"])],
     [Paragraph("Passive Exposure Intelligence Report", S["Cover_Sub"])],
     [Spacer(1, 4*mm)],
     [Paragraph(f"<b>Target:</b>  {target}", S["Cover_Meta"])],
     [Paragraph(f"<b>Date:</b>    {datetime.now().strftime('%d %B %Y, %H:%M UTC')}", S["Cover_Meta"])],
     [Paragraph(f"<b>Analyst:</b> {config['brand'].get('analyst', 'DeCyberGuardian')}", S["Cover_Meta"])],
     [Paragraph(f"<b>Prepared by:</b> {config['brand']['name']}", S["Cover_Meta"])],
    ],
    colWidths=[PAGE_W - 2*MARGIN],
)
    cover_header.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_DARK),
        ("TEXTCOLOR",  (0,0), (-1,-1), C_WHITE),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ("RIGHTPADDING",  (0,0), (-1,-1), 12),
        ("LINEABOVE",  (0,0), (-1,0), 3, C_ACCENT),
    ]))
    story.append(cover_header)
    story.append(Spacer(1, 8*mm))

    # Risk score gauge + summary box on cover
    gauge = draw_risk_gauge(scoring["score"], scoring["rating"])
    cover_score_table = Table(
        [[gauge, Table(
            [[Paragraph("Overall Risk Score", S["Section_H"])],
             [Paragraph(
                f"<b>{scoring['score']}/100</b> — "
                f"<font color='#{scoring['colour'][1:]}'>{scoring['rating'].upper()}</font>",
                S["Body"])],
             [Spacer(1, 2*mm)],
             [Paragraph(f"Total findings: <b>{scoring['finding_count']}</b>", S["Body"])],
             [Paragraph(f"MITRE techniques: <b>{len(scoring.get('mitre_techniques', []))}</b>", S["Body"])],
            ],
            colWidths=[PAGE_W - 2*MARGIN - 175],
        )]],
        colWidths=[175, PAGE_W - 2*MARGIN - 175],
    )
    cover_score_table.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND", (0,0), (-1,-1), C_BG_LIGHT),
        ("BOX",    (0,0), (-1,-1), 0.5, C_BORDER),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(cover_score_table)
    story.append(Spacer(1, 6*mm))

    # Disclaimer banner
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
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#FFF8E1")),
        ("BOX",           (0,0), (-1,-1), 0.5, C_MEDIUM),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(disclaimer)
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    sub_count  = findings["subdomains"]["count"]
    email_count = findings["emails"]["count"]
    breach_count = findings["credential_exposure"]["total_breached"]
    host_count = findings["exposed_services"]["total_hosts"]
    dw_count   = findings["dark_web"]["total_mentions"]

    exec_summary = [
        f"SankofahEye conducted a passive reconnaissance assessment of <b>{target}</b> on "
        f"{datetime.now().strftime('%d %B %Y')}. The scan leveraged open-source intelligence (OSINT) "
        f"sources including Subfinder, theHarvester, Shodan, Have I Been Pwned, VirusTotal, URLScan.io, "
        f"and dark web indexed search. No active exploitation was performed.",
        f"",
        f"The assessment identified <b>{sub_count} subdomains</b>, <b>{email_count} email addresses</b>, "
        f"<b>{host_count} internet-facing hosts</b>, and <b>{breach_count} breached account(s)</b>. "
        f"Dark web monitoring returned <b>{dw_count} mention(s)</b> of the target domain.",
        f"",
        f"The overall exposure risk is rated <b>{scoring['rating'].upper()} ({scoring['score']}/100)</b>. "
        f"Immediate remediation is recommended for all Critical and High severity findings listed in this report.",
    ]
    for line in exec_summary:
        story.append(Paragraph(line, S["Body"]))
    story.append(Spacer(1, 4*mm))

    # Stats summary bar
    stats_data = [
        [Paragraph(f"<b>{sub_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{host_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{breach_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{dw_count}</b>", S["Section_H"]),
         Paragraph(f"<b>{len(findings['exposed_services']['cves'])}</b>", S["Section_H"])],
        [Paragraph("Subdomains", S["Small"]),
         Paragraph("Exposed Hosts", S["Small"]),
         Paragraph("Breached Accounts", S["Small"]),
         Paragraph("Dark Web Mentions", S["Small"]),
         Paragraph("CVEs Detected", S["Small"])],
    ]
    col_w = (PAGE_W - 2*MARGIN) / 5
    stats_table = Table(stats_data, colWidths=[col_w]*5)
    stats_table.setStyle(TableStyle([
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("BACKGROUND",    (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
        ("BACKGROUND",    (0,1), (-1,-1), C_BG_LIGHT),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.25, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 6*mm))

    # ── FINDINGS ──────────────────────────────────────────────
    story.append(Paragraph("Findings & Risk Analysis", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    for i, finding in enumerate(scoring["findings"], 1):
        sev = finding["severity"].lower()
        sev_colour = SEVERITY_COLOURS.get(sev, C_INFO)

        badge_style = ParagraphStyle(
            f"badge_{i}", fontName="Helvetica-Bold",
            fontSize=8, textColor=C_WHITE,
        )

        finding_table = Table(
            [[
                Paragraph(severity_badge(sev), badge_style),
                Paragraph(f"<b>{i}. {finding['finding']}</b>", S["Finding_Title"]),
            ]],
            colWidths=[22*mm, PAGE_W - 2*MARGIN - 22*mm],
        )
        finding_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (0,0), sev_colour),
            ("BACKGROUND",    (1,0), (1,0), colors.HexColor("#FAFAFA")),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("ALIGN",         (0,0), (0,0), "CENTER"),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("BOX",           (0,0), (-1,-1), 0.5, sev_colour),
        ]))

        detail_table = Table(
            [
                [Paragraph("Detail:", S["Body_Bold"]),
                 Paragraph(finding["detail"], S["Body"])],
                [Paragraph("Recommendation:", S["Body_Bold"]),
                 Paragraph(finding["recommendation"], S["Body"])],
                [Paragraph("MITRE ATT&CK:", S["Body_Bold"]),
                 Paragraph(
                     f"{finding['mitre']['id']} — {finding['mitre']['name']}",
                     S["Mitre"])],
            ],
            colWidths=[32*mm, PAGE_W - 2*MARGIN - 32*mm],
        )
        detail_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), C_WHITE),
            ("GRID",          (0,0), (-1,-1), 0.25, C_BORDER),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))

        # Attack scenario block
        atk = finding.get("attack_scenario", {})
        scenario_elements = []
        if atk:
            scenario_header = Table(
                [[Paragraph("⚠ Attack Scenario & Threat Impact", ParagraphStyle(
                    "atk_hdr", fontName="Helvetica-Bold", fontSize=9,
                    textColor=C_WHITE))]],
                colWidths=[PAGE_W - 2*MARGIN],
            )
            scenario_header.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#B71C1C")),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ]))
            scenario_body = Table(
                [
                    [Paragraph("How it would be exploited:", S["Body_Bold"]),
                     Paragraph(atk.get("scenario", ""), S["Body"])],
                    [Paragraph("Potential impact:", S["Body_Bold"]),
                     Paragraph(atk.get("impact", ""), S["Body"])],
                    [Paragraph("Likelihood:", S["Body_Bold"]),
                     Paragraph(atk.get("likelihood", ""), S["Body"])],
                    [Paragraph("Threat actors:", S["Body_Bold"]),
                     Paragraph(atk.get("threat_actors", ""), S["Body"])],
                ],
                colWidths=[32*mm, PAGE_W - 2*MARGIN - 32*mm],
            )
            scenario_body.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#FFEBEE")),
                ("GRID",          (0,0), (-1,-1), 0.25, colors.HexColor("#FFCDD2")),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ]))
            scenario_elements = [scenario_header, scenario_body]

        story.append(KeepTogether(
            [finding_table, detail_table] + scenario_elements + [Spacer(1, 6*mm)]
        ))

    story.append(PageBreak())

    # ── SUBDOMAINS ────────────────────────────────────────────
    story.append(Paragraph("Subdomain Inventory", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))
    story.append(Paragraph(
        f"Total of <b>{sub_count}</b> unique subdomains discovered.", S["Body"]))
    story.append(Spacer(1, 3*mm))

    if findings["subdomains"]["list"]:
        subs = findings["subdomains"]["list"]
        rows_per_col = 35
        cols_data = [subs[i:i+rows_per_col] for i in range(0, len(subs), rows_per_col)]
        max_rows = max(len(c) for c in cols_data)
        for c in cols_data:
            while len(c) < max_rows:
                c.append("")

        num_cols = min(len(cols_data), 3)
        col_w = (PAGE_W - 2*MARGIN) / num_cols
        sub_table_data = list(zip(*cols_data[:num_cols]))
        sub_table = Table(
            [[Paragraph(cell, S["Code"]) for cell in row] for row in sub_table_data],
            colWidths=[col_w]*num_cols,
        )
        sub_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), C_BG_LIGHT),
            ("INNERGRID",     (0,0), (-1,-1), 0.1, C_BORDER),
            ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",    (0,0), (-1,-1), 2),
            ("BOTTOMPADDING", (0,0), (-1,-1), 2),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ]))
        story.append(sub_table)
    else:
        story.append(Paragraph("No subdomains discovered.", S["Body"]))

    story.append(PageBreak())

    # ── EXPOSED SERVICES ──────────────────────────────────────
    story.append(Paragraph("Exposed Services (Shodan)", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    if findings["exposed_services"]["high_risk_ports"]:
        risky = findings["exposed_services"]["high_risk_ports"]
        risk_data = [
            [Paragraph("IP Address", S["Body_Bold"]),
             Paragraph("Port", S["Body_Bold"]),
             Paragraph("Risk Reason", S["Body_Bold"])]
        ]
        for r in risky:
            risk_data.append([
                Paragraph(r["ip"], S["Code"]),
                Paragraph(str(r["port"]), S["Code"]),
                Paragraph(r["reason"], S["Body"]),
            ])
        risk_table = Table(risk_data, colWidths=[45*mm, 18*mm, PAGE_W - 2*MARGIN - 63*mm])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
            ("BACKGROUND",    (0,1), (-1,-1), C_WHITE),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_BG_LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.25, C_BORDER),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        story.append(risk_table)
    else:
        story.append(Paragraph("No high-risk ports detected.", S["Body"]))

    story.append(Spacer(1, 4*mm))

    # CVEs
    if findings["exposed_services"]["cves"]:
        story.append(Paragraph("CVEs Detected", S["Section_H"]))
        cve_list = ", ".join(findings["exposed_services"]["cves"])
        story.append(Paragraph(cve_list, S["Code"]))

    story.append(PageBreak())

    # ── CREDENTIAL EXPOSURE ───────────────────────────────────
    story.append(Paragraph("Credential Exposure (Have I Been Pwned)", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    breaches = findings["credential_exposure"]["breached_accounts"]
    if breaches:
        for acct in breaches:
            story.append(Paragraph(f"<b>{acct['email']}</b>", S["Body_Bold"]))
            breach_data = [[
                Paragraph("Breach", S["Body_Bold"]),
                Paragraph("Date", S["Body_Bold"]),
                Paragraph("Data Exposed", S["Body_Bold"]),
            ]]
            for b in acct["breaches"]:
                breach_data.append([
                    Paragraph(b["name"], S["Body"]),
                    Paragraph(b["date"], S["Body"]),
                    Paragraph(", ".join(b["data_classes"][:5]), S["Small"]),
                ])
            breach_table = Table(
                breach_data,
                colWidths=[50*mm, 30*mm, PAGE_W - 2*MARGIN - 80*mm]
            )
            breach_table.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0), C_CRITICAL),
                ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
                ("GRID",          (0,0), (-1,-1), 0.25, C_BORDER),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, colors.HexColor("#FFEBEE")]),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ]))
            story.append(breach_table)
            story.append(Spacer(1, 4*mm))
    else:
        story.append(Paragraph(
            "No breached accounts detected for the target domain.", S["Body"]))

    story.append(Spacer(1, 4*mm))

    # ── DARK WEB ──────────────────────────────────────────────
    story.append(Paragraph("Dark Web Monitoring", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    dw_mentions = findings["dark_web"]["mentions"]
    if dw_mentions:
        dw_data = [[
            Paragraph("Title / URL", S["Body_Bold"]),
            Paragraph("Risk", S["Body_Bold"]),
            Paragraph("Keywords", S["Body_Bold"]),
        ]]
        for m in dw_mentions[:15]:
            risk_col = C_CRITICAL if m.get("risk") == "high" else C_INFO
            dw_data.append([
                Paragraph(m.get("title", m.get("url", ""))[:80], S["Small"]),
                Paragraph(m.get("risk", "info").upper(),
                    ParagraphStyle("dwr", fontName="Helvetica-Bold",
                                   fontSize=8, textColor=risk_col)),
                Paragraph(", ".join(m.get("matched_keywords", [])), S["Small"]),
            ])
        dw_table = Table(
            dw_data,
            colWidths=[90*mm, 22*mm, PAGE_W - 2*MARGIN - 112*mm]
        )
        dw_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
            ("GRID",          (0,0), (-1,-1), 0.25, C_BORDER),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        story.append(dw_table)
    else:
        story.append(Paragraph(
            "No dark web mentions detected for the target domain.", S["Body"]))

    story.append(PageBreak())


    # ── DNS SECURITY ──────────────────────────────────────────
    story.append(Paragraph("DNS & Email Security Analysis", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    dns_sec   = findings.get("dns_security", {})
    spf       = dns_sec.get("spf", {})
    dmarc     = dns_sec.get("dmarc", {})
    dkim      = dns_sec.get("dkim", {})
    mx        = dns_sec.get("mx", {})
    ns        = dns_sec.get("ns", {})

    dns_summary_data = [
        [Paragraph("Check", S["Body_Bold"]),
         Paragraph("Status", S["Body_Bold"]),
         Paragraph("Detail", S["Body_Bold"])],
        [Paragraph("SPF", S["Body"]),
         Paragraph(
             "✓ Strong" if spf.get("strength") == "strong"
             else "⚠ Weak" if spf.get("strength") == "weak"
             else "✗ Missing",
             ParagraphStyle("spf_s", fontName="Helvetica-Bold", fontSize=9,
                 textColor=(C_LOW if spf.get("strength") == "strong"
                             else C_MEDIUM if spf.get("strength") == "weak"
                             else C_CRITICAL))
         ),
         Paragraph(spf.get("record", "No SPF record found")[:80], S["Small"])],
        [Paragraph("DMARC", S["Body"]),
         Paragraph(
             f"✓ {dmarc.get('policy','').upper()}" if dmarc.get("policy") == "reject"
             else f"⚠ {dmarc.get('policy','NONE').upper()}" if dmarc.get("present")
             else "✗ Missing",
             ParagraphStyle("dmarc_s", fontName="Helvetica-Bold", fontSize=9,
                 textColor=(C_LOW if dmarc.get("policy") == "reject"
                             else C_MEDIUM if dmarc.get("present")
                             else C_CRITICAL))
         ),
         Paragraph(dmarc.get("record", "No DMARC record found")[:80], S["Small"])],
        [Paragraph("DKIM", S["Body"]),
         Paragraph(
             f"✓ {len(dkim.get('found_selectors',[]))} selector(s)" if dkim.get("present") else "✗ Not found",
             ParagraphStyle("dkim_s", fontName="Helvetica-Bold", fontSize=9,
                 textColor=C_LOW if dkim.get("present") else C_CRITICAL)
         ),
         Paragraph(
             ", ".join([s["selector"] for s in dkim.get("found_selectors", [])]) or "No DKIM selectors found",
             S["Small"])],
        [Paragraph("MX / Mail", S["Body"]),
         Paragraph(mx.get("provider", "Unknown"), S["Body"]),
         Paragraph(mx.get("records", ["No MX records"])[0][:80] if mx.get("records") else "No MX records", S["Small"])],
        [Paragraph("Nameservers", S["Body"]),
         Paragraph(ns.get("provider", "Unknown"), S["Body"]),
         Paragraph(", ".join(ns.get("records", []))[:80] if ns.get("records") else "No NS records", S["Small"])],
    ]

    col_w = [25*mm, 35*mm, PAGE_W - 2*MARGIN - 60*mm]
    dns_table = Table(dns_summary_data, colWidths=col_w)
    dns_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
        ("GRID",          (0,0), (-1,-1), 0.25, C_BORDER),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_BG_LIGHT]),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(dns_table)
    story.append(Spacer(1, 4*mm))

    # DNS issues list
    dns_issues_list = dns_sec.get("issues", [])
    if dns_issues_list:
        story.append(Paragraph("DNS Issues Detected:", S["Body_Bold"]))
        for issue in dns_issues_list:
            story.append(Paragraph(f"• {issue}", S["Body"]))
    else:
        story.append(Paragraph("No DNS security issues detected.", S["Body"]))

    # ── MITRE ATT&CK TABLE ────────────────────────────────────
    story.append(Paragraph("MITRE ATT&CK Technique Mapping", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))

    mitre_data = [[
        Paragraph("Technique ID", S["Body_Bold"]),
        Paragraph("Technique Name", S["Body_Bold"]),
    ]]
    for t in scoring.get("mitre_techniques", []):
        mitre_data.append([
            Paragraph(t["id"], S["Mitre"]),
            Paragraph(t["name"], S["Body"]),
        ])

    if len(mitre_data) > 1:
        mitre_table = Table(mitre_data, colWidths=[35*mm, PAGE_W - 2*MARGIN - 35*mm])
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), C_PRIMARY),
            ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
            ("GRID",          (0,0), (-1,-1), 0.25, C_BORDER),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_BG_LIGHT]),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        story.append(mitre_table)
    else:
        story.append(Paragraph("No MITRE techniques mapped.", S["Body"]))

    story.append(Spacer(1, 6*mm))

    # ── CLOSING ───────────────────────────────────────────────
    story.append(Paragraph("About AfriWealth Cyber Intelligence", S["Section_H"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_PRIMARY, spaceAfter=6))
    story.append(Paragraph(
        "AfriWealth Cyber Intelligence provides cyber threat intelligence, passive reconnaissance, "
        "and digital risk advisory services focused on Ghana and the broader West African digital ecosystem. "
        "Our mission is to build and strengthen the cyber resilience of African financial institutions, "
        "fintechs, telecoms, and enterprises through intelligence-led security.",
        S["Body"]
    ))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        f"Tool: {config['brand']['tool']} v{config['brand']['version']} | "
        f"Analyst: {config['brand'].get('analyst', 'DeCyberGuardian')} | "
        f"Website: {config['brand'].get('website', '')}",
        S["Small"]
    ))

    # Build with header/footer
    doc.build(
        story,
        onFirstPage=lambda c, d: header_footer(c, d, config, target),
        onLaterPages=lambda c, d: header_footer(c, d, config, target),
    )

    log.info(f"[PDF] Report saved → {filepath}")
    return filepath
