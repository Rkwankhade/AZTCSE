"""
Module 13: Post-Exploitation PDF Report Generator
Combines findings from all AZTCSE modules into a professional pentest report:
  - Executive Summary
  - Attack Surface Overview
  - Module-by-module findings
  - Kill chain visualizations (ASCII)
  - Remediation roadmap with priority scoring
  - Appendix with raw evidence

Requires: reportlab  (pip install reportlab)
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

# ── Try importing reportlab; fall back to plain HTML if unavailable ──────────
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, inch
    from reportlab.platypus import (
        BaseDocTemplate, Frame, HRFlowable, Image, PageBreak,
        PageTemplate, Paragraph, Spacer, Table, TableStyle,
    )
    from reportlab.platypus.tableofcontents import TableOfContents
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    class colors:
        white = None; black = None
        @staticmethod
        def HexColor(h): return h


# ──────────────────────────────────────────────
# Color Palette
# ──────────────────────────────────────────────

C_DARK      = colors.HexColor("#0d1117")
C_RED       = colors.HexColor("#da3633")
C_ORANGE    = colors.HexColor("#e3642c")
C_YELLOW    = colors.HexColor("#d29922")
C_GREEN     = colors.HexColor("#3fb950")
C_BLUE      = colors.HexColor("#1f6feb")
C_GREY      = colors.HexColor("#8b949e")
C_LIGHT     = colors.HexColor("#f0f6fc")
C_WHITE     = colors.white
C_BLACK     = colors.black
C_PANEL     = colors.HexColor("#161b22")
C_BORDER    = colors.HexColor("#30363d")

SEVERITY_COLORS = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_GREEN,
    "INFO":     C_GREY,
}


# ──────────────────────────────────────────────
# Style Sheet
# ──────────────────────────────────────────────

def build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["cover_title"] = ParagraphStyle(
        "cover_title", fontSize=32, leading=40,
        textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER,
    )
    styles["cover_sub"] = ParagraphStyle(
        "cover_sub", fontSize=14, leading=20,
        textColor=C_GREY, fontName="Helvetica", alignment=TA_CENTER,
    )
    styles["cover_meta"] = ParagraphStyle(
        "cover_meta", fontSize=10, leading=16,
        textColor=C_GREY, fontName="Helvetica", alignment=TA_CENTER,
    )
    styles["h1"] = ParagraphStyle(
        "h1", fontSize=20, leading=26,
        textColor=C_BLUE, fontName="Helvetica-Bold",
        spaceAfter=8,
    )
    styles["h2"] = ParagraphStyle(
        "h2", fontSize=14, leading=20,
        textColor=C_LIGHT, fontName="Helvetica-Bold",
        spaceBefore=12, spaceAfter=6,
    )
    styles["h3"] = ParagraphStyle(
        "h3", fontSize=11, leading=16,
        textColor=C_GREY, fontName="Helvetica-Bold",
        spaceBefore=8, spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "body", fontSize=9, leading=14,
        textColor=C_BLACK, fontName="Helvetica",
        spaceAfter=4,
    )
    styles["code"] = ParagraphStyle(
        "code", fontSize=8, leading=12,
        textColor=colors.HexColor("#58a6ff"), fontName="Courier",
        backColor=C_PANEL, leftIndent=8, rightIndent=8,
        spaceBefore=4, spaceAfter=4,
    )
    styles["critical"] = ParagraphStyle(
        "critical", fontSize=9, leading=13,
        textColor=C_RED, fontName="Helvetica-Bold",
    )
    styles["footer"] = ParagraphStyle(
        "footer", fontSize=7, leading=10,
        textColor=C_GREY, fontName="Helvetica", alignment=TA_CENTER,
    )
    return styles


# ──────────────────────────────────────────────
# Page Template (header + footer)
# ──────────────────────────────────────────────

class AZTCSEDocTemplate(BaseDocTemplate):
    def __init__(self, filename, report_meta: dict, **kwargs):
        super().__init__(filename, **kwargs)
        self.report_meta = report_meta
        self.styles = build_styles()
        frame = Frame(
            1.5 * cm, 2.0 * cm,
            A4[0] - 3.0 * cm, A4[1] - 3.5 * cm,
            id="main",
        )
        template = PageTemplate(id="main", frames=[frame], onPage=self._draw_page)
        self.addPageTemplates([template])

    def _draw_page(self, canvas, doc):
        canvas.saveState()
        # Header bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, A4[1] - 1.2 * cm, A4[0], 1.2 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_BLUE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(1.5 * cm, A4[1] - 0.75 * cm, "AZTCSE — Cloud Security Assessment")
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 1.5 * cm, A4[1] - 0.75 * cm, self.report_meta.get("client", ""))
        # Footer bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, 0, A4[0], 1.5 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(1.5 * cm, 0.55 * cm, "CONFIDENTIAL — For authorized use only")
        canvas.drawRightString(A4[0] - 1.5 * cm, 0.55 * cm, f"Page {doc.page}")
        canvas.restoreState()


# ──────────────────────────────────────────────
# Section Builders
# ──────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    colors_map = {"CRITICAL": "#da3633", "HIGH": "#e3642c", "MEDIUM": "#d29922", "LOW": "#3fb950"}
    c = colors_map.get(sev, "#8b949e")
    return f'<font color="{c}"><b>[{sev}]</b></font>'


def build_cover(styles: dict, meta: dict) -> list:
    story = []
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("AZTCSE", styles["cover_title"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("Cloud Security Assessment Report", styles["cover_sub"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="60%", thickness=1, color=C_BLUE, spaceAfter=20, spaceBefore=10))
    story.append(Paragraph(f"Target: <b>{meta.get('target', 'AWS Account')}</b>", styles["cover_meta"]))
    story.append(Paragraph(f"Account ID: {meta.get('account_id', 'N/A')}", styles["cover_meta"]))
    story.append(Paragraph(f"Region: {meta.get('region', 'us-east-1')}", styles["cover_meta"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(f"Assessment Date: {meta.get('date', datetime.utcnow().strftime('%Y-%m-%d'))}", styles["cover_meta"]))
    story.append(Paragraph(f"Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["cover_meta"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(f"Assessor: {meta.get('assessor', 'AZTCSE Automated Engine')}", styles["cover_meta"]))
    story.append(Paragraph(f"Classification: {meta.get('classification', 'CONFIDENTIAL')}", styles["cover_meta"]))
    story.append(PageBreak())
    return story


def build_exec_summary(styles: dict, findings: dict) -> list:
    story = []
    story.append(Paragraph("1. Executive Summary", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=10))

    total_findings = findings.get("total_findings", 0)
    critical = findings.get("critical", 0)
    high = findings.get("high", 0)
    medium = findings.get("medium", 0)
    low = findings.get("low", 0)
    confirmed_attack_paths = findings.get("confirmed_attack_paths", 0)
    risk_score = findings.get("overall_risk_score", 0.0)

    risk_label = "CRITICAL" if risk_score >= 0.75 else "HIGH" if risk_score >= 0.5 else "MEDIUM" if risk_score >= 0.25 else "LOW"
    risk_color_hex = {"CRITICAL": "da3633", "HIGH": "e3642c", "MEDIUM": "d29922", "LOW": "3fb950"}.get(risk_label, "8b949e")

    summary_text = (
        f"An automated cloud security assessment was conducted against the target AWS account using the AZTCSE framework. "
        f"The assessment identified <b>{total_findings} total findings</b>, including "
        f"<font color='#da3633'><b>{critical} CRITICAL</b></font>, "
        f"<font color='#e3642c'><b>{high} HIGH</b></font>, "
        f"<font color='#d29922'><b>{medium} MEDIUM</b></font>, and "
        f"<font color='#3fb950'><b>{low} LOW</b></font> severity issues. "
        f"A total of <b>{confirmed_attack_paths} attack paths</b> were confirmed against the live AWS environment."
    )
    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 0.5 * cm))

    # Risk score box
    risk_table = Table(
        [[Paragraph(f"Overall Risk Score", styles["h3"]),
          Paragraph(f'<font color="#{risk_color_hex}"><b>{risk_score:.2f} / 1.00 - {risk_label}</b></font>', styles["h2"])]],
        colWidths=[7 * cm, 10 * cm],
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_PANEL),
        ("BOX",        (0, 0), (-1, -1), 1, C_BORDER),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING",  (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.5 * cm))

    # Severity breakdown table
    sev_data = [
        ["Severity", "Count", "Status"],
        [Paragraph(_severity_badge("CRITICAL"), styles["body"]), str(critical), "Immediate action required"],
        [Paragraph(_severity_badge("HIGH"),     styles["body"]), str(high),     "Remediate within 7 days"],
        [Paragraph(_severity_badge("MEDIUM"),   styles["body"]), str(medium),   "Remediate within 30 days"],
        [Paragraph(_severity_badge("LOW"),      styles["body"]), str(low),      "Remediate within 90 days"],
    ]
    sev_table = Table(sev_data, colWidths=[5 * cm, 3 * cm, 9 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
        ("TEXTCOLOR",    (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",    (0, 0), (-1, -1), 0.25, C_BORDER),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    story.append(sev_table)
    story.append(PageBreak())
    return story


def build_attack_surface(styles: dict, attack_data: list) -> list:
    story = []
    story.append(Paragraph("2. Attack Surface & Confirmed Paths", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=10))

    if not attack_data:
        story.append(Paragraph("No attack simulation data provided.", styles["body"]))
        return story

    for sim in attack_data:
        persona = sim.get("persona", "Unknown")
        score   = sim.get("exploit_score", 0)
        ttc     = sim.get("time_to_compromise_hours", 0)
        detect  = sim.get("detection_likelihood", 0)
        vulns   = sim.get("aws_confirmed_vulns", [])
        recs    = sim.get("recommendations", [])
        kc      = sim.get("kill_chain", [])

        score_color = "#da3633" if score >= 0.7 else "#d29922" if score >= 0.4 else "#3fb950"
        story.append(Paragraph(f"2.{attack_data.index(sim)+1} {persona}", styles["h2"]))

        meta_data = [
            ["Exploit Score", f'<font color="{score_color}"><b>{score}</b></font>',
             "Time to Compromise", f"{ttc}h",
             "Detection Likelihood", f"{int(detect*100)}%"],
        ]
        meta_table = Table(
            [[Paragraph(c, styles["body"]) if i % 2 == 0 else Paragraph(c, styles["h3"]) for i, c in enumerate(meta_data[0])]],
            colWidths=[4*cm, 3*cm, 4.5*cm, 2.5*cm, 4.5*cm, 2.5*cm],
        )
        meta_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_PANEL),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3 * cm))

        # Kill chain
        if kc:
            story.append(Paragraph("Kill Chain Steps:", styles["h3"]))
            kc_data = [["Phase", "Technique", "Target", "Success%", "Detect Risk"]]
            for step in kc:
                kc_data.append([
                    step.get("phase", ""),
                    Paragraph(step.get("technique", ""), styles["body"]),
                    step.get("target", ""),
                    f"{int(step.get('success_prob', 0) * 100)}%",
                    f"{int(step.get('detection_risk', 0) * 100)}%",
                ])
            kc_table = Table(kc_data, colWidths=[3.5*cm, 7.5*cm, 2.5*cm, 2*cm, 2.5*cm])
            kc_table.setStyle(TableStyle([
                ("BACKGROUND",     (0, 0), (-1, 0), C_DARK),
                ("TEXTCOLOR",      (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",       (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
                ("BOX",            (0, 0), (-1, -1), 0.5, C_BORDER),
                ("INNERGRID",      (0, 0), (-1, -1), 0.25, C_BORDER),
                ("VALIGN",         (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING",    (0, 0), (-1, -1), 6),
                ("TOPPADDING",     (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
            ]))
            story.append(kc_table)
            story.append(Spacer(1, 0.3 * cm))

        # Confirmed vulns
        if vulns:
            story.append(Paragraph("AWS-Confirmed Vulnerabilities:", styles["h3"]))
            for v in vulns:
                story.append(Paragraph(f"• {v}", styles["critical"]))
            story.append(Spacer(1, 0.2 * cm))

        # Recs
        if recs:
            story.append(Paragraph("Recommendations:", styles["h3"]))
            for r in recs:
                story.append(Paragraph(f"→ {r}", styles["body"]))

        story.append(Spacer(1, 0.5 * cm))

    story.append(PageBreak())
    return story


def build_remediation_roadmap(styles: dict, all_recs: list[str]) -> list:
    story = []
    story.append(Paragraph("3. Remediation Roadmap", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=10))

    # Deduplicate and prioritise
    seen = set()
    unique_recs = []
    for r in all_recs:
        if r not in seen:
            seen.add(r)
            unique_recs.append(r)

    priority_map = {
        "CRITICAL": [r for r in unique_recs if "CRITICAL" in r or "immediately" in r.lower() or "mfa" in r.lower()],
        "HIGH":     [r for r in unique_recs if "7 days" in r or "GuardDuty" in r or "rotate" in r.lower() or "remove" in r.lower()],
        "MEDIUM":   [r for r in unique_recs if "30 days" in r or "Backup" in r or "Pin" in r or "Version" in r],
        "LOW":      [r for r in unique_recs if r not in
                     [x for lst in [
                         [r for r in unique_recs if "CRITICAL" in r or "immediately" in r.lower() or "mfa" in r.lower()],
                         [r for r in unique_recs if "7 days" in r or "GuardDuty" in r or "rotate" in r.lower()],
                         [r for r in unique_recs if "30 days" in r or "Backup" in r or "Pin" in r],
                     ] for x in lst]],
    }

    timeframes = {"CRITICAL": "Immediate (≤48h)", "HIGH": "Short-term (≤7 days)", "MEDIUM": "Mid-term (≤30 days)", "LOW": "Long-term (≤90 days)"}

    for sev, recs in priority_map.items():
        if not recs:
            continue
        sev_color = SEVERITY_COLORS.get(sev, C_GREY)
        story.append(Paragraph(f"{_severity_badge(sev)} — {timeframes[sev]}", styles["h2"]))
        rd_data = [["#", "Action", "AWS Service"]]
        for i, r in enumerate(recs, 1):
            service = "IAM" if "iam" in r.lower() or "mfa" in r.lower() or "role" in r.lower() else \
                      "S3" if "s3" in r.lower() or "bucket" in r.lower() else \
                      "EC2" if "security group" in r.lower() else \
                      "CloudTrail" if "cloudtrail" in r.lower() else \
                      "GuardDuty" if "guardduty" in r.lower() else \
                      "Multi-service"
            rd_data.append([str(i), Paragraph(r, styles["body"]), service])

        rd_table = Table(rd_data, colWidths=[1*cm, 14*cm, 3*cm])
        rd_table.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",      (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("BOX",            (0, 0), (-1, -1), 0.5, C_BORDER),
            ("INNERGRID",      (0, 0), (-1, -1), 0.25, C_BORDER),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LINEAFTER",      (0, 0), (0, -1), 1, sev_color),
        ]))
        story.append(rd_table)
        story.append(Spacer(1, 0.4 * cm))

    story.append(PageBreak())
    return story


def build_appendix(styles: dict, raw_json_files: list[str]) -> list:
    story = []
    story.append(Paragraph("Appendix: Raw Evidence Files", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=10))
    story.append(Paragraph(
        "The following JSON evidence files were generated during the assessment and are referenced in this report:",
        styles["body"]
    ))
    story.append(Spacer(1, 0.3 * cm))
    for f in raw_json_files:
        story.append(Paragraph(f"• {f}", styles["code"]))
    return story


# ──────────────────────────────────────────────
# HTML Fallback Report
# ──────────────────────────────────────────────

def generate_html_report(output_path: str, meta: dict, findings: dict, attack_data: list, all_recs: list) -> str:
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    critical = findings.get("critical", 0)
    high     = findings.get("high", 0)
    medium   = findings.get("medium", 0)
    low      = findings.get("low", 0)

    rows = ""
    for sim in attack_data:
        score = sim.get("exploit_score", 0)
        color = "#da3633" if score >= 0.7 else "#d29922" if score >= 0.4 else "#3fb950"
        vulns_html = "".join(f"<li style='color:#da3633'>{v}</li>" for v in sim.get("aws_confirmed_vulns", []))
        recs_html  = "".join(f"<li>{r}</li>" for r in sim.get("recommendations", []))
        kc_rows = ""
        for step in sim.get("kill_chain", []):
            kc_rows += f"""
            <tr>
              <td>{step.get('phase','')}</td>
              <td>{step.get('technique','')}</td>
              <td>{step.get('target','')}</td>
              <td>{int(step.get('success_prob',0)*100)}%</td>
              <td>{int(step.get('detection_risk',0)*100)}%</td>
            </tr>"""
        rows += f"""
        <div class="persona-block">
          <h3>{sim.get('persona','')}</h3>
          <div class="meta-row">
            <span>Exploit Score: <b style="color:{color}">{score}</b></span>
            <span>Time to Compromise: <b>{sim.get('time_to_compromise_hours',0)}h</b></span>
            <span>Detection: <b>{int(sim.get('detection_likelihood',0)*100)}%</b></span>
          </div>
          <h4>Kill Chain</h4>
          <table><thead><tr><th>Phase</th><th>Technique</th><th>Target</th><th>Success%</th><th>Detect Risk</th></tr></thead>
          <tbody>{kc_rows}</tbody></table>
          {"<h4>Confirmed Vulnerabilities</h4><ul>" + vulns_html + "</ul>" if vulns_html else ""}
          {"<h4>Recommendations</h4><ul>" + recs_html + "</ul>" if recs_html else ""}
        </div>"""

    recs_html_all = "".join(f"<li>{r}</li>" for r in dict.fromkeys(all_recs))

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>AZTCSE Report — {meta.get('target','AWS')}</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#f0f6fc;margin:0;padding:2rem}}
  h1{{color:#1f6feb;border-bottom:1px solid #30363d;padding-bottom:.5rem}}
  h2{{color:#58a6ff}} h3{{color:#8b949e}} h4{{color:#d29922}}
  table{{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.85rem}}
  th{{background:#161b22;color:#f0f6fc;padding:.5rem;text-align:left;border:1px solid #30363d}}
  td{{padding:.4rem .5rem;border:1px solid #30363d;vertical-align:top}}
  tr:nth-child(even){{background:#161b22}}
  .badge-critical{{color:#da3633;font-weight:bold}}
  .badge-high{{color:#e3642c;font-weight:bold}}
  .badge-medium{{color:#d29922;font-weight:bold}}
  .badge-low{{color:#3fb950;font-weight:bold}}
  .persona-block{{background:#161b22;border:1px solid #30363d;padding:1rem;margin:1rem 0;border-radius:6px}}
  .meta-row{{display:flex;gap:2rem;margin:.5rem 0;font-size:.9rem}}
  .cover{{text-align:center;padding:3rem 0;border-bottom:1px solid #30363d;margin-bottom:2rem}}
  footer{{color:#8b949e;font-size:.8rem;text-align:center;margin-top:3rem;border-top:1px solid #30363d;padding-top:1rem}}
</style></head><body>
<div class="cover">
  <h1 style="font-size:2.5rem;border:none">AZTCSE</h1>
  <p style="color:#8b949e;font-size:1.2rem">Cloud Security Assessment Report</p>
  <p>Target: <b>{meta.get('target','AWS Account')}</b> &nbsp;|&nbsp; Account: {meta.get('account_id','N/A')} &nbsp;|&nbsp; Region: {meta.get('region','us-east-1')}</p>
  <p style="color:#8b949e">Generated: {ts} &nbsp;|&nbsp; Assessor: {meta.get('assessor','AZTCSE')}</p>
</div>
<h1>1. Executive Summary</h1>
<table><tr>
  <th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Confirmed Paths</th><th>Risk Score</th>
</tr><tr>
  <td class="badge-critical">{critical}</td>
  <td class="badge-high">{high}</td>
  <td class="badge-medium">{medium}</td>
  <td class="badge-low">{low}</td>
  <td>{findings.get('confirmed_attack_paths',0)}</td>
  <td><b>{findings.get('overall_risk_score',0):.2f}</b></td>
</tr></table>
<h1>2. Attack Surface & Confirmed Paths</h1>{rows}
<h1>3. Remediation Roadmap</h1><ul>{recs_html_all}</ul>
<footer>CONFIDENTIAL — AZTCSE Automated Security Assessment — {ts}</footer>
</body></html>"""

    with open(output_path, "w") as f:
        f.write(html)
    return output_path


# ──────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────

def generate_report(
    account_id: str = "",
    region: str = "us-east-1",
    client_name: str = "Assessment Target",
    assessor: str = "AZTCSE Automated Engine",
    assessor_name: str = "",
    classification: str = "CONFIDENTIAL",
    attack_json_files: list[str] | None = None,
    output_dir: str = ".",
) -> str:
    """
    Generate a professional post-exploitation PDF (or HTML fallback) report.

    Args:
        attack_json_files: list of JSON output files from attack2 / attacker_sim_extended
        output_dir: where to save the report
    Returns:
        Path to the generated report file
    """
    console.rule("[bold blue]Module 13: Post-Exploitation Report Generator[/bold blue]")

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    date_str = datetime.utcnow().strftime("%Y-%m-%d")

    assessor = assessor_name or assessor
    meta = {
        "target":         client_name,
        "account_id":     account_id,
        "region":         region,
        "assessor":       assessor,
        "classification": classification,
        "client":         client_name,
        "date":           date_str,
    }

    # Load attack data from JSON files
    all_attack_data: list[dict] = []
    all_recommendations: list[str] = []
    json_files_found: list[str] = []

    if attack_json_files:
        for jf in attack_json_files:
            if Path(jf).exists():
                json_files_found.append(jf)
                with open(jf) as f:
                    data = json.load(f)
                sims = data.get("simulations", [])
                all_attack_data.extend(sims)
                for s in sims:
                    all_recommendations.extend(s.get("recommendations", []))
    else:
        # Auto-discover JSON files in current directory
        for jf in sorted(Path(output_dir).glob("attack_sim_*.json"), reverse=True):
            json_files_found.append(str(jf))
            with open(jf) as f:
                data = json.load(f)
            sims = data.get("simulations", [])
            all_attack_data.extend(sims)
            for s in sims:
                all_recommendations.extend(s.get("recommendations", []))

    console.print(f"  [cyan]●[/cyan] Loaded {len(json_files_found)} JSON evidence file(s)")
    console.print(f"  [cyan]●[/cyan] Total simulations: {len(all_attack_data)}")

    # Compute aggregate findings
    confirmed_total = sum(len(s.get("aws_confirmed_vulns", [])) for s in all_attack_data)
    avg_score = sum(s.get("exploit_score", 0) for s in all_attack_data) / max(len(all_attack_data), 1)
    findings = {
        "total_findings":       confirmed_total + len(all_recommendations),
        "critical":             sum(1 for s in all_attack_data if s.get("exploit_score", 0) >= 0.75),
        "high":                 sum(1 for s in all_attack_data if 0.5 <= s.get("exploit_score", 0) < 0.75),
        "medium":               sum(1 for s in all_attack_data if 0.25 <= s.get("exploit_score", 0) < 0.5),
        "low":                  sum(1 for s in all_attack_data if s.get("exploit_score", 0) < 0.25),
        "confirmed_attack_paths": confirmed_total,
        "overall_risk_score":   round(avg_score, 2),
    }

    if REPORTLAB_AVAILABLE:
        output_path = str(Path(output_dir) / f"aztcse_report_{ts}.pdf")
        console.print(f"  [cyan]●[/cyan] Generating PDF report...")

        styles = build_styles()
        doc = AZTCSEDocTemplate(output_path, report_meta=meta, pagesize=A4)

        story = []
        story += build_cover(styles, meta)
        story += build_exec_summary(styles, findings)
        story += build_attack_surface(styles, all_attack_data)
        story += build_remediation_roadmap(styles, all_recommendations)
        story += build_appendix(styles, json_files_found)

        doc.build(story)
        console.print(f"  [green]✓ PDF report saved: {output_path}[/green]")
    else:
        output_path = str(Path(output_dir) / f"aztcse_report_{ts}.html")
        console.print(f"  [yellow]⚠ reportlab not installed — generating HTML report instead[/yellow]")
        console.print(f"    Install with: pip install reportlab")
        generate_html_report(output_path, meta, findings, all_attack_data, all_recommendations)
        console.print(f"  [green]✓ HTML report saved: {output_path}[/green]")

    return output_path
