"""Audit report generation.

Produces a self-contained, branded HTML report (posture score, findings,
compliance scorecards and a score trend sparkline) suitable as an audit
deliverable. The HTML is print-ready, so a PDF is one browser "Print to PDF"
away — avoiding heavy native PDF dependencies.
"""

import html
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils import compliance
from utils.scoring import PostureScore

GRADE_COLORS = {"A": "#28c76f", "B": "#28c76f", "C": "#ff9f43", "D": "#ff9f43", "F": "#ea5455"}
SEVERITY_COLORS = {
    "critical": "#b71c1c", "high": "#ea5455", "medium": "#ff9f43", "low": "#1e88e5", "info": "#78909c"
}


def _sparkline(scores: List[int], width: int = 240, height: int = 48) -> str:
    """Render a list of scores (oldest→newest) as an inline SVG sparkline."""
    if not scores:
        return ""
    if len(scores) == 1:
        scores = scores * 2
    n = len(scores)
    step = width / (n - 1)
    points = " ".join(f"{i * step:.1f},{height - (s / 100) * height:.1f}" for i, s in enumerate(scores))
    last_color = GRADE_COLORS.get("A" if scores[-1] >= 80 else "C" if scores[-1] >= 60 else "F", "#888")
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<polyline fill="none" stroke="{last_color}" stroke-width="2" points="{points}"/>'
        f"</svg>"
    )


def _findings_rows(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return '<tr><td colspan="4" style="text-align:center;color:#28c76f;">No issues detected ✅</td></tr>'
    rows = []
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        color = SEVERITY_COLORS.get(sev, "#78909c")
        rows.append(
            f"<tr>"
            f'<td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{html.escape(sev.upper())}</span></td>'
            f"<td>{html.escape(str(f.get('category', '')))}</td>"
            f"<td>{html.escape(str(f.get('detail', '')))}</td>"
            f"<td>{html.escape(str(f.get('recommendation') or ''))}</td>"
            f"</tr>"
        )
    return "".join(rows)


def _compliance_section(findings: List[Dict[str, Any]]) -> str:
    cards = []
    for name, scorecard in compliance.evaluate_all(findings).items():
        pct = scorecard.compliance_percent
        color = "#28c76f" if pct >= 80 else "#ff9f43" if pct >= 50 else "#ea5455"
        control_rows = "".join(
            f"<li style='color:{'#28c76f' if c.compliant else '#ea5455'};'>"
            f"{'✓' if c.compliant else '✗'} {html.escape(c.control_id)} — {html.escape(c.title)}</li>"
            for c in scorecard.controls
        )
        cards.append(
            f'<div class="card"><h3>{html.escape(name)} '
            f'<span style="color:{color};">{pct}%</span></h3>'
            f"<ul>{control_rows}</ul></div>"
        )
    return "".join(cards)


def generate_html_report(
    report: Dict[str, Any],
    posture: PostureScore,
    history_scores: Optional[List[int]] = None,
) -> str:
    """Build a full HTML audit report for a single asset."""
    target = html.escape(str(report.get("target", "unknown")))
    grade = posture.grade
    grade_color = GRADE_COLORS.get(grade, "#888")
    findings = report.get("findings", [])
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    trend = _sparkline(history_scores or [posture.score])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Audit Report — {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #0f1117; color: #e6e6e6; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px; }}
  header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #2a2d3a; padding-bottom: 16px; }}
  .brand {{ font-weight: 800; letter-spacing: 1px; color: #66fcf1; }}
  .score-badge {{ font-size: 64px; font-weight: 900; color: {grade_color}; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a2d3a; font-size: 14px; }}
  th {{ color: #a9b2c3; text-transform: uppercase; font-size: 12px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; }}
  .card {{ flex: 1 1 280px; background: #171a23; border: 1px solid #2a2d3a; border-radius: 8px; padding: 14px; }}
  .card ul {{ list-style: none; padding: 0; margin: 8px 0 0; font-size: 13px; line-height: 1.7; }}
  h2 {{ color: #66fcf1; margin-top: 32px; }}
  @media print {{ body {{ background: #fff; color: #000; }} .card {{ background: #fafafa; }} }}
</style></head>
<body><div class="wrap">
  <header>
    <div><span class="brand">MHcheck</span> · Security Posture Audit</div>
    <div style="text-align:right;color:#a9b2c3;font-size:13px;">{generated}</div>
  </header>

  <h2>Asset: {target}</h2>
  <div style="display:flex;align-items:center;gap:32px;">
    <div><div class="score-badge">{grade}</div><div style="color:#a9b2c3;">{posture.score}/100</div></div>
    <div>
      <div style="color:#a9b2c3;font-size:13px;">Score trend</div>{trend}
      <div style="color:#a9b2c3;font-size:13px;margin-top:6px;">{posture.findings_total} finding(s) · {html.escape(str(dict(posture.severity_counts)))}</div>
    </div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Detail</th><th>Recommendation</th></tr></thead>
    <tbody>{_findings_rows(findings)}</tbody>
  </table>

  <h2>Compliance Scorecards</h2>
  <div class="cards">{_compliance_section(findings)}</div>

  <p style="margin-top:40px;color:#5a6172;font-size:12px;">Generated by MHcheck Audit Platform. For authorized assessment only.</p>
</div></body></html>"""


def save_html_report(report: Dict[str, Any], posture: PostureScore, path: str, history_scores: Optional[List[int]] = None) -> str:
    content = generate_html_report(report, posture, history_scores)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _ascii(text: str) -> str:
    """Down-convert to latin-1 so the core PDF fonts can render arbitrary input."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def generate_pdf_report(
    report: Dict[str, Any],
    posture: PostureScore,
    path: str,
    history_scores: Optional[List[int]] = None,
) -> str:
    """Render a native PDF audit report using fpdf2 (pure Python, no system libs)."""
    from fpdf import FPDF  # imported lazily so the dep is only needed for PDF export

    target = str(report.get("target", "unknown"))
    findings = report.get("findings", [])
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "MHcheck - Security Posture Audit", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(110, 110, 110)
    pdf.cell(0, 6, _ascii(f"Asset: {target}    Generated: {generated}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, _ascii(f"Posture score: {posture.score}/100   Grade: {posture.grade}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _ascii(f"{posture.findings_total} finding(s) - {dict(posture.severity_counts)}"), new_x="LMARGIN", new_y="NEXT")
    if history_scores:
        pdf.cell(0, 6, _ascii(f"Score trend: {history_scores}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    if not findings:
        pdf.cell(0, 6, "No issues detected.", new_x="LMARGIN", new_y="NEXT")
    for f in findings:
        sev = str(f.get("severity", "info")).upper()
        line = f"[{sev}] {f.get('category', '')}: {f.get('detail', '')}"
        pdf.multi_cell(0, 5, _ascii(line))
        rec = f.get("recommendation")
        if rec:
            pdf.set_text_color(90, 90, 90)
            pdf.multi_cell(0, 5, _ascii(f"    -> {rec}"))
            pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Compliance Scorecards", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for name, scorecard in compliance.evaluate_all(findings).items():
        pdf.multi_cell(
            0, 5,
            _ascii(f"{name}: {scorecard.compliance_percent}% compliant ({scorecard.controls_compliant}/{scorecard.controls_total})"),
        )

    pdf.output(path)
    return path
