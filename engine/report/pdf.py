# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/pdf.py — PDF brief via fpdf2 (pure Python).
#  Installed by bootstrap-5-report.sh
# =============================================================================
"""Render the assessment to PDF using fpdf2 (no system libraries required).

The import is gated: if fpdf2 is not installed the run logs a one-line hint and
continues — the HTML and JSON briefs are always produced regardless.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_SEVERITY_RGB = {
    "critical": (176, 0, 32), "high": (232, 89, 12), "medium": (240, 140, 0),
    "low": (47, 158, 68), "info": (134, 142, 150),
}


def _ascii(text: Any) -> str:
    """Reduce text to the latin-1 range fpdf2 core fonts can render."""
    replacements = {"\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
                    "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " ", "\u2022": "-"}
    out = str(text)
    for bad, good in replacements.items():
        out = out.replace(bad, good)
    return out.encode("latin-1", "replace").decode("latin-1")


def render_pdf(assessment: dict[str, Any], operator: str, tool_name: str,
               out_path: Path, logger: logging.Logger) -> bool:
    """Render the PDF; return True on success, False if fpdf2 is unavailable."""
    try:
        from fpdf import FPDF
    except Exception as exc:  # noqa: BLE001 — any import failure means "skip PDF"
        logger.warning("PDF skipped (fpdf2 unavailable: %s). Install with: pip install fpdf2", exc)
        return False

    case = assessment.get("case", {})
    summary = assessment.get("summary", {})
    prov = assessment.get("provenance", {})

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin

    # Title band.
    pdf.set_fill_color(11, 16, 32)
    pdf.rect(0, 0, pdf.w, 26, style="F")
    pdf.set_xy(pdf.l_margin, 8)
    pdf.set_text_color(0, 211, 111)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 8, _ascii("Psypher AI Threat Assessment Brief"))
    pdf.set_xy(pdf.l_margin, 16)
    pdf.set_text_color(180, 192, 208)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, _ascii(f"{tool_name} · PsypherLabs"))
    pdf.ln(18)

    pdf.set_text_color(30, 35, 45)
    pdf.set_font("Helvetica", "", 9)
    for label, value in (("Case", case.get("id", "")), ("Target", case.get("target_name", "")),
                         ("Generated", case.get("created", "")), ("Operator", operator),
                         ("Engine", f"v{case.get('tool_version','')}")):
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(24, 5, _ascii(label))
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _ascii(value), ln=1)
    pdf.ln(2)

    # Summary.
    _heading(pdf, "Executive summary")
    by_sev = summary.get("by_severity", {})
    sev_line = "   ".join(f"{lvl}: {by_sev.get(lvl,0)}" for lvl in ("critical", "high", "medium", "low", "info"))
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(width, 5, _ascii(sev_line))
    pdf.multi_cell(width, 5, _ascii(f"{summary.get('findings_total',0)} finding(s)  ·  "
                                    f"frameworks: {', '.join(summary.get('frameworks', [])) or 'none'}  ·  "
                                    f"graph {prov.get('graph_hash','')}"))
    pdf.ln(2)

    # Findings.
    _heading(pdf, "Findings")
    findings = assessment.get("findings", [])
    if not findings:
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(width, 5, _ascii("No findings. The observed components did not match any known vulnerability."))
    for finding in findings:
        _finding_block(pdf, finding, width)

    # Kill chain.
    _heading(pdf, "Attack path (kill chain)")
    steps = [s for chain in assessment.get("kill_chains", []) for s in chain.get("steps", [])]
    if not steps:
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(width, 5, _ascii("No multi-step attack path was assembled."))
    else:
        pdf.set_font("Helvetica", "", 8.5)
        for step in steps:
            mit = step.get("mitigated_by", "") or "-"
            pdf.multi_cell(width, 4.6, _ascii(f"{step.get('order','')}. {step.get('note','')}  "
                                              f"[{step.get('ref','')}, mitigated_by {mit}]"))

    # Provenance footer.
    pdf.ln(3)
    pdf.set_draw_color(210, 216, 224)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(100, 116, 139)
    src = ", ".join(f"{k} {v}" for k, v in prov.get("source_versions", {}).items()) or "n/a"
    pdf.multi_cell(width, 4, _ascii(
        f"Provenance: engine v{prov.get('tool_version','')} · graph hash {prov.get('graph_hash','')} · "
        f"data: {src} · probes executed: {len(prov.get('probe_log', []))}. "
        "Every identifier in this brief was validated against the knowledge graph. (c) 2026 PsypherLabs."))

    try:
        pdf.output(str(out_path))
    except Exception as exc:  # noqa: BLE001
        logger.error("PDF rendering failed: %s", exc)
        return False
    return True


def _heading(pdf, text: str) -> None:
    pdf.ln(2)
    pdf.set_text_color(11, 16, 32)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, _ascii(text), ln=1)
    pdf.set_draw_color(0, 211, 111)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 40, pdf.get_y())
    pdf.ln(2)
    pdf.set_text_color(30, 35, 45)


def _finding_block(pdf, finding: dict[str, Any], width: float) -> None:
    severity = finding.get("severity", "info")
    rgb = _SEVERITY_RGB.get(severity, (134, 142, 150))
    vuln = (finding.get("vulnerabilities") or [{}])[0]
    cvss = vuln.get("cvss")
    cvss_text = f"{cvss}" if cvss is not None else "not scored"
    cwe = vuln.get("cwe") or finding.get("evidence", {}).get("cwe", "")

    pdf.ln(1)
    pdf.set_fill_color(*rgb)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(22, 5, _ascii(f" {severity.upper()} "), fill=True)
    pdf.set_text_color(20, 25, 35)
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.multi_cell(width - 22, 5, _ascii(finding.get("title", "")))
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(70, 85, 105)
    pdf.multi_cell(width, 4.4, _ascii(
        f"{finding.get('id','')}  |  {vuln.get('cve','')}  |  {cwe}  |  "
        f"CVSS {cvss_text}  |  confidence {finding.get('confidence','')}  |  "
        f"match {finding.get('evidence',{}).get('match','')}"))
    pdf.set_text_color(31, 41, 55)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.multi_cell(width, 4.6, _ascii(finding.get("attack_path", "")))
    techniques = ", ".join(f"{t.get('id','')} {t.get('name','')}".strip() for t in finding.get("techniques", []))
    mitigations = ", ".join(m.get("id", "") for m in finding.get("mitigations", []))
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(90, 100, 120)
    pdf.multi_cell(width, 4.2, _ascii(f"Techniques: {techniques or 'none'}"))
    pdf.multi_cell(width, 4.2, _ascii(f"Mitigations: {mitigations or 'none'}"))
    pdf.ln(1)
