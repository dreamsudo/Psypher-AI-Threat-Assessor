# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/html.py — styled, self-contained HTML brief.
#  Installed by bootstrap-5-report.sh
# =============================================================================
"""Render the assessment into a single, dependency-free HTML document."""
from __future__ import annotations

from html import escape
from typing import Any

_SEVERITY_COLOR = {
    "critical": "#b00020", "high": "#e8590c", "medium": "#f08c00",
    "low": "#2f9e44", "info": "#868e96",
}

_CSS = """
:root { --bg:#0b1020; --accent:#00d36f; --ink:#1a1f2b; }
* { box-sizing: border-box; }
body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       color:#1a1f2b; background:#f5f7fa; line-height:1.5; }
header { background:#0b1020; color:#e7ecf3; padding:28px 40px; border-bottom:3px solid #00d36f; }
header h1 { margin:0 0 4px; font-size:22px; letter-spacing:.3px; }
header h1 .accent { color:#00d36f; }
header .sub { color:#9fb0c3; font-size:13px; }
.meta { display:flex; flex-wrap:wrap; gap:18px; margin-top:14px; font-size:12.5px; color:#c7d2de; }
.meta b { color:#e7ecf3; font-weight:600; }
main { max-width:980px; margin:0 auto; padding:32px 24px 64px; }
h2 { font-size:16px; margin:34px 0 14px; padding-bottom:6px; border-bottom:1px solid #dde3ea; color:#0b1020; }
.chips { display:flex; flex-wrap:wrap; gap:10px; margin:8px 0 4px; }
.chip { padding:6px 12px; border-radius:20px; font-size:12px; font-weight:600; color:#fff; }
.chip .n { font-weight:700; }
.chip.zero { background:#cdd5df !important; color:#6b7280; }
.summary-line { font-size:13px; color:#475569; margin-top:6px; }
.finding { background:#fff; border:1px solid #e3e8ef; border-left-width:5px; border-radius:8px;
           padding:18px 20px; margin:14px 0; box-shadow:0 1px 2px rgba(16,24,40,.04); }
.finding h3 { margin:0 0 8px; font-size:15px; }
.badge { display:inline-block; padding:2px 9px; border-radius:5px; font-size:11px; font-weight:700;
         color:#fff; text-transform:uppercase; letter-spacing:.4px; margin-right:8px; vertical-align:middle; }
.fmeta { font-size:12px; color:#475569; margin:6px 0 10px; }
.fmeta span { margin-right:14px; }
.path { font-size:13.5px; color:#1f2937; margin:10px 0; }
.pill-row { margin:8px 0; }
.pill-row .label { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#64748b; margin-right:8px; }
.pill { display:inline-block; background:#eef2f7; border:1px solid #dde3ea; border-radius:6px;
        padding:3px 8px; font-size:11.5px; margin:3px 4px 3px 0; color:#243044; }
.pill.atlas { background:#eafff4; border-color:#b6f0d2; }
.pill.mit { background:#fff4e6; border-color:#ffe0b3; }
table { width:100%; border-collapse:collapse; font-size:12.5px; margin-top:8px; background:#fff; }
th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #e8edf3; vertical-align:top; }
th { background:#f1f4f8; color:#33415a; font-weight:600; }
td.mono,.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:11.5px; }
.kc-step td:first-child { font-weight:700; color:#0b1020; width:42px; }
footer { max-width:980px; margin:0 auto; padding:18px 24px 48px; color:#64748b; font-size:11.5px; }
.empty { color:#94a3b8; font-style:italic; padding:8px 0; }
"""


def _esc(value: Any) -> str:
    return escape(str(value), quote=True)


def _severity_chip(label: str, count: int) -> str:
    color = _SEVERITY_COLOR.get(label, "#868e96")
    cls = "chip zero" if count == 0 else "chip"
    return f'<span class="{cls}" style="background:{color}">{_esc(label)} <span class="n">{count}</span></span>'


def _technique_pill(ref: dict[str, Any]) -> str:
    cls = "pill atlas" if str(ref.get("id", "")).startswith("AML") else "pill"
    name = f' {_esc(ref.get("name",""))}' if ref.get("name") else ""
    return f'<span class="{cls}"><b class="mono">{_esc(ref.get("id",""))}</b>{name}</span>'


def _mitigation_pill(ref: dict[str, Any]) -> str:
    text = f' {_esc(ref.get("text",""))}' if ref.get("text") else ""
    return f'<span class="pill mit"><b class="mono">{_esc(ref.get("id",""))}</b>{text}</span>'


def _finding_card(finding: dict[str, Any]) -> str:
    severity = finding.get("severity", "info")
    color = _SEVERITY_COLOR.get(severity, "#868e96")
    vuln = (finding.get("vulnerabilities") or [{}])[0]
    cvss = vuln.get("cvss")
    cvss_text = f"{cvss}" if cvss is not None else "not scored"
    ev = finding.get("evidence", {})
    cwe = vuln.get("cwe") or ev.get("cwe", "")
    techniques = "".join(_technique_pill(t) for t in finding.get("techniques", [])) or '<span class="empty">none</span>'
    mitigations = "".join(_mitigation_pill(m) for m in finding.get("mitigations", [])) or '<span class="empty">none</span>'
    return f"""
    <div class="finding" style="border-left-color:{color}">
      <h3><span class="badge" style="background:{color}">{_esc(severity)}</span>{_esc(finding.get('title',''))}</h3>
      <div class="fmeta">
        <span><b>{_esc(finding.get('id',''))}</b></span>
        <span class="mono">{_esc(vuln.get('cve',''))}</span>
        <span class="mono">{_esc(cwe)}</span>
        <span>CVSS {_esc(cvss_text)}</span>
        <span>confidence: {_esc(finding.get('confidence',''))}</span>
        <span>match: {_esc(ev.get('match',''))}{(' (' + _esc(ev.get('observed_version')) + ')') if ev.get('observed_version') else ''}</span>
      </div>
      <p class="path">{_esc(finding.get('attack_path',''))}</p>
      <div class="pill-row"><span class="label">Techniques</span>{techniques}</div>
      <div class="pill-row"><span class="label">Mitigations</span>{mitigations}</div>
    </div>"""


def _kill_chain_rows(chains: list[dict[str, Any]]) -> str:
    rows = []
    for chain in chains:
        for step in chain.get("steps", []):
            rows.append(
                f'<tr class="kc-step"><td>{step.get("order","")}</td>'
                f'<td>{_esc(step.get("note",""))}</td>'
                f'<td class="mono">{_esc(step.get("ref",""))}</td>'
                f'<td>{_esc(step.get("framework",""))}</td>'
                f'<td class="mono">{_esc(step.get("mitigated_by","") or "-")}</td></tr>'
            )
    return "".join(rows)


def _grain_rows(grains: list[dict[str, Any]]) -> str:
    rows = []
    for grain in grains:
        ev = grain.get("evidence") or [{}]
        probe = ev[0].get("probe", "") if ev else ""
        rows.append(
            f'<tr><td>{_esc(grain.get("component",""))}</td>'
            f'<td class="mono">{_esc(grain.get("attribute",""))}</td>'
            f'<td>{_esc(grain.get("value",""))}</td>'
            f'<td>{_esc(grain.get("confidence",""))}</td>'
            f'<td class="mono">{_esc(probe)}</td></tr>'
        )
    return "".join(rows)


def render_html(assessment: dict[str, Any], operator: str, tool_name: str) -> str:
    """Render the full assessment to an HTML string."""
    case = assessment.get("case", {})
    summary = assessment.get("summary", {})
    by_sev = summary.get("by_severity", {})
    prov = assessment.get("provenance", {})

    chips = "".join(_severity_chip(level, by_sev.get(level, 0))
                    for level in ("critical", "high", "medium", "low", "info"))
    findings_html = "".join(_finding_card(f) for f in assessment.get("findings", [])) \
        or '<div class="empty">No findings. The observed components did not match any known vulnerability.</div>'
    kc_rows = _kill_chain_rows(assessment.get("kill_chains", []))
    kc_html = (f'<table><thead><tr><th>#</th><th>Step</th><th>Technique</th><th>Framework</th>'
               f'<th>Mitigation</th></tr></thead><tbody>{kc_rows}</tbody></table>') \
        if kc_rows else '<div class="empty">No multi-step attack path was assembled.</div>'
    grain_rows = _grain_rows(assessment.get("grains", []))
    components = ", ".join(_esc(c.get("id", "")) for c in assessment.get("components", [])) or "none"
    src = ", ".join(f"{_esc(k)} {_esc(v)}" for k, v in prov.get("source_versions", {}).items()) or "n/a"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(tool_name)} — {_esc(case.get('id',''))}</title>
<style>{_CSS}</style></head>
<body>
<header>
  <h1><span class="accent">Psypher</span> AI Threat Assessment Brief</h1>
  <div class="sub">{_esc(tool_name)} · PsypherLabs</div>
  <div class="meta">
    <span><b>Case</b> {_esc(case.get('id',''))}</span>
    <span><b>Target</b> {_esc(case.get('target_name',''))}</span>
    <span><b>Generated</b> {_esc(case.get('created',''))}</span>
    <span><b>Operator</b> {_esc(operator)}</span>
    <span><b>Engine</b> v{_esc(case.get('tool_version',''))}</span>
  </div>
</header>
<main>
  <h2>Executive summary</h2>
  <div class="chips">{chips}</div>
  <div class="summary-line">{_esc(summary.get('findings_total',0))} finding(s) · frameworks: {_esc(', '.join(summary.get('frameworks', [])) or 'none')} · graph {_esc(prov.get('graph_hash',''))}</div>

  <h2>Findings</h2>
  {findings_html}

  <h2>Attack path (kill chain)</h2>
  {kc_html}

  <h2>Observed components &amp; evidence</h2>
  <p class="summary-line">Components: {components}</p>
  {('<table><thead><tr><th>Component</th><th>Attribute</th><th>Value</th><th>Confidence</th><th>Probe</th></tr></thead><tbody>' + grain_rows + '</tbody></table>') if grain_rows else '<div class="empty">No grains were recorded.</div>'}
</main>
<footer>
  Provenance — engine v{_esc(prov.get('tool_version',''))} · graph hash {_esc(prov.get('graph_hash',''))} ·
  data: {src} · probes executed: {_esc(len(prov.get('probe_log', [])))}.
  Every technique, CWE, CVE, and mitigation identifier in this brief was validated against the knowledge graph.
  &copy; 2026 PsypherLabs.
</footer>
</body></html>"""
