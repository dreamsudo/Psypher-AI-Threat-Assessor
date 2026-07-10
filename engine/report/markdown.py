# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/markdown.py — plain-text Markdown brief (diff-able).
#  Authored by PsypherLabs (WS-D).
# =============================================================================
"""Render the assessment to a Markdown brief.

A light, diff-able sibling of the HTML/PDF briefs sharing their information
architecture: a forensic metadata header, then the two attack surfaces as
sections -- Infrastructure (CVE + host-isolation posture) and Behavioral (the
model under adversarial input) -- each finding stamped proved/assumed, carrying
its attack detail and its graph-grounded MITRE defenses (labeled by framework),
its evidence in a fenced block, and a single provenance line. Findings are
ordered act-now first. A pure function over the assessment dict: no model, no
network, no evidence-log dependency, so it renders identically for any run.
"""
from __future__ import annotations

from typing import Any

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_PRIORITY_RANK = {"act-now": 0, "high": 1, "scheduled": 2}
_BEHAVIORAL_MATCH = {"behavioral", "assessed-possible"}
_FRAMEWORK_ORDER = {"ATLAS": 0, "ATT&CK": 1, "D3FEND": 2}


def _is_behavioral(finding: dict[str, Any]) -> bool:
    """Branch B (model behavioral) findings carry a behavioral match label or an
    exchange-log link; everything else (CVE, posture) is Branch A infrastructure."""
    ev = finding.get("evidence") or {}
    return ev.get("match") in _BEHAVIORAL_MATCH or bool(ev.get("exchange_id"))


def _is_proved(finding: dict[str, Any]) -> bool:
    """Proved = a version-confirmed CVE or a demonstrated behavioral compliance.
    Everything else (backport-unverified lead, 'possible'/'reachable' inference)
    is assumed -- honest labeling, never over-claimed."""
    ev = finding.get("evidence") or {}
    if ev.get("grade") == "demonstrated":
        return True
    if ev.get("verify_distro_patch"):
        return False
    return ev.get("version_confirmed") is True


def _sort_key(finding: dict[str, Any]):
    ev = finding.get("evidence") or {}
    return (_PRIORITY_RANK.get(ev.get("priority"), 3),
            _SEV_RANK.get(finding.get("severity"), 5),
            finding.get("id", ""))


def _model_under_test(findings: list) -> str:
    for f in findings:
        m = (f.get("evidence") or {}).get("target_model")
        if m:
            return m
    return "n/a"


def _mitigation_lines(finding: dict[str, Any]) -> list[str]:
    """Graph-grounded MITRE defenses as framework-labeled lines, grouped
    ATLAS -> ATT&CK -> D3FEND. Honest degrade when none are mapped."""
    mits = finding.get("mitigations") or []
    if not mits:
        return ["- _No MITRE countermeasure mapped for this technique._"]
    rows = sorted(mits, key=lambda m: (_FRAMEWORK_ORDER.get(m.get("framework", ""), 9),
                                       m.get("id", "")))
    out = []
    for m in rows:
        line = f"- **{m.get('framework', '?')}** · `{m.get('id', '?')}`"
        text = m.get("text", "")
        if text:
            line += f" — {text}"
        out.append(line)
    return out


def _attack_lines(finding: dict[str, Any]) -> list[str]:
    """The offensive side, shaped by branch (CVE vs technique)."""
    ev = finding.get("evidence") or {}
    lines: list[str] = []
    vulns = finding.get("vulnerabilities") or []
    if vulns:  # CVE (infrastructure)
        v = vulns[0]
        cvss = v.get("cvss")
        parts = [f"`{v.get('cve', '')}`"]
        if v.get("cwe"):
            parts.append(f"`{v.get('cwe')}`")
        parts.append(f"CVSS {cvss if cvss is not None else 'not scored'}")
        lines.append("- " + " · ".join(str(p) for p in parts))
        if ev.get("exploited"):
            rw = " · ransomware-linked" if ev.get("kev_ransomware") else ""
            lines.append(f"- **CISA KEV: actively exploited** "
                         f"(added {ev.get('kev_date_added', '')}){rw} — priority act-now")
        if v.get("mechanism"):
            lines.append(f"- {v.get('mechanism')}")
        if ev.get("verify_distro_patch"):
            lines.append(f"- Lead: {ev.get('match_basis', 'distro backport status unverified')}")
    for t in finding.get("techniques") or []:  # technique (behavioral / posture)
        line = f"- **{t.get('framework', '?')}** · `{t.get('id', '')}`"
        if t.get("name"):
            line += f" — {t.get('name')}"
        lines.append(line)
    if ev.get("verdict"):
        lines.append(f"- Verdict: **{ev.get('verdict')}**")
    return lines or ["- (no attack detail recorded)"]


def _evidence_block(finding: dict[str, Any]) -> list[str]:
    ev = finding.get("evidence") or {}
    if not ev:
        return []
    order = ["match", "grade", "verdict", "method", "access_tier", "observed_version",
             "version_confirmed", "exploited", "priority", "kev_date_added",
             "kev_ransomware", "verify_distro_patch", "cwe", "target_model",
             "exchange_id", "supporting_grains", "match_basis", "rationale"]
    seen: set = set()
    lines = ["```"]
    for k in order:
        if k in ev:
            seen.add(k)
            lines.append(f"{k}: {ev[k]}")
    for k in sorted(ev):
        if k not in seen:
            lines.append(f"{k}: {ev[k]}")
    lines.append("```")
    return lines


def _provenance_line(finding: dict[str, Any]) -> str:
    ev = finding.get("evidence") or {}
    bits = [finding.get("id", "?"), finding.get("component", "?"),
            f"confidence={finding.get('confidence', '?')}"]
    for key, label in (("match", "match"), ("method", "method"),
                       ("access_tier", "access"), ("target_model", "model"),
                       ("exchange_id", "exchange")):
        if ev.get(key):
            bits.append(f"{label}={ev[key]}")
    grains = ev.get("supporting_grains")
    if isinstance(grains, list):
        bits.append(f"grains={len(grains)}")
    return "`" + " · ".join(str(b) for b in bits) + "`"


def _finding_section(finding: dict[str, Any]) -> list[str]:
    sev = (finding.get("severity") or "info").upper()
    proved = "PROVED" if _is_proved(finding) else "ASSUMED"
    out = [f"### {sev} · {proved} · {finding.get('title', '(untitled)')}", ""]
    out += _attack_lines(finding)
    out += ["", "**Defense:**"]
    out += _mitigation_lines(finding)
    block = _evidence_block(finding)
    if block:
        out += ["", "**Evidence:**"]
        out += block
    out += ["", _provenance_line(finding), ""]
    return out


def _surface(title: str, findings: list) -> list[str]:
    out = [f"## {title}", ""]
    if not findings:
        return out + ["_No findings on this surface._", ""]
    for f in sorted(findings, key=_sort_key):
        out += _finding_section(f)
    return out


def render_markdown(assessment: dict[str, Any], operator: str, tool_name: str) -> str:
    case = assessment.get("case") or {}
    prov = assessment.get("provenance") or {}
    summary = assessment.get("summary") or {}
    findings = assessment.get("findings") or []

    behavioral = [f for f in findings if _is_behavioral(f)]
    infra = [f for f in findings if not _is_behavioral(f)]

    by_sev = summary.get("by_severity") or {}
    sev_line = ", ".join(f"{k}: {by_sev[k]}" for k in
                         ("critical", "high", "medium", "low", "info") if k in by_sev) or "none"
    frameworks = ", ".join(summary.get("frameworks") or []) or "none"

    lines = [
        f"# {tool_name} — Assessment Brief",
        "",
        "Full-stack AI/ML security — MITRE ATLAS–grounded penetration testing of the "
        "model and the infrastructure it runs on.",
        "",
        "## Case metadata",
        "",
        f"- **Case:** `{case.get('id', '?')}`",
        f"- **Target:** {case.get('target_name', '?')}",
        f"- **Model under test:** {_model_under_test(findings)}",
        f"- **Operator:** {operator}",
        f"- **Engine version:** {case.get('tool_version', prov.get('tool_version', '?'))}",
        f"- **Created:** {case.get('created', prov.get('created', '?'))}",
        f"- **Graph hash:** `{prov.get('graph_hash', '?')}`",
    ]
    src = prov.get("source_versions") or {}
    if src:
        lines.append("- **Graph sources:** " + ", ".join(f"{k} {v}" for k, v in sorted(src.items())))
    lines += [
        f"- **Findings:** {summary.get('findings_total', len(findings))} ({sev_line})",
        f"- **Frameworks:** {frameworks}",
        f"- **Surfaces:** {len(infra)} infrastructure · {len(behavioral)} behavioral",
        "- **Evidence chain:** verify with `python -m tests.verify --mode audit`",
        "",
        "Legend — **PROVED**: version-confirmed CVE or demonstrated model compliance. "
        "**ASSUMED**: inferred/verify (backport-unconfirmed lead or reachable-by-inference "
        "posture). Findings ordered act-now first.",
        "",
    ]
    lines += _surface("Infrastructure — CVE and host-isolation posture", infra)
    lines += _surface("Behavioral — the model under adversarial input", behavioral)
    lines += [
        "---",
        "",
        "Every identifier in this brief was validated against the knowledge graph before "
        "it was written. Powered by Claude · Designed by PsypherLabs.",
        "",
    ]
    return "\n".join(lines)
