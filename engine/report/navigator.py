# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/navigator.py — MITRE ATT&CK Navigator layer.
#  Installed by bootstrap-5-report.sh
# =============================================================================
"""Render a MITRE ATT&CK Navigator layer from the findings.

Each enterprise technique is scored by the highest severity among the findings
that cite it, and annotated with the responsible component and CVEs. ATLAS
(AML.*) techniques are tracked in the findings but omitted here, because the
Navigator's enterprise domain does not contain them.
"""
from __future__ import annotations

from typing import Any

_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
_COLOR = {"critical": "#b00020", "high": "#e8590c", "medium": "#f08c00",
          "low": "#2f9e44", "info": "#868e96"}


def render_navigator(assessment: dict[str, Any], attack_version: str = "17") -> dict[str, Any]:
    """Build the Navigator layer dictionary."""
    aggregate: dict[str, dict[str, Any]] = {}
    for finding in assessment.get("findings", []):
        severity = finding.get("severity", "info")
        score = _SCORE.get(severity, 10)
        color = _COLOR.get(severity, "#868e96")
        cves = ",".join(v.get("cve", "") for v in finding.get("vulnerabilities", []) if v.get("cve"))
        comment = f"{finding.get('component','')}: {cves}".strip(": ")
        for ref in finding.get("techniques", []):
            technique_id = ref.get("id", "")
            if not technique_id or technique_id.startswith("AML"):
                continue
            entry = aggregate.get(technique_id)
            if entry is None:
                aggregate[technique_id] = {"score": score, "color": color, "comments": {comment}}
            else:
                entry["comments"].add(comment)
                if score > entry["score"]:
                    entry["score"], entry["color"] = score, color

    techniques = [
        {
            "techniqueID": technique_id,
            "score": data["score"],
            "color": data["color"],
            "comment": "; ".join(sorted(c for c in data["comments"] if c)),
            "enabled": True,
        }
        for technique_id, data in sorted(aggregate.items())
    ]

    case = assessment.get("case", {})
    return {
        "name": f"Psypher — {case.get('target_name', 'assessment')}",
        "versions": {"layer": "4.5", "navigator": "4.9.5", "attack": attack_version},
        "domain": "enterprise-attack",
        "description": ("Techniques mapped from validated findings by Psypher AI Threat Assessor. "
                        "ATLAS (AML.*) techniques are recorded in the findings but omitted from this "
                        "enterprise-domain layer."),
        "techniques": techniques,
        "gradient": {"colors": ["#2f9e44", "#f08c00", "#b00020"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": level, "color": _COLOR[level]} for level in ("critical", "high", "medium", "low")],
        "sorting": 3,
        "hideDisabled": False,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0b1020",
    }
