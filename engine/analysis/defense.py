# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/analysis/defense.py — defense-anchor analysis (deterministic, order 38).
# =============================================================================
"""Name the defense for each finding, not just the attack.

Runs after every finding-producing branch (analysis 30, brain 35, posture 37)
and before report (40): for each finding it resolves the graph-grounded
mitigations of the finding's techniques and attaches them as first-class
``Mitigation`` records on ``finding.mitigations`` -- the same field the CVE
analyzer already populates, that ``validate.py`` grounds, and that the HTML/PDF
renderers already print. A named defense therefore actually reaches the report,
instead of a side dict no renderer reads.

Deterministic, no model touchpoint, so no new firewall. Grounding (invariant 3:
findings after order 30 validate their own ids): the shared resolver returns only
mitigations that resolve to a real graph node, so every id attached here is
already a graph node -- nothing ungrounded is introduced, even though the
order-30 firewall has already run.

Framework-agnostic by construction: an ATLAS technique resolves ATLAS mitigations
(AML.M####), an ATT&CK technique resolves ATT&CK mitigations (M####), and once
D3FEND countermeasures are ingested as mitigation nodes (WS-B build 2a) they are
picked up by the very same walk with no change here. A finding whose CVE carries
a CWE but no technique (e.g. distro-promoted CVEs) gets nothing here and is the
target of the CWE->countermeasure slice (build 2b).
"""
from __future__ import annotations

from ..core.contracts import Phase, register_phase
from ..core.models import Mitigation
from .match import mitigations_for_technique


def _graph(ctx):
    return (getattr(ctx, "artifacts", {}) or {}).get("graph")


def _resolve(graph, technique_id):
    """Graph-grounded mitigations for a technique as (id, name, framework) tuples,
    with a parent-technique fallback for a sub-technique that carries none."""
    if graph is None or not technique_id:
        return []
    res = mitigations_for_technique(graph, technique_id)
    if not res and "." in technique_id:
        res = mitigations_for_technique(graph, technique_id.rsplit(".", 1)[0])
    return res


def _framework_for(mid, given):
    if given:
        return given
    if mid.startswith("AML."):
        return "ATLAS"
    if mid.startswith("D3-") or "d3fend" in mid.lower():
        return "D3FEND"
    return "ATT&CK"


class DefensePhase(Phase):
    """Attach graph-grounded Mitigation records, order 38 (after posture, before report)."""

    name = "defense"
    order = 38

    def run(self, ctx) -> None:
        logger = ctx.logger
        graph = _graph(ctx)
        added = 0
        touched = 0

        for finding in getattr(ctx, "findings", []) or []:
            mits = getattr(finding, "mitigations", None)
            if mits is None:
                continue
            existing = {getattr(m, "id", "") for m in mits}
            new_records = []
            for t in getattr(finding, "techniques", []) or []:
                tid = getattr(t, "id", "") or ""
                for mid, name, fw in _resolve(graph, tid):
                    if mid and mid not in existing:
                        existing.add(mid)
                        new_records.append(
                            Mitigation(framework=_framework_for(mid, fw), id=mid, text=name))
            if new_records:
                mits.extend(new_records)
                added += len(new_records)
                touched += 1

        logger.info("defense: attached %d graph-grounded mitigation(s) to %d finding(s)",
                    added, touched)


try:
    register_phase(DefensePhase())
except Exception:
    pass
