# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/analysis/killchain.py — sequence techniques into an ordered chain.
#  Installed by bootstrap-4-analysis.sh
# =============================================================================
"""Sequence the techniques across findings into an ordered attack chain.

The default sequencer is deterministic: it orders each finding's techniques by
the canonical ATT&CK tactic order (with ATLAS tactics appended), pulling the
governing tactic from the graph's ``accomplishes`` edges and a mitigation from
``mitigated_by``. The result is a real, source-grounded kill chain even with no
model available.
"""
from __future__ import annotations

import logging

from ..core.models import Finding, KillChain, KillChainStep
from ..graph.canonical import Graph

# Canonical ATT&CK Enterprise tactic order (kill-chain order), by shortname.
_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _tactic_rank(graph: Graph, technique_id: str) -> tuple[int, str]:
    """Rank a technique by the order of the first tactic it accomplishes."""
    best_rank = len(_TACTIC_ORDER) + 1
    best_name = ""
    for edge in graph.out_edges(technique_id, "accomplishes"):
        tactic = graph.get(edge.dst)
        if tactic is None:
            continue
        shortname = tactic.attrs.get("shortname", "")
        rank = _TACTIC_ORDER.index(shortname) if shortname in _TACTIC_ORDER else len(_TACTIC_ORDER)
        if rank < best_rank:
            best_rank, best_name = rank, tactic.name
    return best_rank, best_name


def _first_mitigation(graph: Graph, technique_id: str) -> str:
    for edge in graph.out_edges(technique_id, "mitigated_by"):
        return edge.dst
    return ""


def build_kill_chain(findings: list[Finding], graph: Graph, logger: logging.Logger,
                     name: str = "Primary attack path") -> KillChain:
    """Assemble one ordered kill chain from the techniques across all findings."""
    seen: dict[str, tuple[int, str, str]] = {}  # technique_id -> (rank, tactic_name, framework)
    for finding in findings:
        for ref in finding.techniques:
            if ref.id in seen:
                continue
            rank, tactic_name = _tactic_rank(graph, ref.id)
            seen[ref.id] = (rank, tactic_name, ref.framework)

    ordered = sorted(seen.items(), key=lambda item: (item[1][0], item[0]))
    steps: list[KillChainStep] = []
    for index, (technique_id, (_, tactic_name, framework)) in enumerate(ordered, start=1):
        node = graph.get(technique_id)
        note = f"{tactic_name}: {node.name}" if node and tactic_name else (node.name if node else technique_id)
        steps.append(KillChainStep(order=index, framework=framework, ref=technique_id,
                                   note=note, mitigated_by=_first_mitigation(graph, technique_id)))
    logger.info("kill chain assembled with %d step(s)", len(steps))
    return KillChain(id="KC-1", name=name, steps=steps)
