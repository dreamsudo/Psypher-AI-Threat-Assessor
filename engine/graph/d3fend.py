# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/d3fend.py — D3FEND countermeasure overlay (deterministic).
# =============================================================================
"""D3FEND defense overlay for the knowledge graph.

Mirrors the CVE promotion overlay: a per-run, deterministic augmentation applied
to the finished graph in the graph phase, never entering the fingerprint cache,
before the closing firewall at order 30. It composes the already-extracted D3FEND
map (ATT&CK technique -> offensive artifact -> defensive technique) into first-
class graph nodes, so the defense phase resolves them exactly like ATLAS/ATT&CK
mitigations and validate.py grounds them like any other node -- no new mechanism.

For each ATT&CK technique that is already a node in the graph, each mapped D3FEND
countermeasure becomes a ``mitigation`` node (framework "D3FEND", id = the
canonical D3FEND identifier) plus a ``mitigated_by`` edge technique -> countermeasure.
A technique the map does not cover (e.g. T1611, Escape to Host) simply gets no
edge -- graceful degrade, never an error. Model-free, no touchpoint. Fail-open:
an absent or malformed map leaves the graph byte-identical.
"""
from __future__ import annotations

import json

from .canonical import Node, Edge


def _frag(iri: str) -> str:
    """The canonical D3FEND identifier: the IRI fragment after '#'."""
    return iri.rsplit("#", 1)[-1] if "#" in iri else iri


def ingest_d3fend(graph, map_path, logger) -> None:
    try:
        with open(map_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.info("d3fend: map absent/unreadable (%s); no defenses added", exc)
        return

    a2a = data.get("attack_to_artifacts") or {}
    a2d = data.get("artifact_to_defenses") or {}
    if not a2a or not a2d:
        logger.info("d3fend: map has no attack/defense slices; no defenses added")
        return

    nodes_added = 0
    edges_added = 0
    seen_edges: set = set()

    for tech_id, artifacts in a2a.items():
        if not graph.has(tech_id):  # anchor only to techniques already in the graph
            continue
        countermeasures: dict[str, str] = {}
        for iri in artifacts or []:
            for defn in a2d.get(iri, []) or []:
                cm_iri = defn.get("def_tech") or ""
                if cm_iri:
                    countermeasures[_frag(cm_iri)] = defn.get("def_tech_label") or _frag(cm_iri)
        for cm_id, cm_label in countermeasures.items():
            if not graph.has(cm_id):
                graph.add_node(Node(id=cm_id, type="mitigation", name=cm_label, framework="D3FEND"))
                nodes_added += 1
            key = (tech_id, cm_id)
            if key not in seen_edges:
                seen_edges.add(key)
                graph.add_edge(Edge(src=tech_id, dst=cm_id, type="mitigated_by", attrs={}))
                edges_added += 1

    logger.info("d3fend: added %d countermeasure node(s) + %d mitigated_by edge(s)",
                nodes_added, edges_added)
