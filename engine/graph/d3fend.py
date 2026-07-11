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

def ingest_d3fend_cwe(graph, slice_path, logger) -> None:
    """Build 2b: overlay the pinned D3FEND CWE->countermeasure slice as
    ``weakness -> mitigated_by -> countermeasure`` edges, salience carried on the
    edge. Anchors only to CWE (weakness) nodes already in the graph -- including
    the distro-promoted CVEs' weakness nodes, which are exactly the findings the
    technique-based overlay leaves undefended. Same overlay contract as
    ingest_d3fend: model-free, no touchpoint, fail-open (an absent or malformed
    slice leaves the graph byte-identical)."""
    try:
        with open(slice_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.info("d3fend-cwe: slice absent/unreadable (%s); no weakness defenses added", exc)
        return

    cwe_map = data.get("cwe") or {}
    if not cwe_map:
        logger.info("d3fend-cwe: slice has no cwe mappings; no weakness defenses added")
        return

    nodes_added = 0
    edges_added = 0
    seen_edges: set = set()

    for cwe_id, entries in cwe_map.items():
        if not graph.has(cwe_id):  # anchor only to weakness nodes already in the graph
            continue
        for entry in entries or []:
            cm_id = (entry.get("id") or "").strip()
            if not cm_id:
                continue
            cm_label = entry.get("label") or cm_id
            if not graph.has(cm_id):
                graph.add_node(Node(id=cm_id, type="mitigation", name=cm_label, framework="D3FEND"))
                nodes_added += 1
            key = (cwe_id, cm_id)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            graph.add_edge(Edge(src=cwe_id, dst=cm_id, type="mitigated_by",
                                attrs={"salience": entry.get("salience", 0.0),
                                       "tactic": entry.get("tactic", "")}))
            edges_added += 1

    logger.info("d3fend-cwe: added %d countermeasure node(s) + %d weakness mitigated_by edge(s)",
                nodes_added, edges_added)
