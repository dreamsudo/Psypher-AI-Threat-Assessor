# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/stix.py — STIX adapter for ATLAS and ATT&CK.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""STIX 2.1 adapter.

ATLAS and ATT&CK both publish STIX bundles, so one adapter ingests both. It
maps STIX object types to canonical nodes and STIX relationships to canonical
edges:

  x-mitre-tactic   -> tactic
  attack-pattern   -> technique   (+ accomplishes edge via kill_chain_phases)
  course-of-action -> mitigation
  relationship "mitigates"       -> mitigated_by (technique -> mitigation)
  relationship "subtechnique-of" -> child_of     (technique -> technique)

Nodes are keyed by their external id (T1059, AML.T0051, TA0001, M1041); the
STIX id is used only to resolve relationships within a bundle.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .canonical import Edge, Graph, Node


def ingest_stix(graph: Graph, source_dir: Path, source_id: str, logger: logging.Logger) -> None:
    """Ingest every STIX bundle (*.json) found under ``source_dir``."""
    bundles = sorted(Path(source_dir).glob("*.json"))
    if not bundles:
        logger.warning("STIX source '%s' has no .json bundles in %s", source_id, source_dir)
        return
    for path in bundles:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("cannot read STIX bundle %s: %s", path, exc)
            continue
        _ingest_bundle(graph, doc, logger)


def _external_id(obj: dict[str, Any]) -> str | None:
    """Return the MITRE external id of a STIX object, if present."""
    refs = obj.get("external_references", [])
    for ref in refs:
        if ref.get("external_id") and str(ref.get("source_name", "")).startswith("mitre"):
            return ref["external_id"]
    for ref in refs:
        if ref.get("external_id"):
            return ref["external_id"]
    return None


def _framework_of(external_id: str | None) -> str:
    """ATLAS ids are prefixed AML; everything else is treated as ATT&CK."""
    if external_id and external_id.startswith("AML"):
        return "ATLAS"
    return "ATT&CK"


def _ingest_bundle(graph: Graph, doc: Any, logger: logging.Logger) -> None:
    objects = doc.get("objects", []) if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
    stix_to_canonical: dict[str, str] = {}
    tactics_by_shortname: dict[str, str] = {}

    # Pass 1 — nodes.
    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        obj_type = obj.get("type")
        if obj_type == "x-mitre-tactic":
            ext = _external_id(obj)
            shortname = obj.get("x_mitre_shortname")
            node = graph.add_node(Node(id=ext or obj["id"], type="tactic", name=obj.get("name", ""),
                                       framework=_framework_of(ext), attrs={"shortname": shortname}))
            stix_to_canonical[obj["id"]] = node.id
            if shortname:
                tactics_by_shortname[shortname] = node.id
        elif obj_type == "attack-pattern":
            ext = _external_id(obj)
            node = graph.add_node(Node(id=ext or obj["id"], type="technique", name=obj.get("name", ""),
                                       framework=_framework_of(ext),
                                       attrs={"is_subtechnique": bool(obj.get("x_mitre_is_subtechnique"))}))
            stix_to_canonical[obj["id"]] = node.id
        elif obj_type == "course-of-action":
            ext = _external_id(obj)
            node = graph.add_node(Node(id=ext or obj["id"], type="mitigation", name=obj.get("name", ""),
                                       framework=_framework_of(ext), attrs={}))
            stix_to_canonical[obj["id"]] = node.id

    # Pass 2 — technique -> tactic via kill-chain phases.
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = stix_to_canonical.get(obj["id"])
        if not technique_id:
            continue
        for phase in obj.get("kill_chain_phases", []):
            tactic_id = tactics_by_shortname.get(phase.get("phase_name"))
            if tactic_id:
                graph.add_edge(Edge(technique_id, tactic_id, "accomplishes", {}))

    # Pass 3 — relationships.
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        src = stix_to_canonical.get(obj.get("source_ref", ""))
        dst = stix_to_canonical.get(obj.get("target_ref", ""))
        if not src or not dst:
            continue
        relationship = obj.get("relationship_type")
        if relationship == "mitigates":
            # STIX: mitigation (source) mitigates technique (target).
            graph.add_edge(Edge(dst, src, "mitigated_by", {}))
        elif relationship == "subtechnique-of":
            graph.add_edge(Edge(src, dst, "child_of", {}))

    logger.debug("STIX bundle ingested: %d objects", len(objects))
