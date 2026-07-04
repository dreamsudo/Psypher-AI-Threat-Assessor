# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/canonical.py — the one canonical graph model.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""The single canonical knowledge-graph model.

Every framework — ATLAS, ATT&CK, CVE, CWE — is normalised into this one shape so
that analysis queries one graph, not four formats. There are six node types and
six edge types:

  nodes : tactic · technique · mitigation · vulnerability · weakness · asset
  edges : accomplishes (technique -> tactic)
          mitigated_by (technique -> mitigation)
          enables      (vulnerability -> technique)   [Claude-proposed, validated]
          instance_of  (vulnerability -> weakness)    [CVE -> CWE]
          child_of     (technique -> technique)       [sub-technique]
          exposes      (asset -> vulnerability)        [added during analysis]
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

NODE_TYPES: frozenset[str] = frozenset(
    {"tactic", "technique", "mitigation", "vulnerability", "weakness", "asset"}
)
EDGE_TYPES: frozenset[str] = frozenset(
    {"accomplishes", "mitigated_by", "enables", "instance_of", "child_of", "exposes"}
)


@dataclass
class Node:
    """A canonical node, keyed by its framework identifier (e.g. T1059, CVE-2025-62164)."""

    id: str
    type: str
    name: str = ""
    framework: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "name": self.name,
                "framework": self.framework, "attrs": self.attrs}


@dataclass
class Edge:
    """A canonical directed edge between two node ids."""

    src: str
    dst: str
    type: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.src, self.type, self.dst)

    def as_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "type": self.type, "attrs": self.attrs}


class Graph:
    """An in-memory canonical graph with merge-on-insert and typed queries."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}

    # -- mutation --------------------------------------------------------------

    def add_node(self, node: Node) -> Node:
        """Insert a node, merging attributes if the id already exists."""
        if node.type not in NODE_TYPES:
            raise ValueError(f"unknown node type: {node.type!r}")
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            return node
        if not existing.name and node.name:
            existing.name = node.name
        if not existing.framework and node.framework:
            existing.framework = node.framework
        for key, value in node.attrs.items():
            if value is not None and existing.attrs.get(key) in (None, "", [], {}):
                existing.attrs[key] = value
        return existing

    def add_edge(self, edge: Edge) -> None:
        """Insert an edge, ignoring exact duplicates and merging attributes."""
        if edge.type not in EDGE_TYPES:
            raise ValueError(f"unknown edge type: {edge.type!r}")
        existing = self._edges.get(edge.key())
        if existing is None:
            self._edges[edge.key()] = edge
        else:
            existing.attrs.update({k: v for k, v in edge.attrs.items() if v is not None})

    # -- queries ---------------------------------------------------------------

    def get(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def has(self, node_id: str) -> bool:
        return node_id in self._nodes

    def by_type(self, node_type: str) -> list[Node]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def out_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        return [e for e in self._edges.values()
                if e.src == node_id and (edge_type is None or e.type == edge_type)]

    def in_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        return [e for e in self._edges.values()
                if e.dst == node_id and (edge_type is None or e.type == edge_type)]

    @property
    def nodes(self) -> Iterable[Node]:
        return self._nodes.values()

    @property
    def edges(self) -> Iterable[Edge]:
        return self._edges.values()

    def counts(self) -> dict[str, int]:
        """Node counts by type plus total edges, for logging and provenance."""
        out = {t: 0 for t in NODE_TYPES}
        for node in self._nodes.values():
            out[node.type] += 1
        out["edges"] = len(self._edges)
        return out

    # -- serialisation ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.as_dict() for n in self._nodes.values()],
            "edges": [e.as_dict() for e in self._edges.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Graph":
        graph = cls()
        for raw in data.get("nodes", []):
            graph._nodes[raw["id"]] = Node(
                id=raw["id"], type=raw["type"], name=raw.get("name", ""),
                framework=raw.get("framework", ""), attrs=raw.get("attrs", {}),
            )
        for raw in data.get("edges", []):
            edge = Edge(src=raw["src"], dst=raw["dst"], type=raw["type"], attrs=raw.get("attrs", {}))
            graph._edges[edge.key()] = edge
        return graph

    def hash(self) -> str:
        """A stable content hash of the graph, for the provenance block."""
        nodes = sorted(
            (n.id, n.type, n.name, json.dumps(n.attrs, sort_keys=True, default=str))
            for n in self._nodes.values()
        )
        edges = sorted(
            (e.src, e.type, e.dst, json.dumps(e.attrs, sort_keys=True, default=str))
            for e in self._edges.values()
        )
        digest = hashlib.sha256()
        digest.update(json.dumps([nodes, edges], sort_keys=True, default=str).encode("utf-8"))
        return digest.hexdigest()[:16]
