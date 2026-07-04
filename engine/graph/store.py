# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/store.py — graph cache store.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""Persistence for the built knowledge graph.

The graph is expensive to build and enrich, so it is frozen to disk as
``nodes.json`` + ``edges.json`` with a ``meta.json`` recording the source
fingerprint, content hash, and counts. It is rebuilt only when the fingerprint
of the underlying source data changes.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .canonical import Graph


class GraphStore:
    """Read/write the cached graph under a store directory."""

    def __init__(self, store_dir: str | Path) -> None:
        self.dir = Path(store_dir)

    def _paths(self) -> tuple[Path, Path, Path]:
        return (self.dir / "nodes.json", self.dir / "edges.json", self.dir / "meta.json")

    def is_fresh(self, fingerprint: str) -> bool:
        """True when a cached graph exists and matches the given source fingerprint."""
        nodes, edges, meta = self._paths()
        if not (nodes.is_file() and edges.is_file() and meta.is_file()):
            return False
        try:
            recorded = json.loads(meta.read_text(encoding="utf-8")).get("fingerprint")
        except (OSError, json.JSONDecodeError):
            return False
        return recorded == fingerprint

    def save(self, graph: Graph, fingerprint: str) -> dict:
        """Persist the graph and return the metadata that was written."""
        self.dir.mkdir(parents=True, exist_ok=True)
        nodes, edges, meta = self._paths()
        data = graph.to_dict()
        nodes.write_text(json.dumps(data["nodes"], indent=2), encoding="utf-8")
        edges.write_text(json.dumps(data["edges"], indent=2), encoding="utf-8")
        metadata = {
            "fingerprint": fingerprint,
            "hash": graph.hash(),
            "counts": graph.counts(),
            "built_at": datetime.now(timezone.utc).isoformat(),
        }
        meta.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return metadata

    def load(self) -> Graph:
        """Load the cached graph from disk."""
        nodes, edges, _ = self._paths()
        return Graph.from_dict({
            "nodes": json.loads(nodes.read_text(encoding="utf-8")),
            "edges": json.loads(edges.read_text(encoding="utf-8")),
        })

    def meta(self) -> dict:
        """Return the stored metadata (empty dict if none)."""
        _, _, meta = self._paths()
        try:
            return json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
