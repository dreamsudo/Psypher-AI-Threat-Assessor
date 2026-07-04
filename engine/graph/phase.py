# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/phase.py — Phase 1 implementation.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""Phase 1 — the knowledge graph.

Builds the canonical graph from the configured sources once and caches it; on
later runs it reloads the cache unless the source data has changed. The built
graph is published on the run context for the analysis phase to query.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from ..core.config import Config
from ..core.contracts import Phase, RunContext
from .canonical import Graph
from .cve import ingest_cve
from .cwe import ingest_cwe
from .enrich import EnrichUnavailable, GraphEnricher
from .stix import ingest_stix
from .store import GraphStore


class GraphPhase(Phase):
    """Build (or load) the knowledge graph and publish it on the context."""

    name = "graph"
    order = 20

    def run(self, ctx: RunContext) -> None:
        store = GraphStore(_resolve(ctx.config, ctx.config.graph.store))
        fingerprint = _fingerprint(ctx.config)

        if store.is_fresh(fingerprint):
            graph = store.load()
            counts = graph.counts()
            ctx.logger.info("loaded cached knowledge graph (%d nodes, %d edges)",
                            sum(v for k, v in counts.items() if k != "edges"), counts["edges"])
        else:
            graph = _build(ctx)
            if ctx.config.graph.enrich:
                _maybe_enrich(graph, ctx)
            metadata = store.save(graph, fingerprint)
            counts = graph.counts()
            ctx.logger.info("built knowledge graph (%d nodes, %d edges, hash %s)",
                            sum(v for k, v in counts.items() if k != "edges"),
                            counts["edges"], metadata["hash"])

        ctx.artifacts["graph"] = graph
        ctx.artifacts["graph_hash"] = graph.hash()


def _resolve(config: Config, path: str) -> Path:
    """Resolve a path relative to the directory containing the config file."""
    return (config.source_path.parent / path).resolve()


def _build(ctx: RunContext) -> Graph:
    """Ingest every configured source into a fresh canonical graph."""
    graph = Graph()
    for source in ctx.config.graph.sources:
        path = _resolve(ctx.config, source.path)
        if not path.exists():
            ctx.logger.warning("source '%s' not found at %s; run data/fetch.sh "
                               "(CVE data ships in data/cve)", source.id, path)
            continue
        ctx.logger.info("ingesting source '%s' (%s)", source.id, source.format)
        if source.format == "stix":
            ingest_stix(graph, path, source.id, ctx.logger)
        elif source.format == "json":
            ingest_cve(graph, path, ctx.logger)
        elif source.format == "xml":
            ingest_cwe(graph, path, ctx.logger)
        else:
            ctx.logger.warning("source '%s': format '%s' is not yet supported; skipping",
                               source.id, source.format)
    return graph


def _maybe_enrich(graph: Graph, ctx: RunContext) -> None:
    """Add Claude-proposed cross-framework edges, if credentials are present."""
    try:
        enricher = GraphEnricher(ctx.config, ctx.logger)
    except EnrichUnavailable as exc:
        ctx.logger.warning("graph enrichment skipped (%s); structural graph only", exc)
        return
    added = enricher.enrich(graph)
    ctx.logger.info("graph enrichment added %d cross-framework 'enables' edge(s)", added)


def _fingerprint(config: Config) -> str:
    """Hash the identity of all present source files so the cache invalidates on change."""
    digest = hashlib.sha256()
    digest.update(b"psypher-graph-schema-v1")
    digest.update(str(config.graph.enrich).encode("utf-8"))
    for source in sorted(config.graph.sources, key=lambda s: s.id):
        directory = _resolve(config, source.path)
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                stat = path.stat()
                digest.update(str(path).encode("utf-8"))
                digest.update(str(stat.st_size).encode("utf-8"))
                digest.update(str(int(stat.st_mtime)).encode("utf-8"))
    return digest.hexdigest()
