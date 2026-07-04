# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/analysis/phase.py — Phase 2 implementation.
#  Installed by bootstrap-4-analysis.sh
# =============================================================================
"""Phase 2 — analysis.

Reads the discovery grains and the frozen knowledge graph, matches candidates
deterministically, judges them into findings (Claude or heuristic), sequences a
kill chain, runs the closing identifier firewall, and records findings and the
kill chain on the run context for the report phase.
"""
from __future__ import annotations

from typing import Any

from ..core.contracts import Phase, RunContext
from ..core.models import Grain
from .analyze import select_analyzer
from .killchain import build_kill_chain
from .match import match_candidates
from .validate import validate_findings, validate_kill_chain


class AnalysisPhase(Phase):
    """Match, judge, sequence, and validate findings."""

    name = "analysis"
    order = 30

    def run(self, ctx: RunContext) -> None:
        graph = ctx.artifacts.get("graph")
        if graph is None:
            ctx.logger.warning("no knowledge graph on the context; skipping analysis "
                               "(is the graph phase installed?)")
            return

        candidates = match_candidates(ctx.grains, graph, ctx.logger)
        if not candidates:
            ctx.logger.info("no vulnerability candidates matched the observed components")
            return

        analyzer = select_analyzer(ctx.config, ctx.logger)
        context = _engagement_context(ctx.grains)

        by_component: dict[str, list] = {}
        for candidate in candidates:
            by_component.setdefault(candidate.component, []).append(candidate)

        for component, items in by_component.items():
            ctx.findings.extend(analyzer.judge(component, items, context))

        validate_findings(ctx.findings, graph, ctx.logger)

        if ctx.findings:
            chain = build_kill_chain(ctx.findings, graph, ctx.logger)
            validate_kill_chain(chain, graph, ctx.logger)
            if chain.steps:
                ctx.kill_chains.append(chain)

        ctx.logger.info("analysis complete: %d finding(s), %d kill-chain step(s)",
                        len(ctx.findings),
                        sum(len(chain.steps) for chain in ctx.kill_chains))


def _engagement_context(grains: list[Grain]) -> list[tuple[str, Any]]:
    """Collect operator-supplied intake facts to give the analyzer context."""
    context: list[tuple[str, Any]] = []
    for grain in grains:
        if any(item.probe == "intake" for item in grain.evidence):
            context.append((grain.attribute, grain.value))
    return context
