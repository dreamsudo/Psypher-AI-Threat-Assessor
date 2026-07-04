# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/discovery/phase.py — Phase 0 implementation.
#  Installed by bootstrap-2-discovery.sh
# =============================================================================
"""Phase 0 — active discovery.

Interrogates each in-scope asset with the permitted probes, ingests operator
intake, and records evidence-backed grains and a component inventory into the
run context for later phases.
"""
from __future__ import annotations

from typing import Any

import yaml

from ..core.contracts import Phase, RunContext
from ..core.models import Confidence, Evidence, Grain
from .strategy import select_strategy


class DiscoveryPhase(Phase):
    """Drive discovery across all in-scope assets."""

    name = "discovery"
    order = 10

    def run(self, ctx: RunContext) -> None:
        strategy = select_strategy(ctx.config, ctx.logger)
        for asset in ctx.config.scope.in_scope:
            ctx.components.append({"id": asset.id, "kind": asset.kind, "access": asset.access})
            ctx.logger.info("discovering asset '%s' (%s, %s access)", asset.id, asset.kind, asset.access)
            strategy.discover(asset, ctx.probes, ctx)
        _ingest_intake(ctx)
        ctx.logger.info("discovery complete: %d component(s), %d grain(s)",
                        len(ctx.components), len(ctx.grains))


def _confidence(value: Any) -> Confidence:
    try:
        return Confidence(str(value).lower())
    except ValueError:
        return Confidence.MEDIUM


def _ingest_intake(ctx: RunContext) -> None:
    """Fold operator-supplied answers (facts no probe can reach) into grains."""
    questionnaire = ctx.config.intake.get("questionnaire")
    if not questionnaire:
        return
    path = (ctx.config.source_path.parent / questionnaire).resolve()
    if not path.is_file():
        ctx.logger.debug("intake questionnaire not found, skipping: %s", path)
        return
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        ctx.logger.error("could not parse intake questionnaire %s: %s", path, exc)
        return

    questions = doc.get("questions", []) if isinstance(doc, dict) else doc
    count = 0
    for item in questions or []:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        answer = item.get("answer")
        if not key or answer in (None, ""):
            continue
        evidence = Evidence(probe="intake", raw=str(item.get("question", "")), tier="operator")
        ctx.grains.append(
            Grain(component="engagement", attribute=str(key), value=answer,
                  confidence=_confidence(item.get("confidence", "high")), evidence=[evidence])
        )
        count += 1
    ctx.logger.info("intake: ingested %d operator-supplied fact(s)", count)
