# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/assemble.py — build the canonical Assessment.
#  Installed by bootstrap-5-report.sh
# =============================================================================
"""Assemble the run context into the canonical Assessment record.

The Assessment's ``as_dict`` is assessment.json — the single structure every
renderer consumes. Provenance is recorded for reproducibility: the engine
version, the data versions ingested, the frozen graph hash, and the full probe
execution log.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from .. import __version__
from ..core.contracts import RunContext
from ..core.models import Assessment, Provenance


def _case_id(prefix: str) -> str:
    """A unique, sortable case identifier: PREFIX-YYYYMMDD-<6 hex>."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6]}"


def _source_versions(ctx: RunContext) -> dict[str, str]:
    """Record the data file (and, where parseable, version) behind each source."""
    versions: dict[str, str] = {}
    base = ctx.config.source_path.parent
    for source in ctx.config.graph.sources:
        directory = (base / source.path).resolve()
        if not directory.is_dir():
            continue
        files = sorted(path.name for path in directory.glob("*") if path.is_file())
        if not files:
            continue
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", files[0])
        versions[source.id] = match.group(1) if match else files[0]
    return versions


def assemble(ctx: RunContext) -> Assessment:
    """Construct the Assessment from everything the phases recorded."""
    provenance = Provenance(
        tool_version=__version__,
        source_versions=_source_versions(ctx),
        graph_hash=str(ctx.artifacts.get("graph_hash", "")),
        probe_log=list(ctx.artifacts.get("probe_log", [])),
    )
    return Assessment(
        case_id=_case_id(ctx.config.engagement.case_prefix),
        target_name=ctx.config.engagement.name,
        provenance=provenance,
        components=ctx.components,
        grains=ctx.grains,
        findings=ctx.findings,
        kill_chains=ctx.kill_chains,
    )
