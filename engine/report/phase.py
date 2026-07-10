# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/phase.py — Phase 3 implementation.
#  Installed by bootstrap-5-report.sh
# =============================================================================
"""Phase 3 — report.

Assembles the canonical assessment, writes each configured format (json, html,
navigator) into a per-case directory, and packages them into a case
archive. An assessment is always produced — even with no findings — so a run
always yields an auditable artifact.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core.contracts import Phase, RunContext
from .assemble import assemble
from .html import render_html
from .web_html import render_web_html
from .markdown import render_markdown
from .navigator import render_navigator
from .package import package_zip

try:  # the tool name lives in one editable place
    from ..core.banner import TOOL_NAME
except Exception:  # noqa: BLE001
    TOOL_NAME = "Psypher AI Threat Assessor"


class ReportPhase(Phase):
    """Render and package the assessment."""

    name = "report"
    order = 40

    def run(self, ctx: RunContext) -> None:
        assessment = assemble(ctx)
        data = assessment.as_dict()
        config = ctx.config
        operator = config.engagement.operator
        formats = config.output.formats

        case_dir = (config.source_path.parent / config.output.dir / assessment.case_id).resolve()
        case_dir.mkdir(parents=True, exist_ok=True)

        written: list[Path] = []
        if "json" in formats:
            report = {k: v for k, v in data.items() if k != "grains"}
            path = case_dir / "assessment.json"
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            written.append(path)
            gpath = case_dir / "grains.json"
            gpath.write_text(json.dumps({"case": data.get("case", {}), "grains": data.get("grains", [])}, indent=2), encoding="utf-8")
            written.append(gpath)
        if "markdown" in formats:
            path = case_dir / "report.md"
            path.write_text(render_markdown(data, operator, TOOL_NAME), encoding="utf-8")
            written.append(path)
        if "html" in formats:
            path = case_dir / "report.html"
            path.write_text(render_html(data, operator, TOOL_NAME), encoding="utf-8")
            written.append(path)
        if "web_html" in formats:
            path = case_dir / "report-brief.html"
            path.write_text(render_web_html(data, operator, TOOL_NAME), encoding="utf-8")
            written.append(path)
        if "navigator" in formats:
            path = case_dir / "navigator-layer.json"
            path.write_text(json.dumps(render_navigator(data), indent=2), encoding="utf-8")
            written.append(path)

        ctx.artifacts["assessment"] = data
        ctx.artifacts["report_dir"] = str(case_dir)

        ctx.logger.info("report assembled: case %s (%d finding(s)), %d artifact(s)",
                        assessment.case_id, len(data.get("findings", [])), len(written))
        for path in written:
            ctx.logger.info("  wrote %s", path.name)

        if config.output.package == "zip" and written:
            zip_path = (config.source_path.parent / config.output.dir / f"{assessment.case_id}.zip").resolve()
            package_zip(written, zip_path, ctx.logger)
            ctx.artifacts["package"] = str(zip_path)
            ctx.logger.info("CASE PACKAGE: %s", zip_path)
