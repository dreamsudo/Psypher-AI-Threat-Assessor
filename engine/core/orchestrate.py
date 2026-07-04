# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/core/orchestrate.py — run controller.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""Run controller: assembles the context, loads installed phases, runs them.

The phase packages are installed by later bootstraps and register themselves at
import time. Their absence is *detected*, not faked: if no phases are installed,
the controller reports exactly which bootstraps to run and stops.
"""
from __future__ import annotations

import importlib
import logging

from .config import Config
from .contracts import PhaseRegistry, RunContext
from .loader import discover_probes

# Phase packages in execution order. Each is installed by a later bootstrap.
_PHASE_PACKAGES: tuple[str, ...] = (
    "engine.discovery",
    "engine.graph",
    "engine.analysis",
    "engine.report",
)


def _import_installed_phases(logger: logging.Logger) -> None:
    """Import each phase package so it can register itself; skip absent ones."""
    for package in _PHASE_PACKAGES:
        try:
            importlib.import_module(package)
        except ModuleNotFoundError:
            logger.debug("phase package not installed: %s", package)


def run_assessment(config: Config, logger: logging.Logger | None = None) -> RunContext:
    """Run a full assessment and return the resulting context.

    Steps: build the context, load permitted probes, import installed phases,
    then execute the registered phases in order.
    """
    logger = logger or logging.getLogger("psypher")

    ctx = RunContext(config=config, logger=logger)
    ctx.probes = discover_probes(config, logger)

    _import_installed_phases(logger)
    phases = PhaseRegistry.ordered()

    if not phases:
        logger.warning(
            "no assessment phases are installed — the engine core is present but phases 0-3 are not. "
            "Run bootstrap-2-discovery.sh, bootstrap-3-graph-analysis.sh and bootstrap-4-report.sh "
            "to install them."
        )
        return ctx

    for phase in phases:
        logger.info("running phase: %s", phase.name)
        phase.run(ctx)

    return ctx
