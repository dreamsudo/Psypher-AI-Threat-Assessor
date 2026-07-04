# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/core/contracts.py — plug-in contracts and run context.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""The stable plug-in surface that packs and phases implement.

Nothing in the engine references a concrete probe, profile, or phase by name.
Packs supply ``ProbeSpec`` instances; phases implement ``Phase`` and register
themselves with the ``PhaseRegistry`` at import time. This module is the single
coupling point between the sealed core and everything swappable.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .config import Config
from .models import Finding, Grain, KillChain


class ProbeTier(str, Enum):
    """The risk tier of a probe, gated by engagement policy."""

    PASSIVE = "passive"
    ACTIVE_SAFE = "active_safe"
    INTRUSIVE = "intrusive"


@dataclass(frozen=True)
class ProbeSpec:
    """A validated probe manifest.

    The engine knows how to *execute* these (shell, script, or http) and how to
    map their output into grains; the pack supplies *which* probes exist. The
    engine never learns a probe's name at author time.
    """

    id: str
    tier: ProbeTier
    applies_to: tuple[str, ...]
    observes: tuple[str, ...]
    run: dict[str, Any]
    parse: dict[str, Any]
    source_path: str


@dataclass
class RunContext:
    """Mutable state threaded through every phase of a single run.

    Each phase reads what it needs and appends its results, so phases stay
    decoupled and individually testable.
    """

    config: Config
    logger: logging.Logger
    probes: list[ProbeSpec] = field(default_factory=list)
    grains: list[Grain] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    kill_chains: list[KillChain] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


class Phase(ABC):
    """A unit of the assessment pipeline.

    Implementations set ``name`` and ``order`` and implement ``run``. Lower
    ``order`` values execute first.
    """

    name: str = ""
    order: int = 0

    @abstractmethod
    def run(self, ctx: RunContext) -> None:
        """Execute this phase, mutating the shared run context."""
        raise NotImplementedError


class PhaseRegistry:
    """Process-wide registry of installed phases, populated at import time."""

    _phases: dict[str, Phase] = {}

    @classmethod
    def register(cls, phase: Phase) -> None:
        """Register a phase instance; later registration of the same name wins."""
        if not phase.name:
            raise ValueError("phase.name must be a non-empty string")
        cls._phases[phase.name] = phase

    @classmethod
    def ordered(cls) -> list[Phase]:
        """Return registered phases sorted by their execution order."""
        return sorted(cls._phases.values(), key=lambda phase: phase.order)

    @classmethod
    def clear(cls) -> None:
        """Remove all registered phases (used by tests)."""
        cls._phases.clear()


def register_phase(phase: Phase) -> None:
    """Module-level convenience wrapper around ``PhaseRegistry.register``."""
    PhaseRegistry.register(phase)
