# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/discovery/strategy.py — recon strategies (Claude-driven + exhaustive).
#  Installed by bootstrap-2-discovery.sh
# =============================================================================
"""Discovery strategies: how the next probe is chosen.

The default is Claude-driven: at each step Claude selects the next probe to run
from the AVAILABLE SET ONLY. Claude may reason about coverage but can never
invent a probe — selections outside the available set are rejected by the
firewall. When no model credentials are present, a deterministic exhaustive
strategy runs every applicable probe. Both strategies are fully functional and
neither fabricates probe output.
"""
from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any

from ..core.config import Asset, Config
from ..core.contracts import ProbeSpec, RunContext
from .harness import Harness, ScopeViolation
from .parse import parse_result
from ..core.prompts import get_prompt


class ReconUnavailable(RuntimeError):
    """Raised when the Claude recon strategy cannot be constructed."""


def _applies(probe: ProbeSpec, asset: Asset) -> bool:
    """A probe applies when its applies_to is empty or contains the asset kind."""
    return (not probe.applies_to) or (asset.kind in probe.applies_to)


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, default=str)


class ReconStrategy(ABC):
    """Base strategy: shares probe execution and grain ingestion."""

    def __init__(self, config: Config, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.harness = Harness(config, logger)

    @abstractmethod
    def discover(self, asset: Asset, probes: list[ProbeSpec], ctx: RunContext) -> None:
        """Drive discovery for one asset, appending grains to the context."""

    def _run(self, probe: ProbeSpec, asset: Asset, ctx: RunContext):
        try:
            result = self.harness.execute(probe, asset, ctx)
        except ScopeViolation as exc:
            self.logger.warning("probe '%s' refused: %s", probe.id, exc)
            return None
        grains = parse_result(probe, result, asset, self.logger)
        ctx.grains.extend(grains)
        self.logger.info("probe '%s' -> %s, %d grain(s)", probe.id,
                         "ok" if result.ok else "error", len(grains))
        return result


class ExhaustiveStrategy(ReconStrategy):
    """Run every applicable probe exactly once, in declared order."""

    def discover(self, asset: Asset, probes: list[ProbeSpec], ctx: RunContext) -> None:
        for probe in probes:
            if _applies(probe, asset):
                self._run(probe, asset, ctx)


# Tool the recon agent must call to make a structured, validated decision.
_SELECT_TOOL: dict[str, Any] = {
    "name": "select_probe",
    "description": "Choose the next probe to run, or signal that discovery is complete.",
    "input_schema": {
        "type": "object",
        "properties": {
            "probe_id": {"type": "string", "description": "id of the next probe; must be one of the available ids"},
            "done": {"type": "boolean", "description": "true when no further probe is needed"},
            "reason": {"type": "string", "description": "one sentence justifying the choice"},
        },
    },
}

_SYSTEM = get_prompt("recon").system


class ClaudeReconStrategy(ReconStrategy):
    """Claude selects probes step by step; the firewall validates every choice."""

    MAX_STEPS = 24

    def __init__(self, config: Config, logger: logging.Logger) -> None:
        super().__init__(config, logger)
        try:
            import anthropic  # imported lazily so the engine runs without the SDK
        except ImportError as exc:
            raise ReconUnavailable("the 'anthropic' package is not installed") from exc
        api_key = os.environ.get(config.model.api_key_env)
        if not api_key:
            raise ReconUnavailable(f"${config.model.api_key_env} is not set")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = config.model.recon_model

    def discover(self, asset: Asset, probes: list[ProbeSpec], ctx: RunContext) -> None:
        available = {p.id: p for p in probes if _applies(p, asset)}
        if not available:
            self.logger.warning("no probes apply to asset '%s'", asset.id)
            return
        history: list[dict[str, Any]] = []
        for step in range(self.MAX_STEPS):
            decision = self._decide(asset, available, ctx, history)
            if decision.get("failed"):
                # Hard model-call failure (SDK already retried): degrade to the
                # deterministic exhaustive path so a transient blip cannot zero the run.
                self.logger.warning("recon failed for '%s'; running exhaustive over remaining probes", asset.id)
                ExhaustiveStrategy(self.config, self.logger).discover(asset, list(available.values()), ctx)
                return
            if decision.get("done"):
                self.logger.info("recon complete for '%s' after %d step(s)", asset.id, step)
                return
            probe_id = decision.get("probe_id", "")
            probe = available.get(probe_id)
            if probe is None:
                # Hallucination firewall: Claude proposed an id outside the available set.
                self.logger.warning("recon proposed unknown probe '%s'; rejected by firewall", probe_id)
                history.append({"step": step, "rejected": probe_id})
                continue
            result = self._run(probe, asset, ctx)
            history.append({"step": step, "ran": probe_id, "ok": bool(result and result.ok)})
            del available[probe_id]
            if not available:
                self.logger.info("recon exhausted available probes for '%s'", asset.id)
                return
        self.logger.info("recon reached step limit (%d) for '%s'", self.MAX_STEPS, asset.id)

    def _decide(self, asset: Asset, available: dict[str, ProbeSpec], ctx: RunContext,
                history: list[dict[str, Any]]) -> dict[str, Any]:
        observed = sorted({f"{g.attribute}={g.value}" for g in ctx.grains if g.component == asset.id})
        catalogue = [
            {"id": p.id, "tier": p.tier.value, "observes": list(p.observes), "applies_to": list(p.applies_to)}
            for p in available.values()
        ]
        prompt = (
            f"Target asset: id={asset.id}, kind={asset.kind}, access={asset.access}.\n\n"
            f"Available probes (choose one id, or set done=true):\n{_json(catalogue)}\n\n"
            f"Facts already observed for this asset:\n{_json(observed) if observed else '(none yet)'}\n\n"
            f"Probes already run this session:\n{_json(history) if history else '(none yet)'}\n\n"
            "Select the next probe that will reveal the most new inventory, or declare done."
        )
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=400,
                system=_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
                tools=[_SELECT_TOOL],
                tool_choice={"type": "tool", "name": "select_probe"},
            )
        except Exception as exc:  # noqa: BLE001 — a hard model/transport failure: signal FAILED
            self.logger.error("recon model call failed (%s); falling back to exhaustive for '%s'", exc, asset.id)
            return {"failed": True}
        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                return dict(block.input)
        return {"done": True}


def select_strategy(config: Config, logger: logging.Logger) -> ReconStrategy:
    """Pick the discovery strategy: Claude-driven when credentials exist, else exhaustive."""
    if config.model.provider == "anthropic" and os.environ.get(config.model.api_key_env):
        try:
            strategy = ClaudeReconStrategy(config, logger)
            logger.info("using Claude-driven recon (model: %s)", config.model.recon_model)
            return strategy
        except ReconUnavailable as exc:
            logger.warning("Claude recon unavailable (%s); falling back to exhaustive probing", exc)
    else:
        logger.info("no model credentials in $%s; using exhaustive probe strategy", config.model.api_key_env)
    return ExhaustiveStrategy(config, logger)
