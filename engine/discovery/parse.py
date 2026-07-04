# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/discovery/parse.py — raw output to evidence-backed grains.
#  Installed by bootstrap-2-discovery.sh
# =============================================================================
"""Translate raw probe output into evidence-backed grains.

Each probe declares a ``parse`` spec describing how its output maps to grain
attributes. Three forms are supported:

  * regex      — {"regex": "<pattern>"} : every named group of every match
                 becomes a grain (attribute = group name).
  * structured — {"json": "<dotted.path>", "attribute": "<name>"} extracts one
                 value from structured data; {"from": "return_value"} expands a
                 returned mapping into one grain per key.
  * lines      — {"lines": true, "attribute": "<name>"} : each non-empty output
                 line becomes a grain.

Directly observed facts are recorded with VERIFIED confidence and carry the
probe's raw output as evidence.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from ..core.config import Asset
from ..core.contracts import ProbeSpec
from ..core.models import Confidence, Evidence, Grain
from .harness import ProbeResult


def parse_result(probe: ProbeSpec, result: ProbeResult, asset: Asset, logger: logging.Logger) -> list[Grain]:
    """Apply the probe's parse spec to its result, returning grains."""
    if not result.ok:
        return []
    spec = probe.parse or {}
    evidence = Evidence(probe=probe.id, raw=result.raw, tier=probe.tier.value)

    if "regex" in spec:
        return _from_regex(spec, result, asset, evidence, logger)
    if "json" in spec or spec.get("from") == "return_value":
        return _from_structured(spec, result, asset, evidence, logger)
    if spec.get("lines"):
        return _from_lines(spec, result, asset, evidence)

    logger.debug("probe '%s' has no actionable parse spec; recording no grains", probe.id)
    return []


def _grain(asset: Asset, attribute: str, value: Any, evidence: Evidence) -> Grain:
    return Grain(component=asset.id, attribute=attribute, value=value,
                 confidence=Confidence.VERIFIED, evidence=[evidence])


def _from_regex(spec: dict, result: ProbeResult, asset: Asset, evidence: Evidence,
                logger: logging.Logger) -> list[Grain]:
    try:
        pattern = re.compile(spec["regex"], re.MULTILINE)
    except re.error as exc:
        logger.error("invalid regex in probe parse spec: %s", exc)
        return []
    grains: list[Grain] = []
    for match in pattern.finditer(result.raw):
        groups = match.groupdict()
        if groups:
            for name, value in groups.items():
                if value is not None:
                    grains.append(_grain(asset, name, value, evidence))
        elif match.group(0):
            grains.append(_grain(asset, spec.get("attribute", "match"), match.group(0), evidence))
    return grains


def _navigate(data: Any, path: str) -> Any:
    """Follow a dotted path through nested dicts/lists; return None if absent."""
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.lstrip("-").isdigit():
            index = int(part)
            current = current[index] if -len(current) <= index < len(current) else None
        else:
            return None
        if current is None:
            return None
    return current


def _from_structured(spec: dict, result: ProbeResult, asset: Asset, evidence: Evidence,
                     logger: logging.Logger) -> list[Grain]:
    data = result.data
    if "json" in spec:
        value = _navigate(data, spec["json"])
        if value is None:
            logger.debug("probe '%s': json path '%s' not present", evidence.probe, spec["json"])
            return []
        attribute = spec.get("attribute") or spec["json"].split(".")[-1]
        return [_grain(asset, attribute, value, evidence)]
    # from == "return_value": expand a returned mapping into one grain per key.
    if isinstance(data, dict):
        return [_grain(asset, key, value, evidence) for key, value in data.items() if value is not None]
    logger.debug("probe '%s': return value is not a mapping; no grains", evidence.probe)
    return []


def _from_lines(spec: dict, result: ProbeResult, asset: Asset, evidence: Evidence) -> list[Grain]:
    attribute = spec.get("attribute", "line")
    return [_grain(asset, attribute, line.strip(), evidence)
            for line in result.raw.splitlines() if line.strip()]
