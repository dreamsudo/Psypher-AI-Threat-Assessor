# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/core/loader.py — discovery and validation of swappable packs.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""Discovery and validation of swappable packs.

Today this loads probe packs; profiles and sources are loaded by the same
contract-driven pattern in later phases. A probe is admitted only if it (a)
parses, (b) validates against the probe contract, (c) is named in the
allowlist, and (d) belongs to an enabled tier.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from .config import Config
from .contracts import ProbeSpec, ProbeTier
from .validation import validate


def _load_probe(path: Path, logger: logging.Logger) -> ProbeSpec | None:
    """Load and validate a single probe manifest; return None on any failure."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("cannot read probe manifest %s: %s", path, exc)
        return None

    errors = validate(data, "probe")
    if errors:
        logger.error("probe manifest %s failed validation: %s", path, "; ".join(errors))
        return None

    return ProbeSpec(
        id=data["id"],
        tier=ProbeTier(data["tier"]),
        applies_to=tuple(data.get("applies_to", [])),
        observes=tuple(data.get("observes", [])),
        min_access=data.get("min_access", "black"),
        run=data["run"],
        parse=data.get("parse", {}),
        source_path=str(path),
    )


def discover_probes(config: Config, logger: logging.Logger) -> list[ProbeSpec]:
    """Load every permitted probe from the configured packs.

    Pack paths are resolved relative to the directory containing the config
    file, so an engagement is portable regardless of the working directory.
    """
    allow = set(config.probes.allowlist)
    enabled_tiers = {name for name, policy in config.probes.tiers.items() if policy.enabled}
    base = config.source_path.parent

    found: dict[str, ProbeSpec] = {}
    for pack in config.probes.packs:
        pack_dir = (base / pack).resolve()
        if not pack_dir.is_dir():
            logger.warning("probe pack directory not found, skipping: %s", pack_dir)
            continue
        for manifest in sorted(pack_dir.glob("*.json")):
            spec = _load_probe(manifest, logger)
            if spec is None:
                continue
            if spec.id not in allow:
                logger.debug("probe '%s' is not in the allowlist; skipping", spec.id)
                continue
            if spec.tier.value not in enabled_tiers:
                logger.info("probe '%s' skipped: tier '%s' is disabled", spec.id, spec.tier.value)
                continue
            if spec.id in found:
                logger.warning("duplicate probe id '%s' (%s); keeping the first definition", spec.id, manifest)
                continue
            found[spec.id] = spec

    logger.info("loaded %d probe(s) from %d configured pack(s)", len(found), len(config.probes.packs))
    return list(found.values())
