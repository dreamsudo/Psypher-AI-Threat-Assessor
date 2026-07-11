# =============================================================================
#  engine/core/prompts.py
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  Prompt loader — externalizes every Claude-touchpoint prompt to data.
# =============================================================================
"""Load engine-side Claude prompts from a YAML registry, not from code.

Roles: recon, enrich, cve, judge. Each role has a mode ("single" | "ensemble")
and a list of variants, each with a `system` string and optional `user_template`.
`get_prompt(role)` returns the first variant (used by the single-prompt call
sites). `get_prompts(role)` returns all variants plus the mode (used by the
ensemble judge). Missing/malformed data or a variant that fails validation falls
back to the shipped default and logs loudly — a prompt problem never crashes a
run. The judge rubric floor is un-bypassable: a judge system prompt missing any
of the four verdicts is rejected in favor of the default.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

_LOG = logging.getLogger(__name__)
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_DEFAULT = os.path.join(_ROOT, "packs", "prompts", "engine-prompts.default.yaml")
_OVERRIDE = os.path.join(_ROOT, "packs", "prompts", "engine-prompts.yaml")

_REQUIRED_VERDICTS = ("complied", "refused", "partial", "confabulated")

_cache: dict | None = None


@dataclass(frozen=True)
class Prompt:
    name: str
    system: str
    user_template: str = ""


def _load_yaml(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    try:
        import yaml
        data = yaml.safe_load(open(path, encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # noqa: BLE001 - a bad file must never crash the run
        _LOG.warning("prompts: could not load %s (%s); ignoring it", path, exc)
        return {}


def _merge(default: dict, override: dict) -> dict:
    """Per-role patch-merge: an override role updates only the keys it names;
    keys it omits (e.g. variants) fall through to the default role. A non-mapping
    override role is ignored (default kept); a bad value fails safe downstream and
    the judge rubric floor still applies in get_prompts."""
    merged = dict(default)
    for role, spec in (override or {}).items():
        if not isinstance(spec, dict):
            _LOG.warning("prompts: override role '%s' malformed (not a mapping); keeping default", role)
            continue
        base = dict(merged.get(role) or {})
        base.update(spec)
        merged[role] = base
    return merged


def _registry() -> dict:
    global _cache
    if _cache is None:
        default = _load_yaml(_DEFAULT)
        if not default:
            _LOG.error("prompts: shipped default registry missing/empty at %s", _DEFAULT)
        _cache = _merge(default, _load_yaml(_OVERRIDE))
    return _cache


def _valid_judge(system: str) -> bool:
    low = (system or "").lower()
    return all(v in low for v in _REQUIRED_VERDICTS)


def _variants(role: str) -> list[dict]:
    spec = _registry().get(role) or {}
    variants = spec.get("variants") if isinstance(spec, dict) else None
    return [v for v in (variants or []) if isinstance(v, dict) and v.get("system")]


def _default_variants(role: str) -> list[dict]:
    default = _load_yaml(_DEFAULT).get(role) or {}
    return [v for v in (default.get("variants") or []) if isinstance(v, dict) and v.get("system")]


def get_prompts(role: str) -> tuple[list[Prompt], str]:
    """Return (variants, mode) for a role. Falls back to shipped defaults."""
    variants = _variants(role)
    if not variants:
        variants = _default_variants(role)
        if not variants:
            _LOG.error("prompts: no variants for role '%s' anywhere", role)
            return [], "single"
    # Judge rubric floor: drop any variant missing a required verdict, fall back.
    if role == "judge":
        kept = [v for v in variants if _valid_judge(v.get("system", ""))]
        if len(kept) != len(variants):
            _LOG.warning("prompts: judge variant(s) missing the four verdicts; "
                         "rejected in favor of valid ones")
        if not kept:
            kept = [v for v in _default_variants(role) if _valid_judge(v.get("system", ""))]
            _LOG.warning("prompts: all judge variants invalid; using shipped default")
        variants = kept
    mode = (_registry().get(role) or {}).get("mode", "single")
    out = [Prompt(name=v.get("name", "base"), system=v["system"],
                  user_template=v.get("user_template", "")) for v in variants]
    return out, mode


def get_prompt(role: str) -> Prompt:
    """Return the first/primary variant for a role (single-prompt call sites)."""
    variants, _ = get_prompts(role)
    if variants:
        return variants[0]
    return Prompt(name="empty", system="")
