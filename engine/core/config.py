# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/core/config.py — engagement control-plane loading and validation.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""Loading and strict validation of the engagement control plane (assessor.yaml).

The loader never assumes defaults for required policy: a missing or malformed
field raises ``ConfigError`` with an actionable message rather than silently
proceeding.
"""
from __future__ import annotations

import os

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACCESS_TIERS: frozenset[str] = frozenset({"black", "gray", "host"})
PROBE_TIERS: frozenset[str] = frozenset({"passive", "active_safe", "intrusive"})
SOURCE_FORMATS: frozenset[str] = frozenset({"stix", "json", "xml", "ttl", "yaml"})
OUTPUT_FORMATS: frozenset[str] = frozenset({"json", "html", "navigator", "markdown", "web_html"})
PACKAGE_FORMATS: frozenset[str] = frozenset({"zip", "none"})


class ConfigError(ValueError):
    """Raised when the engagement configuration is missing or invalid."""


@dataclass
class Asset:
    """A single in-scope target the harness is permitted to interrogate."""

    id: str
    kind: str
    access: str
    endpoint: str | None = None
    host: str | None = None
    ssh: str | None = None
    auth_env: str | None = None


@dataclass
class Scope:
    """The boundary of an engagement."""

    in_scope: list[Asset]
    out_of_scope: list[str]


@dataclass
class TierPolicy:
    """Execution policy for one probe tier."""

    enabled: bool
    require_approval: bool = False


@dataclass
class ProbePolicy:
    """Which probe packs to load and how their tiers are gated."""

    packs: list[str]
    tiers: dict[str, TierPolicy]
    allowlist: list[str]


@dataclass
class ModelConfig:
    """Claude model selection for recon, analysis, and review."""

    provider: str
    recon_model: str
    analysis_model: str
    review_model: str
    api_key_env: str


@dataclass
class SourceSpec:
    """One threat-intel source feeding the knowledge graph."""

    id: str
    path: str
    format: str


@dataclass
class GraphConfig:
    """Knowledge-graph build configuration."""

    store: str
    enrich: bool
    sources: list[SourceSpec]


@dataclass
class OutputConfig:
    """What each assessment run emits."""

    dir: str
    formats: list[str]
    package: str


@dataclass
class Engagement:
    """Engagement identity used for case numbering and attribution."""

    name: str
    case_prefix: str
    operator: str


@dataclass
class Config:
    """The fully-parsed engagement control plane."""

    engagement: Engagement
    scope: Scope
    probes: ProbePolicy
    intake: dict[str, Any]
    model: ModelConfig
    graph: GraphConfig
    output: OutputConfig
    source_path: Path


def _require(mapping: Any, key: str, ctx: str) -> Any:
    """Return ``mapping[key]`` or raise a ``ConfigError`` naming the context."""
    if not isinstance(mapping, dict):
        raise ConfigError(f"{ctx}: expected a mapping, got {type(mapping).__name__}")
    if key not in mapping:
        raise ConfigError(f"{ctx}: missing required key '{key}'")
    return mapping[key]


def _as_str_list(value: Any, ctx: str) -> list[str]:
    """Coerce and validate a value as a list of strings."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{ctx}: expected a list of strings")
    return list(value)


def _parse_asset(raw: Any, index: int) -> Asset:
    ctx = f"scope.in_scope[{index}]"
    asset_id = _require(raw, "id", ctx)
    kind = _require(raw, "kind", ctx)
    access = _require(raw, "access", ctx)
    if access not in ACCESS_TIERS:
        raise ConfigError(f"{ctx}.access: '{access}' is not one of {sorted(ACCESS_TIERS)}")
    return Asset(
        id=str(asset_id),
        kind=str(kind),
        access=str(access),
        endpoint=raw.get("endpoint"),
        host=raw.get("host"),
        ssh=raw.get("ssh"),
        auth_env=raw.get("auth_env"),
    )


def _parse_scope(raw: Any) -> Scope:
    in_scope_raw = _require(raw, "in_scope", "scope")
    if not isinstance(in_scope_raw, list) or not in_scope_raw:
        raise ConfigError("scope.in_scope: expected a non-empty list of assets")
    in_scope = [_parse_asset(item, idx) for idx, item in enumerate(in_scope_raw)]
    out_of_scope = _as_str_list(raw.get("out_of_scope", []), "scope.out_of_scope")
    return Scope(in_scope=in_scope, out_of_scope=out_of_scope)


def _parse_probes(raw: Any) -> ProbePolicy:
    packs = _as_str_list(_require(raw, "packs", "probes"), "probes.packs")
    tiers_raw = _require(raw, "tiers", "probes")
    if not isinstance(tiers_raw, dict):
        raise ConfigError("probes.tiers: expected a mapping")
    tiers: dict[str, TierPolicy] = {}
    for name, policy in tiers_raw.items():
        if name not in PROBE_TIERS:
            raise ConfigError(f"probes.tiers: unknown tier '{name}'; allowed: {sorted(PROBE_TIERS)}")
        if not isinstance(policy, dict):
            raise ConfigError(f"probes.tiers.{name}: expected a mapping")
        enabled = policy.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ConfigError(f"probes.tiers.{name}.enabled: expected a boolean")
        require_approval = policy.get("require_approval", False)
        if not isinstance(require_approval, bool):
            raise ConfigError(f"probes.tiers.{name}.require_approval: expected a boolean")
        tiers[name] = TierPolicy(enabled=enabled, require_approval=require_approval)
    allowlist = _as_str_list(_require(raw, "allowlist", "probes"), "probes.allowlist")
    if not allowlist:
        raise ConfigError("probes.allowlist: must name at least one probe")
    return ProbePolicy(packs=packs, tiers=tiers, allowlist=allowlist)


def _model_field(raw: Any, key: str, *env_names: str) -> str:
    """YAML value for ``key``, overridable at runtime by the first set env var.

    Lets a sourced picker (setmodel.sh) choose the Claude model per shell without
    editing assessor.yaml. The YAML value stays the required floor, so a missing
    field still errors; env only overrides a present, valid default.
    """
    default = str(_require(raw, key, "model"))
    for name in env_names:
        val = os.environ.get(name, "").strip()
        if val:
            return val
    return default


def _parse_model(raw: Any) -> ModelConfig:
    # PSYPHER_CLAUDE_MODEL overrides every role at once (the picker's knob);
    # a per-role var overrides just that role; YAML is the floor when unset.
    return ModelConfig(
        provider=str(_require(raw, "provider", "model")),
        recon_model=_model_field(raw, "recon_model", "PSYPHER_RECON_MODEL", "PSYPHER_CLAUDE_MODEL"),
        analysis_model=_model_field(raw, "analysis_model", "PSYPHER_ANALYSIS_MODEL", "PSYPHER_CLAUDE_MODEL"),
        review_model=_model_field(raw, "review_model", "PSYPHER_REVIEW_MODEL", "PSYPHER_CLAUDE_MODEL"),
        api_key_env=str(_require(raw, "api_key_env", "model")),
    )


def _parse_graph(raw: Any) -> GraphConfig:
    store = str(_require(raw, "store", "graph"))
    enrich = raw.get("enrich", False)
    if not isinstance(enrich, bool):
        raise ConfigError("graph.enrich: expected a boolean")
    sources_raw = _require(raw, "sources", "graph")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ConfigError("graph.sources: expected a non-empty list")
    sources: list[SourceSpec] = []
    for idx, item in enumerate(sources_raw):
        ctx = f"graph.sources[{idx}]"
        fmt = str(_require(item, "format", ctx))
        if fmt not in SOURCE_FORMATS:
            raise ConfigError(f"{ctx}.format: '{fmt}' is not one of {sorted(SOURCE_FORMATS)}")
        sources.append(
            SourceSpec(id=str(_require(item, "id", ctx)), path=str(_require(item, "path", ctx)), format=fmt)
        )
    return GraphConfig(store=store, enrich=enrich, sources=sources)


def _parse_output(raw: Any) -> OutputConfig:
    out_dir = str(_require(raw, "dir", "output"))
    formats = _as_str_list(_require(raw, "formats", "output"), "output.formats")
    unknown = sorted(set(formats) - OUTPUT_FORMATS)
    if unknown:
        raise ConfigError(f"output.formats: unsupported format(s) {unknown}; allowed: {sorted(OUTPUT_FORMATS)}")
    package = str(raw.get("package", "zip"))
    if package not in PACKAGE_FORMATS:
        raise ConfigError(f"output.package: '{package}' is not one of {sorted(PACKAGE_FORMATS)}")
    return OutputConfig(dir=out_dir, formats=formats, package=package)


def _parse_engagement(raw: Any) -> Engagement:
    return Engagement(
        name=str(_require(raw, "name", "engagement")),
        case_prefix=str(_require(raw, "case_prefix", "engagement")),
        operator=str(_require(raw, "operator", "engagement")),
    )


def load_config(path: str | Path) -> Config:
    """Load and validate the engagement control plane from ``path``."""
    source_path = Path(path)
    if not source_path.is_file():
        raise ConfigError(f"config file not found: {source_path}")
    try:
        raw = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse YAML in {source_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    return Config(
        engagement=_parse_engagement(_require(raw, "engagement", "<root>")),
        scope=_parse_scope(_require(raw, "scope", "<root>")),
        probes=_parse_probes(_require(raw, "probes", "<root>")),
        intake=dict(raw.get("intake", {})),
        model=_parse_model(_require(raw, "model", "<root>")),
        graph=_parse_graph(_require(raw, "graph", "<root>")),
        output=_parse_output(_require(raw, "output", "<root>")),
        source_path=source_path.resolve(),
    )
