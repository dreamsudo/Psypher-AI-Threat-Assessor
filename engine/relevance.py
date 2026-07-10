# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/relevance.py — scope observed packages to what matters (deterministic).
# =============================================================================
"""Decide which observed packages are IN SCOPE for the target's role.

Relevance is SCOPE, not severity. An AI-serving host's real surface is the serving
stack, the isolation boundary, and crypto/network/auth — not every installed
package. Promotion uses this to keep out-of-scope CVEs OUT of the graph (they are
catalogued, never turned into report findings); nothing severity-based is hidden.

Deterministic and model-free: package names are matched against the role-group
patterns in packs/relevance/role-groups.yaml (upstream PROJECT names, cross-distro
by construction). The active scope profile is AUTO-SELECTED from what was observed
-- a serving-stack or isolation surface means AI-serving infra (strict); a general
host gets the wider standard profile. If the pack is absent, scoping is DISABLED
(returns None) so promotion behaves exactly as before -- absence never hides a
real finding.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

_PACK = Path(__file__).resolve().parent.parent / "packs" / "relevance" / "role-groups.yaml"
# Observing any package in these tiers marks the target as AI-serving infrastructure.
_INFRA_TIERS = frozenset({"serving_stack", "isolation_boundary"})
_DEFAULT_PROFILE = "standard"


def _match(pattern: str, name: str) -> bool:
    """True if a package name belongs to an upstream project, cross-distro.

    Matches the project as a hyphen/underscore-delimited token, tolerating a
    trailing version so Debian's libssl3 / libseccomp2 and openssl-libs all hit
    'libssl' / 'libseccomp' / 'openssl'. Boundary-anchored so 'ray' never matches
    'array'. Deterministic.
    """
    return re.search(r"(^|[-_])" + re.escape(pattern) + r"[0-9.]*([-_]|$)", name) is not None


def load(path: str = "") -> dict | None:
    """Load and normalise the role-group pack; None if absent or unreadable."""
    p = Path(path) if path else _PACK
    if not p.is_file():
        return None
    try:
        import yaml
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    groups = []
    for g in data.get("role_groups", []):
        if isinstance(g, dict) and g.get("name"):
            groups.append({
                "name": g["name"],
                "tier": g.get("tier", ""),
                "patterns": [str(x) for x in g.get("patterns", [])],
                "techniques": [str(x) for x in g.get("techniques", [])],
                "d3fend_artifact": g.get("d3fend_artifact", ""),
            })
    profiles = {k: list(v) for k, v in (data.get("profiles", {}) or {}).items()}
    exclude = [str(x) for x in (data.get("exclude", []) or [])]
    return {"profiles": profiles, "role_groups": groups, "exclude": exclude}


def resolve(names: Iterable[str], pack: dict) -> dict[str, dict]:
    """Map each package name to the FIRST role-group it matches (any tier)."""
    excl = pack.get("exclude", [])
    out: dict[str, dict] = {}
    for name in names:
        if any(re.search(rx, name) for rx in excl):
            continue  # non-runtime (source/dev/doc) package -> not the installed exposure
        for g in pack["role_groups"]:
            if any(_match(pat, name) for pat in g["patterns"]):
                out[name] = g
                break
    return out


def select_profile(matched: dict[str, dict], pack: dict) -> str:
    """Auto-select the scope profile: the box declares itself by what it runs."""
    tiers = {g["tier"] for g in matched.values()}
    if tiers & _INFRA_TIERS:
        return "strict"
    if _DEFAULT_PROFILE in pack["profiles"]:
        return _DEFAULT_PROFILE
    return next(iter(pack["profiles"]), _DEFAULT_PROFILE)


def in_scope(observed: Iterable[str], logger: logging.Logger | None = None,
             profile: str | None = None) -> set[str] | None:
    """Return the in-scope subset of observed package names, or None if no pack.

    Auto-selects the profile from the inventory unless one is given. A package is
    in scope when it matches a role-group whose tier the active profile includes.
    """
    pack = load()
    if pack is None:
        if logger:
            logger.info("relevance: no role-group pack; scoping disabled (promoting all observed)")
        return None
    names = sorted({str(n).strip().lower() for n in observed if str(n).strip()})
    matched = resolve(names, pack)
    prof = profile or select_profile(matched, pack)
    tiers = set(pack["profiles"].get(prof, []))
    scoped = {n for n, g in matched.items() if g["tier"] in tiers}
    excl = pack.get("exclude", [])
    excluded_n = sum(1 for n in names if any(re.search(rx, n) for rx in excl))
    if logger:
        logger.info("relevance: profile=%s -> %d/%d observed package(s) in scope "
                    "(%d non-runtime excluded) [tiers: %s]",
                    prof, len(scoped), len(names), excluded_n, ", ".join(sorted(tiers)) or "-")
    return scoped
