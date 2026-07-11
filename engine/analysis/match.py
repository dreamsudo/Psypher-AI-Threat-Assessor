# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/analysis/match.py — deterministic grain-to-graph matching.
#  Installed by bootstrap-4-analysis.sh
# =============================================================================
"""Turn grains into vulnerability candidates, deterministically.

This stage involves no model. It builds a software inventory from the grains —
resolving a product name from each grain's value, and recovering that product's
exact version from the grain's own evidence — then tests each observed version
against every CVE's affected range in the graph. A candidate is raised when a
product matches; the version test marks whether the match is version-confirmed
or only product-level. Every candidate carries the techniques the CVE enables
and the mitigations those techniques have, drawn straight from graph edges.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from ..core.models import Evidence, Grain
from ..graph.canonical import Graph


@dataclass
class Candidate:
    """A vulnerability raised against one component, with its graph context."""

    cve_id: str
    component: str
    observed_version: str | None
    version_confirmed: bool
    evidence: Evidence | None
    description: str
    cvss: float | None
    cwes: list[str] = field(default_factory=list)
    techniques: list[tuple[str, str]] = field(default_factory=list)   # (id, name)
    mitigations: list[tuple[str, str, str]] = field(default_factory=list)  # (id, text, framework)


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(name).strip().lower()).strip("-")


def _version_tuple(text: str) -> tuple[int, ...]:
    """Parse the leading numeric components of a version string (e.g. 0.10.2)."""
    out: list[int] = []
    for part in re.split(r"[.\-_+]", str(text)):
        match = re.match(r"^(\d+)", part)
        if not match:
            break
        out.append(int(match.group(1)))
    return tuple(out)


def _compare(left: str, right: str) -> int:
    """Compare two version strings numerically; return -1, 0, or 1."""
    a, b = _version_tuple(left), _version_tuple(right)
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


def _in_range(observed: str | None, affected: dict[str, Any]) -> tuple[bool, bool]:
    """Test an observed version against one affected entry.

    Returns ``(matches, version_confirmed)``. With no observed version, or no
    bounds on the entry, the product still matches but the result is not
    version-confirmed.
    """
    introduced = affected.get("version")
    less_than = affected.get("lessThan")
    less_equal = affected.get("lessThanOrEqual")
    has_bounds = bool(less_than) or bool(less_equal) or (introduced not in (None, "", "0"))
    if observed is None or not has_bounds:
        return (True, False)
    if introduced not in (None, "", "0") and _compare(observed, introduced) < 0:
        return (False, False)
    if less_than and _compare(observed, less_than) >= 0:
        return (False, False)
    if less_equal and _compare(observed, less_equal) > 0:
        return (False, False)
    return (True, True)


def _extract_version(product: str, evidence: list[Evidence]) -> str | None:
    """Recover a product's exact version from a probe's raw evidence.

    Deterministic and model-free. Each pattern is anchored on the product name
    so a version can never be bound to the wrong product. Tried strictest first:
      1. pip freeze / name==version      e.g.  vllm==0.10.2
      2. dpkg -l status line             e.g.  ii  openssh-server  1:9.6p1-3ubuntu13.5  amd64
      3. rpm -qa name-version-release    e.g.  openssh-9.6p1-1.fc40.x86_64
      4. product-adjacent version token  e.g.  Docker version 24.0.7 / OpenSSH_9.6p1
    Product-agnostic sources that do not name the product (a bare
    {"version": "..."} endpoint reply, or `uname -r`) are intentionally not read
    here: binding those to a product is a grain-layer step, handled where the
    probe is authored.
    """
    esc = re.escape(product)
    ver = r"\d+(?:\.\d+)+[\w.\-]*"
    patterns = (
        re.compile(rf"(?mi)^\s*{esc}\s*={{1,2}}\s*([\w.\-]+)"),
        re.compile(rf"(?mi)^[a-z]{{1,3}}\s+{esc}(?::[a-z0-9]+)?\s+(?:\d+:)?(\S+)"),
        re.compile(rf"(?mi)^{esc}-([0-9][^-\s]*)-[^-\s]+"),
        re.compile(rf"(?i)(?<![A-Za-z0-9]){esc}(?![A-Za-z0-9])[^0-9]{{0,14}}?({ver})"),
    )
    for item in evidence:
        raw = item.raw or ""
        for pattern in patterns:
            match = pattern.search(raw)
            if match:
                return match.group(1)
    return None


def build_inventory(grains: list[Grain], graph: Graph) -> dict[str, dict[str, Any]]:
    """Resolve {component: {product: {version, evidence}}} from grains.

    A grain contributes a product only when its value matches a product named
    in some CVE's affected list, so the engine never hard-codes product names.
    """
    known: dict[str, str] = {}
    for vuln in graph.by_type("vulnerability"):
        for entry in vuln.attrs.get("affected", []):
            product = entry.get("product")
            if product:
                known[_normalize(product)] = product

    inventory: dict[str, dict[str, Any]] = {}
    for grain in grains:
        key = _normalize(grain.value if isinstance(grain.value, str) else "")
        if not key or key not in known:
            continue
        product = known[key]
        version = _extract_version(product, grain.evidence)
        component = inventory.setdefault(grain.component, {})
        record = component.setdefault(product, {"version": None, "evidence": None})
        if version and not record["version"]:
            record["version"] = version
        if record["evidence"] is None and grain.evidence:
            record["evidence"] = grain.evidence[0]
    return inventory


def match_candidates(grains: list[Grain], graph: Graph, logger: logging.Logger) -> list[Candidate]:
    """Produce the full list of vulnerability candidates for all components."""
    inventory = build_inventory(grains, graph)
    candidates: list[Candidate] = []
    vulnerabilities = graph.by_type("vulnerability")

    for component, products in inventory.items():
        for product, record in products.items():
            observed = record["version"]
            for vuln in vulnerabilities:
                affected = vuln.attrs.get("affected", [])
                if not any(_normalize(a.get("product", "")) == _normalize(product) for a in affected):
                    continue
                matches = False
                confirmed = False
                for entry in affected:
                    if _normalize(entry.get("product", "")) != _normalize(product):
                        continue
                    entry_match, entry_confirmed = _in_range(observed, entry)
                    if entry_match:
                        matches = True
                        confirmed = confirmed or entry_confirmed
                if not matches:
                    continue
                candidates.append(_build_candidate(vuln.id, component, observed, confirmed,
                                                    record["evidence"], graph))
    logger.info("matching produced %d vulnerability candidate(s) across %d component(s)",
                len(candidates), len(inventory))
    return candidates


def mitigations_for_technique(graph, technique_id) -> list[tuple[str, str, str]]:
    """The graph-grounded mitigations for a technique, as (id, name, framework)
    tuples read from its ``mitigated_by`` edges. One implementation, shared by
    candidate building here and the defense phase, so the walk lives in exactly
    one place. Only mitigations that resolve to a real graph node are returned."""
    out: dict[str, tuple[str, str]] = {}
    for edge in graph.out_edges(technique_id, "mitigated_by"):
        node = graph.get(edge.dst)
        if node is not None:
            out[node.id] = (node.name, node.framework)
    return sorted((mid, nm, fw) for mid, (nm, fw) in out.items())


def mitigations_for_weakness(graph, weakness_id) -> list[tuple[str, str, str, float]]:
    """The graph-grounded countermeasures for a CWE weakness node, as
    (id, name, framework, salience) tuples read from its ``mitigated_by`` edges
    (build 2b: the pinned D3FEND CWE->countermeasure slice). Ordered by salience
    descending, so the weakness-specific defense leads and near-universal
    boilerplate trails. Only countermeasures that resolve to a real graph node
    are returned; a CWE with no edges yields none (graceful degrade)."""
    out: list[tuple[str, str, str, float]] = []
    seen: set[str] = set()
    for edge in graph.out_edges(weakness_id, "mitigated_by"):
        node = graph.get(edge.dst)
        if node is None or node.id in seen:
            continue
        seen.add(node.id)
        try:
            salience = float((getattr(edge, "attrs", None) or {}).get("salience", 0.0))
        except (TypeError, ValueError):
            salience = 0.0
        out.append((node.id, node.name, node.framework, salience))
    out.sort(key=lambda t: (-t[3], t[0]))
    return out


def _build_candidate(cve_id: str, component: str, observed: str | None, confirmed: bool,
                     evidence: Evidence | None, graph: Graph) -> Candidate:
    node = graph.get(cve_id)
    attrs = node.attrs if node else {}
    techniques: list[tuple[str, str]] = []
    mitigations: dict[str, str] = {}
    for edge in graph.out_edges(cve_id, "enables"):
        technique = graph.get(edge.dst)
        if technique is None:
            continue
        techniques.append((technique.id, technique.name))
        for mid, name, fw in mitigations_for_technique(graph, technique.id):
            mitigations[mid] = (name, fw)
    return Candidate(
        cve_id=cve_id, component=component, observed_version=observed,
        version_confirmed=confirmed, evidence=evidence,
        description=attrs.get("description", ""), cvss=attrs.get("cvss"),
        cwes=list(attrs.get("cwes", [])),
        techniques=techniques,
        mitigations=sorted((mid, nm, fw) for mid, (nm, fw) in mitigations.items()),
    )
