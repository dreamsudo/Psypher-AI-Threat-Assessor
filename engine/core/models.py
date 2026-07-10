# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/core/models.py — canonical data records.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""Canonical data records that flow through the assessment pipeline.

These types are the contract between phases. Discovery emits ``Grain`` records;
analysis emits ``Finding`` and ``KillChain`` records; the report builder
assembles them into an ``Assessment`` whose ``as_dict`` is the canonical
``assessment.json`` consumed by every renderer.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    """Ordered severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """How strongly a fact or finding is supported by evidence."""

    VERIFIED = "verified"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


@dataclass
class Evidence:
    """A single observation produced by a probe, recorded for the audit trail."""

    probe: str
    raw: str
    tier: str
    observed_at: str = field(default_factory=_utc_now)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _cap_grain_evidence(item) -> dict:
    """Serialize one Evidence with its raw bounded for the written record."""
    d = item.as_dict()
    d["raw"] = _cap_raw(d.get("raw", ""))
    return d


def _cap_raw(text: str) -> str:
    """Bound a written raw payload so a large shared probe dump is not
    duplicated across every grain in assessment.json. The full raw stays in the
    live Evidence object (analysis reads it in-memory); only the serialized copy
    is sampled, and the truncation is disclosed rather than silent."""
    try:
        from ..discovery.harness import _RAW_CAP as _CAP
    except Exception:
        _CAP = 8000
    s = text or ""
    if len(s) <= _CAP:
        return s
    return s[:_CAP] + ("...[+%d more bytes, full raw retained in the evidence log]" % (len(s) - _CAP))


@dataclass
class Grain:
    """One individually-assessable fact about a target component.

    A grain never enters the assessment as an assumption: its ``confidence``
    and ``evidence`` record exactly how it was learned.
    """

    component: str
    attribute: str
    value: Any
    confidence: Confidence = Confidence.UNVERIFIED
    evidence: list[Evidence] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "attribute": self.attribute,
            "value": self.value,
            "confidence": self.confidence.value,
            "evidence": [_cap_grain_evidence(item) for item in self.evidence],
        }


@dataclass
class TechniqueRef:
    """A reference to a real ATLAS / ATT&CK / EMB3D technique."""

    framework: str
    id: str
    name: str = ""
    validated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Vulnerability:
    """A concrete vulnerability mapped to a finding."""

    cve: str
    cwe: str = ""
    cvss: float | None = None
    mechanism: str = ""
    confirmed_by: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Mitigation:
    """A countermeasure, cited by its real framework identifier."""

    framework: str
    id: str
    text: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single assessed risk against one component."""

    id: str
    component: str
    title: str
    severity: Severity
    confidence: Confidence
    techniques: list[TechniqueRef] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    mitigations: list[Mitigation] = field(default_factory=list)
    attack_path: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "component": self.component,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "techniques": [item.as_dict() for item in self.techniques],
            "vulnerabilities": [item.as_dict() for item in self.vulnerabilities],
            "mitigations": [item.as_dict() for item in self.mitigations],
            "attack_path": self.attack_path,
            "evidence": self.evidence,
        }


@dataclass
class KillChainStep:
    """One ordered step in an end-to-end attack chain."""

    order: int
    framework: str
    ref: str
    note: str = ""
    mitigated_by: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class KillChain:
    """An ordered sequence of steps describing a full attack path."""

    id: str
    name: str
    steps: list[KillChainStep] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "steps": [step.as_dict() for step in self.steps],
        }


@dataclass
class Provenance:
    """Reproducibility metadata: data versions, graph hash, and probe log."""

    tool_version: str
    created: str = field(default_factory=_utc_now)
    source_versions: dict[str, str] = field(default_factory=dict)
    graph_hash: str = ""
    probe_log: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Assessment:
    """The complete, canonical assessment brief.

    ``as_dict`` is the single source of truth that every renderer reads.
    """

    case_id: str
    target_name: str
    provenance: Provenance
    components: list[dict[str, Any]] = field(default_factory=list)
    grains: list[Grain] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    kill_chains: list[KillChain] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """Compute the severity counts and the set of frameworks referenced."""
        by_severity = {level.value: 0 for level in Severity}
        for finding in self.findings:
            by_severity[finding.severity.value] += 1
        frameworks: set[str] = set()
        for finding in self.findings:
            frameworks.update(ref.framework for ref in finding.techniques)
            if finding.vulnerabilities:
                frameworks.add("CVE")
        return {
            "findings_total": len(self.findings),
            "by_severity": by_severity,
            "frameworks": sorted(frameworks),
        }

    def as_dict(self) -> dict[str, Any]:
        """Serialize the whole assessment into the canonical JSON structure."""
        return {
            "case": {
                "id": self.case_id,
                "created": self.provenance.created,
                "tool_version": self.provenance.tool_version,
                "target_name": self.target_name,
            },
            "provenance": self.provenance.as_dict(),
            "summary": self.summary(),
            "components": self.components,
            "grains": [grain.as_dict() for grain in self.grains],
            "findings": [finding.as_dict() for finding in self.findings],
            "kill_chains": [chain.as_dict() for chain in self.kill_chains],
        }
