# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/analysis/analyze.py — finding judgement (Claude + heuristic).
#  Installed by bootstrap-4-analysis.sh
# =============================================================================
"""Judge candidates into findings.

The Claude analyzer is the third firewalled touchpoint: it decides which
candidates genuinely apply given the engagement context, assigns severity,
writes the attack path, and selects techniques and mitigations — but only from
the validated identifiers each candidate already carries. Any identifier it
returns that was not offered is discarded. When no model credentials exist, a
heuristic analyzer produces findings deterministically from CVSS and the graph,
so the pipeline never silently stops.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..core.config import Config
from ..core.models import (Confidence, Evidence, Finding, Mitigation, Severity,
                           TechniqueRef, Vulnerability)
from .match import Candidate
from ..core.prompts import get_prompt


def select_analyzer(config: Config, logger: logging.Logger) -> "Analyzer":
    """Return the Claude analyzer if usable, else the heuristic analyzer."""
    if config.model.provider == "anthropic" and os.environ.get(config.model.api_key_env):
        try:
            return ClaudeAnalyzer(config, logger)
        except AnalyzerUnavailable as exc:
            logger.warning("Claude analysis unavailable (%s); using heuristic analyzer", exc)
    else:
        logger.info("no model credentials; using heuristic analyzer")
    return HeuristicAnalyzer(logger)


class AnalyzerUnavailable(RuntimeError):
    """Raised when the Claude analyzer cannot be constructed."""


def _severity(value: Any, default: Severity = Severity.MEDIUM) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return default


def _confidence(value: Any, default: Confidence = Confidence.MEDIUM) -> Confidence:
    try:
        return Confidence(str(value).lower())
    except ValueError:
        return default


def _severity_from_cvss(cvss: float | None) -> Severity:
    if cvss is None:
        return Severity.MEDIUM
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss > 0.0:
        return Severity.LOW
    return Severity.INFO


def _finding_from(candidate: Candidate, *, severity: Severity, confidence: Confidence,
                  title: str, attack_path: str, technique_ids: list[str],
                  mitigation_ids: list[str]) -> Finding:
    """Assemble a Finding from a judged candidate, keeping only offered ids."""
    offered_techniques = {tid: name for tid, name in candidate.techniques}
    offered_mitigations = {mid: text for mid, text in candidate.mitigations}

    techniques = [
        TechniqueRef(framework=("ATLAS" if tid.startswith("AML") else "ATT&CK"),
                     id=tid, name=offered_techniques[tid], validated=True)
        for tid in technique_ids if tid in offered_techniques
    ]
    mitigations = [
        Mitigation(framework=("ATLAS" if mid.startswith("AML") else "ATT&CK"),
                   id=mid, text=offered_mitigations[mid])
        for mid in mitigation_ids if mid in offered_mitigations
    ]
    cwe = candidate.cwes[0] if candidate.cwes else ""
    confirmed_by = candidate.evidence.probe if candidate.evidence else ""
    return Finding(
        id=f"FND-{candidate.component}-{candidate.cve_id}",
        component=candidate.component, title=title, severity=severity, confidence=confidence,
        techniques=techniques,
        vulnerabilities=[Vulnerability(cve=candidate.cve_id, cwe=cwe, cvss=candidate.cvss,
                                       mechanism=candidate.description, confirmed_by=confirmed_by)],
        mitigations=mitigations, attack_path=attack_path,
        evidence={
            "observed_version": candidate.observed_version,
            "version_confirmed": candidate.version_confirmed,
            "match": "version-confirmed" if candidate.version_confirmed else "product-level",
        },
    )


class Analyzer:
    """Interface implemented by both analyzers."""

    def judge(self, component: str, candidates: list[Candidate],
              context: list[tuple[str, Any]]) -> list[Finding]:
        raise NotImplementedError


class HeuristicAnalyzer(Analyzer):
    """Deterministic, model-free analysis: severity from CVSS, no fabrication."""

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def judge(self, component: str, candidates: list[Candidate],
              context: list[tuple[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for candidate in candidates:
            lead = candidate.techniques[0][1] if candidate.techniques else "adversary techniques"
            version = candidate.observed_version or "an affected version"
            product = "the component"
            attack_path = (
                f"{component} runs {product} {version}, affected by {candidate.cve_id}. "
                f"{candidate.description} This can enable {lead}."
            )
            findings.append(_finding_from(
                candidate,
                severity=_severity_from_cvss(candidate.cvss),
                confidence=Confidence.HIGH if candidate.version_confirmed else Confidence.MEDIUM,
                title=f"{candidate.cve_id} affects {component}",
                attack_path=attack_path,
                technique_ids=[tid for tid, _ in candidate.techniques],
                mitigation_ids=[mid for mid, _ in candidate.mitigations],
            ))
        return findings


_ASSESS_TOOL: dict[str, Any] = {
    "name": "assess_candidates",
    "description": "Judge each vulnerability candidate against the observed component and context.",
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "one of the provided candidate CVE ids"},
                        "applicable": {"type": "boolean"},
                        "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
                        "confidence": {"enum": ["verified", "high", "medium", "low", "unverified"]},
                        "title": {"type": "string"},
                        "attack_path": {"type": "string", "description": "two or three sentences"},
                        "technique_ids": {"type": "array", "items": {"type": "string"},
                                          "description": "subset of the candidate's offered technique ids"},
                        "mitigation_ids": {"type": "array", "items": {"type": "string"},
                                           "description": "subset of the candidate's offered mitigation ids"},
                    },
                    "required": ["cve_id", "applicable", "severity", "confidence", "title", "attack_path"],
                },
            }
        },
        "required": ["findings"],
    },
}

_ASSESS_SYSTEM = get_prompt("cve").system


class ClaudeAnalyzer(Analyzer):
    """Claude-judged analysis with a strict identifier firewall."""

    def __init__(self, config: Config, logger: logging.Logger) -> None:
        self.logger = logger
        try:
            import anthropic
        except ImportError as exc:
            raise AnalyzerUnavailable("the 'anthropic' package is not installed") from exc
        api_key = os.environ.get(config.model.api_key_env)
        if not api_key:
            raise AnalyzerUnavailable(f"${config.model.api_key_env} is not set")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = config.model.analysis_model

    def judge(self, component: str, candidates: list[Candidate],
              context: list[tuple[str, Any]]) -> list[Finding]:
        by_id = {c.cve_id: c for c in candidates}
        decisions = self._assess(component, candidates, context)
        findings: list[Finding] = []
        for decision in decisions:
            cve_id = decision.get("cve_id")
            if cve_id not in by_id:
                # Firewall: a CVE that was not among the candidates.
                self.logger.warning("analysis referenced unknown CVE '%s' for %s; rejected",
                                    cve_id, component)
                continue
            if not decision.get("applicable", False):
                self.logger.info("analysis judged %s not applicable to %s", cve_id, component)
                continue
            candidate = by_id[cve_id]
            offered_t = {tid for tid, _ in candidate.techniques}
            offered_m = {mid for mid, _ in candidate.mitigations}
            technique_ids = [t for t in decision.get("technique_ids", []) if t in offered_t]
            for rejected in set(decision.get("technique_ids", [])) - offered_t:
                self.logger.warning("analysis proposed un-offered technique '%s' for %s; rejected",
                                    rejected, cve_id)
            mitigation_ids = [m for m in decision.get("mitigation_ids", []) if m in offered_m]
            findings.append(_finding_from(
                candidate,
                severity=_severity(decision.get("severity")),
                confidence=_confidence(decision.get("confidence")),
                title=str(decision.get("title") or f"{cve_id} affects {component}"),
                attack_path=str(decision.get("attack_path", "")),
                technique_ids=technique_ids or [tid for tid, _ in candidate.techniques],
                mitigation_ids=mitigation_ids or [mid for mid, _ in candidate.mitigations],
            ))
        return findings

    def _assess(self, component: str, candidates: list[Candidate],
                context: list[tuple[str, Any]]) -> list[dict[str, Any]]:
        payload = {
            "component": component,
            "engagement_context": [{"fact": k, "value": v} for k, v in context],
            "candidates": [
                {
                    "cve_id": c.cve_id,
                    "description": c.description,
                    "cvss": c.cvss,
                    "observed_version": c.observed_version,
                    "version_confirmed": c.version_confirmed,
                    "weaknesses": c.cwes,
                    "offered_techniques": [{"id": tid, "name": name} for tid, name in c.techniques],
                    "offered_mitigations": [{"id": mid, "name": text} for mid, text in c.mitigations],
                }
                for c in candidates
            ],
        }
        prompt = (
            "Assess these vulnerability candidates for the component below and call the tool with "
            "your judgement for each.\n\n" + json.dumps(payload, indent=2)
        )
        try:
            response = self._client.messages.create(
                model=self._model, max_tokens=2048, system=_ASSESS_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
                tools=[_ASSESS_TOOL],
                tool_choice={"type": "tool", "name": "assess_candidates"},
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.error("analysis call failed for %s (%s); no findings for this component",
                             component, exc)
            return []
        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                return [d for d in block.input.get("findings", []) if isinstance(d, dict)]
        return []
