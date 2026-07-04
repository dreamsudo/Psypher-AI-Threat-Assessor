# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/analysis/validate.py — closing hallucination firewall.
#  Installed by bootstrap-4-analysis.sh
# =============================================================================
"""The final identifier firewall.

Every CVE, CWE, technique, and mitigation id referenced by a finding — and every
technique referenced by a kill chain — is checked against the graph. Anything
not present is dropped and logged. This is the last line of defence: candidates
already come from the graph and the analyzers select from offered ids, so a
breach here would indicate a real bug, not a model error.
"""
from __future__ import annotations

import logging

from ..core.models import Finding, KillChain
from ..graph.canonical import Graph


def validate_findings(findings: list[Finding], graph: Graph, logger: logging.Logger) -> list[Finding]:
    """Drop any finding identifier that is absent from the graph."""
    rejects = 0
    for finding in findings:
        kept_techniques = []
        for ref in finding.techniques:
            if graph.has(ref.id):
                ref.validated = True
                kept_techniques.append(ref)
            else:
                rejects += 1
                logger.warning("finding %s cites unknown technique '%s'; dropped", finding.id, ref.id)
        finding.techniques = kept_techniques

        kept_mitigations = [m for m in finding.mitigations if graph.has(m.id)]
        rejects += len(finding.mitigations) - len(kept_mitigations)
        finding.mitigations = kept_mitigations

        for vuln in finding.vulnerabilities:
            if vuln.cve and not graph.has(vuln.cve):
                logger.warning("finding %s cites unknown CVE '%s'", finding.id, vuln.cve)
            if vuln.cwe and not graph.has(vuln.cwe):
                logger.warning("finding %s cites unknown CWE '%s'; clearing", finding.id, vuln.cwe)
                vuln.cwe = ""
    if rejects:
        logger.info("validation dropped %d unverifiable identifier(s)", rejects)
    return findings


def validate_kill_chain(chain: KillChain, graph: Graph, logger: logging.Logger) -> KillChain:
    """Drop any kill-chain step whose technique is absent from the graph."""
    kept = []
    for step in chain.steps:
        if graph.has(step.ref):
            if step.mitigated_by and not graph.has(step.mitigated_by):
                step.mitigated_by = ""
            kept.append(step)
        else:
            logger.warning("kill chain cites unknown technique '%s'; step dropped", step.ref)
    for index, step in enumerate(kept, start=1):
        step.order = index
    chain.steps = kept
    return chain
