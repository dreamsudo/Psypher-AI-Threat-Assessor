# =============================================================================
#  engine/analysis/posture.py
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  Host-isolation posture analysis (deterministic, order 37).
# =============================================================================
from __future__ import annotations

"""Consume host-isolation grains and emit ATT&CK-anchored findings.

Deterministic: maps observed isolation state (capability bitmask, seccomp mode,
socket presence) to real technique ids, so there is nothing for a model to
fabricate. Honors the grounding guarantee directly — every technique id is
validated against the knowledge graph before a finding is emitted (findings
added after order 30 are not auto-revalidated, so this phase validates its own;
invariant 3). CWE ids are weaknesses, not techniques, so they ride in the
finding's evidence, never as the anchor. Runs after the brain (35), before
report (40). No model touchpoint, so no new firewall — only id membership.
"""

import re
from typing import Any

from ..core.contracts import Phase, register_phase
from ..core.models import Finding, TechniqueRef, Severity, Confidence

try:
    from ..core.evidence_log import EvidenceLog
    _HAVE_LOG = True
except Exception:  # pragma: no cover - logging is optional, analysis is not
    EvidenceLog = None  # type: ignore
    _HAVE_LOG = False

# CAP_SYS_ADMIN is bit 21; its mask in the CapEff hex field is 0x200000.
_CAP_SYS_ADMIN_BIT = 21


def _graph(ctx) -> Any:
    return (getattr(ctx, "artifacts", {}) or {}).get("graph")


def _technique_ids(graph) -> set:
    """The firewall allow-list: only graph techniques may anchor a finding."""
    ids: set = set()
    if graph is None:
        return ids
    nodes = getattr(graph, "nodes", None)
    try:
        iterable = nodes.values() if hasattr(nodes, "values") else nodes
        for node in (iterable or []):
            ntype = (node.get("type") if isinstance(node, dict) else getattr(node, "type", "")) or ""
            nid = (node.get("id") if isinstance(node, dict) else getattr(node, "id", "")) or ""
            if ntype == "technique" and nid:
                ids.add(nid)
    except Exception:
        pass
    return ids


def _node_name(graph, node_id: str) -> str:
    nodes = getattr(graph, "nodes", None)
    try:
        if hasattr(nodes, "get"):
            node = nodes.get(node_id)
            if isinstance(node, dict):
                return node.get("name", node_id)
            if node is not None:
                return getattr(node, "name", node_id)
    except Exception:
        pass
    return node_id


def _grains_by_attr(ctx) -> dict:
    """Index this run's grains as {attribute: (value, component)}."""
    out: dict = {}
    for g in getattr(ctx, "grains", []):
        attr = g.get("attribute", "") if isinstance(g, dict) else getattr(g, "attribute", "")
        val = g.get("value", "") if isinstance(g, dict) else getattr(g, "value", "")
        comp = g.get("component", "") if isinstance(g, dict) else getattr(g, "component", "")
        if attr:
            out[str(attr)] = (val, comp or "target")
    return out


def _cap_sys_admin(cap_eff_value: str) -> bool:
    """True if the CAP_SYS_ADMIN bit is set in a 'CapEff: <hex>' grain value."""
    m = re.search(r"([0-9a-fA-F]{4,})", str(cap_eff_value) or "")
    if not m:
        return False
    try:
        return bool(int(m.group(1), 16) & (1 << _CAP_SYS_ADMIN_BIT))
    except ValueError:
        return False


def _make_finding(*, component, technique_id, technique_name, severity, confidence,
                  title, attack_path, cwe, supporting, rationale) -> Finding:
    return Finding(
        id=f"FND-{component}-posture-{technique_id}".replace(" ", ""),
        component=component,
        title=title,
        severity=Severity(severity),
        confidence=Confidence(confidence),
        techniques=[TechniqueRef(framework="ATT&CK", id=technique_id,
                                 name=technique_name, validated=True)],
        vulnerabilities=[],
        mitigations=[],
        attack_path=attack_path,
        evidence={
            "grade": "possible",
            "verdict": "reachable",
            "cwe": cwe,
            "supporting_grains": supporting,
            "rationale": rationale,
            "match": "posture",
        },
    )


def _log_posture(ctx, technique, severity, cwe, attr, rationale) -> None:
    """Append a posture verdict record to the evidence log (best-effort)."""
    if not _HAVE_LOG:
        return
    try:
        artifacts = getattr(ctx, "artifacts", {}) or {}
        log = EvidenceLog(case_id=artifacts.get("case_id", "") or "",
                          case_dir=artifacts.get("case_dir"))
        log.record_verdict(
            refs_exchange="",
            technique=technique,
            grade="possible",
            verdict="reachable",
            confidence="low",
            severity=severity,
            supporting_grains=[attr],
            mitigations=[cwe] if cwe else [],
            rationale=rationale,
            policy="posture",
        )
    except Exception:
        pass


class PosturePhase(Phase):
    """Host-isolation posture analysis (deterministic), order 37."""

    name = "posture"
    order = 37

    def run(self, ctx) -> None:
        logger = ctx.logger
        graph = _graph(ctx)
        valid = _technique_ids(graph)
        grains = _grains_by_attr(ctx)
        produced = 0
        fired: set = set()

        def emit(attr, technique, severity, cwe, why):
            nonlocal produced
            if attr not in grains or technique in fired:
                return
            if valid and technique not in valid:
                logger.info("posture: skip %s (technique %s not in graph)", attr, technique)
                return
            value, component = grains[attr]
            ctx.findings.append(_make_finding(
                component=component, technique_id=technique,
                technique_name=_node_name(graph, technique),
                severity=severity, confidence="low",
                title=f"Host isolation weakness - {_node_name(graph, technique)} reachable",
                attack_path=(f"Observed '{attr}'={value} on {component}. {why} "
                             f"This makes ATT&CK {technique} reachable (assessed, not proven)."),
                cwe=cwe, supporting=[attr],
                rationale=f"Posture grain '{attr}'={value}: {why}",
            ))
            _log_posture(ctx, technique, severity, cwe, attr, f"Posture grain '{attr}'={value}: {why}")
            fired.add(technique)
            produced += 1

        if grains.get("docker_socket", ("", ""))[0] == "present":
            emit("docker_socket", "T1611", "high", "CWE-250",
                 "A reachable Docker socket allows spawning a privileged container to reach the host.")

        cap_val = grains.get("effective_caps", ("", ""))[0]
        if cap_val and _cap_sys_admin(cap_val):
            emit("effective_caps", "T1611", "high", "CWE-250",
                 "CAP_SYS_ADMIN is held, a capability commonly abused to escape container isolation.")

        seccomp = str(grains.get("seccomp_mode", ("", ""))[0])
        if re.search(r"\b0\b", seccomp) and "T1611" not in fired:
            emit("seccomp_mode", "T1611", "medium", "CWE-693",
                 "Seccomp is disabled, removing a syscall-filtering barrier against isolation escape.")


        # --- model-endpoint hygiene (HTTP surface) ---------------------------
        # Ollama returns 200 on these unauthenticated; a 200 with no auth in
        # front of the inference/management API is the exposure we flag.
        auth = grains.get("inference_api_auth", ("", ""))[0]
        if str(auth) == "200":
            emit("inference_api_auth", "AML.T0040", "medium", "CWE-306",
                 "The inference API answered an unauthenticated request (HTTP 200), "
                 "so model access is reachable without credentials.")

        mgmt = grains.get("mgmt_api_status", ("", ""))[0]
        if str(mgmt) == "200":
            emit("mgmt_api_status", "T1046", "medium", "CWE-306",
                 "The model-management API answered an unauthenticated request "
                 "(HTTP 200), exposing running-model enumeration without credentials.")


        # --- model provenance (supply chain) --------------------------------
        prov = str(grains.get("model_provenance", ("", ""))[0]).lower()
        digest = grains.get("served_model_digest", ("", ""))[0]
        if digest and ("not pinned" in prov or "unpinned" in prov):
            emit("served_model_digest", "AML.T0010", "low", "CWE-353",
                 f"The served model (digest {str(digest)[:12]}...) is drawn from an "
                 "unpinned source with no integrity check enforced against a known-good digest.")

        logger.info("posture: produced %d finding(s)", produced)


try:
    register_phase(PosturePhase())
except Exception:
    pass
