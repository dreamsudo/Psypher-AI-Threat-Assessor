# engine/analysis/policy.py
# -----------------------------------------------------------------------------
# Psypher — safeguard policy for Branch B (the brain).  [Bootstrap 7]
#
# The tunable "constitution" the brain reasons against. Loaded from a YAML file
# (default packs/policy/strict.yaml); if absent, built-in STRICT defaults apply,
# so the brain works with zero configuration and errs safe.
#
# Two axes of knobs:
#   * Sensitivity (freely tunable): how much to predict, confidence floors,
#     severity caps, which domains Pass 2 may reason over.
#   * Integrity (tunable toward STRICTER only, floored at honest): a finding must
#     cite real grains; ids must exist in the graph. These cannot be disabled —
#     the floor is what protects the tool's credibility.
# -----------------------------------------------------------------------------
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Policy:
    # grounding (integrity — floored)
    require_supporting_grains: bool = True         # cannot be turned off
    min_grains_for_possible: int = 1               # >=1 always
    drop_unvalidated_ids: bool = True              # cannot be turned off
    # prediction (sensitivity — free)
    enable_structural: bool = True                 # Pass 1: graph-edge reachability
    enable_posture_inference: bool = True          # Pass 2: evidence-leashed posture
    enable_behavioral: bool = True                 # judge red-team exchanges
    max_inference_depth: int = 2
    # confidence / severity (sensitivity — free)
    min_confidence_to_report: str = "low"          # low|medium|high
    possible_findings_require_label: bool = True
    cap_possible_at: str = "high"                  # possible can't be reported critical
    # scope
    domains: list = field(default_factory=lambda: ["enterprise", "atlas"])

    # -- integrity floor, applied after loading -----------------------------
    def _enforce_floor(self) -> "Policy":
        self.require_supporting_grains = True
        self.drop_unvalidated_ids = True
        if self.min_grains_for_possible < 1:
            self.min_grains_for_possible = 1
        return self


_CONF_RANK = {"low": 0, "medium": 1, "high": 2, "verified": 2, "unverified": 0}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def confidence_ok(policy: Policy, confidence: str) -> bool:
    floor = _CONF_RANK.get(str(policy.min_confidence_to_report).lower(), 0)
    return _CONF_RANK.get(str(confidence).lower(), 0) >= floor


def cap_severity(policy: Policy, severity: str, grade: str) -> str:
    if grade == "possible":
        cap = _SEV_RANK.get(str(policy.cap_possible_at).lower(), 3)
        if _SEV_RANK.get(str(severity).lower(), 0) > cap:
            for name, rank in _SEV_RANK.items():
                if rank == cap:
                    return name
    return severity


def load_policy(config, logger=None) -> Policy:
    """
    Resolve the policy path from config.analysis.policy (if present), else the
    default. Missing file -> strict defaults. Always enforces the integrity floor.
    """
    path = None
    analysis_cfg = getattr(config, "analysis", None)
    if analysis_cfg is not None:
        path = getattr(analysis_cfg, "policy", None) or (
            analysis_cfg.get("policy") if isinstance(analysis_cfg, dict) else None
        )
    if not path:
        path = os.environ.get("PSYPHER_POLICY", "packs/policy/strict.yaml")

    data = {}
    if path and os.path.isfile(path):
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception as exc:  # noqa: BLE001
            if logger:
                logger.warning("policy load failed (%s); using strict defaults", exc)
            data = {}
    elif logger:
        logger.info("no policy file at %s; using built-in strict defaults", path)

    p = Policy()
    grounding = data.get("grounding", {}) if isinstance(data, dict) else {}
    prediction = data.get("prediction", {}) if isinstance(data, dict) else {}
    confidence = data.get("confidence", {}) if isinstance(data, dict) else {}
    severity = data.get("severity", {}) if isinstance(data, dict) else {}
    scope = data.get("scope", {}) if isinstance(data, dict) else {}

    p.min_grains_for_possible = int(grounding.get("min_grains_for_possible", p.min_grains_for_possible))
    p.enable_structural = bool(prediction.get("enable_structural", p.enable_structural))
    p.enable_posture_inference = bool(prediction.get("enable_posture_inference", p.enable_posture_inference))
    p.enable_behavioral = bool(prediction.get("enable_behavioral", p.enable_behavioral))
    p.max_inference_depth = int(prediction.get("max_inference_depth", p.max_inference_depth))
    p.min_confidence_to_report = str(confidence.get("min_confidence_to_report", p.min_confidence_to_report))
    p.possible_findings_require_label = bool(confidence.get("possible_findings_require_label", p.possible_findings_require_label))
    p.cap_possible_at = str(severity.get("cap_possible_at", p.cap_possible_at))
    if isinstance(scope.get("domains"), list):
        p.domains = scope["domains"]

    return p._enforce_floor()
