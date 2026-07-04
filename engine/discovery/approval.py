# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/discovery/approval.py — intrusive-probe approval gate.
#  Installed by bootstrap-2-discovery.sh
# =============================================================================
"""Operator approval gate for intrusive probes (default deny)."""
from __future__ import annotations

import logging
import os
import sys

_APPROVE_ENV = "PSYPHER_APPROVE_INTRUSIVE"


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def approve_intrusive(probe_id: str, target: str, logger: logging.Logger) -> bool:
    """Decide whether an intrusive probe may run.

    Approval is granted only by (a) an explicit pre-authorisation environment
    variable, or (b) an interactive operator confirmation on a TTY. With no TTY
    and no pre-authorisation, the probe is denied.
    """
    if _truthy(os.environ.get(_APPROVE_ENV)):
        logger.warning("intrusive probe '%s' pre-approved via $%s", probe_id, _APPROVE_ENV)
        return True
    if not sys.stdin.isatty():
        logger.error(
            "intrusive probe '%s' requires approval but no interactive terminal is available; denying",
            probe_id,
        )
        return False
    try:
        answer = input(f"Approve INTRUSIVE probe '{probe_id}' against {target}? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}
