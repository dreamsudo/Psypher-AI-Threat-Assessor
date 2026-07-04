# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/__init__.py — Phase 3 package.
#  Installed by bootstrap-5-report.sh
# =============================================================================
"""Phase 3 — report. Registers the report phase at import time."""
from ..core.contracts import register_phase
from .phase import ReportPhase

register_phase(ReportPhase())
