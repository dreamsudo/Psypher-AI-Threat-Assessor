# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/discovery/__init__.py — Phase 0 package.
#  Installed by bootstrap-2-discovery.sh
# =============================================================================
"""Phase 0 — active discovery. Registers the discovery phase at import time."""
from ..core.contracts import register_phase
from .phase import DiscoveryPhase

register_phase(DiscoveryPhase())
