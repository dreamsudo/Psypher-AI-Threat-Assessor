# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/__init__.py — Phase 1 package.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""Phase 1 — the knowledge graph. Registers the graph phase at import time."""
from ..core.contracts import register_phase
from .phase import GraphPhase

register_phase(GraphPhase())
