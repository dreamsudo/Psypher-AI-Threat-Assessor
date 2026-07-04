# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/analysis/__init__.py — Phase 2 package.
#  Installed by bootstrap-4-analysis.sh
# =============================================================================
"""Phase 2 — analysis. Registers the analysis phase at import time."""
from ..core.contracts import register_phase
from .phase import AnalysisPhase

register_phase(AnalysisPhase())

# [bootstrap-7] Branch B — register the reasoning brain (order 35, runs after the
# CVE analysis phase and before report). Additive: the CVE branch is untouched.
try:
    from .brain import BrainPhase as _BrainPhase
    from ..core.contracts import register_phase as _register_brain
    _register_brain(_BrainPhase())
except Exception as _brain_exc:  # pragma: no cover
    import logging as _logging
    _logging.getLogger(__name__).warning("brain phase not registered: %s", _brain_exc)
# [PsypherLabs] Host-isolation posture analysis (order 37, after brain, before
# report). Additive and deterministic; validates its own technique ids.
try:
    from .posture import PosturePhase as _PosturePhase
    from ..core.contracts import register_phase as _register_posture
    _register_posture(_PosturePhase())
except Exception as _posture_exc:  # pragma: no cover
    import logging as _logging
    _logging.getLogger(__name__).warning("posture phase not registered: %s", _posture_exc)
