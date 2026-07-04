# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/core/banner.py — startup banner.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""PsypherLabs startup banner for the command-line interface."""
from __future__ import annotations

import os
import sys
from typing import TextIO

from rich.console import Console
from rich.text import Text

# Edit TOOL_NAME to rebrand the CLI; the diamond art below is fixed PsypherLabs branding.
TOOL_NAME: str = "Psypher AI Threat Assessor"
_TAGLINE: str = f" {TOOL_NAME} by PsypherLabs"

# Setting this environment variable to a truthy value suppresses the banner.
_SUPPRESS_ENV: str = "PSYPHER_NO_BANNER"


def _truthy(value: str | None) -> bool:
    """Return True for the common truthy string spellings."""
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def show_banner(stream: TextIO | None = None, *, force: bool = False) -> None:
    """Render the PsypherLabs banner.

    The banner is written to ``stream`` (stderr by default) so stdout stays
    reserved for machine-readable output. It is suppressed automatically when
    the stream is not an interactive terminal, or when the suppression
    environment variable is set, unless ``force`` is True.
    """
    stream = stream or sys.stderr

    if not force:
        if _truthy(os.environ.get(_SUPPRESS_ENV)):
            return
        if not getattr(stream, "isatty", lambda: False)():
            return

    console = Console(file=stream, highlight=False)
    banner = Text()
    banner.append("\n")
    banner.append("               *               \n", style="#39FF14")
    banner.append("              ***              \n", style="#39FF14")
    banner.append("             *****             \n", style="#39FF14")
    banner.append("            *******            \n", style="#39FF14")
    banner.append("           *********           \n", style="#39FF14")
    banner.append("          ***********          \n", style="#39FF14")
    banner.append("         *****Psypher*****     \n", style="#39FF14")
    banner.append("          *****Labs*****      \n", style="#39FF14")
    banner.append("           ***********          \n", style="#39FF14")
    banner.append("            *******            \n", style="#39FF14")
    banner.append("             *****             \n", style="#39FF14")
    banner.append("              ***              \n", style="#39FF14")
    banner.append("               *               \n", style="#39FF14")
    banner.append("\n")
    banner.append(f"{TOOL_NAME}\n", style="#39FF14")
    banner.append("Full-stack AI/ML security \u2014 MITRE ATLAS\u2013grounded penetration testing\n", style="#C7CCC7")
    banner.append("of the model and the infrastructure it runs on\n", style="#C7CCC7")
    banner.append("Powered by Claude \u00b7 Designed by PsypherLabs\n", style="bold #FF2D95")
    console.print(banner)
