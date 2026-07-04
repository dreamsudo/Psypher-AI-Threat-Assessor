# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/package.py — bundle artifacts into a case archive.
#  Installed by bootstrap-5-report.sh
# =============================================================================
"""Bundle the rendered artifacts into a single CASE-<id>.zip."""
from __future__ import annotations

import logging
import zipfile
from pathlib import Path


def package_zip(files: list[Path], zip_path: Path, logger: logging.Logger) -> Path:
    """Write the given files into a zip archive (flat, by basename)."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            if path.is_file():
                archive.write(path, path.name)
    logger.info("packaged %d artifact(s) into %s", len(files), zip_path.name)
    return zip_path
