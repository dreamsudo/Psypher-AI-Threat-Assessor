# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/cwe.py — CWE XML adapter.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""CWE adapter (MITRE CWE XML).

Enriches weakness nodes (already created from CVE references) with their
canonical name and short description. Parsing is namespace-agnostic so it works
against the official ``cwec_*.xml`` regardless of schema-version namespace.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from .canonical import Graph, Node


def _localname(tag: str) -> str:
    """Strip any XML namespace from an element tag."""
    return tag.rsplit("}", 1)[-1]


def ingest_cwe(graph: Graph, source_dir: Path, logger: logging.Logger) -> None:
    """Ingest every CWE catalog (*.xml) found under ``source_dir``."""
    files = sorted(Path(source_dir).glob("*.xml"))
    if not files:
        logger.warning("CWE source has no .xml files in %s", source_dir)
        return
    total = 0
    for path in files:
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError) as exc:
            logger.error("cannot parse CWE catalog %s: %s", path, exc)
            continue
        total += _ingest_root(graph, root)
    logger.debug("CWE adapter ingested %d weakness definition(s)", total)


def _ingest_root(graph: Graph, root: ET.Element) -> int:
    count = 0
    for element in root.iter():
        if _localname(element.tag) != "Weakness":
            continue
        weakness_id = element.get("ID")
        if not weakness_id:
            continue
        name = element.get("Name", "")
        description = ""
        for child in element:
            if _localname(child.tag) == "Description":
                description = "".join(child.itertext()).strip()
                break
        graph.add_node(Node(id=f"CWE-{weakness_id}", type="weakness",
                            name=name or f"CWE-{weakness_id}", framework="CWE",
                            attrs={"description": description}))
        count += 1
    return count
