# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/cve.py — CVE-JSON 5.0 adapter.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""CVE adapter (CVE-JSON 5.0).

Reads CVE records and produces one vulnerability node per CVE — carrying its
description, CVSS base score, affected product/version ranges, and referenced
weaknesses — plus a weakness node and an ``instance_of`` edge for each CWE the
record cites. The affected ranges are retained verbatim so the analysis phase
can test an observed version against them.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .canonical import Edge, Graph, Node


def ingest_cve(graph: Graph, source_dir: Path, logger: logging.Logger) -> None:
    """Ingest every CVE file (*.json) found under ``source_dir``."""
    files = sorted(Path(source_dir).glob("*.json"))
    if not files:
        logger.warning("CVE source has no .json files in %s", source_dir)
        return
    total = 0
    for path in files:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("cannot read CVE file %s: %s", path, exc)
            continue
        for record in _records(doc):
            if _ingest_record(graph, record, logger):
                total += 1
    logger.debug("CVE adapter ingested %d record(s)", total)


def _records(doc: Any) -> list[dict[str, Any]]:
    """Accept a single record, a bare list, or a {'cves': [...]} envelope."""
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict) and isinstance(doc.get("cves"), list):
        return [r for r in doc["cves"] if isinstance(r, dict)]
    if isinstance(doc, dict) and "cveMetadata" in doc:
        return [doc]
    return []


def _first_cvss(metrics: list[dict[str, Any]]) -> float | None:
    """Return the highest-version CVSS base score available, else None."""
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for metric in metrics:
            block = metric.get(key)
            if isinstance(block, dict) and "baseScore" in block:
                try:
                    return float(block["baseScore"])
                except (TypeError, ValueError):
                    continue
    return None


def _ingest_record(graph: Graph, record: dict[str, Any], logger: logging.Logger) -> bool:
    cve_id = record.get("cveMetadata", {}).get("cveId")
    if not cve_id:
        logger.warning("CVE record missing cveId; skipping")
        return False
    cna = record.get("containers", {}).get("cna", {})

    description = ""
    for entry in cna.get("descriptions", []):
        if str(entry.get("lang", "en")).startswith("en"):
            description = entry.get("value", "")
            break

    cvss = _first_cvss(cna.get("metrics", []))

    cwes: list[str] = []
    for problem in cna.get("problemTypes", []):
        for entry in problem.get("descriptions", []):
            if entry.get("cweId"):
                cwes.append(entry["cweId"])

    affected: list[dict[str, Any]] = []
    for block in cna.get("affected", []):
        product = block.get("product")
        versions = block.get("versions", [])
        if versions:
            for version in versions:
                affected.append({
                    "product": product,
                    "version": version.get("version"),
                    "lessThan": version.get("lessThan"),
                    "lessThanOrEqual": version.get("lessThanOrEqual"),
                    "status": version.get("status", "affected"),
                })
        elif product:
            affected.append({"product": product, "status": "affected"})

    graph.add_node(Node(
        id=cve_id, type="vulnerability", name=cve_id, framework="CVE",
        attrs={"description": description, "cvss": cvss, "cwes": cwes, "affected": affected},
    ))
    for cwe in cwes:
        graph.add_node(Node(id=cwe, type="weakness", name="", framework="CWE", attrs={}))
        graph.add_edge(Edge(cve_id, cwe, "instance_of", {}))
    return True
