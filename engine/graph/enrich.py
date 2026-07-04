# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/enrich.py — Claude cross-framework edge proposer.
#  Installed by bootstrap-3-graph.sh
# =============================================================================
"""Graph enrichment: the novel cross-framework links.

No official feed states "CVE-X enables Technique-Y". This step asks Claude to
propose those ``enables`` edges from each vulnerability to the techniques it
makes possible. Claude's proposals are passed through a firewall: a proposed
technique id is added only if it already exists in the graph. Claude may relate
known facts; it can never invent an identifier. Enrichment is skipped cleanly
when no model credentials are available.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..core.config import Config
from .canonical import Edge, Graph, Node
from ..core.prompts import get_prompt


class EnrichUnavailable(RuntimeError):
    """Raised when the enrichment model client cannot be constructed."""


_MAP_TOOL: dict[str, Any] = {
    "name": "map_vulnerability",
    "description": "Map a vulnerability to the ATT&CK/ATLAS techniques it enables.",
    "input_schema": {
        "type": "object",
        "properties": {
            "edges": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string",
                                         "description": "must be one of the provided technique ids"},
                        "confidence": {"enum": ["high", "medium", "low"]},
                        "rationale": {"type": "string", "description": "one sentence"},
                    },
                    "required": ["technique_id"],
                },
            }
        },
        "required": ["edges"],
    },
}

_SYSTEM = get_prompt("enrich").system


class GraphEnricher:
    """Proposes and validates cross-framework 'enables' edges via Claude."""

    def __init__(self, config: Config, logger: logging.Logger) -> None:
        self.logger = logger
        try:
            import anthropic  # imported lazily so the engine runs without the SDK
        except ImportError as exc:
            raise EnrichUnavailable("the 'anthropic' package is not installed") from exc
        api_key = os.environ.get(config.model.api_key_env)
        if not api_key:
            raise EnrichUnavailable(f"${config.model.api_key_env} is not set")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = config.model.analysis_model

    def enrich(self, graph: Graph) -> int:
        """Add validated 'enables' edges; return how many were added."""
        techniques = {node.id: node.name for node in graph.by_type("technique")}
        if not techniques:
            self.logger.warning("graph has no techniques; skipping enrichment "
                                "(run data/fetch.sh to load ATLAS/ATT&CK)")
            return 0
        vulnerabilities = graph.by_type("vulnerability")
        catalogue = _catalogue(techniques)
        added = 0
        for vuln in vulnerabilities:
            for proposal in self._propose(vuln, catalogue):
                technique_id = proposal.get("technique_id", "")
                if technique_id not in techniques:
                    # Firewall: Claude proposed a technique that is not in the graph.
                    self.logger.warning("enrichment proposed unknown technique '%s' for %s; rejected",
                                        technique_id, vuln.id)
                    continue
                graph.add_edge(Edge(vuln.id, technique_id, "enables", {
                    "confidence": proposal.get("confidence", "medium"),
                    "rationale": str(proposal.get("rationale", ""))[:400],
                    "source": "claude-enrichment",
                }))
                added += 1
        return added

    def _propose(self, vuln: Node, catalogue: str) -> list[dict[str, Any]]:
        prompt = (
            f"Vulnerability: {vuln.id}\n"
            f"Description: {vuln.attrs.get('description', '')}\n"
            f"Weaknesses: {', '.join(vuln.attrs.get('cwes', [])) or '(none)'}\n\n"
            f"Available techniques (choose only from these ids):\n{catalogue}\n\n"
            "List the techniques this vulnerability could let an attacker carry out directly."
        )
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
                tools=[_MAP_TOOL],
                tool_choice={"type": "tool", "name": "map_vulnerability"},
            )
        except Exception as exc:  # noqa: BLE001 — a model/transport failure skips this vuln
            self.logger.error("enrichment call failed for %s (%s)", vuln.id, exc)
            return []
        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                edges = block.input.get("edges", [])
                return [e for e in edges if isinstance(e, dict)]
        return []


def _catalogue(techniques: dict[str, str]) -> str:
    """Render the technique id/name list compactly for the prompt."""
    return json.dumps([{"id": tid, "name": name} for tid, name in sorted(techniques.items())], indent=0)
