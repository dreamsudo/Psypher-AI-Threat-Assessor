# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/core/validation.py — JSON Schema validation for packs and outputs.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""JSON Schema loading and validation for pack manifests and emitted artifacts."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

_SCHEMA_DIR = Path(__file__).resolve().parent / "schema"


class SchemaError(ValueError):
    """Raised when a referenced schema cannot be loaded."""


@lru_cache(maxsize=None)
def _load_schema(name: str) -> dict[str, Any]:
    """Load and cache a named schema (``<name>.schema.json``)."""
    path = _SCHEMA_DIR / f"{name}.schema.json"
    if not path.is_file():
        raise SchemaError(f"schema not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def validate(instance: Any, schema_name: str) -> list[str]:
    """Validate ``instance`` against the named schema.

    Returns a list of human-readable error strings; an empty list means valid.
    """
    validator = Draft202012Validator(_load_schema(schema_name))
    errors = sorted(validator.iter_errors(instance), key=lambda err: list(err.path))
    messages: list[str] = []
    for err in errors:
        location = "/".join(str(part) for part in err.path) or "<root>"
        messages.append(f"{location}: {err.message}")
    return messages
