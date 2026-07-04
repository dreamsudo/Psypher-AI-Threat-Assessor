# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  packs/probes/ml-inference/embedding_probe.py — safe inference-API probe.
#  Installed by bootstrap-2-discovery.sh
# =============================================================================
"""Safe, read-only inference-API surface probe (tier: active_safe).

Performs read-only GET requests against an OpenAI-compatible inference endpoint
to establish what API surface it exposes -- never an exploit. The resulting
grains (whether the OpenAI API is present, which model is served, reachability)
let later analysis map the endpoint to the relevant serving-stack CVEs.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any


def _get(url: str, token: str | None, timeout: int, insecure: bool) -> tuple[int, Any]:
    """Issue a single read-only GET; return (status, parsed_json_or_none)."""
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, method="GET", headers=headers)
    context = None
    if url.lower().startswith("https"):
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, (json.loads(body) if body.strip() else None)
            except json.JSONDecodeError:
                return resp.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, None


def run(target: dict, context: dict) -> dict:
    """Entry point invoked by the harness. Returns a mapping of observed attributes."""
    endpoint = (target.get("endpoint") or "").rstrip("/")
    if not endpoint:
        return {"engine_reachable": False}

    timeout = int(context.get("timeout", 30))
    token = context.get("auth_token")
    insecure = bool(context.get("insecure_tls", False))

    status, payload = _get(f"{endpoint}/v1/models", token, timeout, insecure)
    result: dict[str, Any] = {"engine_reachable": status != 0}
    if status == 0:
        return result

    result["openai_compatible"] = status == 200 and isinstance(payload, dict) and "data" in payload
    if result["openai_compatible"]:
        models = payload.get("data") or []
        served = [m.get("id") for m in models if isinstance(m, dict) and m.get("id")]
        if served:
            result["served_model"] = served[0]
    return result
