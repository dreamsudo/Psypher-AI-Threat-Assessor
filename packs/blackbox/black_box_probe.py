# =============================================================================
#  packs/blackbox/black_box_probe.py
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  ISOLATED BLACK-BOX PROBE. Mirrors the script-probe contract (Option A):
#      run(target_view, context_view[, directions]) -> dict
#  target_view={id,kind,access,endpoint,host,ssh}; context_view=
#  {timeout,insecure_tls,auth_token}. Returns a dict, so with parse
#  {"from":"return_value"} the engine would expand it to one grain per key.
#  Two benign legs (§7 — defined/reviewed, not an arbitrary-command channel):
#  http (GET/POST to own endpoint) + infra (fixed benign SSH check, same
#  ssh -o BatchMode=yes pattern as the engine's _run_shell).
# =============================================================================
from __future__ import annotations
import json, subprocess, urllib.error, urllib.request


def _http_leg(target_view, context_view, directions):
    endpoint = (target_view.get("endpoint") or "http://localhost:11434").rstrip("/")
    d = (directions or {}).get("http", {})
    method = str(d.get("method", "GET")).upper()
    url = endpoint + str(d.get("path_suffix", "/api/version"))
    timeout = context_view.get("timeout", 10)
    headers = {"Accept": "application/json"}
    token = context_view.get("auth_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(2048).decode("utf-8", "replace")
        try:
            parsed = json.loads(body) if body.strip() else None
        except json.JSONDecodeError:
            parsed = None
        return {"hello": "world", "url": url, "method": method,
                "status": status, "body": body[:512], "json": parsed}
    except urllib.error.HTTPError as exc:
        return {"hello": "world", "url": url, "status": exc.code, "error": "http_error"}
    except Exception as exc:  # noqa: BLE001
        return {"hello": "world", "url": url, "error": str(exc)}


def _infra_leg(target_view, context_view, directions):
    ssh = target_view.get("ssh")
    d = (directions or {}).get("infra", {})
    cmd = str(d.get("command", "echo hello world; uname -sr; id -un"))
    timeout = context_view.get("timeout", 10) + 10
    if not ssh:
        return {"hello": "world", "note": "no ssh target configured"}
    try:
        out = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", ssh, cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        val = (out.stdout or "").strip() or (out.stderr or "").strip()
        return {"hello": "world", "ssh": ssh, "returncode": out.returncode, "output": val[:512]}
    except Exception as exc:  # noqa: BLE001
        return {"hello": "world", "ssh": ssh, "error": str(exc)}


def run(target_view, context_view, directions=None):
    directions = directions or {}
    return {
        "blackbox_http": _http_leg(target_view, context_view, directions),
        "blackbox_infra": _infra_leg(target_view, context_view, directions),
    }
