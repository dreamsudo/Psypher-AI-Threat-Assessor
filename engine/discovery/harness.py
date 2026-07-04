# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/discovery/harness.py — the sealed probe harness.
#  Installed by bootstrap-2-discovery.sh
# =============================================================================
"""The sealed probe harness.

Executes any conforming probe against an in-scope asset. It enforces three
guarantees on every call, independent of which probe runs:

  * scope    — the target host must not match the engagement denylist
               (the denylist always wins);
  * tier     — the probe's tier must be enabled, and intrusive probes require
               explicit operator approval;
  * bounded  — every execution has a timeout and its output is captured.

Probes are operator-authored and allowlisted; the harness runs them as given
and records each execution for the provenance log.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import logging
import os
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..core.config import Asset, Config
from ..core.contracts import ProbeSpec, ProbeTier, RunContext
from .approval import approve_intrusive

# Default per-probe execution timeout, in seconds.
DEFAULT_TIMEOUT: int = 30
# Cap on captured raw output to keep the provenance log bounded.
_RAW_CAP: int = 8000
# Opt-in to skip TLS verification for HTTP probes against self-signed infra.
_INSECURE_TLS_ENV: str = "PSYPHER_INSECURE_TLS"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


class ScopeViolation(RuntimeError):
    """Raised when a probe is refused by scope or tier policy."""


@dataclass
class ProbeResult:
    """The captured outcome of one probe execution."""

    probe_id: str
    tier: str
    target: str
    ok: bool
    raw: str = ""
    data: Any = None
    error: str = ""
    started: str = field(default_factory=_utc)
    finished: str = field(default_factory=_utc)

    def log_record(self) -> dict[str, Any]:
        """A compact, serialisable record for the provenance probe log."""
        return {
            "probe": self.probe_id,
            "tier": self.tier,
            "target": self.target,
            "ok": self.ok,
            "error": self.error,
            "started": self.started,
            "finished": self.finished,
        }


def _host_of(asset: Asset) -> str | None:
    """Best-effort extraction of the asset's network host."""
    if asset.endpoint:
        host = urlparse(asset.endpoint).hostname
        if host:
            return host
    if asset.host:
        return asset.host
    if asset.ssh and "@" in asset.ssh:
        return asset.ssh.split("@", 1)[1]
    return asset.ssh


def _denied(host: str, denylist: list[str]) -> bool:
    """Return True if ``host`` matches any denylist entry (CIDR or exact)."""
    for entry in denylist:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            if entry == host:
                return True
            continue
        try:
            if ipaddress.ip_address(host) in network:
                return True
        except ValueError:
            # host is a name, not an address; a CIDR entry cannot match it.
            continue
    return False


class Harness:
    """Scope-checked, tier-gated executor for probes."""

    def __init__(self, config: Config, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.timeout = DEFAULT_TIMEOUT
        self._insecure_tls = _truthy(os.environ.get(_INSECURE_TLS_ENV))

    # -- public ----------------------------------------------------------------

    def execute(self, probe: ProbeSpec, asset: Asset, ctx: RunContext) -> ProbeResult:
        """Execute ``probe`` against ``asset`` after enforcing scope and tier policy."""
        self._assert_in_scope(asset)
        self._gate_tier(probe, asset)

        target = _host_of(asset) or asset.id
        runner = {
            "shell": self._run_shell,
            "script": self._run_script,
            "http": self._run_http,
        }.get(probe.run.get("type", ""))

        if runner is None:
            result = ProbeResult(
                probe.id, probe.tier.value, target, ok=False,
                error=f"unsupported run type: {probe.run.get('type')!r}",
            )
        else:
            try:
                result = runner(probe, asset, target)
            except subprocess.TimeoutExpired:
                result = ProbeResult(probe.id, probe.tier.value, target, ok=False,
                                     error=f"timed out after {self.timeout}s")
            except Exception as exc:  # noqa: BLE001 — record any failure, never crash the run
                result = ProbeResult(probe.id, probe.tier.value, target, ok=False, error=str(exc))

        result.finished = _utc()
        ctx.artifacts.setdefault("probe_log", []).append(result.log_record())
        return result

    # -- scope & tier ----------------------------------------------------------

    def _assert_in_scope(self, asset: Asset) -> None:
        host = _host_of(asset)
        if host and _denied(host, self.config.scope.out_of_scope):
            raise ScopeViolation(f"target '{host}' matches the engagement denylist")

    def _gate_tier(self, probe: ProbeSpec, asset: Asset) -> None:
        policy = self.config.probes.tiers.get(probe.tier.value)
        if policy is None or not policy.enabled:
            raise ScopeViolation(f"probe tier '{probe.tier.value}' is not enabled")
        if probe.tier is ProbeTier.INTRUSIVE and policy.require_approval:
            target = _host_of(asset) or asset.id
            if not approve_intrusive(probe.id, target, self.logger):
                raise ScopeViolation(f"intrusive probe '{probe.id}' was not approved")

    # -- runners ---------------------------------------------------------------

    def _run_shell(self, probe: ProbeSpec, asset: Asset, target: str) -> ProbeResult:
        cmd = probe.run["cmd"]
        via = probe.run.get("via", "local")
        if via == "ssh":
            if not asset.ssh:
                return ProbeResult(probe.id, probe.tier.value, target, ok=False,
                                   error="probe requires SSH but the asset has no 'ssh' target")
            argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", asset.ssh, cmd]
        else:
            argv = ["/bin/sh", "-c", cmd]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout, check=False)
        raw = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0
        return ProbeResult(probe.id, probe.tier.value, target, ok=ok, raw=raw[:_RAW_CAP],
                           error="" if ok else f"exit {proc.returncode}")

    def _run_script(self, probe: ProbeSpec, asset: Asset, target: str) -> ProbeResult:
        script_path = (Path(probe.source_path).parent / probe.run["path"]).resolve()
        if not script_path.is_file():
            return ProbeResult(probe.id, probe.tier.value, target, ok=False,
                               error=f"script not found: {script_path}")
        module = self._load_module(probe.id, script_path)
        fn = getattr(module, probe.run["entry"], None)
        if not callable(fn):
            return ProbeResult(probe.id, probe.tier.value, target, ok=False,
                               error=f"entry '{probe.run['entry']}' is not callable in {script_path.name}")
        target_view = {
            "id": asset.id, "kind": asset.kind, "access": asset.access,
            "endpoint": asset.endpoint, "host": asset.host, "ssh": asset.ssh,
        }
        context_view = {
            "timeout": self.timeout,
            "insecure_tls": self._insecure_tls,
            "auth_token": os.environ.get(asset.auth_env) if asset.auth_env else None,
        }
        value = fn(target_view, context_view)
        return ProbeResult(
            probe.id, probe.tier.value, target, ok=value is not None, data=value,
            raw=json.dumps(value, default=str)[:_RAW_CAP] if value is not None else "",
        )

    def _run_http(self, probe: ProbeSpec, asset: Asset, target: str) -> ProbeResult:
        if not asset.endpoint:
            return ProbeResult(probe.id, probe.tier.value, target, ok=False,
                               error="probe requires HTTP but the asset has no 'endpoint'")
        method = probe.run.get("method", "GET").upper()
        url = asset.endpoint.rstrip("/") + probe.run.get("path_suffix", "")
        headers: dict[str, str] = {"Accept": "application/json"}
        if asset.auth_env and os.environ.get(asset.auth_env):
            headers["Authorization"] = f"Bearer {os.environ[asset.auth_env]}"
        request = urllib.request.Request(url, method=method, headers=headers)

        context = None
        if url.lower().startswith("https"):
            context = ssl.create_default_context()
            if self._insecure_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", "replace")
                resp_headers = {key: value for key, value in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", "replace") if exc.fp else ""
            resp_headers = {key: value for key, value in (exc.headers or {}).items()}

        try:
            parsed: Any = json.loads(body) if body.strip() else None
        except json.JSONDecodeError:
            parsed = None
        data = {"status": status, "headers": resp_headers, "json": parsed}
        ok = 200 <= status < 400
        return ProbeResult(probe.id, probe.tier.value, target, ok=ok, raw=body[:_RAW_CAP], data=data,
                           error="" if ok else f"HTTP {status}")

    @staticmethod
    def _load_module(probe_id: str, path: Path):
        """Import a probe script from the pack by file path."""
        spec = importlib.util.spec_from_file_location(f"psypher_probe_{probe_id}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load probe script: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
