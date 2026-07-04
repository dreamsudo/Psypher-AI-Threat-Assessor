# engine/core/evidence_log.py
# -----------------------------------------------------------------------------
# Psypher — shared evidence logger.  [Bootstrap 6]
#
# An append-only, tamper-evident (hash-chained), UUID-linked JSONL logger used
# to record every model exchange (and, later, every verdict) for two purposes:
#   (1) forensics  — an immutable, timestamped, verifiable record of what was
#                    sent and received;
#   (2) training   — the same data as clean (prompt, response, verdict) tuples,
#                    ready to pipe into a dataset later.
#
# Design (done the right way, no corners):
#   * Append-only. A line, once written, is never modified, reordered, or
#     deleted. The capture and its later verdict are TWO records joined by id.
#   * Two record types in one stream, distinguished by `record_type`:
#         "exchange" — written by a probe at capture time.
#         "verdict"  — written by the brain at analysis time (Bootstrap 7),
#                      carrying `refs_exchange` = the exchange's `exchange_id`.
#   * Linked by UUID (`exchange_id`), not by attack name — the unique forensic
#     anchor for one exact firing.
#   * Tamper-evident via a hash chain: each record carries `seq` (monotonic)
#     and `prev_hash` (sha256 of the previous record's canonical JSON). Any
#     later edit or deletion breaks the chain and is detectable.
#   * Two sinks from one write: a per-case log and a global master corpus.
#
# This module is standalone: it imports only the Python standard library, has
# no dependency on the rest of the engine, and is safe to import even when the
# rest of a run has not been set up.  Nothing in the sealed engine imports it
# unless a probe (or the brain) chooses to.
# -----------------------------------------------------------------------------
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

_GENESIS = "sha256:" + ("0" * 64)
_lock = threading.Lock()


def new_exchange_id() -> str:
    """Mint a fresh, globally-unique id for one exchange (one probe firing)."""
    return str(uuid.uuid4())


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(record: dict) -> str:
    # Deterministic serialization so the hash is stable and reproducible.
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _tail(path: str) -> tuple[int, str]:
    """Return (last_seq, last_hash) for an existing chain, or (0, genesis)."""
    if not os.path.isfile(path):
        return 0, _GENESIS
    last_line = ""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
    except OSError:
        return 0, _GENESIS
    if not last_line:
        return 0, _GENESIS
    try:
        rec = json.loads(last_line)
    except json.JSONDecodeError:
        # Chain is corrupt/foreign; do not silently overwrite — start a fresh
        # logical chain but keep appending (the break itself is the evidence).
        return 0, _GENESIS
    return int(rec.get("seq", 0)), _hash(_canonical(rec))


def _append(path: str, payload: dict) -> Optional[dict]:
    """Append one hash-chained record to a single JSONL sink. Returns it."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    last_seq, last_hash = _tail(path)
    record = dict(payload)
    record["seq"] = last_seq + 1
    record["prev_hash"] = last_hash
    line = _canonical(record)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return record


class EvidenceLog:
    """
    A two-sink, append-only, hash-chained evidence writer.

    Each sink maintains its own independent chain (its own seq/prev_hash), so a
    per-case log and the global master can be verified independently.

    Typical use from a probe:

        log = EvidenceLog(case_id="CASE-...", case_dir="assessments/CASE-...")
        xid = log.record_exchange(target="ollama", endpoint="...",
                                  probe="rt_prompt_injection",
                                  attack_id="rt_prompt_injection_override",
                                  technique="AML.T0051", tactic="AML.TA0000",
                                  prompt="...", response="...",
                                  canary="PSYPHER_BREACH_7f3a",
                                  canary_hit=True, latency_ms=812,
                                  outcome="captured",
                                  model_meta={"served_model": "tinyllama:latest"})
        # xid is the exchange_id; the brain later writes a verdict referencing it.
    """

    def __init__(
        self,
        case_id: str = "",
        case_dir: Optional[str] = None,
        master_path: str = "logs/exchanges.jsonl",
    ) -> None:
        self.case_id = case_id
        self.master_path = master_path
        self.case_path = os.path.join(case_dir, "exchanges.jsonl") if case_dir else None

    # -- writing ------------------------------------------------------------
    def record_exchange(
        self,
        *,
        target: str,
        endpoint: str,
        probe: str,
        attack_id: str,
        technique: str,
        tactic: str = "",
        prompt: str,
        response: str,
        canary: str = "",
        canary_hit: bool = False,
        latency_ms: Optional[int] = None,
        outcome: str = "captured",
        cwe: str = "",
        severity_hint: str = "",
        model_meta: Optional[dict] = None,
        exchange_id: Optional[str] = None,
    ) -> str:
        """Write one immutable `exchange` record to both sinks. Returns exchange_id."""
        xid = exchange_id or new_exchange_id()
        payload: dict[str, Any] = {
            "record_type": "exchange",
            "exchange_id": xid,
            "ts": _utc_now(),
            "case_id": self.case_id,
            "target": target,
            "endpoint": endpoint,
            "probe": probe,
            "attack_id": attack_id,
            "technique": technique,
            "tactic": tactic,
            "cwe": cwe,
            "severity_hint": severity_hint,
            "prompt": prompt,
            "response": response,
            "canary": canary,
            "canary_hit": bool(canary_hit),
            "latency_ms": latency_ms,
            "outcome": outcome,
            "model_meta": model_meta or {},
        }
        with _lock:
            if self.case_path:
                _append(self.case_path, payload)
            _append(self.master_path, payload)
        return xid

    def record_verdict(
        self,
        *,
        refs_exchange: str,
        technique: str,
        grade: str,
        verdict: str,
        confidence: str,
        rationale: str = "",
        severity: str = "",
        supporting_grains: Optional[list] = None,
        mitigations: Optional[list] = None,
        policy: str = "",
    ) -> str:
        """
        Write one immutable `verdict` record linked to an exchange. Used by the
        brain (Bootstrap 7); provided here so the log schema is stable from day
        one and callers never mutate an exchange record.
        """
        vid = str(uuid.uuid4())
        payload: dict[str, Any] = {
            "record_type": "verdict",
            "verdict_id": vid,
            "refs_exchange": refs_exchange,
            "ts": _utc_now(),
            "case_id": self.case_id,
            "technique": technique,
            "grade": grade,
            "verdict": verdict,
            "confidence": confidence,
            "severity": severity,
            "supporting_grains": supporting_grains or [],
            "mitigations": mitigations or [],
            "rationale": rationale,
            "policy": policy,
        }
        with _lock:
            if self.case_path:
                _append(self.case_path, payload)
            _append(self.master_path, payload)
        return vid


def verify_chain(path: str) -> tuple[bool, str]:
    """
    Verify a JSONL evidence chain: sequential `seq` and correct `prev_hash`
    linkage. Returns (ok, message). This is the tamper-evidence check.
    """
    if not os.path.isfile(path):
        return False, f"no such log: {path}"
    prev_hash = _GENESIS
    expected_seq = 1
    n = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except json.JSONDecodeError:
                return False, f"line {lineno}: invalid JSON"
            if int(rec.get("seq", -1)) != expected_seq:
                return False, f"line {lineno}: seq {rec.get('seq')} != expected {expected_seq}"
            if rec.get("prev_hash") != prev_hash:
                return False, f"line {lineno}: prev_hash mismatch (chain broken)"
            prev_hash = _hash(_canonical(rec))
            expected_seq += 1
            n += 1
    return True, f"ok: {n} record(s), chain intact"
