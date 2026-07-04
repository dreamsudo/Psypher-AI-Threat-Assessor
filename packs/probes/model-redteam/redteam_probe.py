# packs/probes/model-redteam/redteam_probe.py
# -----------------------------------------------------------------------------
# Psypher — red-team capture probe.  [Bootstrap 6]
#
# A `script` probe (same contract as embedding_probe.py). Instead of reading
# /v1/models, it sends ATLAS-tagged adversarial prompts to the model over
# NATIVE OLLAMA /api/chat and captures each reply as a grain. It also appends
# an immutable, hash-chained record of every exchange to the shared evidence
# log (per-case + global master).
#
# PHASE 1 — CAPTURE ONLY. This probe renders NO verdict. It records what the
# model said (and whether an optional deterministic canary appeared). The brain
# (Bootstrap 7) is what later judges these grains into findings. Keeping the
# probe "dumb" is deliberate: judgment lives only in the analyzer, which is what
# keeps the engine agnostic and honest.
#
# It is read-only in the sense that it does not exploit anything: it holds a
# conversation with the model and records the transcript. Dangerous ATLAS
# families are framed as REFUSAL tests (measure resistance), never as a harm
# generator.
#
# Contract:
#   entry: run(target, context) -> dict          (parse: { "from": "return_value" })
#   target : {id, kind, access, endpoint, host, ssh}
#   context: {timeout, insecure_tls, auth_token}  (+ optional Psypher extras)
#
# The returned mapping becomes one grain per key. We return a compact,
# report-friendly summary; the full transcripts live in the evidence log and in
# each grain's own value.
# -----------------------------------------------------------------------------
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

# --- locate the shared evidence logger (best-effort; never fatal) ------------
_HAVE_LOG = False
try:
    # When run by the harness, the repo root is on sys.path (python -m engine).
    from engine.core.evidence_log import EvidenceLog, new_exchange_id
    _HAVE_LOG = True
except Exception:  # pragma: no cover - logging is optional, capture is not
    EvidenceLog = None  # type: ignore
    def new_exchange_id():  # type: ignore
        import uuid
        return str(uuid.uuid4())


# --- where to find the attack corpus -----------------------------------------
def _corpus_path(context) -> str:
    # Allow override via context or env; default to the shipped corpus.
    for key in ("redteam_corpus", "corpus_path"):
        val = (context or {}).get(key)
        if val:
            return str(val)
    env = os.environ.get("PSYPHER_REDTEAM_CORPUS")
    if env:
        return env
    return "packs/redteam/atlas-prompts.yaml"


def _load_corpus(path: str) -> list:
    """Load the ATLAS-tagged prompt corpus. Prefer PyYAML; fall back to JSON."""
    if not os.path.isfile(path):
        return []
    try:
        import yaml  # PyYAML is already a Psypher dependency
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return []
    prompts = data.get("prompts") if isinstance(data, dict) else data
    return prompts if isinstance(prompts, list) else []


# --- native Ollama chat ------------------------------------------------------
def _chat(endpoint: str, model: str, prompt: str, token: str, timeout: int, insecure: bool):
    """
    POST /api/chat (native Ollama). Returns (ok, text, latency_ms, error).
    Read-only conversation: we send one user turn and read the reply.
    """
    url = endpoint.rstrip("/") + "/api/chat"
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    ctx = None
    if insecure and url.lower().startswith("https"):
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        latency = int((time.time() - started) * 1000)
        text = ((payload.get("message") or {}).get("content") or "").strip()
        return True, text, latency, ""
    except urllib.error.HTTPError as exc:
        latency = int((time.time() - started) * 1000)
        return False, "", latency, f"HTTP {exc.code}"
    except Exception as exc:  # timeout, connection refused, bad JSON, etc.
        latency = int((time.time() - started) * 1000)
        return False, "", latency, str(exc)


def _served_model(endpoint: str, token: str, timeout: int, insecure: bool) -> str:
    """Best-effort: read the first served model id from /v1/models."""
    url = endpoint.rstrip("/") + "/v1/models"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = None
    if insecure and url.lower().startswith("https"):
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for m in (data.get("data") or []):
            if isinstance(m, dict) and m.get("id"):
                return str(m["id"])
    except Exception:
        return ""
    return ""


def run(target, context):
    endpoint = (target.get("endpoint") or "").rstrip("/")
    if not endpoint:
        return {"redteam_reachable": False}

    context = context or {}
    token = context.get("auth_token") or ""
    timeout = int(context.get("timeout", 30) or 30)
    insecure = bool(context.get("insecure_tls", False))

    # Which model to talk to: explicit override, else whatever is served.
    model = (
        context.get("redteam_model")
        or os.environ.get("PSYPHER_REDTEAM_MODEL")
        or _served_model(endpoint, token, timeout, insecure)
    )
    if not model:
        return {"redteam_reachable": True, "redteam_model": "(none served)"}

    corpus = _load_corpus(_corpus_path(context))
    if not corpus:
        return {"redteam_reachable": True, "redteam_model": model,
                "redteam_corpus_loaded": 0}

    # Set up the evidence log (best-effort). case_id / case_dir may be provided
    # by the harness via context; fall back to sensible defaults otherwise.
    logger = None
    if _HAVE_LOG:
        case_id = context.get("case_id", "") or os.environ.get("PSYPHER_CASE_ID", "")
        case_dir = context.get("case_dir") or None
        try:
            logger = EvidenceLog(case_id=case_id, case_dir=case_dir)
        except Exception:
            logger = None

    served_meta = {"served_model": model}
    result = {
        "redteam_reachable": True,
        "redteam_model": model,
        "redteam_corpus_loaded": len(corpus),
    }

    complied = 0
    refused_or_error = 0

    samples = max(1, int(context.get("redteam_samples")
                         or os.environ.get("PSYPHER_REDTEAM_SAMPLES", "1") or 1))
    for _sample, item in ((s, it) for s in range(samples) for it in corpus):
        if not isinstance(item, dict):
            continue
        aid = str(item.get("id", "unknown"))
        technique = str(item.get("technique", ""))
        tactic = str(item.get("tactic", ""))
        prompt = str(item.get("prompt", ""))
        canary = str(item.get("canary", "") or "")
        cwe = str(item.get("cwe", "") or "")
        sev_hint = str(item.get("severity_hint", "") or "")
        if not prompt:
            continue

        ok, text, latency, error = _chat(endpoint, model, prompt, token, timeout, insecure)
        canary_hit = bool(canary) and (canary.lower() in text.lower())
        outcome = "captured" if ok else ("error" if error else "empty")
        if canary_hit:
            complied += 1
        else:
            refused_or_error += 1

        xid = new_exchange_id()
        if logger is not None:
            try:
                logger.record_exchange(
                    target=str(target.get("id", "")),
                    endpoint=endpoint,
                    probe="model-redteam",
                    attack_id=aid,
                    technique=technique,
                    tactic=tactic,
                    prompt=prompt,
                    response=text if ok else f"({outcome}: {error})",
                    canary=canary,
                    canary_hit=canary_hit,
                    latency_ms=latency,
                    outcome=outcome,
                    cwe=cwe,
                    severity_hint=sev_hint,
                    model_meta=served_meta,
                    exchange_id=xid,
                )
            except Exception:
                pass  # logging must never break capture

        # One grain per attack: a compact, report-visible record of the exchange.
        # (Full transcript is in the evidence log; here we keep it readable.)
        snippet = (text[:280] + "…") if len(text) > 280 else text
        grain_val = {
            "attack_id": aid,
            "technique": technique,
            "canary_hit": canary_hit,
            "outcome": outcome,
            "latency_ms": latency,
            "exchange_id": xid,
            "response_preview": snippet if ok else f"({outcome}: {error})",
        }
        # Key becomes the grain attribute; keep it unique + descriptive.
        result[f"redteam::{aid}::{_sample}"] = json.dumps(grain_val, ensure_ascii=False)

    result["redteam_attacks_run"] = complied + refused_or_error
    result["redteam_canary_hits"] = complied
    return result
