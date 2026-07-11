# Psypher AI Threat Assessor · (c) 2026 PsypherLabs · All rights reserved.
# packs/probes/model-artifact/model_artifact.py — model-artifact safety probe.
"""Static, load-free safety scan of served model artifacts (script probe, active_safe).
Same contract as embedding_probe/redteam_probe: run(target, context) -> dict, one grain
per key (parse: {from: return_value}). Reads the colocated model files (engine and target
are one host in a localhost engagement), triages format by MAGIC BYTES (not extension),
and for pickle-derived formats disassembles the opcode stream with stdlib pickletools
(NEVER loads it — loading the pickle is the RCE) against a dangerous-globals denylist.
posture(37) turns a 'dangerous' verdict into a grounded AML.T0010.003 finding. Model
paths: $PSYPHER_MODEL_PATHS (colon-sep) else a bounded walk of well-known stores."""
from __future__ import annotations
import io, os, struct, zipfile, pickletools
from typing import Any

_UNSAFE_MODULES = {"os","nt","posix","subprocess","sys","socket","shutil","pty","commands",
    "asyncio","multiprocessing","importlib","pkgutil","runpy","ctypes","webbrowser",
    "builtins","__builtin__","operator"}
_UNSAFE_CALLABLES = {"system","popen","spawn","spawnv","call","check_call","check_output",
    "run","Popen","eval","exec","compile","getattr","apply","open","breakpoint",
    "__import__","import_module","resolve_name","connect"}
_PICKLE_EXT = {".pkl",".pickle",".pt",".pth",".bin",".ckpt",".model",".npy",".npz",".joblib",".dat"}
_HEAD, _MAX = 262144, 200
_ROOTS = ("~/.ollama/models/blobs","~/.cache/huggingface/hub","/var/lib/ollama/models/blobs","/models","/data/models")

def _sniff(head: bytes, ext: str) -> str:
    if head[:4] == b"GGUF": return "gguf"
    if head[:4] == b"PK\x03\x04": return "zip"
    if head[:1] == b"\x80": return "pickle"
    if head[:6] == b"\x93NUMPY": return "npy"
    if len(head) >= 9 and head[8:9] == b"{":
        try:
            if 0 < struct.unpack("<Q", head[:8])[0] < (1 << 32): return "safetensors"
        except Exception: pass
    if ext == ".onnx": return "onnx"
    if head[:1] in (b"(", b"c", b"]", b"}"): return "pickle"
    return "unknown"

def _dangerous_refs(raw: bytes):
    refs, recent, malformed = [], [], False
    def flag(mod, name):
        mod, name = str(mod).strip(), str(name).strip()
        if mod in _UNSAFE_MODULES or name in _UNSAFE_CALLABLES:
            refs.append(f"{mod}.{name}" if mod else name)
    try:
        for op, arg, _ in pickletools.genops(io.BytesIO(raw)):
            if op.name == "GLOBAL":
                p = str(arg or "").split()
                if len(p) >= 2: flag(p[0], p[-1])
            elif op.name == "STACK_GLOBAL":
                if len(recent) >= 2: flag(recent[-2], recent[-1])
            elif op.name in ("SHORT_BINUNICODE","BINUNICODE","SHORT_BINSTRING","BINSTRING","UNICODE","STRING"):
                recent.append(str(arg or "")); recent[:] = recent[-8:]
    except Exception:
        malformed = True
    return sorted(set(refs)), malformed

def _streams(path: str, fmt: str):
    out = []
    try:
        if fmt == "zip":
            with zipfile.ZipFile(path) as z:
                for i in z.infolist():
                    n = i.filename.lower()
                    if (n.endswith((".pkl",".pickle")) or n.endswith("data.pkl")) and i.file_size <= 8*1024*1024:
                        out.append(z.read(i))
        else:
            with open(path, "rb") as f: out.append(f.read(8*1024*1024))
    except Exception: pass
    return out

def scan_artifact(path: str) -> dict:
    try:
        with open(path, "rb") as f: head = f.read(_HEAD)
    except OSError: return {}
    ext = os.path.splitext(path)[1].lower()
    fmt = _sniff(head, ext)
    if fmt in ("safetensors","gguf","onnx") and ext not in _PICKLE_EXT:
        return {"format": fmt, "verdict": "safe", "unsafe": []}
    if fmt not in ("pickle","zip","npy") and ext not in _PICKLE_EXT:
        return {"format": fmt or "unknown", "verdict": "safe", "unsafe": []}
    unsafe, malformed = [], False
    for raw in _streams(path, "zip" if fmt == "zip" else "raw"):
        r, m = _dangerous_refs(raw); unsafe += r; malformed = malformed or m
    unsafe = sorted(set(unsafe))
    if unsafe or malformed:
        return {"format": fmt or "pickle", "verdict": "dangerous", "unsafe": unsafe or ["<unparseable-opcode-stream>"]}
    return {"format": fmt or "pickle", "verdict": "executable_format", "unsafe": []}

def _candidates():
    env = os.environ.get("PSYPHER_MODEL_PATHS", "")
    if env.strip():
        return [p for p in env.split(":") if p.strip()][:_MAX]
    out = []
    for root in _ROOTS:
        root = os.path.expanduser(root)
        if os.path.isdir(root):
            for dp, _dn, fn in os.walk(root):
                out += [os.path.join(dp, n) for n in fn]
                if len(out) >= _MAX: return out[:_MAX]
    return out[:_MAX]

def run(target: dict, context: dict) -> dict:
    rank = {"safe": 0, "executable_format": 1, "dangerous": 2}
    worst, wfmt, wunsafe, wpath, scanned = "safe", "", [], "", 0
    for p in _candidates():
        res = scan_artifact(p)
        if not res: continue
        scanned += 1
        if rank[res["verdict"]] >= rank[worst]:
            worst, wfmt, wunsafe = res["verdict"], res["format"], res["unsafe"]
            if worst != "safe": wpath = os.path.basename(p)
    out = {"model_serialization_scanned": str(scanned)}
    if scanned:
        out.update({"model_serialization_format": wfmt, "model_serialization_verdict": worst,
                    "model_serialization_unsafe": ",".join(wunsafe), "model_serialization_path": wpath})
    return out
