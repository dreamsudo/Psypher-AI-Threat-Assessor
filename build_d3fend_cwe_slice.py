#!/usr/bin/env python3
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs
#  build_d3fend_cwe_slice.py — Fly 1 of build 2b.
#  Freeze D3FEND's inferred CWE->countermeasure mappings into a committed,
#  versioned data artifact the engine can ingest deterministically (invariant #8),
#  with a mechanical SALIENCE rank precomputed per entry so the report can lead
#  with the weakness-specific defense and demote the near-universal boilerplate.
#
#  Output: data/d3fend/cwe-countermeasures.json
#      { "meta": {...D3FEND version + hash + counts...},
#        "cwe": { "CWE-79": [ {"id","label","tactic","salience"}, ...ranked... ], ... } }
#
#  Salience is deterministic: a technique that defends almost every CWE (e.g.
#  Software Update) is near-universal -> LOW salience; a technique tied to few
#  weaknesses (e.g. Null Pointer Checking) is weakness-specific -> HIGH salience.
#  No judgement, no hand-mapping: the rank is a pure function of the D3FEND data.
#
#  Source: D3FEND public REST API (alpha) — used ONCE here to build the frozen
#  artifact; the engine never calls it. Run on the box (needs network):
#      .venv/bin/python build_d3fend_cwe_slice.py
#  Options:
#      --refresh    ignore the on-disk response cache
#      --limit N    build only the first N CWEs (dry run / testing)
# =============================================================================
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

API = "https://d3fend.mitre.org"
GENERIC_TACTIC = "Model"                    # inventory/mapping — applies to every weakness
MARQUEE = ["CWE-79", "CWE-89", "CWE-787", "CWE-119", "CWE-352", "CWE-22",
           "CWE-125", "CWE-416", "CWE-78", "CWE-476", "CWE-120", "CWE-20"]

G = "\033[38;2;57;255;20m"
R = "\033[38;2;255;45;149m"
Z = "\033[0m"


def say(s): print(f"{G}{s}{Z}")
def warn(s): print(f"{R}{s}{Z}", file=sys.stderr)


def find_root() -> Path:
    for base in (Path.cwd(), Path(__file__).resolve().parent):
        for d in [base, *base.parents]:
            if (d / "engine").is_dir() and (d / "data").is_dir():
                return d
    return Path.cwd()


def api_get(path: str, cache_dir: Path, refresh: bool):
    """GET {API}{path} as JSON, cached on disk. Returns obj or None."""
    import re
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.strip("/")) + ".json"
    cf = cache_dir / safe
    if cf.is_file() and not refresh:
        try:
            return json.loads(cf.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    url = API + path
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "psypher-slice/1.0",
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    cf.parent.mkdir(parents=True, exist_ok=True)
    cf.write_text(raw, encoding="utf-8")
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return None


def all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from all_strings(v)


def cwes_in(obj):
    import re
    out = set()
    for s in all_strings(obj):
        out.update(re.findall(r"CWE-\d+", s))
    return out


def parse_cms(obj):
    """From /api/weakness/cwe/{id}.json (weak_to_def bindings) -> dict
    {tech_label: (tactic, tech_id_fragment)}, EXCLUDING the generic Model tactic."""
    out = {}
    blk = obj.get("weak_to_def") if isinstance(obj, dict) else None
    if not isinstance(blk, dict):
        return out
    for b in (blk.get("results", {}) or {}).get("bindings", []) or []:
        lab = (b.get("def_tech_label") or {}).get("value")
        if not lab:
            continue
        tac = (b.get("def_tactic_label") or {}).get("value", "")
        if not tac or tac == GENERIC_TACTIC:
            continue
        uri = (b.get("def_tech") or {}).get("value", "")
        frag = uri.rsplit("#", 1)[-1] if "#" in uri else uri.rsplit("/", 1)[-1] or lab
        out[lab] = (tac, frag)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the pinned D3FEND CWE->countermeasure slice.")
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    root = find_root()
    cache = root / "build" / "measure" / "d3fend"          # reuse the measurement cache
    cache.mkdir(parents=True, exist_ok=True)
    say(f"== Build D3FEND CWE->countermeasure slice ==  repo: {root}")

    ver = api_get("/api/version.json", cache, args.refresh) or {}
    d3f_version = ver.get("version") or ver.get("ontology_version") or "unknown"
    d3f_hash = ver.get("ontology_hash_sha256", "")
    print(f"  D3FEND version {d3f_version}  hash {d3f_hash[:16]}")

    known = api_get("/api/weakness/all.json", cache, args.refresh)
    if not known:
        warn("  /api/weakness/all.json unavailable — cannot build. Check network.")
        return 2
    cwe_ids = sorted(cwes_in(known), key=lambda c: int(c.split("-")[1]))
    if args.limit:
        cwe_ids = cwe_ids[:args.limit]
    print(f"  CWEs to build: {len(cwe_ids)}")

    # ---- pass 1: fetch every CWE's actionable countermeasures ----------------
    say("-- pass 1: fetch per-CWE countermeasures --")
    raw_map = {}          # cwe -> {label: (tactic, frag)}
    freq = Counter()      # label -> number of CWEs it defends (for salience)
    fetched = fresh = 0
    for cw in cwe_ids:
        cf = cache / ("api_weakness_cwe_" + cw + ".json.json")
        was_cached = cf.is_file() and not args.refresh
        obj = api_get(f"/api/weakness/cwe/{cw}.json", cache, args.refresh)
        fetched += 1
        if not was_cached:
            fresh += 1
            time.sleep(0.12)
        if obj is None:
            continue
        cms = parse_cms(obj)
        if cms:
            raw_map[cw] = cms
            for lab in cms:
                freq[lab] += 1
        if fetched % 50 == 0:
            print(f"    {fetched}/{len(cwe_ids)} (fresh fetches: {fresh})")

    n_cwe = max(len(raw_map), 1)
    print(f"  CWEs with >=1 actionable countermeasure: {len(raw_map)}")

    # ---- salience: rarer-across-CWEs => more weakness-specific => higher rank -
    def salience(label):
        return round(1.0 - (freq[label] / n_cwe), 4)

    # ---- pass 2: rank each CWE's countermeasures + assemble the slice ---------
    say("-- pass 2: rank by salience + write slice --")
    slice_cwe = {}
    for cw, cms in raw_map.items():
        entries = [{"id": frag, "label": lab, "tactic": tac, "salience": salience(lab)}
                   for lab, (tac, frag) in cms.items()]
        entries.sort(key=lambda e: (-e["salience"], e["label"]))
        slice_cwe[cw] = entries

    out = {
        "meta": {
            "source": "MITRE D3FEND REST API (inferred CWE->countermeasure)",
            "d3fend_version": d3f_version,
            "d3fend_ontology_hash_sha256": d3f_hash,
            "built": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cwe_count": len(slice_cwe),
            "generic_tactic_excluded": GENERIC_TACTIC,
            "note": "salience = 1 - (CWEs a technique defends / total CWEs); "
                    "higher = more weakness-specific. Entries pre-ranked salience desc.",
        },
        "cwe": slice_cwe,
    }
    dest = root / "data" / "d3fend" / "cwe-countermeasures.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"  wrote {dest}  ({len(slice_cwe)} CWEs)")

    # ---- self-verify ---------------------------------------------------------
    say("-- self-verify --")
    problems = []
    if len(slice_cwe) < 100:
        problems.append(f"only {len(slice_cwe)} CWEs carried countermeasures — expected hundreds")
    missing = [c for c in MARQUEE if c not in slice_cwe]
    if missing:
        problems.append(f"marquee CWEs missing from slice: {missing}")

    # near-universal techniques should have LOW salience; specific ones HIGH
    universal = sorted(freq, key=lambda l: -freq[l])[:3]
    rarest = sorted((l for l in freq if freq[l] >= 1), key=lambda l: freq[l])[:5]
    print(f"  most universal (low salience): {[(l, freq[l], salience(l)) for l in universal]}")
    print(f"  most specific  (high salience): {[(l, freq[l], salience(l)) for l in rarest]}")

    # structural rank sanity on a memory CWE: its specific tech should outrank a universal one
    def top_labels(cw, k=3):
        return [e["label"] for e in slice_cwe.get(cw, [])[:k]]
    for cw, want in (("CWE-476", "Null Pointer Checking"), ("CWE-119", "Memory Block Start Validation")):
        if cw in slice_cwe:
            labels = [e["label"] for e in slice_cwe[cw]]
            if want in labels:
                rank = labels.index(want)
                soft = "OK" if rank < len(labels) // 2 else "present but low"
                print(f"  {cw}: '{want}' rank {rank+1}/{len(labels)} — {soft}; top3 {top_labels(cw)}")
            else:
                print(f"  {cw}: note — '{want}' not present (D3FEND labels may have shifted)")

    if problems:
        warn("SELF-VERIFY FAILED:")
        for p in problems:
            warn("  - " + p)
        warn("  slice written but flagged — inspect before wiring Fly 2.")
        return 3
    say("SLICE OK — pinned + ranked. Editing data/ auto-invalidates the graph cache;")
    say("the next run rebuilds. Fly 2 wires the engine to read this file.")
    print(f"  commit it:  git add {dest.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
