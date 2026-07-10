#!/usr/bin/env python3
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  data/d3fend_extract.py — extract the D3FEND attack->artifact->defense slices.
#  Standalone acquisition tool (Defense Anchor). No engine imports.
# =============================================================================
"""Extract two grounded slices from the D3FEND full-mappings SPARQL export into
packs/relevance/attack-artifact-map.json, so the engine can later name a MITRE
D3FEND countermeasure for a finding WITHOUT carrying the 44 MB source.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data/d3fend/d3fend-full-mappings.json"
OUT = ROOT / "packs/relevance/attack-artifact-map.json"


def _v(row: dict, key: str) -> str:
    cell = row.get(key)
    return cell.get("value", "") if isinstance(cell, dict) else ""


def main() -> int:
    if not SRC.is_file():
        print("no D3FEND mapping at", SRC, "(44 MB source lives on the box only)")
        return 1
    doc = json.load(open(SRC, encoding="utf-8"))
    rows = doc.get("results", {}).get("bindings", [])
    if not rows:
        print("no results.bindings in", SRC)
        return 1

    attack_to_artifacts: dict[str, set] = defaultdict(set)
    artifact_to_defenses: dict[str, set] = defaultdict(set)
    artifact_labels: dict[str, str] = {}
    all_off_artifacts: set[str] = set()
    all_def_tech: set[str] = set()

    for r in rows:
        tid = _v(r, "off_tech_id").strip()
        off_art = _v(r, "off_artifact").strip()
        off_art_label = _v(r, "off_artifact_label").strip()
        def_tech = _v(r, "def_tech").strip()
        def_tech_label = _v(r, "def_tech_label").strip()
        def_tactic = _v(r, "def_tactic").strip()
        def_tactic_label = _v(r, "def_tactic_label").strip()

        if tid and off_art:
            attack_to_artifacts[tid].add(off_art)
            parent = tid.split(".")[0]
            if parent != tid:
                attack_to_artifacts[parent].add(off_art)
        if off_art:
            all_off_artifacts.add(off_art)
            if off_art_label:
                artifact_labels[off_art] = off_art_label
            if def_tech:
                all_def_tech.add(def_tech)
                artifact_to_defenses[off_art].add(
                    (def_tech, def_tech_label, def_tactic, def_tactic_label))

    a2a = {k: sorted(v) for k, v in sorted(attack_to_artifacts.items())}
    a2d = {
        k: [dict(zip(("def_tech", "def_tech_label", "def_tactic", "def_tactic_label"), t))
            for t in sorted(v)]
        for k, v in sorted(artifact_to_defenses.items())
    }
    labels = dict(sorted(artifact_labels.items()))

    subs = sum(1 for k in a2a if "." in k)
    parents = sum(1 for k in a2a if "." not in k)
    out = {
        "meta": {
            "source": SRC.name,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "rows": len(rows),
            "attack_keys_total": len(a2a),
            "attack_keys_subtech": subs,
            "attack_keys_parent_or_top": parents,
            "distinct_off_artifacts": len(all_off_artifacts),
            "artifact_keys_with_defenses": len(a2d),
            "distinct_def_tech": len(all_def_tech),
            "note": "ATT&CK-only; no ATLAS/CWE. artifact_to_defenses is for the future defense phase.",
        },
        "attack_to_artifacts": a2a,
        "artifact_to_defenses": a2d,
        "artifact_labels": labels,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print("--- D3FEND extract ---")
    print("rows read                 :", len(rows))
    print("attack keys (total)       :", len(a2a), "(%d sub / %d parent-or-top)" % (subs, parents))
    print("distinct off artifacts    :", len(all_off_artifacts))
    print("artifacts with a defense  :", len(a2d))
    print("distinct def techniques   :", len(all_def_tech))
    probe = "T1550.001"
    arts = a2a.get(probe, [])
    print("spot-check %-11s ->" % probe, arts[:2] or "(none)")
    if arts:
        defs = a2d.get(arts[0], [])
        print("   %s ->" % labels.get(arts[0], arts[0]),
              [(d["def_tech_label"], d["def_tactic_label"]) for d in defs][:3] or "(none)")
    print("parent-rollup %-8s ->" % "T1550", (a2a.get("T1550", []) or "(none)")[:3])
    print("wrote", OUT, "(%d bytes)" % OUT.stat().st_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
