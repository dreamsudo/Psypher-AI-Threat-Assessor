# =============================================================================
#  tests/verify_labels.py
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  Label-grounding verifier.
#
#  WHAT IT IS
#    A standalone validation tool that checks every framework identifier the
#    corpus and posture rules emit against the knowledge graph's own node data
#    (built from official ATLAS/ATT&CK/CVE/CWE STIX). It exists because the
#    runtime firewall checks id EXISTENCE, not semantic FIT — a wrong-but-real id
#    (e.g. tagging a discovery attack as AML.T0055 "Unsecured Credentials")
#    passes the firewall silently. This tool surfaces exactly that class of bug.
#
#  WHAT IT CHECKS
#    1. Every technique id used by the red-team corpus exists in the graph AND is
#       type "technique" (not a weakness/tactic), and prints its official name so
#       a human can eyeball semantic fit.
#    2. Every technique id hardcoded in the posture phase's rules likewise.
#    3. Every CWE referenced is type "weakness" (never usable as a technique
#       anchor) and every technique is never a CWE — the two must not cross.
#    4. The local ATLAS STIX bundle version, so staleness is visible.
#
#  WHAT IT DOES NOT DO
#    It does not contact MITRE or the internet. The graph (from official STIX) is
#    the ground truth for what THIS system emits. It reports; it changes nothing.
#
#  USAGE
#    .venv/bin/python -m tests.verify_labels        (from the repo root)
#  Exit code 0 = all ids exist and are correctly typed; non-zero = a problem to
#  review. Semantic fit still needs a human read of the printed names.
# =============================================================================
from __future__ import annotations
import json, os, sys, glob

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

def _load_graph_nodes():
    path = os.path.join(_ROOT, "build", "graph", "nodes.json")
    if not os.path.isfile(path):
        print(f"  [FAIL] graph not built at {path} — run ./run.sh once first")
        sys.exit(2)
    n = json.load(open(path, encoding="utf-8"))
    if isinstance(n, dict):
        return {k: v for k, v in n.items()}, (lambda i: n.get(i))
    idx = {x.get("id"): x for x in n if isinstance(x, dict)}
    return idx, (lambda i: idx.get(i))

def _corpus_ids():
    """Read the ATLAS red-team corpus. The file uses a top-level `prompts:` list;
    each entry carries `id` and `technique`. Skips the .bak sibling."""
    ids = {}
    path = os.path.join(_ROOT, "packs", "redteam", "atlas-prompts.yaml")
    if not os.path.isfile(path):
        print(f"  [warn] corpus not found at {path}")
        return ids
    try:
        import yaml
        data = yaml.safe_load(open(path, encoding="utf-8")) or {}
    except Exception as exc:
        print(f"  [warn] could not parse corpus: {exc}")
        return ids
    for row in (data.get("prompts") or []):
        if isinstance(row, dict) and row.get("technique"):
            ids[row.get("id", "?")] = row["technique"]
    return ids

# Technique + CWE ids hardcoded in the posture phase (kept in sync by hand — if
# you add a posture rule, add its ids here so the verifier covers them).
_POSTURE_TECH = ["T1611", "T1046", "AML.T0040", "AML.T0010"]
_POSTURE_CWE  = ["CWE-250", "CWE-306", "CWE-353", "CWE-693"]

def main():
    nodes, get = _load_graph_nodes()
    problems = 0

    print("=" * 66)
    print(" PSYPHER LABEL VERIFIER  ·  ids checked against the graph's STIX data")
    print("=" * 66)

    # -- ATLAS STIX version (staleness visibility) --
    try:
        d = json.load(open(os.path.join(_ROOT, "data", "atlas-data", "stix-atlas.json"), encoding="utf-8"))
        objs = d.get("objects", d) if isinstance(d, dict) else d
        ver = [o.get("x_mitre_version") for o in objs if isinstance(o, dict) and o.get("type") == "x-mitre-collection"]
        print(f"\n  ATLAS STIX bundle version: {ver or 'unknown'}  ({len(objs)} objects)")
    except Exception as exc:
        print(f"\n  [warn] could not read ATLAS STIX version: {exc}")

    def check_tech(label, aid, tid):
        nonlocal problems
        node = get(tid) or {}
        ntype = node.get("type", "MISSING")
        name = node.get("name", "NOT IN GRAPH")
        status = "ok"
        if ntype == "MISSING" or name == "NOT IN GRAPH":
            status, problems = "FAIL: not in graph", problems + 1
        elif ntype != "technique":
            status, problems = f"FAIL: type is '{ntype}', not technique", problems + 1
        print(f"  [{status:<28}] {label:<26} {tid:<15} {name}")

    def check_cwe(cid):
        nonlocal problems
        node = get(cid) or {}
        ntype = node.get("type", "MISSING")
        name = node.get("name", "NOT IN GRAPH")
        status = "ok"
        if ntype == "MISSING":
            status, problems = "FAIL: not in graph", problems + 1
        elif ntype != "weakness":
            status, problems = f"FAIL: type '{ntype}', not weakness", problems + 1
        print(f"  [{status:<28}] {'CWE':<26} {cid:<15} {name}")

    print("\n  --- CORPUS TECHNIQUES (attack id -> technique) ---")
    for aid, tid in sorted(_corpus_ids().items()):
        check_tech(aid, aid, tid)

    print("\n  --- POSTURE-PHASE TECHNIQUES ---")
    for tid in _POSTURE_TECH:
        check_tech("posture-rule", "-", tid)

    print("\n  --- CWE WEAKNESSES (must be type 'weakness') ---")
    for cid in _POSTURE_CWE:
        check_cwe(cid)
    print()
    print("  --- RELEVANCE ROLE-GROUP TECHNIQUES (role -> technique) ---")
    _rg_path = os.path.join(_ROOT, "packs", "relevance", "role-groups.yaml")
    _map_path = os.path.join(_ROOT, "packs", "relevance", "attack-artifact-map.json")
    _valid_iris = set()
    if os.path.isfile(_map_path):
        _m = json.load(open(_map_path, encoding="utf-8"))
        _valid_iris = set(_m.get("artifact_labels", {})) | set(_m.get("artifact_to_defenses", {}))
    if os.path.isfile(_rg_path):
        try:
            import yaml as _yaml
            _rg = _yaml.safe_load(open(_rg_path, encoding="utf-8")) or {}
        except Exception as _exc:
            print("  [warn] could not parse role-groups:", _exc); _rg = {}
        for _grp in (_rg.get("role_groups") or []):
            _nm = _grp.get("name", "?")
            for _tid in (_grp.get("techniques") or []):
                check_tech(_nm, "-", _tid)
        print()
        print("  --- RELEVANCE ROLE-GROUP D3FEND ARTIFACTS (must exist in the map) ---")
        for _grp in (_rg.get("role_groups") or []):
            _nm = _grp.get("name", "?")
            _iri = _grp.get("d3fend_artifact", "")
            _short = _iri.split("#")[-1] if _iri else "(none)"
            if _iri and _iri in _valid_iris:
                _status = "ok"
            else:
                _status, problems = "FAIL: artifact IRI not in map", problems + 1
            print("  [%-28s] %-26s %s" % (_status, _nm, _short))
    else:
        print("  [warn] no packs/relevance/role-groups.yaml; relevance grounding skipped")

    print("\n" + "=" * 66)
    if problems == 0:
        print("  RESULT: all ids exist and are correctly typed.")
        print("  Semantic fit still needs a human read of the names above.")
    else:
        print(f"  RESULT: {problems} problem(s) — review the FAIL lines above.")
    print("=" * 66)
    sys.exit(1 if problems else 0)

if __name__ == "__main__":
    main()
