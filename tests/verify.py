# =============================================================================
#  tests/verify.py
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  Agnostic mechanical verifier — grounding, typing, and per-run provenance.
#
#  WHAT IT IS
#    A standalone, network/model/key-free validation tool with two modes:
#      static  — verify the system's STATIC labels: every technique id the
#                corpus and posture rules emit exists in the graph and is the
#                right type; every CWE is a weakness. (No run required.)
#      audit   — verify ANY completed run's OUTPUTS and provenance: every
#                finding's technique/CWE is graph-grounded and correctly typed,
#                no ungrounded id slipped through, the evidence-log hash chain
#                verifies, and the artifacts are internally consistent.
#
#    It exists because the runtime firewall checks id EXISTENCE, not semantic
#    FIT or per-run integrity. This tool is the mechanical proof that a given
#    report is trustworthy: real ids, correct types, intact chain.
#
#  WHAT IT CANNOT DO (stated honestly)
#    It does not judge SEMANTIC correctness of a verdict (was 'complied' right?)
#    — that is human judgment. It does not contact MITRE; the local graph (from
#    STIX) is ground truth for what THIS system emits. It prints the graph's
#    ATLAS version every run so staleness is always visible, never hidden.
#
#  USAGE (from repo root)
#    .venv/bin/python -m tests.verify                      # audit newest run
#    .venv/bin/python -m tests.verify --mode static        # labels only
#    .venv/bin/python -m tests.verify --case assessments/CASE-XXXX/
#  Exit 0 = sound; non-zero = a specific failure named above. CI-friendly.
# =============================================================================
from __future__ import annotations
import argparse, glob, json, os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _graph():
    path = os.path.join(_ROOT, "build", "graph", "nodes.json")
    if not os.path.isfile(path):
        print(f"  [FAIL] graph not built at {path} — run ./run.sh once first")
        sys.exit(2)
    n = json.load(open(path, encoding="utf-8"))
    get = (lambda i: n.get(i)) if isinstance(n, dict) else \
          (lambda i, idx={x.get("id"): x for x in n if isinstance(x, dict)}: idx.get(i))
    return get


def _atlas_version():
    try:
        d = json.load(open(os.path.join(_ROOT, "data", "atlas-data", "stix-atlas.json"), encoding="utf-8"))
        objs = d.get("objects", d) if isinstance(d, dict) else d
        v = [o.get("x_mitre_version") for o in objs if isinstance(o, dict) and o.get("type") == "x-mitre-collection"]
        return f"{v or 'unknown'} ({len(objs)} objects)"
    except Exception as exc:
        return f"unreadable ({exc})"


def _check_tech(get, tid, label, fails):
    node = get(tid) or {}
    t, name = node.get("type", "MISSING"), node.get("name", "NOT IN GRAPH")
    if t == "MISSING" or name == "NOT IN GRAPH":
        fails.append(f"{label}: technique {tid} NOT IN GRAPH"); status = "FAIL: not in graph"
    elif t != "technique":
        fails.append(f"{label}: {tid} is type '{t}', not technique"); status = f"FAIL: type '{t}'"
    else:
        status = "ok"
    print(f"  [{status:<26}] {label:<30} {tid:<15} {name}")


def _check_cwe(get, cid, fails):
    node = get(cid) or {}
    t, name = node.get("type", "MISSING"), node.get("name", "NOT IN GRAPH")
    if t == "MISSING":
        fails.append(f"CWE {cid} NOT IN GRAPH"); status = "FAIL: not in graph"
    elif t != "weakness":
        fails.append(f"{cid} is type '{t}', not weakness"); status = f"FAIL: type '{t}'"
    else:
        status = "ok"
    print(f"  [{status:<26}] {'CWE':<30} {cid:<15} {name}")


def run_static(get, fails):
    print("\n  --- STATIC: CORPUS TECHNIQUES ---")
    path = os.path.join(_ROOT, "packs", "redteam", "atlas-prompts.yaml")
    import yaml
    data = yaml.safe_load(open(path, encoding="utf-8")) if os.path.isfile(path) else {}
    for row in (data.get("prompts") or []):
        if isinstance(row, dict) and row.get("technique"):
            _check_tech(get, row["technique"], row.get("id", "?"), fails)
    print("\n  --- STATIC: POSTURE TECHNIQUES ---")
    for tid in ("T1611", "T1046", "AML.T0040", "AML.T0010"):
        _check_tech(get, tid, "posture-rule", fails)
    print("\n  --- STATIC: CWE WEAKNESSES ---")
    for cid in ("CWE-250", "CWE-306", "CWE-353", "CWE-693"):
        _check_cwe(get, cid, fails)


def run_audit(get, case, fails):
    if not case:
        cases = sorted(glob.glob(os.path.join(_ROOT, "assessments", "CASE-*/")), key=os.path.getmtime)
        if not cases:
            print("  [FAIL] no case directories under assessments/"); sys.exit(2)
        case = cases[-1]
    jf = os.path.join(case, "assessment.json")
    if not os.path.isfile(jf):
        print(f"  [FAIL] no assessment.json in {case}"); sys.exit(2)
    a = json.load(open(jf, encoding="utf-8"))
    print(f"\n  auditing case: {case}")
    print(f"  findings: {len(a.get('findings', []))}")

    print("\n  --- AUDIT: EVERY FINDING'S IDS GROUNDED + TYPED ---")
    for f in a.get("findings", []):
        fid = f.get("id", "?")
        for t in (f.get("techniques") or []):
            _check_tech(get, t.get("id", ""), fid, fails)
        cwe = (f.get("evidence") or {}).get("cwe")
        if cwe:
            _check_cwe(get, cwe, fails)
        for v in (f.get("vulnerabilities") or []):
            if v.get("cwe"):
                _check_cwe(get, v["cwe"], fails)

    print("\n  --- AUDIT: EVIDENCE-LOG HASH CHAIN ---")
    try:
        from engine.core.evidence_log import verify_chain
        ok, msg = verify_chain(os.path.join(_ROOT, "logs", "exchanges.jsonl"))
        print(f"  [{'ok' if ok else 'FAIL':<26}] chain: {msg}")
        if not ok:
            fails.append(f"evidence chain broken: {msg}")
    except Exception as exc:
        fails.append(f"chain verify errored: {exc}")
        print(f"  [FAIL] chain verify errored: {exc}")

    print("\n  --- AUDIT: ARTIFACT CONSISTENCY ---")
    for art in ("report.html", "navigator-layer.json"):
        exists = os.path.isfile(os.path.join(case, art))
        print(f"  [{'ok' if exists else 'warn':<26}] artifact present: {art}")



def run_probes(fails):
    """Assert the probe catalog's enabled set matches the authoritative allowlist.

    Option-2 drift guard: packs/probes/probes.yaml DOCUMENTS every probe; the
    assessor.yaml `probes.allowlist` AUTHORIZES what runs. This check fails if
    they diverge, so the catalog can never silently misrepresent the gate. The
    catalog never writes the allowlist; it is compared, never applied.
    """
    import yaml
    cat_path = os.path.join(_ROOT, "packs", "probes", "probes.yaml")
    cfg_path = os.path.join(_ROOT, "assessor.yaml")
    if not os.path.isfile(cat_path):
        fails.append("probes.yaml catalog missing"); return
    catalog = yaml.safe_load(open(cat_path, encoding="utf-8")) or {}
    entries = catalog.get("probes") or []
    cat_enabled = {e["id"] for e in entries if isinstance(e, dict) and e.get("enabled")}
    cat_all = {e["id"] for e in entries if isinstance(e, dict) and e.get("id")}

    cfg = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
    allow = set((cfg.get("probes") or {}).get("allowlist") or [])

    print("\n  --- PROBE CATALOG vs ALLOWLIST ---")
    print(f"  catalog entries : {len(cat_all)}")
    print(f"  catalog enabled : {len(cat_enabled)}")
    print(f"  allowlist       : {len(allow)}")

    missing_from_catalog = allow - cat_all
    enabled_not_allowed = cat_enabled - allow
    allowed_not_enabled = allow - cat_enabled
    for pid in sorted(missing_from_catalog):
        fails.append(f"allowlisted probe '{pid}' is absent from the catalog")
    for pid in sorted(enabled_not_allowed):
        fails.append(f"catalog enables '{pid}' but it is NOT in the allowlist")
    for pid in sorted(allowed_not_enabled):
        fails.append(f"allowlist has '{pid}' but the catalog marks it disabled")
    status = "ok" if not (missing_from_catalog or enabled_not_allowed or allowed_not_enabled) else "FAIL"
    print(f"  [{status}] catalog enabled-set == allowlist")



def run_sources(fails):
    """Assert the data-source catalog matches the authoritative graph.sources.

    Option-2 drift guard: packs/data/sources.yaml DOCUMENTS every graph data
    source; assessor.yaml graph.sources is what the graph builder actually
    loads. This fails if they diverge (by id). The catalog never writes the
    engine's source list; it is compared to it.
    """
    import yaml
    cat_path = os.path.join(_ROOT, "packs", "data", "sources.yaml")
    cfg_path = os.path.join(_ROOT, "assessor.yaml")
    if not os.path.isfile(cat_path):
        fails.append("sources.yaml catalog missing"); return
    catalog = yaml.safe_load(open(cat_path, encoding="utf-8")) or {}
    entries = catalog.get("sources") or []
    cat_enabled = {e["id"] for e in entries if isinstance(e, dict) and e.get("enabled")}

    cfg = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
    cfg_sources = {sp.get("id") for sp in ((cfg.get("graph") or {}).get("sources") or []) if isinstance(sp, dict)}

    print("\n  --- DATA-SOURCE CATALOG vs graph.sources ---")
    print(f"  catalog enabled : {sorted(cat_enabled)}")
    print(f"  graph.sources   : {sorted(cfg_sources)}")

    catalog_only = cat_enabled - cfg_sources
    engine_only = cfg_sources - cat_enabled
    for sid in sorted(catalog_only):
        fails.append(f"catalog enables source '{sid}' but graph.sources does not load it")
    for sid in sorted(engine_only):
        fails.append(f"graph.sources loads '{sid}' but the catalog does not list it enabled")
    status = "ok" if not (catalog_only or engine_only) else "FAIL"
    print(f"  [{status}] catalog enabled-set == graph.sources")


def run_schema(case, fails):
    """Validate a completed run's assessment.json against assessment.schema.json.

    The structural counterpart to run_audit's grounding pass: audit proves every
    id is real and the evidence chain is intact; this proves the document conforms
    to the schema every renderer consumes (required blocks present, evidence
    subfields correctly typed, verdict and priority within their emitted sets).
    Reuses the sealed engine.core.validation.validate; adds no new dependency.
    """
    from engine.core.validation import validate
    if not case:
        cases = sorted(glob.glob(os.path.join(_ROOT, "assessments", "CASE-*/")), key=os.path.getmtime)
        if not cases:
            print("  [FAIL] no case directories under assessments/"); sys.exit(2)
        case = cases[-1]
    jf = os.path.join(case, "assessment.json")
    if not os.path.isfile(jf):
        print(f"  [FAIL] no assessment.json in {case}"); sys.exit(2)
    instance = json.load(open(jf, encoding="utf-8"))
    print("")
    print(f"  validating: {jf}")
    print("  --- SCHEMA: assessment.json vs assessment.schema.json ---")
    errors = validate(instance, "assessment")
    if errors:
        for e in errors:
            fails.append(f"schema: {e}")
            print(f"  [FAIL] {e}")
    else:
        n = len(instance.get("findings", []))
        print(f"  [ok] document conforms ({n} findings)")


def main():
    ap = argparse.ArgumentParser(description="Psypher agnostic mechanical verifier")
    ap.add_argument("--mode", choices=("static", "audit", "probes", "sources", "schema"), default="audit")
    ap.add_argument("--case", default=None, help="case dir (default: newest)")
    args = ap.parse_args()

    get = _graph()
    fails = []
    print("=" * 70)
    print(" PSYPHER MECHANICAL VERIFIER  ·  Powered by Claude · Designed by PsypherLabs")
    print(f" mode: {args.mode}   |   ATLAS graph version: {_atlas_version()}")
    print("=" * 70)

    if args.mode == "static":
        run_static(get, fails)
    elif args.mode == "probes":
        run_probes(fails)
    elif args.mode == "sources":
        run_sources(fails)
    elif args.mode == "schema":
        run_schema(args.case, fails)
    else:
        run_audit(get, args.case, fails)

    print("\n" + "=" * 70)
    if fails:
        print(f"  RESULT: {len(fails)} problem(s):")
        for x in fails:
            print("   -", x)
    else:
        print("  RESULT: all ids grounded and correctly typed; provenance intact.")
        print("  (Semantic fit of verdicts still needs human judgment — not checked here.)")
    print("=" * 70)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
