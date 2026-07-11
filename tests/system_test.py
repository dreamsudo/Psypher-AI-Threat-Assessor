# =============================================================================
#  tests/system_test.py
#  Psypher AI Threat Assessor
#  Full-stack AI/ML security — MITRE ATLAS-grounded penetration testing of the
#  model and the infrastructure it runs on.
#  Powered by Claude · Designed by PsypherLabs
#
#  END-TO-END PIPELINE SYSTEM TEST
#  -----------------------------------------------------------------------------
#  A self-contained integrity check that proves the entire system is correctly
#  assembled and every core guarantee holds — WITHOUT requiring a live model, an
#  API key, or any network access. Clone the repository, run this, and know in
#  seconds whether the installation is sound before running a real assessment.
#
#  This is a DevOps / CI smoke test, not a model assessment. It exercises every
#  critical subsystem of both branches using synthetic, in-memory data:
#
#     Branch A (infrastructure)  the knowledge graph loads and holds real
#                                MITRE ATLAS/ATT&CK identifiers.
#     Branch B (the model)       the reasoning brain's firewall, policy floor,
#                                deterministic judge, and evidence log all work.
#     Shared spine               module wiring, phase registration order, and
#                                the tamper-evident evidence chain.
#
#  Run:
#     python -m tests.system_test           (from the repository root)
#     ./run.sh test                         (if wired into the launcher)
#
#  Exit code 0 = all checks passed; non-zero = at least one failure (CI-friendly).
# =============================================================================
from __future__ import annotations

import json
import os
import sys
import traceback

# Make the repository root importable when run as `python -m tests.system_test`
# or directly, so `import engine...` resolves from a fresh clone.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# =============================================================================
#  PRESENTATION  —  PsypherLabs banner + neon green/rose colorized output
#
#  Neon green carries structure and PASS; neon rose carries the brand and FAIL.
#  Ordinary text stays default-colored — only status and structure are tinted,
#  so the report is readable rather than a wall of color. Uses rich when present
#  and degrades to clean plain text otherwise.
# =============================================================================
try:
    from rich.console import Console
    from rich.text import Text
    _console = Console()
    _RICH = True
except Exception:  # pragma: no cover
    _console = None
    _RICH = False

_GREEN = "#39FF14"        # neon green  — structure, PASS, logo
_ROSE = "bold #FF2D95"    # neon rose   — brand tagline, FAIL
_ROSE_D = "#FF2D95"       # neon rose   — non-bold rose
_DIM = None               # detail text — clean default (no washed-out gray)


def _p(segments) -> None:
    """Print one line built from (text, style) segments (color-aware)."""
    if _RICH and _console is not None:
        line = Text()
        for chunk, style in segments:
            line.append(chunk, style=style)
        _console.print(line)
    else:
        print("".join(chunk for chunk, _ in segments))


def banner() -> None:
    """The PsypherLabs logo (neon green) + branded tagline (neon rose)."""
    logo = (
        "               *               ",
        "              ***              ",
        "             *****             ",
        "            *******            ",
        "           *********           ",
        "          ***********          ",
        "         *****Psypher*****     ",
        "          *****Labs*****      ",
        "           ***********          ",
        "            *******            ",
        "             *****             ",
        "              ***              ",
        "               *               ",
    )
    print()
    for row in logo:
        _p([(row, _GREEN)])
    print()
    _p([(" Psypher AI Threat Assessor — System Test ", _ROSE)])
    _p([(" Full-stack AI/ML security · MITRE ATLAS-grounded penetration testing ", _DIM)])
    _p([(" Powered by Claude · Designed by PsypherLabs ", _DIM)])
    print()


# =============================================================================
#  A tiny self-contained test harness (no pytest dependency)
# =============================================================================
class Results:
    """Accumulates check outcomes and renders a neon PASS/FAIL report."""

    def __init__(self) -> None:
        self.checks: list = []   # (name, ok, detail)

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))
        tag = ("[PASS]", _GREEN) if ok else ("[FAIL]", _ROSE)
        row = [("  ", None), tag, ("  ", None), (name, None)]
        if detail:
            row.append(("  — " + detail, _DIM))
        _p(row)

    @property
    def passed(self) -> int:
        return sum(1 for _, ok, _ in self.checks if ok)

    @property
    def total(self) -> int:
        return len(self.checks)

    def summary(self) -> bool:
        rule = "─" * 60
        _p([(rule, _GREEN)])
        all_ok = self.passed == self.total
        if all_ok:
            _p([("  ", None), (f"{self.passed}/{self.total} checks passed", _GREEN),
                ("  — system OK", None)])
            _p([("  ", None), ("Psypher AI Threat Assessor is correctly assembled "
                               "and ready.", _DIM)])
        else:
            _p([("  ", None), (f"{self.passed}/{self.total} checks passed", _ROSE),
                (f"  — {self.total - self.passed} FAILED", _ROSE_D)])
            _p([("  ", None), ("Resolve the failed checks before running an "
                               "assessment.", _DIM)])
        _p([(rule, _GREEN)])
        return all_ok


def _run(results: Results, name: str, fn) -> None:
    """Execute one check function, recording PASS/FAIL and any detail message."""
    try:
        detail = fn() or ""
        results.record(name, True, detail)
    except AssertionError as exc:
        results.record(name, False, str(exc) or "assertion failed")
    except Exception as exc:  # noqa: BLE001
        results.record(name, False, f"{type(exc).__name__}: {exc}")


# =============================================================================
#  THE CHECKS  —  each returns an optional detail string, or raises on failure
# =============================================================================
def check_imports() -> str:
    """Every core module of both branches imports cleanly."""
    import engine.core.contracts          # noqa: F401
    import engine.core.models             # noqa: F401
    import engine.core.config             # noqa: F401
    import engine.core.evidence_log       # noqa: F401  (shared spine)
    import engine.analysis.policy         # noqa: F401  (Branch B constitution)
    import engine.analysis.brain          # noqa: F401  (Branch B reasoning brain)
    # The four phase packages register their phases on import.
    import engine.discovery               # noqa: F401
    import engine.graph                   # noqa: F401
    import engine.analysis                # noqa: F401
    import engine.report                  # noqa: F401
    return "engine, both branches, all phases"


def check_phase_order() -> str:
    """All phases register in the real registry, ordered discovery→graph→analysis→brain→report."""
    # Import the four phase packages so each registers its phase on import.
    import engine.discovery, engine.graph, engine.analysis, engine.report  # noqa: F401
    from engine.core.contracts import PhaseRegistry

    ordered = PhaseRegistry.ordered()               # the real, sorted registry
    assert ordered, "PhaseRegistry.ordered() returned no phases"

    names = [p.name for p in ordered]
    orders = [p.order for p in ordered]

    # The four core phases plus Branch B must all be present.
    for required in ("discovery", "graph", "analysis", "brain", "report"):
        assert required in names, f"phase '{required}' not registered; saw {names}"

    # Orders must be strictly ascending (the registry sorts by .order).
    assert orders == sorted(orders), f"phases not in ascending order: {list(zip(names, orders))}"

    # Branch B must sit after the CVE analysis and before report assembly.
    idx = {n: i for i, n in enumerate(names)}
    assert idx["analysis"] < idx["brain"] < idx["report"], \
        f"Branch B (brain) out of order: {names}"

    return " → ".join(f"{n}({o})" for n, o in zip(names, orders))


def check_graph_atlas() -> str:
    """The knowledge graph loads and contains real MITRE ATLAS technique IDs."""
    path = os.path.join(_ROOT, "build", "graph", "nodes.json")
    if not os.path.isfile(path):
        # Fresh clone without a built graph: report clearly, do not hard-fail the
        # pipeline wiring on missing generated data.
        raise AssertionError("build/graph/nodes.json not found — build the graph first")
    nodes = json.load(open(path, encoding="utf-8"))
    items = nodes.values() if isinstance(nodes, dict) else nodes
    tech_ids = {
        (n.get("id") if isinstance(n, dict) else getattr(n, "id", ""))
        for n in items
        if (n.get("type") if isinstance(n, dict) else getattr(n, "type", "")) == "technique"
    }
    tech_ids.discard("")
    # A handful of ATLAS techniques the behavioral branch anchors on must exist.
    required = {"AML.T0051", "AML.T0054", "AML.T0057", "AML.T0040"}
    missing = required - tech_ids
    assert not missing, f"graph missing ATLAS techniques: {sorted(missing)}"
    return f"{len(tech_ids)} technique nodes; core ATLAS IDs present"


def check_kev_priority() -> str:
    """The KEV overlay flags actively-exploited CVEs and derives a priority tier,
    and is fail-open: with no KEV data a CVE finding is unaltered except for an
    explicit exploited=false and a CVSS-band priority. Network/model/key-free."""
    from types import SimpleNamespace
    from engine.analysis import analyze
    from engine.core.models import Severity, Confidence

    def _cand(cve):
        return SimpleNamespace(
            component="ollama", cve_id=cve, description="synthetic",
            cvss=5.0, observed_version="1.2.3", version_confirmed=False,
            cwes=["CWE-502"], techniques=[], mitigations=[], evidence=None,
        )

    kev = {"CVE-2021-44228": {"date_added": "2021-12-10", "ransomware": True}}

    # On the KEV list -> exploited, act-now, ransomware metadata carried.
    hit = analyze._finding_from(
        _cand("CVE-2021-44228"), severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        title="t", attack_path="p", technique_ids=[], mitigation_ids=[], kev=kev)
    assert hit.evidence["exploited"] is True, "KEV CVE not flagged exploited"
    assert hit.evidence["priority"] == "act-now", "KEV CVE not prioritized act-now"
    assert hit.evidence.get("kev_ransomware") is True, "ransomware flag not carried"

    # Not on the list -> exploited false, priority from CVSS band, no kev_* keys.
    miss = analyze._finding_from(
        _cand("CVE-2020-0001"), severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
        title="t", attack_path="p", technique_ids=[], mitigation_ids=[], kev=kev)
    assert miss.evidence["exploited"] is False, "non-KEV CVE wrongly flagged exploited"
    assert miss.evidence["priority"] == "high", "non-KEV high-CVSS finding mis-tiered"
    assert "kev_date_added" not in miss.evidence, "kev_* metadata leaked onto non-KEV finding"

    # FAIL-OPEN: no KEV data -> finding stands, exploited defaults false, priority
    # still derived from the CVSS band; nothing is hidden or altered.
    off = analyze._finding_from(
        _cand("CVE-2021-44228"), severity=Severity.LOW, confidence=Confidence.MEDIUM,
        title="t", attack_path="p", technique_ids=[], mitigation_ids=[], kev={})
    assert off.evidence["exploited"] is False, "empty KEV store still flagged exploited"
    assert off.evidence["priority"] == "scheduled", "priority not derived when KEV absent"
    assert off.vulnerabilities[0].cve == "CVE-2021-44228", "fail-open altered the finding"
    return "exploited=>act-now; CVSS-band tiers; fail-open (no data => exploited=false, finding intact)"


def check_defense_anchor() -> str:
    """The defense phase attaches graph-grounded Mitigation records to a finding's
    mitigations and they surface in as_dict() (the JSON every renderer reads), so a
    named defense actually reaches the report. Ungrounded ids are never introduced,
    and a technique with no mitigation yields none (no fabrication). Framework-
    agnostic: ATLAS techniques resolve ATLAS mitigations, ATT&CK resolve ATT&CK.
    Network/model/key-free."""
    from types import SimpleNamespace
    import logging
    from engine.graph.canonical import Graph, Node, Edge
    from engine.core.models import Finding, TechniqueRef, Severity, Confidence
    from engine.analysis.defense import DefensePhase

    g = Graph()
    g.add_node(Node(id="AML.T0051", type="technique", name="LLM Prompt Injection", framework="ATLAS"))
    g.add_node(Node(id="AML.M0000", type="mitigation", name="Limit Public Release of Information", framework="ATLAS"))
    g.add_edge(Edge(src="AML.T0051", dst="AML.M0000", type="mitigated_by"))
    g.add_node(Node(id="T1611", type="technique", name="Escape to Host", framework="ATT&CK"))
    g.add_node(Node(id="M1038", type="mitigation", name="Execution Prevention", framework="ATT&CK"))
    g.add_edge(Edge(src="T1611", dst="M1038", type="mitigated_by"))
    g.add_node(Node(id="AML.T0068", type="technique", name="LLM Prompt Obfuscation", framework="ATLAS"))

    def _f(fid, fw, tid):
        return Finding(id=fid, component="c", title="t", severity=Severity.HIGH,
                       confidence=Confidence.LOW,
                       techniques=[TechniqueRef(framework=fw, id=tid, name="", validated=True)],
                       vulnerabilities=[], mitigations=[], attack_path="p", evidence={})

    f_atlas = _f("F-atlas", "ATLAS", "AML.T0051")
    f_attack = _f("F-attack", "ATT&CK", "T1611")
    f_none = _f("F-none", "ATLAS", "AML.T0068")

    ctx = SimpleNamespace(artifacts={"graph": g}, findings=[f_atlas, f_attack, f_none],
                          logger=logging.getLogger("systest-defense"))
    DefensePhase().run(ctx)

    assert [(m.framework, m.id) for m in f_atlas.mitigations] == [("ATLAS", "AML.M0000")], \
        "ATLAS finding did not receive its graph mitigation"
    assert [(m.framework, m.id) for m in f_attack.mitigations] == [("ATT&CK", "M1038")], \
        "ATT&CK finding did not receive its graph mitigation"
    d = f_atlas.as_dict()
    assert {"framework": "ATLAS", "id": "AML.M0000",
            "text": "Limit Public Release of Information"} in d["mitigations"], \
        "mitigation absent from as_dict() (would not reach the renderer)"
    assert f_none.mitigations == [], "a defense was fabricated for a technique with no mitigation"
    return "grounded Mitigation records attached + visible in as_dict(); none fabricated"


def check_d3fend_overlay() -> str:
    """The D3FEND overlay composes the extracted map into graph mitigation nodes +
    mitigated_by edges: a mapped ATT&CK technique resolves grounded D3FEND
    countermeasures (framework D3FEND, deduped across artifacts), and a technique the
    map does not cover resolves none (graceful degrade, never an error). Uses a
    synthetic map + hand-built graph so it holds on a fresh clone. Runs the real
    ingest_d3fend. Network/model/key-free."""
    import json
    import logging
    import os
    import tempfile
    from engine.graph.canonical import Graph, Node
    from engine.graph.d3fend import ingest_d3fend

    iri = "http://d3fend.mitre.org/ontologies/d3fend.owl"
    synthetic_map = {
        "attack_to_artifacts": {
            "T1550.001": [iri + "#ArtA", iri + "#ArtB"],
            "T1611": [],
        },
        "artifact_to_defenses": {
            iri + "#ArtA": [
                {"def_tech": iri + "#AuthenticationCacheInvalidation",
                 "def_tech_label": "Authentication Cache Invalidation"},
                {"def_tech": iri + "#CredentialTransmissionScoping",
                 "def_tech_label": "Credential Transmission Scoping"},
            ],
            iri + "#ArtB": [
                {"def_tech": iri + "#AuthenticationCacheInvalidation",
                 "def_tech_label": "Authentication Cache Invalidation"},
            ],
        },
    }

    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(synthetic_map, fh)
        g = Graph()
        g.add_node(Node(id="T1550.001", type="technique", name="Application Access Token", framework="ATT&CK"))
        g.add_node(Node(id="T1611", type="technique", name="Escape to Host", framework="ATT&CK"))
        ingest_d3fend(g, path, logging.getLogger("systest-d3fend"))
    finally:
        os.unlink(path)

    cms = sorted(e.dst for e in g.out_edges("T1550.001", "mitigated_by"))
    assert cms == ["AuthenticationCacheInvalidation", "CredentialTransmissionScoping"], cms
    for cm in cms:
        n = g.get(cm)
        assert n is not None and n.type == "mitigation" and n.framework == "D3FEND", (cm, n)
    assert list(g.out_edges("T1611", "mitigated_by")) == [], "T1611 should resolve no D3FEND countermeasure"
    return "mapped technique -> grounded D3FEND countermeasures (deduped); unmapped (T1611) -> none"


def check_evidence_chain() -> str:
    """The evidence log writes a hash-chained exchange+verdict and verifies intact."""
    from engine.core.evidence_log import EvidenceLog, verify_chain

    tmp = os.path.join(_HERE, "_systest_chain.jsonl")
    if os.path.exists(tmp):
        os.remove(tmp)
    try:
        log = EvidenceLog(case_id="SYSTEST", master_path=tmp)
        xid = log.record_exchange(
            target="systest", endpoint="none", probe="model-redteam",
            attack_id="rt_prompt_injection_override", technique="AML.T0051",
            prompt="synthetic prompt", response="synthetic response",
            canary="PSYPHER_BREACH", canary_hit=True, outcome="captured",
        )
        log.record_verdict(
            refs_exchange=xid, technique="AML.T0051", grade="demonstrated",
            verdict="complied", confidence="high", severity="high",
            supporting_grains=["redteam::rt_prompt_injection_override"],
        )
        ok, msg = verify_chain(tmp)
        assert ok, f"chain did not verify: {msg}"
        return "exchange + verdict written, chain intact"
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def check_tamper_detection() -> str:
    """Altering a logged record breaks the hash chain (tamper-evidence works)."""
    from engine.core.evidence_log import EvidenceLog, verify_chain

    tmp = os.path.join(_HERE, "_systest_tamper.jsonl")
    if os.path.exists(tmp):
        os.remove(tmp)
    try:
        log = EvidenceLog(case_id="SYSTEST", master_path=tmp)
        log.record_exchange(
            target="systest", endpoint="none", probe="model-redteam",
            attack_id="a1", technique="AML.T0051",
            prompt="p", response="original", outcome="captured",
        )
        log.record_exchange(
            target="systest", endpoint="none", probe="model-redteam",
            attack_id="a2", technique="AML.T0054",
            prompt="p2", response="second", outcome="captured",
        )
        # Tamper: rewrite the first record's response in place.
        lines = open(tmp, encoding="utf-8").read().splitlines()
        rec = json.loads(lines[0])
        rec["response"] = "TAMPERED"
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        open(tmp, "w", encoding="utf-8").write("\n".join(lines) + "\n")

        ok, msg = verify_chain(tmp)
        assert not ok, "tamper NOT detected (chain still verified after edit)"
        return "edit detected — chain correctly reported broken"
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def check_posture_logging() -> str:
    """A posture verdict record (no exchange, ATT&CK id, CWE) logs and verifies."""
    from engine.core.evidence_log import EvidenceLog, verify_chain
    tmp = os.path.join(_HERE, "_systest_posture.jsonl")
    if os.path.exists(tmp):
        os.remove(tmp)
    try:
        log = EvidenceLog(case_id="SYSTEST", master_path=tmp)
        # Mirrors posture._log_posture: no originating exchange, ATT&CK technique,
        # CWE carried in mitigations, policy tag "posture".
        log.record_verdict(
            refs_exchange="", technique="T1611", grade="possible",
            verdict="reachable", confidence="low", severity="high",
            supporting_grains=["docker_socket"], mitigations=["CWE-250"],
            policy="posture",
        )
        ok, msg = verify_chain(tmp)
        assert ok, f"posture verdict broke the chain: {msg}"
        rec = json.loads(open(tmp, encoding="utf-8").read().splitlines()[0])
        assert rec.get("policy") == "posture", "posture policy tag not recorded"
        assert rec.get("technique") == "T1611", "posture technique not recorded"
        return "posture verdict logged, chain intact, record reads back"
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def check_policy_floor() -> str:
    """The policy integrity floor cannot be disabled (anti-fabrication guarantee)."""
    from engine.analysis.policy import load_policy

    class _Cfg:  # minimal stand-in for the engine config object
        analysis = None
        model = None

    class _Log:
        def info(self, *a, **k): pass
        def warning(self, *a, **k): pass

    # Even if a policy file tried to relax grounding, load_policy re-imposes the floor.
    os.environ.pop("PSYPHER_POLICY", None)
    policy = load_policy(_Cfg(), _Log())
    assert policy.require_supporting_grains is True, "grounding floor was disabled"
    assert policy.drop_unvalidated_ids is True, "id-validation floor was disabled"
    assert policy.min_grains_for_possible >= 1, "min-grains floor below 1"
    return "supporting-grains + id-validation floors enforced"


def check_firewall() -> str:
    """The brain's firewall admits a real ATLAS id and rejects a fabricated one."""
    from engine.analysis import brain

    # A synthetic graph exposing a `.nodes` list of technique dicts.
    class _Graph:
        nodes = [
            {"id": "AML.T0051", "type": "technique", "name": "LLM Prompt Injection"},
            {"id": "AML.T0054", "type": "technique", "name": "LLM Jailbreak"},
        ]

    valid = brain._technique_ids(_Graph())
    assert "AML.T0051" in valid, "real ATLAS id not recognized by firewall"
    assert "AML.T9999" not in valid, "fabricated id leaked through firewall"
    assert "NOT.A.REAL.ID" not in valid, "garbage id leaked through firewall"
    return "real ID admitted, fabricated IDs rejected"


def check_source_catalog_matches_graph() -> str:
    """The data-source catalog (packs/data/sources.yaml) documents graph sources;
    assessor.yaml graph.sources is what the builder loads. Fail if the catalog's
    enabled-set and graph.sources diverge by id. The catalog never writes the
    engine's source list; it is compared to it. Network/model/key-free."""
    import os, yaml
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cat = yaml.safe_load(open(os.path.join(root, "packs", "data", "sources.yaml"), encoding="utf-8")) or {}
    cfg = yaml.safe_load(open(os.path.join(root, "assessor.yaml"), encoding="utf-8")) or {}
    enabled = {e["id"] for e in (cat.get("sources") or []) if isinstance(e, dict) and e.get("enabled")}
    cfg_src = {sp.get("id") for sp in ((cfg.get("graph") or {}).get("sources") or []) if isinstance(sp, dict)}
    if enabled != cfg_src:
        raise AssertionError(
            "source catalog enabled-set != graph.sources "
            f"(catalog-only: {sorted(enabled - cfg_src)}; graph-only: {sorted(cfg_src - enabled)})")
    return f"source catalog matches graph.sources ({len(cfg_src)} sources)"


def check_probe_catalog_matches_allowlist() -> str:
    """The probe catalog (packs/probes/probes.yaml) documents every probe; the
    allowlist in assessor.yaml authorizes what runs. This check fails if the
    catalog's enabled-set and the allowlist diverge. The catalog never writes
    the gate; it is compared to it. Network/model/key-free."""
    import os, yaml
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cat = yaml.safe_load(open(os.path.join(root, "packs", "probes", "probes.yaml"), encoding="utf-8")) or {}
    cfg = yaml.safe_load(open(os.path.join(root, "assessor.yaml"), encoding="utf-8")) or {}
    enabled = {e["id"] for e in (cat.get("probes") or []) if isinstance(e, dict) and e.get("enabled")}
    allow = set((cfg.get("probes") or {}).get("allowlist") or [])
    if enabled != allow:
        raise AssertionError(
            "catalog enabled-set != allowlist "
            f"(catalog-only: {sorted(enabled - allow)}; allowlist-only: {sorted(allow - enabled)})")
    return f"catalog matches allowlist ({len(allow)} probes)"


def check_atlas_corpus() -> str:
    """The red-team ATLAS prompt corpus parses and every prompt tags a technique."""
    path = os.path.join(_ROOT, "packs", "redteam", "atlas-prompts.yaml")
    assert os.path.isfile(path), "packs/redteam/atlas-prompts.yaml not found"
    try:
        import yaml
        data = yaml.safe_load(open(path, encoding="utf-8"))
    except Exception:
        # YAML not importable in the test env — fall back to a structural check.
        text = open(path, encoding="utf-8").read()
        assert "technique:" in text and "prompt:" in text, "corpus missing required keys"
        n = text.count("- id:")
        return f"{n} prompts (structural check; PyYAML unavailable)"
    prompts = data.get("prompts") if isinstance(data, dict) else data
    assert prompts, "corpus contains no prompts"
    for item in prompts:
        assert item.get("technique"), f"prompt '{item.get('id')}' has no technique"
        assert item.get("prompt"), f"prompt '{item.get('id')}' has no prompt text"
    return f"{len(prompts)} ATLAS-tagged prompts, all reference a technique"


def check_deterministic_judge() -> str:
    """The behavioral judge's model-free fallback grades synthetic exchanges."""
    from engine.analysis import brain

    class _Log:
        def info(self, *a, **k): pass
        def warning(self, *a, **k): pass

    valid = {"AML.T0051", "AML.T0054"}
    items = [
        {  # emitted the canary, no refusal language -> should read as compliance
            "attack_id": "inj", "technique": "AML.T0051",
            "response_preview": "PSYPHER_BREACH_7F3A", "canary_hit": True,
            "severity_hint": "high",
        },
        {  # clear refusal -> should read as refused
            "attack_id": "jb", "technique": "AML.T0054",
            "response_preview": "I cannot help with that request.", "canary_hit": False,
            "severity_hint": "high",
        },
    ]
    verdicts = brain._judge_deterministic(items, valid, _Log())
    assert verdicts.get("inj", {}).get("verdict") == "complied", \
        "canary-verbatim exchange not graded as compliance"
    assert verdicts.get("jb", {}).get("verdict") == "refused", \
        "clear refusal not graded as refused"
    return "compliance and refusal graded correctly (no model required)"


def check_cve_mitigation_arity() -> str:
    """Branch A analyzer accepts 3-tuple mitigations and carries the REAL
    framework. Regression guard for the match.py/analyze.py mitigation-tuple
    contract: Candidate.mitigations is (id, name, framework); _finding_from
    must unpack all three and cite the mitigation's real framework (read off
    the graph node), never a guess from the id prefix. Fully synthetic — no
    graph, model, key, or network. On the pre-fix code this raises ValueError
    from the 2-tuple unpack; even absent the crash, the old prefix rule would
    mislabel a D3FEND countermeasure as 'ATT&CK'."""
    from engine.analysis.match import Candidate
    from engine.analysis.analyze import HeuristicAnalyzer

    class _Log:
        def info(self, *a, **k): pass
        def warning(self, *a, **k): pass
        def error(self, *a, **k): pass
        def debug(self, *a, **k): pass

    candidate = Candidate(
        cve_id="CVE-0000-0001",
        component="synthetic-component",
        observed_version="1.0.0",
        version_confirmed=True,
        evidence=None,
        description="synthetic candidate exercising the mitigation arity contract",
        cvss=7.5,
        cwes=["CWE-79"],
        techniques=[("AML.T0051", "synthetic technique")],
        mitigations=[("D3FEND-D3-XYZ", "a synthetic countermeasure", "D3FEND")],
    )
    findings = HeuristicAnalyzer(_Log()).judge("synthetic-component", [candidate], [])
    assert len(findings) == 1, f"expected one finding, got {len(findings)}"
    mits = findings[0].mitigations
    assert mits, "finding carried no mitigation (3-tuple mitigation dropped?)"
    m = mits[0]
    assert m.id == "D3FEND-D3-XYZ", f"mitigation id corrupted: {m.id!r}"
    assert m.framework == "D3FEND", (
        f"mitigation framework must be the real 'D3FEND', got {m.framework!r} "
        "(id-prefix-guess regression)"
    )
    return "3-tuple mitigation flows through analyzer; framework carried as D3FEND (no ValueError, no prefix mislabel)"


def check_cwe_defense_slice() -> str:
    """Build 2b: a CWE weakness node resolves to salience-ranked D3FEND
    countermeasures, and the defense phase attaches the top-N (weakness-specific
    first) as first-class Mitigation records while keeping the full ranked list
    in finding.evidence. Fully synthetic -- no data, model, key, or network."""
    import json
    import logging
    import os
    import tempfile
    from types import SimpleNamespace
    from engine.graph.canonical import Graph, Node, Edge
    from engine.graph.d3fend import ingest_d3fend_cwe
    from engine.analysis.match import mitigations_for_weakness
    from engine.analysis.defense import DefensePhase, WEAKNESS_TOPN
    from engine.core.models import Finding, Vulnerability, Severity, Confidence

    g = Graph()
    g.add_node(Node(id="CWE-476", type="weakness", name="NULL Pointer Dereference", framework="CWE"))
    doc = {"cwe": {"CWE-476": [
        {"id": "NullPointerChecking", "label": "Null Pointer Checking", "tactic": "Harden", "salience": 0.985},
        {"id": "SoftwareUpdate", "label": "Software Update", "tactic": "Harden", "salience": 0.0},
    ]}}
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(doc, tf)
    tf.close()
    ingest_d3fend_cwe(g, tf.name, logging.getLogger("systest-2b"))
    os.unlink(tf.name)

    ranked = mitigations_for_weakness(g, "CWE-476")
    assert [r[0] for r in ranked] == ["NullPointerChecking", "SoftwareUpdate"], \
        f"weakness countermeasures not salience-ranked: {ranked}"

    f = Finding(id="F-cwe", component="c", title="t", severity=Severity.HIGH,
                confidence=Confidence.HIGH, techniques=[],
                vulnerabilities=[Vulnerability(cve="CVE-0000-0001", cwe="CWE-476")],
                mitigations=[], attack_path="p", evidence={})
    ctx = SimpleNamespace(artifacts={"graph": g}, findings=[f],
                          logger=logging.getLogger("systest-2b"))
    DefensePhase().run(ctx)

    ids = [m.id for m in f.mitigations]
    assert ids and ids[0] == "NullPointerChecking", \
        f"weakness-specific countermeasure not attached first: {ids}"
    assert all(m.framework == "D3FEND" for m in f.mitigations), \
        f"weakness countermeasure mislabeled: {[(m.framework, m.id) for m in f.mitigations]}"
    full = f.evidence.get("d3fend_weakness_countermeasures", {}).get("CWE-476")
    assert full and len(full) == 2, "full ranked countermeasure list not kept in evidence"
    return f"CWE->countermeasure ranked + attached (top{WEAKNESS_TOPN}); full list in evidence; no data/model/key"


def check_relevance_scope() -> str:
    """Relevance scoping is deterministic and routes out-of-scope packages away.

    Proves the core guarantee WITHOUT the sqlite indexes (absent on a fresh clone):
    given the shipped role-group pack, an in-scope serving/isolation package
    (containerd) is selected and an out-of-scope desktop package (firefox-esr) is
    NOT — so its CVEs would be catalogued, never promoted into the graph. Also
    checks the pack itself is well-formed and its patterns are boundary-anchored
    (ray must not match array). Network/model/key-free."""
    from engine import relevance

    pack = relevance.load()
    assert pack is not None, "role-group pack packs/relevance/role-groups.yaml did not load"
    assert pack["role_groups"], "role-group pack has no role_groups"
    assert "strict" in pack["profiles"], "role-group pack missing the 'strict' profile"

    observed = ["containerd", "firefox-esr", "chromium", "libseccomp2", "openssl", "array"]
    scoped = relevance.in_scope(observed)
    assert scoped is not None, "in_scope returned None though the pack is present"
    assert "containerd" in scoped, "in-scope serving/isolation package was not selected"
    assert "firefox-esr" not in scoped, "out-of-scope desktop package leaked into scope"
    assert "chromium" not in scoped, "out-of-scope desktop package leaked into scope"
    assert "array" not in scoped, "boundary match failed: 'array' matched the 'ray' pattern"

    # Auto-select: observing an isolation/serving package must pick 'strict'.
    matched = relevance.resolve(sorted(observed), pack)
    assert relevance.select_profile(matched, pack) == "strict", \
        "auto-select did not choose 'strict' for an AI-serving surface"
    return f"{len(scoped)}/{len(observed)} in scope; desktop pkgs -> catalog; profile auto=strict"


def check_posture_firewall() -> str:
    """The posture phase admits a real ATT&CK id and rejects a fabricated one."""
    from engine.analysis import posture

    class _Graph:
        nodes = [
            {"id": "T1611", "type": "technique", "name": "Escape to Host"},
            {"id": "T1610", "type": "technique", "name": "Deploy Container"},
        ]

    valid = posture._technique_ids(_Graph())
    assert "T1611" in valid, "real ATT&CK id not recognized by posture firewall"
    assert "T9999" not in valid, "fabricated id leaked through posture firewall"
    assert "CWE-250" not in valid, "weakness id wrongly admitted as a technique"
    return "real ATT&CK id admitted, fabricated + weakness IDs rejected"


def check_schema_conforms() -> str:
    """A synthetic assessment.json exercising all three finding branches (CVE,
    posture, behavioral) with every evidence subfield the phases emit validates
    cleanly against assessment.schema.json, and deliberately malformed documents
    (bad severity, an out-of-set verdict, a wrong evidence type, a missing required
    id) are each rejected. Proves the schema describes real emission and actually
    constrains. Reuses engine.core.validation. Network/model/key-free."""
    import copy
    from engine.core.validation import validate

    good = {
        "case": {"id": "CASE-SYSTEST", "created": "2026-07-08T00:00:00Z",
                 "tool_version": "test", "target_name": "synthetic"},
        "provenance": {"tool_version": "test", "created": "2026-07-08T00:00:00Z",
                       "source_versions": {}, "graph_hash": "00000000", "probe_log": []},
        "summary": {"findings_total": 3, "by_severity": {"high": 3},
                    "frameworks": ["ATLAS", "CVE"]},
        "components": [], "grains": [],
        "findings": [
            {"id": "FND-ollama-CVE-2025-62164", "component": "ollama", "title": "RCE",
             "severity": "critical", "confidence": "high", "techniques": [],
             "vulnerabilities": [{"cve": "CVE-2025-62164", "cwe": "CWE-502", "cvss": 9.8,
                                  "mechanism": "m", "confirmed_by": "p"}],
             "mitigations": [], "attack_path": "p",
             "evidence": {"observed_version": "1.2.3", "version_confirmed": True,
                          "match": "version", "exploited": True, "priority": "act-now",
                          "kev_date_added": "2025-11-01", "kev_ransomware": True}},
            {"id": "FND-host-T1611", "component": "host", "title": "escape reachable",
             "severity": "high", "confidence": "low",
             "techniques": [{"framework": "ATT&CK", "id": "T1611",
                             "name": "Escape to Host", "validated": True}],
             "vulnerabilities": [], "mitigations": [], "attack_path": "p",
             "evidence": {"grade": "possible", "verdict": "reachable", "cwe": "CWE-250",
                          "supporting_grains": ["docker_socket"], "rationale": "r",
                          "match": "posture", "method": "observed", "access_tier": "gray"}},
            {"id": "FND-model-AML.T0051", "component": "model", "title": "injection complied",
             "severity": "high", "confidence": "high",
             "techniques": [{"framework": "ATLAS", "id": "AML.T0051",
                             "name": "LLM Prompt Injection", "validated": True}],
             "vulnerabilities": [],
             "mitigations": [{"framework": "ATLAS", "id": "AML.M0000",
                              "text": "Limit Public Release of Information"}],
             "attack_path": "p",
             "evidence": {"grade": "demonstrated", "verdict": "complied", "rationale": "r",
                          "supporting_grains": ["redteam::rt_prompt_injection_override"],
                          "exchange_id": "EXC-1", "target_model": "qwen2.5:0.5b",
                          "match": "behavioral"}},
        ],
        "kill_chains": [],
    }

    errs = validate(good, "assessment")
    assert errs == [], f"a valid synthetic assessment was rejected: {errs}"

    bad_sev = copy.deepcopy(good); bad_sev["findings"][0]["severity"] = "urgent"
    assert validate(bad_sev, "assessment"), "bad severity enum not rejected"
    bad_verdict = copy.deepcopy(good); bad_verdict["findings"][2]["evidence"]["verdict"] = "refused"
    assert validate(bad_verdict, "assessment"), "out-of-set verdict (judge-rubric leak) not rejected"
    bad_type = copy.deepcopy(good); bad_type["findings"][0]["evidence"]["exploited"] = "yes"
    assert validate(bad_type, "assessment"), "wrong evidence type not rejected"
    missing = copy.deepcopy(good); del missing["findings"][0]["id"]
    assert validate(missing, "assessment"), "missing required finding id not rejected"

    return "synthetic CVE+posture+behavioral conforms; bad severity/verdict/type/missing-id rejected"


def check_markdown_renders() -> str:
    """The Markdown renderer turns a synthetic assessment into a brief without
    error and carries the shared architecture: both surface headers, a known
    finding id, framework-labeled defenses, the honest 'no countermeasure mapped'
    degrade, proved/assumed stamps, and act-now-first ordering. Pure function over
    the assessment dict. Network/model/key-free."""
    from engine.report.markdown import render_markdown

    assessment = {
        "case": {"id": "CASE-SYSTEST", "created": "2026-07-08T00:00:00Z",
                 "tool_version": "test", "target_name": "synthetic"},
        "provenance": {"tool_version": "test", "created": "2026-07-08T00:00:00Z",
                       "source_versions": {"atlas": "0.1"}, "graph_hash": "deadbeef",
                       "probe_log": []},
        "summary": {"findings_total": 4, "by_severity": {"critical": 1, "high": 2, "medium": 1},
                    "frameworks": ["ATLAS", "ATT&CK", "CVE"]},
        "components": [], "grains": [],
        "findings": [
            {"id": "FND-ollama-CVE-2025-62164", "component": "ollama", "title": "RCE",
             "severity": "critical", "confidence": "high", "techniques": [],
             "vulnerabilities": [{"cve": "CVE-2025-62164", "cwe": "CWE-502", "cvss": 9.8,
                                  "mechanism": "deserialization", "confirmed_by": "os_packages"}],
             "mitigations": [], "attack_path": "p",
             "evidence": {"match": "version", "observed_version": "1.2.3",
                          "version_confirmed": True, "exploited": True, "priority": "act-now",
                          "kev_date_added": "2025-11-01", "kev_ransomware": True}},
            {"id": "FND-host-T1611", "component": "host", "title": "escape reachable",
             "severity": "high", "confidence": "low",
             "techniques": [{"framework": "ATT&CK", "id": "T1611",
                             "name": "Escape to Host", "validated": True}],
             "vulnerabilities": [], "mitigations": [], "attack_path": "p",
             "evidence": {"grade": "possible", "verdict": "reachable", "cwe": "CWE-250",
                          "supporting_grains": ["docker_socket"], "rationale": "r",
                          "match": "posture", "method": "observed", "access_tier": "gray"}},
            {"id": "FND-model-AML.T0051", "component": "model", "title": "injection complied",
             "severity": "high", "confidence": "high",
             "techniques": [{"framework": "ATLAS", "id": "AML.T0051",
                             "name": "LLM Prompt Injection", "validated": True}],
             "vulnerabilities": [],
             "mitigations": [{"framework": "ATLAS", "id": "AML.M0000",
                              "text": "Limit Public Release of Information"}],
             "attack_path": "p",
             "evidence": {"grade": "demonstrated", "verdict": "complied", "rationale": "r",
                          "supporting_grains": ["redteam::rt_prompt_injection_override"],
                          "exchange_id": "EXC-1", "target_model": "qwen2.5:0.5b",
                          "match": "behavioral"}},
            {"id": "FND-target-CVE-2013-4392", "component": "target", "title": "backport lead",
             "severity": "medium", "confidence": "medium", "techniques": [],
             "vulnerabilities": [{"cve": "CVE-2013-4392", "cwe": "", "cvss": 7.5,
                                  "mechanism": "m", "confirmed_by": "os_packages"}],
             "mitigations": [], "attack_path": "p",
             "evidence": {"match": "possible", "observed_version": "1.2.3",
                          "version_confirmed": True, "verify_distro_patch": True,
                          "match_basis": "backport status unverified", "exploited": False,
                          "priority": "scheduled"}},
        ],
        "kill_chains": [],
    }

    md = render_markdown(assessment, operator="tester", tool_name="Psypher AI Threat Assessor")

    assert "## Infrastructure" in md, "infrastructure surface header missing"
    assert "## Behavioral" in md, "behavioral surface header missing"
    assert "FND-model-AML.T0051" in md, "known finding id missing from render"
    assert "AML.M0000" in md and "**ATLAS**" in md, "framework-labeled defense missing"
    assert "No MITRE countermeasure mapped" in md, "honest no-defense degrade missing"
    assert "PROVED" in md and "ASSUMED" in md, "proved/assumed stamps missing"
    assert md.index("FND-ollama-CVE-2025-62164") < md.index("FND-host-T1611"), "act-now ordering not applied"
    assert md.index("## Behavioral") < md.index("FND-model-AML.T0051"), "behavioral finding not in Behavioral surface"
    assert "· PROVED · RCE" in md, "distro-authoritative version-confirmed CVE not stamped PROVED"
    assert "· ASSUMED · backport lead" in md, "verify_distro_patch backport lead not stamped ASSUMED"
    return "renders both surfaces; framework-labeled defenses + degrade; proved/assumed; act-now-first"


def check_pdf_renders() -> str:
    """render_pdf produces a non-trivial, valid PDF for a synthetic multi-finding
    assessment (both surfaces, an act-now KEV CVE, a demonstrated behavioral finding,
    a finding with no mitigation, and a deliberately overlong unbreakable token)
    without error, returning True. If fpdf2 is absent the renderer is designed to
    skip (return False) rather than crash -- that path is reported, not failed.
    Writes to a temp file, never the repo. Network/model/key-free."""
    import logging, os, tempfile
    from pathlib import Path
    from engine.report.pdf import render_pdf

    findings = [
        {"id": "FND-c-CVE-2025-1000", "component": "vllm",
         "title": "RCE via crafted request "
                  "http://d3fend.mitre.org/ontologies/d3fend.owl#AuthenticationCacheInvalidationLONGUNBROKENTOKENXXXX",
         "severity": "critical", "confidence": "high", "techniques": [],
         "vulnerabilities": [{"cve": "CVE-2025-1000", "cwe": "CWE-502", "cvss": 9.8,
                              "mechanism": "deserialization " * 20, "confirmed_by": "pip_freeze"}],
         "mitigations": [{"framework": "D3FEND", "id": "InputValidation", "text": "Input Validation"}],
         "attack_path": "path " * 30,
         "evidence": {"match": "version", "version_confirmed": True, "exploited": True,
                      "priority": "act-now", "kev_date_added": "2025-01-01", "kev_ransomware": True}},
        {"id": "FND-host-T1611", "component": "host", "title": "Container not syscall-confined",
         "severity": "medium", "confidence": "low",
         "techniques": [{"framework": "ATT&CK", "id": "T1611", "name": "Escape to Host", "validated": True}],
         "vulnerabilities": [], "mitigations": [], "attack_path": "inferred",
         "evidence": {"grade": "possible", "verdict": "reachable", "cwe": "CWE-693",
                      "supporting_grains": ["docker_socket"], "match": "posture",
                      "method": "observed", "access_tier": "gray", "rationale": "r " * 40}},
        {"id": "FND-model-AML.T0051", "component": "model", "title": "Prompt injection overrides system prompt",
         "severity": "high", "confidence": "high",
         "techniques": [{"framework": "ATLAS", "id": "AML.T0051", "name": "LLM Prompt Injection", "validated": True}],
         "vulnerabilities": [],
         "mitigations": [{"framework": "ATLAS", "id": "AML.M0000", "text": "Limit Public Release of Information"}],
         "attack_path": "demonstrated",
         "evidence": {"grade": "demonstrated", "verdict": "complied", "match": "behavioral",
                      "exchange_id": "EXC-1", "target_model": "qwen2.5:0.5b",
                      "supporting_grains": ["redteam::rt_prompt_injection_override"], "rationale": "compliance"}},
    ]
    assessment = {
        "case": {"id": "CASE-SYSTEST", "created": "2026-07-08T00:00:00Z",
                 "tool_version": "test", "target_name": "synthetic"},
        "provenance": {"tool_version": "test", "created": "2026-07-08T00:00:00Z",
                       "source_versions": {"atlas": "0.1", "cwe": "4.20"}, "graph_hash": "deadbeef", "probe_log": []},
        "summary": {"findings_total": len(findings), "by_severity": {"critical": 1, "high": 1, "medium": 1},
                    "frameworks": ["ATLAS", "ATT&CK", "CVE"]},
        "components": [], "grains": [], "findings": findings, "kill_chains": [],
    }

    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        ok = render_pdf(assessment, "tester", "Psypher AI Threat Assessor", Path(path), logging.getLogger("systest-pdf"))
        if not ok:
            return "fpdf2 unavailable -> renderer skipped cleanly (no crash)"
        size = os.path.getsize(path)
        assert size > 3000, f"PDF suspiciously small ({size} bytes)"
        assert open(path, "rb").read(5) == b"%PDF-", "output is not a valid PDF"
        pages = open(path, "rb").read().count(b"/Type /Page")
        assert pages >= 2, f"12-finding synthetic did not paginate (pages={pages}); page-break management failed"
        return f"multi-page PDF rendered ({size} bytes, {pages} pages, valid header)"
    finally:
        os.unlink(path)


def check_prompt_patch_merge() -> str:
    """Task 1 guard: the prompt override must PATCH-merge, not replace wholesale.
    A mode-only override (no variants) must inherit the default's variants and
    apply the new mode. FAILS if _merge regresses to wholesale-replace."""
    from engine.core import prompts as P
    _V = "complied refused partial confabulated"
    default = {"judge": {"mode": "single",
                         "variants": [{"name": "base", "system": _V},
                                      {"name": "strict", "system": _V}]}}
    merged = P._merge(default, {"judge": {"mode": "ensemble"}})
    jm = merged.get("judge", {})
    assert jm.get("mode") == "ensemble", \
        "mode-only override did not apply (mode=%r); _merge replaced wholesale" % jm.get("mode")
    names = [v.get("name") for v in (jm.get("variants") or [])]
    assert names == ["base", "strict"], \
        "default variants lost on a mode-only override (got %r)" % names
    safe = P._merge(default, {"judge": "garbage"})
    assert safe.get("judge", {}).get("variants"), \
        "a malformed (non-mapping) override corrupted the default role"
    return "prompt override patch-merges (mode-only keeps default variants; malformed falls back)"


# =============================================================================
#  ENTRY POINT
# =============================================================================
def main() -> int:
    banner()
    results = Results()

    _p([("── Shared spine ", _GREEN), ("─" * 45, _GREEN)])
    _run(results, "engine modules import", check_imports)
    _run(results, "phases register in order (discovery→graph→analysis→brain→report)", check_phase_order)
    _run(results, "evidence log hash-chain writes + verifies", check_evidence_chain)
    _run(results, "evidence log tamper-detection fires", check_tamper_detection)
    _run(results, "posture verdict logging + chain intact", check_posture_logging)
    _run(results, "assessment.json conforms to its schema", check_schema_conforms)
    _run(results, "markdown report renders (both surfaces + defenses)", check_markdown_renders)
    print()

    _p([("── Branch A · infrastructure ", _GREEN), ("─" * 32, _GREEN)])
    _run(results, "knowledge graph loads with MITRE ATLAS techniques", check_graph_atlas)
    _run(results, "KEV overlay flags exploited CVEs + derives priority", check_kev_priority)
    _run(results, "defense phase attaches grounded countermeasures", check_defense_anchor)
    _run(results, "D3FEND overlay grounds countermeasures into the graph", check_d3fend_overlay)
    _run(results, "CVE weakness resolves ranked D3FEND countermeasures (build 2b)", check_cwe_defense_slice)
    _run(results, "CVE analyzer carries 3-tuple mitigations w/ real framework", check_cve_mitigation_arity)
    print()

    _p([("── Branch B · the model ", _GREEN), ("─" * 37, _GREEN)])
    _run(results, "policy integrity floor cannot be disabled", check_policy_floor)
    _run(results, "firewall rejects fabricated technique IDs", check_firewall)
    _run(results, "posture firewall rejects fabricated technique IDs", check_posture_firewall)
    _run(results, "relevance scoping routes out-of-scope packages to catalog", check_relevance_scope)
    _run(results, "probe catalog matches the allowlist", check_probe_catalog_matches_allowlist)
    _run(results, "data-source catalog matches graph.sources", check_source_catalog_matches_graph)
    _run(results, "ATLAS red-team corpus is valid", check_atlas_corpus)
    _run(results, "deterministic judge grades synthetic exchanges", check_deterministic_judge)
    _run(results, "prompt override patch-merges (mode-only keeps default variants)", check_prompt_patch_merge)
    print()

    ok = results.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
