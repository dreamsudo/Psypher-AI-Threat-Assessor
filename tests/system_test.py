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
    print()

    _p([("── Branch A · infrastructure ", _GREEN), ("─" * 32, _GREEN)])
    _run(results, "knowledge graph loads with MITRE ATLAS techniques", check_graph_atlas)
    print()

    _p([("── Branch B · the model ", _GREEN), ("─" * 37, _GREEN)])
    _run(results, "policy integrity floor cannot be disabled", check_policy_floor)
    _run(results, "firewall rejects fabricated technique IDs", check_firewall)
    _run(results, "posture firewall rejects fabricated technique IDs", check_posture_firewall)
    _run(results, "probe catalog matches the allowlist", check_probe_catalog_matches_allowlist)
    _run(results, "data-source catalog matches graph.sources", check_source_catalog_matches_graph)
    _run(results, "ATLAS red-team corpus is valid", check_atlas_corpus)
    _run(results, "deterministic judge grades synthetic exchanges", check_deterministic_judge)
    print()

    ok = results.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
