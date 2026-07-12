<h1 align="center">Psypher AI Threat Assessor</h1>

<p align="center"><em>Full-stack AI/ML security — MITRE ATLAS–grounded penetration testing of the model <strong>and</strong> the infrastructure it runs on.</em></p>

<p align="center">
  <img alt="Grounded in MITRE ATLAS" src="https://img.shields.io/badge/grounded-MITRE%20ATLAS-2B5CE6">
  <img alt="Infra + Behavioral" src="https://img.shields.io/badge/surfaces-infra%20%2B%20behavioral-2B5CE6">
  <img alt="Penetration testing" src="https://img.shields.io/badge/mode-penetration%20testing-E4572E">
  <img alt="Publication safe" src="https://img.shields.io/badge/output-publication%20safe-2B5CE6">
  <img alt="Powered by Claude" src="https://img.shields.io/badge/powered%20by-Claude-111111">
</p>

<p align="center"><strong>Powered by Claude · Designed by PsypherLabs</strong></p>

![System overview](images/P01-system-overview.png)

---

## What is Psypher?

Psypher assesses an AI/ML deployment the way an attacker would — across **two orthogonal surfaces at once**:

- **Branch A — Infrastructure.** Does this host run a known-vulnerable version? Deterministic CVE/CWE
  analysis, backport-aware, grounded in NVD + the distribution's own security tracker.
- **Branch B — Behavioral.** How does the model respond when attacked? Claude judges refusal-test prompts
  drawn from MITRE ATLAS, backed by an unfakeable canary signal.

Both branches run over **one grounded knowledge graph** and emit **one report**. The guiding rule is
**"the model proposes, the graph disposes"**: every technique, tactic, mitigation, CVE, and CWE that
Psypher reports is a real node in a graph built from official sources — nothing is invented.

## Why it's different

- **Grounded, not generated.** A membership check (`has(id)`) is the arbiter at every point a model or a
  mapping could introduce an identifier. No fabricated CVEs, no hallucinated techniques.
- **Two surfaces, one report.** Infrastructure and model behavior are different questions with different
  truth conditions — Psypher tests both and renders them together.
- **Deterministic where truth can't move.** Branch A is model-free by design; every model touchpoint has a
  deterministic fallback, so a run always finishes — without a key, without the network.
- **Honest by construction.** Findings are stamped **PROVED** vs **ASSUMED**; posture is **observed** vs
  **inferred**; an empty result is an honest sentence, not a failure.
- **Publication-safe.** Refusal tests measure *resistance* — they never produce the harmful artifact — and
  output carries no personal paths, usernames, or secrets.

## How it works

**Architecture** — a sealed core surrounded by four packages, fed by data, extended by pluggable packs:

![Engine architecture](images/P02-engine-architecture.png)
![Repository Map — the tree that every other figure traces back to · directories cobalt, the adversarial pack warm](images/P03-repository-map.png)

*Repository Map — the tree that every other figure traces back to · directories cobalt, the adversarial pack warm.*


**The pipeline** — seven phases in execution order; the identifier firewall closes at order 30:

![The 7-phase pipeline](images/P05-pipeline.png)

**Two branches converge** — infrastructure (cobalt) and behavioral (coral) into one prioritized report:

![Two branches, one report](images/P09-two-branches.png)

**The knowledge graph** — the grounding layer both branches query:

![Knowledge graph](images/P06-knowledge-graph.png)
![Databases Compose the Graph — each dataset contributes specific node and edge types — together they build the closed vocabulary](images/P07-db-composition.png)

*Databases Compose the Graph — each dataset contributes specific node and edge types — together they build the closed vocabulary.*


**The grounding firewall** — the model proposes on one side, the graph disposes on the other; ungrounded
identifiers are discarded:

![The grounding firewall](images/P08-firewall.png)
![The Probe Catalog by Family — ~two dozen probes across five families · the catalog documents, the allowlist authorizes](images/P39-probe-catalog.png)

*The Probe Catalog by Family — ~two dozen probes across five families · the catalog documents, the allowlist authorizes.*


## The CVE lifecycle

How one observed package becomes a version-precise, ranked, defended finding — every gate in order, and
never a raw version match (the distribution's tracker decides whether a CVE is really open):

![CVE lifecycle end to end](images/P10-cve-lifecycle.png)

## Behavioral testing

Findings are sequenced along attacker tactics, with a D3FEND countermeasure branching off each step:

![Kill-chain and countermeasures](images/P13-killchain.png)

## Quick start

> Full detail is in the [User Manual](USER-MANUAL.md), Parts III–V.

**1. Get the code and build the environment** (the launcher builds its virtualenv on first run):
```bash
./run.sh --help
```

**2. Build the grounding data** (large downloads — this is the step people skip and then wonder why
nothing works):
```bash
cd data && ./fetch.sh && ./nvd-build.sh && cd ..
.venv/bin/python data/distro_index.py
.venv/bin/python data/kev_build.py
.venv/bin/python data/d3fend_extract.py
.venv/bin/python data/build_d3fend_cwe_slice.py
.venv/bin/python data/relevance_build.py
```

**3. Point it at your target.** Edit `assessor.yaml` to describe the model endpoint and host you are
**authorized** to test, and choose a policy (start with `strict`).

**4. (Optional) Add an API key** — without one, Psypher runs fully deterministically; with one, it adds
Claude's reasoning to the behavioral judging:
```bash
source setkey.sh
```

**5. Run it:**
```bash
./run.sh run
```

**6. Read the report** — open `report-brief.html` in the case directory for the polished view, or
`report.md` for the plain one.

> **Tip:** before your first real run, prove the installation in seconds — no model, no key, no network:
> ```bash
> .venv/bin/python -m tests.system_test
> ```

## Configuration

One file — `assessor.yaml` — defines the target, which checks run, the model roles, the data sources, and
the outputs. It is strictly validated on load (a bad key exits `2` and names it). Behavioral boldness is
**not** in this file — it rides on the `PSYPHER_POLICY` profile.

![assessor.yaml control plane](images/P12-config-plane.png)

## What you get

`assemble.py` builds one canonical assessment; each renderer is a pure, read-only view of it —
`report-brief.html` (branded), `report.html`, `report.md`, `assessment.json`, `grains.json`, an ATT&CK
Navigator layer, and a hash-chained evidence log.

![Report fan-out](images/P35-report-fanout.png)
![Anatomy of a Finding Card — every field a rendered finding carries, and where it comes from](images/P36-finding-card.png)

*Anatomy of a Finding Card — every field a rendered finding carries, and where it comes from.*

![Evidence · Split & Hash-Chained — findings are kept lean while the full evidence lives beside them — and every exchange is tamper-evident](images/P38-evidence-artifacts.png)

*Evidence · Split & Hash-Chained — findings are kept lean while the full evidence lives beside them — and every exchange is tamper-evident.*


## Safety & design principles

![Design principles and non-goals](images/P52-principles.png)
![The Three Verifiers — three independent tools prove the installation, each run, and the label types — before you trust anything](images/P48-three-verifiers.png)

*The Three Verifiers — three independent tools prove the installation, each run, and the label types — before you trust anything.*

![The Invariants Map — the fifteen properties the system guarantees, and the file that enforces each](images/P51-invariants-map.png)

*The Invariants Map — the fifteen properties the system guarantees, and the file that enforces each.*


Psypher is built to **say less rather than claim more**. It only tests targets you are authorized to test;
it measures whether a model *resists* an attack class rather than manufacturing the attack; it never
reports an identifier it cannot ground; and its output is safe to keep and share.

## Documentation

| Document | What it covers |
|---|---|
| [User Manual](USER-MANUAL.md) | Operating the tool end to end (illustrated) |
| Developer Manual | The full code walk, per file/function |
| Technical Paper | Design rationale |
| Setup · Control-Plane · Policy · Posture · CVE-Seed manuals | Focused references |

## The diagram atlas

Every major file, function, and part of the system has a schematic figure — **52 figures** in a consistent
blueprint style, each traceable to its exact source file and Developer-Manual section. They live in
[`images/`](images/) and are referenced throughout the manuals.

---

<p align="center"><strong>Powered by Claude · Designed by PsypherLabs</strong></p>
