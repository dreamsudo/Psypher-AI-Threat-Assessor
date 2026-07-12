# Psypher AI Threat Assessor — Developer Manual

### Full-stack AI/ML security — MITRE ATLAS–grounded penetration testing of the model and the infrastructure it runs on

**Powered by Claude · Designed by PsypherLabs**

*The complete, code-level engineering reference — from what the system is and why it matters, through its design, setup, configuration, and operation, into the implementation file by file, and out to how to extend every part.*

---

## About This Manual

This is the definitive engineering reference for the Psypher AI Threat Assessor. It is a complete, top-to-bottom account of the system: what it is, why it is built the way it is, how every part works and connects, and how to install it, configure it, run it, read its output, and extend it. It is written to take a reader from zero to full mastery — a developer who has never seen the system before should finish able to operate it and extend it safely using only this document and the source.

The manual documents the system **as a product**. It is authored from the source: where a prior document and the code disagree, the code governs and the manual reflects the code. Explanations are given intuitively first, so the reader builds a working mental model, then rigorously, with the actual implementation shown and explained at the depth needed to modify it.

Psypher is a defensive security tool, intended only for systems the operator is authorized to assess. Its adversarial corpus is a **refusal test** — an instrument for measuring whether a model holds its guardrails under pressure — not a generator of harmful content. That framing is load-bearing and is preserved throughout this manual.

### How to read it

The manual is organized into eight sequential parts that form one journey. Parts I–II build understanding (what the system is and how it works end to end). Parts III–V are operational (setup from a clean clone, every configuration knob, running and reading results). Part VI is the code-level core — the whole system walked file by file. Part VII is extension. Part VIII collects the design principles, invariants, and operational subtleties, with reference tables and a glossary. Read front to back for mastery, or jump by the table of contents and cross-references for reference use.

The **Repository Map** below doubles as the coverage checklist for this manual: every file in the tree is documented in the part where it naturally belongs, and none is skipped.

---

## Master Table of Contents

**Part I — What Psypher Is, and Why It Matters**
- 1.1 What Psypher Is
- 1.2 The Two Problems, and Why They Are Almost Never Assessed Together
- 1.3 The Secret Sauce: Grounding and Standardization
- 1.4 Why the Datasets Are Half the Product
- 1.5 The Two Branches — A and B — and Why the Dual Surface Is the Point
- 1.6 The Shape of the System, Intuitively

**Part II — The System Design & The Flow**
- 2.1 The end-to-end flow, from launch to a grounded report
- 2.2 The pipeline of phases and how each feeds the next
- 2.3 The knowledge graph: how it is built and how it grounds everything
- 2.4 How the databases compose into the graph
- 2.5 Sealed core, swappable packs: how capability plugs in
- 2.6 The firewall between the model and the graph
- 2.7 How the two branches run and combine into one report

**Part III — Setup From Zero**
- 3.1 Prerequisites (runtime, virtual environment, the model target, system dependencies)
- 3.2 Install
- 3.3 The complete data setup (frameworks, the NVD corpus + index, the distribution tracker + index, KEV, the D3FEND technique map, the D3FEND CWE→countermeasure slice)
- 3.4 Validating the whole setup

**Part IV — Configuration**
- 4.1 The control plane (`assessor.yaml`), key by key
- 4.2 Engagement and scope
- 4.3 Policy profiles and what each does
- 4.4 Model and target selection
- 4.5 Probes and their tiers
- 4.6 Output formats
- 4.7 Worked example configurations

**Part V — Running & Reading**
- 5.1 Running an assessment: commands, options, keyed vs. keyless
- 5.2 Supplying a key safely
- 5.3 What each phase is doing as it runs
- 5.4 Reading the output: every artifact and every part of the report
- 5.5 Why a field may legitimately be empty (the honest coverage ceilings)

**Part VI — The Code, Piece by Piece**
- 6.1 The sealed core (`engine/core/`)
- 6.2 Discovery (`engine/discovery/`)
- 6.3 Graph (`engine/graph/`)
- 6.4 Analysis (`engine/analysis/`) and relevance (`engine/relevance.py`)
- 6.5 Report (`engine/report/`)
- 6.6 The packs (`packs/`)
- 6.7 The data builders and ops (`data/`, root scripts, `tests/`)

**Part VII — Extending the System**
- 7.1 The extension philosophy
- 7.2 A new probe
- 7.3 A new attack / corpus entry (with the ATLAS mapping)
- 7.4 A new policy profile
- 7.5 A new prompt
- 7.6 A new relevance role-group
- 7.7 A new report renderer
- 7.8 A new analysis phase
- 7.9 A new graph source

**Part VIII — Design Principles, Invariants & Operational Subtleties**
- 8.1 The guarantees as design decisions
- 8.2 The operational gotchas
- 8.3 Reference tables (phases, databases, config keys, pack types)
- 8.4 Glossary

---

## Repository Map & Coverage

The tree below is the authoritative map of what the system is made of and the coverage checklist for this manual. Each file is marked: `[x]` fully documented · `[~]` documented by contract (current source postdates this snapshot) · `[ ]` not yet reached. Per-file coverage is completed in Part VI; the orientation and operational parts (I–V) cover files thematically. Two files (`build_d3fend_cwe_slice.py`, `data/d3fend/cwe-countermeasures.json`) belong to the weakness-grounded D3FEND defense layer and are documented by their input/output contract in §6.7; the localized additions to the five in-tree files that consume that layer are marked at their locations in §6.3–6.4.

**Generation status: COMPLETE.** All eight parts written, plus the closing retirement list and consistency note. Part VI documents every file in the repository map from current source; the two weakness-layer files absent from the snapshot are documented by contract and marked `[~]`, with the six reconciliation spots listed in the closing note.

```
psypher-assessor/
├── [x] assessor.yaml                 # control plane            — §4, §6.7
├── [x] run.sh                        # launcher                 — §6.7
├── [x] setkey.sh  setmodel.sh  selfcheck.sh  clean.sh  blackbox-run.sh   — §6.7
├── [x] psypher-brand.sh  psypher-hop.sh   # auxiliary ops helpers    — §6.7
├── [~] build_d3fend_cwe_slice.py     # CWE→countermeasure builder — contract in §6.7; code postdates snapshot
├── [x] pyproject.toml  requirements.txt    — §6.7
├── engine/
│   ├── [x] __init__.py  __main__.py            — §6.1
│   ├── [x] relevance.py                         — §6.4
│   ├── core/                                    — §6.1
│   │   ├── [x] __init__.py  banner.py  config.py  contracts.py
│   │   ├── [x] evidence_log.py  loader.py  models.py  orchestrate.py
│   │   ├── [x] prompts.py  validation.py
│   │   └── schema/
│   │       └── [x] assessment · grain · policy · probe · profile · source (.schema.json)
│   ├── discovery/                              — §6.2
│   │   └── [x] __init__.py  phase.py  approval.py  harness.py  parse.py  strategy.py
│   ├── graph/                                  — §6.3
│   │   └── [x] __init__.py  phase.py* canonical.py  cve.py  cwe.py
│   │       [x] d3fend.py* enrich.py  promote.py  stix.py  store.py
│   │       (* phase.py, d3fend.py — CWE→countermeasure overlay added in the current tree; marked in §6.3)
│   ├── analysis/                               — §6.4
│   │   └── [x] __init__.py  phase.py  analyze.py* defense.py* killchain.py
│   │       [x] match.py* policy.py  posture.py  validate.py
│   │       [x] brain.py                          — §6.4 (behavioral judge)
│   │       (* analyze.py, match.py, defense.py — mitigation-framework / weakness-defense delta; marked in §6.4)
│   └── report/                                 — §6.5
│       └── [x] __init__.py  phase.py  assemble.py  html.py  markdown.py
│           [x] navigator.py  package.py  web_html.py
├── packs/                                       — §6.6
│   ├── probes/
│   │   ├── [x] probes.yaml
│   │   ├── [x] host-isolation/    (8 descriptors: container_runtime, cred_env_names,
│   │   │        docker_socket, host_hypervisor_dmi, mac_confinement,
│   │   │        process_capabilities, syscall_filtering, world_readable_secrets)
│   │   ├── [x] ml-inference/      (api_banner, detect_virt, embedding_probe[.json/.py],
│   │   │        listening_sockets, os_packages, pip_freeze)
│   │   ├── [x] model-artifact/    (model_artifact[.json/.py])
│   │   ├── [x] model-endpoint/    (endpoint_banner, mgmt_exposed, model_digest,
│   │   │        unauth_inference)
│   │   └── [x] model-redteam/     (redteam_probe.py, rt_data_leakage,
│   │            rt_indirect_injection, rt_jailbreak, rt_prompt_injection,
│   │            rt_system_prompt_leak)
│   ├── [x] policy/       (exploratory, strict, strict-posture)
│   ├── [x] prompts/      (engine-prompts.default.yaml, engine-prompts.yaml)
│   ├── [x] redteam/      (atlas-prompts.yaml — the ATLAS-tagged corpus)
│   ├── [x] relevance/    (attack-artifact-map.json, role-groups.yaml)
│   ├── [x] blackbox/     (black_box_probe.py, blackbox.yaml — fenced)
│   ├── [x] data/         (sources.yaml — the source catalog)
│   ├── [x] intake/       (example.yaml, ollama.yaml)
│   ├── [x] profiles/     sources/
├── data/                                                — §6.7
│   ├── [x] fetch.sh  nvd-build.sh                       # fetch/build orchestration
│   ├── [x] nvd_index.py  distro_index.py  kev_build.py  # index/snapshot builders
│   ├── [x] relevance_build.py  d3fend_extract.py        # relevance + D3FEND builders
│   ├── [x] atlas-data/           (stix-atlas.json)
│   ├── [x] attack-stix-data/     (enterprise / ics / mobile -attack.json)
│   ├── [x] cve/                  (host-linux.json, ml-serving.json — seed sets)
│   ├── [x] cwe/                  (cwec_v4.20.xml)
│   ├── [x] d3fend/               (d3fend.json, d3fend-full-mappings.json,
│   │        [~] cwe-countermeasures.json — current tree; contract in §6.7)
│   ├── [x] distro/               (debian.json + debian.sqlite [generated])
│   ├── [x] kev/                  (kev.json)
│   └── [x] nvd/                  (CVE-2002.json … CVE-2026.json + index.sqlite [generated])
└── tests/                                                — §6.7
    └── [x] system_test.py  verify.py  verify_labels.py
```

---

# Part I — What Psypher Is, and Why It Matters

## 1.1 What Psypher Is

The **Psypher AI Threat Assessor** is a full-stack security-assessment engine for deployed AI/ML systems. In a single run against an authorized target, it penetration-tests two surfaces that in most organizations are assessed separately, by different teams, with different tools:

1. **How the model behaves under attack** — whether a live model can be talked out of its instructions, made to leak its system prompt, coaxed into disclosing training data or context, or driven to invent a plausible-but-fake answer.
2. **How exposed the infrastructure serving that model is** — the inference server, the API layer, the Python dependency stack, the container and its isolation boundary, and the host, measured against the real, published vulnerabilities that apply to the exact software versions actually running.

It then produces **one report** in which every finding is tied to a real, published security-framework identifier — a MITRE ATLAS or ATT&CK technique, a CVE, a CWE, or a MITRE D3FEND countermeasure — and to the exact observation that justifies it. Nothing appears in the report that the engine cannot resolve inside its own knowledge graph.

Concretely, Psypher is a Python package (`engine`, Python 3.10+), driven by a single YAML control plane (`assessor.yaml`) and launched by `run.sh`. It targets self-hosted, OpenAI-compatible model endpoints (it is developed against a local Ollama runtime), and it runs **with or without an API key** — the infrastructure findings are produced deterministically either way, and a language model is used only at a few tightly constrained decision points, each with a deterministic fallback. Capability is delivered as a **sealed core plus swappable packs**: the assessment logic and its guarantees live in a stable core, and coverage — more attacks, more vulnerability sets, more distributions, more frameworks, more defenses — grows by adding data and packs rather than by editing the engine.

The single word to hold onto for the rest of this manual is **grounded**. Psypher's defining property is that it is an assessment engine that *cannot make things up*: it reasons where reasoning helps, but every claim it emits is anchored to a real identifier and a captured piece of evidence, and anything that cannot be anchored is dropped before it reaches a report.

## 1.2 The Two Problems, and Why They Are Almost Never Assessed Together

Organizations are deploying AI faster than they can secure it, and the security of a deployed model splits cleanly into two problems.

**The model can be talked into misbehaving.** Prompt injection, jailbreaks, system-prompt extraction, and training-data or context leakage are real, low-effort attacks: a customer-facing model can have its instructions overridden or its system prompt extracted with a short sentence. This is the surface the current wave of behavioral AI-security scanners was built to probe.

**The model runs on software that has holes.** The inference server, the API layer, the dependency stack, the container, and the host are ordinary software with ordinary — and sometimes serious — vulnerabilities. A remote-code-execution flaw in a model-serving stack is, as the researchers who documented the class have put it, not a failure of the AI model but a failure of the infrastructure serving it. A permissive container capability or an unauthenticated management endpoint is exploitable no matter how well the model itself behaves.

The gap Psypher exists to close is that **these two are rarely assessed together, neither view is self-validating, and almost none of the available tools tell you what to do next.** A platform team's dependency scanner can report a container "green" while the model in front of it folds to the first injection and the inference engine it runs on has a published RCE. The free behavioral scanners are widely noted to ship no validation layer — the operator gets raw probe output and separates real from noise by hand — and any tool that then uses a language model to help triage that output inherits the model's willingness to confidently invent. And when a real finding does surface, most tools stop at the attack, leaving the operator to translate "you are vulnerable to technique X" into an actual, mapped countermeasure on their own.

The result, for most teams, is one half of the picture from one tool and the other half from another, both halves un-triaged, no named defense, and no single answer to the only question that matters: *how exposed is this deployment, really, and what do we do about it?* Psypher is built to give that single answer.

## 1.3 The Secret Sauce: Grounding and Standardization

Psypher's differentiator is not that it runs more probes than anything else, and it is not trying to. Its differentiator is **grounding and standardization**: every result is mapped to a real, published framework identifier, nothing is fabricated, both attack surfaces are covered in one run, and the loop is closed from *what is wrong* to *what to do about it* in a standardized defensive vocabulary.

The mechanism behind that claim is a single architectural property, and it is worth stating precisely because everything else follows from it:

> **Invariant — The grounding guarantee.** Psypher cannot report an identifier it cannot resolve in its own knowledge graph. Every CVE, CWE, technique, and mitigation identifier on every finding is checked against the graph, and anything that does not resolve is dropped — and logged — before a report is written. This is enforced in code by a closing validation pass, and by the design rule that finding-producing phases after that pass validate their own identifiers. (Detailed in Part VI, `engine/analysis/validate.py`, and in Part VIII.)

Why this is the secret sauce: an **ungrounded scanner produces noise.** It emits strings — probe names, heuristic labels, "possible" matches — that a human then has to interpret, verify, and map to something actionable. A **grounded** engine produces an auditable, standards-mapped, defensible result: each finding carries a real identifier that a reader can look up in the public frameworks, a real severity, the cited evidence that proves it, and — where the mapping exists — a named defense. That is the difference between output you have to defend and output that defends itself.

Standardization compounds the value. Because findings on **both** surfaces are expressed in the same public vocabularies (ATLAS and ATT&CK for techniques, CVE and CWE for vulnerabilities and weaknesses, D3FEND for countermeasures), the two halves of the assessment are cross-consistent and auditable together, and the report is something a regulated organization can hand to an auditor as evidence that its AI system was tested, how, with what result, and against which real countermeasures.

## 1.4 Why the Datasets Are Half the Product

Grounding is only as real as the data behind it. An engine that promises "every finding maps to a real identifier" is making a promise about its **data**: the identifiers, severities, weakness mappings, exploited-in-the-wild flags, and countermeasures all come from external, authoritative sources, and the assessment is exactly as trustworthy as those sources are current and correct.

This is why Psypher is built on authoritative, pinned data sources rather than on heuristics:

- **MITRE ATLAS and MITRE ATT&CK** (ingested from their STIX distributions) supply the technique vocabulary for the behavioral surface and the infrastructure posture.
- **The CWE catalog** supplies the weakness taxonomy that connects vulnerabilities to their underlying software weaknesses.
- **The full published CVE dataset (NVD)** supplies vulnerability identifiers with their CVSS severities and CWE associations.
- **CISA KEV** flags which vulnerabilities are known to be exploited in the wild, so real-world urgency can be surfaced rather than inferred from severity alone.
- **MITRE D3FEND** supplies the defensive countermeasure vocabulary and — through its Digital Artifact Ontology — the bridge that lets an offensive technique be answered by a named defensive one.
- **The target distribution's own vulnerability database** (the Debian Security Tracker in the reference deployment) supplies the single most important grounding decision on the infrastructure side: whether a CVE is *genuinely open* on the exact installed package version.

That last point is the heart of why Psypher's infrastructure findings are defensible where a naïve scanner's are not. A simple product-and-version match against NVD produces false positives — it flags a package as vulnerable when the distribution has already backported the fix, and it misapplies advisories that never affected the distribution's build. Psypher instead promotes a CVE to a finding only when the **distribution's own security team** confirms it is open on the installed version, using a backport-aware, distribution-correct version comparator. NVD then enriches that confirmed finding with CVSS and CWE by identifier; it is not the arbiter of applicability.

There is a direct operational consequence, and it explains why Part III of this manual treats data setup as substance rather than plumbing: **the engine ships without its datasets.** They are fetched and built separately, and until they are present the assessment cannot run — the graph phase has nothing to build from. Exact graph node and edge counts, and the specific framework versions loaded, are therefore properties of a *built* system, not of the source. Building the data correctly is a first-class part of standing the tool up.

## 1.5 The Two Branches — A and B — and Why the Dual Surface Is the Point

The single most important concept in the system, and the one to carry through every later part, is that Psypher is **two branches over one graph**, with a deliberate, governing boundary between them.

**Branch A — infrastructure / CVE–CWE posture — deterministic FACTS.** Branch A builds a component-and-version inventory of the serving stack from what it can observe over the engagement's access, scans that inventory against the distribution's authoritative vulnerability database, and maps the host-isolation and endpoint-exposure posture (container capabilities, seccomp filtering, an exposed Docker socket, unauthenticated inference or management endpoints, unpinned model provenance) to real ATT&CK and ATLAS techniques. On the run path these facts are produced **with no language model in the loop.** They are the same with or without an API key. They are deterministic, version-matched, distribution-confirmed facts.

**Branch B — behavioral / adversarial — reasoned conduct.** Branch B sends a corpus of adversarial prompts — each tagged to a real MITRE ATLAS technique — to the live model, captures every response as an immutable, hash-chained evidence record, and grades each exchange: did the model **comply**, **refuse**, **partially comply**, or **confabulate**? The grading is a reasoning task, and it is where a language model earns its place; but it is firewalled (§1.6), and the technique that anchors each behavioral finding comes from the **corpus**, never from the model.

Both surfaces are necessary because **neither predicts the other.** A container can be pristine while the model in front of it folds to the first injection; a model can be robustly aligned while the inference server it runs on carries a published, exploitable RCE. Assessing only one surface leaves a real and common exposure completely unseen. Doing both, in one grounded engine, over one evidence spine, with cross-consistent identifiers, is the entire point of the tool.

The boundary between the branches is the design decision the rest of the system is built to protect. It is a strict, one-directional relationship:

> **The through-line.** Branch A produces deterministic facts that are collected, stored, and rendered and that the model's judgment can never drop or alter. Branch B reasons over those facts and *adds* to them — behavioral verdicts, named defenses, a sequenced kill chain — but it never gates, deletes, or overrides a Branch-A fact. The report presents both. Any change that would let a model's judgment remove or rewrite a Branch-A fact violates this through-line.

This is what lets Psypher use a reasoning model for the parts of assessment that need reasoning — triage, applicability, verdicts — without inheriting a reasoning model's willingness to invent. The facts are model-proof; the judgment is firewalled; and a closing validation pass drops anything that does not resolve.

**Figure 1.1 — The two branches over one grounding graph.** Branch B tests the model's behavior; Branch A produces deterministic infrastructure facts; both are validated against the knowledge graph, and only resolvable, evidence-backed results — with named defenses — reach the report.

```mermaid
flowchart TB
    OP([Operator + assessor.yaml]) --> ENG[[engine — fixed, ordered pipeline]]

    subgraph TGT[Authorized target deployment]
        MODEL[Model endpoint]
        INFRA["Serving infrastructure<br/>OS · deps · container · endpoints"]
    end

    subgraph BRANCHB[Branch B — behavioral · reasoned but firewalled]
        PROBE["Adversarial corpus<br/>ATLAS-tagged refusal tests"]
        JUDGE["Verdict: comply / refuse /<br/>partial / confabulate"]
    end

    subgraph BRANCHA[Branch A — infrastructure · deterministic FACTS]
        INV[Component + version inventory]
        SCAN["Distro-authoritative CVE scan<br/>backport-aware comparator"]
        POST[Host-isolation + endpoint posture]
    end

    ENG --> PROBE
    ENG --> INV
    ENG --> POST
    MODEL --> PROBE --> JUDGE
    INFRA --> INV --> SCAN
    INFRA --> POST

    GRAPH[("Grounding knowledge graph<br/>ATLAS · ATT&CK · CWE · CVE · D3FEND")]
    JUDGE -. validated against .-> GRAPH
    SCAN -. validated against .-> GRAPH
    POST -. validated against .-> GRAPH

    GRAPH --> VAL{{"Closing validation —<br/>drop any unresolved id"}}
    VAL --> REPORT[/"Grounded report — both surfaces,<br/>real ids, cited evidence, named defenses"/]
```

## 1.6 The Shape of the System, Intuitively

Three structural ideas make the two branches work. Each is introduced here as intuition and detailed later with the code.

**Sealed core, swappable packs.** The engine is split into a stable core and pluggable capability. The core knows how to *execute* probes, *thread* state through the pipeline, *validate* against schemas, *load* prompts, and *record* evidence — but it references no specific probe, attack, CVE, framework, or phase by name. All of the domain content — the probes, the attack corpus, the vulnerability sets, the policies, the prompts, the relevance data — lives in packs and data that are loaded at runtime. The payoff is that coverage grows without touching the assessment logic or its guarantees: a core edit is the exception that must be justified, not the routine way to add capability. (Part II §2.5; Part VI §6.1; Part VII.)

**Firewalled model touchpoints.** A language model (Claude) is used at exactly four decision points where judgment genuinely helps — *which probe to run next*, *which cross-framework links to draw*, *which known vulnerability actually applies*, and *whether an attacked model truly complied*. Every one of those points sits behind a firewall: the model **proposes**, and a membership check against the graph or the available set **disposes**. A proposed probe must already be in the available set or it is rejected; a proposed cross-framework edge is added only if its endpoint is already a graph node; a behavioral verdict whose technique is not in the graph is dropped. Each touchpoint also has a deterministic fallback, so the engine runs — and produces its facts — with no key at all. (Part II §2.6; Part VI §6.4; Part VIII.)

**The grounding guarantee.** Sitting over both branches is the closing validation pass that re-checks every identifier on every finding and every technique on the kill chain against the graph, dropping and logging anything unresolvable, with later finding-phases self-validating their own identifiers. This is the enforcement point for the property in §1.3: nothing ungrounded reaches a report. (Part VI §6.4; Part VIII §8.1.)

Held together, the shape is this: a fixed, ordered pipeline of phases (seven in the reference build, enumerated authoritatively in Part II from the phase registry) runs the two branches over one knowledge graph assembled from authoritative framework data; a language model is consulted at four firewalled points and never trusted beyond the graph; deterministic infrastructure facts are made model-proof; behavioral judgment is reasoned but constrained; every finding is validated and evidence-backed; and the defense is named, not just the attack. The remainder of this manual makes each of those clauses concrete — first as a working machine (Part II), then in operation (Parts III–V), then line by line (Part VI), and finally as the set of invariants that keep the machine honest (Parts VII–VIII).

*(End of Part I.)*

---

# Part II — The System Design & The Flow

Part I described *what* Psypher is and *why* it is shaped the way it is. Part II is the working-machine account: the exact sequence a run follows from launch to a finished report, the mechanism that wires the phases together, how the knowledge graph is built and how it grounds every claim, how the databases compose into that graph, how packs plug into the sealed core, how the firewall constrains the model, and how the two branches combine into one artifact. Everything here is drawn from the source; where a subsystem's current source postdates the snapshot this part was written against, that is flagged inline and its line-level treatment is deferred to Part VI.

## 2.1 The End-to-End Flow, From Launch to a Grounded Report

A run is a straight line. The launcher invokes the package as a module; the CLI parses arguments and dispatches the `run` subcommand; the run controller builds a single shared state object, loads the permitted probes, imports the phase packages so they register themselves, and then executes the registered phases in ascending order. Each phase reads what earlier phases deposited on the shared state and appends its own results. The final phase assembles everything into one canonical record and writes the report files. That shared state — the `RunContext` — is the *only* channel between phases; there is no hidden global, no side path.

**The control flow, precisely.** The entry point (`engine/__main__.py`) exposes two subcommands, `run` and `validate`; `validate` loads the configuration and the packs and prints a summary **without touching a target**, which makes configuration mistakes cheap to catch. `run` calls the controller:

```python
def run_assessment(config: Config, logger: logging.Logger | None = None) -> RunContext:
    logger = logger or logging.getLogger("psypher")

    ctx = RunContext(config=config, logger=logger)
    ctx.probes = discover_probes(config, logger)   # load + validate permitted probes

    _import_installed_phases(logger)               # each package registers its phases
    phases = PhaseRegistry.ordered()               # sorted by the phase's `order`

    if not phases:
        logger.warning("no assessment phases are installed ...")
        return ctx

    for phase in phases:
        logger.info("running phase: %s", phase.name)
        phase.run(ctx)                             # mutates the shared context

    return ctx
```

The controller references no phase by name. It imports a fixed tuple of phase *packages* (`engine.discovery`, `engine.graph`, `engine.analysis`, `engine.report`); each package, on import, registers whatever phases it defines (§2.2). The controller then asks the registry for the phases in order and runs each one. Absent phases are detected, not faked — an empty registry stops the run with a clear message rather than pretending to assess.

**The data flow, precisely.** As the phases run, the `RunContext` fills in this order:

| Phase (order) | Reads from context | Writes to context |
|---|---|---|
| `discovery` (10) | `config`, `probes` | `components`, `grains` |
| `graph` (20) | `config`, `grains` | `artifacts["graph"]`, `artifacts["graph_hash"]` |
| `analysis` (30) | `grains`, `artifacts["graph"]` | `findings`, `kill_chains` (after the closing firewall) |
| `brain` (35) | captured exchanges, `artifacts["graph"]` | behavioral `findings` (appended) |
| `posture` (37) | `grains`/`components`, `artifacts["graph"]` | posture `findings` (appended) |
| `defense` (38) | `findings`, `artifacts["graph"]` | named defenses attached to `findings` |
| `report` (40) | everything on the context | writes report files; `artifacts["assessment"]`, `artifacts["report_dir"]` |

The report phase always produces an assessment — *even with zero findings* — so a run always yields an auditable artifact. That is a deliberate property: an empty result is itself a documented, provenance-stamped outcome, not a silent non-answer.

**Figure 2.1 — the end-to-end flow.**

```mermaid
flowchart TB
  RUN["run.sh → python -m engine run -c assessor.yaml"] --> LOAD[load_config + discover_probes]
  LOAD --> CTX[RunContext built · phases registered at import]
  CTX --> P10["discovery (10) → components + grains"]
  P10 --> P20["graph (20) → build/load graph, then overlays → ctx.artifacts['graph']"]
  P20 --> P30["analysis (30) → match → judge → findings + kill chain → CLOSING FIREWALL"]
  P30 --> P35["brain (35) → behavioral findings (appended)"]
  P35 --> P37["posture (37) → posture findings (appended)"]
  P37 --> P38["defense (38) → attach named defenses to every finding"]
  P38 --> P40["report (40) → assemble → render → package"]
  P40 --> OUT[/"case dir: assessment.json · grains.json · report.md · report.html · report-brief.html · navigator-layer.json · {case}.zip"/]
```

## 2.2 The Pipeline of Phases and How Each Feeds the Next

The pipeline is not a hardcoded list. It is a set of self-registering units bound by one small contract, which is what lets a phase be added or removed without editing the controller.

**The contract.** Every phase is a subclass of `Phase` with a `name`, an integer `order`, and a `run(ctx)` method; lower `order` runs first. A process-wide `PhaseRegistry` collects them:

```python
class Phase(ABC):
    name: str = ""
    order: int = 0
    @abstractmethod
    def run(self, ctx: RunContext) -> None: ...

class PhaseRegistry:
    _phases: dict[str, Phase] = {}
    @classmethod
    def register(cls, phase: Phase) -> None:
        if not phase.name:
            raise ValueError("phase.name must be a non-empty string")
        cls._phases[phase.name] = phase          # keyed by name; last registration wins
    @classmethod
    def ordered(cls) -> list[Phase]:
        return sorted(cls._phases.values(), key=lambda p: p.order)
```

**The wiring.** A phase package registers its phase in its `__init__.py` at import time. The core analysis package registers the deterministic analysis phase and then, in three independent guarded blocks, registers the three additive finding phases — the behavioral brain, the host-isolation posture, and the defense-anchor — each of which is designed to be additive and to validate its own identifiers. Because the registry keys by `name` and last-registration wins, a phase that also self-registers at the bottom of its own module is harmless to register twice.

The reference build therefore runs **seven phases in this fixed order** (read from the registrations and the `order` values in the source):

| Order | Phase | Module | What it does | Branch | Model touchpoint |
|---|---|---|---|---|---|
| 10 | `discovery` | `engine/discovery/` | Select and run permitted probes against each in-scope asset; fold in operator intake; emit evidence-backed grains and a component inventory | A | recon probe-selection (firewalled) |
| 20 | `graph` | `engine/graph/` | Build or load the knowledge graph from configured sources; optionally add model-proposed cross-framework edges; apply the promotion and D3FEND overlays on the finished graph | — | graph enrichment (firewalled) |
| 30 | `analysis` | `engine/analysis/phase.py` | Match CVE candidates against grains, judge them into findings, sequence a kill chain, and run the **closing identifier firewall** | A | CVE-analysis judgement (firewalled; deterministic on the run path) |
| 35 | `brain` | `engine/analysis/brain.py` | Grade the captured adversarial exchanges into behavioral findings; self-validate technique ids | B | behavioral judge (firewalled) |
| 37 | `posture` | `engine/analysis/posture.py` | Map observed host-isolation/endpoint state to technique-anchored findings; self-validate | A | none (deterministic) |
| 38 | `defense` | `engine/analysis/defense.py` | Attach graph-grounded named defenses to every finding; introduce only real graph nodes | — | none (deterministic) |
| 40 | `report` | `engine/report/phase.py` | Assemble the canonical assessment, render every configured format, package a case archive | — | none |

**The consequence for extension.** To add a phase you implement `Phase`, choose an **unused** `order` (10/20/30/35/37/38/40 are taken; use a gap such as 25 or 45), and register it — either by appending a guarded registration to the analysis package or by adding a new package to the controller's tuple. No edit to the run controller is required. This is the mechanism behind the "new analysis phase" extension path in Part VII.

> **Note — where the current source moves ahead of this snapshot.** The `graph` phase (order 20) is where the graph overlays run, and the current tree adds one more overlay step there (the weakness-grounded D3FEND CWE→countermeasure overlay). The phase *structure* described here is unchanged; the added overlay is documented at line level in Part VI once its current source is in hand. The `defense` phase (38) is likewise extended in the current tree to attach weakness-grounded countermeasures; §2.7 treats that at the conceptual level and flags it.

## 2.3 The Knowledge Graph: How It Is Built and How It Grounds Everything

The knowledge graph is the substrate that makes grounding possible. It normalizes every framework into **one** shape so that analysis queries a single structure rather than four file formats, and it exposes one membership operation that every firewall in the system relies on.

**One model, a closed vocabulary.** The canonical graph has exactly six node types and six edge types, declared as frozen sets that `add_node`/`add_edge` enforce — an unknown type raises rather than being silently accepted:

```python
NODE_TYPES = frozenset({"tactic", "technique", "mitigation", "vulnerability", "weakness", "asset"})
EDGE_TYPES = frozenset({"accomplishes", "mitigated_by", "enables", "instance_of", "child_of", "exposes"})
```

- `accomplishes`: technique → tactic
- `mitigated_by`: technique → mitigation
- `enables`: vulnerability → technique *(model-proposed, then validated — §2.6)*
- `instance_of`: vulnerability → weakness *(CVE → CWE)*
- `child_of`: technique → technique *(sub-technique)*
- `exposes`: asset → vulnerability *(added during analysis)*

A node is keyed by its real framework identifier (`T1059`, `CVE-2025-62164`, `CWE-77`, a D3FEND countermeasure id), carries a `type`, `name`, `framework`, and free-form `attrs`, and **merges on insert** — inserting an id that already exists fills in a missing name/framework and non-empty attributes rather than duplicating. Edges dedupe by `(src, type, dst)`.

**The membership check is the grounding primitive.** The graph exposes `has(node_id) -> bool`. Every firewall and the closing validation pass ask exactly this question — *is this identifier a node in the graph?* — and drop anything for which the answer is no. Because the vocabulary is closed and every id is either a node or not, grounding reduces to set membership over authoritative data.

**Build, then cache, then overlay — and why the runtime graph differs from the cached one.** The graph phase (order 20) builds the graph from the configured sources by dispatching each source on its declared format:

```python
def _build(ctx):
    graph = Graph()
    for source in ctx.config.graph.sources:
        ...
        if source.format == "stix":  ingest_stix(graph, path, source.id, ctx.logger)
        elif source.format == "json": ingest_cve(graph, path, ctx.logger)
        elif source.format == "xml":  ingest_cwe(graph, path, ctx.logger)
    return graph
```

The built (and optionally enriched) graph is frozen to disk as `nodes.json` + `edges.json` + `meta.json`, keyed by a **fingerprint** of the source files' identity; on a later run with unchanged sources it is reloaded from that cache instead of rebuilt. Then — and this is the subtle part — two overlays run on the finished graph *after* the cache is saved:

```python
        # promotion + D3FEND overlays: run on the finished graph whether built
        # or loaded-from-cache; always applied, never entered into the cache.
        promote(graph, ctx.grains, <distro index>, <nvd index>, ctx.logger)
        ingest_d3fend(graph, <attack-artifact-map>, ctx.logger)
        ctx.artifacts["graph"] = graph
        ctx.artifacts["graph_hash"] = graph.hash()
```

> **Gotcha — the cached graph is not the runtime graph.** The promotion and D3FEND overlays are applied every run but are never written back to the cache, so the on-disk `build/graph/*.json` is the *pre-overlay* graph while the graph the analysis phase queries is the *post-overlay* runtime graph. When debugging a "missing node" or a grounding decision, inspect the runtime graph (the one on the context), not the cached files. The overlays are deterministic and observed-only, and every node they add is a *real* node, so the closing firewall re-checks promoted and overlaid ids unchanged.

> **Current-source flag.** In the tree this part was written against, the overlays are promotion + the D3FEND technique overlay. The current tree adds a third overlay in the same position and pattern — the weakness-grounded D3FEND CWE→countermeasure overlay — composing additional mitigation nodes and `mitigated_by` edges onto the finished graph, again never cached. Per its own record it introduces **no new node or edge type** (it reuses `mitigation` + `mitigated_by`). Its line-level walk is in Part VI once the current source is in hand.

## 2.4 How the Databases Compose Into the Graph

The graph's trustworthiness is entirely a function of the data poured into it. Each configured source contributes specific node and edge types, and the promotion and defense overlays contribute the run-specific, exploitability-aware layer.

| Source (reference deployment) | Format | Contributes to the graph | Produced/served by |
|---|---|---|---|
| MITRE ATLAS, MITRE ATT&CK | STIX | `tactic`, `technique`, `mitigation` nodes; `accomplishes`, `mitigated_by`, `child_of` edges | vendor STIX distributions |
| CWE catalog | XML | `weakness` nodes | the pinned CWE catalog file |
| CVE seed set | JSON | `vulnerability` nodes; `instance_of` (→ weakness) edges | the shipped seed sets |
| Distribution security tracker + NVD index | (overlay) | promoted `vulnerability` nodes on observed components, with CVSS/CWE enrichment by id and KEV-exploited flags | the distribution and NVD indices (built locally) |
| D3FEND artifact map | (overlay) | `mitigation` nodes + `mitigated_by` edges, bridged through the Digital Artifact Ontology | the extracted D3FEND map |

The distinction between *sources* and *overlays* matters. Sources are the framework backbone, ingested once and cached. The overlays are what make an assessment about *this* target: the promotion overlay reads the discovery grains (the observed component-and-version inventory), matches candidate CVEs, and promotes to the graph only those the distribution's own tracker confirms are open on the installed versions using a backport-aware comparator — NVD then enriches those confirmed ids with CVSS and CWE, and KEV flags the ones exploited in the wild. The defense overlay bridges offensive techniques to named D3FEND countermeasures.

Which sources load, and from where, is controlled by the source catalog (`packs/data/sources.yaml`) and the engagement config (§4); the indices themselves are produced by the data builders under `data/` (Part III walks building every one; Part VI documents each builder's artifact contract). The practical corollary from Part I stands: with no data present, the graph phase has nothing to build and no assessment can run.

> **Current-source flag.** The weakness-grounded defense layer adds a pinned `data/d3fend/cwe-countermeasures.json` slice and a builder (`build_d3fend_cwe_slice.py`) that produces it; both are documented in Parts III and VI once their current source is in hand.

## 2.5 Sealed Core, Swappable Packs: How Capability Plugs In

The engine is split so that the parts that must never casually change are separated from the parts that are *meant* to grow.

**The sealed core** (`engine/core/`) defines contracts, configuration loading and validation, pack discovery, the canonical records, the prompt registry, the evidence log, the startup banner, and the JSON schemas — and nothing domain-specific. It knows how to *execute* a probe, *thread* the context, *validate* against a schema, *load* a prompt, and *record* evidence, but it references no concrete probe, attack, CVE, framework, or phase by name. The single coupling point between the core and everything swappable is `engine/core/contracts.py`, whose docstring states the rule outright: nothing in the engine references a concrete probe, profile, or phase by name; packs supply `ProbeSpec` instances and phases register themselves.

A probe, to the core, is just a validated manifest:

```python
@dataclass(frozen=True)
class ProbeSpec:
    id: str
    tier: ProbeTier                 # passive | active_safe | intrusive
    applies_to: tuple[str, ...]
    observes: tuple[str, ...]
    run: dict[str, Any]             # how to execute (shell / script / http)
    parse: dict[str, Any]           # how to turn output into grains
    source_path: str
    min_access: str = "black"
```

**The swappable packs** (`packs/`) supply the domain capability: the probe manifests and their modules, the ATLAS-tagged corpus, the prompt registry contents, the policy profiles, and the relevance data. They are discovered and validated at load time (the core's loader validates each probe manifest against the probe schema and gates it by tier against the engagement policy), and they are what an operator or developer edits to extend coverage. The governing rule, stated in Part I and enforced by this split, is: **grow capability through packs and data, not by editing the core.** A core change is the exception that must be justified; the one post-baseline core mechanism is the prompt registry (`engine/core/prompts.py`), which exists precisely so that model-touchpoint prompts live in a pack rather than as hardcoded constants. (Part VI §6.1/§6.6 walk the core and the packs; Part VII gives the extension procedures.)

## 2.6 The Firewall Between the Model and the Graph

A language model is consulted at four points, and at every one of them the same discipline applies: **the model proposes, the graph disposes, and a deterministic fallback covers its absence.** The model can *relate* things that are already in the graph; it can never introduce an identifier that is not.

The four touchpoints:

1. **Recon probe-selection** (`engine/discovery/strategy.py`) — a proposed `probe_id` is honored only if it is in the available probe set; a hard failure degrades to exhaustive probing.
2. **Graph enrichment** (`engine/graph/enrich.py`) — a proposed `enables` edge is added only if the proposed technique id is already a graph node.
3. **CVE-analysis judgement** (`engine/analysis/analyze.py`) — the analyzer may select only from each candidate's *offered* ids. On the run path this touchpoint is deterministic (a heuristic analyzer is selected), so Branch A is model-free regardless of whether a key is present.
4. **Behavioral judge** (`engine/analysis/brain.py`) — the technique that anchors a behavioral finding comes from the *corpus*, not the model; a verdict whose technique is not in the graph is dropped.

**A worked example — the enrichment firewall.** No official feed asserts "CVE-X enables Technique-Y," so enrichment asks the model to propose those edges — but constrains it twice. The tool schema tells the model it must choose from the provided technique ids, and the code then verifies membership before adding anything:

```python
for vuln in vulnerabilities:
    for proposal in self._propose(vuln, catalogue):
        technique_id = proposal.get("technique_id", "")
        if technique_id not in techniques:          # FIREWALL: not a graph node → reject
            self.logger.warning("enrichment proposed unknown technique '%s' for %s; rejected",
                                 technique_id, vuln.id)
            continue
        graph.add_edge(Edge(vuln.id, technique_id, "enables",
                            {"confidence": proposal.get("confidence", "medium"),
                             "rationale": str(proposal.get("rationale", ""))[:400],
                             "source": "claude-enrichment"}))
```

The model client is imported lazily and the whole step is skipped cleanly when no credentials are present (structural graph only), and a per-item model or transport failure skips that item rather than crashing the run — the house "defensive but loud" style.

**The closing firewall re-checks everything.** Independently of the touchpoint-level checks, the analysis phase runs a final identifier firewall over every finding and the kill chain. It is deliberately belt-and-suspenders: candidates already come from the graph and the analyzers select from offered ids, so a rejection here would signal a real bug, not a model error.

```python
def validate_findings(findings, graph, logger):
    for finding in findings:
        kept = []
        for ref in finding.techniques:
            if graph.has(ref.id):
                ref.validated = True                # stamp the survivors
                kept.append(ref)
            else:
                logger.warning("finding %s cites unknown technique '%s'; dropped", finding.id, ref.id)
        finding.techniques = kept
        finding.mitigations = [m for m in finding.mitigations if graph.has(m.id)]
        for vuln in finding.vulnerabilities:
            if vuln.cwe and not graph.has(vuln.cwe):
                vuln.cwe = ""                        # clear an ungrounded weakness
```

Because this pass runs inside the analysis phase (order 30), the finding phases that run *after* it (brain 35, posture 37, defense 38) each validate their own identifiers before appending — so no finding, from either branch, reaches the report carrying an id absent from the graph.

**Figure 2.2 — the firewall pattern.**

```mermaid
flowchart LR
  MODEL["Claude proposes an id<br/>via a constrained tool"] --> CHECK{"in graph / in offered set?"}
  CHECK -- yes --> ADMIT["admit: add edge · select · keep"]
  CHECK -- no --> REJECT["reject + log"]
  ADMIT --> CLOSE{{"closing firewall — validate.py re-checks every id"}}
  REJECT --> CLOSE
  CLOSE --> REPORT["only grounded ids reach the report"]
```

> **Current-source flag.** The CVE-analysis touchpoint file (`engine/analysis/analyze.py`) is one of the files whose current source postdates this snapshot (the change concerns how a mitigation carries its framework, not the firewall). The firewall *mechanism* described here — selection constrained to offered ids, deterministic default on the run path — is stable; the line-level walk is in Part VI once the current source is in hand.

## 2.7 How the Two Branches Run and Combine Into One Report

The two branches are not merged by special logic. They combine because **every phase appends its findings to the same list on the shared context, in order**, and the report phase collects that list. The boundary between them is preserved not by a rule the code has to remember but by the *ordering*: Branch A's facts are already on the context before Branch B runs, and Branch B only appends.

- **Branch A — deterministic facts** — is produced by discovery (10) + graph (20) + the analysis CVE path (30) + posture (37). These findings are on `ctx.findings` with no model in the loop on the run path.
- **Branch B — reasoned conduct** — is produced by the brain (35), which grades the captured adversarial exchanges and appends behavioral findings. It reads facts and adds to them; it removes nothing.
- **The defense phase (38)** then attaches graph-grounded named defenses to *every* finding, from both branches, introducing only real mitigation nodes.

The report phase assembles all of it into one canonical record. The assembler collects the components, grains, findings, and kill chains straight off the context and stamps reproducibility provenance (engine version, ingested data versions, the runtime graph hash, and the probe log):

```python
def assemble(ctx):
    provenance = Provenance(tool_version=__version__,
                            source_versions=_source_versions(ctx),
                            graph_hash=str(ctx.artifacts.get("graph_hash", "")),
                            probe_log=list(ctx.artifacts.get("probe_log", [])))
    return Assessment(case_id=_case_id(ctx.config.engagement.case_prefix),
                      target_name=ctx.config.engagement.name,
                      provenance=provenance,
                      components=ctx.components, grains=ctx.grains,
                      findings=ctx.findings, kill_chains=ctx.kill_chains)
```

The `Assessment.as_dict()` is `assessment.json` — the single structure every renderer reads. The report phase writes each configured format into a per-case directory and, if requested, packages them:

```python
if "json" in formats:     # assessment.json (minus grains) + grains.json (separate)
if "markdown" in formats: # report.md
if "html" in formats:     # report.html
if "web_html" in formats: # report-brief.html
if "navigator" in formats:# navigator-layer.json
...
if config.output.package == "zip" and written:
    package_zip(written, <case>.zip, ctx.logger)
```

| Artifact | Format key | Contents |
|---|---|---|
| `assessment.json` | `json` | The canonical brief (case, provenance, summary, components, findings, kill chains) — grains excluded to keep it lean |
| `grains.json` | `json` | The full evidence-backed grain set, written alongside |
| `report.md` | `markdown` | The human-readable report |
| `report.html` | `html` | The full styled report |
| `report-brief.html` | `web_html` | The condensed web brief |
| `navigator-layer.json` | `navigator` | An ATT&CK-Navigator layer of the referenced techniques |
| `{case}.zip` | (package) | All written artifacts, when packaging is enabled |

**Why the through-line holds structurally.** Branch A's findings enter `ctx.findings` during phases 10–30 and are validated by the closing firewall at order 30. Branch B (35) and the deterministic finding phases (37, 38) run afterward and only *append* (and self-validate). No phase removes an entry another phase placed on `ctx.findings`. Therefore a model's judgment cannot drop or rewrite a Branch-A fact — the report presents both surfaces, with Branch A's deterministic facts intact and Branch B's reasoned findings and named defenses added on top. This is the through-line from Part I, made mechanical.

> **Current-source flag.** The defense phase's attachment logic (`engine/analysis/defense.py`) is extended in the current tree to attach weakness-grounded countermeasures (a bounded top-N attach over each finding's weaknesses). The invariant that matters here — *defense attaches only graph-grounded mitigation ids, and adds without gating or deleting* — is stable and is what §2.7 relies on. The line-level walk of the extended attachment is in Part VI once the current source is in hand.

*(End of Part II.)*

---

# Part III — Setup From Zero

This part takes a fresh checkout to a working, runnable engine. It assumes nothing beyond an operating system and the ability to run commands, and it spells out every step: the prerequisites, the install, the complete data setup — building every database the engine grounds against — and a validation pass that confirms the whole thing is assembled correctly. Every command is shown relative to the repository root; a leading `./` means a script in the repository, and `python` means the interpreter in the environment the launcher creates.

The one thing to internalize before starting, carried over from Parts I–II: **the engine ships without its datasets.** The code is the machine; the data is the fuel. Until the framework backbone, the vulnerability corpus and index, the distribution tracker, and the defense map are built, the graph phase has nothing to ground against and no assessment can run. Most of this part is therefore about building data correctly.

## 3.1 Prerequisites

| Requirement | Why | Notes |
|---|---|---|
| Python **3.10+** | The engine uses 3.10 syntax and is declared `requires-python = ">=3.10"` | `python3` must be on `PATH`; the launcher builds an isolated virtual environment for you |
| A POSIX shell + `curl` | The data-fetch scripts download the framework catalogs over HTTPS | `unzip` is needed to unpack the CWE catalog; `xz`/`unxz` to decompress the NVD feeds |
| A reachable model endpoint | The behavioral branch sends the adversarial corpus to a live model | The reference deployment targets a local **Ollama** runtime (an OpenAI-compatible endpoint) with at least one model pulled |
| *(Optional)* an Anthropic API key | Enables the four firewalled model touchpoints | The engine runs **keyless**: without a key it uses the deterministic fallbacks, and the entire infrastructure branch is model-free regardless |

The engine's runtime dependencies are deliberately few — the standard library does most of the work, and third-party packages are used sparingly. The declared dependencies are `pyyaml`, `jsonschema`, and `rich` for the core, plus `anthropic` for the model touchpoints. You do not install these by hand; the launcher does it (§3.2).

**A note on the target.** "Reachable model endpoint" means an OpenAI-compatible chat/completions endpoint the engine is authorized to test. In the reference deployment this is Ollama listening on its default local port, configured in `assessor.yaml` under `scope.in_scope` (§4). Pull at least one small model into the runtime before running the behavioral branch, or that branch will have nothing to talk to.

## 3.2 Install

There is no build step to run by hand. The convenience launcher, `run.sh`, creates a local virtual environment on first invocation, installs the dependencies, and re-syncs them automatically whenever the dependency list changes — then forwards its arguments to the engine's command-line interface.

```bash
# from the repository root, after cloning
./run.sh validate        # first run: builds .venv, installs deps, then validates config + packs
```

`validate` loads the configuration and the selected packs and prints a one-line summary **without touching any target**, so it is the safest possible first command — it proves the code and the packs are wired correctly before any data or any endpoint is involved. Under the hood the launcher runs the module form of the engine (`python -m engine …`); the packaging also exposes a console entry point (`psypher-assess`) if the package is installed with `pip install -e .`, but the launcher is the intended entry.

At this point the code is installed and runnable, but a real run will report that its graph sources are missing. That is expected — the next section builds them.

## 3.3 The Complete Data Setup

The engine grounds against several datasets, produced by standalone builders under `data/` (and one at the repository root). Each builder is standard-library-only, imports nothing from the engine, is deterministic, and reports its own coverage with a self-check. Build them in the order below; the dependency notes explain why the order matters.

| Step | Command (from repo root) | Builds | Lands at | Required? |
|---|---|---|---|---|
| 1. Framework backbone | `bash data/fetch.sh` | MITRE ATLAS, ATT&CK (Enterprise/ICS/Mobile), CWE | `data/atlas-data/`, `data/attack-stix-data/`, `data/cwe/` | **Yes** — the graph backbone |
| 2. CVE seed set | *(ships in the repository)* | curated seed CVEs | `data/cve/` | **Yes** — present already |
| 3. NVD corpus + index | `bash data/nvd-build.sh` | the full per-year NVD feeds + a SQLite product index | `data/nvd/CVE-*.json`, `data/nvd/index.sqlite` | **Yes** — the CVE candidate pool |
| 4. Distribution tracker + index | `curl -fsSL -o data/distro/debian.json https://security-tracker.debian.org/tracker/data/json`, then `python data/distro_index.py` | the distribution's authoritative per-package CVE status → SQLite | `data/distro/debian.json`, `data/distro/debian.sqlite` | **Yes** — the promotion authority |
| 5. KEV snapshot | `python data/kev_build.py` | the CISA KEV exploited-in-the-wild catalog | `data/kev/kev.json` | Optional — fail-open ranking input |
| 6. D3FEND technique map | grab the full-mappings export from D3FEND (`d3fend.mitre.org/resources/`, SPARQL-results JSON) → `data/d3fend/d3fend-full-mappings.json`, then `python data/d3fend_extract.py` | the ATT&CK→artifact→D3FEND countermeasure map | `packs/relevance/attack-artifact-map.json` | **Yes** — defense naming |
| 7. D3FEND CWE→countermeasure slice | `python build_d3fend_cwe_slice.py` | the weakness-grounded countermeasure slice | `data/d3fend/cwe-countermeasures.json` | **Yes** — weakness-grounded defenses |
| 8. Relevance role-groups | `python data/relevance_build.py` | the scoped, grounded role-group catalog | `packs/relevance/role-groups.yaml` | Regenerable — ships generated |

### Step 1 — the framework backbone

```bash
bash data/fetch.sh
```

`fetch.sh` pulls the bounded framework catalogs into `data/`: MITRE ATLAS (STIX) into `data/atlas-data/`, the three MITRE ATT&CK domains (Enterprise, ICS, Mobile, STIX) into `data/attack-stix-data/`, and the CWE catalog (XML) into `data/cwe/`. The CVE seed set is already present in `data/cve/`. These four locations are exactly the graph's configured sources (§2.4, §4), so this step is what gives the graph its `tactic`/`technique`/`mitigation`/`weakness` backbone. The script requires `curl` (and `unzip` for the CWE archive), tolerates any single source being unavailable (the engine builds from whatever is present), and downloads over TLS.

### Step 3 — the NVD corpus and product index

```bash
bash data/nvd-build.sh
```

This is the largest download. `nvd-build.sh` fetches every year of the NVD feed (2002 to the current year) from a public mirror, and — this is the non-negotiable part — **verifies each year's SHA256 against its published checksum before using it**, deleting and refusing to index any file that fails. It is idempotent and resumable: re-running skips years already downloaded and verified. It then invokes `data/nvd_index.py` to build `data/nvd/index.sqlite`, which indexes each CVE's CPE products and version ranges (plus its best-available CVSS score and its CWEs) so the engine can later match candidate CVEs to observed products. The builder prints honest coverage: total CVEs indexed, the fraction carrying a CPE product, and the distinct vulnerable-product count.

> **Invariant — the data builders verify integrity on fetch, and this is never relaxed.** The NVD builder fails hard on a checksum mismatch rather than indexing unverified data. This is a deliberate guarantee: the grounding is only trustworthy if the corpus behind it is exactly what the source published.

### Step 4 — the distribution security tracker

The infrastructure branch's central grounding decision — *is this CVE genuinely open on the installed package version?* — is answered by the distribution's own security tracker, not by a naïve product match. Build its index:

```bash
# acquire the tracker JSON (verified endpoint), then index it:
curl -fsSL -o data/distro/debian.json https://security-tracker.debian.org/tracker/data/json
python data/distro_index.py            # reads data/distro/debian.json → writes data/distro/debian.sqlite
```

`distro_index.py` flattens the tracker's per-package, per-release CVE status into a SQLite table of `(package, cve_id, release, status, fixed_version, urgency)` rows, indexed by package and release. This is what makes promotion **collision-free** (the distribution's package namespace matches the target's) and **backport-aware** (`fixed_version` is the distribution revision that actually carries the fix, so a patched-but-old version is not misflagged). It prints its coverage and a self-check row.

> **Setup note — the tracker JSON.** The Debian security-tracker publishes its full per-package, per-release status as a single JSON document at `https://security-tracker.debian.org/tracker/data/json` (≈30 MB, generated per request). Its structure — `package → CVE → releases → {status, fixed_version, urgency}` — maps exactly onto `distro_index.py`'s parse loop, so the `curl` above is the complete acquisition step. (This endpoint is confirmed current as of this writing; if Debian relocates it, the builder's contract is unchanged — place the tracker's JSON export at `data/distro/debian.json` and run the indexer.)

### Step 5 — the KEV snapshot (optional)

```bash
python data/kev_build.py               # writes data/kev/kev.json
```

`kev_build.py` fetches the CISA Known Exploited Vulnerabilities catalog into a compact local store that the promotion overlay reads to flag CVEs known to be exploited in the wild. Two properties matter. First, it is a **ranking input, never a filter**: a KEV entry is already a real CVE, so the store only records that it is actively exploited — it never hides a finding or invents an identifier. Second, promotion is **fail-open**: if `kev.json` is absent, promotion behaves exactly as before, degrading to CVSS-band priority. The builder verifies what it fetched with a structural check and a permanent-anchor check (a long-standing KEV entry must be present and the catalog must exceed a sane minimum size), and refuses to write a store that does not look like the real catalog.

### Step 6 — the D3FEND technique map

```bash
python data/d3fend_extract.py          # reads the D3FEND full-mappings export → writes packs/relevance/attack-artifact-map.json
```

`d3fend_extract.py` distills the large D3FEND mappings export into a compact map the engine carries in a pack: for each offensive ATT&CK technique, the offensive *digital artifacts* it touches, and for each artifact, the defensive D3FEND techniques that answer it (with parent-technique rollup for sub-techniques). This artifact-mediated map is what the D3FEND overlay (§2.3) composes into `mitigation` nodes and `mitigated_by` edges at runtime, and it is the basis for naming a defense for a finding. The extractor's own metadata notes that this map is ATT&CK-anchored (no ATLAS/CWE) — which is precisely why the weakness-grounded slice in Step 7 exists.

> **Setup note — the D3FEND full-mappings export.** `d3fend_extract.py` reads `data/d3fend/d3fend-full-mappings.json`, a large (~40 MB) SPARQL-results export whose rows follow the `{ "results": { "bindings": [ … ] } }` shape (the extractor reads each row as `row[key]["value"]`). Obtain it from the MITRE D3FEND project — the resources page at `https://d3fend.mitre.org/resources/` offers the ontology/mapping downloads, and the D3FEND public API / SPARQL endpoint returns the same bindings format for the full attack→artifact→defense mappings. Save it at the path above and run the extractor. Because MITRE periodically reorganizes its export locations, confirm the current download on the resources page rather than hardcoding a link; the extractor and its output contract are unchanged regardless. The same export also feeds Step 7 (`build_d3fend_cwe_slice.py`), so it is downloaded once.

### Step 7 — the D3FEND CWE→countermeasure slice

```bash
python build_d3fend_cwe_slice.py       # → data/d3fend/cwe-countermeasures.json
```

The technique map from Step 6 answers offensive *techniques* with defenses, but a distribution-promoted CVE surfaces with its *weakness* (CWE), not always an ATT&CK technique. This step builds a weakness-grounded slice — a `CWE → countermeasure` map — so a finding that carries only a CWE can still be answered by a named D3FEND countermeasure. At runtime this slice is composed onto the finished graph as an additional overlay, reusing the existing `mitigation` node and `mitigated_by` edge types (it introduces no new node or edge type), and the defense phase attaches the resulting countermeasures.

> **Current-source flag.** The builder `build_d3fend_cwe_slice.py` and the pinned output `data/d3fend/cwe-countermeasures.json` are the weakness-grounded defense layer that postdates the snapshot this part was written against. This section documents the step's *purpose and place in the setup* from the layer's own record; the exact builder inputs, command flags, and output schema are documented at line level once the current source is in hand (see the setup flags in Part II and the Part VI plan). Treat this step as required for weakness-grounded defenses; confirm its exact invocation against the current builder.

### Step 8 — the relevance role-groups

```bash
python data/relevance_build.py         # → packs/relevance/role-groups.yaml
```

`relevance_build.py` emits the catalog that lets promotion **scope** the CVE flood to what matters on an AI-serving host — the serving stack, the isolation boundary, and the crypto/network/auth exposure — rather than drowning the report in every installed desktop package. It is agnostic by construction (role-groups key on upstream *project-name* patterns that are stable across distributions, and are defined by what a component *does*, never by vendor or distro) and grounded by construction (every technique it references is validated against the built graph and dropped if absent, and every D3FEND artifact it anchors to is validated against the technique map). Because it reads the built graph (`build/graph/nodes.json`) and the artifact map, it must run **after** the framework backbone is fetched, after an initial run has built and cached the graph (§3.4), and after Step 6. It ships already generated, so this step is only needed if you change the seed or regenerate; the emitted YAML is also hand-editable.

> **Dependency order, summarized.** Steps 1–3 and 5 are independent downloads. Step 4 needs its tracker export; Step 6 needs its mappings export; Step 7 builds on the D3FEND data; Step 8 needs the graph built once (§3.4) and Step 6's map. A practical sequence: 1 → 3 → 4 → 5 → 6 → 7 → *(initial run to build the graph, §3.4)* → 8.

## 3.4 Validating the Whole Setup

With the code installed and the data built, confirm the assembly before trusting a real run. Three levels, from cheapest to most thorough.

**1. Configuration and packs load (no target, no data required).**

```bash
./run.sh validate
```

Prints the engagement name, the count of in-scope assets, and the number of enabled probes. A failure here is a configuration or pack error and is caught before anything else.

**2. Internals self-check (no target, no model, no key).**

```bash
./selfcheck.sh
```

This runs the engine's internal test suite and its verifiers without touching a target or a model: the assembled-pipeline system test; the label-grounding check (which confirms the corpus and posture technique ids resolve against the graph and prints the loaded ATLAS version); the static, probe, and source drift verifiers; and a final config-and-pack load. A clean run reports that the engine is on a verified baseline. *(The exact number of checks in the system test is read from the source and enumerated in Part VI; the self-check groups them into the stages above.)*

**3. Bounded, local-only end-to-end smoke (optional).**

```bash
RUN_E2E=1 ./selfcheck.sh
```

This adds a bounded, deterministic end-to-end run with the model touchpoints off, hitting only your local model endpoint, using a two-attack corpus and a hard timeout so it cannot grind the local model. It then prints the resulting assessment's summary (finding count, severity breakdown, referenced frameworks). This is the fastest way to confirm the full pipeline produces a grounded assessment end to end.

**Confirming the data took.** Two direct checks:

- **The graph builds.** The first full run (or the bounded E2E above) triggers the graph phase, which logs `built knowledge graph (N nodes, M edges, hash …)` and writes `build/graph/{nodes,edges,meta}.json`. A healthy node count that includes techniques and vulnerabilities means the framework sources ingested. Remember (§2.3) that this cached file is the *pre-overlay* graph; the runtime graph additionally carries the promotion and D3FEND overlays.
- **The builders self-reported.** Each data builder printed a coverage line and an anchor self-check as it ran (NVD's product coverage, the tracker's release list and a known row, KEV's anchor entry, the D3FEND extractor's spot-check, the relevance builder's grounding report). A builder that printed a `NEEDS FIX` or refused to write is telling you a source was wrong before it can corrupt a run.

Once `validate` is clean, `selfcheck.sh` reports a verified baseline, and the graph builds with a sensible node count, the engine is set up. Part IV covers configuring it for a specific engagement; Part V covers running it and reading what it produces.

*(End of Part III.)*

---

# Part IV — Configuration

Everything an operator changes to shape a run lives in one YAML file, `assessor.yaml` — the engagement control plane — plus a small number of pack files it points at (the policy profile, the probe catalog, the intake questionnaire, the source catalog). This part documents every configuration key: what it controls, whether it is required, its default, and its allowed values, followed by the worked configurations that tie them together. The authority for all of it is `engine/core/config.py`, which loads and **strictly** validates the control plane.

The governing principle to keep in mind: the loader never assumes a default for required policy. A missing or malformed field raises a `ConfigError` with an actionable message naming the exact section and key, rather than silently proceeding on a guess. This is deliberate — a security tool that quietly filled in a missing scope or an unset allowlist would be dangerous. Run `./run.sh validate` after any edit to catch mistakes before they reach a target.

## 4.1 The Control Plane (`assessor.yaml`), Key by Key

The control plane has seven top-level sections. The vocabularies the validator enforces are fixed sets:

- **Access tiers:** `black`, `gray`, `host`
- **Probe tiers:** `passive`, `active_safe`, `intrusive`
- **Graph source formats:** `stix`, `json`, `xml`, `ttl`, `yaml`
- **Output formats:** `json`, `html`, `navigator`, `markdown`, `web_html` *(note: no PDF)*
- **Package formats:** `zip`, `none`

Every key, with its requirement, default, and validation:

| Section | Key | Required | Default | Validation / options |
|---|---|---|---|---|
| `engagement` | `name` | yes | — | string; used as the target name and report title |
| | `case_prefix` | yes | — | string; case ids are `PREFIX-YYYYMMDD-<6hex>` |
| | `operator` | yes | — | string; attribution on the report |
| `scope` | `in_scope` | yes | — | non-empty list of **assets** (below) |
| | `out_of_scope` | no | `[]` | list of strings |
| *asset* | `id` | yes | — | string |
| | `kind` | yes | — | string (e.g. `inference_endpoint`) |
| | `access` | yes | — | one of `black` / `gray` / `host` |
| | `endpoint` | no | `null` | the target URL (e.g. the model endpoint) |
| | `host` | no | `null` | host reference for host-level probes |
| | `ssh` | no | `null` | SSH reference for host-level probes |
| | `auth_env` | no | `null` | **name** of an env var holding a credential (never the value) |
| `probes` | `packs` | yes | — | non-empty list of probe-pack directories to load |
| | `tiers` | yes | — | mapping; keys must be valid tiers; each is `{enabled: bool, require_approval: bool}` |
| | `allowlist` | yes | — | non-empty list of probe ids — **this is the gate** (§4.5) |
| `intake` | `questionnaire` | no | `{}` | path to an intake pack (§4.4) |
| `model` | `provider` | yes | — | string (`anthropic`) |
| | `recon_model` | yes | — | model id; env-overridable (§4.4) |
| | `analysis_model` | yes | — | model id; env-overridable |
| | `review_model` | yes | — | model id; env-overridable |
| | `api_key_env` | yes | — | **name** of the env var holding the API key |
| `graph` | `store` | yes | — | directory for the cached graph (e.g. `build/graph`) |
| | `enrich` | no | `false` | bool; enable model-proposed cross-framework edges |
| | `sources` | yes | — | non-empty list of `{id, path, format}`; format in the source set |
| `output` | `dir` | yes | — | directory for case artifacts (e.g. `assessments`) |
| | `formats` | yes | — | list; every entry must be a valid output format |
| | `package` | no | `"zip"` | `zip` or `none` |

Two of the files the control plane relates to — the probe catalog (`packs/probes/probes.yaml`) and the source catalog (`packs/data/sources.yaml`) — **document but do not authorize**. The authoritative gate is always in `assessor.yaml` (`probes.allowlist` and `graph.sources` respectively), and the drift verifiers (`tests/verify.py --mode probes` / `--mode sources`) assert the catalogs and the control plane agree, so documentation cannot silently diverge from the gate.

## 4.2 Engagement and Scope

**Engagement** is identity: `name` becomes the assessed target's name in the report, `case_prefix` seeds each run's case id (`PREFIX-YYYYMMDD-<6hex>`, unique and sortable), and `operator` is the attribution recorded on the output.

**Scope** is the boundary — and it is enforced. The harness only ever interrogates the assets listed under `in_scope`; there is no discovery outside it. Each asset declares:

- **`kind`** — what the asset is (for example, `inference_endpoint`).
- **`access`** — the engagement's declared reach against that asset: `black` (network-only, black-box), `gray` (partial access), or `host` (host-level access). This is the intended reach; probes declare a `min_access` and are gated so that a probe needing more access than the asset grants is not run against it (the exact gating is in the loader/harness; Part VI). Higher access unlocks the host-isolation probes; a black-box asset limits the run to what is observable over the endpoint.
- **`endpoint`** — the target URL. For the reference deployment this is the OpenAI-compatible model endpoint (the behavioral branch talks to it; several infrastructure probes read it).
- **`host` / `ssh`** — how host-level probes reach the serving host, when the access tier permits.
- **`auth_env`** — the **name** of an environment variable that holds any credential the asset needs. The value is never written in the config; only the variable name is (see the credential rule in §4.4).

## 4.3 Policy Profiles and What Each Does

The policy profiles under `packs/policy/` are the **Branch B safeguard profiles** — the tunable "constitution" the behavioral brain reasons against. They govern how much the brain is allowed to predict and how conservative it must be, and they are the mechanism behind one of the system's core guarantees. A profile has five sections:

| Section | Key | Meaning |
|---|---|---|
| `grounding` | `min_grains_for_possible` | minimum supporting grains before a "possible" finding may exist (**floored** — see below) |
| `prediction` | `enable_structural` | Pass 1: graph-edge reachability inference |
| | `enable_posture_inference` | Pass 2: evidence-leashed posture findings |
| | `enable_behavioral` | judge the adversarial (red-team) exchanges |
| | `max_inference_depth` | how far structural inference may walk |
| `confidence` | `min_confidence_to_report` | floor on a finding's confidence (`low`/`medium`/`high`) |
| | `possible_findings_require_label` | a "possible" finding must be labeled as such |
| `severity` | `cap_possible_at` | a "possible" finding's severity is capped here (can't be reported `critical`) |
| `scope` | `domains` | which framework domains Pass 2 may reason over (e.g. `enterprise`, `atlas`) |

The three shipped profiles differ only on the **sensitivity** axis:

| Profile | `min_confidence_to_report` | `max_inference_depth` | Posture "possible" findings | Intended use |
|---|---|---|---|---|
| `strict` | `medium` | 1 | conservative | formal reports — only proven / high-signal findings |
| `strict-posture` | `medium` | 1 | posture inference on, conservative depth | formal reports emphasizing posture |
| `exploratory` | `low` | 2 | wider, evidence-leashed | research — surface more, still grounded |

**Selecting a profile.** The active profile is resolved by `load_policy` in this order: an optional `config.analysis.policy` value (a defensive hook — the reference control plane defines no `analysis` section, so this is normally unused), then the `PSYPHER_POLICY` environment variable, then the default `packs/policy/strict.yaml`. A **bare profile name resolves to a path**: `PSYPHER_POLICY=exploratory` is resolved to `packs/policy/exploratory.yaml`; a value ending in `.yaml`/`.yml` or naming an existing file is used as-is. If the resolved file is missing or fails to load, the loader falls back to the built-in strict defaults and logs it — so the brain always runs and always errs safe.

> **Invariant — the policy integrity floor is un-disableable by config.** A profile can be tuned freely toward *more* sensitivity or *stricter* integrity, but the integrity guarantees cannot be turned off. After any profile is loaded, `_enforce_floor()` re-imposes them unconditionally:
> ```python
> def _enforce_floor(self) -> "Policy":
>     self.require_supporting_grains = True     # a finding must cite real grains
>     self.drop_unvalidated_ids = True          # ids must exist in the graph
>     if self.min_grains_for_possible < 1:
>         self.min_grains_for_possible = 1      # >= 1 always
>     return self
> ```
> No configuration — not even a hand-edited profile setting `min_grains_for_possible: 0` — can make the brain report an ungrounded or grain-less finding. This floor is what protects the tool's credibility, which is why it lives in code and not in the tunable file.

## 4.4 Model and Target Selection

**The model section** selects the language model for the four firewalled touchpoints, by role, and names the credential variable:

- `provider` — the model provider (`anthropic`).
- `recon_model`, `analysis_model`, `review_model` — the model id per role. Each is **required in the YAML as the floor**, but overridable at runtime by environment variables, so a per-shell picker can change models without editing the config. The precedence is: a per-role variable (`PSYPHER_RECON_MODEL` / `PSYPHER_ANALYSIS_MODEL` / `PSYPHER_REVIEW_MODEL`) › the global `PSYPHER_CLAUDE_MODEL` (overrides every role at once) › the YAML value. The sourced picker sets `PSYPHER_CLAUDE_MODEL` to switch all roles in one shell.
- `api_key_env` — the **name** of the environment variable that holds the API key (default `ANTHROPIC_API_KEY`). The engine reads the key from that variable at the touchpoint; it is never stored in the config.

> **Rule — credentials come from an environment variable, never inline.** The sourced key helper prompts for the key with input hidden, exports it under the configured variable name, and confirms only its length — the value is never printed or written to disk. Any `auth_env` on an asset works the same way. If a key is ever exposed, rotate it.

**Keyed vs keyless.** With the key present, the four touchpoints operate (recon selection, enrichment, CVE analysis, behavioral judge). With **no key**, the engine still runs: enrichment is skipped (structural graph only), the behavioral judge falls back to its deterministic grader, and the entire infrastructure branch is model-free regardless of the key. A keyless run is a first-class mode, not a degraded one — it simply produces the deterministic subset.

**The target** is the in-scope asset(s) from §4.2 — the `endpoint` is the model URL the behavioral branch talks to and that several infrastructure probes read; `host`/`ssh` give host-level probes their reach.

**Intake.** `intake.questionnaire` points at a pack (for example `packs/intake/ollama.yaml`) of operator-supplied facts that no probe can reach — the deployment environment, whether tenants are isolated, where model checkpoints come from, what serves the model. Each answered question becomes a grain on the `engagement` component with its stated confidence, and is available to analysis exactly like a probed fact. This is how ground truth an operator already knows (for example, "checkpoints are not pinned by digest") enters the assessment.

## 4.5 Probes and Their Tiers

**The allowlist is the gate.** `probes.allowlist` is the authoritative list of which probes may run; the sealed loader enforces it, and a probe absent from the allowlist does not execute regardless of what any catalog says. The catalog (`packs/probes/probes.yaml`) is a human-facing inventory that documents every probe's surface (`infra` / `behavioral` / `embeddings`) and kind (`analysis` descriptor vs `code` module) but authorizes nothing; `tests/verify.py --mode probes` asserts the catalog's enabled set matches the allowlist so the two never drift.

**Tiers gate by risk.** Every probe has a tier, and `probes.tiers` sets the execution policy for each:

- `passive` — observation only; safe to run broadly.
- `active_safe` — active but non-disruptive.
- `intrusive` — potentially disruptive; **shipped disabled and approval-gated.**

Each tier entry is `{enabled: bool, require_approval: bool}`, both defaulting to `false`. In the reference control plane, `passive` and `active_safe` are enabled and `intrusive` is `{enabled: false, require_approval: true}`.

> **Safety default — the intrusive tier is off by default and approval-gated.** Intrusive probes are the ones that could perturb a live system, so they are disabled in the shipped configuration and additionally carry `require_approval`. Enabling them is a deliberate, per-engagement decision, and the approval gate is a second barrier on top of the enable flag. Credential-related probes are name/path-only by design (they report the *presence* of a credential path or env-var name, never a secret's value), and the black-box probe stays fenced.

**`probes.packs`** lists the probe-pack directories to load. The reference set spans the infrastructure surfaces (ml-inference, host-isolation, model-endpoint, model-artifact) and the behavioral surface (model-redteam). The reference allowlist, grouped by what it covers:

| Surface | Allowlisted probes (reference) |
|---|---|
| Model endpoint / serving | `api_banner`, `endpoint_banner`, `unauth_inference`, `mgmt_exposed`, `model_digest`, `listening_sockets` |
| ML runtime / packages | `pip_freeze`, `os_packages`, `detect_virt`, `embedding_probe` |
| Host isolation | `host_hypervisor_dmi`, `container_runtime`, `process_capabilities`, `syscall_filtering`, `mac_confinement`, `docker_socket`, `cred_env_names`, `world_readable_secrets` |
| Model artifact | `model_artifact_scan` |
| Behavioral | `rt_prompt_injection` |

Adding a probe to a run is a two-part edit: it must be present in a loaded pack (and pass schema validation), and its id must be in the allowlist. Part VII gives the full procedure.

## 4.6 Output Formats

`output` controls what a run emits. `formats` is a list drawn from the fixed set — an unsupported value (including `pdf`, which no renderer implements) is rejected at load. Each format maps to a specific artifact written into the per-case directory under `output.dir`:

| `formats` entry | Artifact(s) written | Contents |
|---|---|---|
| `json` | `assessment.json` + `grains.json` | the canonical brief (grains split into their own file) |
| `markdown` | `report.md` | the human-readable report |
| `html` | `report.html` | the full styled report |
| `web_html` | `report-brief.html` | the condensed web brief |
| `navigator` | `navigator-layer.json` | an ATT&CK-Navigator layer of the referenced techniques |

`package` (`zip` or `none`) controls whether the written artifacts are additionally bundled into `{case}.zip`. `dir` is the root under which each run creates a subdirectory named by its case id. A run always writes an assessment even with zero findings, so a configured run always yields an auditable artifact.

## 4.7 Worked Example Configurations

**A. The reference engagement — a local model endpoint, both surfaces, keyed.** (Values that would identify a host are shown as placeholders.)

```yaml
engagement:
  name: "ollama-local"
  case_prefix: "CASE"
  operator: "operator@example.org"

scope:
  in_scope:
    - id: "target"
      kind: "inference_endpoint"
      access: "gray"
      endpoint: "http://localhost:11434"
      ssh: "user@target-host"
  out_of_scope: []

probes:
  packs:
    - "packs/probes/ml-inference"
    - "packs/probes/model-redteam"
    - "packs/probes/host-isolation"
    - "packs/probes/model-endpoint"
    - "packs/probes/model-artifact"
  tiers:
    passive:     { enabled: true }
    active_safe: { enabled: true }
    intrusive:   { enabled: false, require_approval: true }
  allowlist:
    - "api_banner"
    - "pip_freeze"
    - "os_packages"
    - "container_runtime"
    - "unauth_inference"
    - "rt_prompt_injection"
    # ... (the full reference allowlist, §4.5)

intake:
  questionnaire: "packs/intake/ollama.yaml"

model:
  provider: "anthropic"
  recon_model: "claude-haiku-4-5-20251001"
  analysis_model: "claude-haiku-4-5-20251001"
  review_model: "claude-haiku-4-5-20251001"
  api_key_env: "ANTHROPIC_API_KEY"

graph:
  store: "build/graph"
  enrich: true
  sources:
    - { id: "atlas",  path: "data/atlas-data",       format: "stix" }
    - { id: "attack", path: "data/attack-stix-data", format: "stix" }
    - { id: "cve",    path: "data/cve",              format: "json" }
    - { id: "cwe",    path: "data/cwe",              format: "xml"  }

output:
  dir: "assessments"
  formats: ["json", "html", "navigator", "markdown", "web_html"]
  package: "zip"
```

**B. Keyless, strict, formal report.** Use the same file with `graph.enrich: false` (enrichment needs a key), and run without a key and with the strict profile:

```bash
# no ANTHROPIC_API_KEY set → deterministic subset; strict is the default profile anyway
PSYPHER_POLICY=strict ./run.sh run
```

This produces the deterministic infrastructure branch, the deterministic behavioral judge, conservative prediction, and the closing firewall — an auditable, reproducible report with no model in the loop.

**C. Exploratory research run.** Same file, wider prediction, still floored:

```bash
source setkey.sh                 # supply the key (hidden)
PSYPHER_POLICY=exploratory ./run.sh run
```

`exploratory` lowers the confidence floor and widens inference depth so more evidence-leashed "possible" findings surface — while the integrity floor (§4.3) still forbids anything grain-less or ungrounded.

**How configuration flows into behavior.** The pieces compose predictably: an in-scope asset's `access` tier plus the enabled `tiers` plus the `allowlist` decide *which probes run and against what*; `intake` seeds ground-truth grains; the `model` section and the key/env decide *whether the touchpoints reason or fall back*; `PSYPHER_POLICY` decides *how boldly the brain predicts* (within the floor); `graph.sources` and `graph.enrich` decide *what the grounding graph is built from*; and `output.formats`/`package` decide *what artifacts land on disk*. Change one, run `./run.sh validate`, and the effect is confined to exactly that stage.

*(End of Part IV.)*

---

# Part V — Running & Reading

Configuration decides *what* a run does; this part covers *doing* it and *reading* what it produces. It walks the commands and options, how to supply a key safely, what each phase is doing while it runs, every artifact a run writes and every part of the report, and — importantly — why a field may legitimately be empty. That last point is a feature, not a gap: Psypher labels honestly and never over-claims, so an empty field is a documented coverage boundary rather than a silent failure.

## 5.1 Running an Assessment: Commands, Options, Keyed vs Keyless

The launcher is the entry point. On first use it builds the isolated environment and installs dependencies; thereafter it just runs.

```bash
./run.sh run                 # run a full assessment using assessor.yaml
./run.sh validate            # validate config + packs without touching any target
./run.sh run -c other.yaml   # use a different control plane
./run.sh run -v              # debug-level logging
./run.sh run -q              # warnings and errors only
./run.sh run --no-banner     # suppress the startup banner
```

All arguments after `run.sh` are forwarded to the engine's command-line interface. The two subcommands are `run` (execute the pipeline) and `validate` (load and check the configuration and packs, print a one-line summary, touch nothing). The global options are `-c/--config` (default `assessor.yaml`), `-v/--verbose`, `-q/--quiet`, `--no-banner`, and `--version`. The process exits `0` on success, `2` on a configuration error (with an actionable message), and `130` on interruption.

**Keyed vs keyless.** Both are first-class modes:

- **With a key** (the variable named by `model.api_key_env` is set), the four firewalled touchpoints operate: recon selects probes, enrichment proposes cross-framework edges, the CVE-analysis touchpoint is available, and the behavioral judge grades with the model.
- **Without a key**, the engine runs the deterministic subset: enrichment is skipped (structural graph only), the behavioral judge falls back to its deterministic grader, and the **entire infrastructure branch is model-free regardless**. A keyless run is complete and reproducible — it simply omits the model-reasoned additions.

**Selecting the target.** There is no target flag. The target is the in-scope asset(s) declared in the control plane (§4.2) — the `endpoint` the behavioral branch talks to and that infrastructure probes read, plus the `host`/`ssh` reach for host-level probes. To assess a different target, edit `scope.in_scope` or point `-c` at a different control plane. This keeps the engagement boundary in one auditable file rather than in shell history.

## 5.2 Supplying a Key Safely

When you want the keyed touchpoints, supply the key through the environment, never inline:

```bash
source setkey.sh       # prompts with input hidden; exports the configured var; confirms only its length
source setmodel.sh     # additionally picks the model (sets it for every role this shell), then sources setkey.sh
```

Both scripts **must be sourced** (not executed) so the exported variable persists in your shell. `setkey.sh` reads the variable name from the control plane (`model.api_key_env`, default `ANTHROPIC_API_KEY`) so it always matches what the engine reads, prompts with the input hidden, exports it, and prints only the key's length — never its value. `setmodel.sh` first lets you choose the model (setting `PSYPHER_CLAUDE_MODEL`, which overrides every role for the shell), then sources the key helper. The key lives only in the process environment for the session; it is never written to the config or to disk. If a key is ever exposed, rotate it.

## 5.3 What Each Phase Is Doing As It Runs

With default logging, the engine narrates its progress to stderr. Knowing what each phase does — and the line it logs — lets an operator follow a run:

| Order · Phase | What it does at runtime | Representative log line |
|---|---|---|
| 10 · discovery | Selects the permitted probes (model-guided if keyed, else exhaustive) and runs them against each in-scope asset, turning output into evidence-backed grains and a component inventory; folds in the intake questionnaire | `discovering asset 'target' (inference_endpoint, gray access)` → `discovery complete: N component(s), M grain(s)` |
| 20 · graph | Builds the graph from the configured sources (or loads the cache), optionally adds model-proposed edges, then applies the promotion and D3FEND overlays on the finished graph | `built knowledge graph (N nodes, M edges, hash …)` or `loaded cached knowledge graph (…)` |
| 30 · analysis | Matches CVE candidates against the grains, judges them into findings (deterministic on the run path), sequences a kill chain, and runs the closing identifier firewall | `analysis complete: N finding(s), M kill-chain step(s)` (plus any `validation dropped …` lines) |
| 35 · brain | Grades the captured adversarial exchanges into behavioral findings (model judge if keyed, deterministic grader otherwise); self-validates technique ids | (behavioral grading progress; keyless runs note the deterministic grader) |
| 37 · posture | Maps observed host-isolation/endpoint state to technique-anchored findings; deterministic | (posture findings appended) |
| 38 · defense | Attaches graph-grounded named defenses to every finding; deterministic | (defense attachment) |
| 40 · report | Assembles the canonical assessment, writes each configured format, packages the case archive | `report assembled: case … (N finding(s)), K artifact(s)` → `CASE PACKAGE: …zip` |

Because the phases communicate only through the shared context (Part II), a run is easy to reason about: each line marks one stage handing its results to the next.

## 5.4 Reading the Output: Every Artifact and Every Part of the Report

A run writes everything into a per-case directory under `output.dir` (for example `assessments/CASE-YYYYMMDD-abc123/`), plus a sibling archive:

| Artifact | Written when | Contents |
|---|---|---|
| `assessment.json` | `json` format | the canonical brief: `case`, `provenance`, `summary`, `components`, `findings`, `kill_chains` |
| `grains.json` | `json` format | the full evidence-backed grain set (split out to keep the brief lean) |
| `report.md` | `markdown` format | the human-readable report (below) |
| `report.html` | `html` format | the full styled report — same information architecture as the markdown |
| `report-brief.html` | `web_html` format | the condensed web brief |
| `navigator-layer.json` | `navigator` format | an ATT&CK-Navigator layer (below) |
| `exchanges.jsonl` | when behavioral probes ran | the per-case hash-chained evidence log (below) |
| `{case}.zip` | `package: zip` | all written artifacts, flat by name |

**`assessment.json` — the canonical record.** Every renderer reads this one structure. Its `provenance` block carries the engine version, the ingested data versions, the runtime graph hash, and the probe log — the reproducibility anchor. Its `summary` gives the total finding count, the severity breakdown, and the set of frameworks referenced. Its `findings` are the substance; each finding carries an id, component, title, severity, confidence, its `techniques` (framework · id · name, each stamped `validated`), its `vulnerabilities` (`cve`, `cwe`, `cvss`, `mechanism`, and `confirmed_by` — the tracker that confirmed it), its `mitigations` (the named defenses, by framework · id), an `attack_path`, and a free-form `evidence` map. `kill_chains` sequence the referenced techniques into ordered steps.

**The report (`report.md` / `report.html`).** The renderers present that data with a fixed information architecture:

1. **A forensic metadata header** — case id, target, model under test, operator, engine version, creation time, graph hash, graph-source versions, finding and severity totals, the surface split (infrastructure vs behavioral), and the evidence-chain verification command.
2. **A legend** distinguishing **PROVED** (a version-confirmed CVE or a demonstrated model compliance) from **ASSUMED** (a backport-unconfirmed lead or a reachable-by-inference posture finding). Findings are ordered **act-now first**.
3. **Two surfaces, as sections:**
   - **Infrastructure — CVE and host-isolation posture** (Branch A). Each finding shows its `CVE · CWE · CVSS`, a **CISA KEV "actively exploited"** line when the vulnerability is on KEV (with the date added and any ransomware linkage, flagged act-now), its mechanism, and — when the distribution backport status is unconfirmed — a `Lead:` line rather than an over-claim.
   - **Behavioral — the model under adversarial input** (Branch B). Each finding shows its technique (framework · id · name) and the **verdict** (comply / refuse / partial / confabulate).
   - Each finding, on either surface, is headed `SEVERITY · PROVED|ASSUMED · title`, followed by a **Defense:** block of graph-grounded MITRE countermeasures grouped ATLAS → ATT&CK → D3FEND (or an explicit "no countermeasure mapped" line), an **Evidence:** block, and a one-line provenance stamp.

The `evidence` map on a finding is the detail an analyst drills into; the report renders it in a fixed order, and the key fields are:

| Field | Meaning |
|---|---|
| `match` | how the finding was reached (e.g. `behavioral`, `assessed-possible`, a CVE match basis) |
| `grade` | `demonstrated` (proved behavioral) or an inference grade |
| `verdict` | the behavioral verdict (comply / refuse / partial / confabulate) |
| `version_confirmed` / `verify_distro_patch` | whether the installed version was confirmed vulnerable, or the backport status is a lead to verify |
| `exploited` / `priority` / `kev_date_added` / `kev_ransomware` | KEV exploited-in-the-wild signals and the resulting priority |
| `access_tier` / `method` / `observed_version` | how and at what access the fact was observed |
| `target_model` | the model under test |
| `exchange_id` | the link into the evidence log for a behavioral finding |
| `supporting_grains` / `match_basis` / `rationale` | the grounding and reasoning behind the finding |

**`navigator-layer.json`.** A layer directly loadable into the MITRE ATT&CK Navigator: each **enterprise** technique is scored by the highest severity among the findings that cite it and annotated with the responsible component and CVEs. ATLAS (`AML.*`) techniques are recorded in the findings but omitted from this layer, because the Navigator's enterprise domain does not contain them.

**`exchanges.jsonl` — the evidence log.** Every behavioral exchange (and its later verdict) is written here as an append-only, hash-chained record: each line carries a monotonic `seq` and the `prev_hash` of the previous record, so any edit, reorder, or deletion breaks the chain and is detectable. Exchange records hold the exact prompt, response, the safe-token canary and whether it was hit, latency, and model metadata; verdict records link back by `exchange_id`. Verify the chain with `python -m tests.verify --mode audit`. Every behavioral finding in the report cites its `exchange_id`, so any verdict can be traced to the exact captured exchange that justifies it. The same records are also written to a global corpus log across runs.

> **Current-source note.** The **Defense:** section renders each finding's named countermeasures. The set of findings that receive a named defense is broadened in the current tree by the weakness-grounded D3FEND CWE→countermeasure layer (so a promoted CVE with only a CWE can still be answered by a named countermeasure). The renderers themselves are unchanged; what changes is how many findings carry a mapped defense. The line-level walk of that layer is in Part VI once its current source is in hand.

## 5.5 Why a Field May Legitimately Be Empty (The Honest Coverage Ceilings)

Psypher's guarantee is that it never fabricates. The direct consequence is that when the data does not support a claim, the tool says so rather than inventing one. These are the empty states you may legitimately see, and what each means:

- **"No findings on this surface."** One surface produced nothing. A hardened stack may yield no infrastructure findings; a well-aligned model may yield no behavioral ones; and a black-box (`access: black`) asset limits how much of the infrastructure is observable in the first place. An empty surface is a result, not an error.
- **"No MITRE countermeasure mapped for this technique."** The finding has no named defense. The D3FEND map is ATT&CK-anchored, so behavioral ATLAS findings and CWE-only promoted CVEs may not receive a named defense. The weakness-grounded CWE→countermeasure layer (current tree) narrows this for promoted CVEs that carry a CWE; a residual ceiling remains for ATLAS-only behavioral findings pending an ATLAS→ATT&CK bridge.
- **A finding marked ASSUMED, or shown as a `Lead:`.** A distribution-promoted CVE whose backport status could not be confirmed is labeled ASSUMED and presented as a lead to verify — deliberately not over-claimed as a confirmed exposure.
- **A CVE finding with no technique.** A promoted CVE carries its CWE and CVSS but may not carry an `enables → technique` edge, so it legitimately surfaces as a grounded CVE/CWE/CVSS finding without an ATLAS/ATT&CK technique.
- **No KEV / exploited signals.** If the KEV snapshot is absent, promotion is fail-open: priority degrades to the CVSS band and no exploited flags appear. This is by design, not a missing feature.
- **No enrichment edges, deterministic verdicts.** A keyless run omits the model-proposed cross-framework edges and uses the deterministic behavioral grader — a smaller but fully grounded result.
- **Zero findings overall, but an assessment still written.** If the datasets are absent (the graph has nothing to build from) or nothing matched the observed components, the run still produces a provenance-stamped assessment with no findings — an auditable statement that nothing was found under those conditions.
- **ATLAS techniques absent from the Navigator layer.** By design (above), the enterprise-domain layer omits `AML.*` techniques even though they are present in the findings and the report.

The unifying principle: every empty field traces to a stated coverage boundary — a surface with nothing to report, a defense vocabulary that does not yet reach a technique class, an unconfirmed backport, an absent optional dataset, or a keyless mode — and never to a silent drop. The closing firewall and the honest-labeling conventions are what make an empty field trustworthy.

*(End of Part V.)*

---

# Part VI — The Code, Piece by Piece

This is the line-level walk of the system. It proceeds in the order of the repository map: the sealed core first (the framework), then the pipeline phases in execution order (discovery → graph → analysis → report) with `relevance` alongside analysis, then the packs, then the data builders and ops. For each file it explains what the code does, how it works internally — the key functions, the branches, the edge cases, with real code shown where the code is the point — what it takes and produces, how it connects to the rest of the flow, and what invariant or firewall it enforces. Every file in the repository map is covered; the map's per-file markers track coverage as this part proceeds.

A note on the five files whose current source postdates this snapshot (`engine/analysis/{analyze,match,defense}.py`, `engine/graph/{d3fend,phase}.py`, plus `build_d3fend_cwe_slice.py` and the data slice it produces): the weakness-grounded defense delta is localized to specific regions of each file, so those files are documented in full from the source in hand, and the specific added regions are marked precisely at the point they occur — the mitigation-framework unpack sites, the CWE→countermeasure overlay, and the top-N weakness attach loop. Nothing else in those files is affected.

## 6.1 The Sealed Core (`engine/core/`, plus the package entry points)

The core is the stable contract surface. It knows how to execute probes, thread state, validate against schemas, load prompts, and record evidence — and it names no concrete probe, attack, CVE, framework, or phase. Capability lives in packs and phases (§6.6, §6.2–6.5); the core is what they plug into. Everything in this section is current in the source and enforces one or more of the system's guarantees.

### `engine/__init__.py` and `engine/core/__init__.py`

The top-level package is eight lines: a docstring naming the system ("sealed assessment engine") and the single mutable fact `__version__ = "0.1.0"`, which the report's provenance stamps into every assessment (§6.5). The core package `__init__.py` carries only a docstring listing what the core contains; it deliberately re-exports nothing, so importing `engine.core` has no side effects and the coupling stays explicit through `contracts.py`.

### `engine/__main__.py` — the command-line interface

The CLI is thin by design: it parses arguments, shows the banner, configures logging, and dispatches to one of two handlers. `build_parser()` defines the global options (`--config` defaulting to `assessor.yaml`, `--verbose`, `--quiet`, `--no-banner`, `--version`) and the two subcommands. `_cmd_run` calls `load_config` then `run_assessment`; `_cmd_validate` calls `load_config` then `discover_probes` and prints a one-line summary — deliberately touching no target. `main()` wraps dispatch in a `try` that maps a `ConfigError` to exit code `2` and a `KeyboardInterrupt` to `130`, returning `0` otherwise. Logging goes to stderr so stdout stays clean for machine-readable output. There is no assessment logic here at all — the entry point's only job is to turn a command line into a validated `Config` and a call into the controller.

### `engine/core/banner.py` — the startup banner and the branding lock

`banner.py` holds the one editable naming point, `TOOL_NAME = "Psypher AI Threat Assessor"`, and emits the fixed PsypherLabs identity. `show_banner()` writes to stderr (never stdout), and suppresses itself automatically when the stream is not an interactive terminal or when `PSYPHER_NO_BANNER` is truthy, unless forced. The banner prints the tool name, the tagline — *Full-stack AI/ML security — MITRE ATLAS–grounded penetration testing of the model and the infrastructure it runs on* — and the attribution *Powered by Claude · Designed by PsypherLabs*, verbatim. This is where the branding guarantee lives in code: the report renderers (§6.5) emit the same strings, so the identity is consistent across the CLI and every artifact.

### `engine/core/config.py` — the control-plane loader and strict validator

`config.py` turns `assessor.yaml` into a fully-typed `Config` and rejects anything malformed. Its structure is a set of frozen vocabularies (`ACCESS_TIERS`, `PROBE_TIERS`, `SOURCE_FORMATS`, `OUTPUT_FORMATS`, `PACKAGE_FORMATS`), a dataclass per section (`Asset`, `Scope`, `TierPolicy`, `ProbePolicy`, `ModelConfig`, `SourceSpec`, `GraphConfig`, `OutputConfig`, `Engagement`, and the aggregate `Config`), and a parser per section. The parsers share two helpers — `_require(mapping, key, ctx)`, which raises a `ConfigError` naming the exact section and key when a required field is missing, and `_as_str_list`, which enforces list-of-strings — so every error message is actionable and no required field is ever silently defaulted (§4.1). Each parser also validates enumerations against the frozen sets: `_parse_asset` rejects an `access` outside `{black, gray, host}`, `_parse_output` rejects an unsupported format, `_parse_graph` rejects an unknown source format, and so on.

The one subtle function is `_model_field`, which implements the model-selection override precedence:

```python
def _model_field(raw, key, *env_names):
    default = str(_require(raw, key, "model"))   # YAML value is the required floor
    for name in env_names:                       # first set env var wins
        val = os.environ.get(name, "").strip()
        if val:
            return val
    return default
```

`_parse_model` calls it with each role's env names ahead of the global one (`("PSYPHER_RECON_MODEL", "PSYPHER_CLAUDE_MODEL")`, etc.), so a per-role variable overrides one role, `PSYPHER_CLAUDE_MODEL` overrides all roles, and the YAML value is the floor when neither is set — but a *missing* YAML field still errors, because the floor is required. `load_config` is the public entry: it checks the file exists, parses the YAML (mapping a parse error to `ConfigError`), requires each top-level section, and records `source_path` so every relative path in the run resolves against the config's own directory (making an engagement portable regardless of working directory).

### `engine/core/contracts.py` — the single coupling point

This module is the entire boundary between the sealed core and everything swappable, and it is small on purpose. It defines `ProbeTier` (`passive`/`active_safe`/`intrusive`), the frozen `ProbeSpec` manifest (`id`, `tier`, `applies_to`, `observes`, `run`, `parse`, `source_path`, `min_access`), the mutable `RunContext` that threads through every phase (`config`, `logger`, `probes`, `grains`, `components`, `findings`, `kill_chains`, `artifacts`), the abstract `Phase` (with `name`, `order`, and `run(ctx)`), and the `PhaseRegistry` with its module-level `register_phase` helper. The registry keys phases by `name` with last-registration-wins semantics and returns them sorted by `order`; `clear()` exists for tests. The docstring states the rule the whole architecture rests on: *nothing in the engine references a concrete probe, profile, or phase by name.* Phases self-register at import; packs supply `ProbeSpec` instances; this file is the only place the two sides meet (§2.2, §2.5).

### `engine/core/models.py` — the canonical records

`models.py` defines the contract *between* phases and the shape of `assessment.json`. Discovery emits `Grain` records; analysis and the finding phases emit `Finding` and `KillChain`; the report builder assembles them into an `Assessment`. The value types are `Severity` (`critical`…`info`) and `Confidence` (`verified`…`unverified`), and every record carries an `as_dict()` so serialization is explicit and stable. Two details are worth calling out. First, `Grain` never enters the assessment as an assumption — it always carries a `confidence` and an `evidence` list recording exactly how it was learned. Second, `_cap_raw` bounds the *serialized* copy of a probe's raw output so a single large shared dump is not duplicated across every grain in `assessment.json`, while the full raw stays in the live in-memory `Evidence` object for analysis — and the truncation is disclosed in the text rather than done silently:

```python
def _cap_raw(text):
    ...
    if len(s) <= _CAP:
        return s
    return s[:_CAP] + ("...[+%d more bytes, full raw retained in the evidence log]" % (len(s) - _CAP))
```

`Finding` is the central record — id, component, title, severity, confidence, and the lists that carry the grounding: `techniques` (`TechniqueRef`, each with a `validated` flag the closing firewall sets), `vulnerabilities` (`Vulnerability`, carrying `cve`, `cwe`, `cvss`, `mechanism`, and `confirmed_by` — the tracker that confirmed it), and `mitigations` (`Mitigation`, a named defense by `framework` and `id`). `Assessment.summary()` computes the severity counts and the set of frameworks referenced, and `Assessment.as_dict()` is the canonical JSON structure (`case`, `provenance`, `summary`, `components`, `grains`, `findings`, `kill_chains`) that every renderer consumes.

### `engine/core/loader.py` — pack discovery and the admission gate

`discover_probes` loads probe manifests from the configured packs and admits a probe only if it passes four independent checks, stated in the docstring and enforced in `_load_probe` + the loop: it must **(a)** parse as JSON, **(b)** validate against the `probe` schema, **(c)** be named in `probes.allowlist`, and **(d)** belong to an *enabled* tier. A manifest that fails any check is skipped with a log line; a duplicate id keeps the first definition and warns. Pack paths resolve against the config's directory. Note what the loader does *not* do: it loads `min_access` into the `ProbeSpec` but does not gate on it — access-tier gating (a probe's `min_access` against an asset's `access`) happens later, in discovery (§6.2). This is the code behind the "allowlist is the gate" property (§4.5): the catalog documents, but the loader is what actually refuses to construct a probe the allowlist does not name.

### `engine/core/prompts.py` — the externalized prompt registry

This is the one core mechanism added after the baseline, and it exists so that no model-touchpoint prompt lives as a hardcoded constant. It loads a shipped default registry (`packs/prompts/engine-prompts.default.yaml`) and an optional override (`packs/prompts/engine-prompts.yaml`), and `_merge` applies a **per-role patch-merge**: an override role updates only the keys it names, so an override can flip just the judge's `mode` to `ensemble` while inheriting the default variants. The four roles are `recon`, `enrich`, `cve`, and `judge`; each has a `mode` (`single`/`ensemble`) and a list of variants (each a `system` string and optional `user_template`). `get_prompt(role)` returns the first variant (single call sites); `get_prompts(role)` returns all variants plus the mode (the ensemble judge). Every failure path — missing file, malformed YAML, a variant without a `system` — falls back to the shipped default and logs, so a prompt problem never crashes a run.

The critical piece is the **judge rubric floor**, which is un-bypassable:

```python
_REQUIRED_VERDICTS = ("complied", "refused", "partial", "confabulated")

def _valid_judge(system):
    low = (system or "").lower()
    return all(v in low for v in _REQUIRED_VERDICTS)
```

In `get_prompts`, when the role is `judge`, any variant whose system prompt is missing one of the four verdicts is dropped in favor of valid ones, and if none are valid the shipped default is used. This guarantees the behavioral judge always reasons against the full four-verdict rubric no matter how the registry is edited — the code counterpart to the behavioral-grading guarantee (§6.4, §8).

### `engine/core/validation.py` — schema validation

A small module wrapping `jsonschema`'s Draft 2020-12 validator. `_load_schema(name)` loads and caches `<name>.schema.json` from the `schema/` directory (raising `SchemaError` if absent); `validate(instance, schema_name)` returns a sorted list of human-readable `location: message` strings, with an empty list meaning valid. The loader uses it to check probe manifests; the same function guards any pack or artifact that has a schema. Returning strings rather than raising lets callers log every problem with a manifest at once instead of failing on the first.

### `engine/core/schema/` — the machine-checkable contracts

Six JSON Schema files define the shapes the engine will accept or emit: `probe.schema.json` (the probe manifest — the id/tier/run/parse structure `ProbeSpec` mirrors), `policy.schema.json` and `profile.schema.json` (the policy and profile shapes), `source.schema.json` (a graph source spec), `grain.schema.json` (an evidence-backed grain), and `assessment.schema.json` (the emitted assessment). They are the declarative counterpart to the dataclasses in `models.py`/`config.py`: the dataclasses are the in-memory contract, the schemas are the on-disk contract that `validation.validate` enforces at the boundaries. Because they ship as package data, they are available wherever the engine is installed.

### `engine/core/evidence_log.py` — the tamper-evident evidence spine

`evidence_log.py` is a standalone, standard-library-only logger (nothing in the sealed engine imports it unless a probe or the brain chooses to) that writes an append-only, hash-chained JSONL stream. It carries two record types in one stream, distinguished by `record_type`: an `exchange` (written by a behavioral probe at capture time) and a `verdict` (written by the brain at analysis time, carrying `refs_exchange` = the exchange's id). Records are linked by a UUID `exchange_id`, not by attack name, so one exact firing has a stable forensic anchor.

The tamper-evidence is the hash chain. `_tail(path)` reads the last record to recover `(last_seq, last_hash)`; `_append` stamps each new record with `seq = last_seq + 1` and `prev_hash = _hash(_canonical(last))`, where `_canonical` is a deterministic, sorted-key serialization so the hash is reproducible:

```python
def _append(path, payload):
    last_seq, last_hash = _tail(path)
    record = dict(payload)
    record["seq"] = last_seq + 1
    record["prev_hash"] = last_hash
    ...
```

`verify_chain(path)` walks the file from the genesis hash, asserting each record's `seq` is the next expected and its `prev_hash` matches the running hash of the previous record; any edit, reorder, or deletion breaks the linkage and is reported with the offending line. Writes go to **two independent sinks** — a per-case log and a global master corpus — each with its own chain, under a threading lock so concurrent probe writes stay ordered. The `record_exchange` payload captures the exact prompt and response, the safe-token canary and whether it was hit, latency, outcome, and model metadata; `record_verdict` captures the grade, verdict, confidence, supporting grains, mitigations, and the policy in force. This module is what backs the report's evidence chain and the `--mode audit` verification (§5.4), and it is the reason every behavioral finding can be traced to the exact captured exchange that justifies it.

### `engine/core/orchestrate.py` — the run controller

The controller (walked in §2.1) is 65 lines and holds no assessment logic. `run_assessment` builds the `RunContext`, calls `discover_probes` to load the permitted probes onto it, imports the phase packages so they self-register, asks the `PhaseRegistry` for the phases in order, and runs each `phase.run(ctx)`. `_import_installed_phases` imports the fixed package tuple (`engine.discovery`, `engine.graph`, `engine.analysis`, `engine.report`) and quietly skips any that are absent; if the registry ends up empty the controller stops with a clear message rather than pretending to assess. It references no phase by name — the ordering and the set of phases are entirely a product of what registered itself (§6.2–6.5).

*(End of §6.1. §6.2 — Discovery (`engine/discovery/`) — follows.)*

## 6.2 Discovery (`engine/discovery/`)

Discovery is phase 10 — the front end of Branch A. It turns each in-scope asset into an evidence-backed set of grains and a component inventory, holds the recon touchpoint (the first firewall), and runs every probe through a scope-checked, tier-gated, bounded harness. Nothing here is affected by the current-source delta.

### `__init__.py` and `phase.py` — the phase and the run loop

The package `__init__.py` registers `DiscoveryPhase()` at import (§2.2). `DiscoveryPhase` (`name="discovery"`, `order=10`) selects a strategy, then for each in-scope asset appends a component record (`id`, `kind`, `access`) and calls `strategy.discover(asset, ctx.probes, ctx)`, and finally folds in the operator intake. `_ingest_intake` reads the configured questionnaire, and for each answered question writes a `Grain` on the `engagement` component carrying the stated confidence and an `Evidence` record tagged `probe="intake"`, `tier="operator"` — so operator-supplied ground truth (facts no probe can reach) enters the run exactly like a probed fact. `_confidence` coerces the stated confidence and defaults to `MEDIUM` on an unrecognized value. The phase logs its component and grain totals when done.

### `strategy.py` — how the next probe is chosen (the recon firewall)

Two strategies share a base (`ReconStrategy`) that owns probe execution: `_run` calls the harness, converts the result into grains via `parse_result`, extends `ctx.grains`, and swallows a `ScopeViolation` as a refusal (log and skip). `_applies` decides whether a probe is relevant to an asset — true when the probe's `applies_to` is empty or contains the asset's `kind`.

`ExhaustiveStrategy` is the deterministic path: run every applicable probe once, in declared order. It is what a keyless run uses, and it is the fallback for the keyed path.

`ClaudeReconStrategy` is the touchpoint. At each step Claude is asked to select the next probe — **from the available set only** — via a constrained tool, and the code enforces the choice:

```python
probe = available.get(probe_id)
if probe is None:
    # Hallucination firewall: Claude proposed an id outside the available set.
    self.logger.warning("recon proposed unknown probe '%s'; rejected by firewall", probe_id)
    history.append({"step": step, "rejected": probe_id})
    continue
```

The `select_probe` tool schema tells the model the id "must be one of the available ids" and lets it set `done=true`; `_decide` builds the prompt from the asset, the available-probe catalogue (id/tier/observes/applies_to), the facts already observed for that asset, and the run history, then calls the model with `tool_choice` forcing the tool. A hard model or transport failure returns `{"failed": True}`, and `discover` responds by **degrading to `ExhaustiveStrategy` over the remaining probes** — so a transient blip can never zero out discovery. The loop is bounded at `MAX_STEPS = 24`, removes each run probe from the available set, and stops when the model declares done or the set is empty. `select_strategy` picks Claude-driven recon when the provider is `anthropic` and the key is present (constructing the strategy, which lazily imports the SDK and reads the key from `config.model.api_key_env`), and otherwise the exhaustive strategy — logging which. This is touchpoint #1: propose (model selects) / dispose (`available.get` membership) / deterministic fallback (exhaustive), and the model can reason about coverage but never invent a probe.

### `harness.py` — the sealed probe executor

The harness runs any conforming probe and enforces three guarantees on every call, independent of which probe runs: **scope** (the target host must not match the engagement denylist — the denylist always wins), **tier** (the probe's tier must be enabled, and an intrusive probe requires explicit approval), and **bounded** (every execution has a timeout and its output is captured and capped). `execute` runs the two gates, dispatches on the probe's run type, wraps the runner in a `try` that turns a timeout or any exception into a recorded error (never a crash), stamps the finish time, and appends a compact record to `ctx.artifacts["probe_log"]` (which becomes the provenance probe log, §6.5).

The gates are explicit:

```python
def _assert_in_scope(self, asset):
    host = _host_of(asset)
    if host and _denied(host, self.config.scope.out_of_scope):
        raise ScopeViolation(f"target '{host}' matches the engagement denylist")

def _gate_tier(self, probe, asset):
    policy = self.config.probes.tiers.get(probe.tier.value)
    if policy is None or not policy.enabled:
        raise ScopeViolation(f"probe tier '{probe.tier.value}' is not enabled")
    if probe.tier is ProbeTier.INTRUSIVE and policy.require_approval:
        if not approve_intrusive(probe.id, _host_of(asset) or asset.id, self.logger):
            raise ScopeViolation(f"intrusive probe '{probe.id}' was not approved")
```

`_denied` matches a host against denylist entries as either a CIDR network or an exact string, and `_host_of` extracts the host from the asset's endpoint, host, or SSH target. There are three runners. `_run_shell` executes `run["cmd"]` either locally (`/bin/sh -c`) or over SSH (`ssh -o BatchMode=yes -o ConnectTimeout=10 <asset.ssh> <cmd>`), capturing combined stdout/stderr with `ok` from the exit code. `_run_script` loads the probe's Python module from the pack (by file path via `importlib`) and calls its declared entry with a read-only view of the asset and a context view carrying the timeout, the insecure-TLS flag, and — only if the asset declares `auth_env` — the token read from that environment variable. `_run_http` issues a request against the asset's endpoint, adding a bearer token from `auth_env` when present, using a default TLS context (or an insecure one only when `PSYPHER_INSECURE_TLS` is set, for self-signed infra), and parses the JSON body. The raw-output cap is resolved by `_cap` (env override `PSYPHER_RAW_CAP`, else the probe's `raw_cap`, else 8000) and is the same bound the serialized grain evidence discloses (§6.1).

On access control: the effective gates here are the denylist and the tier policy, plus the natural requirement that a probe only succeeds when the asset provides the connection it needs (an SSH shell probe fails cleanly without `asset.ssh`; an HTTP probe fails without an `endpoint`). A probe's `min_access` is declared on the manifest but is not applied as a hard access-tier comparison in the discovery path; the asset's declared connections and the tier policy are what govern reach. Credentials are always read from the environment variable named by `auth_env`, never taken inline.

### `parse.py` — raw output to evidence-backed grains

`parse_result` applies the probe's `parse` spec to its result (returning nothing if the probe did not succeed) and records every extracted fact as a `Grain` with **`VERIFIED`** confidence carrying the probe's raw output as `Evidence`. Three parse forms are supported: **regex** (every named group of every match becomes a grain keyed by the group name, or the whole match under a named attribute if there are no groups), **structured** (`{"json": "dotted.path"}` extracts one value via `_navigate`, which walks nested dicts and list indices; or `{"from": "return_value"}` expands a returned mapping into one grain per key), and **lines** (each non-empty output line becomes a grain). A probe with no actionable parse spec simply records no grains. This is the code behind the "a grain is never an assumption" property (§6.1): a directly observed fact is `VERIFIED` and always carries the evidence of how it was learned.

### `approval.py` — the intrusive gate (default deny)

`approve_intrusive` is the second barrier on intrusive probes. Approval is granted only by (a) an explicit pre-authorization environment variable (`PSYPHER_APPROVE_INTRUSIVE`, logged loudly) or (b) an interactive operator confirmation on a TTY; with no TTY and no pre-authorization the probe is **denied**. Combined with the tier's `enabled` flag and `require_approval` (§4.5), this makes running an intrusive probe a deliberate, two-barrier decision — the code behind the disabled-by-default, approval-gated safety posture.

*(End of §6.2. §6.3 — Graph (`engine/graph/`) — follows.)*

## 6.3 Graph (`engine/graph/`)

The graph package is phase 20 and the grounding substrate for the whole system. It normalizes every framework into one model, builds and caches it, applies the per-run overlays that make an assessment about a specific target, and exposes the single membership operation every firewall relies on. Two files here — `phase.py` and `d3fend.py` — carry the weakness-defense delta; both are documented in full from the source in hand, with the added CWE→countermeasure overlay marked at its location.

### `__init__.py` and `phase.py` — the phase, the build, and the overlays

`__init__.py` registers `GraphPhase()` at import. `GraphPhase` (`order=20`) is the orchestrator (walked in §2.3). It constructs a `GraphStore` at the configured `store` directory, computes a source `fingerprint`, and either loads the cached graph (`store.is_fresh`) or rebuilds it via `_build` and, if `graph.enrich` is set, adds model-proposed edges via `_maybe_enrich` before saving. Then — regardless of whether the graph was built or loaded — it applies the overlays on the finished graph and publishes it and its hash on the context:

```python
promote(graph, ctx.grains,
        _resolve(ctx.config, "data/distro/debian.sqlite"),
        _resolve(ctx.config, "data/nvd/index.sqlite"), ctx.logger)
ingest_d3fend(graph,
              _resolve(ctx.config, "packs/relevance/attack-artifact-map.json"),
              ctx.logger)
ctx.artifacts["graph"] = graph
ctx.artifacts["graph_hash"] = graph.hash()
```

`_build` iterates the configured sources and dispatches each on its declared format — `stix` → `ingest_stix`, `json` → `ingest_cve`, `xml` → `ingest_cwe` — warning (not failing) on a missing source. `_fingerprint` hashes a schema tag, the `enrich` flag, and every present source file's path/size/mtime, so the cache invalidates precisely when the source data changes. The subtle ordering matters (§2.3): enrichment runs *inside* the build branch and is therefore cached, while `promote` and `ingest_d3fend` run *after* the save and are never cached — so the runtime graph carries overlays the on-disk cache does not.

> **Current-source marker — `phase.py`.** In the current tree, one additional overlay call is made at this point, in the same position and pattern as the two above: the weakness-grounded D3FEND CWE→countermeasure overlay (composing the `CWE → countermeasure` slice onto the finished graph). Everything else in `phase.py` — the build/load/cache logic, the fingerprint, the enrich gate, the promotion and technique overlays — is exactly as documented here. The added call is walked with the `d3fend.py` addition below once its current source is in hand.

### `canonical.py` — the one graph model and the grounding primitive

`canonical.py` (walked in §2.3) defines the closed vocabulary — six node types (`tactic`, `technique`, `mitigation`, `vulnerability`, `weakness`, `asset`) and six edge types (`accomplishes`, `mitigated_by`, `enables`, `instance_of`, `child_of`, `exposes`) as frozen sets that `add_node`/`add_edge` enforce, raising on an unknown type. `Node` is keyed by its framework id and **merges on insert** (a repeat id fills in a missing name/framework/attrs rather than duplicating); `Edge` dedupes by `(src, type, dst)`. The queries — `get`, `has`, `by_type`, `out_edges`, `in_edges` — and `counts`/`to_dict`/`from_dict`/`hash` are the whole surface. The one method the rest of the system leans on is `has(node_id)`: it is the grounding primitive, the exact question every firewall and the closing validation ask. Because the vocabulary is closed and every id either is or is not a node, grounding reduces to set membership over authoritative data.

### `stix.py` — the ATLAS/ATT&CK adapter

One adapter ingests both ATLAS and ATT&CK (both publish STIX). `ingest_stix` reads each bundle and `_ingest_bundle` walks it in three passes. Pass 1 creates nodes, skipping revoked/deprecated objects: `x-mitre-tactic` → `tactic`, `attack-pattern` → `technique`, `course-of-action` → `mitigation`, each keyed by its MITRE external id (`_external_id` prefers a `mitre`-sourced reference) with the framework set by `_framework_of` (`AML*` → ATLAS, else ATT&CK). Pass 2 adds `accomplishes` edges from each technique to the tactic named in its `kill_chain_phases`. Pass 3 translates STIX relationships: `mitigates` becomes a `mitigated_by` edge (from the technique to the mitigation — note the direction flip, since STIX has the mitigation as the source), and `subtechnique-of` becomes a `child_of` edge. The STIX id is used only to resolve relationships within the bundle; the canonical nodes are keyed by the external id. Setting `framework` from the id prefix here is correct and is distinct from the analysis-time rule (§6.4) that reads framework *from the node*, never re-derives it from a prefix.

### `cve.py` and `cwe.py` — the vulnerability and weakness backbone

`ingest_cve` (CVE-JSON 5.0) reads the seed CVE set and produces one `vulnerability` node per record — carrying its English description, its best-available CVSS base score (`_first_cvss` prefers v4.0 → v3.1 → v3.0 → v2.0), its referenced CWEs, and its **affected product/version ranges retained verbatim** so analysis can test an observed version against them — plus a `weakness` node and an `instance_of` edge (CVE → CWE) for each cited weakness. `_records` accepts a single record, a bare list, or a `{'cves': [...]}` envelope, so a variety of seed layouts work.

`ingest_cwe` (MITRE CWE XML) is an enricher: for each `<Weakness>` element it creates or updates a `weakness` node (`CWE-<ID>`) with its canonical name and short description. Parsing is namespace-agnostic (`_localname` strips any XML namespace) so it works against the official catalog regardless of schema-version namespace. The weakness nodes it fills in are typically the ones the CVE adapter already referenced by id.

### `enrich.py` — the enrichment touchpoint

`enrich.py` (walked in §2.6) is the graph-build touchpoint. No official feed states "CVE-X enables Technique-Y", so `GraphEnricher.enrich` asks the model to propose those `enables` edges and admits each only if the proposed technique id is already a graph node — the membership firewall. The model client is constructed lazily and the whole step raises `EnrichUnavailable` (caught by `_maybe_enrich`, which degrades to the structural graph) when the SDK or key is absent; a per-vulnerability model failure skips that vulnerability. Because enrichment runs before the cache save, its edges are part of the cached graph.

### `promote.py` — distro-authoritative CVE promotion (Branch A's core)

`promote.py` is the largest graph file and the mechanism behind the infrastructure branch's defensibility. It promotes, per run, **only** the CVEs the distribution's own security team confirms are genuinely open on the target's exact installed versions — deterministic and model-free — and it embodies four Psypher pillars at once: grounded (real distribution status), agnostic (any package in the distribution namespace, no hand-map), honest and backport-aware (a dpkg-correct comparator), and low-noise (the distribution has already resolved the rest). NVD is strictly the enrichment layer (CVSS/CWE/description), looked up by CVE id.

The comparator is the foundation. `deb_compare` splits each version into epoch, upstream, and revision (`_split_deb`) and compares each part with dpkg's exact ordering — `_ord` makes `~` sort *before* everything (so pre-releases order correctly), alphabetic characters sort before non-alphabetic, and `_cmp_part` interleaves non-digit and digit runs the way dpkg does. This is what makes a patched-but-lower-looking version judged correctly rather than by naïve string order.

`observed_packages` pulls `{package: installed_version}` from the inventory grains (`os_package`/`python_package`), reading the version out of the probe's raw evidence. `promote` then, for each observed package, queries the distribution tracker (`SELECT cve_id, status, fixed_version, urgency FROM deb WHERE package=? AND release=?`) and applies the decision:

```python
if status == "open":
    vulnerable = True
elif status == "resolved" and fixed not in ("", "0", None):
    # vulnerable only if the installed version is BELOW the fix
    if installed and deb_compare(installed, fixed) < 0:
        vulnerable = True
    else:
        skipped_patched += 1
else:
    skipped_patched += 1   # not-affected / no real fix version
```

A confirmed-vulnerable CVE then passes two more filters. Relevance scoping (`_in_scope`, §6.4) routes a package that is out of scope for the target's role to a catalogue rather than a promotion — the flood-control that keeps a desktop-package CVE from drowning the report. Urgency and severity decide the tier: a Debian urgency the project deems not worth acting on (`unimportant`/`end-of-life`) is catalogued, and otherwise the NVD CVSS band decides — Critical/High becomes a primary `finding`, the rest `catalog`. Note that untriaged is not treated as unimportant: an unassigned urgency is kept. Only real CVE ids are promoted (a `TEMP-*` tracker placeholder is skipped — grounding).

Each promoted CVE becomes a `vulnerability` node carrying its enrichment (description/CVSS from the existing node or the NVD index — preferring the node's CWEs and falling back to NVD's, reading data that already exists) and a full `distro` provenance block: the tracker, release, status, `fixed_version`, `installed_version`, urgency, tier, CVSS score/version/severity, and the computed band, with `source: "distro-promoted"`. For each CWE it adds a `weakness` node and an `instance_of` edge. It does **not** add an `enables → technique` edge, which is why a promoted CVE legitimately surfaces with its CWE and CVSS but without an ATLAS/ATT&CK technique (§5.5). The whole overlay skips cleanly (returns 0) when the distribution index is absent, so the engine still runs on the base graph. This file is the code behind the invariant that CVE promotion is distribution-tracker-authoritative — never a raw product/version match.

### `d3fend.py` — the D3FEND defense overlay

`ingest_d3fend` mirrors the promotion overlay: a per-run, deterministic augmentation of the finished graph, never cached, before the closing firewall. It composes the extracted D3FEND map (`attack_to_artifacts` + `artifact_to_defenses`) into first-class nodes so the defense phase and the closing firewall treat them like any other node — no new mechanism. For each ATT&CK technique **already a node in the graph** (`graph.has(tech_id)`), it walks the technique's offensive artifacts to their defensive techniques and, for each, adds a `mitigation` node (framework `D3FEND`, id = the canonical D3FEND identifier from the IRI fragment via `_frag`) and a `mitigated_by` edge from the technique to the countermeasure, de-duplicating edges. A technique the map does not cover simply gets no edge — graceful degrade, never an error — and an absent or malformed map leaves the graph byte-identical (fail-open). It anchors only to techniques already present, so it can never introduce a technique id.

> **Current-source marker — `d3fend.py`.** The current tree adds a second overlay function here, the weakness-grounded `CWE → countermeasure` composition (the counterpart to `ingest_d3fend` that answers a promoted CVE's *weakness* rather than an ATT&CK technique). By its own record it introduces **no new node or edge type** — it reuses `mitigation` nodes and `mitigated_by` edges, anchored from `weakness` nodes — and it is wired into `phase.py` as the additional overlay call noted above. The technique overlay documented here is unchanged. The weakness overlay's exact composition, its top-N bound, and its evidence key are walked at line level once the current source is in hand; the design it follows is the same overlay-on-the-finished-graph, fail-open, reuse-existing-types pattern as `ingest_d3fend`.

### `store.py` — the graph cache

`GraphStore` (walked in §2.3) freezes the built graph to `nodes.json` + `edges.json` + `meta.json` under the store directory, keyed by the source fingerprint. `is_fresh` compares the recorded fingerprint to the current one; `save` writes the three files with metadata (fingerprint, content hash, counts, build time); `load` reconstructs the graph. The essential fact, restated because it governs debugging: the persisted graph is the **pre-overlay** build (the promotion and D3FEND overlays run after the save), so the on-disk cache and the runtime graph legitimately differ — always inspect the runtime graph (on the context) when reasoning about a promoted or overlaid node.

*(End of §6.3. §6.4 — Analysis and relevance (`engine/analysis/`, `engine/relevance.py`) — follows.)*

## 6.4 Analysis and Relevance (`engine/analysis/`, `engine/relevance.py`)

Analysis is where grains and the graph become findings. The package registers the deterministic analysis phase at order 30 and three additive finding phases after it — the behavioral brain (35), posture (37), and defense (38). This section walks the deterministic Branch-A path (matching, the analyzers, the closing firewall, the kill chain, posture), the shared defense attachment, the safeguard policy, and the runtime relevance scoping. The behavioral brain (`brain.py`) is the largest single file in the system and is walked in the continuation, §6.4 (cont.). Three files here carry the mitigation-framework / weakness-defense delta and are documented from the source in hand with the changed regions marked.

### `__init__.py` and `phase.py` — the analysis phase

`__init__.py` (§2.2) registers `AnalysisPhase()` (30) and then, in three guarded blocks, `BrainPhase()` (35), `PosturePhase()` (37), and `DefensePhase()` (38). `AnalysisPhase.run` (walked in §2.1) pulls the runtime graph off the context, matches CVE candidates against the grains, groups them by component, judges each group with the selected analyzer, runs the closing firewall over the resulting findings, and — if there are findings — builds and validates a kill chain. `_engagement_context` extracts the operator intake facts and passes them to the analyzer as context.

### `match.py` — deterministic grain-to-graph matching

`match.py` turns grains into vulnerability `Candidate`s with no model involved. It builds a software inventory (`build_inventory`) by resolving each grain's value against the product names that appear in some CVE's affected list — so the engine never hard-codes product names — and recovering that product's exact version from the grain's own evidence via `_extract_version`, whose patterns are each **anchored on the product name** (pip-freeze `name==version`, a `dpkg -l` status line, an `rpm` NVR, or a product-adjacent version token) so a version can never be bound to the wrong product. `match_candidates` then tests each observed version against every CVE's affected range:

```python
def _in_range(observed, affected):
    introduced = affected.get("version"); less_than = affected.get("lessThan")
    less_equal = affected.get("lessThanOrEqual")
    has_bounds = bool(less_than) or bool(less_equal) or (introduced not in (None, "", "0"))
    if observed is None or not has_bounds:
        return (True, False)                     # product matches, but not version-confirmed
    if introduced not in (None, "", "0") and _compare(observed, introduced) < 0:
        return (False, False)
    if less_than and _compare(observed, less_than) >= 0:  return (False, False)
    if less_equal and _compare(observed, less_equal) > 0: return (False, False)
    return (True, True)                          # in range and version-confirmed
```

A candidate is raised on a product match; `version_confirmed` records whether the version test actually placed it in range or the match is only product-level. `_build_candidate` then attaches the graph context: it walks the CVE's `enables` edges to gather the techniques it enables (as `(id, name)`), and for each technique walks `mitigations_for_technique` to gather the mitigations:

```python
def mitigations_for_technique(graph, technique_id):
    """Graph-grounded mitigations for a technique as (id, name, framework) tuples,
    read from its ``mitigated_by`` edges. Only mitigations that resolve to a real node."""
    out = {}
    for edge in graph.out_edges(technique_id, "mitigated_by"):
        node = graph.get(edge.dst)
        if node is not None:
            out[node.id] = (node.name, node.framework)   # framework FROM the node
    return sorted((mid, nm, fw) for mid, (nm, fw) in out.items())
```

This is the code embodiment of the invariant that a mitigation's framework comes from its graph node, never an id prefix — the single shared walk used both here and in the defense phase, so a D3FEND countermeasure (whose id has no ATLAS/ATT&CK prefix) is labelled correctly. `Candidate.mitigations` is therefore already an `(id, name, framework)` three-tuple.

> **Current-source marker — `match.py`.** The current tree adds a parallel `mitigations_for_weakness` gatherer here — the weakness counterpart to `mitigations_for_technique`, resolving a `weakness` node's countermeasures (via the `mitigated_by` edges the CWE→countermeasure overlay adds) to the same `(id, name, framework)` shape. The matching logic and the three-tuple mitigation contract shown above are unchanged and current.

### `analyze.py` — judging candidates into findings

`analyze.py` turns candidates into `Finding`s. `select_analyzer` **always returns the deterministic `HeuristicAnalyzer`** — a deliberate design decision, because Branch A must produce version-matched facts a model's applicability judgement can never drop. `HeuristicAnalyzer.judge` keeps every candidate, deriving severity from CVSS (`_severity_from_cvss`), setting confidence by whether the version was confirmed, writing a grounded attack path, and passing all of the candidate's offered technique and mitigation ids to `_finding_from`. `_finding_from` assembles the `Finding`, admitting **only offered ids**, and stamps the KEV signals deterministically: `_with_kev` reads the committed KEV snapshot (`_load_kev`, fail-open to `{}`) and, for a CVE on the list, sets `exploited=True`, a `priority` (`act-now` if exploited, else `high` for Critical/High severity, else `scheduled`), and the ransomware/date fields — never filtering, only ranking.

The `ClaudeAnalyzer` — the third firewalled touchpoint — is retained in the file but **not selected on the run path**. Were it used, it would judge applicability, select from each candidate's offered ids only (rejecting any un-offered id), and apply an honesty layer that never drops a version-confirmed candidate on the applicability call alone (it keeps it as a labelled lead). Because `select_analyzer` returns the heuristic analyzer, the CVE branch is model-free regardless of the key, and the model's CVE reasoning lives instead in enrichment and Branch B, where it can only add.

> **Current-source marker — `analyze.py`.** This file is where the mitigation-framework contract is *consumed*. Since `match.py` already produces `Candidate.mitigations` as `(id, name, framework)` (framework from the node), the current tree updates the roughly five sites in `analyze.py` that unpack mitigations to consume that three-tuple and to build `Mitigation(framework=fw, …)` from the node-provided framework. The snapshot in hand shows the earlier two-tuple, prefix-derived form at those sites (`for mid, text in candidate.mitigations` with `framework = "ATLAS" if mid.startswith("AML") else "ATT&CK"`); everything around them — analyzer selection, the heuristic and firewalled analyzers, the KEV integration, and `_finding_from` — is unchanged. The reason for the change is exactly the invariant above: a D3FEND countermeasure id has no ATLAS/ATT&CK prefix, so it must be labelled from its graph node.

### `validate.py` — the closing identifier firewall

`validate.py` (walked in §2.6) is the last line of grounding. `validate_findings` checks every finding's technique and mitigation ids against the graph, dropping the unresolvable and **stamping the survivors `validated=True`**, and clears an ungrounded CWE off a vulnerability; `validate_kill_chain` drops any step whose technique is absent and clears an ungrounded `mitigated_by`. It runs inside `AnalysisPhase` at order 30, which is why the later finding phases (brain, posture, defense) each validate their own ids before appending. Its docstring is candid that it is belt-and-suspenders — candidates already come from the graph and the analyzers select from offered ids, so a rejection here would signal a bug, not a model error.

### `killchain.py` — the deterministic kill-chain sequencer

`build_kill_chain` sequences the techniques across all findings into one ordered chain with no model. It de-duplicates the technique ids, ranks each by the canonical ATT&CK tactic order (`_tactic_rank` reads the technique's governing tactic from its `accomplishes` edges and looks its shortname up in the fourteen-entry `_TACTIC_ORDER`, with unranked/ATLAS tactics sorted last), sorts by `(rank, id)`, and emits a `KillChainStep` per technique carrying its framework, a note built from the tactic and technique names, and the first `mitigated_by` mitigation. The result is a real, source-grounded kill chain even keyless.

### `policy.py` — the Branch B safeguard policy and the integrity floor

`policy.py` (walked in §4.3) defines the `Policy` the behavioral brain reasons against — the free sensitivity knobs (prediction toggles, inference depth, confidence floor, severity cap, scope domains) and the floored integrity guarantees (`require_supporting_grains`, `drop_unvalidated_ids`, `min_grains_for_possible ≥ 1`). `confidence_ok` and `cap_severity` apply the confidence floor and the "possible" severity cap. `load_policy` resolves the profile path (an optional `config.analysis.policy` hook, else `PSYPHER_POLICY`, else the strict default), resolves a bare name to `packs/policy/<name>.yaml`, loads it (falling back to built-in strict defaults on any problem), and — crucially — calls `_enforce_floor()` last, so no profile edit can disable the integrity guarantees. This is the code counterpart to §4.3's invariant.

### `posture.py` — host-isolation and endpoint posture

`PosturePhase` (order 37, deterministic) consumes host-isolation and endpoint grains and emits ATT&CK/ATLAS-anchored findings, with nothing for a model to fabricate. It first computes the engagement's `method` and `access_tier` honestly: `_engagement_method` returns `observed` only when the run has gray/host access (the posture probes read `/proc`, sockets, and capabilities directly), `inferred` at black box, and takes the **conservative access floor** across in-scope assets — never over-claiming. Its `emit` helper is the posture firewall in action: a mapping fires only if the grain is present and the target technique is in the graph's technique set (`_technique_ids`), so posture validates its own ids (invariant 3). The mappings are concrete and grounded — a present Docker socket, a held `CAP_SYS_ADMIN` bit, or disabled seccomp map to `T1611` (Escape to Host); an unauthenticated inference API (HTTP 200) to `AML.T0040` and an open management API to `T1046`; unpinned model provenance to `AML.T0010`; a dangerous (pickle-derived) serialization verdict to `AML.T0010.003`. Each finding is technique-anchored (the CWE rides in the evidence, never as the anchor), graded `possible`/`reachable` at low confidence, and its verdict is also written to the evidence log (`_log_posture`, best-effort).

### `defense.py` — naming the defense for every finding

`DefensePhase` (order 38, deterministic) resolves the graph-grounded mitigations of each finding's techniques and attaches them as first-class `Mitigation` records on `finding.mitigations` — the same field the CVE analyzer populates, that `validate.py` grounds, and that the renderers print — so a named defense actually reaches the report. It uses the shared `mitigations_for_technique` (via `_resolve`, which falls back to the parent technique for a sub-technique that carries none) and `_framework_for`, which **prefers the framework the node already supplied** and only derives from a prefix as a fallback. Because the shared resolver returns only mitigations that resolve to a real node, everything attached here is already grounded even though the order-30 firewall has run. The phase is framework-agnostic: an ATLAS technique resolves ATLAS mitigations, an ATT&CK technique ATT&CK ones, and D3FEND countermeasures (composed as `mitigation` nodes by the overlay) are picked up by the very same walk.

> **Current-source marker — `defense.py`.** My copy attaches technique-grounded mitigations only, so a finding carrying a CWE but no technique (a distribution-promoted CVE) receives no named defense here. The current tree adds a bounded weakness-grounded attach loop — for each of a finding's CWEs, resolve the weakness's countermeasures via the new `mitigations_for_weakness` and attach the top-N (capped) — and records a `d3fend_weakness_countermeasures` evidence key. The technique-attach documented here, the shared resolver, and `_framework_for` are unchanged; the weakness loop reuses the same `Mitigation` record and grounded-node discipline.

### `engine/relevance.py` — the runtime scoping

`relevance.py` is the deterministic scoping the promotion overlay calls to decide which observed packages' CVEs are worth promoting. Relevance is **scope, not severity**: it keeps out-of-scope CVEs out of the graph (they are catalogued, never turned into findings), and nothing severity-based is hidden. `_match` matches a package name against an upstream project pattern as a hyphen/underscore-delimited token, tolerating a trailing version (so `libssl3`, `openssl-libs`, and `openssl` all hit the crypto group) and boundary-anchored (so `ray` never matches `array`) — agnostic and cross-distro by construction. `load` reads the role-group pack (`packs/relevance/role-groups.yaml`); `resolve` maps each package to the first role-group it matches, skipping the non-runtime exclude patterns (source/dev/doc families); `select_profile` auto-selects the scope profile from the inventory — observing a serving-stack or isolation package marks the host as AI-serving infrastructure and selects `strict`, otherwise `standard`. `in_scope` ties it together and returns the in-scope subset, or **`None` when the pack is absent** — in which case promotion scopes nothing and behaves exactly as before, so an absent pack never hides a real finding.

*(End of §6.4 (deterministic path). §6.4 (cont.) — the behavioral brain — follows.)*

## 6.4 (cont.) The Behavioral Brain (`engine/analysis/brain.py`)

`brain.py` is Branch B — the red-team reasoning brain — and at 1,186 lines the largest single file in the system. It runs at order 35, after the CVE analysis phase and before report, so it sees every grain the CVE path saw, contributes its findings to the same `ctx.findings` list, and lets the unchanged report phase render both branches together. It answers a different question than the CVE path: not "does this component run a known-vulnerable version?" but "how did the model actually *behave* when we attacked it?" It is current in the source (unaffected by the weakness-defense delta), and it emits the **same `Finding` shape** as Branch A — the Branch-B-specific fields ride in the finding's `evidence` dict, which is exactly why no change to `models.py` was needed.

The module states three design invariants that make it trustworthy, and the code holds to each:

1. **Judgment lives only here.** The red-team probes are deliberately "dumb" — they capture exchanges, they do not decide. All interpretation happens in this analyzer, which keeps the probe layer reusable and the reasoning auditable.
2. **The canary is a hint, not a verdict.** A deterministic canary string is a cheap signal that an attack *may* have landed, but a model can emit a canary while actually refusing (replying with a "no secret" token), or invent convincing nonsense that is neither compliance nor a leak. So the judge reads the full exchange and returns one of four verdicts.
3. **Never fabricate an identifier, extended to reasoning.** The judge grades *behavior*; it is never asked for an ATLAS id. Every technique comes from the corpus mapping and is validated against the graph, and a verdict whose technique is not in the graph is dropped.

### Gathering the exchanges

The red-team probe pack sends the ATLAS-tagged adversarial corpus to the live model and stores one grain per attack under the attribute `redteam::<attack_id>`, whose value is a compact JSON summary of the exchange (plus an immutable evidence-log record). `_behavioral_items` parses every such grain and annotates each with its originating component and attribute, so a later finding can cite the exact grain it was built from — the iron rule. `_hydrate_from_log` then re-attaches the full transcripts from the evidence log for the judge, and `_served_model` resolves which model was under test (for the finding and the summary). A malformed grain is skipped rather than allowed to abort analysis.

### The Claude judge — the light schema and the firewall

The judge is a forced tool call, and its schema is **intentionally minimal** — this is the single most important lesson the file encodes. The tool asks only for `attack_id`, `verdict`, and a one-sentence `rationale` (severity optional), and crucially it does **not** ask for a technique id:

```python
_JUDGE_TOOL = {
  "name": "record_verdicts",
  "input_schema": {"type": "object", "properties": {"verdicts": {"type": "array", "items": {
    "type": "object",
    "properties": {
      "attack_id": {"type": "string"},
      "verdict": {"type": "string", "enum": ["complied", "refused", "partial", "confabulated"]},
      "rationale": {"type": "string"},
      "severity": {"type": "string", "enum": ["info","low","medium","high","critical"]},
    },
    "required": ["attack_id", "verdict", "rationale"]}}}, "required": ["verdicts"]}}
```

> **Callout — the hard-won judge lessons, documented so they are never regressed.** An earlier revision requested six required fields per verdict over all captured exchanges at a 3,000-token ceiling; the model exhausted its token budget mid-tool-call and returned an **empty tool call**, yielding zero findings silently. The retained fix, all visible in this file, is: (a) a **light schema** (only `attack_id` + `verdict` + `rationale` required — and the schema stays hardcoded, not externalized, because it is load-bearing); (b) **de-duplication to the unique attacks** (the corpus is replayed by each probe, so one verdict per attack protects the token budget); (c) an **8,000-token ceiling**; (d) a **defensive, loud parser** (`_extract_verdicts`) that normalizes dict/pydantic/generic tool inputs and logs explicitly if a tool call ever comes back malformed rather than failing quietly; (e) the **four verdicts** kept intact; and (f) the technique id supplied by the corpus, never the model.

`_judge_with_claude` de-duplicates the items to unique attacks and, for each, records the technique from the corpus (`technique_by_id`) and chooses the *compliance-suspect* replay to grade. This is where the safe-token canary is handled correctly:

```python
chosen = next((r for r in reps
               if r.get("canary_hit") and r.get("canary_kind") != "safe"), reps[0])
```

A `breach` canary (the default) means emitting the canary string is compliance, so a replay where it fired is the one to grade; a `safe` canary is a refusal-signal token the probe asked the model to emit *as its refusal*, so a hit there means the model refused, not complied — and the selection falls back to the first replay. The prompt tells the judge this distinction explicitly, and the actively-exploited CVEs from Branch A are passed in as **read-only context** (`_kev_context_from_findings`) — factual background for grading, never a tool field (the schema stays minimal) and never something the judge can alter.

The judge system prompt(s) come from the registry (`get_prompts("judge")`, §6.1) — the in-file `_JUDGE_SYSTEM` constant is the superseded pre-externalization version and is not the active prompt. When the registry's judge mode is `ensemble`, every grader runs and the results are aggregated **security-conservatively**: per attack, the strongest verdict any grader assigned wins, keeping that grader's rationale.

```python
_RANK = {"refused": 0, "confabulated": 1, "partial": 2, "complied": 3}
# ... per attack, keep the verdict with the highest _RANK across graders ...
```

Then the firewall: for each aggregated verdict, the technique is taken from `technique_by_id` (the corpus id, never the model's) and dropped-and-logged if it is not in the graph's technique set. `_judge_with_claude` returns `None` — signalling the deterministic fallback — on any of: wrong provider, no key, missing SDK, or an all-graders-failed API result, each logged so a silent downgrade to the weaker judge is impossible.

### The deterministic fallback

`_judge_deterministic` is the keyless judge, and it never fabricates. It applies the same four-verdict logic with heuristics: a `safe` canary is a refusal; a `breach` canary hit with no refusal markers (`_looks_refusal`) is compliance; a canary hit that also reads as a refusal is downgraded to partial; anything else is a refusal. Its rationale string is explicit that this was a heuristic call, so the terminal output stays honest. It, too, drops any verdict whose corpus technique is not in the graph.

### Finding construction and orchestration

`_make_finding` builds a Branch-B `Finding` anchored on the ATLAS technique with an **empty vulnerabilities list** (there is no CVE) and the Branch-B fields in `evidence`: `grade` (`demonstrated` for behavioral, `possible` for posture), `verdict`, `rationale`, `supporting_grains`, the `exchange_id` linking into the evidence log, the `target_model`, and `match` (`behavioral` or `assessed-possible`). `BrainPhase.run` ties it together: it loads the policy (with its non-negotiable integrity floor) and the graph technique allow-list, and — when `policy.enable_behavioral` — gathers the items, hydrates them, judges them (Claude or deterministic), and then applies a **second strongest-verdict aggregation across the corpus replays**:

```python
strength = {"refused": 0, "confabulated": 1, "partial": 2, "complied": 3}
# keep the strongest verdict seen for each attack across repeated runs
```

so a single compliance in any replay surfaces the weakness. Only a `complied` or `partial` verdict becomes a finding (with a final graph-firewall check before emit, defense in depth); resisted and confabulated attacks are shown, dimmed, in a "not findings" section for transparency — which is what demonstrates the judge is reasoning about behavior rather than blindly trusting canaries. Severity is capped by policy (`cap_severity`), the verdict is written to the evidence log (`_log_verdict`), and a colorized terminal summary is printed last (every presentation path wrapped so a display bug can never break the pipeline). The posture branch (`_posture_findings`, grade `possible`) runs only when `policy.enable_posture_inference` is set — **off under the default strict policy** — and is a minimal, conservative reachability inference (a reachable inference API → `AML.T0040`) distinct from the deterministic order-37 `PosturePhase`. The whole module degrades safely: no key falls back to the deterministic judge, no captured exchanges produces nothing, and it never requires the target model to be reachable to finish a run.

*(End of §6.4. §6.5 — Report (`engine/report/`) — follows.)*

## 6.5 Report (`engine/report/`)

Report is phase 40, the last phase. It assembles the canonical `Assessment` from everything the run produced, renders it into each configured format, and packages the case directory. Every renderer is a **pure function over the assessment dict** — no model, no network, no dependency on the live grains or the evidence log — so a given assessment renders identically on any machine. The package's most important structural property is that the two "brief" renderers (Markdown and the branded web brief) share their classification logic from one module, so they can never disagree about what a finding is.

### `__init__.py` and `phase.py` — the report phase

`__init__.py` registers `ReportPhase()` (40). `ReportPhase.run` (walked in §2.7 and §5.4) builds the assessment via `assemble`, then for each format in `config.output.formats` calls the matching renderer and writes the artifact into the case directory — `assessment.json` (the full structured record via `Assessment.as_dict`), `grains.json` (the evidence detail, kept separate by design), `report.md`, `report.html`, `report-brief.html`, `navigator-layer.json` — and finally, if `config.output.package` is set, zips the directory. A renderer that is not configured is simply not called; there is no PDF renderer.

### `assemble.py` — building the canonical assessment

`assemble` (walked in §2.7) turns the `RunContext` into an `Assessment`: it builds the `case` block (id, target, timestamps, tool version), the `provenance` block (the engine version, the `source_versions` map, the runtime `graph_hash`, and the `probe_log` of executed probes), and collects the components, grains, findings, and kill chains that the phases deposited on the context. It computes nothing about the findings themselves — Branch A and Branch B already produced them — so the assessment is a faithful serialization of the run.

### `markdown.py` — the Markdown brief and the shared classification

`markdown.py` renders the two-surface Markdown brief (walked at output level in §5.4) and, crucially, **owns the classification helpers the other briefs import**: `_is_behavioral` (a finding is behavioral when its evidence `match` is `behavioral`/`assessed-possible` or its grade is `demonstrated`/`possible` — i.e. it came from Branch B), `_is_proved` (proved vs assumed — a version-confirmed CVE or a demonstrated behavioral compliance, versus a product-level or reachable-only assessment), `_sort_key` (severity then confidence then id, so the most serious, most certain findings lead), and `_model_under_test`. It lays the report out as two penetration-test surfaces — Infrastructure (CVE/CWE/host) and Behavioral (ATLAS) — with a PROVED/ASSUMED marker on each finding and act-now ordering, and its evidence rendering shows a behavioral finding's graded rationale and the `exchange_id` reference. Keeping these helpers in one module is a deliberate single-source-of-truth decision.

### `html.py` — the full self-contained HTML report

`html.py` renders a single, **dependency-free** HTML document with inline CSS. It is card-based: `_finding_card` renders each finding as a severity-bordered card with a severity badge, a metadata line (id, CVE, CWE, CVSS, confidence, and the match type with the observed version when present), the attack path, and rows of technique and mitigation pills (ATLAS techniques and mitigations styled distinctly); `_severity_chip` renders the executive severity chips (a zero count is muted); `_kill_chain_rows` and `_grain_rows` render the kill-chain and evidence tables. `render_html` assembles the header (case/target/generated/operator/engine), an executive summary with the severity chips and framework list, the findings, the attack-path table, and the observed-components-and-evidence table, closing with a provenance footer that states every identifier in the brief was validated against the knowledge graph. Each empty case renders an honest sentence rather than a blank ("No findings. The observed components did not match any known vulnerability."). This renderer lists all findings as cards; it does not split them into the two surfaces the Markdown and web briefs use.

### `web_html.py` — the branded "Assessment Brief"

`web_html.py` is the richer, designed sibling of `html.py` (which it leaves untouched) — the dark-navy PsypherLabs "Assessment Brief" written to `report-brief.html`. Its docstring states a design contract the code holds to, and it is worth preserving verbatim in spirit:

- **Consumes, never computes.** The renderer reads the finding set and lays it out; it never re-grounds, re-judges, drops, or adds a finding. It **imports** `_is_behavioral`, `_is_proved`, `_sort_key`, and `_model_under_test` from `markdown.py`, so this brief and the Markdown brief cannot drift on what is behavioral/proved or how findings are ordered.
- **Fail-safe on missing optional data.** A finding with no KEV stamp, a technique with no mitigation, a CVE with no CWE — each renders cleanly with the relevant slot omitted, because real runs carry every combination of present and absent optional fields.
- **No fabricated content.** `assessment.json` does not carry the raw prompt/response transcript (that lives in `grains.json` by design), so the evidence block shows the graded rationale and the `exchange_id` **reference** — never invented dialogue.
- **Branding is verbatim** — the H1, the grounding-guarantee, and the six-bodies foundations are reproduced exactly.

`render_web_html` assembles: a brandbar and a header with a facts grid (case, target, model under test, assessed time, engine version, graph hash, operator, access tier); the six grounding "bodies" (ATLAS, ATT&CK, CVE, CWE, KEV, D3FEND) as labelled cards; an executive panel pairing a Priority breakdown (act-now / high / scheduled, bucketed by each finding's `priority`) with Proved/Assumed counts and a Surfaces-tested summary; the phase pipeline as a visual flow (deterministic vs model-touchpoint phases marked distinctly); and then the two penetration-test surfaces — Infrastructure and Behavioral — each as a section of finding cards, followed by the kill chain and observed-components sections. `_finding_card` composes per-finding attack chips, defense chips, and KEV chips, a CVE or technique metadata line, an evidence block, and a provenance line; a card with an assumed (not proved) finding is styled distinctly. Honest-empty holds here too ("No infrastructure findings — the observed serving stack matched no known-vulnerable version"; "No behavioral findings — the model resisted every judged attack").

### `navigator.py` — the ATT&CK Navigator layer

`navigator.py` (walked at output level in §5.4) emits a MITRE ATT&CK Navigator layer JSON: it collects the enterprise ATT&CK techniques referenced by the findings, scores each by the maximum severity of the findings citing it, and writes a standard layer file that imports directly into the ATT&CK Navigator. ATLAS techniques are intentionally omitted, because the Navigator is an ATT&CK-Enterprise tool — so the layer is a faithful ATT&CK view, and the ATLAS behavioral surface lives in the briefs.

### `package.py` — the packager

`package.py` zips the finished case directory into a single archive when packaging is enabled, so the entire evidence-carrying output (the structured records, the briefs, the Navigator layer, and the logs) can be handed off as one file. It is a straightforward, dependency-light bundler with no interpretation of the contents.

*(End of §6.5. §6.6 — Packs (`packs/`) — follows.)*

## 6.6 Packs (`packs/`)

The packs are where all domain capability lives — the sealed core (§6.1) names none of it. A recurring pattern runs through the pack layer: a human-facing **catalog documents**, the control plane **authorizes**, and a drift verifier asserts the two agree (§4.5). The categories are the probes, the policy profiles, the prompt registry, the red-team corpus, the relevance data, the fenced blackbox tool, the intake questionnaires, and the data-source catalog.

### `packs/probes/` — the probe packs

`probes.yaml` is the **catalog** — the single human-facing view of every probe across both surfaces, listing each probe's `surface` (`infra`/`behavioral`/`embeddings`) and `kind` (`analysis` descriptor vs `code` module) and an `enabled` flag that mirrors the allowlist. It documents; it does not authorize — the security gate stays `probes.allowlist` in `assessor.yaml`, enforced by the sealed loader, and `tests/verify.py --mode probes` asserts the catalog's enabled set matches the allowlist so the two never drift.

Each probe is a JSON manifest matching the `ProbeSpec` contract (§6.1) — `id`, `tier`, `applies_to`, `observes`, `run`, `parse`. A host-isolation probe is representative:

```json
{ "id": "docker_socket", "tier": "passive",
  "applies_to": ["host", "inference_endpoint"], "observes": ["docker_socket"],
  "run": { "type": "shell", "cmd": "test -S /var/run/docker.sock && echo present || echo absent", "via": "ssh" },
  "parse": { "lines": true, "attribute": "docker_socket" } }
```

The packs group by surface. **`host-isolation/`** is eight passive shell probes that read isolation indicators over SSH — `process_capabilities` (the `CapEff` bitmask from `/proc/self/status`), `syscall_filtering` (seccomp mode), `docker_socket`, `container_runtime`, `mac_confinement` (the AppArmor/SELinux profile), `host_hypervisor_dmi`, `cred_env_names`, and `world_readable_secrets`. Two of these are careful by construction: `cred_env_names` reports only the **names** of credential-looking environment variables (grepping for `KEY`/`TOKEN`/`SECRET` patterns), never their values, and `world_readable_secrets` reports the **paths** of world-readable secret files, never their contents — the probes observe posture, they do not exfiltrate secrets. **`ml-inference/`** holds the inventory probes that feed Branch A — `pip_freeze` and `os_packages` produce the `python_package`/`os_package` grains that promotion matches against the distribution tracker, alongside `listening_sockets`, `detect_virt`, and `api_banner`, plus `embedding_probe.py` for the embeddings surface. **`model-endpoint/`** holds endpoint-hygiene probes (`unauth_inference`, `mgmt_exposed`, `model_digest`, `endpoint_banner`) whose HTTP results feed the posture phase (an unauthenticated `200` becomes `AML.T0040`/`T1046`).

**`model-artifact/`** is worth a closer look. `model_artifact.py` is an `active_safe` script probe that performs a **static, load-free safety scan** of served model files: it triages format by magic bytes (not extension), and for pickle-derived formats it disassembles the opcode stream with the standard library's `pickletools.genops` — **never unpickling, because loading the pickle is the remote-code-execution** — flagging any `GLOBAL`/`STACK_GLOBAL` reference to a dangerous module or callable (a denylist including `os`, `subprocess`, `socket`, `eval`, `exec`, `system`, `Popen`). A safetensors/GGUF/ONNX file is `safe`; a pickle with dangerous references (or an unparseable opcode stream) is `dangerous`; a clean pickle is `executable_format`. A `dangerous` verdict is what the posture phase (§6.4) turns into the critical `AML.T0010.003` deserialization finding. This is a good model for a security-sensitive probe: it inspects without executing.

**`model-redteam/`** is the behavioral capture path. `redteam_probe.py` is a capture-only script probe that sends the ATLAS-tagged corpus to the live model over the native chat API, replays the corpus a configurable number of times (default three — which is why the brain aggregates the strongest verdict across replays, §6.4), and for each exchange writes one `redteam::<attack_id>::<sample>` grain **and** an immutable, hash-chained record to the shared evidence log carrying a stable `exchange_id`. It detects the optional canary as a hint only and **renders no verdict** — judgment lives in the brain. Its framing is explicit and load-bearing: it holds a conversation and records the transcript; dangerous ATLAS families are run as **refusal tests** that measure resistance, never as a harm generator. The `rt_*.json` manifests are the probe descriptors that invoke it, most disabled by default in the catalog.

### `packs/policy/` — the Branch B safeguard profiles

Three YAML profiles define the "constitution" the behavioral brain reasons against (§4.3, §6.4). **`strict.yaml`** (the default) reports only proven, high-signal findings: `enable_posture_inference: false` (no "possible" findings), `enable_behavioral: true` (the red-team judgment is proven signal), `max_inference_depth: 1`, `min_confidence_to_report: medium`. **`strict-posture.yaml`** is the same but turns posture inference on. **`exploratory.yaml`** widens prediction for research: posture on, `max_inference_depth: 2`, `min_confidence_to_report: low`. All three carry the same non-negotiable integrity floor — `min_grains_for_possible: 1` and `possible_findings_require_label: true` — which `policy.py`'s `_enforce_floor` re-applies after loading, so editing a profile can widen sensitivity but never disable grounding.

### `packs/prompts/` — the prompt registry

`engine-prompts.default.yaml` holds the shipped system prompts for all four Claude touchpoints: `recon` (choose the next probe from the offered ids only), `enrich` (propose an `enables` edge only from the offered technique ids), `cve` (judge candidates and select only from offered ids, be conservative), and `judge` — which ships **two graders**, a `base` four-verdict grader and a `strict` grader that resolves ambiguity toward compliance. The override, `engine-prompts.yaml`, is two lines:

```yaml
judge:
  mode: ensemble
```

This is the per-key patch-merge from §6.1 in action: it flips only the judge's mode to `ensemble` — so both graders run and the brain takes the strongest verdict — while inheriting the shipped judge variants unchanged. The default file is explicitly not to be edited for tuning; the override is the tuning surface.

### `packs/redteam/atlas-prompts.yaml` — the red-team corpus

The corpus is the ATLAS-indexed set of adversarial prompts. Each entry ties an attack to the graph with a fixed schema — `id`, a **real ATLAS `technique`** (validated against the graph by the brain's firewall), a `tactic` (for kill-chain ordering), a `name`, the `prompt`, an optional `canary` (a deterministic hard-signal), an optional `canary_kind` (`breach` by default, or `safe` where emitting the token *is* the correct refusal), an optional `cwe`, and an optional `severity_hint`. Coverage spans the LLM-relevant ATLAS families — direct prompt injection (`AML.T0051`), jailbreak (`AML.T0054`), system-prompt extraction (`AML.T0056`), and data leakage (`AML.T0057`), among others — each with a few variants. The framing is stated at the top of the file and is the reason the corpus is a defensible artifact: **dangerous families are written as refusal tests.** The prompts use benign, deterministic canary tokens to measure whether the model resists, and a finding is "the model failed to refuse X," never the harmful content itself. (This manual describes the corpus schema and its technique coverage; it does not reproduce the corpus prompts.)

### `packs/relevance/` — the scope data

`role-groups.yaml` (generated by `data/relevance_build.py`) is the pack `engine/relevance.py` consumes (§6.4). It defines scope `profiles` (the tightest, `strict`, includes the serving-stack, isolation-boundary, and host-privesc tiers; `standard`/`full` add crypto/network, auth/secrets, and web-frontend), an `exclude` list of non-runtime families (source/dev/doc packages, never in scope), and the `role_groups` themselves — each mapping a set of upstream **project-name patterns** (cross-distro, e.g. the model-server group matches `vllm`, `triton`, `tgi`, `ollama`, `ray`, and more) to a `tier`, a set of **real graph technique ids**, and a real **D3FEND artifact IRI**. `attack-artifact-map.json` is the large extracted D3FEND map (ATT&CK technique → offensive artifact → defensive technique) that the D3FEND overlay composes onto the graph (§6.3). Together these encode the "scope, not severity" and "agnostic, grounded" properties in data.

### `packs/blackbox/` — the fenced diagnostic

The blackbox pack is a deliberately fenced side-tool: `blackbox.yaml` is a standalone config **separate from `assessor.yaml`**, off by default, **not a phase and not allowlisted**, run only by its own launcher. `black_box_probe.py` mirrors the script-probe contract but exposes only two benign, reviewed legs — an HTTP version check against the target's own endpoint, and a fixed, benign SSH check using the same `BatchMode=yes` pattern as the engine's shell runner — explicitly *not* an arbitrary-command channel. It exists for isolated connectivity diagnostics and is intentionally kept outside the assessment pipeline.

### `packs/intake/` and `packs/data/sources.yaml`

`packs/intake/` holds the operator questionnaires (`example.yaml`, `ollama.yaml`) — the facts no probe can reach (deployment environment, tenant isolation, checkpoint provenance) that discovery folds into `engagement` grains (§6.2). `packs/data/sources.yaml` is the **source catalog** — it documents the graph data sources (`atlas`, `attack`, `cve`, `cwe`, each with a path and format) but, like `probes.yaml`, does not authorize: the authoritative list stays `graph.sources` in `assessor.yaml`, and `verify.py --mode sources` asserts they match. It references the large data files by path and never contains them. The empty `packs/profiles/` and `packs/sources/` directories are placeholders (with `.gitkeep`) for operator-supplied profiles and graph sources.

*(End of §6.6. §6.7 — Data builders, ops, and tests — follows.)*

## 6.7 Data builders, ops, and tests

This closes Part VI with everything outside `engine/` and `packs/`: the builders that produce the indices the pipeline reads, the root operational scripts, the cached graph output, the project metadata, and the test/verifier suite that mechanically proves the system's guarantees.

### `data/` — the index builders

The builders are standalone, standard-library-only, deterministic, and import no engine code — each turns an upstream corpus into the exact artifact a pipeline component reads, and prints a self-check. Part III walks running them end to end; here are their contracts.

`distro_index.py` builds `data/distro/debian.sqlite` — the authoritative per-package, per-release CVE status that makes promotion collision-free and backport-aware. Its schema is the table promotion queries:

```sql
CREATE TABLE deb (package TEXT, cve_id TEXT, release TEXT, status TEXT, fixed_version TEXT, urgency TEXT);
CREATE INDEX idx_deb_pkg ON deb(package, release);
```

`nvd_index.py` builds `data/nvd/index.sqlite` — a `cve` table keyed by CVE id carrying `cvss`, `cvss_severity`, `cvss_version`, and `cwes`, the read-only enrichment that promotion and the KEV path look up by id. `kev_build.py` builds `data/kev/kev.json` — the `{CVE-ID: {ransomware, date_added, …}}` map the analyzer loads (fail-open) as a ranking signal, never a filter. `d3fend_extract.py` reads the large D3FEND full-mappings export and builds `packs/relevance/attack-artifact-map.json` — the ATT&CK-technique → offensive-artifact → defensive-technique map the D3FEND overlay composes onto the graph (§6.3). `relevance_build.py` builds `packs/relevance/role-groups.yaml` — the scoped, grounded role-group catalog `engine/relevance.py` consumes (§6.4). The acquisition wrappers `fetch.sh` and `nvd-build.sh` download the upstream corpora and drive the indexers (Part III). Each builder ships a self-check (for example, `distro_index.py` asserts a known package/CVE/release row is present after building) so a broken build is visible immediately.

> **Current-source marker — `build_d3fend_cwe_slice.py` and `data/d3fend/cwe-countermeasures.json`.** These belong to the weakness-grounded D3FEND layer and postdate this snapshot, so they are documented by contract rather than at line level. `build_d3fend_cwe_slice.py` is the builder — the CWE-slice counterpart to `d3fend_extract.py` — that reads the same D3FEND export and emits `data/d3fend/cwe-countermeasures.json`, the `CWE → countermeasure` slice that the graph's `ingest_d3fend_cwe` overlay (§6.3) composes into `mitigation` nodes anchored from `weakness` nodes, and that the defense phase's weakness attach loop (§6.4) resolves. By its record it introduces no new node or edge type and follows the same standalone, deterministic, self-checking builder pattern as the others. Part III includes it as build step 7 in the data-build sequence.

### Root operational scripts

`run.sh` is the launcher — it activates the environment and runs `python -m engine`, and also exposes the `test`/`audit` conveniences that wrap the suite below. `setkey.sh` and `setmodel.sh` set the API-key and model-selection environment variables for a session (§5.2), `selfcheck.sh` is a preflight check, and `clean.sh` resets generated output. `blackbox-run.sh` is the separate launcher for the fenced blackbox tool (§6.6) — deliberately not part of the main pipeline. `psypher-brand.sh` and `psypher-hop.sh` are auxiliary operator helpers (branding/banner tooling and a connection helper) that sit outside the assessment path.

### `build/graph/` — the cached graph output

`build/graph/` holds the `GraphStore` freeze — `nodes.json`, `edges.json`, and `meta.json` (§6.3). This is the **pre-overlay** cached graph, keyed by the source fingerprint recorded in `meta.json` (alongside the content hash, counts, and build time); the promotion and D3FEND overlays are applied at runtime and are not in these files, which is why the on-disk cache and the runtime graph legitimately differ. The verifiers read `nodes.json` here as their ground truth for what identifiers the system can emit.

### Project metadata

`pyproject.toml` and `requirements.txt` declare the small dependency set (the Anthropic SDK, `rich` for the terminal output, `jsonschema` for validation, and PyYAML), `.gitignore` excludes the large data corpora and generated artifacts, and `assessor.yaml` is the control plane walked in Part IV.

### `tests/` — the executable proof of the invariants

The test suite is where the system's guarantees become mechanical checks that run without a model, a key, or network access.

`system_test.py` is the end-to-end integrity smoke test — clone the repository, run it, and know in seconds whether the installation is sound. It runs **20 checks** in three groups, using synthetic in-memory data:

- **Shared spine (7):** modules import; phases register in the correct order; the evidence-log hash chain writes and verifies; tamper-detection fires on an edited chain; posture verdict logging keeps the chain intact; `assessment.json` conforms to its schema; and the Markdown report renders both surfaces with defenses.
- **Branch A · infrastructure (4):** the knowledge graph loads with real MITRE ATLAS technique ids; the KEV overlay flags exploited CVEs and derives priority; the defense phase attaches grounded countermeasures; and the D3FEND overlay grounds countermeasures into the graph.
- **Branch B · the model (9):** the policy integrity floor cannot be disabled; the analysis firewall rejects fabricated technique ids; the posture firewall does likewise; relevance scoping routes out-of-scope packages to the catalogue; the probe catalogue matches the allowlist; the source catalogue matches `graph.sources`; the ATLAS corpus is valid; the deterministic judge grades synthetic exchanges; and the prompt override patch-merges (a mode-only override keeps the default variants). 

Exit code 0 means every check passed. In effect this file is the executable form of the guarantees in Part VIII. (A `check_pdf_renders` function exists in the file but is deliberately not wired into the run, a residue of the retired PDF renderer.)

`verify.py` is the mechanical verifier that proves a *given run* is trustworthy. It has several modes: `static` verifies the system's static labels (every technique id the corpus and posture rules emit exists in the graph and is the right type; every CWE is a weakness); `audit` (the default) verifies a completed run's outputs and provenance — every finding's technique and CWE are graph-grounded and correctly typed, no ungrounded id slipped through, the evidence-log hash chain verifies, and the artifacts are internally consistent; and it also checks the probe and source catalogues against the control plane and the assessment against its schema. It is candid about its limit: it does not judge whether a verdict was *semantically* right — that is human judgment — and it prints the graph's ATLAS version every run so staleness is always visible. `verify_labels.py` is the focused label-grounding tool that predates the consolidated verifier and complements the runtime firewall: because the firewall checks id **existence** but not semantic **fit**, a wrong-but-real id (tagging one attack with another technique's id) would pass silently — so this tool confirms every corpus and posture id is a real `technique` node and prints its official name for a human to eyeball, and confirms CWEs are `weakness` nodes that never cross into technique anchors. Together, the three give three independent assurances: the installation is sound (`system_test.py`), each report is grounded and intact (`verify.py`), and the labels are the right *kind* of thing (`verify_labels.py`).

*(End of §6.7 — and of Part VI. Every file in the repository map is documented from current source; the two weakness-layer files absent from this snapshot are documented by contract and marked `[~]`. Part VII — Extending the System — follows.)*

---

# Part VII — Extending the System

Everything in Part VI was built so that this part is short. The system has one governing extension rule, stated in Part I and enforced by the architecture: **grow capability through packs and data, not by editing the sealed core.** A core change is the rare exception that must be justified against §6.1. Each procedure below names the exact files to touch, the gate that must be satisfied, the verifier that proves it, and the pitfalls — all pointing back to the mechanism that makes it work.

Two rules run through all of them and are worth stating once. First: **every framework identifier a new component introduces must resolve to a graph node, or it is dropped.** A technique or mitigation id that is not a node is rejected by the closing firewall (§2.6), the analysis/posture firewalls (§6.4), and — for behavioral verdicts — the brain's firewall (§6.4); the id existing is necessary but not sufficient, because `verify_labels.py` (§6.7) still checks it is the right *type*. Second: **run the verifiers after any change.** `system_test.py` proves the installation still holds together, and `verify.py`/`verify_labels.py` prove the labels and any run are grounded.

## 7.1 Add a probe

A probe adds a way to observe the target. All you write is data (a JSON manifest) and, for a `script` probe, a small Python module — the sealed harness (§6.2) runs it.

1. Write the manifest matching the `ProbeSpec` schema (§6.1): `id`, `tier` (`passive`/`active_safe`/`intrusive`), `applies_to` (asset kinds), `observes`, a `run` block (`shell` with `cmd`/`via`, `script` with `path`/`entry`, or `http` with `method`/`path_suffix`), and a `parse` block (`regex`/`json`/`lines`). Place it in the relevant pack directory under `packs/probes/`.
2. For a `script` probe, write the module next to the manifest with the entry signature `run(target, context) -> dict`, and set `parse: {"from": "return_value"}` so each returned key becomes a grain. Follow `model_artifact.py`'s discipline for anything sensitive: observe without executing or exfiltrating (read indicators, not secret values).
3. **Add the probe id to `probes.allowlist` in `assessor.yaml`.** This is the step that actually enables it — the manifest alone does nothing (§4.5, §6.1).
4. Add a matching row to the `packs/probes/probes.yaml` catalogue (surface/kind/enabled) so the documentation stays in step.
5. Verify: `tests/verify.py --mode probes` asserts the catalogue matches the allowlist; the loader validates the manifest against `probe.schema.json` at startup.

**Pitfalls.** The allowlist is the gate, not the manifest. The tier must be enabled in the engagement policy, and an intrusive probe also needs approval (§6.2). A probe only reaches an asset the connection it needs is declared on (SSH/endpoint). The `parse` spec must match the probe's actual output or it records no grains. A new posture mapping that turns a grain into a finding lives in `posture.py`/`brain.py`, not the probe — the probe stays "dumb."

## 7.2 Add a red-team attack

An attack is a new entry in the corpus (§6.6) — a refusal test, framed as measuring resistance, never as generating harm.

1. Add an entry to `packs/redteam/atlas-prompts.yaml` with `id`, a **real ATLAS `technique`** id, a `tactic`, a `name`, the `prompt`, and optionally a `canary` (with `canary_kind: breach` or `safe`), a `cwe`, and a `severity_hint`.
2. Ensure the `technique` id is present in the graph (it comes from the ATLAS/ATT&CK STIX you built in Part III). If it is not a node, the brain's firewall drops every verdict for that attack (§6.4).
3. Verify: `tests/verify.py --mode static` (or `verify_labels.py`) confirms the id exists **and is typed `technique`**, and prints its official MITRE name so you can eyeball semantic fit.

**Pitfalls.** The firewall checks existence, not fit — a wrong-but-real id (a plausible ATLAS technique that does not match the attack) passes the firewall silently and only `verify_labels.py` plus a human read will catch it. Keep the framing defensive: the finding is "the model failed to refuse X," and a `safe` canary is a token whose emission is the *correct refusal*. The corpus is replayed several times per run, so design the canary to be a clean deterministic signal.

## 7.3 Add a policy profile

A profile tunes how much the behavioral brain may predict, within a floor it cannot cross (§4.3, §6.6).

1. Copy `packs/policy/strict.yaml` to `packs/policy/<name>.yaml` and edit the free knobs: the `prediction` toggles (`enable_structural`/`enable_posture_inference`/`enable_behavioral`, `max_inference_depth`), the `confidence.min_confidence_to_report`, the `severity.cap_possible_at`, and the `scope.domains`.
2. Select it at run time with `PSYPHER_POLICY=<name>` (a bare name resolves to `packs/policy/<name>.yaml`; a path or `.yaml` value is used as-is).

**Pitfalls.** You cannot disable the integrity floor — `policy.py`'s `_enforce_floor` re-applies `min_grains_for_possible ≥ 1`, `possible_findings_require_label`, and id-dropping after your file loads (§6.4). A malformed or missing file falls back to built-in strict defaults, so the brain always runs and always errs safe.

## 7.4 Add or change a Claude-touchpoint prompt

Prompts are data in the registry (§6.6); the tuning surface is the override file, never the shipped default.

1. Create or edit `packs/prompts/engine-prompts.yaml` (the override). Because `_merge` is a **per-key patch-merge** (§6.1), you edit only what you want to change — a role, a `mode`, or a `variants` list — and everything else falls through to `engine-prompts.default.yaml`.
2. For the judge, add a grader to `variants` and/or set `mode: ensemble` to run all graders and take the strongest verdict.

**Pitfalls.** Do not edit the shipped default (it is the fallback). The judge rubric floor is un-bypassable: a judge system prompt missing any of the four verdicts (`complied`/`refused`/`partial`/`confabulated`) is rejected in favor of the default (§6.1). The judge **tool schema is not externalized** — it stays hardcoded in `brain.py` because the light schema is load-bearing (§6.4); only the system prompt is data.

## 7.5 Add a relevance role-group

A role-group extends what counts as in-scope for a target's role (§6.4, §6.6).

1. Add an entry to `packs/relevance/role-groups.yaml` (or regenerate it with `python data/relevance_build.py`): a `name`, a `tier`, a list of upstream **project-name `patterns`** (cross-distro, version-tolerant), a list of **real graph `techniques`**, and a real D3FEND `d3fend_artifact` IRI.
2. Confirm the group's `tier` is included in the profiles under which it should apply (`strict`/`standard`/`full`).

**Pitfalls.** Relevance is scope, not severity — a package matched by a group whose tier is not in the active profile is **catalogued, not hidden** (§6.3). Patterns match project names, not distro package names, so they work across distributions; add non-runtime families to `exclude`. Techniques that are not graph nodes will not survive downstream grounding.

## 7.6 Add a report renderer

A renderer adds an output format. It consumes the assessment and never recomputes it (§6.5).

1. Write `render_<fmt>(assessment, operator, tool_name) -> str` in `engine/report/<fmt>.py`, importing the classification helpers (`_is_behavioral`, `_is_proved`, `_sort_key`) from `markdown.py` rather than duplicating them.
2. Wire it into the format dispatch in `engine/report/phase.py` (and `assemble.py` if it needs a new field), and add the format name to `config.output.formats` and to the `OUTPUT_FORMATS` vocabulary in `engine/core/config.py`.

**Pitfalls.** A renderer must be a **pure function** of the assessment dict — no model, no network, no re-grounding, re-judging, dropping, or adding of findings (§6.5). Be fail-safe on missing optional data (a finding with no KEV, a technique with no mitigation) and never fabricate content — `assessment.json` carries no raw transcript, so reference the `exchange_id`, don't invent dialogue. A format name absent from the frozen `OUTPUT_FORMATS` set is rejected by config validation. (This is the one procedure that touches a core file — the format vocabulary in `config.py` — which is why the format set is a deliberate, small, reviewed list.)

## 7.7 Add an analysis phase

A phase adds a stage to the pipeline (§2.1–2.2, §6.4). It self-registers and threads the shared context.

1. Subclass `Phase` (`name`, a numeric `order`, and `run(ctx)`), read what you need off the `RunContext` (`ctx.grains`, `ctx.artifacts["graph"]`, `ctx.findings`), and append your findings. Call `register_phase()` at import, and ensure the package is imported by the controller's phase-import set so it registers.
2. Choose an order slot relative to the existing phases (discovery 10, graph 20, analysis 30, brain 35, posture 37, defense 38, report 40).

**Pitfalls.** The closing firewall runs inside analysis at order 30, so **any phase that emits findings after 30 must validate its own technique/mitigation ids against the graph** (invariant 3 — this is exactly what `posture.py` and `brain.py` do, §6.4). Emit the canonical `Finding` shape and put branch-specific fields in its `evidence` dict — that is why no `models.py` change is needed. If your phase calls a model, it needs its own firewall in the propose → graph-membership → deterministic-fallback pattern (§2.6); never trust a model for an identifier.

## 7.8 Add a graph data source

A source extends the grounding graph with a new authoritative corpus (§6.3).

1. Provide the data: add a builder under `data/` (following the standalone, stdlib-only, self-checking pattern) and the corpus it produces.
2. Add the source to `graph.sources` in `assessor.yaml` (`id`, `path`, `format`), and add a matching row to the `packs/data/sources.yaml` catalogue.
3. If the corpus is a **new format**, add a dispatch branch in `engine/graph/phase.py`'s `_build` and write an ingester alongside `stix.py`/`cve.py`/`cwe.py` that maps the corpus into the canonical graph.

**Pitfalls.** The node and edge vocabularies are **closed** — `add_node`/`add_edge` reject any type outside the six-and-six (§6.3), so a genuinely new relationship is a deliberate core change, not a pack edit. Set a node's `framework` at ingest from the source, and remember that analysis reads framework *from the node*, never from an id prefix (§6.4). Changing the source data changes the fingerprint and invalidates the cache automatically (§6.3). Verify with `tests/verify.py --mode sources` (catalogue matches the control plane).

## 7.9 The pattern behind all of them

Every procedure above is the same shape: **add data (a manifest, a corpus entry, a profile, a source) or a self-contained module (a probe, a renderer, a phase) that plugs into a contract the sealed core already enforces, then satisfy the gate and run the verifier.** The core does not change because it never needed to know about the specific probe, attack, framework, or format — it knows only how to load, thread, ground, and record. When an extension *does* require a core edit — a new output format in `config.py`, a new node/edge type in `canonical.py`, a new firewalled model touchpoint — treat it as an exception that earns its own review against the invariants in Part VIII, because those files are the contract the entire system's guarantees rest on.

*(End of Part VII. Part VIII — Design Principles, Invariants & Operational Subtleties — follows.)*

---

# Part VIII — Design Principles, Invariants & Operational Subtleties

This part is the reference capstone: the guarantees restated as the design decisions that produced them, the hard invariants with the exact code that enforces each, the subtleties that trip people up, and consolidated lookup tables and a glossary. Everything here has already been shown in the code across Parts II–VI; this is where it is collected.

## 8.1 Design principles — the decisions behind the system

**Grounding over generation.** The system's central bet is that a security tool must never invent an identifier. Every technique, tactic, mitigation, CVE, and CWE it reports is a node in a graph built from official sources, and the graph's `has(id)` membership test is the arbiter at every point a model or a mapping could introduce one. This is why the graph exists as a first-class phase rather than a lookup table, and why "the model proposes, the graph disposes" recurs at every touchpoint.

**Two orthogonal branches, one report.** Infrastructure vulnerability ("does this run a known-vulnerable version?") and model behavior ("how did the model respond when attacked?") are genuinely different questions with different truth conditions, so the system runs them as two branches — Branch A (deterministic, CVE/CWE/host) and Branch B (reasoned, behavioral) — that emit the *same* `Finding` shape and are rendered together. The decision to keep the `Finding` shape fixed and let branch-specific data ride in an `evidence` dict is what let Branch B be added with no change to the core data model.

**Determinism where truth must not move.** Branch A is model-free by deliberate choice: version-matched facts must never be dropped by a model's applicability judgment, so `select_analyzer` always returns the deterministic analyzer and Claude's CVE reasoning is confined to enrichment and Branch B, where it can only add. Every model touchpoint has a deterministic fallback, so the pipeline always finishes — without a key, without the SDK, without the target reachable.

**Firewalled model touchpoints.** Where a model *is* used (recon, enrichment, the retained CVE analyzer, the behavioral judge), it is boxed into a fixed pattern: propose → graph-membership check → deterministic fallback. The model's judgment is kept as signal; its identifiers are never trusted.

**Honesty as a feature.** The system is built to say less rather than claim more: an empty finding set renders as an honest sentence, findings are marked PROVED vs ASSUMED, posture is `observed` vs `inferred` with a conservative access floor, CVE promotion defers to the distribution's own security team, and the web brief references an `exchange_id` rather than fabricating a transcript. Untriaged is not treated as unimportant; a promoted CVE with no technique legitimately shows none.

**Sealed core, swappable packs.** Capability lives in packs and data; the core knows only how to load, thread, ground, and record. This is what makes the extension procedures in Part VII data edits rather than core surgery, and it is enforced by the single coupling point (`contracts.py`) and the closed graph vocabulary.

**Auditability end to end.** Every behavioral exchange is written to a hash-chained, tamper-evident log with a stable `exchange_id` that each finding references, and three verifiers prove the installation, each run, and the label types independently.

## 8.2 The invariants and where they are enforced

| # | Invariant | Enforced in | Why |
|---|-----------|-------------|-----|
| 1 | Every emitted identifier is a graph node | closing firewall (`validate.py`, order 30); analysis/posture firewalls; brain firewall (§6.4) | grounding — no fabricated ids reach a report |
| 2 | A mitigation's framework comes from its graph node, never an id prefix | `match.py` `mitigations_for_technique`; `defense.py` `_framework_for` (§6.4) | a D3FEND countermeasure id has no ATLAS/ATT&CK prefix |
| 3 | Findings produced after order 30 validate their own ids | `posture.py`, `brain.py`, `defense.py` (§6.4) | the closing firewall runs only at 30 |
| 4 | The policy integrity floor cannot be disabled | `policy.py` `_enforce_floor` (§4.3, §6.4) | a profile edit must not weaken grounding |
| 5 | The judge rubric floor (four verdicts) is un-bypassable | `prompts.py` `get_prompts("judge")` (§6.1) | the behavioral grade must always use the full rubric |
| 6 | Branding is emitted verbatim | `banner.py`; the report renderers (§6.1, §6.5) | fixed product identity |
| 7 | CVE promotion is distribution-authoritative and backport-aware | `promote.py` `deb_compare` + open/resolved logic (§6.3) | never a raw product/version match |
| 8 | Relevance is scope, not severity | `relevance.py`; `promote.py` (§6.3–6.4) | out-of-scope CVEs are catalogued, never hidden |
| 9 | The judge tool schema stays light and hardcoded | `brain.py` `_JUDGE_TOOL` (§6.4) | a heavy schema caused empty tool calls / zero findings |
| 10 | The allowlist is the gate; catalogues only document | `loader.py`; `verify.py --mode probes/sources` (§6.1, §6.7) | one authoritative gate, drift-checked |
| 11 | Probes capture; the analyzer judges | the probe packs; `brain.py` (§6.4, §6.6) | dumb probes stay reusable, reasoning stays auditable |
| 12 | The canary is a hint, not a verdict | `brain.py` judge + deterministic fallback (§6.4) | a model can emit a canary while refusing, or confabulate |
| 13 | The `Finding` shape is fixed; branch-specific data rides in `evidence` | `models.py`; `brain.py` `_make_finding` (§6.1, §6.4) | Branch B added with no core data-model change |
| 14 | Overlays never enter the cache | `graph/phase.py` (promotion + D3FEND run post-save) (§6.3) | runtime graph legitimately differs from the cache |
| 15 | Every touchpoint degrades to a deterministic fallback | recon/enrich/analyze/brain (§2.6, §6.4) | a run never requires a model, key, or network to finish |

## 8.3 Operational subtleties and gotchas

**The runtime graph is not the cached graph.** The on-disk `build/graph/*.json` is the pre-overlay build; promotion and the D3FEND overlays are applied at runtime and are never cached. When debugging a promoted or overlaid node, inspect the graph on the run context (`ctx.artifacts["graph"]`), not the cache files.

**Honest-zero is a result, not a failure.** No findings means the observed components matched no known-vulnerable version and the model resisted every judged attack. The renderers say exactly that; do not read an empty report as a broken run.

**`min_access` is metadata, not a hard gate.** The effective access control in discovery is the denylist plus the tier policy plus the connections the asset actually declares (an SSH probe fails cleanly without `ssh`, an HTTP probe without `endpoint`). A probe's `min_access` is carried on the manifest but not applied as a comparison gate (§6.2).

**Strongest-verdict aggregation happens twice.** The behavioral verdict is aggregated at two levels, both using `complied > partial > confabulated > refused`: across graders in the ensemble (`_judge_with_claude`) and across corpus replays in the phase (`BrainPhase.run`). A single compliance in any replay surfaces the weakness (§6.4).

**A safe-token canary is a refusal.** When a corpus entry sets `canary_kind: safe`, emitting the canary is the *correct refusal*, and both the Claude judge and the deterministic fallback grade it as `refused` — the opposite of a `breach` canary (§6.4, §6.6).

**A promoted CVE has a CWE but no technique edge.** Promotion adds a vulnerability node and `instance_of` edges to its CWEs, but no `enables → technique` edge, so a distribution-promoted CVE legitimately surfaces with its CWE and CVSS and no ATLAS/ATT&CK technique. This is correct, not a gap in the finding (§6.3, §5.5).

**Existence is not fit.** The runtime firewall proves an id is a real node; it does not prove the id *matches* the finding. `verify_labels.py` (and `verify.py --mode static`) prove the id is the right *type* and print its official name for a human to judge semantic fit (§6.7).

**Catalogues document; the control plane authorizes.** `packs/probes/probes.yaml` and `packs/data/sources.yaml` are human-facing inventories that authorize nothing; the gates are `probes.allowlist` and `graph.sources` in `assessor.yaml`, and the drift verifiers assert the two agree (§4.5, §6.7).

**The stale-snapshot boundary (this manual's own note).** The mitigation-framework contract is fully current in `match.py` (which already produces `(id, name, framework)` mitigations from the graph node); the five consuming unpack sites in `analyze.py` and the weakness attach loop in `defense.py` are the localized additions that the current tree carries, along with the `ingest_d3fend_cwe` overlay in `d3fend.py`/`phase.py` and the `build_d3fend_cwe_slice.py` builder. These are marked at their locations in §6.3–6.4 and by contract in §6.7; the delta introduces no new node or edge type.

## 8.4 Reference tables

### The pipeline

| Phase | Order | Branch | Model touchpoint? | Role |
|-------|-------|--------|-------------------|------|
| discovery | 10 | A | recon (firewalled) | probe in-scope assets → evidence-backed grains + component inventory |
| graph | 20 | shared | enrich (firewalled) | build/load the canonical graph; apply promotion + D3FEND overlays at runtime |
| analysis | 30 | A | CVE analyzer (retained, not selected) | match candidates → deterministic findings → closing firewall → kill chain |
| brain | 35 | B | judge (firewalled) | judge captured red-team exchanges → behavioral findings; policy-gated posture |
| posture | 37 | A | none | host-isolation/endpoint grains → technique-anchored "possible" findings |
| defense | 38 | shared | none | attach graph-grounded mitigations to every finding |
| report | 40 | shared | none | assemble the assessment; render each format; package |

### The graph vocabulary (closed)

- **Node types (6):** `tactic`, `technique`, `mitigation`, `vulnerability`, `weakness`, `asset`.
- **Edge types (6):** `accomplishes` (technique→tactic), `mitigated_by` (technique/weakness→mitigation), `enables` (vulnerability→technique), `instance_of` (vulnerability→weakness), `child_of` (technique→technique), `exposes` (asset→…).

### The firewalled touchpoints

| Role | Proposes | Disposed by | Fallback |
|------|----------|-------------|----------|
| recon | the next probe to run | membership in the available-probe set | exhaustive strategy |
| enrich | `enables` edges (vuln→technique) | technique must be a graph node | structural graph (no enrichment) |
| CVE analyzer *(retained, off-path)* | applicability, severity, offered ids | offered-id membership | deterministic heuristic analyzer (always selected) |
| judge | one verdict per attack (four-verdict rubric) | corpus technique must be a graph node | deterministic canary + refusal heuristic |

### The un-disableable floors

- **Policy integrity floor:** `min_grains_for_possible ≥ 1`, `possible_findings_require_label`, drop-unvalidated-ids — re-applied by `_enforce_floor` after any profile loads.
- **Judge rubric floor:** a judge system prompt missing any of `complied`/`refused`/`partial`/`confabulated` is rejected in favor of the default.
- **Grounding floor:** the closing firewall + per-phase self-validation; nothing ungrounded reaches a report.

### Environment variables

| Variable | Effect |
|----------|--------|
| `ANTHROPIC_API_KEY` (the configured `api_key_env`) | enables the model touchpoints; absent → deterministic everywhere |
| `PSYPHER_CLAUDE_MODEL` | overrides the model for all roles |
| `PSYPHER_<ROLE>_MODEL` (e.g. `_RECON_`, `_ANALYSIS_`) | overrides one role (takes precedence over the global) |
| `PSYPHER_POLICY` | selects the Branch B profile (bare name → `packs/policy/<name>.yaml`) |
| `PSYPHER_APPROVE_INTRUSIVE` | pre-authorizes intrusive probes (else TTY confirmation, else denied) |
| `PSYPHER_INSECURE_TLS` | skip TLS verification for self-signed infra (HTTP probes) |
| `PSYPHER_RAW_CAP` | override the captured raw-output cap |
| `PSYPHER_NO_BANNER` | suppress the startup banner |
| `PSYPHER_REDTEAM_SAMPLES` | number of corpus replays (default 3) |
| `PSYPHER_REDTEAM_CORPUS` / `PSYPHER_REDTEAM_MODEL` | override the corpus path / the model under test |
| `PSYPHER_MODEL_PATHS` | explicit model-artifact paths for the serialization scan |

### Output artifacts

| Artifact | Contents |
|----------|----------|
| `assessment.json` | the canonical record (case, provenance, summary, components, grains, findings, kill chains) |
| `grains.json` | the evidence detail, kept separate from the assessment |
| `report.md` | the two-surface Markdown brief (PROVED/ASSUMED, act-now ordering) |
| `report.html` | the dependency-free styled HTML report (cards, tables, provenance footer) |
| `report-brief.html` | the branded "Assessment Brief" (grounding bodies, priority/verity, two surfaces) |
| `navigator-layer.json` | an ATT&CK Navigator layer (ATLAS omitted) |
| `logs/exchanges.jsonl` | the hash-chained evidence log (per-case; a global master also exists) |
| `<case>.zip` | the packaged case directory (when packaging is enabled) |
| `build/graph/{nodes,edges,meta}.json` | the pre-overlay cached graph + fingerprint/hash/counts |

### Enums and exit codes

- **Verdicts:** `complied`, `refused`, `partial`, `confabulated`. **Grades:** `demonstrated` (behavioral, proven), `possible` (posture, reachable).
- **Severity:** `critical`, `high`, `medium`, `low`, `info`. **Confidence:** `verified`, `high`, `medium`, `low`, `unverified`. **Priority:** `act-now`, `high`, `scheduled`.
- **Exit codes:** the engine returns `0` (success), `2` (config error), `130` (interrupt); `system_test.py`/`verify.py`/`verify_labels.py` return `0` on success and non-zero on any failure (CI-friendly).

## 8.5 Glossary

- **Grain** — an evidence-backed observation (component, attribute, value, confidence, evidence); the atomic fact produced by discovery. Never an assumption.
- **Candidate** — a vulnerability raised against a component by deterministic matching, carrying its graph context (techniques, mitigations); consumed by the analyzer.
- **Finding** — a judged result; the canonical output record, identical in shape across both branches, with branch-specific fields in its `evidence` dict.
- **Kill chain** — the findings' techniques sequenced by canonical tactic order into an ordered attack path.
- **Grounding** — the property that an identifier resolves to a node in the knowledge graph; the arbiter is `graph.has(id)`.
- **Firewall** — a point that discards any identifier a model (or mapping) proposes that is not in the graph.
- **Touchpoint** — a place the engine calls a model; each is firewalled and has a deterministic fallback.
- **Promotion** — the per-run, distribution-authoritative selection of CVEs genuinely open on the target's exact installed versions (backport-aware).
- **Overlay** — a per-run, deterministic augmentation of the finished graph (promotion, D3FEND) applied after the cache save; never cached.
- **Catalogue vs allowlist** — a catalogue (`probes.yaml`, `sources.yaml`) documents; the allowlist / `graph.sources` in `assessor.yaml` authorizes; drift verifiers assert they agree.
- **Branch A / Branch B** — the infrastructure (CVE/CWE/host, deterministic) and behavioral (model, reasoned) analysis paths.
- **Posture** — deterministic host-isolation/endpoint findings that make a technique *reachable* ("possible") without a CVE or behavioral proof.
- **Behavioral** — findings graded from the model's actual responses to the adversarial corpus ("demonstrated").
- **PROVED / ASSUMED** — a report marker: a version-confirmed CVE or demonstrated compliance vs a product-level or reachable-only assessment.
- **Canary (breach / safe)** — a deterministic token in a corpus entry; emitting a `breach` canary is compliance, emitting a `safe` canary is the correct refusal.
- **Corpus** — the ATLAS-indexed red-team prompt set (`atlas-prompts.yaml`); each entry is a refusal test tied to a real ATLAS technique.
- **Role-group / relevance** — the mapping of upstream project families to a scope tier used to keep out-of-scope CVEs out of the report (catalogued, not hidden).
- **Evidence log / exchange_id** — the hash-chained, tamper-evident record of every behavioral exchange; the `exchange_id` links a finding to the exact captured exchange.
- **KEV** — the CISA Known Exploited Vulnerabilities snapshot; a ranking signal (`act-now` priority, read-only judge context), never a filter.
- **D3FEND overlay** — the composition of the ATT&CK→artifact→countermeasure map (and, in the current tree, a CWE→countermeasure slice) into `mitigation` nodes so defenses are named for each finding.

*(End of Part VIII.)*

---

# Closing — Document Retirement & Consistency

This manual was written to be the single authoritative developer and architecture reference for the Psypher AI Threat Assessor: one document, built by reading the actual source file by file, that covers what the system is (Part I), how it is designed and flows (Part II), how to set it up, configure it, and run it (Parts III–V), what every file does at the code level (Part VI), how to extend it (Part VII), and the principles, invariants, and reference tables that hold it together (Part VIII). With Parts I–VIII complete and the repository map fully resolved, the developer-facing content previously spread across several documents now lives here.

## What this manual supersedes

| Source document | Status | Where its content now lives |
|-----------------|--------|-----------------------------|
| Prior developer manual (2026-07-09 base) | **Retire** — fully superseded | This document in its entirety, at greater depth and from current source |
| Control-plane manual | Consolidated | Part IV (every `assessor.yaml` key) and §6.1 (`config.py`) |
| Setup manual | Consolidated | Part III (setup from zero) and §6.7 (the data builders) |
| User manual | Consolidated | Part V (running and reading) and §6.5 (the renderers) |
| Policy manual | Consolidated | Part IV (profiles) and §6.4 (`policy.py`, the floor) |
| Posture manual | Consolidated | §6.4 (`posture.py`, the mapping rules and firewall) |
| CVE-seed guide | Consolidated | Part III (build steps) and §6.3 (`cve.py`, `promote.py`) |
| Pocket / quick-reference | Consolidated | Part VIII §8.4 (reference tables) and §8.5 (glossary) |
| Corpus-mapping SOP | Consolidated | §6.6 (the corpus) and §7.2 (add a red-team attack) |
| POC technical paper | **Retain as distinct** | Complementary — the narrative, origin, and design rationale; not superseded |

The recommendation is to **retire the prior developer manual outright** and to treat this document as the authoritative developer/architecture reference in place of the consolidated operator manuals. If the team wants to keep any of those as short, operator-facing quick-start pages, they can remain — but their developer and architecture content is now here, mapped to the specific parts above, so a change to the system needs updating in one place. The POC technical paper stays as the complementary "why and how it came to be" narrative.

## Consistency

The manual is internally consistent across its eight parts. The repository map at the front is the single coverage spine — every file is marked, forward references from Parts II–V resolve into the per-file walk in Part VI, and Part VII's procedures and Part VIII's invariants both point back to the mechanisms Part VI established. Branding is reproduced verbatim wherever it appears (the locked name, tagline, and attribution), publication-safety was maintained throughout (no personal paths or usernames, generic repo-relative commands, the defensive refusal-test framing preserved for the corpus and red-team paths), and contested specifics were taken from source rather than from summaries — the system test's **20 checks**, the `deb`/`cve` SQLite schemas, the light judge schema, and the mitigation-framework contract were each read from the code.

**One honest reconciliation note.** This manual was written against a curated source snapshot. The weakness-grounded D3FEND defense layer postdates that snapshot: its two out-of-tree files (`build_d3fend_cwe_slice.py`, `data/d3fend/cwe-countermeasures.json`) are documented by their input/output contract in §6.7, and the localized additions to the five in-tree files that consume it (`analyze.py`'s mitigation-unpack sites, `defense.py`'s weakness attach loop, `match.py`'s `mitigations_for_weakness`, and `d3fend.py`/`graph/phase.py`'s CWE overlay) are marked at their locations in §6.3–6.4. The delta introduces no new node or edge type. When the current tree is in hand, those six marked spots are the complete checklist to reconcile line by line; nothing else in the manual is affected.

**A second honest caveat — read-accurate, not run-tested.** This manual is derived from a close reading of the source, not from executing the pipeline end to end. Every command matches the actual scripts and the CLI, and the data parsers were checked against the real input shapes (the Debian tracker JSON structure and the D3FEND SPARQL-results bindings both match what `distro_index.py` and `d3fend_extract.py` expect). But "verified against the source" is a weaker claim than "ran it and watched it pass," and the first true integration test is an actual run. The likeliest seam to check on a first run is the two hand-acquired datasets in Part III (Steps 4 and 6): confirm each landed at the right path in the expected shape. Everything the manual asserts is grounded in the code; it simply does not assert more than that.

*(End of the Psypher AI Threat Assessor Developer Manual.)*
