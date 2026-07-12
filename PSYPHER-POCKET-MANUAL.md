# Psypher — Pocket Manual 🥷

**Psypher AI Threat Assessor**
*Full-stack AI/ML security — MITRE ATLAS–grounded penetration testing of the model and the infrastructure it runs on*
**Powered by Claude · Designed by PsypherLabs**

---

The no-fuss guide to **deploying, configuring, and running** Psypher. Straight to the point: get it on your machine, feed it the data, point it at a target, hit go. Everything you actually need, nothing you don't. (Want the deep dives — how it works, extending it — that's the User + Developer manuals. This is the speedrun.)

> ⚠️ **Real quick, the only rule that matters:** point this at stuff you *own or have written permission to test.* It's a pentest tool. The attack prompts are **refusal tests** (do you resist? not "make bad stuff"), but it actively poke a live system, so treat every run like the real thing.

---

## 🏁 TL;DR — the whole thing in 8 moves

```bash
# 1. get a model running (Ollama, serves on :11434)
ollama pull tinyllama

# 2. install the engine (creates its own venv)
./run.sh --help

# 3. pull the framework data (ATLAS / ATT&CK / CWE)
cd data && ./fetch.sh && cd ..

# 4. build the CVE index (big — grab a coffee ☕)
cd data && ./nvd-build.sh && cd ..

# 5. get the 2 files that aren't auto-downloaded (see §DATA)
curl -fsSL -o data/distro/debian.json https://security-tracker.debian.org/tracker/data/json
#   + drop the D3FEND export at data/d3fend/d3fend-full-mappings.json  (see §DATA)

# 6. finish the data (distro + KEV + D3FEND + relevance)
.venv/bin/python data/distro_index.py
.venv/bin/python data/kev_build.py
.venv/bin/python data/d3fend_extract.py
.venv/bin/python data/build_d3fend_cwe_slice.py
.venv/bin/python data/relevance_build.py

# 7. sanity check (no model/key/net needed — 20 checks)
.venv/bin/python -m tests.system_test

# 8. edit assessor.yaml → point at your target → GO
./run.sh run
```

That's the vibe. Details below if a step bites you. 👇

---

## 🧰 What you need

- **A Unix-y shell** (Linux/macOS). On Windows? → jump to §WINDOWS.
- **Python 3.10+** (`python3`). The launcher builds its own venv + installs deps — you don't pip anything by hand.
- **CLI tools:** `curl`, `unzip`, `xz`/`unxz`, `sha256sum`. Usually already there.
- **A model to test** — a local Ollama endpoint (§MODEL).
- *(optional)* an **Anthropic API key** — adds Claude's brain to the behavioral judging. No key = full deterministic mode, still legit.

---

## 🤖 §MODEL — get a model running (from zero)

Psypher talks to a live model over a local HTTP endpoint. Easiest path = Ollama.

```bash
# install ollama (Linux one-liner; macOS: grab the app at ollama.com)
curl -fsSL https://ollama.com/install.sh | sh

# pull a model (small one is fine to start; matches the default config)
ollama pull tinyllama

# ollama auto-serves on http://localhost:11434
# (if it's not running: `ollama serve`)

# ✅ check it's up + your model's there:
curl http://localhost:11434/api/tags
```

Note the URL — `http://localhost:11434` — you'll drop it in the config. Done. ✅

---

## ⚙️ Install (10 seconds)

```bash
./run.sh --help
```

First run builds `.venv` and installs deps automatically, then prints the help. See the banner + usage = you're good. ✅ (Deps are tiny: yaml, jsonschema, rich, the Anthropic SDK.)

---

## 📦 §DATA — feed it the data (the important part)

Psypher grounds every finding in official data, so **no data = nothing to run.** A fresh clone ships the code, the seed CVEs, and a KEV snapshot — everything else you build once. Here's the deal:

**Auto-downloaded (just run the script):**

```bash
# frameworks: ATLAS + ATT&CK + CWE  (small, quick)
cd data && ./fetch.sh && cd ..

# full CVE corpus + index (from a maintained NVD mirror, SHA-256 verified)
cd data && ./nvd-build.sh && cd ..
```
> ☕ **Real numbers on the NVD build:** it pulls ~25 years of feeds → **~3–4 GB on disk** once decompressed, **~20–45 min** depending on your connection. It's **resumable** — if it dies, just run it again, it skips what's already verified. Don't do this on a laptop with 2 GB free. 😅

**The 2 files you grab yourself** (they live in gitignored folders, so they're not in the clone):

**① Debian tracker JSON** — the "is this CVE *actually* still open on my version" source. One curl:
```bash
curl -fsSL -o data/distro/debian.json https://security-tracker.debian.org/tracker/data/json
```
~30 MB, generated live by Debian. This is the real endpoint, and its shape (`package → CVE → releases → status/fixed_version/urgency`) is exactly what the indexer eats. ✅

**② D3FEND full-mappings export** — the defensive half (names a real countermeasure per finding). This one's **not** a wget-and-go:
- Grab the **full attack↔artifact↔defense mappings** from the **MITRE D3FEND resources page → `https://d3fend.mitre.org/resources/`** (ontology / mappings downloads), or query the D3FEND **SPARQL/API** — you want **SPARQL-results JSON**, i.e. the `{ "results": { "bindings": [ … ] } }` shape.
- Save it as **`data/d3fend/d3fend-full-mappings.json`**.
- 🫡 **Heads up:** MITRE moves export URLs around, so confirm the current download on that resources page rather than trusting a hardcoded link. Same file feeds both `d3fend_extract.py` and `build_d3fend_cwe_slice.py`.

**Then finish the build** (turn those into the indexes/slices the engine reads):
```bash
.venv/bin/python data/distro_index.py            # → debian.sqlite
.venv/bin/python data/kev_build.py               # → kev.json (fetches CISA KEV)
.venv/bin/python data/d3fend_extract.py          # → attack-artifact map
.venv/bin/python data/build_d3fend_cwe_slice.py  # → CWE→countermeasure slice (named defenses on infra findings)
.venv/bin/python data/relevance_build.py         # → role-groups (what's in-scope for an AI host)
```
Each prints a summary + self-check line. If a builder yells, the file it wanted probably isn't where it should be.

**What's truly required vs nice-to-have:** frameworks + NVD + Debian = the backbone (real, precise findings). KEV + the two D3FEND steps = enrich it (priority flags, named defenses) and **fail open** if missing — the tool still runs honestly without them. Want the full polished report? Do all of it.

---

## 🎛️ Configure — `assessor.yaml`

One file. Point it at your target and pick your vibe. The bits you'll actually touch:

```yaml
scope:
  in_scope:
    - id: "target"
      kind: "inference_endpoint"
      access: "gray"                      # black = endpoint-only · gray/host = + SSH host checks
      endpoint: "http://localhost:11434"  # your Ollama URL
      ssh: "user@target-host"             # drop this line if you have no host access
  out_of_scope: []                        # hard denylist — never touched

probes:
  tiers:
    passive:     { enabled: true }
    active_safe: { enabled: true }
    intrusive:   { enabled: false, require_approval: true }   # off by default, on purpose
  allowlist:                              # ⬅️ THE GATE. a probe runs only if it's listed here
    - "endpoint_banner"
    - "unauth_inference"
    - "rt_prompt_injection"
    # ...add/remove ids to turn checks on/off

output:
  dir: "assessments"
  formats: ["web_html", "markdown"]       # web_html = the pretty brief. also: html, json, navigator
  package: "zip"
```

Quick knobs:
- **`access`** decides reach: `black` = only what's visible from outside (host stuff shows as *inferred*); `gray`/`host` = SSH in, host checks run for real (*observed*).
- **`allowlist`** is the on/off switch for every probe. The catalog (`packs/probes/probes.yaml`) just *documents*; the allowlist *authorizes*.
- **Policy** (how bold the behavioral judging is) rides on an env var, not this file:
  - `strict` (default) = only proven findings · `strict-posture` = + reachability · `exploratory` = infers more.
  - use it like: `PSYPHER_POLICY=exploratory ./run.sh run`
  - the integrity floor never turns off — you widen what you *see*, never let it make stuff up.

---

## ▶️ Run it

```bash
# optional: add Claude's brain (MUST be sourced so the key sticks)
source setkey.sh
# and/or pick the model:  source setmodel.sh

# dry run first — checks config + probes, touches nothing:
./run.sh validate

# send it 🚀
./run.sh run
```

Heads up: the CLI **needs a subcommand** — `./run.sh run` (bare `./run.sh` errors). Handy flags go *before* it: `./run.sh --verbose run`, `./run.sh --config other.yaml run`.

**While it runs:** you'll watch the stages fly by — discovery → graph → analysis → brain → posture → defense → report. Slowest bit is usually the model answering the attack prompts. Ends with exit code 0 and a fresh case folder under `assessments/CASE-xxxx/`.

---

## 📖 Read it

Open **`report-brief.html`** (the pretty one) — or `report.md` for plain text. Top shows the case + target + priority counts. Then two sections:

**Infra finding** looks like:
```
[HIGH] OpenSSL 3.0.11 — CVE-2024-XXXXX  ·  CWE-125  ·  CVSS 7.5  ·  🔴 act-now (on KEV)
  Debian: OPEN on bookworm — installed 3.0.11, fixed in 3.0.14
  Defense (D3FEND): Message Authentication  → full ranked list in the finding's
                    `d3fend_weakness_countermeasures` (see assessment.json)
```

**Behavioral finding** looks like:
```
[HIGH] Prompt Injection — ATLAS AML.T0051  ·  verdict: complied
  Why: model followed the injected instruction and emitted the canary token.
  Evidence: exchange_id abc123  (full exchange in the log, not pasted here)
```

**Blank fields aren't bugs — they're honesty:**
- **No findings at all** = the model resisted everything + no vuln versions matched. Real result. ✅
- **CVE with no technique** = distro-sourced CVEs have no authoritative ATLAS link, so it's left blank (not invented).
- **No named defense** = that weakness has no mapped countermeasure. It won't guess.
- **No transcript in the report** = it references `exchange_id` instead of fabricating dialogue (real exchange's in the log).
- **Host stuff "inferred"** = you ran black-box; give it SSH and it becomes "observed."

---

## 🧹 Clean up & refresh

**Reset generated stuff** (safe — never touches code/packs/config):
```bash
./clean.sh
```
Interactive: it asks what to nuke. Defaults (just hit Enter) clear caches + old case outputs + blackbox output. It'll offer, but **keeps by default**, the graph cache (rebuilds next run), the source data, and the evidence log (backs it up if you do reset it).

**Refresh the data** (world moves, keep grounding fresh) — just re-run the builder:
| refresh | command | how often |
|---|---|---|
| KEV (exploited) | `.venv/bin/python data/kev_build.py` | often (changes a lot) |
| NVD | `cd data && ./nvd-build.sh && cd ..` | now and then (only grabs new years) |
| Debian | re-curl the JSON, then `.venv/bin/python data/distro_index.py` | now and then |
| Frameworks | `cd data && ./fetch.sh && cd ..` | on MITRE updates |
| D3FEND (+ slice) | re-grab export, then `d3fend_extract.py` **and** `build_d3fend_cwe_slice.py` | on D3FEND updates |

After a refresh the graph **auto-rebuilds** next run (cache notices the data changed). Re-check with `.venv/bin/python -m tests.verify --mode static` (prints the framework version so staleness is visible). If you only refresh one thing regularly → **KEV**. It's fast and drives the act-now flag.

---

## 🪟 §WINDOWS

Psypher is Unix-y (bash + shell scripts). On Windows, run it in **WSL2** (Ubuntu): install WSL, open the Ubuntu shell, clone there, and follow this manual exactly as-is. Run Ollama either inside WSL or on Windows and point `endpoint` at it. Native PowerShell isn't supported — WSL is the move.

---

## 🆘 When stuff breaks

| symptom | fix |
|---|---|
| "graph not built" / nothing runs | you skipped the data build → do §DATA; check `.venv/bin/python -m tests.verify --mode static` |
| stops with a config error (exit 2) | typo in `assessor.yaml` → `./run.sh validate` names the bad key |
| "argument required" | you ran bare `./run.sh` → use `./run.sh run` |
| `source setkey.sh` nags "run me with source" | you ran it instead of sourcing → `source setkey.sh` |
| **no findings** | often not a bug (resisted + no vulns). Check the report lists observed components — if yes, clean result |
| no behavioral findings | only 1 attack probe is on by default → add more `rt_*` ids to the allowlist |
| no infra findings | NVD/Debian index missing, or no host access → build data / add SSH |
| can't reach the model | wrong URL or model not served → check `endpoint` + `ollama serve`; run still finishes with what it got |
| self-signed TLS error | `PSYPHER_INSECURE_TLS=1 ./run.sh run` |

**Your 4 diagnostic commands:**
```bash
./run.sh validate                                 # config + probes ok?
.venv/bin/python -m tests.system_test             # install sound? (20 checks)
.venv/bin/python -m tests.verify --mode static    # data grounded + typed right?
.venv/bin/python -m tests.verify                  # is my last run legit?
```

---

## 🃏 Cheat sheet

```bash
# setup
./run.sh --help                      # install (first run builds venv)
cd data && ./fetch.sh && cd ..       # frameworks
cd data && ./nvd-build.sh && cd ..   # CVE index (big)
curl -fsSL -o data/distro/debian.json https://security-tracker.debian.org/tracker/data/json
.venv/bin/python data/distro_index.py
.venv/bin/python data/kev_build.py
.venv/bin/python data/d3fend_extract.py
.venv/bin/python data/build_d3fend_cwe_slice.py
.venv/bin/python data/relevance_build.py

# run
source setkey.sh                     # (optional) add Claude — must be sourced
./run.sh validate                    # dry run
./run.sh run                         # go
PSYPHER_POLICY=exploratory ./run.sh run   # bolder judging

# check / clean
.venv/bin/python -m tests.system_test        # self-check
.venv/bin/python -m tests.verify             # audit last run
./clean.sh                                   # reset generated artifacts
```

**Env vars worth knowing:** `PSYPHER_POLICY` (strict/strict-posture/exploratory) · `PSYPHER_CLAUDE_MODEL` (override model) · `PSYPHER_INSECURE_TLS` (self-signed) · `PSYPHER_APPROVE_INTRUSIVE` (allow intrusive probes) · `PSYPHER_REDTEAM_SAMPLES` (corpus replays, default 3).

---

## 💯 Real talk (so you're not surprised)

- The first true integration test is *you* running it. If a seam's off, it'll most likely be one of the two hand-grabbed data files (§DATA) — check they're the right shape at the right path.
- **The D3FEND export URL isn't hardcoded on purpose** — MITRE moves it. Grab it from the resources page, save to the path in §DATA, done.
- Everything here is the **deploy + config + run** surface. It's complete for *that* — getting Psypher live and pointed at a target. For the "why" and the "how it works," that's the other manuals.

Now go run it. 🥷

*Psypher AI Threat Assessor · Powered by Claude · Designed by PsypherLabs*
