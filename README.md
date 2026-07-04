# Psypher AI Threat Assessor

An evidence-driven, framework-grounded threat assessment engine by PsypherLabs.

The engine is **sealed**: a fixed core (config, plug-in loader, contracts, run
orchestrator, reporting) that you never edit per task. Everything that varies by
use case lives in **packs** (probes, profiles, sources, intake) and is loaded
through stable contracts. Adding a use case means adding a pack, not editing the
engine.

## Layout

```
engine/          sealed core — never edited per task
  core/          config, contracts, models, loader, orchestrator, banner, schemas
  discovery/     Phase 0  (installed by bootstrap-2)
  graph/         Phase 1  (installed by bootstrap-3)
  analysis/      Phase 2  (installed by bootstrap-3)
  report/        Phase 3  (installed by bootstrap-4)
packs/           swappable per use case (probes / profiles / sources / intake)
assessor.yaml    the engagement control plane (scope, policy, model, sources)
```

## Install & run

```bash
./run.sh validate            # validate config + packs without touching a target
./run.sh run                 # run an assessment with the configured packs
./run.sh --no-banner run     # suppress the banner (for pipelines)
```

`run.sh` creates a local virtual environment on first use and installs
dependencies from `requirements.txt`.

## Build order

This repository is assembled by four bootstrap scripts, run in order:

1. `bootstrap-1-core.sh` — sealed engine core (this script)
2. `bootstrap-2-discovery.sh` — Phase 0 discovery + a starter probe pack
3. `bootstrap-3-graph-analysis.sh` — Phases 1 & 2 (knowledge graph + analysis)
4. `bootstrap-4-report.sh` — Phase 3 (assemble, render, package)
