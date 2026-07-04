#!/usr/bin/env bash
# Psypher AI Threat Assessor — internals self-check.
# Default: fast internals only (no target, no Claude).
# RUN_E2E=1 ./selfcheck.sh  (or: ./selfcheck.sh full) -> also a BOUNDED end-to-end
#   smoke run: 2-attack corpus + hard timeout, so it can't grind the local model.
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
PY=.venv/bin/python
FAIL=0
line(){ printf '\n\033[38;2;57;255;20m===== %s =====\033[0m\n' "$1"; }
run(){ "$@"; local rc=$?; [ $rc -ne 0 ] && { FAIL=1; printf '\033[38;2;255;45;149m[step exited %d]\033[0m\n' "$rc"; }; return 0; }
[ -x "$PY" ] || { echo "no .venv yet — run ./run.sh once to build it, then re-run this."; exit 1; }
case "${1:-}" in full|--full|-f) RUN_E2E=1;; esac

line "1/4  system test (13 checks — pure internals, no target/model/key)"
run $PY -m tests.system_test
line "2/4  label grounding (corpus + posture ids vs graph; prints ATLAS version)"
run $PY -m tests.verify_labels
line "3/4  drift + static verifiers"
run $PY -m tests.verify --mode static
run $PY -m tests.verify --mode probes
run $PY -m tests.verify --mode sources
line "4/4  config + probe load (no target touched)"
run $PY -m engine validate

if [ "${RUN_E2E:-0}" = "1" ]; then
  line "E2E  bounded deterministic run (Claude OFF; hits ONLY your local Ollama)"
  echo "note: behavioral capture is slow (each rt_* probe re-sends the corpus to the"
  echo "      local model), so this smoke run uses a 2-attack corpus + a 240s timeout."
  TMPC="$(mktemp /tmp/psypher-smoke-XXXXXX.yaml)"
  if $PY -c "import yaml,sys;d=yaml.safe_load(open('packs/redteam/atlas-prompts.yaml'));d['prompts']=d['prompts'][:2];yaml.safe_dump(d,open(sys.argv[1],'w'),sort_keys=False)" "$TMPC" 2>/dev/null; then
    ( unset ANTHROPIC_API_KEY
      export PSYPHER_REDTEAM_CORPUS="$TMPC"
      export PSYPHER_REDTEAM_MODEL="${PSYPHER_REDTEAM_MODEL:-qwen2.5:0.5b}"
      timeout 240 ./run.sh run ) || echo "[e2e ended or timed out — output above]"
    rm -f "$TMPC"
    CASE="$(ls -dt assessments/CASE-*/ 2>/dev/null | head -1)"
    if [ -n "$CASE" ]; then
      echo "case: $CASE"
      $PY -c "import json,sys;s=json.load(open(sys.argv[1]+'assessment.json'))['summary'];print('findings:',s['findings_total'],'| by_severity:',s['by_severity'],'| frameworks:',s['frameworks'])" "$CASE" 2>/dev/null
    fi
  else echo "[could not build smoke corpus — skipping e2e]"; rm -f "$TMPC"; fi
fi

line "summary"
if [ "$FAIL" = "0" ]; then printf '\033[38;2;57;255;20mINTERNALS OK — fork is on a verified baseline.\033[0m\n'
else printf '\033[38;2;255;45;149mSOME STEPS REPORTED NONZERO — read the sections above.\033[0m\n'; fi
[ "${RUN_E2E:-0}" = "1" ] || echo "(internals only. bounded end-to-end: RUN_E2E=1 ./selfcheck.sh)"
