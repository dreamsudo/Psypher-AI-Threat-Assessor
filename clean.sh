#!/usr/bin/env bash
# =============================================================================
#  clean.sh — Psypher AI Threat Assessor · PsypherLabs
#  Interactive reset. Deletes GENERATED ARTIFACTS only; never touches the tool,
#  its packs, its tests, or its config. Prompts iteratively so the operator
#  chooses how far to reset. Safe defaults on empty input (just press Enter).
#
#  NEVER TOUCHED, regardless of answers:
#    engine/  packs/  tests/  data sources' *source files*, assessor.yaml,
#    assessor.yaml.clean, run.sh, *-run.sh, *.sh tools, requirements.txt,
#    pyproject.toml, README.md
# =============================================================================
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")"

echo "=============================================================="
echo " Psypher reset — clean generated artifacts"
echo " Repo: $(pwd)"
echo "=============================================================="
echo "This removes ONLY generated artifacts. Tool code and config are never touched."
echo

ask() {  # ask "question" default(y/n) -> returns 0 for yes
  local q="$1" def="${2:-n}" ans
  local hint="[y/N]"; [ "$def" = "y" ] && hint="[Y/n]"
  read -r "ans?  $q $hint " 2>/dev/null || read -rp "  $q $hint " ans
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy] ]]
}

PLAN=()

# --- always-safe artifacts (still confirmed, default yes) ---
if ask "Delete Python caches (__pycache__/*.pyc)?" y; then PLAN+=("caches"); fi
if ask "Delete assessment run outputs (assessments/CASE-*)?" y; then PLAN+=("cases"); fi
if ask "Delete black-box output (blackbox-out/*)?" y; then PLAN+=("blackbox"); fi

# --- data & graph: keep by default (your rule) ---
echo
echo "  --- data & graph (kept by default) ---"
if ask "Delete the built graph cache (build/graph/)? Rebuilds on next run." n; then PLAN+=("graph"); fi
if ask "Delete SOURCE DATA (data/atlas-data, attack-stix-data, cve, cwe)? You would need data/fetch.sh to restore it." n; then PLAN+=("data"); fi

# --- evidence log: forensic record, backup forced ---
echo
echo "  --- forensic evidence log ---"
if ask "Reset the hash-chained evidence log (logs/exchanges.jsonl)? A backup is kept." n; then PLAN+=("evlog"); fi

# --- bak revert points: keep by default ---
echo
echo "  --- backups / revert points ---"
if ask "Delete .bak revert points (brain.py.bak-prompts, assessor.yaml.bak-*, etc.)? Not recommended." n; then PLAN+=("baks"); fi

# --- summary + confirm ---
echo
echo "=============================================================="
echo " PLAN:"
[ ${#PLAN[@]} -eq 0 ] && { echo "   nothing selected — exiting."; exit 0; }
for p in "${PLAN[@]}"; do echo "   - $p"; done
echo "=============================================================="
ask "Proceed with the above?" n || { echo "Aborted. Nothing deleted."; exit 0; }

for p in "${PLAN[@]}"; do case "$p" in
  caches)   find . -path ./.venv -prune -o -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null; echo "  cleared caches";;
  cases)    rm -rf assessments/CASE-* 2>/dev/null; echo "  cleared case outputs";;
  blackbox) rm -f blackbox-out/* 2>/dev/null; echo "  cleared blackbox-out";;
  graph)    rm -rf build/graph/* 2>/dev/null; echo "  cleared graph cache (will rebuild)";;
  data)     rm -rf data/atlas-data data/attack-stix-data data/cve data/cwe 2>/dev/null; echo "  cleared source data (run data/fetch.sh to restore)";;
  evlog)    cp logs/exchanges.jsonl logs/exchanges.jsonl.bak 2>/dev/null; : > logs/exchanges.jsonl 2>/dev/null; echo "  reset evidence log (backup: logs/exchanges.jsonl.bak)";;
  baks)     find . -path ./.venv -prune -o -name "*.bak*" -exec rm -f {} + 2>/dev/null; echo "  deleted .bak files";;
esac; done

echo
echo "Done. Tool code and config untouched."
echo "Tip: verify with  .venv/bin/python -m tests.system_test"
