#!/usr/bin/env bash
# =============================================================================
#  dump_source.sh
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#
#  Dumps EVERY source file of the repository into ONE heavily-labeled Markdown
#  file, so the whole codebase can be uploaded to a flat store (e.g. Claude's
#  project knowledge) while preserving each file's full path from the repo root.
#
#  Usage (from the repo root):
#      ./dump_source.sh
#  Or point it at the repo and/or name the output:
#      ./dump_source.sh /path/to/psypher-assessor  psypher-source-dump.md
#
#  Optional toggles (environment variables, all default OFF):
#      INCLUDE_BAKS=1             also dump *.bak* snapshots (historical copies)
#      INCLUDE_GENERATED=1       also dump build/ logs/ assessments/ blackbox-out/
#      INCLUDE_FRAMEWORK_DATA=1  also dump the huge fetched ATLAS/ATT&CK/CWE data
#
#  ALWAYS excluded: .git, .venv, every __pycache__, all *.pyc, and the output
#  file itself. Everything excluded is listed in the dump header, so the record
#  of the repo stays complete even when a category is left out.
# =============================================================================
set -euo pipefail

ROOT="${1:-$PWD}"
OUT="${2:-psypher-source-dump.md}"
INCLUDE_BAKS="${INCLUDE_BAKS:-0}"
INCLUDE_GENERATED="${INCLUDE_GENERATED:-0}"
INCLUDE_FRAMEWORK_DATA="${INCLUDE_FRAMEWORK_DATA:-0}"

cd "$ROOT"
ROOT="$PWD"                       # normalize to an absolute path

# --- sanity: does this actually look like the psypher repo? ------------------
if [ ! -f assessor.yaml ] || [ ! -d engine ]; then
  echo "ERROR: '$ROOT' does not look like the psypher-assessor repo" >&2
  echo "       (expected ./assessor.yaml and ./engine). Pass the repo path as arg 1." >&2
  exit 1
fi

# make OUT absolute so find can reliably exclude it
case "$OUT" in /*) : ;; *) OUT="$ROOT/$OUT" ;; esac
OUT_BASE="$(basename "$OUT")"

# --- build the directory-prune set -------------------------------------------
PRUNE=( -path ./.git -o -path ./.venv -o -name __pycache__ -o -name node_modules )
if [ "$INCLUDE_GENERATED" != "1" ]; then
  PRUNE+=( -o -path ./build -o -path ./assessments -o -path ./logs -o -path ./blackbox-out )
fi
if [ "$INCLUDE_FRAMEWORK_DATA" != "1" ]; then
  PRUNE+=( -o -path ./data/atlas-data -o -path ./data/attack-stix-data -o -path ./data/cwe )
fi

# --- build the filename-exclusion set ----------------------------------------
NAMEF=( ! -name '*.pyc' ! -name "$OUT_BASE" ! -name 'psypher-source-dump.md' \
        ! -name 'psypher-fulldump.txt' ! -name '*.zip' ! -name '*.swp' )
if [ "$INCLUDE_BAKS" != "1" ]; then
  NAMEF+=( ! -name '*.bak*' )
fi

# --- collect the file list (sorted, stable, paths relative to repo root) -----
LIST="$(mktemp)"
trap 'rm -f "$LIST"' EXIT
find . \( "${PRUNE[@]}" \) -prune -o -type f "${NAMEF[@]}" -print \
  | sed 's|^\./||' | LC_ALL=C sort > "$LIST"
TOTAL="$(wc -l < "$LIST" | tr -d ' ')"

if [ "$TOTAL" -eq 0 ]; then
  echo "ERROR: no files matched. Are you in the right directory?" >&2
  exit 1
fi

# --- map a filename to a fenced-code language hint ---------------------------
lang_for() {
  local base ext; base="$(basename "$1")"; ext="${1##*.}"
  case "$base" in
    .gitignore) echo gitignore; return;;
    Dockerfile) echo dockerfile; return;;
    *.yalm)     echo yaml; return;;
  esac
  case "$ext" in
    py) echo python;; sh) echo bash;; yaml|yml) echo yaml;; json) echo json;;
    toml) echo toml;; md) echo markdown;; xml) echo xml;; txt) echo text;;
    cfg|ini) echo ini;; html|htm) echo html;; css) echo css;; js) echo javascript;;
    *) echo text;;
  esac
}

# counts of what we deliberately left out, for the header record
c_pyc="$(find . -type f -name '*.pyc' 2>/dev/null | wc -l | tr -d ' ')"
c_bak="$(find . -type f -name '*.bak*' 2>/dev/null | wc -l | tr -d ' ')"

# --- write the dump ----------------------------------------------------------
{
  echo "# Psypher AI Threat Assessor — Full Labeled Source Dump"
  echo
  echo "### Full-stack AI/ML security — MITRE ATLAS–grounded penetration testing of the model and the infrastructure it runs on"
  echo
  echo "**Powered by Claude · Designed by PsypherLabs**"
  echo
  echo "> Every source file of the repository, in one file. Each file is labeled with its full path from the repo root, so the codebase can be uploaded to a flat store (where directory structure is lost) without losing track of where anything lives."
  echo
  echo "- **Repository root:** \`$ROOT\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M:%SZ') (UTC)"
  echo "- **Host:** $(id -un 2>/dev/null || echo '?')@$(hostname 2>/dev/null || echo '?')"
  echo "- **Files dumped:** $TOTAL"
  echo
  echo "**Deliberately excluded** (to keep this the *current* system and a sane size — the full record of what exists is still the manifest below plus these notes):"
  echo "- \`.git/\`, \`.venv/\`, every \`__pycache__/\`, all \`*.pyc\` ($c_pyc compiled files)"
  if [ "$INCLUDE_BAKS" != "1" ]; then
    echo "- \`*.bak*\` snapshots ($c_bak backup files) — historical copies, NOT the current system. Re-run with \`INCLUDE_BAKS=1\` to include them."
  fi
  if [ "$INCLUDE_FRAMEWORK_DATA" != "1" ]; then
    echo "- Fetched framework data \`data/atlas-data/\`, \`data/attack-stix-data/\`, \`data/cwe/\` — large third-party downloads, not project code. Re-run with \`INCLUDE_FRAMEWORK_DATA=1\` to include them."
  fi
  if [ "$INCLUDE_GENERATED" != "1" ]; then
    echo "- Runtime/generated \`build/\`, \`logs/\`, \`assessments/\`, \`blackbox-out/\`. Re-run with \`INCLUDE_GENERATED=1\` to include them."
  fi
  echo
  echo "---"
  echo
  echo "## Manifest — every file in this dump ($TOTAL)"
  echo
  echo "| # | Path (from repo root) | Lines | Bytes | Type |"
  echo "|---:|---|---:|---:|---|"
  i=0
  while IFS= read -r f; do
    i=$((i+1))
    ln="$(wc -l < "$f" 2>/dev/null | tr -d ' ')"
    by="$(wc -c < "$f" 2>/dev/null | tr -d ' ')"
    printf '| %d | `%s` | %s | %s | %s |\n' "$i" "$f" "$ln" "$by" "$(lang_for "$f")"
  done < "$LIST"
  echo
  echo "---"
  echo
  echo "# FILES"

  i=0
  while IFS= read -r f; do
    i=$((i+1))
    ln="$(wc -l < "$f" 2>/dev/null | tr -d ' ')"
    by="$(wc -c < "$f" 2>/dev/null | tr -d ' ')"
    lang="$(lang_for "$f")"
    echo
    echo "<!-- ===================================================================== -->"
    echo "===== BEGIN FILE [$i/$TOTAL]: $f ====="
    echo
    echo "## [$i/$TOTAL] \`$f\`"
    echo
    echo "**Repo path:** \`$f\` · **Lines:** $ln · **Bytes:** $by · **Type:** \`$lang\`"
    echo
    if grep -Iq . "$f" 2>/dev/null; then
      # choose a fence longer than the longest backtick run in the file,
      # so nothing inside can break out of the code block
      ticks="$(grep -oE '`+' "$f" 2>/dev/null | awk '{ if (length>m) m=length } END { print m+0 }' || true)"
      ticks="${ticks:-0}"
      flen=$((ticks + 1)); [ "$flen" -lt 3 ] && flen=3
      fence="$(printf '%*s' "$flen" '' | tr ' ' '`')"
      printf '%s%s\n' "$fence" "$lang"
      cat "$f"
      printf '\n%s\n' "$fence"
    elif [ ! -s "$f" ]; then
      echo "_(empty file)_"
    else
      echo "_(binary or non-UTF-8 file — contents not dumped)_"
    fi
    echo
    echo "===== END FILE [$i/$TOTAL]: $f ====="
  done < "$LIST"

  echo
  echo "---"
  echo
  echo "*End of source dump — $TOTAL files. Powered by Claude · Designed by PsypherLabs.*"
} > "$OUT"

# --- report to the operator --------------------------------------------------
echo "Wrote $TOTAL files to: $OUT" >&2
echo "Output size: $(wc -c < "$OUT" | tr -d ' ') bytes" >&2
echo "Toggles: INCLUDE_BAKS=$INCLUDE_BAKS INCLUDE_GENERATED=$INCLUDE_GENERATED INCLUDE_FRAMEWORK_DATA=$INCLUDE_FRAMEWORK_DATA" >&2
