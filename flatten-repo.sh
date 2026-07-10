#!/usr/bin/env bash
###############################################################################
# flatten-repo.sh
#
# PURPOSE
#   Walk a repository and "flatten" it into ONE single text file, while
#   preserving the original directory hierarchy through explicit labels. Even
#   though the result is a flat file, every chunk is clearly tagged with its
#   full relative path, a directory "breadcrumb", and its depth in the tree.
#
#   By default this captures your ACTUAL PROJECT and ignores machine-generated
#   noise: Python virtualenvs (.venv/venv/env), byte-code caches (__pycache__,
#   *.pyc), tooling caches, and the .git store. Everything else — including
#   generated data you care about like build/ outputs and logs — is kept.
#
#   Output is written into a fresh, TIMESTAMPED folder so runs never clobber
#   each other. Binary files are recorded as a labeled placeholder (not raw
#   bytes) so the combined file stays readable.
#
# USAGE
#   ./flatten-repo.sh [ROOT_DIR]
#     ROOT_DIR   Directory to flatten. Defaults to the current directory ".".
#
# OUTPUT (created in the current working directory)
#   ./flatten_YYYYMMDD_HHMMSS/
#       <repo>_flat_YYYYMMDD_HHMMSS.txt   <- the single combined file
#       MANIFEST.txt                      <- numbered list of every file
#       TREE.txt                          <- directory tree snapshot
#
# REQUIREMENTS
#   bash >= 4.4, plus coreutils (find, sort, stat, wc). `tree` and `file` are
#   used if present but the script degrades gracefully without them.
###############################################################################

# --- Shell safety -----------------------------------------------------------
# No `set -e`: this is a "capture everything" tool, so a single odd file must
# never abort the whole run. We still guard undefined vars (-u) and broken
# pipes (pipefail), and handle per-file errors by hand.
set -uo pipefail

# ============================================================================
# CONFIG — the knobs you might want to change
# ============================================================================

# Directory names (globs allowed) to prune — i.e. NOT descend into.
# These defaults strip Python env + VCS + tooling noise. Comment a line out to
# KEEP that folder (e.g. remove ".git" to include git internals, or "build" if
# you consider it generated). "flatten_*" is always pruned automatically.
EXCLUDE_DIRS=(
  ".venv" "venv" "env" "virtualenv" "ENV"   # Python virtual environments
  "__pycache__"                             # compiled byte-code cache
  ".pytest_cache" ".mypy_cache" ".ruff_cache" ".tox"  # test/lint tooling caches
  ".eggs" "*.egg-info"                      # packaging build artifacts
  "node_modules"                            # JS deps (harmless if absent)
  ".git"                                    # VCS store (comment out to keep)
)

# File name globs to skip (compiled / non-source artifacts).
EXCLUDE_FILE_GLOBS=( "*.pyc" "*.pyo" "*.pyd" )

# "yes" -> binary files become a labeled placeholder (recommended).
# "no"  -> binary files are dumped verbatim (WILL corrupt the text file).
SKIP_BINARY_CONTENT="yes"

# Max bytes of content to inline per file. 0 = unlimited.
MAX_BYTES_PER_FILE=0

# ============================================================================
# SETUP — resolve root and create the timestamped output folder
# ============================================================================

ROOT="${1:-.}"
if [[ ! -d "$ROOT" ]]; then
  echo "error: '$ROOT' is not a directory" >&2
  exit 1
fi
ROOT_ABS="$(cd "$ROOT" && pwd -P)"
REPO_NAME="$(basename "$ROOT_ABS")"

TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="flatten_${TS}"
mkdir -p "$OUT_DIR"
OUT_FILE="${OUT_DIR}/${REPO_NAME}_flat_${TS}.txt"
MANIFEST="${OUT_DIR}/MANIFEST.txt"
TREEFILE="${OUT_DIR}/TREE.txt"

# ============================================================================
# FILE DISCOVERY
# ============================================================================

# Directory prune group. Always prune previous flatten_* output so re-runs
# don't ingest their own results, then add every EXCLUDE_DIRS entry.
prune=( -type d '(' -name 'flatten_*' )
for d in "${EXCLUDE_DIRS[@]}"; do prune+=( -o -name "$d" ); done
prune+=( ')' -prune )

# File-name exclusion filter (a chain of `! -name GLOB`).
fileflt=()
for g in "${EXCLUDE_FILE_GLOBS[@]}"; do fileflt+=( '!' -name "$g" ); done

# Ignore pattern for `tree` (dir names + file globs + flatten_*), joined by '|'.
TREE_IGNORE="flatten_*"
for p in "${EXCLUDE_DIRS[@]}" "${EXCLUDE_FILE_GLOBS[@]}"; do TREE_IGNORE+="|${p}"; done

# Enumerate every kept file (NUL-safe + sorted): regular files AND symlinks,
# minus the excluded dirs and file globs.
mapfile -d '' FILES < <(
  find "$ROOT_ABS" "${prune[@]}" \
    -o '(' '(' -type f -o -type l ')' "${fileflt[@]}" -print0 ')' \
    | sort -z
)
TOTAL="${#FILES[@]}"

# ============================================================================
# HELPERS
# ============================================================================

detect_mime() {
  if command -v file >/dev/null 2>&1; then
    file -b --mime "$1" 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

# True (0) if the file is binary. Prefers `file --mime-encoding`; empty=text.
is_binary() {
  local f="$1"
  [[ -s "$f" ]] || return 1
  if command -v file >/dev/null 2>&1; then
    [[ "$(file -b --mime-encoding "$f" 2>/dev/null)" == "binary" ]]; return
  fi
  grep -Iq . "$f" 2>/dev/null && return 1 || return 0
}

filesize() { stat -c %s "$1" 2>/dev/null || wc -c < "$1" 2>/dev/null || echo 0; }

# ============================================================================
# PASS 1 — build the manifest and tally file types
# ============================================================================

n_text=0; n_bin=0; n_link=0
: > "$MANIFEST"
idx=0
for f in "${FILES[@]}"; do
  idx=$((idx+1))
  rel="${f#"$ROOT_ABS"/}"
  if [[ -L "$f" ]]; then
    kind="link";   n_link=$((n_link+1)); sz=0
  elif is_binary "$f"; then
    kind="binary"; n_bin=$((n_bin+1));   sz="$(filesize "$f")"
  else
    kind="text";   n_text=$((n_text+1)); sz="$(filesize "$f")"
  fi
  printf '%04d  %-7s %10s B  %s\n' "$idx" "$kind" "$sz" "$rel" >> "$MANIFEST"
done

# ============================================================================
# Directory tree snapshot (respects the same exclusions)
# ============================================================================

{
  if command -v tree >/dev/null 2>&1; then
    tree -a -I "$TREE_IGNORE" "$ROOT_ABS"
  else
    find "$ROOT_ABS" "${prune[@]}" -o '(' "${fileflt[@]}" -print ')' \
      | sed "s|^${ROOT_ABS}|.|" \
      | awk -F/ '{ pad=""; for(i=1;i<NF;i++) pad=pad"  "; print pad $NF }'
  fi
} > "$TREEFILE" 2>/dev/null

# Optional git context for the header.
GIT_INFO="n/a"
if command -v git >/dev/null 2>&1 && git -C "$ROOT_ABS" rev-parse --git-dir >/dev/null 2>&1; then
  GIT_INFO="$(git -C "$ROOT_ABS" describe --always --dirty 2>/dev/null) @ $(git -C "$ROOT_ABS" rev-parse --abbrev-ref HEAD 2>/dev/null)"
fi

# Human-readable exclusion summary for the header.
EXCL_DISPLAY="$(IFS=', '; echo "${EXCLUDE_DIRS[*]}"), $(IFS=', '; echo "${EXCLUDE_FILE_GLOBS[*]}")"

# ============================================================================
# PASS 2 — write the single combined flat file
# ============================================================================

{
  printf '%s\n' "################################################################################"
  printf '# REPOSITORY FLATTEN — %s\n' "$REPO_NAME"
  printf '# Generated : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
  printf '# Root      : %s\n' "$ROOT_ABS"
  printf '# Host      : %s\n' "$(hostname 2>/dev/null || echo unknown)"
  printf '# Git       : %s\n' "$GIT_INFO"
  printf '# Files     : %d total  (%d text, %d binary, %d symlink)\n' "$TOTAL" "$n_text" "$n_bin" "$n_link"
  printf '# Excluded  : %s\n' "$EXCL_DISPLAY"
  printf '# Tool      : flatten-repo.sh\n'
  printf '%s\n\n' "################################################################################"

  printf '%s\n' "===================================== TREE ====================================="
  cat "$TREEFILE"
  printf '\n%s\n' "=================================== MANIFEST ==================================="
  cat "$MANIFEST"
  printf '\n%s\n\n' "================================ FILE CONTENTS ================================="

  idx=0
  for f in "${FILES[@]}"; do
    idx=$((idx+1))
    rel="${f#"$ROOT_ABS"/}"
    dir="$(dirname "$rel")"; [[ "$dir" == "." ]] && dir="(root)"
    breadcrumb="${rel//\// → }"
    depth="$(awk -F/ '{print NF}' <<< "$rel")"
    mime="$(detect_mime "$f")"

    printf '%s\n' "╔══════════════════════════════════════════════════════════════════════════════"
    printf '║ FILE %04d / %04d\n' "$idx" "$TOTAL"
    printf '║ PATH : %s\n' "$rel"
    printf '║ TREE : %s   (depth %s)\n' "$breadcrumb" "$depth"
    printf '║ DIR  : %s\n' "$dir"

    if [[ -L "$f" ]]; then
      target="$(readlink "$f" 2>/dev/null)"
      printf '║ TYPE : symlink -> %s\n' "$target"
      printf '%s\n' "╠══════════════════════════════════════════════════════════════════════════════"
      printf '[symlink; target: %s — not followed]\n' "$target"
    elif [[ ! -r "$f" ]]; then
      printf '║ TYPE : %s\n' "$mime"
      printf '%s\n' "╠══════════════════════════════════════════════════════════════════════════════"
      printf '[unreadable: permission denied]\n'
    elif is_binary "$f" && [[ "$SKIP_BINARY_CONTENT" == "yes" ]]; then
      sz="$(filesize "$f")"
      printf '║ SIZE : %s bytes | binary | %s\n' "$sz" "$mime"
      printf '%s\n' "╠══════════════════════════════════════════════════════════════════════════════"
      printf '[binary file — %s bytes — content omitted]\n' "$sz"
    else
      sz="$(filesize "$f")"
      lines="$(wc -l < "$f" 2>/dev/null | tr -d ' ')"
      printf '║ SIZE : %s bytes | %s lines | %s\n' "$sz" "${lines:-0}" "$mime"
      printf '%s\n' "╠══════════════════════════════════════════════════════════════════════════════"
      if [[ "$MAX_BYTES_PER_FILE" -gt 0 ]]; then
        head -c "$MAX_BYTES_PER_FILE" "$f"
        [[ "$sz" -gt "$MAX_BYTES_PER_FILE" ]] && \
          printf '\n[... truncated: showing first %s of %s bytes ...]\n' "$MAX_BYTES_PER_FILE" "$sz"
      else
        cat "$f"
      fi
      printf '\n'
    fi

    printf '%s\n\n' "╚═══ END ${rel} ═══"
  done

  printf '%s\n' "################################################################################"
  printf '# END OF FLATTEN — %d files captured\n' "$TOTAL"
  printf '%s\n' "################################################################################"
} > "$OUT_FILE"

# ============================================================================
# DONE
# ============================================================================
echo "✔ Flatten complete."
echo "  Output folder : $OUT_DIR"
echo "  Combined file : $OUT_FILE"
echo "  Files captured: $TOTAL  ($n_text text, $n_bin binary, $n_link symlink)"
echo "  Excluded      : Python env, caches, compiled files, .git"
