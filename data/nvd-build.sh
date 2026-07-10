#!/usr/bin/env bash
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  data/nvd-build.sh — fetch + SHA256-verify the full NVD, then build the index.
#  Standalone (Part C / C1). Source: Fraunhofer FKIE nvd-json-data-feeds mirror.
#  Idempotent + resumable: re-running skips years already downloaded & verified.
# =============================================================================
set -euo pipefail
BASE="https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"
DIR="$(cd "$(dirname "$0")" && pwd)/nvd"
FIRST=2002
LAST="$(date +%Y)"
mkdir -p "$DIR"; cd "$DIR"

verify() {  # $1 = decompressed json, $2 = meta file
  local calc want
  calc="$(sha256sum "$1" | cut -d' ' -f1)"
  want="$(grep -i '^sha256:' "$2" | cut -d: -f2 | tr -d '[:space:]')"
  [ -n "$want" ] && [ "$calc" = "$want" ]
}

for y in $(seq "$FIRST" "$LAST"); do
  json="CVE-$y.json"; xz="CVE-$y.json.xz"; meta="CVE-$y.meta"
  if [ -f "$json" ] && [ -f "$meta" ] && verify "$json" "$meta"; then
    echo "[skip] $y already present and verified"; continue
  fi
  echo "[fetch] $y"
  curl -fsSL -o "$xz"   "$BASE/CVE-$y.json.xz"
  curl -fsSL -o "$meta" "$BASE/CVE-$y.meta"
  unxz -k -f "$xz"
  if verify "$json" "$meta"; then
    echo "[ok]   $y SHA256 verified"
  else
    echo "[FAIL] $y checksum mismatch — removing, NOT indexing"; rm -f "$json"; exit 1
  fi
done

echo "[index] building SQLite product index over all verified feeds"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/.venv/bin/python" "$ROOT/data/nvd_index.py" "$DIR"
echo "[done] NVD store + index ready under $DIR"
