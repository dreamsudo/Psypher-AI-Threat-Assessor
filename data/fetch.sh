#!/usr/bin/env bash
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  data/fetch.sh — fetch the bounded framework catalogs into data/.
#
#  CVE data is shipped curated in data/cve/. This pulls the large but bounded
#  catalogs: MITRE ATLAS (STIX), ATT&CK Enterprise (STIX), and CWE (XML).
#  URLs are the best-known upstream locations; adjust if a project relocates a
#  file. The engine tolerates any source that is missing and builds from the
#  rest.
# =============================================================================
set -euo pipefail
DATA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${DATA_DIR}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required" >&2; exit 1; }; }
need curl

echo "[fetch] MITRE ATLAS (STIX) -> atlas-data/"
mkdir -p atlas-data
curl -fsSL -o atlas-data/stix-atlas.json \
  "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"

echo "[fetch] MITRE ATT&CK Enterprise (STIX) -> attack-stix-data/"
mkdir -p attack-stix-data
curl -fsSL -o attack-stix-data/enterprise-attack.json \
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

echo "[fetch] MITRE CWE (XML) -> cwe/"
mkdir -p cwe
if command -v unzip >/dev/null 2>&1; then
  curl -fsSL -o cwe/cwec_latest.xml.zip "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
  ( cd cwe && unzip -o cwec_latest.xml.zip >/dev/null && rm -f cwec_latest.xml.zip )
else
  echo "[fetch] note: 'unzip' not found; download https://cwe.mitre.org/data/xml/cwec_latest.xml.zip manually into data/cwe/" >&2
fi

echo "[fetch] done. CVE data is already present in data/cve/ (curated)."
