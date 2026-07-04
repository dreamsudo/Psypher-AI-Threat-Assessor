#!/usr/bin/env bash
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  run.sh — convenience launcher (auto-syncing).
#
#  Creates a local virtual environment on first run, and re-installs
#  dependencies automatically whenever requirements.txt changes (so bootstraps
#  that add a dependency just work). All arguments are forwarded to the CLI.
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"
VENV_DIR="${ROOT_DIR}/.venv"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required but was not found on PATH" >&2
  exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "[setup] creating virtual environment in .venv" >&2
  python3 -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# Re-sync dependencies only when requirements.txt changes (hash comparison).
REQ_HASH_FILE="${VENV_DIR}/.req-sha256"
CURRENT_HASH="$(sha256sum "${ROOT_DIR}/requirements.txt" | awk '{print $1}')"
if [[ ! -f "${REQ_HASH_FILE}" || "$(cat "${REQ_HASH_FILE}")" != "${CURRENT_HASH}" ]]; then
  echo "[setup] syncing dependencies (requirements.txt changed)" >&2
  python -m pip install --quiet --upgrade pip
  python -m pip install --quiet -r "${ROOT_DIR}/requirements.txt"
  echo "${CURRENT_HASH}" > "${REQ_HASH_FILE}"
fi

exec python -m engine "$@"
