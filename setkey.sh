#!/usr/bin/env bash
# =============================================================================
#  setkey.sh — Psypher AI Threat Assessor · PsypherLabs
#  Silently prompts for ANTHROPIC_API_KEY, exports it, and confirms the engine
#  can see it. MUST be sourced so the export persists in your shell:
#      source setkey.sh
# =============================================================================
if [ "${BASH_SOURCE[0]}" = "${0}" ] && [ -z "$ZSH_EVAL_CONTEXT" ]; then
  echo "  Run me with:  source setkey.sh   (so the key stays set in this shell)"
  exit 1
fi

# Read the config's key-env name (defaults to ANTHROPIC_API_KEY) so this always
# matches whatever assessor.yaml actually points at.
_KEYVAR=$(.venv/bin/python -c "import yaml;print(yaml.safe_load(open('assessor.yaml'))['model'].get('api_key_env','ANTHROPIC_API_KEY'))" 2>/dev/null)
[ -z "$_KEYVAR" ] && _KEYVAR="ANTHROPIC_API_KEY"

printf "  Paste %s (input hidden), then Enter: " "$_KEYVAR"
read -rs _K; echo
if [ -z "$_K" ]; then echo "  No key entered — nothing changed."; else
  export "$_KEYVAR"="$_K"; unset _K
  echo "  $_KEYVAR set — length ${#ANTHROPIC_API_KEY} (value not shown)."
fi

# Confirm the engine will actually see it, via the exact var name from config.
.venv/bin/python -c "
import os
v='$_KEYVAR'
print('  engine check -> config key_env:', v, '| present in shell:', bool(os.environ.get(v)))
" 2>/dev/null || echo "  (engine check skipped — run from repo root with .venv present)"
