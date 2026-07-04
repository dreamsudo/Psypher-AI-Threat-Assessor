#!/usr/bin/env bash
# setmodel.sh — Psypher AI Threat Assessor · PsypherLabs
# Pick the Claude model for THIS shell, then set the key. MUST be sourced:
#     source setmodel.sh
if [ "${BASH_SOURCE[0]}" = "${0}" ] && [ -z "$ZSH_EVAL_CONTEXT" ]; then
  echo "  Run me with:  source setmodel.sh"; exit 1
fi
echo "  Claude model that powers the engine (recon · enrich · CVE · judge):"
echo "    1) Haiku 4.5   claude-haiku-4-5-20251001    \$1 / \$5   (cheapest — default)"
echo "    2) Sonnet 5    claude-sonnet-5              \$2 / \$10  (balanced)"
echo "    3) Opus 4.8    claude-opus-4-8              \$5 / \$25  (powerful)"
echo "    4) Fable 5     claude-fable-5              \$10 / \$50  (flagship)"
printf "  Enter 1-4 [1]: "; read -r _C
case "${_C:-1}" in
  1|"") _M="claude-haiku-4-5-20251001" ;;
  2)    _M="claude-sonnet-5" ;;
  3)    _M="claude-opus-4-8" ;;
  4)    _M="claude-fable-5" ;;
  *)    echo "  Not 1-4 — nothing changed."; return 1 2>/dev/null || exit 1 ;;
esac
export PSYPHER_CLAUDE_MODEL="$_M"; unset _C _M
echo "  PSYPHER_CLAUDE_MODEL=$PSYPHER_CLAUDE_MODEL  (overrides all Claude roles this shell)"
if [ -f setkey.sh ]; then source setkey.sh
else echo "  (setkey.sh missing — set the key: read -rs ANTHROPIC_API_KEY; export ANTHROPIC_API_KEY)"; fi
