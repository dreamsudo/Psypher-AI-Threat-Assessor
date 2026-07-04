#!/usr/bin/env bash
# =============================================================================
#  psypher-hop.sh — a purely-cosmetic hopping-rabbit loading screen.
#
#  Runs the real assessment (./run.sh run) UNCHANGED in the background, shows a
#  little rabbit hopping toward a carrot while you wait, then prints the full
#  (colored) output and the real finding count. Touches nothing in the pipeline.
#
#  Usage:  ./psypher-hop.sh            (instead of ./run.sh run)
#          ./psypher-hop.sh run        (extra args are forwarded to run.sh)
#
#  It inherits your environment, so ANTHROPIC_API_KEY / PSYPHER_REDTEAM_MODEL
#  set in the shell still apply exactly as normal.
# =============================================================================
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

LOG="$(mktemp /tmp/psypher-hop.XXXXXX.log)"
export FORCE_COLOR=1          # make rich emit color even though we capture output

CARROT="🥕"
RABBIT="🐇"
WIDTH=18                      # length of the track (in dots)

# restore cursor + clean up the temp log no matter how we exit
cleanup() { printf '\033[?25h'; rm -f "$LOG"; }
trap 'printf "\033[?25h\n"; kill "$PID" 2>/dev/null; rm -f "$LOG"; exit 130' INT TERM
trap cleanup EXIT

# build a run of N middot dots (safe with multibyte chars)
dots() { local n=$1 s='' i; for ((i=0; i<n; i++)); do s+='·'; done; printf '%s' "$s"; }

# deadpan bunny-security caption, chosen by how close the rabbit is to the carrot
caption_for() {
  local p=$1
  if   (( p >= 15 )); then echo "sniffing the perimeter...";
  elif (( p >= 11 )); then echo "digging through the graph...";
  elif (( p >= 7  )); then echo "checking the CVE burrow...";
  elif (( p >= 4  )); then echo "interrogating the model...";
  elif (( p >= 1  )); then echo "hopping home with the loot...";
  else                     echo "nom nom nom...";
  fi
}

# --- launch the REAL assessment in the background (output captured) ----------
./run.sh run "$@" >"$LOG" 2>&1 &
PID=$!

printf '\033[?25l'            # hide cursor during the animation

# --- hop the rabbit right -> left toward the carrot, looping until done ------
while kill -0 "$PID" 2>/dev/null; do
  for (( p=WIDTH; p>=0; p-- )); do
    kill -0 "$PID" 2>/dev/null || break
    before="$(dots "$p")"
    after="$(dots "$((WIDTH - p))")"
    printf '\r %s%s%s%s   %-32s' "$CARROT" "$before" "$RABBIT" "$after" "$(caption_for "$p")"
    sleep 0.14
  done
done

wait "$PID"; rc=$?

printf '\r%80s\r' ''          # wipe the animation line

# --- show the real (colored) assessment output ------------------------------
cat "$LOG"

# --- final flourish with the actual finding count ---------------------------
N="$(grep -oE '[0-9]+ finding' "$LOG" | grep -oE '[0-9]+' | tail -1)"
[ -z "$N" ] && N="?"
printf '\n %s%s  nom nom nom — %s findings!\n' "$RABBIT" "$CARROT" "$N"

exit "$rc"
