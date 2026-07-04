#!/usr/bin/env bash
# =============================================================================
#  psypher-brand.sh — the Psypher banner + sloth/mango loader (cosmetic only).
#
#  Prints the neon diamond logo + locked motto, then a sloth crawling toward a
#  mango, looping until the work is done. Touches nothing in the pipeline.
#
#  Usage:
#    ./psypher-brand.sh            demo: banner + sloth loops (Ctrl-C to stop)
#    ./psypher-brand.sh run        wrap the real assessment: banner, sloth
#                                  loops while ./run.sh run works, then output
# =============================================================================
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

GREEN=$'\033[38;2;57;255;20m'    # neon green  #39FF14
ROSE=$'\033[1;38;2;255;45;149m'  # neon rose   #FF2D95 (bold)
DIM=$'\033[38;2;199;204;199m'    # soft gray
RESET=$'\033[0m'
MANGO="🥭"
SLOTH="🦥"
WIDTH=18

# ---- banner: neon diamond + locked motto -----------------------------------
banner() {
  printf '%s' "$GREEN"
  cat <<'LOGO'

               *               
              ***              
             *****             
            *******            
           *********           
          ***********          
         *****Psypher*****     
          *****Labs*****      
           ***********          
            *******            
             *****             
              ***              
               *               
LOGO
  printf '%s\n' "$RESET"
  printf '%sPsypher AI Threat Assessor%s\n' "$GREEN" "$RESET"
  printf '%sFull-stack AI/ML security — MITRE ATLAS–grounded penetration testing%s\n' "$DIM" "$RESET"
  printf '%sof the model and the infrastructure it runs on%s\n' "$DIM" "$RESET"
  printf '%sPowered by Claude · Designed by PsypherLabs%s\n\n' "$ROSE" "$RESET"
}

# ---- deadpan sloth captions (cycled at random each pass) --------------------
CAPTIONS=(
  "sniffing the perimeter..."
  "digging through the graph..."
  "checking the CVE burrow..."
  "interrogating the model..."
  "slothing toward the exploit..."
  "hanging from the attack tree..."
  "one claw on the payload..."
  "chewing on the threat model..."
  "slowly cornering the model..."
  "napping between probes..."
  "in no rush, still winning..."
  "reticulating the mango splines..."
  "creeping up on a finding..."
  "the model cannot outrun a sloth..."
  "a mango a day keeps the exploits away..."
  "this model is one ripe mango..."
  "peeling back the layers..."
  "slow and steady catches the pirate..."
  "boarding the models weak spots..."
  "walking the plank of least privilege..."
  "plundering the prompt for treasure..."
  "X marks the jailbreak..."
  "hoisting the mainframe..."
  "no parrot, just payloads..."
  "the model walked the plank..."
  "this AI has a soft underbelly..."
  "teaching the model some manners..."
  "the weights are talking..."
  "hallucination detected, mango secured..."
  "the model blinked first..."
  "tokens in, secrets out..."
  "prompt injected, sloth unbothered..."
  "guardrails? more like guard-fails..."
  "the model confessed everything..."
  "jailbreak in three, two, zzz..."
  "too slow to fail..."
  "outsmarting the smart machine..."
  "eating exploits like fruit..."
  "the graph never lies..."
  "one nap away from root..."
)
random_caption() { echo "${CAPTIONS[RANDOM % ${#CAPTIONS[@]}]}"; }

dots() { local n=$1 s='' i; for ((i=0; i<n; i++)); do s+='·'; done; printf '%s' "$s"; }

cleanup() { printf '\033[?25h'; }
trap cleanup EXIT

# one right->left crawl; prints frames, picks a fresh caption for the pass
one_pass() {
  local cap; cap="$(random_caption)"
  local p
  for (( p=WIDTH; p>=0; p-- )); do
    "$@" || return 0
    printf '\r %s%s%s%s   %s%-34s%s' "$MANGO" "$(dots "$p")" "$SLOTH" "$(dots "$((WIDTH-p))")" "$DIM" "$cap" "$RESET"
    sleep 0.14
  done
}

# ---- MODE 1: plain demo (no args) — loops forever until Ctrl-C --------------
if [ "$#" -eq 0 ]; then
  banner
  printf '\033[?25l'
  trap 'printf "\033[?25h\n"; exit 0' INT TERM
  while true; do one_pass true; done
fi

# ---- MODE 2: wrap the real assessment — loops until the run finishes --------
LOG="$(mktemp /tmp/psypher-brand.XXXXXX.log)"
export FORCE_COLOR=1
trap 'printf "\033[?25h\n"; kill "$PID" 2>/dev/null; rm -f "$LOG"; exit 130' INT TERM
trap 'printf "\033[?25h"; rm -f "$LOG"' EXIT

banner
./run.sh "$@" >"$LOG" 2>&1 &
PID=$!
printf '\033[?25l'
# keep looping full crawls until the background run exits
while kill -0 "$PID" 2>/dev/null; do
  one_pass kill -0 "$PID"
done
wait "$PID"; rc=$?
printf '\r%80s\r' ''
cat "$LOG"
# universal finish line — report the real count if we can find one, else just done
N="$(grep -oE '[0-9]+ finding' "$LOG" | grep -oE '[0-9]+' | tail -1)"
if [ -n "$N" ]; then
  printf '\n %s%s  nom nom nom — %s findings!\n' "$SLOTH" "$MANGO" "$N"
else
  printf '\n %s%s  nom nom nom — assessment complete.\n' "$SLOTH" "$MANGO"
fi
exit "$rc"
