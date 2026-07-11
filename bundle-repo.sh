#!/usr/bin/env bash
###############################################################################
#  bundle-repo.sh  —  Psypher AI Threat Assessor : codebase bundler (TAILORED)
#  ===========================================================================
#  This is the BESPOKE, bulletproof bundler for the psypher-assessor repository.
#  It photographs the code into a small set of segmented, richly-labeled text
#  files that the Psypher project chats (Coder / Navigator) read as authority.
#  It is tuned to THIS repo's exact layout; the generic template it derives from
#  is kept separately for other repos.
#
#  ---------------------------------------------------------------------------
#  OUTPUT CONTRACT  (exactly these files, into ./repo-bundle_<YYYYMMDD_HHMMSS>/)
#  ---------------------------------------------------------------------------
#  The Operating Protocol and the two prompts key off these names — they are
#  fixed and must not drift:
#      Bundle Guide.md         the authority guide: how to read the bundle + regen
#      00_INDEX.md             authoritative map: routing table + MASTER TREE +
#                              per-section manifest + drop ledger  (READ FIRST)
#      01_ENGINE_CORE.txt      the sealed framework
#      02_ENGINE_PIPELINE.txt  the four stages: discovery -> graph -> analysis -> report
#      03_PACKS.txt            data-driven assessment content (probes/policies/prompts/…)
#      04_DATA_AND_OPS.txt     data builders + ops scripts + config + tests + capped data
#  No 99_MISC file is expected: section 04 is a "*" catch-all, so every kept file
#  lands in a section. A built-in AUDIT (near the end) proves that kept + capped +
#  dropped == every file walked, so nothing is ever silently missed.
#
#  ---------------------------------------------------------------------------
#  CLASSIFICATION POLICY  (tailored to this repo — see the CONFIG block for lists)
#  ---------------------------------------------------------------------------
#  KEEP (full contents):
#      • all engine source            engine/**/*.py
#      • all packs                    packs/**  (probe JSON + .py, policies, prompts,
#                                      red-team corpus, relevance maps)
#      • all data/ops builders        data/*.py, data/*.sh, build_d3fend_cwe_slice.py,
#                                      the root operator scripts, tests/*.py
#      • small config + schemas       assessor.yaml, pyproject.toml, requirements.txt,
#                                      engine/core/schema/*.schema.json, probe JSON
#  CAP (format sample only — first N lines/bytes; first file per directory sampled):
#      • the reference datasets       data/{atlas-data,attack-stix-data,cve,cwe,
#                                      d3fend,distro,kev,nvd}/*  (NVD yearly JSONs cap
#                                      too when re-fetched; today only index.sqlite is
#                                      present there and is dropped as a database)
#      • the generated graph          build/graph/*.json
#  DROP (excluded, but every item is listed with a reason in 00_INDEX.md):
#      • all documentation            *.md  →  keeps EDIT-LOG.md, PSYPHER-PROBE-ROADMAP.md,
#                                      and any changelog OUT of the bundle by design; the
#                                      Developer Manual + edit ledger live on disk separately
#      • generated output tree        assessments/  (pruned wholesale)
#      • databases                    *.sqlite  (data/nvd/index.sqlite, data/distro/debian.sqlite)
#      • runtime log                  logs/exchanges.jsonl
#      • byte-code / caches / VCS     __pycache__, *.pyc, .git, tool caches, IDE dirs
#      • the bundler + prior bundles  this script self-excludes; repo-bundle_* pruned
#      There is NO changelog in this system; nothing changelog-named is ever bundled.
#
#  ---------------------------------------------------------------------------
#  BULLETPROOFING
#  ---------------------------------------------------------------------------
#    • NUL-safe walk (spaces/newlines in names), binary & symlink & unreadable
#      files handled explicitly, empty dirs are harmless (no files → nothing to miss).
#    • Self-excludes by its own basename; prunes prior repo-bundle_*/ so re-runs
#      never ingest their own output.
#    • Degrades gracefully: uses python3 (outlines + tree), tree, jq if present;
#      falls back cleanly if any are missing.
#    • Final AUDIT asserts full accounting and that every contract file was written.
#
#  Usage:  ./bundle-repo.sh [ROOT_DIR]     (defaults to "." — run it from the repo root)
#  Needs:  bash >= 4.3 + coreutils.  python3/tree/jq/git used if present.
#  Ref:    Operating Protocol — authority is `Bundle Guide.md` + this bundle + the manual.
###############################################################################
set -uo pipefail

###############################################################################
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │ 1. SECTIONS  —  THE ONE THING YOU EDIT PER REPO                          │
#  └─────────────────────────────────────────────────────────────────────────┘
#  Each entry:   "ID|TITLE|glob1,glob2,...|One-line description"
#    • ID     two digits, sets file order + name (e.g. 01 -> 01_<TITLE>.txt).
#    • TITLE  short label; spaces become underscores in the filename.
#    • globs  comma-separated path globs matched against each file's RELATIVE
#             path. Shell globbing: * matches across '/', ? and [..] work.
#    • desc   shown atop the section file and used to build the routing table.
#             (Descriptions may contain commas; they must NOT contain '|'.)
#  A file joins the FIRST section whose ANY glob matches. Put path-specific
#  sections (e.g. data/*) BEFORE extension-only sections. Anything matched by no
#  section is swept into an auto 99_MISC section, so nothing is lost — but aim to
#  cover everything on purpose. Provide a final "*" catch-all to avoid MISC.
#
#  ── THIS REPO'S LAYOUT (locked to the Psypher output contract) ──
#  Four sections, pinned so the filenames come out EXACTLY as the prompts expect
#  (title "ENGINE CORE" -> 01_ENGINE_CORE.txt, "DATA AND OPS" -> 04_DATA_AND_OPS.txt).
#  Section 04's glob is "*", making it the catch-all: every file not claimed by
#  01–03 lands there, which guarantees full coverage (the AUDIT near the end proves
#  it). Do NOT add a 5th section — the prompts read exactly these four. For THIS
#  tree, files route like so:
#     01 ENGINE CORE .... engine/core/** (incl. schema/*.schema.json) + engine/__init__.py
#                         + engine/__main__.py + engine/relevance.py
#     02 ENGINE PIPELINE  engine/{discovery,graph,analysis,report}/**   (stage order)
#     03 PACKS .......... packs/**  (host-isolation, ml-inference, model-artifact,
#                         model-endpoint, model-redteam probes; policies; prompts;
#                         redteam corpus; relevance; blackbox; intake; data/sources.yaml)
#     04 DATA AND OPS ... root scripts (run/clean/setkey/setmodel/selfcheck/blackbox-run/
#                         psypher-brand/psypher-hop) + build_d3fend_cwe_slice.py +
#                         assessor.yaml + pyproject.toml + requirements.txt +
#                         data/ builders (d3fend_extract/distro_index/kev_build/nvd_index/
#                         relevance_build .py, fetch.sh, nvd-build.sh) + tests/*.py +
#                         CAPPED: data/**/* datasets and build/graph/*.json
SECTIONS=(
  "01|ENGINE CORE|engine/core/*,engine/__init__.py,engine/__main__.py,engine/relevance.py|The sealed framework: orchestration, config, data models, contracts, the prompt registry, the evidence log, validation, and the assessment/grain/policy/probe/profile/source JSON schemas. No probe names or attack strings live here."
  "02|ENGINE PIPELINE|engine/discovery/*,engine/graph/*,engine/analysis/*,engine/report/*|The fixed, ordered assessment pipeline in execution order: discovery (enumerate/probe the target) -> graph (build+enrich the knowledge graph with CVE/CWE/ATT&CK/D3FEND) -> analysis (scoring, posture, kill-chain, policy matching) -> report (assemble HTML/markdown/navigator). Each stage exposes a phase.py."
  "03|PACKS|packs/*|Data-driven assessment content loaded at runtime (never core logic): probe descriptors + modules grouped by domain (host-isolation, ml-inference, model-artifact, model-endpoint, model-redteam), scan policies, the engine + red-team prompt registries, relevance role/artifact maps, the black-box probe, and intake examples."
  "04|DATA AND OPS|*|How the tool is fed and operated: the reference-data builder scripts (NVD/ATT&CK/CWE/KEV/D3FEND ingestion + the CWE-slice builder), operator shell scripts (run/setup/keys/model), the control-plane config, the test suite, and CAPPED format samples of the large reference datasets and the generated graph."
)

###############################################################################
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │ 2. CLASSIFICATION KNOBS  —  usually fine as-is; tune per repo if needed  │
#  └─────────────────────────────────────────────────────────────────────────┘
OUT_PREFIX="repo-bundle"          # output folder name + re-run prune prefix
LINE_CAP=150                      # capped files: max lines of sample
BYTE_CAP=$((16*1024))             # capped files: max bytes of sample
CAP_THRESHOLD=$((32*1024))        # ANY data-extension file larger than this is capped

# Directories pruned wholesale (never walked). Universally-noisy defaults; add
# repo-specific generated dirs here (e.g. "assessments" "coverage" "target").
EXCLUDE_DIRS=( .venv venv env virtualenv ENV __pycache__ .pytest_cache .mypy_cache
               .ruff_cache .tox .eggs "*.egg-info" node_modules .git .hg .svn
               .idea .vscode assessments )

# Files DROPPED by basename glob. Generated/binary artifacts + ALL documentation.
# Dropping "*.md" is DELIBERATE for Psypher: it keeps EDIT-LOG.md, the developer
# manual, packs/redteam/PSYPHER-PROBE-ROADMAP.md, and any changelog OUT of the
# bundle — they live on disk separately per the Operating Protocol. Databases and
# archives are binary/huge and never belong in a text bundle.
DROP_GLOBS=( "*.md"                                  # all docs (manual, EDIT-LOG, roadmap, changelogs)
             "*.sqlite" "*.sqlite3" "*.db"           # databases (data/nvd/index.sqlite, data/distro/debian.sqlite)
             "*.xz" "*.gz" "*.tgz" "*.zip" "*.7z" "*.rar" "*.tar"   # archives
             "*.bak*" "*.orig" "*.rej"               # backups / merge cruft
             "*.meta"                                # sidecar checksums
           )
# Case-insensitive basename substring drop — belt-and-suspenders so nothing whose
# name contains "changelog" can ever slip in (this system has no changelog).
DROP_SUBSTR=( "changelog" )

# Files DROPPED by EXACT relative path — here, only the runtime log (it can hold
# live prompts/keys). The bundler self-excludes by its own basename automatically,
# so it never needs listing. Add another exact path here only if this tree grows one.
DROP_NAMES=( "logs/exchanges.jsonl" )

# Data directories whose files become capped format samples regardless of size.
# (The size threshold above already auto-caps big data files anywhere.)
CAP_PATH_PREFIXES=( "data/nvd/" "data/attack-stix-data/" "data/cwe/" "data/d3fend/" "data/kev/" "data/atlas-data/" "data/cve/" "data/distro/" "build/graph/" )             # e.g. ( "data/nvd/" "data/attack-stix-data/" "build/graph/" )

# Extensions treated as "data" for capping decisions.
DATA_EXTS=( json xml jsonl ndjson csv tsv )

###############################################################################
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │ 3. MACHINERY  —  do not edit below unless changing behavior for all repos │
#  └─────────────────────────────────────────────────────────────────────────┘
ROOT="${1:-.}"; [[ -d "$ROOT" ]] || { echo "error: '$ROOT' not a directory" >&2; exit 1; }
ROOT_ABS="$(cd "$ROOT" && pwd -P)"; REPO_NAME="$(basename "$ROOT_ABS")"
SELF="$(basename "$0")"                       # so the script never bundles itself
TS="$(date +%Y%m%d_%H%M%S)"; OUT_DIR="${OUT_PREFIX}_${TS}"; mkdir -p "$OUT_DIR"
IDX="$OUT_DIR/00_INDEX.md"
command -v python3 >/dev/null 2>&1 && HAVE_PY=1 || HAVE_PY=0

# ---- section table accessors --------------------------------------------------
# SECTIONS entries are "ID|TITLE|globs|desc"; these pull fields by ID.
sec_title(){ local e i t; for e in "${SECTIONS[@]}"; do IFS='|' read -r i t _ _ <<<"$e"; [[ "$i" == "$1" ]] && { printf '%s' "$t"; return; }; done; [[ "$1" == 99 ]] && printf 'MISC / UNCATEGORIZED'; }
sec_desc(){ local e i d; for e in "${SECTIONS[@]}"; do IFS='|' read -r i _ _ d <<<"$e"; [[ "$i" == "$1" ]] && { printf '%s' "$d"; return; }; done; [[ "$1" == 99 ]] && printf 'Files matched by no section rule — review and fold into a section if needed.'; }
sec_slug(){ local t s; t="$(sec_title "$1")"; s="${t//[^A-Za-z0-9]/_}"; while [[ "$s" == *__* ]]; do s="${s//__/_}"; done; s="${s#_}"; s="${s%_}"; printf '%s' "$s"; }
sec_file(){ printf '%s/%s_%s.txt' "$OUT_DIR" "$1" "$(sec_slug "$1")"; }

# ---- generic helpers ----------------------------------------------------------
detect_mime(){ command -v file >/dev/null 2>&1 && { file -b --mime "$1" 2>/dev/null || echo unknown; } || echo unknown; }
filesize(){ stat -c %s "$1" 2>/dev/null || wc -c < "$1" 2>/dev/null || echo 0; }
is_binary(){ local f="$1"; [[ -s "$f" ]] || return 1
  if command -v file >/dev/null 2>&1; then [[ "$(file -b --mime-encoding "$f" 2>/dev/null)" == binary ]]; return; fi
  grep -Iq . "$f" 2>/dev/null && return 1 || return 0; }
lc(){ printf '%s' "${1,,}"; }
ext_of(){ local b="${1##*/}"; [[ "$b" == *.* ]] && printf '%s' "${b##*.}" || printf ''; }

# DROP decision: self, exact names, substrings, then basename globs.
is_drop(){ local rel="$1" b="${1##*/}" n g s
  [[ "$b" == "$SELF" ]] && return 0
  for n in "${DROP_NAMES[@]}";  do [[ "$rel" == "$n" ]] && return 0; done
  for s in "${DROP_SUBSTR[@]}"; do [[ "$(lc "$b")" == *"$s"* ]] && return 0; done
  for g in "${DROP_GLOBS[@]}";  do case "$b" in $g) return 0;; esac; done
  return 1; }

# CAP decision: schemas never capped; data-extension files capped if under a
# listed prefix OR larger than the threshold.
is_cap(){ local f="$1" rel="$2" b="${2##*/}" e; e="$(lc "$(ext_of "$rel")")"
  [[ "$b" == *.schema.json ]] && return 1
  local isdata=0 x; for x in "${DATA_EXTS[@]}"; do [[ "$e" == "$x" ]] && isdata=1 && break; done
  [[ $isdata -eq 0 ]] && return 1
  local p; for p in "${CAP_PATH_PREFIXES[@]}"; do [[ "$rel" == "$p"* ]] && return 0; done
  [[ "$(filesize "$f")" -gt "$CAP_THRESHOLD" ]] && return 0 || return 1; }

# Assign a file to the first section whose any glob matches; else 99 (MISC).
bucket_of(){ local rel="$1" e id g gg x
  for e in "${SECTIONS[@]}"; do IFS='|' read -r id _ g _ <<<"$e"; IFS=',' read -ra gg <<<"$g"
    for x in "${gg[@]}"; do case "$rel" in $x) printf '%s' "$id"; return;; esac; done
  done; printf '99'; }

# Generic narrative order inside a section: entry/index files first, schemas last.
rank_of(){ local b="${1##*/}" rr=500
  case "$b" in __main__.*) rr=10;; __init__.*) rr=11;; index.*|main.*|mod.rs|lib.rs) rr=12;; phase.*) rr=20;; esac
  case "$b" in *.schema.*) rr=900;; esac
  printf '%03d' "$rr"; }

drop_reason(){ local b="${1##*/}" s
  [[ "$b" == "$SELF" ]] && { echo "the bundler itself"; return; }
  for s in "${DROP_SUBSTR[@]}"; do [[ "$(lc "$b")" == *"$s"* ]] && { echo "$s"; return; }; done
  case "$1" in $(printf '%s|' "${DROP_NAMES[@]}")xXx) : ;; esac  # (names handled below)
  local n; for n in "${DROP_NAMES[@]}"; do [[ "$1" == "$n" ]] && { echo "listed drop"; return; }; done
  case "$b" in *.md) echo doc;; *.bak*|*.orig|*.rej) echo backup;; *.sqlite|*.sqlite3|*.db) echo database;;
    *.xz|*.gz|*.tgz|*.zip|*.7z|*.rar|*.tar) echo archive;; *.meta) echo "metadata sidecar";; *) echo excluded;; esac; }

count_under(){ find "$ROOT_ABS" -type d -name "$1" -prune -print0 2>/dev/null \
  | while IFS= read -r -d '' d; do find "$d" -type f 2>/dev/null; done | wc -l; }

# ---- embedded python: per-file OUTLINE (classes/methods/functions/docstring) --
read -r -d '' OUTLINER_PY <<'PYEOF' || true
import ast, sys
p = sys.argv[1]
try: src = open(p, encoding="utf-8", errors="replace").read()
except Exception: sys.exit(0)
def a(fn):
    xs=[x.arg for x in fn.args.args]
    if fn.args.vararg: xs.append("*"+fn.args.vararg.arg)
    if fn.args.kwarg: xs.append("**"+fn.args.kwarg.arg)
    return ", ".join(xs)
try: t=ast.parse(src)
except SyntaxError:
    for i,l in enumerate(src.splitlines(),1):
        s=l.strip()
        if s.startswith("class ") or s.startswith("def "): print("  "+s.rstrip(":")+"   L%d"%i)
    sys.exit(0)
d=ast.get_docstring(t)
if d: print("  doc: "+d.strip().splitlines()[0][:110])
for n in t.body:
    if isinstance(n, ast.ClassDef):
        bs=[]
        for b in n.bases:
            try: bs.append(ast.unparse(b))
            except Exception: bs.append(getattr(b,"id","?"))
        print("  class %s%s   L%d"%(n.name, "("+", ".join(bs)+")" if bs else "", n.lineno))
        for s in n.body:
            if isinstance(s,(ast.FunctionDef,ast.AsyncFunctionDef)): print("    .%s(%s)   L%d"%(s.name,a(s),s.lineno))
    elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)): print("  def %s(%s)   L%d"%(n.name,a(n),n.lineno))
PYEOF

# ---- embedded python: ASCII tree from "path<TAB>annotation" lines on stdin ----
read -r -d '' TREEPRINT_PY <<'PYEOF' || true
import sys
root = sys.argv[1] if len(sys.argv)>1 else "."
tree={}
for line in sys.stdin:
    line=line.rstrip("\n")
    if not line: continue
    p,ann=(line.split("\t",1)+[""])[:2]
    parts=p.split("/"); cur=tree
    for seg in parts[:-1]: cur=cur.setdefault(seg,{})
    cur.setdefault("__f__",[]).append((parts[-1],ann))
def walk(d,prefix=""):
    dirs={k:v for k,v in d.items() if k!="__f__"}; files=d.get("__f__",[])
    items=[(n,"d",None) for n in dirs]+[(n,"f",x) for n,x in files]
    items.sort(key=lambda z:z[0].lower())
    for i,(name,kind,ann) in enumerate(items):
        last=i==len(items)-1; conn="└── " if last else "├── "; ext="    " if last else "│   "
        if kind=="d": print(prefix+conn+name+"/"); walk(dirs[name],prefix+ext)
        else: print(prefix+conn+name+("   "+ann if ann else ""))
print(root+"/"); walk(tree)
PYEOF

emit_outline(){ local f="$1" e; e="$(lc "$2")"
  case "$e" in
    py) [[ $HAVE_PY -eq 1 ]] && python3 -c "$OUTLINER_PY" "$f" 2>/dev/null | head -n 80 ;;
    sh|bash) awk 'NR<=10 && /^#/ && !/^#!/ {print "  # "substr($0,3); c++} c>=2{exit}' "$f" 2>/dev/null
      grep -nE '^[[:space:]]*(function[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)' "$f" 2>/dev/null \
        | sed -E 's/^([0-9]+):[[:space:]]*(function[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*).*/  fn \3()   L\1/' | head -n 60 ;;
    yaml|yml) grep -nE '^[A-Za-z0-9_.-]+:' "$f" 2>/dev/null | sed -E 's/^([0-9]+):([A-Za-z0-9_.-]+):.*/  key: \2   L\1/' | head -n 60 ;;
    json) command -v jq >/dev/null 2>&1 && jq -r 'if type=="object" then (keys_unsorted[]|"  ."+.) elif type=="array" then "  [array of \(length) items]" else "  ("+(type)+")" end' "$f" 2>/dev/null | head -n 60 ;;
  esac; }

# ============================================================================ DISCOVER + CLASSIFY
prune=( -type d '(' -name 'flatten_*' -o -name "${OUT_PREFIX}_*" )
for d in "${EXCLUDE_DIRS[@]}"; do prune+=( -o -name "$d" ); done
prune+=( ')' -prune )
mapfile -d '' FILES < <(find "$ROOT_ABS" "${prune[@]}" -o '(' -type f -o -type l ')' -print0 | sort -z)

declare -a REL FULL STATUS BUCKET KEY SIZE KIND
declare -A SAMPLED
N=0
for f in "${FILES[@]}"; do
  rel="${f#"$ROOT_ABS"/}"; REL[N]="$rel"; FULL[N]="$f"
  if   [[ -L "$f" ]]; then KIND[N]=link;   SIZE[N]=0
  elif is_binary "$f"; then KIND[N]=binary; SIZE[N]="$(filesize "$f")"
  else KIND[N]=text; SIZE[N]="$(filesize "$f")"; fi
  if is_drop "$rel"; then STATUS[N]=DROP; BUCKET[N]=""; KEY[N]=""
  else
    if is_cap "$f" "$rel"; then STATUS[N]=CAP; else STATUS[N]=KEEP; fi
    BUCKET[N]="$(bucket_of "$rel")"; KEY[N]="${BUCKET[N]}:$(rank_of "$rel"):$rel"
  fi
  N=$((N+1))
done

# order kept/capped files (bucket, then rank, then path) and record drops
declare -a ORDERED DROPPED
sortable=()
for ((i=0;i<N;i++)); do
  [[ "${STATUS[i]}" == DROP ]] && { DROPPED+=("$i"); continue; }
  sortable+=( "${KEY[i]}"$'\t'"$i" )
done
if ((${#sortable[@]})); then
  while IFS= read -r line; do ORDERED+=( "${line##*$'\t'}" ); done < <(printf '%s\n' "${sortable[@]}" | sort)
fi

# section id list in SECTIONS order, plus 99 if any file landed there
declare -a SEC_ORDER; declare -A SEC_HAS
for e in "${SECTIONS[@]}"; do IFS='|' read -r sid _ _ _ <<<"$e"; SEC_ORDER+=("$sid"); done
for idx in ${ORDERED[@]+"${ORDERED[@]}"}; do SEC_HAS["${BUCKET[idx]}"]=1; done
[[ -n "${SEC_HAS[99]:-}" ]] && SEC_ORDER+=("99")

indices_for(){ local sid="$1" idx; for idx in ${ORDERED[@]+"${ORDERED[@]}"}; do [[ "${BUCKET[idx]}" == "$sid" ]] && printf '%s\n' "$idx"; done; }

# subtree for a set of indices (uses python if present, else a sorted list)
subtree(){ local idx cap
  { for idx in "$@"; do cap=""; [[ "${STATUS[idx]}" == CAP ]] && cap="[CAP]"; printf '%s\t%s\n' "${REL[idx]}" "$cap"; done; } \
    | { [[ $HAVE_PY -eq 1 ]] && python3 -c "$TREEPRINT_PY" "$REPO_NAME" || sort; }; }

# ============================================================================ ONE FILE BLOCK
emit_block(){ local idx="$1" seq="$2" tot="$3"
  local f="${FULL[idx]}" rel="${REL[idx]}" st="${STATUS[idx]}" e; e="$(ext_of "$rel")"
  local dir="${rel%/*}"; [[ "$dir" == "$rel" ]] && dir="(root)"
  local crumb="${rel//\// → }" depth mime; depth="$(awk -F/ '{print NF}' <<<"$rel")"; mime="$(detect_mime "$f")"
  printf '╔══ [%03d/%03d] ═══════════════════════════════════════════════════════════════\n' "$seq" "$tot"
  printf '║ PATH : %s\n║ TREE : %s   (depth %s)\n║ DIR  : %s\n' "$rel" "$crumb" "$depth" "$dir"
  if [[ "${KIND[idx]}" == link ]]; then
    printf '║ TYPE : symlink -> %s\n╠──────\n[symlink; not followed]\n' "$(readlink "$f" 2>/dev/null)"
  elif [[ ! -r "$f" ]]; then
    printf '║ TYPE : %s | %s\n╠──────\n[unreadable]\n' "$mime" "$st"
  elif [[ "${KIND[idx]}" == binary ]]; then
    printf '║ SIZE : %s bytes | binary | %s | %s\n╠──────\n[binary — content omitted]\n' "${SIZE[idx]}" "$mime" "$st"
  elif [[ "$st" == CAP ]]; then
    local sz="${SIZE[idx]}" lines; lines="$(wc -l <"$f" 2>/dev/null | tr -d ' ')"
    printf '║ SIZE : %s bytes | %s lines | %s | STATUS CAPPED\n' "$sz" "${lines:-0}" "$mime"
    if [[ -n "${SAMPLED[$dir]:-}" ]]; then
      printf '║ NOTE : same format as the first capped file in %s/ — body omitted\n╠──────\n[sample omitted; see the first capped file in this directory]\n' "$dir"
    else
      SAMPLED[$dir]=1
      printf '║ NOTE : format sample — first %s lines / %s bytes of %s total lines\n' "$LINE_CAP" "$BYTE_CAP" "${lines:-0}"
      if command -v jq >/dev/null 2>&1 && [[ "$(lc "$e")" == json && "$sz" -lt 2097152 ]]; then
        local keys; keys="$(jq -r 'if type=="object" then (keys_unsorted|join(", ")) elif type=="array" then "[array of "+(length|tostring)+" items]" else type end' "$f" 2>/dev/null)"
        [[ -n "$keys" ]] && printf '║ KEYS : %s\n' "$keys"
      fi
      printf '╠──────\n'; head -n "$LINE_CAP" "$f" 2>/dev/null | head -c "$BYTE_CAP"
      printf '\n[... TRUNCATED: sample of %s total lines / %s total bytes ...]\n' "${lines:-0}" "$sz"
    fi
  else
    local sz="${SIZE[idx]}" lines out; lines="$(wc -l <"$f" 2>/dev/null | tr -d ' ')"
    printf '║ SIZE : %s bytes | %s lines | %s | STATUS FULL\n' "$sz" "${lines:-0}" "$mime"
    out="$(emit_outline "$f" "$e")"
    if [[ -n "$out" ]]; then printf '║ OUTLINE:\n'; printf '%s\n' "$out" | sed 's/^/║ /'; fi
    printf '╠──────\n'; cat "$f"; printf '\n'
  fi
  printf '╚══ END %s ══\n\n' "$rel"
}

# ============================================================================ WRITE SECTION FILES
for sid in "${SEC_ORDER[@]}"; do
  mapfile -t idxs < <(indices_for "$sid"); tot="${#idxs[@]}"; [[ $tot -eq 0 ]] && continue
  file="$(sec_file "$sid")"; title="$(sec_title "$sid")"; desc="$(sec_desc "$sid")"
  {
    printf '################################################################################\n'
    printf '# %s — %s  [%s]\n' "$REPO_NAME" "$title" "$sid"
    printf '# %d file(s) | generated %s\n' "$tot" "$(date '+%Y-%m-%d %H:%M:%S %z')"
    printf '################################################################################\n\n'
    printf 'ABOUT THIS SECTION\n  %s\n\n' "$desc"
    printf 'STRUCTURE (this section — the authoritative full tree is in 00_INDEX.md)\n'
    subtree "${idxs[@]}" | sed 's/^/  /'
    printf '\nCONTENTS\n'
    s=0; for idx in "${idxs[@]}"; do s=$((s+1)); printf '  [%03d/%03d] %-5s %s\n' "$s" "$tot" "${STATUS[idx]}" "${REL[idx]}"; done
    printf '\n=== FILES ===\n\n'
    s=0; for idx in "${idxs[@]}"; do s=$((s+1)); emit_block "$idx" "$s" "$tot"; done
    printf '################################################################################\n# END %s\n################################################################################\n' "$title"
  } > "$file"
done

# ============================================================================ INDEX (00) — AUTHORITY
nkeep=0; ncap=0; ndrop=0
for ((i=0;i<N;i++)); do case "${STATUS[i]}" in KEEP) nkeep=$((nkeep+1));; CAP) ncap=$((ncap+1));; DROP) ndrop=$((ndrop+1));; esac; done
venv_n=$(( $(count_under '.venv') + $(count_under 'venv') + $(count_under 'virtualenv') ))
git_n=$(count_under '.git'); pyc_n=$(count_under '__pycache__')
GIT_INFO="n/a"
if command -v git >/dev/null 2>&1 && git -C "$ROOT_ABS" rev-parse --git-dir >/dev/null 2>&1; then
  GIT_INFO="$(git -C "$ROOT_ABS" describe --always --dirty 2>/dev/null) @ $(git -C "$ROOT_ABS" rev-parse --abbrev-ref HEAD 2>/dev/null)"; fi

master_tree(){ local cap
  { for ((i=0;i<N;i++)); do [[ "${STATUS[i]}" == DROP ]] && continue
      cap=""; [[ "${STATUS[i]}" == CAP ]] && cap=" [CAP]"
      printf '%s\t·%s%s\n' "${REL[i]}" "${BUCKET[i]}" "$cap"
    done; } | { [[ $HAVE_PY -eq 1 ]] && python3 -c "$TREEPRINT_PY" "$REPO_NAME" || sort; }; }

{
  printf '# %s — codebase bundle (index & authority)\n\n' "$REPO_NAME"
  printf '%s\n' "- Generated : $(date '+%Y-%m-%d %H:%M:%S %z')" "- Root      : $ROOT_ABS" "- Git       : $GIT_INFO"
  printf '%s\n'   "- Bundled   : $((nkeep+ncap)) files ($nkeep full, $ncap capped)"
  printf '%s\n\n' "- Dropped   : $ndrop walked files + wholesale dirs (listed below)"
  printf 'The MASTER TREE below is the authoritative map of the repository: every leaf is\n'
  printf 'tagged with the section file that holds it (·NN) and `[CAP]` if only a format\n'
  printf 'sample is included. Answer from these files; if something is absent, check the\n'
  printf 'drop ledger before concluding it is missing.\n\n'

  printf '## Sections\n\n| File | Contents |\n|---|---|\n'
  for sid in "${SEC_ORDER[@]}"; do [[ -z "${SEC_HAS[$sid]:-}" ]] && continue
    printf '| `%s_%s.txt` | %s |\n' "$sid" "$(sec_slug "$sid")" "$(sec_desc "$sid")"; done
  printf '\n## Routing — where to look\n\n| If you need… | Go to |\n|---|---|\n'
  for sid in "${SEC_ORDER[@]}"; do [[ -z "${SEC_HAS[$sid]:-}" ]] && continue
    printf '| %s | `%s` |\n' "$(sec_desc "$sid")" "$sid"; done
  printf '\n'

  printf '## MASTER TREE (authoritative — ·NN = section file, [CAP] = format sample only)\n\n```\n'
  master_tree
  printf '```\n\n## Manifest\n\n'
  for sid in "${SEC_ORDER[@]}"; do [[ -z "${SEC_HAS[$sid]:-}" ]] && continue
    printf '### %s_%s\n```\n' "$sid" "$(sec_slug "$sid")"
    s=0; while IFS= read -r idx; do s=$((s+1)); printf '  [%03d] %-5s %9s B  %s\n' "$s" "${STATUS[idx]}" "${SIZE[idx]}" "${REL[idx]}"; done < <(indices_for "$sid")
    printf '```\n\n'; done

  printf '## Excluded\n\n'
  printf '**Wholesale (not walked):** `.venv` (%d files), `.git` (%d), `__pycache__`/*.pyc (%d), plus caches/node_modules/IDE dirs and prior `flatten_*` / `%s_*` bundles.\n\n' "$venv_n" "$git_n" "$pyc_n" "$OUT_PREFIX"
  printf '**Dropped individually (%d):**\n```\n' "$ndrop"
  for idx in ${DROPPED[@]+"${DROPPED[@]}"}; do printf '  %-22s %9s B  %s\n' "[$(drop_reason "${REL[idx]}")]" "${SIZE[idx]}" "${REL[idx]}"; done
  printf '```\n\n_Capped files show only a format sample (first %d lines / %d bytes); only the first file per directory is sampled._\n' "$LINE_CAP" "$BYTE_CAP"
} > "$IDX"

# ============================================================================ BUNDLE GUIDE (authority guide — makes the bundle self-describing)
# Emits "Bundle Guide.md" (exact name, with the space) into the bundle folder. Its
# reading rules match the block format this script produces, so any downstream reader
# (or prompt) that cites PATH / TREE / OUTLINE / STATUS gets an accurate contract.
docs_dropped=0; for g in "${DROP_GLOBS[@]}"; do [[ "$g" == "*.md" ]] && docs_dropped=1; done
write_guide(){
  local gf="$OUT_DIR/Bundle Guide.md" sid
  {
    printf '# Bundle Guide — how to read the %s code bundle\n\n' "$REPO_NAME"
    printf 'This is a curated snapshot of the %s codebase, produced by `bundle-repo.sh`. It is the\n' "$REPO_NAME"
    printf 'entry point and the rules for reading the code — read it first, then work from `00_INDEX.md`.\n\n'
    printf '## The bundle files\n\n'
    printf -- '- `00_INDEX.md` — the authoritative map: routing table, MASTER TREE, per-section manifest, and the drop ledger. **Read it first** and route from it.\n'
    for sid in "${SEC_ORDER[@]}"; do [[ -z "${SEC_HAS[$sid]:-}" ]] && continue
      printf -- '- `%s_%s.txt` — %s\n' "$sid" "$(sec_slug "$sid")" "$(sec_desc "$sid")"
    done
    cat <<'G1'

## How to read a block

Every file in a section is one labeled block. The header says where it lives and how complete it is:

- `PATH` — the file's real repository path. **Cite code by this PATH, never by the bundle filename.**
- `TREE` — a breadcrumb of the path's place in the hierarchy.
- `OUTLINE` — the file's classes, methods, functions, and docstring, so you can see its shape at a glance.
- `STATUS` — **`FULL`** = the complete file is included; **`CAPPED`** = only a format sample (the first lines) is included, so **never treat a capped file as complete.**

## Finding things

- Route through `00_INDEX.md`'s routing table to the right section file, and treat its MASTER TREE as the authoritative map of what exists and where. Don't scan every file.
- Before concluding something is missing, check the **drop ledger** in `00_INDEX.md` — it may have been excluded on purpose, not lost.

## Snapshot and companions

- This bundle is a **photograph** of the code as of the last `bundle-repo.sh` run. A file edited afterward is stale in the bundle until it is regenerated.
G1
    if [[ $docs_dropped -eq 1 ]]; then
      printf -- '- All `.md` documentation is dropped from the bundle by design, so companion docs (a developer manual, an edit ledger) live on disk **separately** — consult them there.\n'
    else
      printf -- '- Anything the drop rules exclude (see the drop ledger) lives outside the bundle.\n'
    fi
    cat <<'G2'

## Regenerating

Run `./bundle-repo.sh` on the box to rebuild the bundle and reset the snapshot. The script excludes itself from the bundle — read it on disk, not from the bundle.
G2
  } > "$gf"
}
write_guide

# ============================================================================ AUDIT — prove nothing was missed
# Bulletproofing: independently re-derive the accounting and refuse to claim
# success unless (a) every file walked is either bundled or dropped — no file
# fell through with no bucket and no drop — and (b) every file named in the output
# contract actually exists on disk. Any failure prints a loud WARNING with the
# offending paths so a silent miss can never pass unnoticed.
audit_fail=0
# (a) full accounting: for every non-dropped file, it must have a section bucket.
UNACCOUNTED=()
for ((i=0;i<N;i++)); do
  [[ "${STATUS[i]}" == DROP ]] && continue
  [[ -z "${BUCKET[i]}" ]] && UNACCOUNTED+=( "${REL[i]}" )
done
if (( ${#UNACCOUNTED[@]} )); then
  audit_fail=1
  echo "‼ AUDIT WARNING: ${#UNACCOUNTED[@]} file(s) matched no section and were not dropped:" >&2
  printf '    %s\n' "${UNACCOUNTED[@]}" >&2
fi
# The arithmetic identity must hold: kept + capped + dropped == total files walked.
if (( nkeep + ncap + ndrop != N )); then
  audit_fail=1
  echo "‼ AUDIT WARNING: accounting mismatch — kept($nkeep)+capped($ncap)+dropped($ndrop) != walked($N)." >&2
fi
# (b) contract check: every promised output file must be present.
for want in "Bundle Guide.md" "00_INDEX.md" "01_ENGINE_CORE.txt" "02_ENGINE_PIPELINE.txt" "03_PACKS.txt" "04_DATA_AND_OPS.txt"; do
  [[ -f "$OUT_DIR/$want" ]] || { audit_fail=1; echo "‼ AUDIT WARNING: expected output file missing: $want" >&2; }
done
if (( audit_fail == 0 )); then
  echo "✔ AUDIT PASSED — all $N files accounted for ($nkeep full, $ncap capped, $ndrop dropped); every contract file present."
else
  echo "✘ AUDIT FOUND PROBLEMS (see warnings above) — do NOT trust this bundle until resolved." >&2
fi

# ============================================================================ DONE
echo "✔ Bundle complete → $OUT_DIR/"
echo "  Bundle Guide.md"
echo "  00_INDEX.md"
for sid in "${SEC_ORDER[@]}"; do [[ -z "${SEC_HAS[$sid]:-}" ]] && continue
  mapfile -t _c < <(indices_for "$sid"); printf '  %s_%s.txt (%d)\n' "$sid" "$(sec_slug "$sid")" "${#_c[@]}"; done
echo "  Bundled: $((nkeep+ncap)) ($nkeep full, $ncap capped) | Dropped: $ndrop walked + wholesale dirs"
