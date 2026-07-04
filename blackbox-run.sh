#!/usr/bin/env bash
# =============================================================================
#  blackbox-run.sh — Psypher AI Threat Assessor · PsypherLabs
#  Standalone runner for the ISOLATED black-box probe. Off by default; refuses
#  unless packs/blackbox/blackbox.yaml has enabled: true. Loads ONLY the
#  black-box config, runs the probe with the real script-probe contract, writes
#  its own tagged output + evidence stream. NOT part of the pipeline, NOT a
#  phase, NOT allowlisted — structurally fenced from the four Claude touchpoints.
# =============================================================================
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"
[[ -d .venv ]] || { echo "error: .venv missing — run ./run.sh once first" >&2; exit 1; }
source .venv/bin/activate
exec python - "$@" <<'PY'
import json, os, sys, time, importlib.util
CFG = "packs/blackbox/blackbox.yaml"
import yaml
cfg = yaml.safe_load(open(CFG, encoding="utf-8")) if os.path.isfile(CFG) else {}
if not cfg.get("enabled"):
    print("black box is DISABLED (set enabled: true in %s to run)." % CFG)
    sys.exit(0)
tgt = cfg.get("target", {})
target_view = {"id": tgt.get("id","blackbox-target"), "kind": tgt.get("kind","inference_endpoint"),
               "access": tgt.get("access","gray"), "endpoint": tgt.get("endpoint"),
               "host": tgt.get("host"), "ssh": tgt.get("ssh")}
auth_env = tgt.get("auth_env")
context_view = {"timeout": 10, "insecure_tls": False,
                "auth_token": os.environ.get(auth_env) if auth_env else None}
spec = importlib.util.spec_from_file_location("black_box_probe",
        "packs/blackbox/black_box_probe.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
result = mod.run(target_view, context_view, cfg.get("directions", {}))
tag = (cfg.get("output", {}) or {}).get("tag", "blackbox")
outdir = (cfg.get("output", {}) or {}).get("dir", "blackbox-out")
os.makedirs(outdir, exist_ok=True)
ts = time.strftime("%Y%m%d-%H%M%S")
# tagged grains (blackbox::<key>) + a run record, its own separable stream
grains = [{"attribute": f"{tag}::{k}", "value": v} for k, v in result.items()]
record = {"ts": ts, "target": target_view["id"], "tag": tag, "grains": grains}
outfile = os.path.join(outdir, f"blackbox-{ts}.json")
json.dump(record, open(outfile, "w", encoding="utf-8"), indent=2, default=str)
print("black box ran. wrote", outfile)
for g in grains:
    print(" ", g["attribute"], "->", json.dumps(g["value"], default=str)[:120])
PY
