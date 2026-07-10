# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  data/kev_build.py — CISA KEV catalog -> local store (WS-A prioritization floor).
# =============================================================================
"""Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog and write a
compact local store that the CVE promotion overlay reads to flag CVEs known to
be exploited in the wild.

Standalone, stdlib-only, no engine imports (same contract as the other data/
builders). Deterministic and model-free. This is a RANKING input, never a
filter: a CVE on KEV is already a real CVE, so the store only records that it
is actively exploited — it never hides a finding or invents an id.

The written data/kev/kev.json IS the committed offline / reproducible snapshot.
If the file is absent, promotion falls back to its prior behaviour byte-for-byte
(fail-open). CISA has no SHA companion feed, so integrity here is TLS-verified
transport plus a structural + anchor self-check that refuses to write a store
that does not look like the real catalog.

Usage (from the repo root):
    .venv/bin/python data/kev_build.py             # fetch live -> data/kev/kev.json
    PSYPHER_KEV_URL=<url> .venv/bin/python data/kev_build.py   # override feed URL
"""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Canonical CISA KEV JSON feed (confirmed public, no auth). Overridable via
# PSYPHER_KEV_URL; if CISA ever moves it, change this one constant or set the
# env var. The self-check below refuses to write a garbage store either way.
_DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_OUT = Path(__file__).resolve().parent / "kev" / "kev.json"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
# Permanent KEV entry (Log4Shell) used as a hard self-check anchor.
_ANCHOR = "CVE-2021-44228"
# Roadmap's sudo example — reported only, never a hard gate (recent ids churn).
_SUDO = "CVE-2025-32463"
_MIN_ENTRIES = 500  # real catalog is 1,200+; anything smaller means a bad fetch.


def _fetch(url: str) -> bytes:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "psypher-kev-build/1.0"})
    with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
        return resp.read()


def normalise(raw: bytes) -> dict:
    """Parse the CISA feed into a compact {CVE-ID: {...}} store. Raises
    ValueError on an unexpected shape so a moved/renamed feed cannot silently
    empty the store. Pure function — callable from a test with synthetic bytes."""
    doc = json.loads(raw.decode("utf-8"))
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("feed has no 'vulnerabilities' array")
    cves = {}
    for v in vulns:
        cid = (v.get("cveID") or "").strip().upper()
        if not _CVE_RE.match(cid):
            continue
        # CISA ships this as the string "Known"/"Unknown", not a boolean.
        ransom = (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        cves[cid] = {
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware": ransom,
        }
    return {
        "source": "CISA KEV",
        "catalog_version": doc.get("catalogVersion", ""),
        "date_released": doc.get("dateReleased", ""),
        "fetched": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(cves),
        "cves": cves,
    }


def main() -> int:
    url = os.environ.get("PSYPHER_KEV_URL", _DEFAULT_URL)
    print("KEV: fetching %s" % url)
    try:
        raw = _fetch(url)
    except Exception as exc:  # builder must fail loud, never half-write
        print("KEV: fetch failed: %s" % exc, file=sys.stderr)
        return 2
    try:
        store = normalise(raw)
    except ValueError as exc:
        print("KEV: %s; refusing to write. Confirm the URL." % exc, file=sys.stderr)
        return 3

    n = store["count"]
    if n < _MIN_ENTRIES:
        print("KEV: only %d CVEs parsed (<%d); feed shape looks wrong, not writing"
              % (n, _MIN_ENTRIES), file=sys.stderr)
        return 3
    if _ANCHOR not in store["cves"]:
        print("KEV: anchor %s absent; feed shape looks wrong, not writing" % _ANCHOR,
              file=sys.stderr)
        return 3

    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("KEV: wrote %s" % _OUT)
    print("KEV: %d exploited CVEs [catalog %s, released %s]"
          % (n, store["catalog_version"] or "?", store["date_released"] or "?"))
    print("KEV: anchor %s present: yes" % _ANCHOR)
    print("KEV: %s (sudo, roadmap example) present: %s"
          % (_SUDO, "yes" if _SUDO in store["cves"] else "no"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
