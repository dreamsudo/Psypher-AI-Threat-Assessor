#!/usr/bin/env python3
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  data/distro_index.py — index the Debian security tracker into SQLite.
#  Standalone acquisition tool (Part C / C3). No engine imports.
# =============================================================================
"""Build data/distro/debian.sqlite from the Debian security-tracker JSON.

Authoritative per-package, per-release CVE status. Rows: (package, cve_id,
release, status, fixed_version). This is what makes promotion collision-free
(Debian's package namespace == the target's) and backport-aware (fixed_version
is the Debian revision that carries the fix). Deterministic, stdlib only.
"""
from __future__ import annotations
import json, sqlite3, sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "data/distro/debian.json")
DB = SRC.with_name("debian.sqlite")

SCHEMA = """
DROP TABLE IF EXISTS deb;
CREATE TABLE deb (package TEXT, cve_id TEXT, release TEXT, status TEXT, fixed_version TEXT, urgency TEXT);
"""

def main():
    doc = json.load(open(SRC, encoding="utf-8"))
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    rows = []
    pkgs = cves = 0
    for package, entries in doc.items():
        pkgs += 1
        for cid, info in entries.items():
            cves += 1
            for rel, r in info.get("releases", {}).items():
                rows.append((package, cid, rel, r.get("status", ""),
                             str(r.get("fixed_version", "")), r.get("urgency", "")))
        if len(rows) >= 50000:
            con.executemany("INSERT INTO deb VALUES (?,?,?,?,?,?)", rows); rows = []
    if rows:
        con.executemany("INSERT INTO deb VALUES (?,?,?,?,?,?)", rows)
    con.execute("CREATE INDEX idx_deb_pkg ON deb(package, release)")
    con.commit()
    total = con.execute("SELECT COUNT(*) FROM deb").fetchone()[0]
    rels = [r[0] for r in con.execute("SELECT DISTINCT release FROM deb ORDER BY 1")]
    print("packages:", pkgs, "| package-CVE pairs:", cves, "| status rows:", total)
    print("releases present:", rels)
    # self-check: our sudo CVE in sid
    row = con.execute("SELECT package,cve_id,release,status,fixed_version,urgency FROM deb "
                      "WHERE package='sudo' AND cve_id='CVE-2025-32463' AND release='sid'").fetchone()
    print("self-check sudo/CVE-2025-32463/sid:", row)
    con.close()
    print("wrote", DB)

if __name__ == "__main__":
    main()
