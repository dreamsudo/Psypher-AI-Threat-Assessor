#!/usr/bin/env python3
# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  data/nvd_index.py — build a SQLite product index from on-disk NVD feeds.
#  Standalone acquisition tool (Part C / C1). No engine imports.
# =============================================================================
"""Build data/nvd/index.sqlite: product -> CVE, from decompressed NVD-2.0 feeds.

Reads every CVE-<YEAR>.json (Fraunhofer FKIE / NVD-2.0 format) under the NVD
directory and indexes each CPE product so the engine can later promote only the
CVEs whose product matches something observed on a target. Deterministic,
standard-library only. Reports coverage honestly.
"""
from __future__ import annotations
import glob, json, os, sqlite3, sys
from pathlib import Path

NVD_DIR = Path(sys.argv[1] if len(sys.argv) > 1 else "data/nvd")
DB_PATH = NVD_DIR / "index.sqlite"

SCHEMA = """
DROP TABLE IF EXISTS cve;
DROP TABLE IF EXISTS affected;
CREATE TABLE cve (cve_id TEXT PRIMARY KEY, description TEXT, cvss REAL,
                  cvss_severity TEXT, cvss_version TEXT, cwes TEXT, published TEXT, last_modified TEXT);
CREATE TABLE affected (cve_id TEXT, part TEXT, vendor TEXT, product TEXT, vulnerable INTEGER,
                       version TEXT, v_start_incl TEXT, v_start_excl TEXT,
                       v_end_incl TEXT, v_end_excl TEXT);
"""

def best_cvss(metrics):
    _ver = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0",
            "cvssMetricV40": "4.0", "cvssMetricV2": "2.0"}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            if "baseScore" in data:
                return (float(data["baseScore"]),
                        data.get("baseSeverity", m.get("baseSeverity", "")),
                        _ver[key])
    return None, "", ""

def en_desc(descs):
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""

def cwes_of(weaknesses):
    out = []
    for w in weaknesses:
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out

def affected_rows(cve_id, configurations):
    for cfg in configurations:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                p = m.get("criteria", "").split(":")
                if len(p) < 6 or p[0] != "cpe":
                    continue
                yield (cve_id, p[2], p[3], p[4], 1 if m.get("vulnerable") else 0, p[5],
                       m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                       m.get("versionEndIncluding"), m.get("versionEndExcluding"))

def main():
    feeds = sorted(glob.glob(str(NVD_DIR / "CVE-*.json")))
    if not feeds:
        print("no CVE-*.json feeds under", NVD_DIR); return 1
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    total = with_cpe = 0
    for feed in feeds:
        doc = json.load(open(feed, encoding="utf-8"))
        items = doc.get("cve_items", doc if isinstance(doc, list) else [])
        cve_rows, aff_rows = [], []
        for rec in items:
            inner = rec.get("cve", rec)
            cid = inner.get("id")
            if not cid:
                continue
            total += 1
            score, sev, cvver = best_cvss(inner.get("metrics", {}))
            cve_rows.append((cid, en_desc(inner.get("descriptions", [])), score, sev, cvver,
                             json.dumps(cwes_of(inner.get("weaknesses", []))),
                             inner.get("published", ""), inner.get("lastModified", "")))
            rows = list(affected_rows(cid, inner.get("configurations", [])))
            if rows:
                with_cpe += 1
                aff_rows.extend(rows)
        con.executemany("INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?,?)", cve_rows)
        con.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?,?,?,?,?)", aff_rows)
        con.commit()
        print("indexed %-20s %6d CVEs" % (os.path.basename(feed), len(cve_rows)))
    con.execute("CREATE INDEX idx_affected_product ON affected(product)")
    con.commit()
    distinct = con.execute("SELECT COUNT(DISTINCT product) FROM affected WHERE vulnerable=1").fetchone()[0]
    print("\n--- coverage ---")
    print("total CVEs indexed      :", total)
    print("CVEs with a CPE product :", with_cpe, "(%.1f%%)" % (100*with_cpe/total if total else 0))
    print("distinct vuln products  :", distinct)
    row = con.execute("SELECT product, vulnerable, v_start_incl, v_end_excl FROM affected "
                      "WHERE cve_id='CVE-2025-32463' AND vulnerable=1").fetchall()
    print("self-check CVE-2025-32463 vulnerable rows:", row)
    con.close()
    print("wrote", DB_PATH)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
