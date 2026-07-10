# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/graph/promote.py — authoritative distro-driven CVE promotion (Part C).
# =============================================================================
"""Promote, per run, ONLY the CVEs the distro's security team says are genuinely
open on the target's exact package versions. Deterministic, model-free.

Design (Psypher pillars): the distro tracker is the authoritative source, so this
is grounded (real distro status), agnostic (any package in the distro namespace,
no hand-map), honest + backport-aware (compares the installed version against the
distro's fix version using a dpkg-correct comparator), and low-noise (the distro
has already resolved/not-affected the rest). NVD remains the ENRICHMENT layer
(CVSS/CWE/description), looked up by CVE id in the graph. This runs as a per-run
OVERLAY after the base graph is built/loaded, so promoted nodes never enter the
fingerprint-keyed cache; promoted CVEs are real nodes so the closing firewall
re-checks them unchanged.
"""
from __future__ import annotations

import re
import json
import sqlite3
from pathlib import Path

from .canonical import Edge, Graph, Node
from ..relevance import in_scope as _in_scope

INVENTORY_ATTRS = frozenset({"os_package", "python_package"})
_DEFAULT_RELEASE = "sid"
# Urgencies Debian explicitly deems not worth acting on -> catalog, not a primary
# finding. Everything else (low/medium/high, "not yet assigned", empty) is kept:
# untriaged is NOT unimportant (e.g. CVE-2025-32463 is "not yet assigned").
CATALOG_URGENCY = frozenset({"unimportant", "end-of-life"})
_CVE_RE = __import__("re").compile(r"^CVE-\d{4}-\d+$")


# ---- dpkg-correct Debian version comparison (proven == dpkg --compare-versions)
def _split_deb(v: str):
    v = str(v)
    if ":" in v:
        epoch, _, rest = v.partition(":")
    else:
        epoch, rest = "0", v
    if "-" in rest:
        upstream, _, revision = rest.rpartition("-")
    else:
        upstream, revision = rest, "0"
    return epoch, upstream, revision


def _ord(ch: str) -> int:
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _cmp_part(a: str, b: str) -> int:
    def toks(s):
        out, i = [], 0
        while i < len(s):
            m = re.match(r"\D*", s[i:]); nd = m.group(0); i += len(nd)
            m = re.match(r"\d*", s[i:]); dg = m.group(0); i += len(dg)
            out.append((nd, dg))
        return out
    ta, tb = toks(a), toks(b)
    for i in range(max(len(ta), len(tb))):
        nda, dga = ta[i] if i < len(ta) else ("", "")
        ndb, dgb = tb[i] if i < len(tb) else ("", "")
        oa, ob = [_ord(c) for c in nda], [_ord(c) for c in ndb]
        for j in range(max(len(oa), len(ob))):
            x = oa[j] if j < len(oa) else 0
            y = ob[j] if j < len(ob) else 0
            if x != y:
                return -1 if x < y else 1
        na = int(dga) if dga else 0
        nb = int(dgb) if dgb else 0
        if na != nb:
            return -1 if na < nb else 1
    return 0


def deb_compare(v1: str, v2: str) -> int:
    """Return -1/0/1 comparing two Debian versions (matches dpkg)."""
    e1, u1, r1 = _split_deb(v1)
    e2, u2, r2 = _split_deb(v2)
    if int(e1 or 0) != int(e2 or 0):
        return -1 if int(e1 or 0) < int(e2 or 0) else 1
    c = _cmp_part(u1, u2)
    if c:
        return c
    return _cmp_part(r1 or "0", r2 or "0")


# ---- observed packages ------------------------------------------------------
def observed_packages(grains):
    """Return {package_name: installed_version} from inventory grains."""
    out = {}
    for g in grains:
        if getattr(g, "attribute", "") in INVENTORY_ATTRS and isinstance(g.value, str):
            name = g.value.strip().lower()
            if not name or name in out:
                continue
            ver = None
            for ev in g.evidence:
                m = re.search(r"(?mi)^\s*%s\s*==\s*(\S+)" % re.escape(name), ev.raw or "")
                if m:
                    ver = m.group(1); break
            out[name] = ver
    return out


def _release(config) -> str:
    return (getattr(getattr(config, "distro", None), "release", None)
            or _DEFAULT_RELEASE)


def _severity_band(score) -> str:
    """Map a CVSS base score to a severity band. Unscored stays explicit."""
    if score is None:
        return "Unscored"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unscored"
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"


def _nvd_rank(nvd_con, cid: str) -> dict:
    """Read grounded CVSS score/severity/version for a real CVE id from the NVD
    index. Only ever called for a CVE the distro already confirmed open, so this
    reads a real record; it never invents one. Returns bare defaults if absent."""
    _empty = {"cvss": None, "cvss_severity": "", "cvss_version": "", "cwes": []}
    if nvd_con is None:
        return dict(_empty)
    try:
        row = nvd_con.execute(
            "SELECT cvss, cvss_severity, cvss_version, cwes FROM cve WHERE cve_id = ?",
            (cid,)).fetchone()
    except sqlite3.Error:
        return dict(_empty)
    if not row:
        return dict(_empty)
    cwes = []
    if row[3]:
        try:
            parsed = json.loads(row[3])
            if isinstance(parsed, list):
                cwes = [c for c in parsed if isinstance(c, str) and c.startswith("CWE-")]
        except (ValueError, TypeError):
            cwes = []
    return {"cvss": row[0], "cvss_severity": row[1] or "", "cvss_version": row[2] or "",
            "cwes": cwes}


def _cve_attrs(graph: Graph, cid: str) -> dict:
    """Pull enrichment (cvss/cwes/description) from an existing NVD node if present."""
    node = graph.get(cid)
    if node:
        return {"description": node.attrs.get("description", ""),
                "cvss": node.attrs.get("cvss"),
                "cwes": list(node.attrs.get("cwes", []))}
    return {"description": "", "cvss": None, "cwes": []}


def promote(graph, grains, distro_path, nvd_path, logger, extra_products=()) -> int:
    """Promote distro-confirmed-open CVEs for observed packages. Returns count.

    ``distro_path`` is the distro SQLite (data/distro/debian.sqlite) — the
    authoritative open/resolved status. ``nvd_path`` is the NVD index
    (data/nvd/index.sqlite) — CVSS score/severity/version enrichment, read-only,
    by CVE id. Skips cleanly (returns 0) if the distro index is absent, so the
    engine still runs on the base graph alone.
    """
    path = Path(distro_path)
    if not path.is_file():
        logger.info("promotion: no distro index at %s; base graph only", path)
        return 0
    _np = Path(nvd_path)
    nvd_con = sqlite3.connect("file:%s?mode=ro" % _np, uri=True) if _np.is_file() else None

    pkgs = observed_packages(grains)
    if not pkgs:
        logger.info("promotion: no inventory packages observed; nothing to promote")
        return 0

    release = _release(getattr(graph, "_config", None)) if hasattr(graph, "_config") else _DEFAULT_RELEASE

    scoped = _in_scope(pkgs.keys(), logger)  # in-scope package names, or None if no relevance pack
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    promoted, catalog_out, checked, skipped_patched = {}, {}, 0, 0
    try:
        for pkg, installed in pkgs.items():
            rows = con.execute(
                "SELECT cve_id, status, fixed_version, urgency FROM deb "
                "WHERE package = ? AND release = ?", (pkg, release)).fetchall()
            for cid, status, fixed, urgency in rows:
                checked += 1
                if not _CVE_RE.match(cid or ""):
                    continue  # grounding: promote only real CVE ids (skip TEMP-*)
                vulnerable = False
                if status == "open":
                    vulnerable = True
                elif status == "resolved" and fixed not in ("", "0", None):
                    # vulnerable only if the installed version is BELOW the fix
                    if installed and deb_compare(installed, fixed) < 0:
                        vulnerable = True
                    else:
                        skipped_patched += 1
                else:
                    skipped_patched += 1  # not-affected / no real fix version
                if vulnerable:
                    if scoped is not None and pkg not in scoped:
                        catalog_out.setdefault(cid, pkg)  # relevance: out-of-scope for the role -> catalogued, NOT promoted
                        continue
                    if (urgency or "").lower() in CATALOG_URGENCY:
                        tier = "catalog"
                    else:
                        _band = _severity_band(_nvd_rank(nvd_con, cid)["cvss"])
                        tier = "finding" if _band in ("Critical", "High") else "catalog"
                    promoted.setdefault(cid, {"package": pkg, "installed": installed,
                                              "fixed": fixed, "status": status,
                                              "urgency": urgency or "", "tier": tier})
    finally:
        con.close()

    count = 0
    try:
        for cid, meta in promoted.items():
            enr = _cve_attrs(graph, cid)
            rank = _nvd_rank(nvd_con, cid)
            score = rank["cvss"] if rank["cvss"] is not None else enr["cvss"]
            # CWE enrichment: the graph node (thin CVE seed) often has none; the
            # NVD index carries the real CWE for the same id. Prefer the node's,
            # fall back to NVD's -- reading data that already exists, never invented.
            cwes = enr["cwes"] or rank.get("cwes", [])
            enr["cwes"] = cwes
            band = _severity_band(score)
            graph.add_node(Node(id=cid, type="vulnerability", name=cid, framework="CVE",
                                attrs={"description": enr["description"], "cvss": score,
                                       "cwes": enr["cwes"],
                                       "affected": [{"product": meta["package"],
                                                     "version": meta["installed"],
                                                     "status": "affected"}],
                                       "distro": {"tracker": "debian", "release": release,
                                                  "status": meta["status"],
                                                  "fixed_version": meta["fixed"],
                                                  "installed_version": meta["installed"],
                                                  "urgency": meta["urgency"],
                                                  "tier": meta["tier"],
                                                  "cvss_score": score,
                                                  "cvss_version": rank["cvss_version"],
                                                  "cvss_severity": rank["cvss_severity"],
                                                  "severity_band": band},
                                       "source": "distro-promoted"}))
            for cwe in enr["cwes"]:
                graph.add_node(Node(id=cwe, type="weakness", name="", framework="CWE", attrs={}))
                graph.add_edge(Edge(cid, cwe, "instance_of", {}))
            count += 1
    finally:
        if nvd_con is not None:
            nvd_con.close()

    findings_n = sum(1 for m in promoted.values() if m["tier"] == "finding")
    catalog_n = count - findings_n
    logger.info("promotion: %d package(s), %d distro records -> %d in-scope CVE(s) promoted "
                "(%d findings / %d catalog[low|unimportant]) ; %d out-of-scope catalogued ; "
                "%d patched/not-affected dropped [debian/%s]", len(pkgs), checked, count,
                findings_n, catalog_n, len(catalog_out), skipped_patched, release)
    return count
