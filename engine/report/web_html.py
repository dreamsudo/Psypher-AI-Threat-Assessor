# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/report/web_html.py — the branded "Assessment Brief" web report.
#  Authored by PsypherLabs (WS-Report).
# =============================================================================
"""Render the assessment into the branded dark-navy "Assessment Brief" HTML.

A second, richer sibling of html.py (which is left untouched): the same
assessment dict, rendered in the PsypherLabs brief design — brandbar, the six
grounding bodies, an executive priority/verity panel, the phase pipeline, and
the two penetration-test surfaces (infrastructure and behavioral) as finding
cards. A pure function over the assessment dict — no model, no network, no
grains/evidence-log dependency, so it renders identically for any run.

DESIGN CONTRACT (do not regress):
  * Renderer CONSUMES, never computes. It reads the finding set and lays it out;
    it never re-grounds, re-judges, drops, or adds a finding. Classification of
    a finding (behavioral vs infrastructure, proved vs assumed, ordering) is
    IMPORTED from markdown.py so the two briefs cannot drift.
  * FAIL-SAFE on missing optional data. A finding with no KEV stamp, a technique
    with no mitigation, a CVE with no CWE — each renders cleanly (the relevant
    slot is omitted) rather than erroring or showing a blank. Real runs carry
    every combination of present/absent optional fields.
  * NO fabricated content. assessment.json does not carry the raw prompt/response
    transcript (that lives in grains.json by design), so the evidence block shows
    the graded rationale and the exchange_id REFERENCE — never invented dialogue.
  * Branding is verbatim: the H1, the grounding-guarantee, and the six-bodies
    foundations are locked product framing, reproduced exactly.
"""
from __future__ import annotations

from html import escape
from typing import Any

# Shared classification logic — imported, never duplicated, so this brief and
# the Markdown brief always agree on what is behavioral/proved and how findings
# are ordered. (Single source of truth: markdown.py.)
from .markdown import _is_behavioral, _is_proved, _sort_key, _model_under_test


def _esc(value: Any) -> str:
    return escape(str(value), quote=True)


# --- the mockup stylesheet, reproduced verbatim (psypher-report-mockup-v2) ----
_CSS = """
:root{
  --navy-900:#080d1a; --navy-850:#0b1122; --navy-800:#0f1830; --navy-780:#132039;
  --navy-700:#182747; --line:#213257; --line-soft:#182a4d;
  --white:#f5f9ff;
  --ink:#e9eff9; --ink-2:#c4d3ee; --ink-3:#8299c2;
  --green:#00e07a; --cyan:#2ad3f0; --violet:#b493ff; --rose:#ff4d75; --amber:#ffb833;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:
    radial-gradient(1100px 560px at 84% -10%, #12275230, transparent 60%),
    radial-gradient(820px 460px at -6% 6%, #0a3a3330, transparent 55%),
    var(--navy-900);
  color:var(--ink);font-family:var(--sans);line-height:1.52;
  -webkit-font-smoothing:antialiased;padding:26px 18px 60px}
.wrap{max-width:1020px;margin:0 auto}
.mono{font-family:var(--mono)}
h1,h2,h3,h4{color:var(--white)}
.brandbar{height:2px;border-radius:2px;margin-bottom:20px;
  background:linear-gradient(90deg,var(--green),var(--cyan) 42%,var(--violet) 74%,var(--rose))}
.head{border:1px solid var(--line);border-radius:16px;
  background:linear-gradient(180deg,#101c36,#0a1020);padding:26px 26px 22px;position:relative;overflow:hidden}
.head::after{content:"";position:absolute;right:-60px;top:-70px;width:280px;height:280px;
  background:radial-gradient(circle,#00e07a16,transparent 66%)}
.htop{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;flex-wrap:wrap;position:relative}
h1{margin:0;font-size:26px;letter-spacing:.2px;font-weight:750;line-height:1.15}
h1 .ai{color:var(--green)}
.thesisline{margin-top:8px;font-family:var(--mono);font-size:11px;letter-spacing:2.6px;text-transform:uppercase}
.thesisline b{color:var(--green)} .thesisline i{color:var(--cyan);font-style:normal} .thesisline u{color:var(--violet);text-decoration:none}
.hstatus{text-align:right;font-family:var(--mono);font-size:11px;color:var(--ink-3);padding-top:4px}
.hstatus .ok{color:var(--green);font-size:13px;display:block;margin-top:2px}
.facts{position:relative;display:grid;grid-template-columns:repeat(auto-fit,minmax(186px,1fr));gap:0 26px;margin-top:22px;
  border-top:1px solid var(--line-soft);padding-top:4px}
.fact{padding:9px 0;border-bottom:1px solid transparent}
.fact .k{font-size:9.5px;letter-spacing:1.5px;text-transform:uppercase;color:var(--ink-3)}
.fact .v{font-family:var(--mono);font-size:13px;color:var(--white);margin-top:3px;word-break:break-word}
.found{margin-top:16px;border:1px solid var(--line);border-radius:16px;background:var(--navy-800);padding:22px 24px}
.found .eb{display:flex;align-items:center;gap:11px;margin-bottom:10px}
.found .eb .bar{width:26px;height:2px;border-radius:2px;background:linear-gradient(90deg,var(--green),var(--cyan))}
.found .eb span{font-family:var(--mono);font-size:10.5px;letter-spacing:2.6px;color:var(--ink-3)}
.found h2{margin:0 0 10px;font-size:20px;font-weight:730}
.thesis{font-size:13.5px;color:var(--ink);margin:0 0 20px;max-width:84ch}
.thesis b{color:var(--white)} .thesis .g{color:var(--green)} .thesis .c{color:var(--cyan)} .thesis .v{color:var(--violet)}
.ds{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:11px}
.dcard{border:1px solid var(--line);border-radius:11px;background:var(--navy-780);padding:13px 15px}
.dcard .nm{display:flex;align-items:baseline;gap:8px}
.dcard .nm b{color:var(--white);font-size:14px;font-weight:680}
.dcard .nm .badge{font-family:var(--mono);font-size:9.5px;letter-spacing:1px;padding:2px 6px;border-radius:5px;
  border:1px solid var(--line);color:var(--ink-2);margin-left:auto}
.dcard .ct{color:var(--white);font-size:12px;margin-top:6px;font-weight:600}
.dcard .gr{color:var(--ink-2);font-size:11.5px;margin-top:4px;line-height:1.45}
.dcard.atlas .badge{color:var(--violet);border-color:#4a3a7a}
.dcard.attack .badge{color:var(--cyan);border-color:#1f5566}
.dcard.cve   .badge{color:var(--rose);border-color:#6b2440}
.dcard.kev   .badge{color:var(--amber);border-color:#6b4a12}
.dcard.d3f   .badge{color:var(--green);border-color:#12603c}
.exec{margin-top:16px;display:grid;grid-template-columns:1.12fr .88fr;gap:14px}
.panel{border:1px solid var(--line);border-radius:15px;background:var(--navy-800);padding:18px 20px}
.panel h3{margin:0 0 13px;font-size:10.5px;letter-spacing:1.8px;text-transform:uppercase;color:var(--ink-2);font-weight:700}
.prio{display:flex;gap:11px}
.prio .cell{border:1px solid var(--line);border-radius:12px;padding:13px 15px;background:var(--navy-780);flex:1}
.prio .now{background:linear-gradient(180deg,#320f22,#1c0b16);border-color:#6b1f3c;flex:1.35}
.prio .num{font-size:34px;font-weight:820;line-height:1;font-family:var(--mono);color:var(--white)}
.prio .now .num{color:var(--rose)}
.prio .lbl{font-size:10px;letter-spacing:1.4px;text-transform:uppercase;color:var(--ink-2);margin-top:6px;font-weight:700}
.prio .now .lbl{color:#ffc0d0}
.split2{display:flex;gap:10px;flex:1.2} .split2 .cell{flex:1} .split2 .num{font-size:23px}
.verity{display:flex;gap:10px;margin-top:11px}
.vpill{flex:1;border-radius:10px;padding:10px 13px;font-size:12px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.vpill.pv{border:1px solid #12603c;background:#0a1e17;color:#a8f5cf} .vpill.pv b{color:var(--green)}
.vpill.as{border:1px dashed #7a5410;background:#1c150a;color:#ffdfa0} .vpill.as b{color:var(--amber)}
.vpill b{font-family:var(--mono);font-size:15px}
.srf{display:flex;align-items:center;gap:11px;border:1px solid var(--line);border-radius:11px;padding:12px 14px;background:var(--navy-780);margin-bottom:9px}
.srf:last-child{margin-bottom:0}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.dot.infra{background:var(--cyan);box-shadow:0 0 10px #2ad3f099} .dot.behav{background:var(--violet);box-shadow:0 0 10px #b493ff99}
.srf .nm{font-weight:650;font-size:14px;color:var(--white)}
.srf .sub{display:block;color:var(--ink-3);font-size:11px;font-weight:400}
.srf .ct{margin-left:auto;font-family:var(--mono);font-size:16px;color:var(--white)}
.phases{margin-top:14px}
.flow{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.ph{display:flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:999px;padding:6px 12px 6px 9px;background:var(--navy-780);font-size:12.5px;color:var(--ink)}
.ph .ord{font-family:var(--mono);font-size:10px;color:var(--ink-3)}
.ph .tick{width:6px;height:6px;border-radius:50%;background:var(--green)}
.ph.det .tick{background:var(--cyan)} .ph.mdl .tick{background:var(--violet)}
.arw{color:var(--ink-3);font-family:var(--mono)}
.section-head{display:flex;align-items:flex-end;gap:18px;margin:38px 0 16px;padding-bottom:15px;
  border-bottom:1px solid var(--line)}
.section-head .accent{width:4px;align-self:stretch;min-height:56px;border-radius:3px}
.section-head.infra .accent{background:var(--cyan);box-shadow:0 0 18px #2ad3f04d}
.section-head.behav .accent{background:var(--violet);box-shadow:0 0 18px #b493ff4d}
.section-head .eyebrow{font-family:var(--mono);font-size:10.5px;letter-spacing:3px;margin-bottom:8px}
.section-head.infra .eyebrow{color:var(--cyan)} .section-head.behav .eyebrow{color:var(--violet)}
.section-head h2{margin:0;font-size:23px;font-weight:740;letter-spacing:.2px}
.section-head .sub{margin:7px 0 0;color:var(--ink-2);font-size:13px;max-width:78ch}
.section-head .count{margin-left:auto;text-align:right;align-self:center;font-family:var(--mono);white-space:nowrap}
.section-head .count b{font-size:27px;color:var(--white)}
.section-head .count span{display:block;font-size:9.5px;letter-spacing:1.6px;color:var(--ink-3);text-transform:uppercase;margin-top:2px}
.card{border:1px solid var(--line);border-left:3px solid var(--green);border-radius:14px;background:var(--navy-800);padding:17px 19px;margin-bottom:12px}
.card.assumed{border-left:3px dashed var(--amber)}
.card .top{display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap}
.sev{font-family:var(--mono);font-size:10.5px;font-weight:750;letter-spacing:.6px;padding:5px 9px;border-radius:6px;flex:none;margin-top:1px}
.sev.crit{background:#3a1020;color:#ff88a6;border:1px solid #6b1f3c}
.sev.high{background:#3a1d0c;color:#ffbe86;border:1px solid #6b421b}
.sev.med{background:#2e290f;color:#ffe89a;border:1px solid #675a1b}
.sev.low{background:#0f2233;color:#8ecbff;border:1px solid #1b4a67}
.sev.info{background:#1a2130;color:#9fb0c8;border:1px solid #2b3a52}
.sev.pass{background:#0a1e17;color:#8ff5c2;border:1px solid #12603c}
.ttl{font-size:16.5px;font-weight:700;margin:0;flex:1;min-width:230px;color:var(--white)}
.verdict{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:1px;padding:5px 10px;border-radius:6px;flex:none;margin-top:1px}
.verdict.comp{background:#3a1020;color:#ff88a6;border:1px solid #6b1f3c}
.verdict.part{background:#2e290f;color:#ffe89a;border:1px solid #675a1b}
.verdict.refu{background:#0a1e17;color:var(--green);border:1px solid #12603c}
.verdict.conf{background:#2e1108;color:#ffcf8e;border:1px solid #8a5412}
.stamp{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:1.2px;padding:5px 10px;border-radius:6px;flex:none;margin-top:1px}
.stamp.proved{background:#0a1e17;color:var(--green);border:1px solid #1a7d4f}
.stamp.assumed{background:#1c150a;color:var(--amber);border:1px dashed #8a6012}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin-top:9px}
.chip{font-family:var(--mono);font-size:11px;padding:3px 8px;border-radius:6px;border:1px solid var(--line);background:var(--navy-780);color:var(--ink-2)}
.chip.now{background:#3a1020;border-color:#8a2a4a;color:#ff9fb6;font-weight:700}
.chip.kev{background:#2e1108;border-color:#8a5412;color:#ffcf8e;font-weight:700}
.meta{display:flex;gap:16px;flex-wrap:wrap;margin:11px 0 0;font-family:var(--mono);font-size:12.5px;color:var(--white)}
.meta .lab{color:var(--ink-3);font-size:11px}
.say{margin:11px 0 0;font-size:13.5px;color:var(--ink)}
.ev{margin-top:12px;border:1px solid var(--line-soft);border-radius:9px;background:#070c18;padding:12px 14px;font-family:var(--mono);font-size:12px;color:var(--ink-2);overflow-x:auto;white-space:pre-wrap}
.ev .lab{color:var(--ink-3);font-size:9.5px;letter-spacing:1.5px;text-transform:uppercase;display:block;margin-bottom:7px}
.ev .hit{color:var(--rose);font-weight:700} .ev .ref{color:var(--green);font-weight:700}
.ad{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:13px}
.adcol{border:1px solid var(--line);border-radius:10px;padding:12px 13px;background:var(--navy-780)}
.adcol.atk{border-color:#5c1f38;background:#1c0e16}
.adcol.def{border-color:#12603c;background:#0a1a14}
.adh{font-family:var(--mono);font-size:11px;font-weight:800;letter-spacing:2.5px;margin-bottom:9px;display:flex;align-items:center;gap:8px}
.adh .sq{width:7px;height:7px;border-radius:2px;flex:none}
.adcol.atk .adh{color:var(--rose)} .adcol.atk .sq{background:var(--rose)}
.adcol.def .adh{color:var(--green)} .adcol.def .sq{background:var(--green)}
.adcol .chip{display:block;margin-bottom:6px}
.adcol .chip:last-child{margin-bottom:0}
.adcol.atk .chip{border-color:#5c1f38;color:#ff9fb6;background:#26101a}
.adcol.def .chip{border-color:#1a7d4f;color:#8ff5c2;background:#0c211a}
.adcol .none{color:var(--amber);border-color:#675a1b;background:#1c150a}
.prov{margin-top:13px;padding-top:11px;border-top:1px solid var(--line-soft);font-family:var(--mono);font-size:11px;color:var(--ink-3);display:flex;gap:14px;flex-wrap:wrap}
.prov .g{color:var(--green)}
@media(max-width:760px){.exec,.ad{grid-template-columns:1fr}}
.foot{margin-top:34px;border:1px solid var(--line);border-radius:16px;background:var(--navy-850);padding:20px 22px}
.foot .gg{font-size:13.5px;color:var(--ink);margin:0 0 14px}
.foot .gg b{color:var(--green)}
.foot .fgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:0 26px}
.sign{margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft);text-align:center;font-size:12px;color:var(--ink-3);letter-spacing:.4px}
.sign b{color:var(--ink-2)}
"""

# --- severity / verdict CSS-class maps ---------------------------------------
_SEV_CLASS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}
_VERDICT_CLASS = {"complied": "comp", "partial": "part", "refused": "refu", "confabulated": "conf"}
_PRIORITY_BUCKET = {"act-now": "now", "high": "high", "scheduled": "scheduled"}


def _priority_of(finding: dict[str, Any]) -> str:
    """The remediation bucket for the exec panel. CVE findings carry an explicit
    evidence.priority (Phase-2 KEV stamp: act-now/high/scheduled). Behavioral and
    posture findings do not, so bucket them by severity the way a reader triages —
    critical/high -> high, else scheduled. Ranking for display only; never alters
    a finding."""
    ev = finding.get("evidence") or {}
    p = ev.get("priority")
    if p in _PRIORITY_BUCKET:
        return p
    return "high" if finding.get("severity") in ("critical", "high") else "scheduled"


# --- small card helpers (all fail-safe on absent optional data) --------------
def _chip(text: str, cls: str = "") -> str:
    c = f"chip {cls}".strip()
    return f'<span class="{c}">{_esc(text)}</span>'


def _attack_chips(finding: dict[str, Any]) -> str:
    """ATTACK column: the techniques (and, for a CVE, the CVE id itself)."""
    out = []
    for v in finding.get("vulnerabilities") or []:
        if v.get("cve"):
            label = f"{v.get('cve')}"
            if v.get("cwe"):
                label += f" · {v.get('cwe')}"
            out.append(_chip(label))
    for t in finding.get("techniques") or []:
        name = f" · {t.get('name')}" if t.get("name") else ""
        out.append(_chip(f"{t.get('framework','')} {t.get('id','')}{name}".strip()))
    return "".join(out) or _chip("no technique mapped", "none")


def _defense_chips(finding: dict[str, Any]) -> str:
    """DEFENSE column: the graph-grounded mitigations, framework-labeled. Fail-safe
    to the mockup's 'none' chip when a technique has no mapped countermeasure."""
    mits = finding.get("mitigations") or []
    if not mits:
        return _chip("No countermeasure mapped", "none")
    out = []
    for m in mits:
        text = f" · {m.get('text')}" if m.get("text") else ""
        out.append(_chip(f"{m.get('framework','')} {m.get('id','')}{text}".strip()))
    return "".join(out)


def _kev_chips(finding: dict[str, Any]) -> str:
    """The act-now / CISA-KEV chips — shown ONLY when the finding is KEV-flagged.
    Absent evidence.exploited -> no chips (fail-safe)."""
    ev = finding.get("evidence") or {}
    if ev.get("exploited") is not True:
        return ""
    rw = " · ransomware-linked" if ev.get("kev_ransomware") else ""
    added = f" (added {ev.get('kev_date_added')})" if ev.get("kev_date_added") else ""
    return (f'<div class="chips"><span class="chip now">\u2691 ACT NOW</span>'
            f'<span class="chip kev">CISA KEV \u00b7 exploited in the wild{_esc(added)}{_esc(rw)}</span></div>')


def _cve_meta(finding: dict[str, Any]) -> str:
    """The CVE/CVSS/CWE/component meta row for an infrastructure finding."""
    v = (finding.get("vulnerabilities") or [{}])[0]
    ev = finding.get("evidence") or {}
    cwe = v.get("cwe") or ev.get("cwe") or ""
    cvss = v.get("cvss")
    cvss_text = f"{cvss}" if cvss is not None else "not scored"
    bits = []
    if v.get("cve"):
        bits.append(f'<span><span class="lab">CVE</span> {_esc(v.get("cve"))}</span>')
    bits.append(f'<span><span class="lab">CVSS</span> {_esc(cvss_text)}</span>')
    if cwe:
        bits.append(f'<span><span class="lab">CWE</span> {_esc(cwe)}</span>')
    ver = ev.get("observed_version")
    comp = f'{finding.get("component","")}' + (f' {ver}' if ver else "")
    bits.append(f'<span><span class="lab">Component</span> {_esc(comp)}</span>')
    if finding.get("confidence"):
        bits.append(f'<span><span class="lab">Confidence</span> {_esc(finding.get("confidence"))}</span>')
    if ev.get("match"):
        bits.append(f'<span><span class="lab">Match</span> {_esc(ev.get("match"))}</span>')
    return '<div class="meta">' + "".join(bits) + "</div>"


def _technique_meta(finding: dict[str, Any]) -> str:
    """The ATLAS/tactic/grade meta row for a behavioral or posture finding."""
    ev = finding.get("evidence") or {}
    bits = []
    for t in finding.get("techniques") or []:
        fw = t.get("framework", "")
        name = f" · {t.get('name')}" if t.get("name") else ""
        bits.append(f'<span><span class="lab">{_esc(fw)}</span> {_esc(t.get("id",""))}{_esc(name)}</span>')
        break  # one technique anchors the card
    if ev.get("cwe"):
        bits.append(f'<span><span class="lab">Weakness</span> {_esc(ev.get("cwe"))}</span>')
    if ev.get("grade"):
        bits.append(f'<span><span class="lab">Grade</span> {_esc(ev.get("grade"))}</span>')
    if ev.get("access_tier"):
        bits.append(f'<span><span class="lab">Access</span> {_esc(ev.get("access_tier"))}</span>')
    if ev.get("method"):
        bits.append(f'<span><span class="lab">Method</span> {_esc(ev.get("method"))}</span>')
    if finding.get("confidence"):
        bits.append(f'<span><span class="lab">Confidence</span> {_esc(finding.get("confidence"))}</span>')
    return '<div class="meta">' + "".join(bits) + "</div>"


def _evidence_block(finding: dict[str, Any]) -> str:
    """The proof block. Shows the graded rationale (behavioral/posture) or the
    observed-version proof (CVE), plus the exchange_id/grain REFERENCE. Never a
    fabricated prompt/response transcript — assessment.json does not carry it."""
    ev = finding.get("evidence") or {}
    v = (finding.get("vulnerabilities") or [{}])[0]
    label, body = "", ""
    if v.get("cve"):
        ver = ev.get("observed_version", "")
        vc = "version-confirmed" if ev.get("version_confirmed") else str(ev.get("match", ""))
        label = "Proof \u00b7 observed version"
        body = f'{_esc(v.get("confirmed_by") or "package check")} \u2192 <span class="ref">{_esc(ver)}</span>   ({_esc(vc)})'
    elif ev.get("rationale"):
        label = "Judge rationale"
        body = _esc(ev.get("rationale"))
    else:
        return ""
    ref_bits = []
    if ev.get("exchange_id"):
        ref_bits.append(f'exchange {_esc(ev.get("exchange_id"))}')
    grains = ev.get("supporting_grains")
    if isinstance(grains, list) and grains:
        ref_bits.append(f'grain {_esc(grains[0])}')
    ref = ("\n<span class=\"ref\">" + " \u00b7 ".join(ref_bits) + "</span>") if ref_bits else ""
    return f'<div class="ev"><span class="lab">{label}</span>{body}{ref}</div>'


def _prov_line(finding: dict[str, Any]) -> str:
    ev = finding.get("evidence") or {}
    bits = [f'<span>{_esc(finding.get("id",""))}</span>']
    if ev.get("target_model"):
        bits.append(f'<span>model {_esc(ev.get("target_model"))}</span>')
    if ev.get("method"):
        bits.append(f'<span>{_esc(ev.get("method"))}</span>')
    if ev.get("exchange_id"):
        bits.append(f'<span>exchange #{_esc(str(ev.get("exchange_id"))[:8])}</span>')
    bits.append(f'<span class="g">grounded \u2713</span>')
    return '<div class="prov">' + "".join(bits) + "</div>"


def _finding_card(finding: dict[str, Any]) -> str:
    """One finding rendered in the brief-card design. Behavioral findings carry a
    verdict chip; infrastructure findings carry a CVE meta row and KEV chips."""
    sev = finding.get("severity", "info")
    sev_cls = _SEV_CLASS.get(sev, "info")
    proved = _is_proved(finding)
    behavioral = _is_behavioral(finding)
    ev = finding.get("evidence") or {}

    card_cls = "card" if proved else "card assumed"
    stamp = ('<span class="stamp proved">\u2714 PROVED</span>' if proved
             else '<span class="stamp assumed">\u25c7 ASSUMED \u00b7 VERIFY</span>')

    # verdict chip (behavioral only)
    verdict_html = ""
    if behavioral and ev.get("verdict"):
        vcls = _VERDICT_CLASS.get(ev.get("verdict"), "part")
        verdict_html = f'<span class="verdict {vcls}">{_esc(str(ev.get("verdict")).upper())}</span>'

    kev = _kev_chips(finding)
    meta = _cve_meta(finding) if finding.get("vulnerabilities") else _technique_meta(finding)
    say = f'<p class="say">{_esc(finding.get("attack_path",""))}</p>' if finding.get("attack_path") else ""
    evb = _evidence_block(finding)

    return f"""
  <article class="{card_cls}">
    <div class="top">
      <span class="sev {sev_cls}">{_esc(str(sev).upper())}</span>
      <h4 class="ttl">{_esc(finding.get('title',''))}</h4>
      {verdict_html}
      {stamp}
    </div>
    {kev}
    {meta}
    {say}
    {evb}
    <div class="ad">
      <div class="adcol atk"><div class="adh"><span class="sq"></span>ATTACK</div>{_attack_chips(finding)}</div>
      <div class="adcol def"><div class="adh"><span class="sq"></span>DEFENSE</div>{_defense_chips(finding)}</div>
    </div>
    {_prov_line(finding)}
  </article>"""


# --- the static, verbatim framing (locked branding — reproduced from mockup) --
_FOUNDATIONS = """
  <section class="found">
    <div class="eb"><span class="bar"></span><span>WHAT THIS IS GROUNDED IN</span></div>
    <h2>One assessment, six authoritative bodies of knowledge</h2>
    <p class="thesis"><b>Psypher is deterministic by construction.</b> Claude does the judgment a scanner can't — which probe to run, which CVE truly applies, whether a model response is a real compliance or a convincing fake — but at <span class="g">four firewalled decision points</span> it can only choose identifiers that already exist in the assembled knowledge graph; it can never invent one. Every result is expressed in a <span class="c">standard MITRE identifier</span>, so an assessment is reproducible, auditable, and directly comparable <span class="v">across targets and across teams</span>. AI-judged, evidence-grounded, framework-standardized — one common language for the security of the model and the stack it runs on.</p>
    <div class="ds">
      <div class="dcard atlas"><div class="nm"><b>MITRE ATLAS</b><span class="badge">AML.T / AML.M</span></div><div class="ct">Adversarial threat landscape for AI systems</div><div class="gr">Grounds the behavioral surface — every adversarial prompt maps to a real ATLAS technique, every named model defense to a real ATLAS mitigation.</div></div>
      <div class="dcard attack"><div class="nm"><b>MITRE ATT&amp;CK</b><span class="badge">ENT+ICS+MOB</span></div><div class="ct">Adversary tactics &amp; techniques for the stack</div><div class="gr">Grounds the infrastructure surface — exploitation techniques and their mitigations, across Enterprise, ICS and Mobile.</div></div>
      <div class="dcard"><div class="nm"><b>MITRE CWE</b><span class="badge">v4.20</span></div><div class="ct">Common weakness enumeration</div><div class="gr">The weakness class behind every vulnerability — deserialization, protection-mechanism failure, and the rest — carried on each finding.</div></div>
      <div class="dcard cve"><div class="nm"><b>CVE</b><span class="badge">SEED + NVD + DEBIAN</span></div><div class="ct">Real, published vulnerabilities</div><div class="gr">A curated seed, the full NVD feed as the CVSS authority, and the Debian security tracker as the open/fixed/backport authority.</div></div>
      <div class="dcard kev"><div class="nm"><b>CISA KEV</b><span class="badge">KNOWN EXPLOITED</span></div><div class="ct">Known Exploited Vulnerabilities catalog</div><div class="gr">CISA's list of CVEs confirmed exploited in the wild — the signal that lifts a finding to <b style="color:var(--rose)">act now</b>, above raw CVSS.</div></div>
      <div class="dcard d3f"><div class="nm"><b>MITRE D3FEND</b><span class="badge">COUNTERMEASURES</span></div><div class="ct">Defensive countermeasure ontology</div><div class="gr">Names the D3FEND technique that counters each infrastructure attack — so every attack in this report is paired with a real defense.</div></div>
    </div>
  </section>"""

_PIPELINE = """
  <section class="panel phases">
    <h3>What the system did &nbsp;·&nbsp; pipeline</h3>
    <div class="flow">
      <span class="ph"><span class="tick"></span><span class="ord">10</span>discovery</span><span class="arw">&rarr;</span>
      <span class="ph"><span class="tick"></span><span class="ord">20</span>graph</span><span class="arw">&rarr;</span>
      <span class="ph det"><span class="tick"></span><span class="ord">30</span>analysis &middot; CVE</span><span class="arw">&rarr;</span>
      <span class="ph mdl"><span class="tick"></span><span class="ord">35</span>brain &middot; behavioral</span><span class="arw">&rarr;</span>
      <span class="ph det"><span class="tick"></span><span class="ord">37</span>posture</span><span class="arw">&rarr;</span>
      <span class="ph"><span class="tick"></span><span class="ord">38</span>defense</span><span class="arw">&rarr;</span>
      <span class="ph"><span class="tick"></span><span class="ord">40</span>report</span>
    </div>
  </section>"""


# --- superset sections: kill chain, components, observed-evidence (grains) ----
# html.py renders all three; the web brief must contain everything html.py does.
_KC_CSS_NOTE = ""  # styling reuses .panel / .meta / table-ish rows


def _kill_chain_section(assessment) -> str:
    """The Attack path (kill chain) — html.py renders this section (with an empty
    state when there are none). Reproduced so the web brief is a strict superset."""
    chains = assessment.get("kill_chains") or []
    steps = [(c, s) for c in chains for s in (c.get("steps") or [])]
    rows = ""
    for _c, s in steps:
        mit = s.get("mitigated_by", "") or "-"
        rows += (f'<div class="prov" style="border-top:none;padding-top:4px">'
                 f'<span class="g">{_esc(s.get("order",""))}</span>'
                 f'<span>{_esc(s.get("note",""))}</span>'
                 f'<span class="mono">{_esc(s.get("ref",""))}</span>'
                 f'<span>{_esc(s.get("framework",""))}</span>'
                 f'<span>mitigated_by {_esc(mit)}</span></div>')
    body = rows or '<p class="say">No multi-step attack path was assembled.</p>'
    return (f'<section class="panel" style="margin-top:14px">'
            f'<h3>Attack path &nbsp;·&nbsp; kill chain</h3>{body}</section>')


def _components_line(assessment) -> str:
    """The observed components list — html.py shows 'Components: {list}'."""
    comps = assessment.get("components") or []
    names = ", ".join(_esc(c.get("id", "")) for c in comps if c.get("id")) or "none"
    return (f'<section class="panel" style="margin-top:14px">'
            f'<h3>Observed components</h3><p class="say mono">{names}</p></section>')



def render_web_html(assessment: dict[str, Any], operator: str, tool_name: str) -> str:
    """Render the assessment to the branded Assessment Brief HTML string."""
    case = assessment.get("case") or {}
    prov = assessment.get("provenance") or {}
    summary = assessment.get("summary") or {}
    findings = assessment.get("findings") or []

    # classification via the shared helpers (single source of truth)
    behavioral = [f for f in findings if _is_behavioral(f)]
    infra = [f for f in findings if not _is_behavioral(f)]
    infra.sort(key=_sort_key)
    behavioral.sort(key=_sort_key)

    proved_n = sum(1 for f in findings if _is_proved(f))
    assumed_n = len(findings) - proved_n
    buckets = {"now": 0, "high": 0, "scheduled": 0}
    for f in findings:
        buckets[_PRIORITY_BUCKET[_priority_of(f)]] += 1

    model = _model_under_test(findings)
    access = next((( f.get("evidence") or {}).get("access_tier") for f in findings
                   if (f.get("evidence") or {}).get("access_tier")), "n/a")
    src = prov.get("source_versions") or {}
    src_line = ", ".join(f"{k} {v}" for k, v in sorted(src.items())) or "n/a"

    # facts grid
    facts = [
        ("Case", case.get("id", "")),
        ("Target", case.get("target_name", "")),
        ("Model under test", model),
        ("Assessed (UTC)", case.get("created", prov.get("created", ""))),
        ("Engine", f"v{case.get('tool_version', prov.get('tool_version',''))}"),
        ("Graph hash", prov.get("graph_hash", "")),
        ("Operator", operator),
        ("Access tier", access),
    ]
    facts_html = "".join(
        f'<div class="fact"><div class="k">{_esc(k)}</div><div class="v">{_esc(v)}</div></div>'
        for k, v in facts
    )

    infra_cards = "".join(_finding_card(f) for f in infra) or \
        '<article class="card"><p class="say">No infrastructure findings — the observed serving stack matched no known-vulnerable version.</p></article>'
    behav_cards = "".join(_finding_card(f) for f in behavioral) or \
        '<article class="card"><p class="say">No behavioral findings — the model resisted every judged attack.</p></article>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Psypher — Assessment Brief · {_esc(case.get('id',''))}</title>
<style>{_CSS}</style></head>
<body>
<div class="wrap">
  <div class="brandbar"></div>
  <header class="head">
    <div class="htop">
      <div>
        <h1>Psypher <span class="ai">AI</span> Threat Assessment Brief</h1>
        <div class="thesisline"><b>Deterministic</b> &middot; <i>AI-judged</i> &middot; <u>MITRE-standardized</u></div>
      </div>
      <div class="hstatus">Findings<span class="ok">{_esc(summary.get('findings_total', len(findings)))} total</span></div>
    </div>
    <div class="facts">{facts_html}</div>
  </header>
{_FOUNDATIONS}
  <section class="exec">
    <div class="panel">
      <h3>Priority</h3>
      <div class="prio">
        <div class="now cell"><div class="num">{buckets['now']}</div><div class="lbl">Act now</div></div>
        <div class="split2">
          <div class="cell"><div class="num">{buckets['high']}</div><div class="lbl">High</div></div>
          <div class="cell"><div class="num">{buckets['scheduled']}</div><div class="lbl">Scheduled</div></div>
        </div>
      </div>
      <div class="verity">
        <div class="vpill pv">Proved <b>{proved_n}</b></div>
        <div class="vpill as">Assumed <b>{assumed_n}</b></div>
      </div>
    </div>
    <div class="panel">
      <h3>Surfaces tested</h3>
      <div class="srf"><span class="dot infra"></span><span class="nm">Infrastructure<span class="sub">the serving stack — CVE / CWE / host</span></span><span class="ct">{len(infra)}</span></div>
      <div class="srf"><span class="dot behav"></span><span class="nm">Behavioral<span class="sub">the live model — MITRE ATLAS</span></span><span class="ct">{len(behavioral)}</span></div>
    </div>
  </section>
{_PIPELINE}
  <div class="section-head infra">
    <div class="accent"></div>
    <div>
      <div class="eyebrow">INFRASTRUCTURE PENETRATION TEST</div>
      <h2>Vulnerabilities in the serving stack</h2>
      <p class="sub">Known flaws in the software running the model — matched to real CVE/CWE records, reported only on a confirmed match, each paired with its graph-grounded countermeasure.</p>
    </div>
    <div class="count"><b>{len(infra)}</b><span>findings</span></div>
  </div>
  {infra_cards}
  <div class="section-head behav">
    <div class="accent"></div>
    <div>
      <div class="eyebrow">BEHAVIORAL PENETRATION TEST</div>
      <h2>Adversarial resistance of the live model</h2>
      <p class="sub">How the model responds to adversarial input — each attack tagged to a real MITRE ATLAS technique, each response reasoning-judged, every verdict anchored to the captured exchange that proves it.</p>
    </div>
    <div class="count"><b>{len(behavioral)}</b><span>findings</span></div>
  </div>
  {behav_cards}
{_kill_chain_section(assessment)}
{_components_line(assessment)}
  <footer class="foot">
    <p class="gg"><b>Grounding guarantee.</b> Every CVE, CWE, technique and countermeasure in this report resolves to a node in the assembled knowledge graph. If it isn't in the graph, it isn't in this report — nothing is inferred from the model's memory.</p>
    <div class="fgrid">
      <div class="fact"><div class="k">Frameworks</div><div class="v">{_esc(', '.join(summary.get('frameworks', [])) or 'n/a')}</div></div>
      <div class="fact"><div class="k">Graph sources</div><div class="v">{_esc(src_line)}</div></div>
      <div class="fact"><div class="k">Graph hash</div><div class="v">{_esc(prov.get('graph_hash',''))}</div></div>
      <div class="fact"><div class="k">Assessed (UTC)</div><div class="v">{_esc(case.get('created',''))}</div></div>
      <div class="fact"><div class="k">Probes executed</div><div class="v">{_esc(len(prov.get('probe_log', [])))}</div></div>
    </div>
    <div class="sign"><b>Powered by Claude &middot; Designed by PsypherLabs</b></div>
  </footer>
</div>
</body></html>"""
