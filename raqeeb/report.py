"""Investigation reports for a case or a server, as one self-contained HTML file."""
from __future__ import annotations

import html
import unicodedata
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from raqeeb import cases, clock, evidence, inventory, listings, register, seals, team
from raqeeb.models import Asset, Case, User

SEVERITIES = ("Critical", "High", "Medium", "Low")
VERDICTS = {"match": "Matches a published release", "subset": "Part of a published release",
            "deviation": "Differs from the published release", "unknown": "Package not in the reference library"}
CLOSURES = {"fixed": "True positive, fixed at source", "mitigated": "True positive, mitigated",
            "benign_positive": "Benign positive, expected behaviour", "false_positive": "False positive",
            "risk_accepted": "Risk accepted", "duplicate": "Duplicate",
            "inconclusive": "Undetermined, not enough evidence", "out_of_scope": "Out of scope", "other": "Other"}

STYLE = """
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.6 "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; color: #14202e; background: #eef2f6; }
main { max-width: 980px; margin: 32px auto; background: #fff; padding: 48px 56px; border-radius: 10px; box-shadow: 0 2px 18px rgba(10,22,40,.08); }
header { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; border-bottom: 3px solid #0e1726; padding-bottom: 20px; }
.brand { font-weight: 700; letter-spacing: .08em; color: #0b8f73; font-size: 13px; }
h1 { font-size: 26px; margin: 6px 0 4px; }
h2 { font-size: 17px; margin: 34px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #d8dee6; }
h3 { font-size: 15px; margin: 22px 0 8px; }
.muted { color: #5b6878; }
.mono, code { font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 12.5px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
th, td { text-align: left; vertical-align: top; padding: 7px 10px; border-bottom: 1px solid #e3e8ee; }
th { background: #f4f7fa; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #4a5768; }
table.meta th { width: 190px; text-transform: none; letter-spacing: 0; font-size: 13px; }
.sev { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: #fff; }
.Critical { background: #c0392b; } .High { background: #d9761c; } .Medium { background: #b8950c; } .Low { background: #6c7a89; }
.verdict-deviation { color: #c0392b; font-weight: 700; } .verdict-match { color: #0b8f73; font-weight: 700; }
.summary { background: #f4f7fa; border-left: 4px solid #0b8f73; padding: 14px 18px; border-radius: 4px; }
.finding { border: 1px solid #e3e8ee; border-radius: 6px; padding: 14px 18px; margin: 12px 0; page-break-inside: avoid; }
.finding p { margin: 6px 0; }
.compare { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.compare div { background: #f7f9fb; border: 1px solid #e3e8ee; border-radius: 6px; padding: 10px 12px; white-space: pre-wrap; word-break: break-word; }
.hidden { background: #fadbd8; color: #c0392b; border-radius: 3px; padding: 0 3px; }
.added { background: #fdebd0; }
footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid #d8dee6; font-size: 12px; color: #5b6878; }
.print { position: fixed; top: 16px; right: 16px; padding: 8px 16px; border: 0; border-radius: 6px; background: #0b8f73; color: #fff; font-weight: 600; cursor: pointer; }
@media print { body { background: #fff; } main { box-shadow: none; margin: 0; padding: 0; max-width: none; } .print { display: none; } h2 { page-break-after: avoid; } }
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value))


def _visible(text: str) -> str:
    out = []
    for char in text or "":
        if unicodedata.category(char) in ("Cf", "Cc") and char not in "\n\t":
            out.append(f'<span class="hidden">[U+{ord(char):04X}]</span>')
        else:
            out.append(_e(char))
    return "".join(out)


def _observed(published: str, observed: str) -> str:
    published, observed = published or "", observed or ""
    if observed.startswith(published) and len(observed) > len(published):
        return _visible(published) + f'<span class="added">{_visible(observed[len(published):])}</span>'
    return _visible(observed)


def _sev(level) -> str:
    return f'<span class="sev {_e(level)}">{_e(level)}</span>' if level else "—"


def _rows(pairs) -> str:
    return "".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in pairs)


def _summary_of(page: dict, case: dict | None) -> str:
    scan = page.get("read_scan")
    if not scan:
        return f"{_e(page['label'])} has not answered a scan with its tool list yet, so there is nothing to assess."
    verdict = (page.get("provenance") or {}).get("verdict") or "unknown"
    counts = Counter(f["severity"] for f in page["findings"])
    mix = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]) or "none"
    text = [f"The server at <code>{_e(page['endpoint'])}</code> answered the MCP handshake and declared "
            f"{len(page['tools'])} tools on scan <code>{_e(scan['reference'])}</code> ({_e(clock.shown(scan['started_at']))}).",
            f"Against the reference library the result is <b>{_e(VERDICTS.get(verdict, verdict))}</b>"
            + (f" (<code>{_e(scan['release'])}</code>)." if scan.get("release") else ".")]
    redefined = (page.get("provenance") or {}).get("redefined") or []
    if redefined:
        text.append(f"Redefined against the release: {', '.join(f'<code>{_e(n)}</code>' for n in redefined)}.")
    text.append(f"Open findings: {len(page['findings'])} ({mix}). "
                f"Authentication: {'required' if page.get('auth_required') else 'not requested'}.")
    if case:
        opener = "Raqeeb opened this case automatically" if case["automatic"] else f"{_e(case['opened_by'])} opened this case"
        text.insert(0, f"{opener} on {_e(clock.shown(case['opened_at']))}: {_e(case['reason'])}")
        if case["status"] == cases.CLOSED:
            text.append(f"Closed by {_e(case['closed_by'])} as {_e(CLOSURES.get(case['closure_reason'], case['closure_reason']))}: "
                        f"{_e(case['closure_note'])}")
    return " ".join(text)


def _differences(page: dict) -> str:
    provenance = page.get("provenance") or {}
    rows = [tool for tool in page["tools"] if tool["status"] in ("redefined", "added")]
    if not rows:
        return "<p>No declared tool differs from the published release.</p>" if provenance.get("verdict") in ("match", "subset") \
            else "<p>No release comparison is available for this server.</p>"
    parts = []
    for tool in rows:
        parts.append(f"<h3><code>{_e(tool['name'])}</code> · {_e(tool['status'])}</h3>")
        for diff in tool["differences"]:
            parts.append(f'<p class="muted">Field: {_e(diff["field"])}</p><div class="compare">'
                         f'<div><b>Published</b><br>{_visible(diff.get("published") or "")}</div>'
                         f'<div><b>Observed</b><br>{_observed(diff.get("published") or "", diff.get("observed") or "")}</div></div>')
        if tool["status"] == "added":
            parts.append(f'<div class="compare"><div><b>Observed</b><br>{_visible(tool["description"])}</div></div>')
    absent = provenance.get("absent") or []
    if absent:
        parts.append(f"<p>In the release but not declared: {', '.join(f'<code>{_e(n)}</code>' for n in absent)}.</p>")
    return "".join(parts)


def _findings(findings: list) -> str:
    if not findings:
        return "<p>No findings.</p>"
    table = ("<table><tr><th>Reference</th><th>Severity</th><th>Finding</th><th>Tool</th><th>Evidence</th>"
             "<th>OWASP MCP</th><th>MITRE</th><th>Status</th></tr>"
             + "".join(f"<tr><td class=mono>{_e(f['reference'])}</td><td>{_sev(f['severity'])}</td><td>{_e(f['title'])}</td>"
                       f"<td class=mono>{_e(f['tool'] or '—')}</td><td class=mono>{_e(f['evidence_level'])}</td>"
                       f"<td class=mono>{_e(f.get('owasp_mcp') or '—')}</td><td class=mono>{_e(f.get('technique_id') or '—')}</td>"
                       f"<td>{_e(f['status'].replace('_', ' '))}</td></tr>" for f in findings)
             + "</table>")
    detail = "".join(
        f'<div class="finding"><b>{_e(f["reference"])} · {_e(f["title"])}</b> {_sev(f["severity"])}'
        + "".join(f"<p>{_visible(fact)}</p>" for fact in f["observed_facts"])
        + (f'<p class="muted"><b>Inference:</b> {_e(f["inference"])}</p>' if f.get("inference") else "")
        + (f'<p><b>Recommendation:</b> {_e(f["recommendation"])}</p>' if f.get("recommendation") else "")
        + f'<p class="muted mono">First seen {_e(clock.shown(f["first_seen_at"]))} on {_e(f["first_scan"])} · '
          f'last seen {_e(clock.shown(f["last_seen_at"]))} on {_e(f["last_scan"])}</p></div>'
        for f in findings)
    return table + detail


def _scans(scans: list) -> str:
    return ("<table><tr><th>Scan</th><th>When</th><th>By</th><th>Outcome</th><th>Verdict</th><th>Tools</th><th>Declarations</th></tr>"
            + "".join(f"<tr><td class=mono>{_e(s['reference'])}</td><td>{_e(clock.shown(s['started_at']))}</td>"
                      f"<td>{_e(s['operator'])} ({_e(s['trigger'])})</td><td>{_e(s['outcome'].replace('_', ' '))}</td>"
                      f"<td>{_e(s['verdict'] or '—')}</td><td>{_e(s['tool_count'] if s['tool_count'] is not None else '—')}</td>"
                      f"<td class=mono>{_e((s['declarations'] or '—')[:16])}</td></tr>" for s in scans)
            + "</table>")


def _integrity(db: Session, page: dict) -> str:
    key = evidence.issuer()
    chain = seals.check(db)
    scan = page.get("read_scan")
    return ("<table class=meta>" + _rows([
        ("Signing key", f"<code>{_e(key['key_id'])}</code> ({_e(key['algorithm'])})"),
        ("Declarations digest", f"<code>{_e(scan['declarations'])}</code> (SHA-256)" if scan else "—"),
        ("Signed evidence", f"Download for <code>{_e(scan['reference'])}</code> from the server page, then run "
                            f"<code>python3 -m raqeeb.evidence verify &lt;file&gt; --key {_e(key['key_id'])}</code>" if scan else "—"),
        ("Audit chain", f"{'Intact' if chain['intact'] else 'Broken'}, {chain['sealed']} sealed entries"),
    ]) + "</table>")


METHOD = ("<p>Raqeeb sent the MCP handshake and asked for the tool list. It called no tool and sent no credential. "
          "Declarations were compared with the published releases in the reference library, analysed for "
          "instructions aimed at the agent, and compared with the previous scan of the same server.</p>")
LIMITS = ("<p>Findings describe declarations, not what a tool does when called. A server whose package is not in the "
          "reference library cannot be compared with a release. Change monitoring starts at the first scan.</p>")


def _document(title: str, subtitle: str, meta: str, body: str, by: str) -> str:
    stamp = clock.now()
    return (f"<!DOCTYPE html><html lang=en><head><meta charset=utf-8><title>{_e(title)}</title>"
            f"<style>{STYLE}</style></head><body>"
            f'<button class="print" onclick="window.print()">Print or save as PDF</button><main>'
            f'<header><div><div class="brand">RAQEEB · INVESTIGATION REPORT</div><h1>{_e(title)}</h1>'
            f'<div class="muted">{subtitle}</div></div><div class="muted mono" style="text-align:right">'
            f'Generated {_e(stamp)}<br>by {_e(by)}</div></header>{meta}{body}'
            f"<footer>Generated by Raqeeb from stored scan records. Times are in {_e(clock.now().rsplit(' ', 1)[-1])}.</footer></main></body></html>")


def for_case(db: Session, user: User, case: Case, asset: Asset) -> str:
    item = cases.case_dict(db, case, asset, full=True)
    page = inventory.detail(db, user, asset)
    linked = {f["reference"] for f in item["findings"]}
    meta = "<table class=meta>" + _rows([
        ("Case", f"<code>{_e(item['reference'])}</code>"),
        ("Server", f"{_e(item['asset'])} · <code>{_e(item['endpoint'])}</code>"),
        ("Severity", _sev(item["severity"])),
        ("Status", _e(item["status"].capitalize())),
        ("Opened", f"{_e(clock.shown(item['opened_at']))} by {'Raqeeb' if item['automatic'] else _e(item['opened_by'])}"),
        ("Rule", _e(item["rule_text"] or "Opened by hand")),
        ("Owner", _e(item["owner_name"] or item["owner"] or "Unassigned")),
        ("Authorization", _e(listings.basis(db, asset)["text"])),
        ("Scans", f"Opened on <code>{_e(item['scan'])}</code>, last checked on <code>{_e(item['last_scan'])}</code>"),
        ("Closure", f"{_e(CLOSURES.get(item['closure_reason'], item['closure_reason']))} by {_e(item['closed_by'])}, "
                    f"{_e(clock.shown(item['closed_at']))}" if item["status"] == cases.CLOSED else "Open"),
    ]) + "</table>"
    timeline = ("<table><tr><th>When</th><th>Who</th><th>Event</th><th>Detail</th></tr>"
                + "".join(f"<tr><td>{_e(clock.shown(e['at']))}</td><td>{_e(e['actor'])}</td><td>{_e(e['kind'].replace('_', ' '))}</td>"
                          f"<td>{_e(e['text'])}</td></tr>" for e in item["timeline"]) + "</table>")
    body = (f'<h2>1. Summary</h2><div class="summary">{_summary_of(page, item)}</div>'
            f"<h2>2. Scope and method</h2>{METHOD}"
            f"<h2>3. Comparison with the published release</h2>{_differences(page)}"
            f"<h2>4. Findings linked to this case</h2>{_findings(item['findings'])}"
            f"<h2>5. Other open findings on this server</h2>{_findings([f for f in page['findings'] if f['reference'] not in linked])}"
            f"<h2>6. Case timeline</h2>{timeline}"
            f"<h2>7. Scan history</h2>{_scans(page['scans'])}"
            f"<h2>8. Evidence integrity</h2>{_integrity(db, page)}"
            f"<h2>9. Limitations</h2>{LIMITS}")
    return _document(f"{item['reference']} · {item['title']}", _e(item["asset"]), meta, body,
                     team.name_of(db, user) or user.username)


def for_server(db: Session, user: User, asset: Asset) -> str:
    page = inventory.detail(db, user, asset)
    scan = page.get("read_scan")
    verdict = (page.get("provenance") or {}).get("verdict") or "unknown"
    meta = "<table class=meta>" + _rows([
        ("Server", f"{_e(page['label'])} · <code>{_e(page['endpoint'])}</code>"),
        ("Verdict", f'<span class="verdict-{_e(verdict)}">{_e(VERDICTS.get(verdict, verdict))}</span>'),
        ("Release", f"<code>{_e(scan['release'])}</code>" if scan and scan.get("release") else "—"),
        ("Last read", f"<code>{_e(scan['reference'])}</code>, {_e(clock.shown(scan['started_at']))}" if scan else "Never"),
        ("Tools", _e(len(page["tools"]))),
        ("Authentication", "Required" if page.get("auth_required") else "Not requested"),
        ("Authorization", _e(listings.basis(db, asset)["text"])),
        ("Open cases", ", ".join(f"<code>{_e(c['reference'])}</code>" for c in page["cases"] if c["status"] != cases.CLOSED) or "None"),
    ]) + "</table>"
    body = (f'<h2>1. Summary</h2><div class="summary">{_summary_of(page, None)}</div>'
            f"<h2>2. Scope and method</h2>{METHOD}"
            f"<h2>3. Comparison with the published release</h2>{_differences(page)}"
            f"<h2>4. Findings</h2>{_findings(page['findings'])}"
            f"<h2>5. Scan history</h2>{_scans(page['scans'])}"
            f"<h2>6. Evidence integrity</h2>{_integrity(db, page)}"
            f"<h2>7. Limitations</h2>{LIMITS}")
    return _document(f"Server report · {page['label']}", _e(page["endpoint"]), meta, body,
                     team.name_of(db, user) or user.username)
