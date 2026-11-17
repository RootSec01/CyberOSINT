"""One live picture of everything registered, and a briefing written from it."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from raqeeb import cases, evidence, inventory, monitoring, provenance, register, seals, team
from raqeeb.models import Alert, AuditEntry, Scan, User
from raqeeb.paths import PROJECT_ROOT

SEVERITIES = ["Critical", "High", "Medium", "Low"]
RANK = {level: index for index, level in enumerate(SEVERITIES)}
STALE_DAYS = 7
TREND_DAYS = 14
FIELD_STUDY = PROJECT_ROOT / "observatory" / "analysis.json"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _age_days(stamp: str | None) -> float | None:
    if not stamp:
        return None
    moment = datetime.fromisoformat(stamp.replace("Z", "+00:00")).replace(tzinfo=None)
    return (_utcnow() - moment).total_seconds() / 86400


def snapshot(db: Session, user: User) -> dict:
    servers = inventory.inventory(db, user)
    read = [s for s in servers if s.get("scan") and s["scan"].get("outcome") == "read"]
    deviating = [s for s in read if s["scan"].get("verdict") == "deviation"]
    stale = [s for s in servers if not s.get("scan") or (_age_days(s["scan"]["started_at"]) or 0) > STALE_DAYS]

    by_severity = {level: 0 for level in SEVERITIES}
    open_findings = register.findings(db, user, status="open").all()
    for finding, _ in open_findings:
        if finding.severity in by_severity:
            by_severity[finding.severity] += 1

    pairs = cases.cases(db, user).all()
    open_pairs = [(case, asset) for case, asset in pairs if case.status != "closed"]
    oldest = min(open_pairs, key=lambda pair: pair[0].opened_at, default=None)

    changes = inventory.changes(db, user)
    week = [c for c in changes if (_age_days(c["at"]) or 0) <= 7]

    audit = db.query(AuditEntry)
    if user.role != "admin":
        audit = audit.filter(AuditEntry.operator == user.username)
    entries = audit.order_by(AuditEntry.ts.desc(), AuditEntry.id.desc()).limit(8).all()

    risky = sorted(read, key=lambda s: (
        -(s["scan"].get("verdict") == "deviation"),
        RANK.get(s["scan"].get("severity"), len(SEVERITIES)),
        -s.get("flagged_tools", 0), -s.get("open_cases", 0)))

    verdicts = Counter(s["scan"].get("verdict") or "unknown" for s in read)
    categories = Counter((finding.title, _evidence(finding).get("owasp_mcp")) for finding, _ in open_findings)
    techniques = Counter(_evidence(finding).get("technique_id") for finding, _ in open_findings)
    techniques.pop(None, None)

    ids = [s["id"] for s in servers]
    since = _utcnow() - timedelta(days=TREND_DAYS - 1)
    start = since.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
    days = {(start + timedelta(days=n)).date().isoformat(): {"manual": 0, "scheduled": 0} for n in range(TREND_DAYS)}
    for scan in db.query(Scan).filter(Scan.asset_id.in_(ids), Scan.started_at >= start):
        day = register._utc(scan.started_at).date().isoformat()
        if day in days:
            days[day]["scheduled" if scan.trigger == "scheduled" else "manual"] += 1

    people = team.people(db, user)
    alerts = (db.query(Alert).filter(Alert.user_id.in_(people))
              .order_by(Alert.created_at.desc(), Alert.id.desc()).limit(8).all())
    labels = {s["id"]: s["label"] for s in servers}
    schedule = monitoring.status(db, user)
    upcoming = sorted((p for p in schedule["plans"] if p["next_scan"]), key=lambda p: p["next_scan"])
    chain = seals.check(db)
    library = provenance._library()

    return {
        "generated_at": _utcnow().isoformat(),
        "servers": {"total": len(servers), "read": len(read), "deviation": len(deviating),
                    "stale": len(stale),
                    "tools": sum(s["scan"]["tool_count"] for s in read),
                    "flagged": sum(s.get("flagged_tools", 0) for s in read)},
        "deviating": [s["label"] for s in deviating][:3],
        "findings": {"open": len(open_findings), "by_severity": by_severity},
        "cases": {"open": len(open_pairs),
                  "unassigned": sum(1 for case, _ in open_pairs if not case.owner_id),
                  "oldest": cases.case_dict(db, *oldest) if oldest else None,
                  "latest": [cases.case_dict(db, case, asset) for case, asset in open_pairs[:6]]},
        "changes": {"week": len(week), "latest": changes[:6]},
        "risky": risky[:6],
        "activity": [{"ts": register._stamp(e.ts), "operator": e.operator,
                      "action": e.action, "detail": e.detail, "decision": e.decision}
                     for e in entries],
        "last_scan": max((s["scan"]["started_at"] for s in servers if s.get("scan")), default=None),
        "provenance": {**{v: verdicts.get(v, 0) for v in ("match", "subset", "deviation", "unknown")},
                       "not_read": len(servers) - len(read)},
        "categories": [{"title": title, "owasp": owasp, "count": count}
                       for (title, owasp), count in categories.most_common(6)],
        "techniques": [{"id": tid, "count": count} for tid, count in techniques.most_common(6)],
        "trend": [{"day": day, **counts} for day, counts in days.items()],
        "alerts": {"unread": sum(1 for a in db.query(Alert.acknowledged)
                                 .filter(Alert.user_id.in_(people), Alert.acknowledged == False)),  # noqa: E712
                   "latest": [{"id": a.id, "severity": a.severity, "kind": a.kind, "title": a.title,
                               "detail": a.detail, "asset_id": a.asset_id, "asset": labels.get(a.asset_id),
                               "acknowledged": a.acknowledged, "created_at": register._stamp(a.created_at)}
                              for a in alerts]},
        "monitoring": {"enabled": schedule["enabled"], "monitored": schedule["monitored"],
                       "upcoming": upcoming[:5]},
        "integrity": {"intact": chain["intact"], "sealed": chain["sealed"],
                      "key_id": evidence.issuer()["key_id"]},
        "library": {"packages": len(library.packages), "releases": sum(1 for _ in library.releases())}
                   if library else None,
        "field": field_study(),
    }


def _evidence(finding) -> dict:
    try:
        return json.loads(finding.evidence_json) if finding.evidence_json else {}
    except ValueError:
        return {}


def field_study() -> dict | None:
    """The published aggregate from the public registry study; no server is named."""
    if not FIELD_STUDY.exists():
        return None
    data = json.loads(FIELD_STUDY.read_text(encoding="utf-8"))
    latest, period = data["latest"], data["period"]
    return {"runs": len(data["runs"]), "from": period["from"], "to": period["to"],
            "endpoints": latest["endpoints"], "ok": latest["ok"], "auth_required": latest["auth_required"],
            "other": latest["endpoints"] - latest["ok"] - latest["auth_required"],
            "tools": data["declarations"]["tools"],
            "day_to_day": [{"to": d["to"], "changed": d["changed"], "comparable": d["comparable"],
                            "share": d["share"]} for d in data["day_to_day"]],
            "changed_once": period["changed_at_least_once"], "listed": period["listed_tools_in_every_run"],
            "rules": [{"finding": r["finding"], "servers": r["servers"], "share": r["share_of_servers"]}
                      for r in data["declarations"]["rules"]]}


def _count(number: int, word: str) -> str:
    return f"{number} {word}{'' if number == 1 else 's'}"


def briefing(db: Session, user: User) -> str:
    s = snapshot(db, user)
    servers, findings, open_cases = s["servers"], s["findings"], s["cases"]
    lines = [f"Briefing, {_utcnow().strftime('%d %b %Y, %H:%M')} UTC."]

    lines.append(f"{_count(servers['total'], 'server')} registered; {servers['read']} read, "
                 f"declaring {_count(servers['tools'], 'tool')} of which {servers['flagged']} are flagged.")
    if s["deviating"]:
        named = ", ".join(s["deviating"])
        extra = servers["deviation"] - len(s["deviating"])
        lines.append(f"Deviation from the published release on {named}"
                     + (f" and {_count(extra, 'other server')}." if extra > 0 else "."))
    elif servers["read"]:
        lines.append("No server deviates from its published release.")

    parts = ", ".join(f"{count} {level}" for level, count in findings["by_severity"].items() if count)
    lines.append(f"Open findings: {findings['open']}" + (f" ({parts})." if parts else "."))

    oldest = open_cases["oldest"]
    line = f"Cases: {open_cases['open']} open, {open_cases['unassigned']} unassigned."
    if oldest:
        age = int(_age_days(oldest["opened_at"]) or 0)
        line += f" Oldest is {oldest['reference']}" + (f", open for {_count(age, 'day')}." if age else ", opened today.")
    lines.append(line)
    lines.append(f"Declared tools changed on {_count(s['changes']['week'], 'server scan')} in the last 7 days.")

    steps = []
    if servers["deviation"]:
        steps.append("Work the deviation cases first.")
    if open_cases["unassigned"]:
        steps.append(f"Assign the {_count(open_cases['unassigned'], 'unowned case')}.")
    if servers["stale"]:
        steps.append(f"Rescan the {_count(servers['stale'], 'server')} not read in {STALE_DAYS} days.")
    if steps:
        lines.append("Next: " + " ".join(steps))
    lines.append("Written from the live database; nothing left the platform.")
    return "\n".join(lines)
