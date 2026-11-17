"""One live picture of everything registered, and a briefing written from it."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from raqeeb import cases, inventory, register
from raqeeb.models import AuditEntry, User

SEVERITIES = ["Critical", "High", "Medium", "Low"]
RANK = {level: index for index, level in enumerate(SEVERITIES)}
STALE_DAYS = 7


def _age_days(stamp: str | None) -> float | None:
    if not stamp:
        return None
    moment = datetime.fromisoformat(stamp.replace("Z", "+00:00")).replace(tzinfo=None)
    return (datetime.utcnow() - moment).total_seconds() / 86400


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

    return {
        "generated_at": datetime.utcnow().isoformat(),
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
        "activity": [{"ts": e.ts.isoformat() if e.ts else None, "operator": e.operator,
                      "action": e.action, "detail": e.detail, "decision": e.decision}
                     for e in entries],
        "last_scan": max((s["scan"]["started_at"] for s in servers if s.get("scan")), default=None),
    }


def _count(number: int, word: str) -> str:
    return f"{number} {word}{'' if number == 1 else 's'}"


def briefing(db: Session, user: User) -> str:
    s = snapshot(db, user)
    servers, findings, open_cases = s["servers"], s["findings"], s["cases"]
    lines = [f"Briefing, {datetime.utcnow().strftime('%d %b %Y, %H:%M')} UTC."]

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
