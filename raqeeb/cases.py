"""Cases: what needs a decision, who opened it and why, who owns it, and how it was closed."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Query, Session

from raqeeb import register, team
from raqeeb.models import Asset, Case, CaseEvent, CaseFinding, CaseRule, Finding, Scan, User
from raqeeb.register import Rejected

DEVIATION, COMMAND_EXECUTION, MANUAL = "deviation", "command_execution", "manual"
OPEN, INVESTIGATING, CLOSED = "open", "investigating", "closed"
FIXED = "fixed"
CLOSURES = (FIXED, "risk_accepted", "false_positive", "duplicate", "out_of_scope")
MIN_NOTE = 10


@dataclass(frozen=True)
class Rule:
    title: str
    severity: str
    text: str


RULES = {
    DEVIATION: Rule("Declared tools differ from the published release", "High",
                    "A server matches a published package but its declarations differ from every release of it."),
    COMMAND_EXECUTION: Rule("Command execution tool listed without authentication", "Critical",
                            "A tool that executes commands is listed to callers that present no credential."),
}


@dataclass
class Trigger:
    key: str
    reason: str
    findings: list


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _log(db: Session, case: Case, actor: str, kind: str, text: str) -> None:
    db.add(CaseEvent(case_id=case.id, actor=actor, kind=kind, text=text, at=_now()))


def _link(db: Session, case: Case, findings: list) -> None:
    linked = {row.finding_id for row in db.query(CaseFinding.finding_id).filter(CaseFinding.case_id == case.id)}
    for finding in findings:
        if finding.id not in linked:
            db.add(CaseFinding(case_id=case.id, finding_id=finding.id))


def _counted(names: list, word: str) -> str:
    return f"{len(names)} {word}: {', '.join(names)}"


def _triggers(db: Session, asset: Asset, payload: dict) -> dict[str, Trigger]:
    proof = payload.get("safe_proof") or {}
    current = db.query(Finding).filter(Finding.asset_id == asset.id, Finding.status != register.RESOLVED).all()
    fired: dict[str, Trigger] = {}

    assessment = proof.get("provenance") or {}
    if assessment.get("verdict") == "deviation":
        redefined, added = sorted(assessment.get("redefined") or []), sorted(assessment.get("added") or [])
        release = f"{assessment.get('package')}@{(assessment.get('versions') or ['?'])[-1]}"
        parts = [_counted(names, word) for names, word in ((redefined, "redefined"), (added, "added")) if names]
        fired[DEVIATION] = Trigger(
            key=f"{release}|{','.join(redefined)}|{','.join(added)}",
            reason=f"Closest published release {release}. {'; '.join(parts)}.",
            findings=[f for f in current if f.tool in redefined + added])

    executing = sorted(f.tool for f in current if f.category == "rce" and f.tool)
    if executing and proof.get("auth_required") is False:
        fired[COMMAND_EXECUTION] = Trigger(
            key=",".join(executing),
            reason=(f"The server lists {', '.join(executing)} to callers that present no credential. "
                    "Raqeeb read the declaration only; the tool was not called."),
            findings=[f for f in current if f.category in ("rce", "open_capability")])
    return fired


def _switched_off(db: Session, team_id: int) -> set[str]:
    return {row.rule for row in db.query(CaseRule).filter(CaseRule.team_id == team_id, CaseRule.enabled == False)}  # noqa: E712


def _open(db: Session, asset: Asset, scan: str, *, rule: str, title: str, severity: str, reason: str,
          key: str, opened_by: str) -> Case:
    case = Case(reference=f"pending-{asset.id}-{rule}-{_now().timestamp()}", asset_id=asset.id, rule=rule,
                title=title, reason=reason, evidence_key=key, severity=severity, status=OPEN,
                opened_by=opened_by, opened_at=_now(), scan=scan, last_scan=scan)
    db.add(case)
    db.flush()
    case.reference = f"CASE-{case.opened_at:%Y}-{case.id:04d}"
    return case


def _clear_closure(case: Case) -> None:
    case.closed_by = case.closed_at = case.closure_reason = case.closure_note = None


def review(db: Session, asset: Asset, scan: Scan, payload: dict) -> list[Case]:
    """After a scan that read the tool list: open, refresh or reopen the cases its rules call for."""
    if scan.outcome != register.READ:
        return []
    fired = _triggers(db, asset, payload)
    off = _switched_off(db, team.team_of_asset(db, asset))
    touched = []
    for name, rule in RULES.items():
        trigger = fired.get(name)
        case = db.query(Case).filter(Case.asset_id == asset.id, Case.rule == name).order_by(Case.id.desc()).first()
        if trigger is None:
            if case and case.status != CLOSED and case.present:
                case.present = False
                _log(db, case, register.SYSTEM, "seen",
                     f"Not observed in {scan.reference}. Close the case once the fix is confirmed.")
                touched.append(case)
            continue
        if case is None:
            if name in off:
                continue
            case = _open(db, asset, scan.reference, rule=name, title=rule.title, severity=rule.severity,
                         reason=trigger.reason, key=trigger.key, opened_by=register.SYSTEM)
            _log(db, case, register.SYSTEM, "opened", f"Opened by rule from {scan.reference}. {rule.text}")
        elif case.status == CLOSED:
            case.last_scan = scan.reference
            if case.closure_reason != FIXED and case.evidence_key == trigger.key:
                continue
            why = ("after it was closed as fixed" if case.evidence_key == trigger.key
                   else "with different evidence")
            _clear_closure(case)
            case.status, case.present = OPEN, True
            case.reason, case.evidence_key = trigger.reason, trigger.key
            _log(db, case, register.SYSTEM, "reopened", f"Observed in {scan.reference} {why}. {trigger.reason}")
        else:
            case.last_scan = scan.reference
            if not case.present:
                case.present = True
                _log(db, case, register.SYSTEM, "seen", f"Observed again in {scan.reference}.")
            if case.evidence_key != trigger.key:
                case.reason, case.evidence_key = trigger.reason, trigger.key
                _log(db, case, register.SYSTEM, "seen", f"Evidence changed in {scan.reference}. {trigger.reason}")
        _link(db, case, trigger.findings)
        touched.append(case)
    db.commit()
    return touched


def open_by_hand(db: Session, by: User, finding: Finding, asset: Asset, title: str, note: str) -> Case:
    note = note.strip()
    if len(note) < MIN_NOTE:
        raise Rejected(f"say why this needs a case, in at least {MIN_NOTE} characters")
    case = _open(db, asset, finding.last_scan, rule=MANUAL, title=title.strip()[:200] or finding.title,
                 severity=finding.severity, reason=note, key=finding.reference, opened_by=by.username)
    _log(db, case, by.username, "opened", f"Opened by hand from {finding.reference}. {note}")
    _link(db, case, [finding])
    db.commit()
    return case


def _still_open(case: Case) -> None:
    if case.status == CLOSED:
        raise Rejected("this case is closed; reopen it first")


def assign(db: Session, case: Case, by: User, username: str) -> Case:
    _still_open(case)
    username = username.strip().lower()
    if not username:
        case.owner_id = None
        _log(db, case, by.username, "assigned", "Unassigned.")
    else:
        owner = db.query(User).filter(User.username == username).first()
        if not team.can_own_cases(db, by, owner):
            raise Rejected("a case can be assigned to an active admin or analyst of this team")
        case.owner_id = owner.id
        _log(db, case, by.username, "assigned", f"Assigned to {team.name_of(db, owner)}.")
    db.commit()
    return case


def set_status(db: Session, case: Case, by: User, status: str) -> Case:
    _still_open(case)
    status = status.strip().lower()
    if status not in (OPEN, INVESTIGATING):
        raise Rejected("status is open or investigating; closing needs a reason")
    if status != case.status:
        case.status = status
        if status == INVESTIGATING and case.owner_id is None:
            case.owner_id = by.id
        _log(db, case, by.username, "status", f"Status changed to {status}.")
        db.commit()
    return case


def close(db: Session, case: Case, by: User, reason: str, note: str) -> Case:
    _still_open(case)
    reason, note = reason.strip().lower(), note.strip()
    if reason not in CLOSURES:
        raise Rejected(f"closure reason must be one of: {', '.join(CLOSURES)}")
    if len(note) < MIN_NOTE:
        raise Rejected(f"closing needs a note of at least {MIN_NOTE} characters on what was done")
    case.status, case.closed_by, case.closed_at = CLOSED, by.username, _now()
    case.closure_reason, case.closure_note = reason, note
    _log(db, case, by.username, "closed", f"Closed as {reason.replace('_', ' ')}. {note}")
    db.commit()
    return case


def reopen(db: Session, case: Case, by: User, note: str) -> Case:
    note = note.strip()
    if case.status != CLOSED:
        raise Rejected("this case is not closed")
    if len(note) < MIN_NOTE:
        raise Rejected(f"reopening needs a note of at least {MIN_NOTE} characters")
    _clear_closure(case)
    case.status = OPEN
    _log(db, case, by.username, "reopened", f"Reopened. {note}")
    db.commit()
    return case


def add_note(db: Session, case: Case, by: User, text: str) -> Case:
    text = text.strip()
    if not text:
        raise Rejected("the note is empty")
    _log(db, case, by.username, "note", text)
    db.commit()
    return case


def release_from(db: Session, user_id: int) -> int:
    held = db.query(Case).filter(Case.owner_id == user_id).all()
    for case in held:
        case.owner_id = None
        _log(db, case, register.SYSTEM, "assigned", "Unassigned: the owner left the team.")
    db.commit()
    return len(held)


def cases(db: Session, user: User, *, asset_id: Optional[int] = None, status: str = "", severity: str = "",
          rule: str = "", owner: str = "", opened_by: str = "", closure: str = "", text: str = "",
          seen: str = "opened", bounds=(None, None)) -> Query:
    if seen not in ("opened", "closed"):
        raise Rejected("seen must be opened or closed")
    query = db.query(Case, Asset).join(Asset, Asset.id == Case.asset_id)
    if user.role != "admin":
        query = query.filter(Asset.user_id.in_(team.people(db, user)))
    if asset_id is not None:
        query = query.filter(Case.asset_id == asset_id)
    for column, value in ((Case.status, status.lower()), (Case.severity, severity), (Case.rule, rule.lower()),
                          (Case.opened_by, opened_by), (Case.closure_reason, closure.lower())):
        if value.strip():
            query = query.filter(column == value.strip())
    owner = owner.strip().lower()
    if owner == "none":
        query = query.filter(Case.owner_id.is_(None))
    elif owner:
        found = db.query(User.id).filter(User.username == owner).first()
        query = query.filter(Case.owner_id == (found[0] if found else -1))
    if text.strip():
        like = f"%{text.strip()}%"
        query = query.filter(or_(Case.reference.ilike(like), Case.title.ilike(like), Case.reason.ilike(like),
                                 Asset.label.ilike(like), Asset.value.ilike(like)))
    moment = Case.opened_at if seen == "opened" else Case.closed_at
    return register.within(query, moment, bounds).order_by(Case.opened_at.desc(), Case.id.desc())


def references(db: Session, finding_ids: list[int]) -> dict[int, str]:
    """The newest case each finding belongs to."""
    if not finding_ids:
        return {}
    rows = (db.query(CaseFinding.finding_id, Case.reference).join(Case, Case.id == CaseFinding.case_id)
            .filter(CaseFinding.finding_id.in_(finding_ids)).order_by(Case.id))
    return {finding_id: reference for finding_id, reference in rows}


def case_dict(db: Session, case: Case, asset: Asset, *, full: bool = False) -> dict:
    owner = db.query(User).filter(User.id == case.owner_id).first() if case.owner_id else None
    linked = db.query(CaseFinding).filter(CaseFinding.case_id == case.id).count()
    rule = RULES.get(case.rule)
    out = {"reference": case.reference, "asset_id": asset.id, "asset": asset.label or asset.value,
           "endpoint": asset.value, "title": case.title, "severity": case.severity, "status": case.status,
           "rule": case.rule, "rule_text": rule.text if rule else None, "reason": case.reason,
           "opened_by": case.opened_by, "automatic": case.opened_by == register.SYSTEM,
           "opened_at": register._stamp(case.opened_at), "scan": case.scan, "last_scan": case.last_scan,
           "still_observed": case.present,
           "owner": owner.username if owner else None, "owner_name": team.name_of(db, owner),
           "closed_by": case.closed_by, "closed_at": register._stamp(case.closed_at),
           "closure_reason": case.closure_reason, "closure_note": case.closure_note,
           "finding_count": linked}
    if full:
        rows = (db.query(Finding).join(CaseFinding, CaseFinding.finding_id == Finding.id)
                .filter(CaseFinding.case_id == case.id).order_by(Finding.id))
        out["findings"] = [register.finding_dict(finding, asset) for finding in rows]
        out["timeline"] = [{"at": register._stamp(event.at), "actor": event.actor, "kind": event.kind,
                            "text": event.text}
                           for event in db.query(CaseEvent).filter(CaseEvent.case_id == case.id).order_by(CaseEvent.id)]
    return out


def rules_for(db: Session, user: User) -> list[dict]:
    off = _switched_off(db, team.team_of(db, user))
    return [{"rule": name, "title": rule.title, "severity": rule.severity, "text": rule.text,
             "enabled": name not in off} for name, rule in RULES.items()]


def set_rule(db: Session, user: User, name: str, enabled: bool) -> None:
    if name not in RULES:
        raise Rejected(f"rule must be one of: {', '.join(RULES)}")
    team_id = team.team_of(db, user)
    row = db.query(CaseRule).filter(CaseRule.team_id == team_id, CaseRule.rule == name).first()
    if row is None:
        row = CaseRule(team_id=team_id, rule=name)
        db.add(row)
    row.enabled, row.changed_by = enabled, user.username
    db.commit()


def forget_asset(db: Session, asset_id: int) -> None:
    ids = [row[0] for row in db.query(Case.id).filter(Case.asset_id == asset_id)]
    if ids:
        db.query(CaseEvent).filter(CaseEvent.case_id.in_(ids)).delete(synchronize_session=False)
        db.query(CaseFinding).filter(CaseFinding.case_id.in_(ids)).delete(synchronize_session=False)
        db.query(Case).filter(Case.id.in_(ids)).delete(synchronize_session=False)
