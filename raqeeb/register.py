"""Scans and findings kept by reference, so a result can be cited, filtered and followed over time."""
from __future__ import annotations

import json
from datetime import datetime, time, timedelta, timezone
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Query, Session

from raqeeb import redaction, team
from raqeeb.declarations import tools_digest
from raqeeb.models import Asset, Declaration, Finding, Scan, User

READ = "read"
AUTH_REQUIRED = "auth_required"
NO_MCP = "no_mcp"
UNAUTHORIZED = "unauthorized"

OPEN = "open"
ACKNOWLEDGED = "acknowledged"
RISK_ACCEPTED = "risk_accepted"
RESOLVED = "resolved"
SET_BY_PEOPLE = (OPEN, ACKNOWLEDGED, RISK_ACCEPTED)
NOTE_REQUIRED = (RISK_ACCEPTED,)
MIN_NOTE = 10

SYSTEM = "raqeeb"
SEVERITIES = ("Critical", "High", "Medium", "Low")
PAGE = 200
LARGEST_PAGE = 500


class Rejected(ValueError):
    """A request the register cannot honour as asked."""


def _utc(moment: Optional[datetime]) -> Optional[datetime]:
    if moment is None:
        return None
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def _stamp(moment: Optional[datetime]) -> Optional[str]:
    moment = _utc(moment)
    return moment.isoformat(timespec="seconds") if moment else None


def _moment(text: str, *, closing: bool) -> datetime:
    text = text.strip()
    try:
        if len(text) == 10:
            day = datetime.strptime(text, "%Y-%m-%d").date()
            start = datetime.combine(day, time.min, tzinfo=timezone.utc)
            return start + timedelta(days=1) if closing else start
        return _utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        raise Rejected(f"not a date or time: {text!r}; use YYYY-MM-DD or YYYY-MM-DDTHH:MM") from None


def window(since: str = "", until: str = "", on: str = "") -> tuple[Optional[datetime], Optional[datetime]]:
    """Bounds in UTC, upper bound exclusive. A bare date covers that whole day."""
    if on.strip():
        if since.strip() or until.strip():
            raise Rejected("use either on, or since and until")
        return _moment(on, closing=False), _moment(on[:10], closing=True)
    start = _moment(since, closing=False) if since.strip() else None
    end = _moment(until, closing=True) if until.strip() else None
    if start and end and end <= start:
        raise Rejected("until is not after since")
    return start, end


def within(query: Query, column, bounds: tuple[Optional[datetime], Optional[datetime]]) -> Query:
    start, end = bounds
    if start:
        query = query.filter(column >= start)
    if end:
        query = query.filter(column < end)
    return query


def page(query: Query, limit: int, offset: int) -> tuple[int, list]:
    limit = max(1, min(limit, LARGEST_PAGE))
    return query.count(), query.offset(max(0, offset)).limit(limit).all()


def _outcome(payload: dict) -> str:
    if payload.get("skipped"):
        return UNAUTHORIZED
    proof = payload.get("safe_proof") or {}
    if not proof.get("is_mcp"):
        return NO_MCP
    return AUTH_REQUIRED if proof.get("auth_required") else READ


def _identity(finding: dict, seen: dict[str, int]) -> str:
    base = f"{finding.get('finding_type') or finding.get('category')}:{finding.get('affected_tool') or '-'}"
    seen[base] = seen.get(base, 0) + 1
    return base if seen[base] == 1 else f"{base}#{seen[base]}"


def _evidence(finding: dict) -> str:
    kept = ("observed_facts", "inference", "recommendation", "technique_id", "owasp_mcp",
            "confidence", "verification_status")
    return json.dumps({key: finding.get(key) for key in kept}, default=str)


def _follow_findings(db: Session, scan: Scan, detected: list[dict], *, complete: bool = True) -> None:
    """Bring the asset's findings up to date. A finding the scan did not see is resolved only when
    the scan read the whole tool list: a listing that failed part way, or stopped at the page
    limit, says nothing about the tools it never reached."""
    known = {row.fingerprint: row for row in db.query(Finding).filter(Finding.asset_id == scan.asset_id)}
    seen: dict[str, int] = {}
    present = set()
    for finding in detected:
        fingerprint = _identity(finding, seen)
        present.add(fingerprint)
        row = known.get(fingerprint)
        if row is None:
            row = Finding(asset_id=scan.asset_id, fingerprint=fingerprint, reference="",
                          status=OPEN, status_by=SYSTEM, status_at=scan.started_at,
                          first_scan=scan.reference, first_seen_at=scan.started_at)
            db.add(row)
        elif row.status == RESOLVED:
            row.status, row.status_by, row.status_at = OPEN, SYSTEM, scan.started_at
            row.status_note = f"Seen again in {scan.reference}"
        row.category = finding.get("category") or ""
        row.title = finding.get("title") or ""
        row.severity = finding.get("severity") or "Low"
        row.evidence_level = finding.get("evidence_level") or ""
        row.tool = finding.get("affected_tool")
        row.evidence_json = _evidence(finding)
        row.last_scan, row.last_seen_at = scan.reference, scan.started_at
    for fingerprint, row in known.items():
        if complete and fingerprint not in present and row.status != RESOLVED:
            row.status, row.status_by, row.status_at = RESOLVED, SYSTEM, scan.started_at
            row.status_note = f"Not declared in {scan.reference}"
    db.flush()
    for row in db.query(Finding).filter(Finding.asset_id == scan.asset_id, Finding.reference == ""):
        row.reference = f"FND-{row.id:06d}"


def _keep_declarations(db: Session, digest: Optional[str], tools: Optional[list]) -> None:
    if not digest or not tools or db.query(Declaration.id).filter(Declaration.digest == digest).first():
        return
    db.add(Declaration(digest=digest, tools_json=json.dumps(redaction.redact_secrets(tools), default=str)))


def declared_tools(db: Session, digest: Optional[str]) -> Optional[list]:
    row = db.query(Declaration).filter(Declaration.digest == digest).first() if digest else None
    return json.loads(row.tools_json) if row else None


def record_scan(db: Session, asset: Asset, payload: dict, *, operator: str, trigger: str,
                run_row: Optional[int] = None, tools: Optional[list] = None) -> Scan:
    """Give one scan its reference and bring the asset's findings up to date with it."""
    proof = payload.get("safe_proof") or {}
    provenance = proof.get("provenance") or {}
    outcome = _outcome(payload)
    started = datetime.now(timezone.utc)
    scan = Scan(asset_id=asset.id, reference=f"pending-{asset.id}-{started.timestamp()}",
                operator=operator, trigger=trigger, started_at=started, outcome=outcome, run_row=run_row)
    if outcome == READ:
        detected = proof.get("mcp_findings") or []
        scan.severity = proof.get("severity")
        scan.tool_count = proof.get("tool_count")
        scan.finding_count = len(detected)
        scan.declarations = payload.get("declarations")
        _keep_declarations(db, scan.declarations, tools)
        scan.verdict = provenance.get("verdict")
        if provenance.get("package"):
            scan.release = f"{provenance['package']}@{(provenance.get('versions') or ['?'])[-1]}"
    db.add(scan)
    db.flush()
    scan.reference = f"SCN-{started:%Y%m%d}-{scan.id:04d}"
    if outcome == READ:
        _follow_findings(db, scan, detected, complete=payload.get("tools_complete", True))
    db.commit()
    return scan


def declarations_digest(tools: Optional[list]) -> Optional[str]:
    return tools_digest(tools) if tools else None


def set_status(db: Session, finding: Finding, status: str, note: str, by: str) -> Finding:
    status, note = status.strip().lower(), note.strip()
    if status == RESOLVED:
        raise Rejected("a finding is resolved by a scan that no longer sees it, not by hand")
    if status not in SET_BY_PEOPLE:
        raise Rejected(f"status must be one of: {', '.join(SET_BY_PEOPLE)}")
    if finding.status == RESOLVED:
        raise Rejected("this finding is resolved; it reopens by itself if a scan sees it again")
    if status in NOTE_REQUIRED and len(note) < MIN_NOTE:
        raise Rejected(f"accepting a risk needs a written reason of at least {MIN_NOTE} characters")
    finding.status, finding.status_by = status, by
    finding.status_at, finding.status_note = datetime.now(timezone.utc), note or None
    db.commit()
    return finding


def _visible(db: Session, query: Query, user: User) -> Query:
    return query if user.role == "admin" else query.filter(Asset.user_id.in_(team.people(db, user)))


def scans(db: Session, user: User, *, asset_id: Optional[int] = None, outcome: str = "", operator: str = "",
          trigger: str = "", verdict: str = "", text: str = "",
          bounds: tuple[Optional[datetime], Optional[datetime]] = (None, None)) -> Query:
    query = _visible(db, db.query(Scan, Asset).join(Asset, Asset.id == Scan.asset_id), user)
    if asset_id is not None:
        query = query.filter(Scan.asset_id == asset_id)
    for column, value in ((Scan.outcome, outcome), (Scan.operator, operator),
                          (Scan.trigger, trigger), (Scan.verdict, verdict)):
        if value.strip():
            query = query.filter(column == value.strip())
    if text.strip():
        like = f"%{text.strip()}%"
        query = query.filter(or_(Scan.reference.ilike(like), Scan.release.ilike(like), Scan.declarations.ilike(like),
                                 Asset.label.ilike(like), Asset.value.ilike(like)))
    return within(query, Scan.started_at, bounds).order_by(Scan.started_at.desc(), Scan.id.desc())


def findings(db: Session, user: User, *, asset_id: Optional[int] = None, severity: str = "", status: str = "",
             evidence: str = "", category: str = "", tool: str = "", changed_by: str = "", scan: str = "",
             text: str = "", seen: str = "first",
             bounds: tuple[Optional[datetime], Optional[datetime]] = (None, None)) -> Query:
    if seen not in ("first", "last", "status"):
        raise Rejected("seen must be first, last or status")
    query = _visible(db, db.query(Finding, Asset).join(Asset, Asset.id == Finding.asset_id), user)
    if asset_id is not None:
        query = query.filter(Finding.asset_id == asset_id)
    for column, value in ((Finding.severity, severity), (Finding.status, status.lower()),
                          (Finding.evidence_level, evidence.upper()), (Finding.category, category),
                          (Finding.tool, tool), (Finding.status_by, changed_by)):
        if value.strip():
            query = query.filter(column == value.strip())
    if scan.strip():
        query = query.filter(or_(Finding.first_scan == scan.strip(), Finding.last_scan == scan.strip()))
    if text.strip():
        like = f"%{text.strip()}%"
        query = query.filter(or_(Finding.reference.ilike(like), Finding.title.ilike(like), Finding.tool.ilike(like),
                                 Finding.category.ilike(like), Asset.label.ilike(like), Asset.value.ilike(like)))
    moment = {"first": Finding.first_seen_at, "last": Finding.last_seen_at, "status": Finding.status_at}[seen]
    return within(query, moment, bounds).order_by(Finding.last_seen_at.desc(), Finding.id.desc())


def forget_asset(db: Session, asset_id: int) -> None:
    db.query(Finding).filter(Finding.asset_id == asset_id).delete(synchronize_session=False)
    db.query(Scan).filter(Scan.asset_id == asset_id).delete(synchronize_session=False)


def latest_reference(db: Session, asset_id: int) -> Optional[str]:
    row = db.query(Scan.reference).filter(Scan.asset_id == asset_id).order_by(Scan.id.desc()).first()
    return row[0] if row else None


def _asset_fields(asset: Asset) -> dict:
    return {"asset_id": asset.id, "asset": asset.label or asset.value, "endpoint": asset.value}


def scan_dict(scan: Scan, asset: Asset) -> dict:
    return {"reference": scan.reference, **_asset_fields(asset), "started_at": _stamp(scan.started_at),
            "operator": scan.operator, "trigger": scan.trigger, "outcome": scan.outcome,
            "severity": scan.severity, "verdict": scan.verdict, "release": scan.release,
            "tool_count": scan.tool_count, "finding_count": scan.finding_count,
            "declarations": scan.declarations}


def finding_dict(finding: Finding, asset: Asset) -> dict:
    evidence = json.loads(finding.evidence_json) if finding.evidence_json else {}
    return {"reference": finding.reference, **_asset_fields(asset), "category": finding.category,
            "title": finding.title, "severity": finding.severity, "evidence_level": finding.evidence_level,
            "tool": finding.tool, "status": finding.status, "status_by": finding.status_by,
            "status_at": _stamp(finding.status_at), "status_note": finding.status_note,
            "first_scan": finding.first_scan, "last_scan": finding.last_scan,
            "first_seen_at": _stamp(finding.first_seen_at), "last_seen_at": _stamp(finding.last_seen_at),
            "observed_facts": evidence.get("observed_facts") or [], "inference": evidence.get("inference"),
            "recommendation": evidence.get("recommendation"), "technique_id": evidence.get("technique_id"),
            "owasp_mcp": evidence.get("owasp_mcp"), "confidence": evidence.get("confidence"),
            "verification_status": evidence.get("verification_status")}
