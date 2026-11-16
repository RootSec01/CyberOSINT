"""What the console shows about servers: the list, one server in full, and what changed."""
from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from raqeeb import cases, provenance, register, team
from raqeeb.declarations import canonical_tools, compare
from raqeeb.models import Asset, Case, Finding, Run, Scan, User

RECENT_RELEASES = 5
RECENT_SCANS = 30


def _assets(db: Session, user: User):
    query = db.query(Asset).filter(Asset.kind == "mcp")
    if user.role != "admin":
        query = query.filter(Asset.user_id.in_(team.people(db, user)))
    return query.order_by(Asset.id)


def _read_scans(db: Session, asset_id: int) -> list[Scan]:
    return (db.query(Scan).filter(Scan.asset_id == asset_id, Scan.outcome == register.READ)
            .order_by(Scan.id).all())


def _named_changes(db: Session, before: Optional[str], after: Optional[str]) -> Optional[dict]:
    old, new = register.declared_tools(db, before), register.declared_tools(db, after)
    if old is None or new is None:
        return None
    added, removed, redefined = compare(canonical_tools(old), canonical_tools(new))
    return {"added": added, "removed": removed, "redefined": redefined}


def _last_change(db: Session, scans: list[Scan]) -> Optional[dict]:
    for earlier, later in reversed(list(zip(scans, scans[1:]))):
        if earlier.declarations != later.declarations:
            return {"scan": later.reference, "at": register._stamp(later.started_at),
                    **(_named_changes(db, earlier.declarations, later.declarations) or {})}
    return None


def _row(db: Session, asset: Asset) -> dict:
    latest = db.query(Scan).filter(Scan.asset_id == asset.id).order_by(Scan.id.desc()).first()
    open_findings = db.query(Finding).filter(Finding.asset_id == asset.id, Finding.status != register.RESOLVED)
    return {"id": asset.id, "label": asset.label or asset.value, "endpoint": asset.value,
            "monitoring": asset.monitoring,
            "scan": register.scan_dict(latest, asset) if latest else None,
            "open_findings": open_findings.count(),
            "flagged_tools": len({f.tool for f in open_findings if f.tool}),
            "open_cases": db.query(Case).filter(Case.asset_id == asset.id, Case.status != cases.CLOSED).count(),
            "last_change": _last_change(db, _read_scans(db, asset.id))}


def inventory(db: Session, user: User) -> list[dict]:
    return [_row(db, asset) for asset in _assets(db, user)]


def _parameters(tool: dict) -> list[dict]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    required = set(schema.get("required") or []) if isinstance(schema, dict) else set()
    properties = schema.get("properties") if isinstance(schema, dict) else None
    return [{"name": name, "type": str(spec.get("type", "any")) if isinstance(spec, dict) else "any",
             "required": name in required} for name, spec in (properties or {}).items()]


def _release_history(assessment: dict) -> Optional[dict]:
    library, package = provenance._library(), assessment.get("package")
    if not library or not package:
        return None
    here = (assessment.get("versions") or [None])[-1]
    listed = [(version, record) for _, version, record in library.releases(package) if record.get("manifest")]
    history, earlier = [], None
    for version, record in listed:
        tools = canonical_tools(library.tools(record["manifest"]))
        if earlier is None:
            change = {"first": True}
        else:
            added, removed, redefined = compare(earlier, tools)
            change = {"added": len(added), "removed": len(removed), "redefined": len(redefined)}
        history.append({"version": version, "published": (record.get("published") or "")[:10],
                        "tool_count": len(tools), "here": version == here, **change})
        earlier = tools
    return {"package": package, "total": len(history), "releases": history[-RECENT_RELEASES:]}


def _provenance(assessment: dict) -> Optional[dict]:
    if not assessment:
        return None
    return {"verdict": assessment.get("verdict"), "package": assessment.get("package"),
            "library": assessment.get("library"),
            **{key: assessment.get(key) or [] for key in ("versions", "added", "absent", "redefined")}}


def detail(db: Session, user: User, asset: Asset) -> dict:
    latest = db.query(Scan).filter(Scan.asset_id == asset.id).order_by(Scan.id.desc()).first()
    read = db.query(Scan).filter(Scan.asset_id == asset.id, Scan.outcome == register.READ).order_by(Scan.id.desc()).first()
    stored = db.query(Run).filter(Run.id == read.run_row).first() if read and read.run_row else None
    proof = (json.loads(stored.report_json).get("safe_proof") or {}) if stored and stored.report_json else {}
    assessment = proof.get("provenance") or {}
    differences = {d["tool"]: d for d in assessment.get("differences") or []}

    rows = (db.query(Finding).filter(Finding.asset_id == asset.id, Finding.status != register.RESOLVED)
            .order_by(Finding.id).all())
    held = cases.references(db, [finding.id for finding in rows])
    findings = [{**register.finding_dict(finding, asset), "case": held.get(finding.id)} for finding in rows]

    known = assessment.get("verdict") in ("match", "subset", "deviation")
    tools = []
    for tool in register.declared_tools(db, read.declarations if read else None) or []:
        name = str(tool.get("name") or "")
        status = ("redefined" if name in (assessment.get("redefined") or []) else
                  "added" if name in (assessment.get("added") or []) else
                  "identical" if known else "unverified")
        tools.append({"name": name, "description": tool.get("description") or "", "status": status,
                      "parameters": _parameters(tool),
                      "differences": (differences.get(name) or {}).get("fields") or [],
                      "findings": [f["reference"] for f in findings if f["tool"] == name]})

    scans = (db.query(Scan).filter(Scan.asset_id == asset.id).order_by(Scan.id.desc()).limit(RECENT_SCANS))
    open_cases = cases.cases(db, user, asset_id=asset.id).all()
    return {**_row(db, asset),
            "auth_required": proof.get("auth_required") if read else None,
            "read_scan": register.scan_dict(read, asset) if read else None,
            "latest_outcome": latest.outcome if latest else None,
            "provenance": _provenance(assessment),
            "tools": tools, "findings": findings,
            "releases": _release_history(assessment),
            "scans": [register.scan_dict(scan, asset) for scan in scans],
            "cases": [cases.case_dict(db, case, owner) for case, owner in open_cases]}


def changes(db: Session, user: User, *, asset_id: Optional[int] = None, kind: str = "", text: str = "",
            bounds=(None, None)) -> list[dict]:
    if kind not in ("", "between_scans", "against_release"):
        raise register.Rejected("kind must be between_scans or against_release")
    start, end = bounds
    found = []
    for asset in _assets(db, user):
        if asset_id is not None and asset.id != asset_id:
            continue
        scans = _read_scans(db, asset.id)
        events = []
        if scans and scans[0].verdict == "deviation":
            events.append(("against_release", None, scans[0]))
        for earlier, later in zip(scans, scans[1:]):
            if earlier.declarations != later.declarations:
                events.append(("between_scans", earlier, later))
        for name, earlier, later in events:
            moment = register._utc(later.started_at)
            if (kind and kind != name) or (start and moment < start) or (end and moment >= end):
                continue
            entry = {"kind": name, "at": register._stamp(later.started_at), "scan": later.reference,
                     "previous_scan": earlier.reference if earlier else None,
                     "asset_id": asset.id, "asset": asset.label or asset.value, "endpoint": asset.value,
                     "verdict": later.verdict, "release": later.release,
                     "declarations": later.declarations,
                     "previous_declarations": earlier.declarations if earlier else None,
                     "added": None, "removed": None, "redefined": None}
            if earlier:
                entry.update(_named_changes(db, earlier.declarations, later.declarations) or {})
            needle = text.strip().lower()
            if needle and needle not in json.dumps(entry).lower():
                continue
            found.append(entry)
    return sorted(found, key=lambda entry: (entry["at"], entry["scan"]), reverse=True)
