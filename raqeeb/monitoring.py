"""Scheduled rescans per server, and the alerts a scan raises about what changed."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy.orm import Session

from raqeeb import inventory, register, team
from raqeeb.models import Alert, Asset, Scan, Schedule, User

CHOICES = (0, 1, 5, 15, 60, 360, 1440)
RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
ENDED = {register.NO_MCP: "got no MCP answer", register.AUTH_REQUIRED: "was asked for a credential",
         register.UNAUTHORIZED: "was outside the authorized scope"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def enabled() -> bool:
    return os.getenv("SCHEDULER_ENABLED", "false").strip().lower() == "true"


def default_minutes() -> int:
    try:
        return max(1, int(os.getenv("SCAN_INTERVAL_MINUTES", "60")))
    except ValueError:
        return 60


def every(db: Session, asset: Asset) -> int:
    row = db.query(Schedule).filter(Schedule.asset_id == asset.id).first()
    if row:
        return row.every_minutes
    return default_minutes() if asset.monitoring else 0


def next_at(asset: Asset, minutes: int) -> Optional[datetime]:
    if not minutes:
        return None
    if not asset.last_scanned_at:
        return _now()
    return register._utc(asset.last_scanned_at) + timedelta(minutes=minutes)


def set_every(db: Session, asset: Asset, by: User, minutes: int) -> int:
    if minutes not in CHOICES:
        raise register.Rejected(f"interval must be one of: {', '.join(str(c) for c in CHOICES)} minutes")
    row = db.query(Schedule).filter(Schedule.asset_id == asset.id).first() or Schedule(asset_id=asset.id)
    row.every_minutes, row.set_by, row.set_at = minutes, by.username, _now()
    asset.monitoring = minutes > 0
    db.add(row)
    db.commit()
    return minutes


def due(db: Session, now: Optional[datetime] = None) -> list[Asset]:
    now = now or _now()
    found = []
    for asset in db.query(Asset).filter(Asset.kind == "mcp").all():
        moment = next_at(asset, every(db, asset))
        if moment and moment <= now:
            found.append(asset)
    return found


def plan(db: Session, asset: Asset) -> dict:
    minutes = every(db, asset)
    moment = next_at(asset, minutes)
    return {"asset_id": asset.id, "asset": asset.label or asset.value, "every_minutes": minutes,
            "last_scan": register._stamp(asset.last_scanned_at),
            "next_scan": moment.isoformat() if moment else None}


def status(db: Session, user: User) -> dict:
    assets = [a for a in db.query(Asset).filter(Asset.kind == "mcp").order_by(Asset.id) if team.sees(db, user, a)]
    plans = [plan(db, asset) for asset in assets]
    return {"enabled": enabled(), "default_minutes": default_minutes(), "choices": list(CHOICES),
            "webhook": bool(os.getenv("ALERT_WEBHOOK_URL", "").strip()),
            "monitored": sum(1 for p in plans if p["every_minutes"]), "plans": plans}


def _counted(names: list, word: str) -> Optional[str]:
    return f"{len(names)} {word}: {', '.join(names[:4])}{'…' if len(names) > 4 else ''}" if names else None


def after_scan(db: Session, asset: Asset, scan: Scan, notify: Callable[[Alert], None]) -> list[Alert]:
    earlier = (db.query(Scan).filter(Scan.asset_id == asset.id, Scan.id < scan.id)
               .order_by(Scan.id.desc()).first())
    if not earlier:
        return []
    label = asset.label or asset.value
    raised = []
    if scan.outcome == register.READ:
        previous = (db.query(Scan).filter(Scan.asset_id == asset.id, Scan.id < scan.id,
                                          Scan.outcome == register.READ)
                    .order_by(Scan.id.desc()).first())
        covered = (db.query(Alert).filter(Alert.asset_id == asset.id, Alert.created_at >= scan.started_at)
                   .count())
        remediated = previous and RANK.get(scan.severity, 0) < RANK.get(previous.severity, 0)
        named = (inventory._named_changes(db, previous.declarations, scan.declarations) or {}
                 if previous and previous.declarations != scan.declarations and not (covered or remediated) else {})
        if named.get("redefined") or named.get("added"):
            parts = [part for part in (_counted(named.get("redefined") or [], "redefined"),
                                       _counted(named.get("added") or [], "added"),
                                       _counted(named.get("removed") or [], "removed")) if part]
            raised.append(Alert(
                user_id=asset.user_id, asset_id=asset.id, kind="change",
                severity="High",
                title=f"Declared tools changed on {label}",
                detail=f"{'; '.join(parts)}. {previous.reference} to {scan.reference}.",
                run_id=scan.reference))
    elif earlier.outcome == register.READ:
        raised.append(Alert(
            user_id=asset.user_id, asset_id=asset.id, kind="unreachable", severity="Medium",
            title=f"{label} stopped answering",
            detail=f"Read on {earlier.reference}; {scan.reference} {ENDED.get(scan.outcome, 'did not read the tool list')}.",
            run_id=scan.reference))
    for alert in raised:
        db.add(alert)
    db.commit()
    for alert in raised:
        notify(alert)
    return raised
