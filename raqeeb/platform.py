"""The console's on/off switch."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from raqeeb import register
from raqeeb.models import PlatformState, User

OPEN_PATHS = ("/api/login", "/api/health", "/api/platform", "/api/public/")


def state(db: Session) -> PlatformState:
    return db.get(PlatformState, 1) or PlatformState(id=1, online=True)


def is_online(db: Session) -> bool:
    return state(db).online


def as_dict(db: Session) -> dict:
    row = state(db)
    return {"online": row.online, "message": row.message, "changed_by": row.changed_by,
            "changed_at": register._stamp(row.changed_at)}


def switch(db: Session, by: User, online: bool, message: str = "") -> PlatformState:
    row = state(db)
    row.online, row.message = online, (message.strip()[:500] or None)
    row.changed_by, row.changed_at = by.username, datetime.now(timezone.utc)
    db.merge(row)
    db.commit()
    return state(db)


def gated(path: str) -> bool:
    return path.startswith("/api/") and not path.startswith(OPEN_PATHS)
