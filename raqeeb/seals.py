"""A hash chain over the audit log: each entry's seal covers the entry and the seal before it.

The chain shows that a sealed entry was edited or removed. It does not stop someone with
database access from rewriting the whole chain.
"""
from __future__ import annotations

import hashlib
import json
import threading

from sqlalchemy.orm import Session

from raqeeb.models import AuditEntry, AuditSeal

START = "0" * 64
_one_writer = threading.Lock()


def _digest(previous: str, entry: AuditEntry) -> str:
    moment = entry.ts.replace(tzinfo=None).isoformat(timespec="seconds") if entry.ts else ""
    fields = [entry.id, moment, entry.action, entry.operator, entry.decision, entry.detail]
    return hashlib.sha256((previous + json.dumps(fields, ensure_ascii=False)).encode("utf-8")).hexdigest()


def record(db: Session, **fields) -> AuditEntry:
    with _one_writer:
        entry = AuditEntry(**fields)
        db.add(entry)
        db.flush()
        last = db.query(AuditSeal).order_by(AuditSeal.id.desc()).first()
        previous = last.digest if last else START
        db.add(AuditSeal(entry_id=entry.id, previous=previous, digest=_digest(previous, entry)))
        db.commit()
        return entry


def check(db: Session) -> dict:
    seals = db.query(AuditSeal).order_by(AuditSeal.id).all()
    entries = {entry.id: entry for entry in db.query(AuditEntry)}
    previous = START
    for seal in seals:
        entry = entries.get(seal.entry_id)
        if entry is None:
            return {"intact": False, "sealed": len(seals), "broken_at": seal.entry_id,
                    "reason": "a sealed entry was removed"}
        if seal.previous != previous or seal.digest != _digest(previous, entry):
            return {"intact": False, "sealed": len(seals), "broken_at": seal.entry_id,
                    "reason": "a sealed entry or its seal was changed"}
        previous = seal.digest
    return {"intact": True, "sealed": len(seals), "unsealed": len(entries) - len(seals),
            "head": previous if seals else None}
