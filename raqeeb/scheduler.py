"""Background monitoring scheduler.

Every monitored MCP server is rescanned on its own interval (Settings or the
server page; ``SCAN_INTERVAL_MINUTES`` when none was chosen). A single daemon
thread wakes every ``SCHEDULER_TICK_SECONDS`` (default 30) and scans the
servers whose interval has passed.

Design choices (deliberately conservative):
  * A plain ``threading.Thread(daemon=True)`` — zero new dependencies. The
    scan cadence (hourly) makes a heavyweight scheduler unnecessary for now.
  * OFF unless ``SCHEDULER_ENABLED=true``. Importing this module never starts a
    thread, so the test suite and any tooling that imports ``main`` stay inert
    and deterministic; the loop only runs in a real deployment that opts in.
  * The per-asset work lives in ``main.scan_asset`` (imported lazily to avoid a
    circular import), so the scheduler, the manual "scan now" endpoint, and the
    ``/api/scan`` endpoint all share one code path.

Env:
    SCHEDULER_ENABLED     "true" to run the loop (default: off)
    SCAN_INTERVAL_MINUTES default interval for a monitored server (default 60)
    SCHEDULER_TICK_SECONDS how often the loop looks for due servers (default 30)
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict

log = logging.getLogger("raqeeb.scheduler")

_thread: threading.Thread | None = None
_stop = threading.Event()


def _enabled() -> bool:
    return os.getenv("SCHEDULER_ENABLED", "false").strip().lower() == "true"


def run_once() -> Dict[str, Any]:
    """Run one monitoring pass over every asset with ``monitoring=True``.

    Returns a summary dict. Safe to call directly (this is what the tests use);
    each asset is scanned in isolation so one failure never aborts the pass.
    """
    # Imported here, not at module load, to avoid a circular import with main.
    from raqeeb.db import SessionLocal
    from raqeeb.main import scan_asset
    from raqeeb.models import Asset, User

    scanned = skipped = failed = 0
    db = SessionLocal()
    try:
        assets = (
            db.query(Asset).filter(Asset.monitoring == True).all()  # noqa: E712
        )
        for asset in assets:
            owner = db.query(User).filter(User.id == asset.user_id).first()
            if not owner or not owner.is_active:
                skipped += 1
                continue
            try:
                scan_asset(db, owner, asset, operator="raqeeb", trigger="scheduled")
                scanned += 1
            except Exception as exc:  # keep going across assets
                failed += 1
                log.warning("scheduled scan failed for asset %s: %s",
                            getattr(asset, "id", "?"), exc)
    finally:
        db.close()

    summary = {
        "scanned": scanned,
        "skipped": skipped,
        "failed": failed,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    log.info("monitoring pass complete: %s", summary)
    return summary


def _tick_seconds() -> int:
    try:
        return max(5, int(os.getenv("SCHEDULER_TICK_SECONDS", "30")))
    except ValueError:
        return 30


def run_due() -> Dict[str, Any]:
    """Scan every server whose own interval has passed since its last scan."""
    from raqeeb import monitoring
    from raqeeb.db import SessionLocal
    from raqeeb.main import scan_asset
    from raqeeb.models import User

    scanned = failed = 0
    db = SessionLocal()
    try:
        for asset in monitoring.due(db):
            owner = db.query(User).filter(User.id == asset.user_id).first()
            if not owner or not owner.is_active:
                continue
            try:
                scan_asset(db, owner, asset, operator="raqeeb", trigger="scheduled")
                scanned += 1
            except Exception as exc:
                db.rollback()
                failed += 1
                log.warning("scheduled scan failed for asset %s: %s", asset.id, exc)
    finally:
        db.close()
    return {"scanned": scanned, "failed": failed, "at": datetime.now(timezone.utc).isoformat()}


def _loop() -> None:
    while not _stop.wait(_tick_seconds()):
        try:
            run_due()
        except Exception as exc:  # a bad pass must never kill the loop
            log.error("scheduler loop error: %s", exc)


def start_if_enabled() -> bool:
    """Start the daemon loop iff SCHEDULER_ENABLED=true. No-op otherwise.

    Returns True only when this call actually started the thread.
    """
    global _thread
    if not _enabled():
        return False
    if _thread is not None and _thread.is_alive():
        return False
    _stop.clear()
    _thread = threading.Thread(
        target=_loop, name="raqeeb-scheduler", daemon=True)
    _thread.start()
    log.info("scheduler started (tick=%ss)", _tick_seconds())
    return True


def stop() -> None:
    """Signal the loop to stop (used in tests / graceful shutdown)."""
    _stop.set()
