"""Background monitoring scheduler for CyberOSINT.

Every asset flagged ``monitoring=True`` is re-scanned on a fixed interval so the
platform behaves like continuous EASM rather than one-shot scanning. A single
daemon thread wakes every ``SCAN_INTERVAL_MINUTES`` (default 60), runs one pass
over all monitored assets, and updates each asset's last-scan status.

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
    SCAN_INTERVAL_MINUTES minutes between passes (default 60, floor 1)
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict

log = logging.getLogger("cyberosint.scheduler")

_thread: threading.Thread | None = None
_stop = threading.Event()


def _enabled() -> bool:
    return os.getenv("SCHEDULER_ENABLED", "false").strip().lower() == "true"


def _interval_seconds() -> int:
    try:
        minutes = int(os.getenv("SCAN_INTERVAL_MINUTES", "60"))
    except ValueError:
        minutes = 60
    return max(60, minutes * 60)  # never tighter than one minute


def run_once() -> Dict[str, Any]:
    """Run one monitoring pass over every asset with ``monitoring=True``.

    Returns a summary dict. Safe to call directly (this is what the tests use);
    each asset is scanned in isolation so one failure never aborts the pass.
    """
    # Imported here, not at module load, to avoid a circular import with main.
    from db import SessionLocal
    from main import scan_asset
    from models_db import Asset, User

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
                scan_asset(db, owner, asset)
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


def _loop() -> None:
    # Wait one interval before the first pass (don't hammer at boot).
    while not _stop.wait(_interval_seconds()):
        try:
            run_once()
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
        target=_loop, name="cyberosint-scheduler", daemon=True)
    _thread.start()
    log.info("scheduler started (interval=%ss)", _interval_seconds())
    return True


def stop() -> None:
    """Signal the loop to stop (used in tests / graceful shutdown)."""
    _stop.set()
