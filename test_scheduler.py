"""Scheduler tests.

Verify that (1) scanning one asset updates its status and stores a run under its
owner, (2) a monitoring pass scans only assets with monitoring=True, and (3) the
background loop never auto-starts under pytest — it runs only when explicitly
enabled. All scans use a TEST-NET IP so the pass is fully offline.
"""
import tempfile

import pytest
from sqlalchemy import create_engine

import db
import models_db as m
import scheduler


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/scheduler.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="mon", password_hash="x"))
        s.flush()
        uid = s.query(m.User).filter_by(username="mon").first().id
        s.add_all([
            m.Asset(user_id=uid, kind="ip", value="192.0.2.1",
                    label="watched", monitoring=True),
            m.Asset(user_id=uid, kind="ip", value="198.51.100.7",
                    label="paused", monitoring=False),
        ])
    yield


def _owner_and_asset(session, value):
    a = session.query(m.Asset).filter_by(value=value).first()
    owner = session.query(m.User).filter_by(id=a.user_id).first()
    return owner, a


def test_scan_asset_updates_status_and_persists_run():
    from main import scan_asset
    with db.session_scope() as s:
        owner, asset = _owner_and_asset(s, "192.0.2.1")
        before = s.query(m.Run).filter_by(user_id=owner.id).count()
        payload = scan_asset(s, owner, asset)
        assert isinstance(payload, dict)
        # asset status refreshed
        assert asset.last_scanned_at is not None
        assert asset.last_run_id
        # a run was stored for the owner
        after = s.query(m.Run).filter_by(user_id=owner.id).count()
        assert after == before + 1


def test_run_once_scans_only_monitored_assets():
    summary = scheduler.run_once()
    assert summary["scanned"] >= 1
    assert summary["failed"] == 0
    with db.session_scope() as s:
        watched = s.query(m.Asset).filter_by(value="192.0.2.1").first()
        paused = s.query(m.Asset).filter_by(value="198.51.100.7").first()
        assert watched.last_scanned_at is not None   # monitored -> scanned
        assert paused.last_scanned_at is None         # monitoring=False -> skipped


def test_scheduler_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SCHEDULER_ENABLED", raising=False)
    assert scheduler.start_if_enabled() is False      # never auto-runs in tests


def test_scheduler_starts_only_when_enabled(monkeypatch):
    monkeypatch.setenv("SCHEDULER_ENABLED", "true")
    monkeypatch.setenv("SCAN_INTERVAL_MINUTES", "60")
    try:
        started = scheduler.start_if_enabled()
        assert started is True
        assert scheduler._thread is not None
        assert scheduler._thread.daemon is True
    finally:
        scheduler.stop()
