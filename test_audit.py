"""Audit tests: privacy-setting changes and copilot calls are recorded, with no
sensitive content, and the log is isolated per non-admin user."""
import tempfile

import pytest
from sqlalchemy import create_engine

import db
import models_db as m
from security import hash_password


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/audit.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="ida", password_hash=hash_password("password123")))
        s.add(m.User(username="joe", password_hash=hash_password("password123")))
        s.flush()
        uid = s.query(m.User).filter_by(username="ida").first().id
        s.add(m.Asset(user_id=uid, kind="ip", value="192.0.2.5", monitoring=True))
    yield


def _tok(username):
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    t = c.post("/api/login",
               data={"username": username, "password": "password123"}).json()["token"]
    return c, {"Authorization": f"Bearer {t}"}


def test_settings_change_is_audited():
    c, H = _tok("ida")
    c.put("/api/settings", data={"ai_mode": "redacted", "ai_provider": "openai"}, headers=H)
    entries = c.get("/api/audit", headers=H).json()["entries"]
    hits = [e for e in entries if e["action"] == "privacy_settings_update"]
    assert hits
    assert "mode=redacted" in hits[0]["detail"] and "provider=openai" in hits[0]["detail"]


def test_copilot_call_is_audited_without_sensitive_data():
    c, H = _tok("ida")
    with db.session_scope() as s:
        aid = s.query(m.Asset).filter_by(value="192.0.2.5").first().id
    c.post(f"/api/assets/{aid}/copilot",
           data={"question": "secret question mentioning 192.0.2.5"}, headers=H)
    entries = c.get("/api/audit", headers=H).json()["entries"]
    cop = [e for e in entries if e["action"] == "copilot_query"]
    assert cop, "copilot query should be audited"
    blob = str(cop)
    assert "secret question" not in blob and "192.0.2.5" not in blob
    assert "mode=" in cop[0]["detail"] and "ai_called=" in cop[0]["detail"]


def test_audit_isolated_between_users():
    c2, H2 = _tok("joe")
    c2.put("/api/settings", data={"ai_mode": "local"}, headers=H2)
    entries = c2.get("/api/audit", headers=H2).json()["entries"]
    assert entries and all(e["operator"] == "joe" for e in entries)  # never sees ida's
