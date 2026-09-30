"""Settings tests: defaults to offline, validates + updates, isolated per user."""
import tempfile

import pytest
from sqlalchemy import create_engine

import db
import models_db as m
from security import hash_password


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/settings.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="sam", password_hash=hash_password("password123")))
        s.add(m.User(username="tom", password_hash=hash_password("password123")))
    yield


def _tok(username):
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    t = c.post("/api/login",
               data={"username": username, "password": "password123"}).json()["token"]
    return c, {"Authorization": f"Bearer {t}"}


def test_settings_default_is_offline():
    c, H = _tok("sam")
    body = c.get("/api/settings", headers=H).json()
    assert body["ai_mode"] == "offline"
    assert set(body["modes"]) == {"offline", "redacted", "local"}
    assert "openai" in body["providers"] and "anthropic" in body["providers"]
    assert "keys_present" in body


def test_settings_update_and_validation():
    c, H = _tok("sam")
    ok = c.put("/api/settings",
               data={"ai_mode": "redacted", "ai_provider": "anthropic"}, headers=H).json()
    assert ok["ai_mode"] == "redacted" and ok["ai_provider"] == "anthropic"
    bad = c.put("/api/settings", data={"ai_mode": "bogus"}, headers=H)
    assert bad.status_code == 400


def test_settings_isolated_between_users():
    c, H = _tok("sam")
    c.put("/api/settings", data={"ai_mode": "local"}, headers=H)
    c2, H2 = _tok("tom")
    assert c2.get("/api/settings", headers=H2).json()["ai_mode"] == "offline"
