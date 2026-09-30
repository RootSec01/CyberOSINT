"""Deployment-readiness tests: health probe, CORS, security headers, SPA root,
and login rate limiting (brute-force protection)."""
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

import db
import models_db as m
from security import hash_password


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/deploy.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="dev", password_hash=hash_password("password123")))
    yield


def _client():
    import main
    return TestClient(main.app)


def test_health_probe_ok():
    r = _client().get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["database"]["connected"] is True


def test_cors_allows_configured_origin():
    r = _client().get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_security_headers_present():
    r = _client().get("/api/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_spa_root_serves_placeholder_without_build():
    # No dist build in the test workspace -> API placeholder, still 200.
    r = _client().get("/")
    assert r.status_code == 200
    assert "CyberOSINT" in r.text


def test_login_not_rate_limited_by_default():
    import main
    assert main.limiter.enabled is False
    c = _client()
    codes = [c.post("/api/login",
                    data={"username": "nope", "password": "bad"}).status_code
             for _ in range(15)]
    assert 429 not in codes


def test_login_rate_limited_when_enabled():
    import main
    main.limiter.enabled = True
    try:
        c = _client()
        codes = [c.post("/api/login",
                        data={"username": "nope", "password": "bad"}).status_code
                 for _ in range(12)]
        assert 429 in codes            # brute-force burst is throttled
    finally:
        main.limiter.enabled = False   # restore global state for other tests
        main.limiter.reset()
