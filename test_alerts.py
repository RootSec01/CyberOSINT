"""Alert tests: escalating drift raises exactly one alert, harmless drift raises
none, the list/ack endpoints work, and alerts are isolated per user."""
import json
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine

import db
import models_db as m
from security import hash_password

LOW = {"services": [{"port": 22, "service": "ssh"}],
       "vulnerabilities": [], "risk": {"level": "Low"}, "vulnerability_count": 0}
HIGH = {"services": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
        "vulnerabilities": [{"cve_id": "CVE-2024-1234"}],
        "risk": {"level": "High"}, "vulnerability_count": 1, "run_id": "cur-run"}


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/alerts.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="alice", password_hash=hash_password("password123")))
        s.add(m.User(username="bob", password_hash=hash_password("password123")))
        s.flush()
        aid = s.query(m.User).filter_by(username="alice").first().id
        s.add(m.Asset(user_id=aid, kind="ip", value="203.0.113.77",
                      label="web", monitoring=True))
    yield


def _alice_asset(s):
    return s.query(m.Asset).filter_by(value="203.0.113.77").first()


def _seed_two_runs(prev_report, cur_report):
    """Reset runs/alerts, then lay down a previous and a current run."""
    now = datetime.now(timezone.utc)
    with db.session_scope() as s:
        a = _alice_asset(s)
        s.query(m.Run).filter_by(target_value=a.value).delete()
        s.query(m.Alert).delete()
        s.add_all([
            m.Run(user_id=a.user_id, run_id="prev", target_type="ip",
                  target_value=a.value, report_json=json.dumps(prev_report),
                  created_at=now - timedelta(hours=1)),
            m.Run(user_id=a.user_id, run_id=cur_report.get("run_id", "cur"),
                  target_type="ip", target_value=a.value,
                  report_json=json.dumps(cur_report), created_at=now),
        ])


def test_escalating_drift_raises_one_alert():
    import main
    _seed_two_runs(LOW, HIGH)
    with db.session_scope() as s:
        a = _alice_asset(s)
        user = s.query(m.User).filter_by(id=a.user_id).first()
        alert = main._maybe_raise_alert(s, user, a, HIGH)
        assert alert is not None
        assert alert.severity == "Critical"          # new CVE -> Critical
        assert s.query(m.Alert).filter_by(user_id=a.user_id).count() == 1


def test_no_change_raises_no_alert():
    import main
    same = {**LOW, "run_id": "cur2"}
    _seed_two_runs(LOW, same)
    with db.session_scope() as s:
        a = _alice_asset(s)
        user = s.query(m.User).filter_by(id=a.user_id).first()
        assert main._maybe_raise_alert(s, user, a, same) is None
        assert s.query(m.Alert).count() == 0


def _client_token(username):
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    tok = c.post("/api/login",
                 data={"username": username, "password": "password123"}).json()["token"]
    return c, {"Authorization": f"Bearer {tok}"}


def test_alerts_endpoint_lists_and_acks():
    import main
    _seed_two_runs(LOW, HIGH)
    with db.session_scope() as s:
        a = _alice_asset(s)
        user = s.query(m.User).filter_by(id=a.user_id).first()
        main._maybe_raise_alert(s, user, a, HIGH)

    c, H = _client_token("alice")
    body = c.get("/api/alerts", headers=H).json()
    assert body["unread"] >= 1 and len(body["alerts"]) >= 1

    aid = body["alerts"][0]["id"]
    acked = c.post(f"/api/alerts/{aid}/ack", headers=H).json()
    assert acked["acknowledged"] is True

    only_unread = c.get("/api/alerts?unacknowledged=true", headers=H).json()
    assert all(al["id"] != aid for al in only_unread["alerts"])


def test_alerts_isolated_between_users():
    c, H = _client_token("bob")
    body = c.get("/api/alerts", headers=H).json()
    assert body["alerts"] == [] and body["unread"] == 0
