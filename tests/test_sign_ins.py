import pytest

from raqeeb import db
from raqeeb import models as m
from raqeeb.security import hash_password
from raqeeb.team import VIEWER
from tests.test_cases import get, signed_in

BROWSER = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64); probe=1"}


@pytest.fixture
def admin(console):
    with db.session_scope() as session:
        session.add(m.User(username="root", role="admin", password_hash=hash_password("password123")))
    return signed_in(console, "root")


def _viewer(name="viewer"):
    with db.session_scope() as session:
        owner = session.query(m.User).filter_by(username="rami").one()
        viewer = m.User(username=name, password_hash=hash_password("password123"))
        session.add(viewer)
        session.flush()
        session.add(m.Member(user_id=viewer.id, team_id=owner.id, role=VIEWER, created_by="rami"))


def test_sign_ins_and_refusals_are_recorded_with_address_and_browser(console, admin):
    console.post("/api/login", headers=BROWSER, data={"username": "rami", "password": "wrong"})
    console.post("/api/login", headers=BROWSER, data={"username": "rami", "password": "password123"})
    refused = get(console, admin, "/api/audit", action="sign_in_failed")["entries"][0]
    assert refused["operator"] == "rami" and refused["decision"] == "denied" and refused["ip"]
    assert f"ip={refused['ip']}" in refused["detail"]
    assert "agent=Mozilla/5.0 (X11 Linux x86_64) probe 1" in refused["detail"]
    assert get(console, admin, "/api/audit", action="signed_in", operator="rami")["total"] == 1
    integrity = console.get("/api/audit/integrity", headers=admin).json()
    assert integrity["intact"] is True


def test_a_viewer_cannot_mark_the_team_alerts_read(console):
    _viewer()
    viewer = signed_in(console, "viewer")
    assert console.post("/api/alerts/ack-all", headers=viewer).status_code == 403
    assert console.post("/api/alerts/ack-all", headers=signed_in(console, "rami")).status_code == 200


def test_only_administrators_see_other_peoples_sign_ins(console, admin):
    console.post("/api/login", data={"username": "root", "password": "wrong"})
    rami = signed_in(console, "rami")
    assert get(console, rami, "/api/audit", action="sign_in_failed")["total"] == 0
    assert get(console, admin, "/api/audit", action="sign_in_failed")["total"] == 1


def test_visitors_cannot_enter_unless_the_installation_offers_it(console, monkeypatch):
    _viewer()
    assert console.get("/api/platform").json()["guest"] is False
    assert console.post("/api/guest").status_code == 404
    monkeypatch.setenv("GUEST_USER", "rami")
    assert console.post("/api/guest").status_code == 404, "an owner is never a visitor account"
    monkeypatch.setenv("GUEST_USER", "root")
    assert console.post("/api/guest").status_code == 404, "an administrator is never a visitor account"


def test_a_visitor_looks_but_cannot_change_anything(console, admin, monkeypatch):
    _viewer()
    monkeypatch.setenv("GUEST_USER", "viewer")
    assert console.get("/api/platform").json()["guest"] is True
    entered = console.post("/api/guest", headers=BROWSER)
    assert entered.status_code == 200 and entered.json()["guest"] is True
    visitor = {"Authorization": f"Bearer {entered.json()['token']}"}
    assert console.get("/api/assets", headers=visitor).status_code == 200
    added = console.post("/api/assets", headers=visitor, data={"kind": "mcp", "value": "127.0.0.1:9", "label": "x"})
    assert added.status_code == 403
    assert console.post("/api/members", headers=visitor,
                        data={"username": "intruder", "password": "password123", "role": "admin"}).status_code == 403
    assert console.put("/api/platform", headers=visitor, data={"online": "false"}).status_code == 403
    for method, path in (("put", "/api/profile"), ("put", "/api/settings"), ("post", "/api/alerts/ack-all")):
        assert getattr(console, method)(path, headers=visitor, data={"display_name": "x"}).status_code == 403, path
    assert console.post("/api/overview/briefing", headers=visitor).status_code == 200
    visits = get(console, admin, "/api/audit", action="visitor_entered")["entries"]
    assert len(visits) == 1 and visits[0]["operator"] == "visitor" and visits[0]["ip"]
    assert get(console, visitor, "/api/audit", action="visitor_entered")["total"] == 0, \
        "visitors never see each other's addresses"
