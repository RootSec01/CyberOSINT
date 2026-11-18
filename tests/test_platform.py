import dataclasses
import threading

import pytest

from lab import server as lab_server
from observatory.registry import OFFICIAL
from raqeeb import db, listings, main, monitoring
from raqeeb import models as m
from raqeeb.security import hash_password
from tests.test_cases import STATUS, get, signed_in

URL = "https://mcp.docs.example.org/mcp"
ENTRY = {"server": {"name": "org.example/docs", "version": "1.2.0", "title": "Docs search",
                    "description": "Search public documentation",
                    "remotes": [{"type": "streamable-http", "url": URL}]},
         "_meta": {OFFICIAL: {"status": "active", "isLatest": True}}}


@pytest.fixture
def admin(console):
    with db.session_scope() as session:
        session.add(m.User(username="root", role="admin", password_hash=hash_password("password123")))
    return signed_in(console, "root")


@pytest.fixture
def registry(monkeypatch):
    monkeypatch.setattr(listings, "_fetch", lambda params: {"servers": [ENTRY]})
    monkeypatch.setattr(listings, "public_address", lambda host: True)


def test_a_platform_admin_takes_the_console_offline_and_back(console, admin):
    user = signed_in(console, "rami")
    assert console.put("/api/platform", headers=user, data={"online": "false"}).status_code == 403
    switched = console.put("/api/platform", headers=admin, data={"online": "false", "message": "Maintenance"})
    assert switched.json()["online"] is False
    blocked = console.get("/api/inventory", headers=user)
    assert blocked.status_code == 503 and blocked.json()["offline"] is True
    assert console.get("/api/platform").json() == {**switched.json()}
    assert console.get("/api/inventory", headers=admin).status_code == 200
    with db.session_scope() as session:
        assert monitoring.due(session) == []
    console.put("/api/platform", headers=admin, data={"online": "true"})
    assert console.get("/api/inventory", headers=user).status_code == 200
    assert get(console, admin, "/api/audit", action="platform_switched")["entries"]


def test_a_server_outside_the_lab_needs_an_ownership_statement(console):
    user = signed_in(console, "rami")
    refused = console.post("/api/assets", headers=user, data={"kind": "mcp", "value": "mcp.example.com:443"})
    assert refused.status_code == 400 and "own this server" in refused.json()["detail"]
    created = console.post("/api/assets", headers=user,
                           data={"kind": "mcp", "value": "mcp.example.com:443", "attested": "true"})
    assert created.status_code == 201
    basis = get(console, user, f"/api/assets/{created.json()['id']}/detail")["basis"]
    assert basis["kind"] == "attested" and basis["text"].startswith("rami: I own this server")
    assert get(console, user, "/api/audit", action="server_attested")["entries"]


def test_registry_servers_are_confirmed_listed_and_read_at_most_hourly(console, registry):
    user = signed_in(console, "rami")
    found = get(console, user, "/api/registry/search", q="docs")["servers"]
    assert found == [{"server": "org.example/docs", "version": "1.2.0", "url": URL, "title": "Docs search",
                      "description": "Search public documentation", "added": False}]
    assert console.post("/api/registry/add", headers=user, data={"url": URL + "x"}).status_code == 400
    added = console.post("/api/registry/add", headers=user, data={"url": URL})
    assert added.status_code == 201 and added.json()["value"] == URL
    asset = added.json()["id"]
    detail = get(console, user, f"/api/assets/{asset}/detail")
    assert detail["basis"]["kind"] == "registry" and detail["schedule"]["every_minutes"] == 1440
    assert console.put(f"/api/assets/{asset}/schedule", headers=user, data={"every_minutes": 5}).status_code == 400
    assert console.put(f"/api/assets/{asset}/schedule", headers=user, data={"every_minutes": 60}).status_code == 200
    assert get(console, user, "/api/registry/search", q="docs")["servers"][0]["added"] is True
    assert console.delete(f"/api/assets/{asset}", headers=user).status_code == 200


def test_a_full_endpoint_url_is_read_as_given(console):
    user = signed_in(console, "rami")
    lab = lab_server.make_server("modern", 0, tools=[STATUS])
    threading.Thread(target=lab.serve_forever, daemon=True).start()
    try:
        created = console.post("/api/assets", headers=user, data={
            "kind": "mcp", "value": f"http://127.0.0.1:{lab.server_address[1]}/mcp", "label": "url"})
        scan = console.post(f"/api/assets/{created.json()['id']}/scan", headers=user).json()["scan"]
        assert scan["safe_proof"]["tool_count"] == 1
    finally:
        lab.shutdown()
        lab.server_close()


def test_production_refuses_loopback_and_closes_the_older_routes(console, monkeypatch):
    user = signed_in(console, "rami")
    monkeypatch.setattr(main, "DEPLOYMENT", dataclasses.replace(main.DEPLOYMENT, production=True))
    assert console.post("/api/assets", headers=user, data={"kind": "mcp", "value": "127.0.0.1:9"}).status_code == 400
    assert console.post("/api/assets", headers=user, data={"kind": "domain", "value": "example.com"}).status_code == 400
    assert console.post("/api/scan", headers=user, data={"target": "example.com"}).status_code == 404
    created = console.post("/api/assets", headers=user, data={"kind": "mcp", "value": "127.0.0.1:9", "attested": "true"})
    scan = console.post(f"/api/assets/{created.json()['id']}/scan", headers=user).json()["scan"]
    assert scan["skipped"] and "not authorized" in scan["reason"]


def test_sign_ins_are_recorded_and_pages_carry_a_content_policy(console):
    assert console.post("/api/login", data={"username": "rami", "password": "wrong"}).status_code == 401
    user = signed_in(console, "rami")
    actions = [e["action"] for e in get(console, user, "/api/audit")["entries"]]
    assert "signed_in" in actions
    health = console.get("/api/health")
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]
