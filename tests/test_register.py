import tempfile
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from lab import server as lab_server
from raqeeb import db, register
from raqeeb import models as m
from raqeeb.security import hash_password


def tool(name, description, **properties):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties}}


SHELL = tool("run_shell_command", "Execute an arbitrary shell command on the host", command={"type": "string"})
READER = tool("read_file", "Read a file from disk", path={"type": "string"})
STATUS = tool("get_status", "Report service status")


@pytest.fixture
def console():
    engine = create_engine(f"sqlite:///{tempfile.mkdtemp()}/register.db",
                           connect_args={"check_same_thread": False}, future=True)
    db.engine = engine
    db.SessionLocal.configure(bind=engine)
    db.init_db()
    with db.session_scope() as session:
        session.add_all([m.User(username="rami", password_hash=hash_password("password123")),
                         m.User(username="noor", password_hash=hash_password("password123")),
                         m.User(username="root", role="admin", password_hash=hash_password("password123"))])
    from raqeeb import main
    return TestClient(main.app)


def signed_in(client, username):
    token = client.post("/api/login", data={"username": username, "password": "password123"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


class Lab:
    """A loopback MCP server whose declared tools can be swapped between scans."""

    def __init__(self, client, headers, label="lab"):
        self.client, self.headers = client, headers
        self.server = lab_server.make_server("legacy", 0, tools=[])
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        created = client.post("/api/assets", headers=headers,
                              data={"kind": "mcp", "value": f"127.0.0.1:{self.port}", "label": label})
        assert created.status_code == 201, created.text
        self.asset = created.json()["id"]

    def scan(self, tools, **paging):
        self.server.RequestHandlerClass = lab_server._make_handler("legacy", None, "dangerous", tools, **paging)
        answer = self.client.post(f"/api/assets/{self.asset}/scan", headers=self.headers)
        assert answer.status_code == 200, answer.text
        return answer.json()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def lab(console):
    running = Lab(console, signed_in(console, "rami"))
    yield running
    running.close()


def listed(client, headers, path, **params):
    answer = client.get(path, headers=headers, params=params)
    assert answer.status_code == 200, answer.text
    return answer.json()


def test_every_scan_gets_its_own_reference(lab):
    first = lab.scan([SHELL, STATUS])
    second = lab.scan([SHELL, STATUS])
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    assert first["scan"]["scan_reference"].startswith(f"SCN-{today}-")
    assert first["scan"]["scan_reference"] != second["scan"]["scan_reference"]
    assert second["asset"]["last_scan"] == second["scan"]["scan_reference"]

    scans = listed(lab.client, lab.headers, "/api/scans")
    assert scans["total"] == 2
    latest = scans["scans"][0]
    assert latest["reference"] == second["scan"]["scan_reference"]
    assert (latest["outcome"], latest["operator"], latest["trigger"]) == ("read", "rami", "manual")
    assert latest["tool_count"] == 2 and latest["finding_count"] >= 1
    assert latest["declarations"] == scans["scans"][1]["declarations"]


def test_a_scan_can_be_opened_by_reference_with_its_report_and_findings(lab):
    reference = lab.scan([SHELL])["scan"]["scan_reference"]
    opened = listed(lab.client, lab.headers, f"/api/scans/{reference.lower()}")
    assert opened["reference"] == reference
    assert opened["report"]["safe_proof"]["tool_count"] == 1
    assert {f["first_scan"] for f in opened["findings"]} == {reference}
    assert lab.client.get("/api/scans/SCN-19990101-9999", headers=lab.headers).status_code == 404


def test_a_finding_keeps_its_reference_across_scans(lab):
    first = lab.scan([SHELL, READER])["scan"]["scan_reference"]
    before = {f["reference"]: f for f in listed(lab.client, lab.headers, "/api/findings")["findings"]}
    second = lab.scan([SHELL, READER])["scan"]["scan_reference"]
    after = {f["reference"]: f for f in listed(lab.client, lab.headers, "/api/findings")["findings"]}

    assert before.keys() == after.keys() and before
    assert all(reference.startswith("FND-") for reference in after)
    assert {f["first_scan"] for f in after.values()} == {first}
    assert {f["last_scan"] for f in after.values()} == {second}
    assert {f["status"] for f in after.values()} == {"open"}
    assert {f["status_by"] for f in after.values()} == {"raqeeb"}


def test_a_finding_resolves_when_a_scan_no_longer_sees_it_and_reopens_if_it_returns(lab):
    lab.scan([SHELL, STATUS])
    shell = listed(lab.client, lab.headers, "/api/findings", tool="run_shell_command")["findings"][0]

    gone = lab.scan([STATUS])["scan"]["scan_reference"]
    resolved = listed(lab.client, lab.headers, f"/api/findings/{shell['reference']}")
    assert (resolved["status"], resolved["status_by"]) == ("resolved", "raqeeb")
    assert resolved["status_note"] == f"Not declared in {gone}"

    back = lab.scan([SHELL, STATUS])["scan"]["scan_reference"]
    reopened = listed(lab.client, lab.headers, f"/api/findings/{shell['reference']}")
    assert (reopened["status"], reopened["status_note"]) == ("open", f"Seen again in {back}")
    assert reopened["first_scan"] == shell["first_scan"]


def test_a_listing_that_fails_part_way_resolves_nothing(lab):
    lab.scan([SHELL, STATUS, READER])
    reader = listed(lab.client, lab.headers, "/api/findings", tool="read_file")["findings"][0]

    # the server lists one tool per page and fails on the second page: read_file was never read
    partial = lab.scan([SHELL, STATUS, READER], page_size=1, broken_page=1)
    assert partial["scan"]["safe_proof"]["tool_count"] == 1
    kept = listed(lab.client, lab.headers, f"/api/findings/{reader['reference']}")
    assert kept["status"] == "open"
    assert kept["last_scan"] == reader["last_scan"]


def test_a_listing_cut_at_the_page_limit_resolves_nothing(lab):
    from raqeeb import mcp_protocol
    many = [SHELL] + [tool(f"status_{n}", "Report service status") for n in range(mcp_protocol._MAX_TOOL_PAGES)] + [READER]
    lab.scan(many)
    reader = listed(lab.client, lab.headers, "/api/findings", tool="read_file")["findings"][0]

    # one tool per page: the client stops at its page limit with read_file still unread
    lab.scan(many, page_size=1)
    kept = listed(lab.client, lab.headers, f"/api/findings/{reader['reference']}")
    assert kept["status"] == "open"


def test_a_complete_paged_listing_still_resolves_what_it_no_longer_declares(lab):
    lab.scan([SHELL, STATUS, READER])
    reader = listed(lab.client, lab.headers, "/api/findings", tool="read_file")["findings"][0]

    gone = lab.scan([SHELL, STATUS], page_size=1)["scan"]["scan_reference"]
    resolved = listed(lab.client, lab.headers, f"/api/findings/{reader['reference']}")
    assert (resolved["status"], resolved["status_note"]) == ("resolved", f"Not declared in {gone}")


def test_people_change_status_with_a_reason_and_cannot_resolve_by_hand(lab):
    lab.scan([SHELL])
    reference = listed(lab.client, lab.headers, "/api/findings")["findings"][0]["reference"]
    change = lambda **form: lab.client.post(f"/api/findings/{reference}/status", headers=lab.headers, data=form)

    assert change(status="acknowledged").json()["status_by"] == "rami"
    assert change(status="risk_accepted").status_code == 422
    assert change(status="risk_accepted", note="too short").status_code == 422
    accepted = change(status="risk_accepted", note="Lab host, isolated from production").json()
    assert (accepted["status"], accepted["status_note"]) == ("risk_accepted", "Lab host, isolated from production")
    assert change(status="resolved").status_code == 422
    assert change(status="closed").status_code == 422

    lab.scan([SHELL])
    assert listed(lab.client, lab.headers, f"/api/findings/{reference}")["status"] == "risk_accepted"

    trail = listed(lab.client, lab.headers, "/api/audit", action="finding_status")["entries"]
    assert [e["decision"] for e in trail] == ["risk_accepted", "acknowledged"]
    assert reference in trail[0]["detail"]


def test_findings_filter_by_field_text_and_person(lab):
    lab.scan([SHELL, READER])
    everything = listed(lab.client, lab.headers, "/api/findings")
    critical = listed(lab.client, lab.headers, "/api/findings", severity="Critical")
    assert 0 < critical["total"] < everything["total"]
    assert {f["severity"] for f in critical["findings"]} == {"Critical"}

    by_tool = listed(lab.client, lab.headers, "/api/findings", tool="read_file")
    assert by_tool["total"] >= 1 and {f["tool"] for f in by_tool["findings"]} == {"read_file"}
    assert listed(lab.client, lab.headers, "/api/findings", q="shell")["total"] >= 1
    assert listed(lab.client, lab.headers, "/api/findings", q=by_tool["findings"][0]["reference"])["total"] == 1

    reference = by_tool["findings"][0]["reference"]
    lab.client.post(f"/api/findings/{reference}/status", headers=lab.headers, data={"status": "acknowledged"})
    mine = listed(lab.client, lab.headers, "/api/findings", changed_by="rami", status="acknowledged")
    assert [f["reference"] for f in mine["findings"]] == [reference]
    assert len(listed(lab.client, lab.headers, "/api/findings", limit=1)["findings"]) == 1


def test_records_filter_by_day_and_by_time_range(lab):
    lab.scan([SHELL])
    earlier = datetime(2026, 11, 14, 9, 30, tzinfo=timezone.utc)
    with db.session_scope() as session:
        old = session.query(m.Scan).one()
        old.started_at = earlier
        for row in session.query(m.Finding):
            row.first_seen_at = earlier
    lab.scan([SHELL])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    scans = lambda **params: listed(lab.client, lab.headers, "/api/scans", **params)["total"]

    assert scans(on="2026-11-14") == 1 and scans(on=today) == 1 and scans(on="2026-11-13") == 0
    assert scans(since="2026-11-14T09:00", until="2026-11-14T10:00") == 1
    assert scans(since="2026-11-14T09:31", until="2026-11-14T10:00") == 0
    assert scans(since="2026-11-14", until=today) == 2
    assert scans(until="2026-11-14") == 1
    assert scans(operator="rami", on="2026-11-14") == 1 and scans(operator="noor") == 0

    assert listed(lab.client, lab.headers, "/api/findings", on="2026-11-14")["total"] >= 1
    assert listed(lab.client, lab.headers, "/api/findings", on="2026-11-14", seen="last")["total"] == 0
    assert listed(lab.client, lab.headers, "/api/audit", on="2026-11-14")["total"] == 0

    for bad in ({"on": "14/11/2026"}, {"since": "2026-11-15", "until": "2026-11-14T00:00"},
                {"on": today, "since": today}):
        assert lab.client.get("/api/scans", headers=lab.headers, params=bad).status_code == 422
    assert lab.client.get("/api/findings", headers=lab.headers, params={"seen": "never"}).status_code == 422


def test_records_stay_with_their_owner_and_admins_see_all(console, lab):
    reference = lab.scan([SHELL])["scan"]["scan_reference"]
    finding = listed(console, lab.headers, "/api/findings")["findings"][0]["reference"]
    other, admin = signed_in(console, "noor"), signed_in(console, "root")

    assert listed(console, other, "/api/scans")["total"] == 0
    assert listed(console, other, "/api/findings")["total"] == 0
    assert console.get(f"/api/scans/{reference}", headers=other).status_code == 404
    assert console.get(f"/api/findings/{finding}", headers=other).status_code == 404
    refused = console.post(f"/api/findings/{finding}/status", headers=other, data={"status": "acknowledged"})
    assert refused.status_code == 404
    assert listed(console, admin, "/api/scans")["total"] == 1
    assert listed(console, admin, "/api/findings", q=finding)["total"] == 1


def test_scheduled_scans_are_recorded_under_raqeeb(console, lab):
    from raqeeb import scheduler
    lab.server.RequestHandlerClass = lab_server._make_handler("legacy", None, "dangerous", [SHELL])
    scheduler.run_once()
    scan = listed(console, lab.headers, "/api/scans")["scans"][0]
    assert (scan["operator"], scan["trigger"]) == ("raqeeb", "scheduled")


def test_a_server_that_asks_for_a_credential_is_recorded_without_findings(console):
    headers = signed_in(console, "rami")
    guarded = lab_server.make_server("legacy", 0, auth_token="lab-token")
    threading.Thread(target=guarded.serve_forever, daemon=True).start()
    try:
        created = console.post("/api/assets", headers=headers, data={
            "kind": "mcp", "value": f"127.0.0.1:{guarded.server_address[1]}", "label": "guarded"})
        console.post(f"/api/assets/{created.json()['id']}/scan", headers=headers)
    finally:
        guarded.shutdown()
        guarded.server_close()
    scan = listed(console, headers, "/api/scans")["scans"][0]
    assert scan["outcome"] == register.AUTH_REQUIRED and scan["finding_count"] is None
    assert listed(console, headers, "/api/findings")["total"] == 0


def test_window_reads_days_and_instants():
    day = datetime(2026, 11, 15, tzinfo=timezone.utc)
    assert register.window(on="2026-11-15") == (day, day + timedelta(days=1))
    assert register.window(since="2026-11-15T10:00+04:00")[0] == datetime(2026, 11, 15, 6, tzinfo=timezone.utc)
    assert register.window(until="2026-11-15") == (None, day + timedelta(days=1))
    assert register.window() == (None, None)
