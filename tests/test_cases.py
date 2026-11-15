import threading

import pytest

from lab import server as lab_server
from lab.tampering import PACKAGE, _altered
from raqeeb import db
from raqeeb import models as m
from reference.library import Library


def tool(name, description, **properties):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties}}


SHELL = tool("run_shell_command", "Execute an arbitrary shell command on the host", command={"type": "string"})
STATUS = tool("get_status", "Report service status")
REASON = "Redeployed from the published package and rescanned"


def shipped():
    library = Library()
    _, _, release = list(library.releases(PACKAGE))[-1]
    return library.tools(release["manifest"])


def signed_in(client, username, password="password123"):
    token = client.post("/api/login", data={"username": username, "password": password}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


class Lab:
    def __init__(self, client, headers):
        self.client, self.headers = client, headers
        self.server = lab_server.make_server("legacy", 0, tools=[])
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        created = client.post("/api/assets", headers=headers, data={
            "kind": "mcp", "value": f"127.0.0.1:{self.server.server_address[1]}", "label": "files"})
        self.asset = created.json()["id"]

    def scan(self, tools):
        self.server.RequestHandlerClass = lab_server._make_handler("legacy", None, "dangerous", tools)
        answer = self.client.post(f"/api/assets/{self.asset}/scan", headers=self.headers)
        assert answer.status_code == 200, answer.text
        return answer.json()["scan"]


@pytest.fixture
def lab(console):
    running = Lab(console, signed_in(console, "rami"))
    yield running
    running.server.shutdown()
    running.server.server_close()


def get(client, headers, path, **params):
    answer = client.get(path, headers=headers, params=params)
    assert answer.status_code == 200, answer.text
    return answer.json()


def post(client, headers, path, **form):
    return client.post(path, headers=headers, data=form)


def test_an_altered_published_server_opens_a_case_that_says_who_opened_it_and_why(lab):
    altered, changed = _altered(shipped())
    scan = lab.scan(altered)
    assert len(scan["cases"]) == 1

    case = get(lab.client, lab.headers, f"/api/cases/{scan['cases'][0]}")
    assert case["reference"].startswith("CASE-") and case["status"] == "open"
    assert (case["opened_by"], case["automatic"], case["rule"]) == ("raqeeb", True, "deviation")
    assert case["scan"] == scan["scan_reference"] and case["owner"] is None
    assert case["title"] == "Declared tools differ from the published release"
    assert f"1 redefined: {changed}" in case["reason"] and PACKAGE in case["reason"]
    assert "differ from every release" in case["rule_text"]
    assert {f["tool"] for f in case["findings"]} == {changed}
    opened = case["timeline"][0]
    assert (opened["actor"], opened["kind"]) == ("raqeeb", "opened")
    assert scan["scan_reference"] in opened["text"]
    finding = get(lab.client, lab.headers, f"/api/findings/{case['findings'][0]['reference']}")
    assert finding["case"] == case["reference"]


def test_the_published_server_itself_opens_no_deviation_case(lab):
    lab.scan(shipped())
    assert get(lab.client, lab.headers, "/api/cases", rule="deviation")["total"] == 0


def test_a_repeated_scan_does_not_open_a_second_case(lab):
    first = lab.scan([SHELL, STATUS])["cases"]
    second = lab.scan([SHELL, STATUS])["cases"]
    assert first == second and len(first) == 1
    listed = get(lab.client, lab.headers, "/api/cases")
    assert listed["total"] == 1
    assert listed["cases"][0]["rule"] == "command_execution" and listed["cases"][0]["severity"] == "Critical"
    assert listed["cases"][0]["last_scan"] != listed["cases"][0]["scan"]


def test_closing_needs_a_reason_and_a_note_and_records_who_closed_it(lab):
    reference = lab.scan([SHELL])["cases"][0]
    close = lambda **form: post(lab.client, lab.headers, f"/api/cases/{reference}/close", **form)

    assert close(reason="fixed").status_code == 422
    assert close(reason="done", note=REASON).status_code == 422
    assert close(reason="fixed", note="ok").status_code == 422
    closed = close(reason="risk_accepted", note="Lab host, isolated from production").json()
    assert (closed["status"], closed["closed_by"], closed["closure_reason"]) == ("closed", "rami", "risk_accepted")
    assert closed["closure_note"] == "Lab host, isolated from production"
    assert closed["timeline"][-1]["text"] == "Closed as risk accepted. Lab host, isolated from production"

    for path, form in (("assign", {"owner": "rami"}), ("status", {"status": "investigating"}),
                       ("close", {"reason": "fixed", "note": REASON})):
        assert post(lab.client, lab.headers, f"/api/cases/{reference}/{path}", **form).status_code == 422
    assert post(lab.client, lab.headers, f"/api/cases/{reference}/reopen", note="no").status_code == 422
    reopened = post(lab.client, lab.headers, f"/api/cases/{reference}/reopen", note="Accepted too early").json()
    assert (reopened["status"], reopened["closed_by"], reopened["closure_reason"]) == ("open", None, None)


def test_an_accepted_risk_stays_closed_but_a_fixed_case_reopens_when_seen_again(lab):
    reference = lab.scan([SHELL])["cases"][0]
    close = lambda reason: post(lab.client, lab.headers, f"/api/cases/{reference}/close",
                                reason=reason, note=REASON)
    status = lambda: get(lab.client, lab.headers, f"/api/cases/{reference}")

    close("risk_accepted")
    assert lab.scan([SHELL])["cases"] == [] and status()["status"] == "closed"

    post(lab.client, lab.headers, f"/api/cases/{reference}/reopen", note="Reviewing the decision")
    close("fixed")
    again = lab.scan([SHELL])
    case = status()
    assert again["cases"] == [reference] and case["status"] == "open" and case["closure_reason"] is None
    last = case["timeline"][-1]
    assert (last["actor"], last["kind"]) == ("raqeeb", "reopened")
    assert again["scan_reference"] in last["text"] and "closed as fixed" in last["text"]


def test_a_case_notes_when_its_cause_is_no_longer_observed_and_leaves_closing_to_people(lab):
    reference = lab.scan([SHELL, STATUS])["cases"][0]
    gone = lab.scan([STATUS])
    case = get(lab.client, lab.headers, f"/api/cases/{reference}")
    assert case["status"] == "open" and case["still_observed"] is False
    assert case["timeline"][-1]["text"].startswith(f"Not observed in {gone['scan_reference']}")
    lab.scan([STATUS])
    assert len(get(lab.client, lab.headers, f"/api/cases/{reference}")["timeline"]) == len(case["timeline"])


def test_investigating_takes_ownership_and_notes_join_the_timeline(lab):
    reference = lab.scan([SHELL])["cases"][0]
    moved = post(lab.client, lab.headers, f"/api/cases/{reference}/status", status="investigating").json()
    assert (moved["status"], moved["owner"]) == ("investigating", "rami")
    assert post(lab.client, lab.headers, f"/api/cases/{reference}/status", status="closed").status_code == 422
    noted = post(lab.client, lab.headers, f"/api/cases/{reference}/notes", text="Asked the owner of the host").json()
    assert [event["kind"] for event in noted["timeline"]] == ["opened", "status", "note"]
    assert post(lab.client, lab.headers, f"/api/cases/{reference}/notes", text="  ").status_code == 422
    trail = get(lab.client, lab.headers, "/api/audit", q=reference)["entries"]
    assert {entry["action"] for entry in trail} == {"case_status", "case_note"}


def test_any_finding_can_be_turned_into_a_case_by_hand(lab):
    lab.scan([tool("read_file", "Read a file from disk", path={"type": "string"})])
    finding = get(lab.client, lab.headers, "/api/findings", tool="read_file")["findings"][0]
    assert finding["case"] is None
    assert post(lab.client, lab.headers, "/api/cases", finding=finding["reference"], note="short").status_code == 422
    opened = post(lab.client, lab.headers, "/api/cases", finding=finding["reference"],
                  note="Path is not constrained on this host")
    assert opened.status_code == 201
    case = opened.json()
    assert (case["opened_by"], case["automatic"], case["rule"]) == ("rami", False, "manual")
    assert case["reason"] == "Path is not constrained on this host"
    assert [f["reference"] for f in case["findings"]] == [finding["reference"]]
    assert finding["reference"] in case["timeline"][0]["text"]


def test_cases_filter_by_status_owner_day_and_text(lab):
    reference = lab.scan([SHELL])["cases"][0]
    count = lambda **params: get(lab.client, lab.headers, "/api/cases", **params)["total"]
    today = get(lab.client, lab.headers, f"/api/cases/{reference}")["opened_at"][:10]

    assert count(status="open") == 1 and count(status="closed") == 0
    assert count(owner="none") == 1 and count(owner="rami") == 0
    assert count(on=today) == 1 and count(on="2020-01-01") == 0
    assert count(q=reference) == 1 and count(q="command execution") == 1 and count(q="zzz") == 0
    assert count(opened_by="raqeeb", severity="Critical") == 1

    post(lab.client, lab.headers, f"/api/cases/{reference}/assign", owner="rami")
    post(lab.client, lab.headers, f"/api/cases/{reference}/close", reason="fixed", note=REASON)
    assert count(owner="rami", status="closed", closure="fixed") == 1
    assert count(seen="closed", on=today) == 1
    assert lab.client.get("/api/cases", headers=lab.headers, params={"seen": "never"}).status_code == 422


def test_a_rule_can_be_switched_off_for_new_cases(lab):
    rules = get(lab.client, lab.headers, "/api/case-rules")
    assert [r["rule"] for r in rules["rules"]] == ["deviation", "command_execution"]
    assert all(r["enabled"] for r in rules["rules"]) and "fixed" in rules["closure_reasons"]
    off = lab.client.put("/api/case-rules/command_execution", headers=lab.headers, data={"enabled": "false"})
    assert [r["enabled"] for r in off.json()["rules"]] == [True, False]
    assert lab.scan([SHELL])["cases"] == []
    assert lab.client.put("/api/case-rules/unknown", headers=lab.headers, data={"enabled": "true"}).status_code == 422


def test_cases_are_not_visible_outside_the_team(console, lab):
    reference = lab.scan([SHELL])["cases"][0]
    other = signed_in(console, "outsider")
    assert get(console, other, "/api/cases")["total"] == 0
    assert console.get(f"/api/cases/{reference}", headers=other).status_code == 404
    assert post(console, other, f"/api/cases/{reference}/close", reason="fixed", note=REASON).status_code == 404


def test_search_finds_servers_scans_findings_and_cases(lab):
    scan = lab.scan([SHELL])
    found = lambda text: get(lab.client, lab.headers, "/api/search", q=text)
    assert [s["label"] for s in found("files")["servers"]] == ["files"]
    assert [s["reference"] for s in found(scan["scan_reference"])["scans"]] == [scan["scan_reference"]]
    assert [c["reference"] for c in found(scan["cases"][0])["cases"]] == scan["cases"]
    assert found("FND-")["findings"] and found("shell")["findings"]
    assert all(not found("nothing-like-this")[kind] for kind in ("servers", "scans", "findings", "cases"))
    assert lab.client.get("/api/search", headers=lab.headers, params={"q": "a"}).status_code == 422


def test_deleting_a_server_removes_its_scans_findings_and_cases(lab):
    lab.scan([SHELL])
    assert lab.client.delete(f"/api/assets/{lab.asset}", headers=lab.headers).status_code == 200
    with db.session_scope() as session:
        for table in (m.Scan, m.Finding, m.Case, m.CaseFinding, m.CaseEvent):
            assert session.query(table).count() == 0
