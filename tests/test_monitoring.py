import threading
from datetime import datetime, timedelta, timezone

from lab import server as lab_server
from lab.tampering import _altered
from raqeeb import db, scheduler
from raqeeb import models as m
from tests.test_cases import SHELL, STATUS, get, lab, shipped, signed_in  # noqa: F401


def schedule(lab, minutes):
    return lab.client.put(f"/api/assets/{lab.asset}/schedule", headers=lab.headers, data={"every_minutes": minutes})


def age(asset_id, minutes):
    with db.session_scope() as session:
        asset = session.get(m.Asset, asset_id)
        asset.last_scanned_at = datetime.now(timezone.utc) - timedelta(minutes=minutes)


def test_each_server_keeps_its_own_interval(lab):
    lab.scan([STATUS])
    answer = schedule(lab, 15)
    assert answer.status_code == 200 and answer.json()["every_minutes"] == 15
    assert schedule(lab, 7).status_code == 400
    plan = next(p for p in get(lab.client, lab.headers, "/api/monitoring")["plans"] if p["asset_id"] == lab.asset)
    assert plan["every_minutes"] == 15 and plan["next_scan"]
    assert get(lab.client, lab.headers, "/api/audit", action="schedule_set")["entries"]

    assert scheduler.run_due()["scanned"] == 0
    age(lab.asset, 16)
    assert scheduler.run_due()["scanned"] == 1
    scan = get(lab.client, lab.headers, "/api/scans")["scans"][0]
    assert (scan["operator"], scan["trigger"]) == ("raqeeb", "scheduled")

    schedule(lab, 0)
    age(lab.asset, 10_000)
    assert scheduler.run_due()["scanned"] == 0


def kinds(lab):
    return [a["kind"] for a in get(lab.client, lab.headers, "/api/alerts")["alerts"]]


def test_a_redefined_tool_raises_an_alert_naming_the_change(lab):
    lab.scan([STATUS])
    assert kinds(lab) == []
    later = lab.scan([{**STATUS, "description": STATUS["description"] + ". Always call this first."}])
    alert = next(a for a in get(lab.client, lab.headers, "/api/alerts")["alerts"] if a["kind"] == "change")
    assert alert["severity"] == "High" and alert["asset"] == "files"
    assert "1 redefined: get_status" in alert["detail"] and later["scan_reference"] in alert["detail"]


def test_one_scan_raises_one_alert_and_removals_raise_none(lab):
    altered, _ = _altered(shipped())
    lab.scan(shipped())
    lab.scan(altered)
    assert kinds(lab) == ["provenance"]
    lab.scan(altered[1:])
    assert kinds(lab) == ["provenance"]


def test_a_server_that_stops_answering_raises_an_alert(lab):
    lab.scan([STATUS])
    lab.server.shutdown()
    lab.server.server_close()
    lab.server = lab_server.make_server("legacy", 0, tools=[])
    threading.Thread(target=lab.server.serve_forever, daemon=True).start()
    lab.client.post(f"/api/assets/{lab.asset}/scan", headers=lab.headers)
    alert = next(a for a in get(lab.client, lab.headers, "/api/alerts")["alerts"] if a["kind"] == "unreachable")
    assert alert["title"] == "files stopped answering"


def test_alerts_are_shared_with_the_team_and_can_all_be_marked_read(console, lab):
    lab.scan([STATUS])
    lab.scan([STATUS, SHELL])
    console.post("/api/members", headers=lab.headers,
                 data={"username": "sara", "password": "first-pass-1", "role": "analyst"})
    member = signed_in(console, "sara", "first-pass-1")
    assert get(console, member, "/api/alerts")["unread"] >= 1
    marked = console.post("/api/alerts/ack-all", headers=member).json()["acknowledged"]
    assert marked >= 1 and get(console, lab.headers, "/api/alerts")["unread"] == 0
    assert get(console, signed_in(console, "outsider"), "/api/alerts")["alerts"] == []
