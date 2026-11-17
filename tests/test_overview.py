import pytest

from tests.test_cases import Lab, REASON, SHELL, STATUS, get, post, shipped, signed_in


@pytest.fixture
def lab(console):
    running = Lab(console, signed_in(console, "rami"))
    yield running
    running.server.shutdown()
    running.server.server_close()


def test_overview_counts_follow_the_estate(console, lab):
    headers = lab.headers
    lab.scan([STATUS, SHELL])
    seen = get(console, headers, "/api/overview")
    assert seen["servers"]["total"] == 1 and seen["servers"]["read"] == 1
    assert seen["servers"]["tools"] == 2
    assert seen["findings"]["open"] >= 1
    assert seen["cases"]["open"] == 1 and seen["cases"]["unassigned"] == 1
    assert seen["risky"][0]["label"] == "files"
    assert seen["last_scan"] is not None
    reference = seen["cases"]["latest"][0]["reference"]
    assert post(console, headers, f"/api/cases/{reference}/close", reason="fixed", note=REASON).status_code == 200
    assert get(console, headers, "/api/overview")["cases"]["open"] == 0


def test_briefing_is_written_from_stored_rows_and_audited(console, lab):
    headers = lab.headers
    lab.scan(shipped())
    text = console.post("/api/overview/briefing", headers=headers).json()["text"]
    assert "1 server registered" in text
    assert "No server deviates" in text
    assert "nothing left the platform" in text
    entries = get(console, headers, "/api/audit", action="briefing")["entries"]
    assert entries and entries[0]["decision"] == "written"


def test_overview_is_scoped_to_the_team(console, lab):
    lab.scan([SHELL])
    other = signed_in(console, "outsider")
    seen = get(console, other, "/api/overview")
    assert seen["servers"]["total"] == 0 and seen["cases"]["open"] == 0
