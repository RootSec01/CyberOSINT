import pytest

from lab.tampering import PACKAGE, _altered
from tests.test_cases import SHELL, STATUS, Lab, get, shipped, signed_in, tool


@pytest.fixture
def lab(console):
    running = Lab(console, signed_in(console, "rami"))
    yield running
    running.server.shutdown()
    running.server.server_close()


def test_the_inventory_row_summarises_the_latest_scan(lab):
    assert get(lab.client, lab.headers, "/api/inventory")["servers"][0]["scan"] is None
    scan = lab.scan([SHELL, STATUS])
    row = get(lab.client, lab.headers, "/api/inventory")["servers"][0]
    assert (row["label"], row["scan"]["reference"]) == ("files", scan["scan_reference"])
    assert (row["scan"]["outcome"], row["scan"]["severity"], row["scan"]["tool_count"]) == ("read", "Critical", 2)
    assert row["open_findings"] >= 2 and row["flagged_tools"] == 1 and row["open_cases"] == 1
    assert row["last_change"] is None


def test_the_server_page_shows_each_tool_with_its_text_and_the_published_text(lab):
    altered, changed = _altered(shipped())
    lab.scan(altered)
    page = get(lab.client, lab.headers, f"/api/assets/{lab.asset}/detail")

    assert page["auth_required"] is False and page["provenance"]["verdict"] == "deviation"
    assert page["provenance"]["package"] == PACKAGE and page["provenance"]["redefined"] == [changed]
    assert (page["provenance"]["added"], page["provenance"]["absent"]) == ([], [])
    tools = {t["name"]: t for t in page["tools"]}
    assert len(tools) == len(altered)
    assert {t["status"] for name, t in tools.items() if name != changed} == {"identical"}
    target = tools[changed]
    field = target["differences"][0]
    assert target["status"] == "redefined" and field["field"] == "description"
    assert field["observed"] == target["description"] and field["observed"].startswith(field["published"])
    assert "​" in field["observed"]
    assert [p["name"] for p in target["parameters"]] and target["findings"]
    assert set(target["findings"]) <= {f["reference"] for f in page["findings"]}
    assert all(f["case"] for f in page["findings"] if f["tool"] == changed)

    history = page["releases"]
    assert history["package"] == PACKAGE and history["total"] >= len(history["releases"]) == 5
    assert [r["here"] for r in history["releases"]].count(True) == 1 and history["releases"][-1]["here"]
    assert page["scans"][0]["reference"] == page["read_scan"]["reference"]
    assert [c["rule"] for c in page["cases"]] == ["deviation"]


def test_a_server_no_package_matches_gets_no_release_history(lab):
    lab.scan([SHELL])
    page = get(lab.client, lab.headers, f"/api/assets/{lab.asset}/detail")
    assert page["provenance"]["verdict"] == "unknown" and page["releases"] is None
    assert [t["status"] for t in page["tools"]] == ["unverified"]


def test_stored_declarations_keep_text_but_not_credentials(lab):
    leaky = tool("connect", "Connects with postgres://admin:hunter2@db.internal/app at 10.0.0.5")
    lab.scan([leaky])
    kept = get(lab.client, lab.headers, f"/api/assets/{lab.asset}/detail")["tools"][0]["description"]
    assert "hunter2" not in kept and "db.internal/app at 10.0.0.5" in kept


def test_changes_name_what_was_added_removed_and_redefined(lab):
    first = lab.scan([SHELL, STATUS])
    second = lab.scan([STATUS, tool("run_shell_command", "Runs a command"), tool("read_file", "Read a file")])
    lab.scan([STATUS, tool("run_shell_command", "Runs a command"), tool("read_file", "Read a file")])

    listed = get(lab.client, lab.headers, "/api/changes")
    assert listed["total"] == 1
    change = listed["changes"][0]
    assert (change["kind"], change["scan"], change["previous_scan"]) == (
        "between_scans", second["scan_reference"], first["scan_reference"])
    assert (change["added"], change["removed"], change["redefined"]) == (["read_file"], [], ["run_shell_command"])
    row = get(lab.client, lab.headers, "/api/inventory")["servers"][0]
    assert row["last_change"]["scan"] == second["scan_reference"] and row["last_change"]["added"] == ["read_file"]

    count = lambda **params: get(lab.client, lab.headers, "/api/changes", **params)["total"]
    assert count(kind="between_scans") == 1 and count(kind="against_release") == 0
    assert count(on=change["at"][:10]) == 1 and count(on="2020-01-01") == 0
    assert count(q="read_file") == 1 and count(q="zzz") == 0 and count(asset_id=lab.asset + 1) == 0
    assert lab.client.get("/api/changes", headers=lab.headers, params={"kind": "other"}).status_code == 422


def test_a_first_scan_that_differs_from_the_release_is_listed_as_a_change(lab):
    altered, _ = _altered(shipped())
    scan = lab.scan(altered)
    change = get(lab.client, lab.headers, "/api/changes")["changes"][0]
    assert (change["kind"], change["scan"], change["previous_scan"]) == ("against_release", scan["scan_reference"], None)
    assert change["verdict"] == "deviation" and PACKAGE in change["release"]


def test_the_pages_are_closed_to_other_teams(console, lab):
    lab.scan([SHELL])
    other = signed_in(console, "outsider")
    assert get(console, other, "/api/inventory")["servers"] == []
    assert get(console, other, "/api/changes")["total"] == 0
    assert console.get(f"/api/assets/{lab.asset}/detail", headers=other).status_code == 404
