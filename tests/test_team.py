import pytest

from tests.test_cases import REASON, SHELL, Lab, get, post, signed_in


@pytest.fixture
def owner(console):
    running = Lab(console, signed_in(console, "rami"))
    yield running
    running.server.shutdown()
    running.server.server_close()


def add(owner, username, role, **extra):
    return post(owner.client, owner.headers, "/api/members", username=username, password="first-pass-1",
                role=role, **extra)


def test_someone_nobody_added_owns_a_team_of_one(owner):
    profile = get(owner.client, owner.headers, "/api/profile")
    assert (profile["role"], profile["can"]) == ("owner", ["read", "work", "manage"])
    members = get(owner.client, owner.headers, "/api/members")
    assert [(m["username"], m["role"]) for m in members["members"]] == [("rami", "owner")]
    assert members["roles"] == ["admin", "analyst", "viewer"]


def test_the_profile_name_is_what_cases_show(owner):
    saved = owner.client.put("/api/profile", headers=owner.headers, data={
        "display_name": "Rami Omar", "email": "rami@example.org", "title": "SOC Analyst"}).json()
    assert (saved["display_name"], saved["email"], saved["title"]) == ("Rami Omar", "rami@example.org", "SOC Analyst")
    bad = owner.client.put("/api/profile", headers=owner.headers, data={"email": "not-an-address"})
    assert bad.status_code == 422

    reference = owner.scan([SHELL])["cases"][0]
    assigned = post(owner.client, owner.headers, f"/api/cases/{reference}/assign", owner="rami").json()
    assert (assigned["owner"], assigned["owner_name"]) == ("rami", "Rami Omar")
    assert assigned["timeline"][-1]["text"] == "Assigned to Rami Omar."


def test_the_owner_adds_members_who_sign_in_and_see_the_team_s_work(owner):
    reference = owner.scan([SHELL])["cases"][0]
    assert add(owner, "sara", "analyst", display_name="Sara Ali", email="sara@example.org").status_code == 201
    assert add(owner, "sara", "analyst").status_code == 422
    assert add(owner, "x", "analyst").status_code == 422
    assert add(owner, "noor", "owner").status_code == 422
    assert post(owner.client, owner.headers, "/api/members", username="omar", password="short",
                role="viewer").status_code == 422

    sara = signed_in(owner.client, "sara", "first-pass-1")
    assert get(owner.client, sara, "/api/profile")["role"] == "analyst"
    assert [a["id"] for a in get(owner.client, sara, "/api/assets")] == [owner.asset]
    assert get(owner.client, sara, "/api/cases")["total"] == 1
    assert get(owner.client, sara, "/api/findings")["total"] >= 1
    assert get(owner.client, sara, "/api/scans")["total"] == 1
    assert [m["username"] for m in get(owner.client, sara, "/api/members")["members"]] == ["rami", "sara"]

    scanned = owner.client.post(f"/api/assets/{owner.asset}/scan", headers=sara)
    assert scanned.status_code == 200
    assert get(owner.client, sara, "/api/scans", operator="sara")["total"] == 1
    closed = post(owner.client, sara, f"/api/cases/{reference}/close", reason="fixed", note=REASON).json()
    assert closed["closed_by"] == "sara"


def test_a_case_is_assigned_only_to_someone_who_can_work_it(owner):
    reference = owner.scan([SHELL])["cases"][0]
    add(owner, "sara", "analyst", display_name="Sara Ali")
    add(owner, "vera", "viewer")
    assign = lambda name: post(owner.client, owner.headers, f"/api/cases/{reference}/assign", owner=name)

    assert assign("sara").json()["owner_name"] == "Sara Ali"
    assert get(owner.client, owner.headers, "/api/cases", owner="sara")["total"] == 1
    assert assign("vera").status_code == 422
    assert assign("outsider").status_code == 422
    assert assign("nobody").status_code == 422
    assert assign("").json()["owner"] is None


def test_a_viewer_reads_everything_and_changes_nothing(owner):
    reference = owner.scan([SHELL])["cases"][0]
    finding = get(owner.client, owner.headers, "/api/findings")["findings"][0]["reference"]
    add(owner, "vera", "viewer")
    vera = signed_in(owner.client, "vera", "first-pass-1")

    assert get(owner.client, vera, f"/api/cases/{reference}")["reference"] == reference
    assert get(owner.client, vera, "/api/profile")["can"] == ["read"]
    refused = [
        owner.client.post(f"/api/assets/{owner.asset}/scan", headers=vera),
        owner.client.post("/api/assets", headers=vera, data={"kind": "mcp", "value": "127.0.0.1:1"}),
        owner.client.delete(f"/api/assets/{owner.asset}", headers=vera),
        post(owner.client, vera, f"/api/findings/{finding}/status", status="acknowledged"),
        post(owner.client, vera, f"/api/cases/{reference}/close", reason="fixed", note=REASON),
        post(owner.client, vera, f"/api/cases/{reference}/notes", text="hello"),
        post(owner.client, vera, "/api/cases", finding=finding, note="Needs a second look"),
        post(owner.client, vera, "/api/members", username="zed", password="first-pass-1", role="viewer"),
        owner.client.put("/api/case-rules/deviation", headers=vera, data={"enabled": "false"}),
    ]
    assert [answer.status_code for answer in refused] == [403] * len(refused)
    assert "viewer role cannot" in refused[0].json()["detail"]


def test_only_the_owner_manages_admins_and_analysts_manage_nobody(owner):
    add(owner, "adam", "admin")
    add(owner, "sara", "analyst")
    roster = {m["username"]: m["id"] for m in get(owner.client, owner.headers, "/api/members")["members"]}
    adam, sara = signed_in(owner.client, "adam", "first-pass-1"), signed_in(owner.client, "sara", "first-pass-1")

    assert post(owner.client, adam, "/api/members", username="noor", password="first-pass-1",
                role="analyst").status_code == 201
    assert post(owner.client, adam, "/api/members", username="amal", password="first-pass-1",
                role="admin").status_code == 422
    assert owner.client.patch(f"/api/members/{roster['sara']}", headers=adam, data={"role": "admin"}).status_code == 422
    assert owner.client.delete(f"/api/members/{roster['adam']}", headers=adam).status_code == 422
    assert owner.client.delete(f"/api/members/{roster['rami']}", headers=owner.headers).status_code == 422
    assert post(owner.client, sara, "/api/members", username="zed", password="first-pass-1",
                role="viewer").status_code == 403

    promoted = owner.client.patch(f"/api/members/{roster['sara']}", headers=owner.headers, data={"role": "viewer"})
    assert {m["username"]: m["role"] for m in promoted.json()["members"]}["sara"] == "viewer"
    assert owner.client.patch("/api/members/99999", headers=owner.headers, data={"role": "viewer"}).status_code == 404


def test_removing_a_member_ends_their_access_and_frees_their_cases(owner):
    reference = owner.scan([SHELL])["cases"][0]
    add(owner, "sara", "analyst", display_name="Sara Ali")
    sara = signed_in(owner.client, "sara", "first-pass-1")
    created = owner.client.post("/api/assets", headers=sara, data={"kind": "mcp", "value": "127.0.0.1:9", "label": "hers"})
    post(owner.client, owner.headers, f"/api/cases/{reference}/assign", owner="sara")
    member = get(owner.client, owner.headers, "/api/members")["members"][1]["id"]

    removed = owner.client.delete(f"/api/members/{member}", headers=owner.headers)
    assert [(m["username"], m["active"]) for m in removed.json()["members"]] == [("rami", True), ("sara", False)]
    assert owner.client.get("/api/profile", headers=sara).status_code == 401
    case = get(owner.client, owner.headers, f"/api/cases/{reference}")
    assert case["owner"] is None and case["timeline"][-1]["text"] == "Unassigned: the owner left the team."
    kept = {a["id"]: a["owner_id"] for a in get(owner.client, owner.headers, "/api/assets")}
    assert created.json()["id"] in kept and len(set(kept.values())) == 1
    trail = get(owner.client, owner.headers, "/api/audit", action="member_removed")
    assert trail["total"] == 1


def test_teams_do_not_see_each_other(console, owner):
    owner.scan([SHELL])
    add(owner, "sara", "analyst")
    outsider = signed_in(console, "outsider")
    assert get(console, outsider, "/api/assets") == []
    assert [m["username"] for m in get(console, outsider, "/api/members")["members"]] == ["outsider"]
    assert get(console, outsider, "/api/search", q="files") == {"servers": [], "scans": [], "findings": [], "cases": []}
