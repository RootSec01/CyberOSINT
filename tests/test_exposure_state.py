"""Exposure lifecycle: an exposure opens, is proven closed, and is recognised
when it comes back; a scan whose evidence cannot prove an absence never claims
a remediation; identity survives redefinition and renames.

Runs on SQLite always, and on PostgreSQL too when TEST_POSTGRES_URL points at a
disposable database (CI does this).
"""
import json
import os
import tempfile

import pytest
from sqlalchemy import create_engine

from raqeeb import db
from raqeeb import exposure_state as es
from raqeeb import manifest_fingerprint as mf
from raqeeb import models as m
from raqeeb.security import hash_password

BACKENDS = ["sqlite"] + (["postgresql"] if os.getenv("TEST_POSTGRES_URL") else [])


def server(tools, auth_required=False):
    return {"protocol_version": "2025-06-18", "server_info": {"name": "lab", "version": "1"},
            "auth_required": auth_required,
            "tools": [{"name": n, "description": d, "inputSchema": {"type": "object"}} for n, d in tools]}


def mcp_payload(tools, *, dangerous=None, auth_required=False, run_id="run-1",
                is_mcp=True, complete=True, snapshot=True):
    """A safe-proof payload in the shape ``scan_asset`` stores.

    ``tools`` is every declared tool as (name, description); ``dangerous`` maps
    the ones the detectors flagged to their risk flags (default: all of them).
    """
    srv = server(tools, auth_required)
    if dangerous is None:
        dangerous = {n: ["command_exec"] for n, _ in tools}
    proof = {
        "is_mcp": is_mcp, "auth_required": auth_required,
        "manifest_fingerprint": mf.fingerprint(srv),
        "dangerous_tools": [{"name": n, "risk_flags": f} for n, f in dangerous.items()],
        "tool_listing": {"complete": complete, "pages": 1,
                         "reason": None if complete else "tools/list error -32603"},
    }
    if snapshot:
        proof["manifest_snapshot"] = mf.snapshot_for_storage(srv)
    return {"run_id": run_id, "kind": "safe_proof", "risk": {"level": "Critical"},
            "target": "127.0.0.1:9000", "safe_proof": proof}


SHELL = ("run_shell", "Run any shell command")
READ = ("read_file", "Read a file by path")


def surface_payload(cves, *, run_id="surface-1", total=None, sources=("shodan",), simulated=False):
    return {"run_id": run_id, "services": [{"port": 443, "service": "https"}],
            "vulnerabilities": [{"cve_id": c, "severity": "High"} for c in cves],
            "vulnerability_count": len(cves) if total is None else total,
            "risk": {"level": "High"}, "sources": list(sources), "simulation_used": simulated}


# --- pure decision logic (no database) --------------------------------------

@pytest.mark.parametrize("previous,present,expected", [
    (None, True, es.OPEN), (None, False, None),
    (es.OPEN, True, es.OPEN), (es.OPEN, False, es.REMEDIATED),
    (es.REMEDIATED, True, es.REGRESSED), (es.REMEDIATED, False, es.REMEDIATED),
    (es.REGRESSED, True, es.REGRESSED), (es.REGRESSED, False, es.REMEDIATED),
])
def test_next_state_transitions(previous, present, expected):
    assert es.next_state(previous, present) == expected


def test_observe_reads_tools_auth_and_declarations():
    obs = es.observe(mcp_payload([SHELL, READ]))
    assert set(obs.present) == {"tool:run_shell", "tool:read_file", es.AUTH_KEY}
    assert obs.present["tool:run_shell"]["detail"] == "command_exec"
    assert obs.present["tool:run_shell"]["definition"].startswith("sha256:")
    assert obs.present["tool:run_shell"]["definition"] != obs.present["tool:read_file"]["definition"]
    assert set(obs.can_close) == {"tool", "auth"} and obs.limits == []


def test_presence_is_read_through_drift():
    """Lifecycle and drift alerts must never disagree about what was present."""
    from raqeeb import drift
    payload = mcp_payload([SHELL, READ], dangerous={"run_shell": ["command_exec"]})
    tools = {k.split(":", 1)[1] for k in es.observe(payload).present if k.startswith("tool:")}
    assert tools == set(drift.snapshot(payload)["dangerous_tools"])


def test_authenticated_server_has_no_anonymous_exposure():
    assert es.observe(mcp_payload([], auth_required=True)).present == {}


def test_observe_refuses_scans_that_saw_nothing():
    assert es.observe({"skipped": True, "kind": "safe_proof"}) is None
    assert es.observe(mcp_payload([], is_mcp=False)) is None
    assert es.observe({}) is None
    assert es.observe(surface_payload(["CVE-2026-0001"], simulated=True)) is None


def test_incomplete_listing_cannot_close_tools():
    obs = es.observe(mcp_payload([SHELL], complete=False))
    assert "tool" not in obs.can_close and "auth" in obs.can_close
    assert "not read to the end" in obs.limits[0]


def test_unknown_listing_completeness_cannot_close_tools():
    payload = mcp_payload([SHELL])
    del payload["safe_proof"]["tool_listing"]       # reports from before this field
    assert "tool" not in es.observe(payload).can_close


def test_unknown_auth_posture_cannot_close_anonymous_access():
    obs = es.observe(mcp_payload([SHELL], auth_required=None))
    assert "auth" not in obs.can_close and es.AUTH_KEY not in obs.present


def test_truncated_cve_list_cannot_close_cves():
    obs = es.observe(surface_payload(["CVE-2026-0001"], total=40))
    assert obs.can_close == () and "keeps 1 of 40" in obs.limits[0]
    assert es.observe(surface_payload(["CVE-2026-0001"], sources=())).can_close == ()
    assert es.observe(surface_payload(["CVE-2026-0001"])).can_close == ("cve",)


def test_match_renames_requires_a_unique_known_declaration():
    assert es.match_renames({"tool:a": "d1"}, {"tool:b": "d1"}) == {"tool:a": "tool:b"}
    assert es.match_renames({"tool:a": "d1"}, {"tool:b": "d1", "tool:c": "d1"}) == {}
    assert es.match_renames({"tool:a": None}, {"tool:b": None}) == {}
    assert es.match_renames({"tool:a": "d1"}, {"tool:b": "d2"}) == {}


# --- lifecycle against the database -----------------------------------------

@pytest.fixture(scope="module", autouse=True, params=BACKENDS)
def backend(request):
    if request.param == "sqlite":
        eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/exposure.db",
                            connect_args={"check_same_thread": False}, future=True)
    else:
        eng = create_engine(os.environ["TEST_POSTGRES_URL"], future=True)
        db.Base.metadata.drop_all(bind=eng)
    old_engine = db.engine
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="nadia", password_hash=hash_password("password123")))
        s.flush()
        uid = s.query(m.User).filter_by(username="nadia").first().id
        s.add(m.Asset(user_id=uid, kind="mcp", value="127.0.0.1:9000", label="lab", monitoring=True))
    yield request.param
    db.engine = old_engine
    db.SessionLocal.configure(bind=old_engine)
    eng.dispose()


def _asset(s):
    return s.query(m.Asset).filter_by(value="127.0.0.1:9000").first()


def _fresh(s):
    s.query(m.ExposureState).delete()
    s.query(m.Alert).delete()
    s.query(m.Run).delete()
    s.commit()
    return _asset(s)


def _rows(s, asset_id):
    return {r.key: r for r in s.query(m.ExposureState).filter_by(asset_id=asset_id).all()}


def test_full_lifecycle_open_remediated_regressed():
    with db.session_scope() as s:
        asset = _fresh(s)
        first = es.reconcile(s, asset, mcp_payload([SHELL]))
        assert first["reconciled"] and "tool:run_shell" in first["opened"]

        second = es.reconcile(s, asset, mcp_payload([], run_id="run-2"))
        assert second["remediated"] == ["tool:run_shell"]
        row = _rows(s, asset.id)["tool:run_shell"]
        assert row.state == es.REMEDIATED and row.remediated_at is not None
        # The evidence is the scan that proved closure, not the one that found it.
        assert row.evidence_run_id == "run-2"
        assert row.evidence_fingerprint == mcp_payload([])["safe_proof"]["manifest_fingerprint"]
        assert row.evidence_reason == es.REASON_REMOVED

        third = es.reconcile(s, asset, mcp_payload([SHELL], run_id="run-3"))
        assert third["regressed"] == ["tool:run_shell"]
        row = _rows(s, asset.id)["tool:run_shell"]
        assert row.state == es.REGRESSED and row.times_regressed == 1
        assert row.first_seen_at < row.regressed_at          # a return is not a new finding
        assert third["summary"]["exposed_now"] == 2          # the tool and anonymous access


def test_anonymous_access_survives_tool_removal():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        es.reconcile(s, asset, mcp_payload([], run_id="run-2"))
        rows = _rows(s, asset.id)
        assert rows["tool:run_shell"].state == es.REMEDIATED
        assert rows[es.AUTH_KEY].state == es.OPEN


@pytest.mark.parametrize("payload", [
    mcp_payload([], is_mcp=False, run_id="run-2"),
    {"kind": "safe_proof", "skipped": True, "reason": "target not authorized"},
])
def test_scans_that_saw_nothing_change_nothing(payload):
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        assert es.reconcile(s, asset, payload)["reconciled"] is False
        assert _rows(s, asset.id)["tool:run_shell"].state == es.OPEN


def test_incomplete_listing_holds_missing_tools_but_records_present_ones():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL, READ]))
        result = es.reconcile(s, asset, mcp_payload([SHELL], run_id="run-2", complete=False))
        assert result["remediated"] == [] and result["held"] == ["tool:read_file"]
        assert result["limits"] and "not read to the end" in result["limits"][0]
        rows = _rows(s, asset.id)
        assert rows["tool:read_file"].state == es.OPEN
        assert rows["tool:run_shell"].evidence_run_id == "run-2"


def test_server_that_starts_requiring_auth_has_not_removed_its_tools():
    """A 401 before tools/list hides the tools; it does not remove them."""
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        locked = mcp_payload([], auth_required=True, run_id="run-2", complete=False)
        locked["safe_proof"]["tool_listing"]["reason"] = "not attempted"
        result = es.reconcile(s, asset, locked)
        rows = _rows(s, asset.id)
        assert rows["tool:run_shell"].state == es.OPEN and result["held"] == ["tool:run_shell"]
        assert rows[es.AUTH_KEY].state == es.REMEDIATED
        assert rows[es.AUTH_KEY].evidence_reason == es.REASON_AUTH_REQUIRED


def test_unknown_auth_posture_holds_anonymous_access():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        result = es.reconcile(s, asset, mcp_payload([SHELL], auth_required=None, run_id="run-2"))
        assert _rows(s, asset.id)[es.AUTH_KEY].state == es.OPEN
        assert result["held"] == [es.AUTH_KEY]


def test_redefined_tool_keeps_its_identity_and_history():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        before = _rows(s, asset.id)["tool:run_shell"]
        first_seen, old_digest = before.first_seen_at, before.definition_digest
        result = es.reconcile(s, asset, mcp_payload(
            [("run_shell", "Run any shell command as root")], run_id="run-2"))
        assert result["opened"] == [] and result["remediated"] == []
        row = _rows(s, asset.id)["tool:run_shell"]
        assert row.state == es.OPEN and row.first_seen_at == first_seen
        assert row.evidence_reason == es.REASON_REDEFINED
        assert row.definition_digest != old_digest


def test_renamed_tool_moves_its_row_instead_of_closing_it():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        first_seen = _rows(s, asset.id)["tool:run_shell"].first_seen_at
        result = es.reconcile(s, asset, mcp_payload(
            [("exec_command", SHELL[1])], run_id="run-2"))
        assert result["renamed"] == ["tool:run_shell -> tool:exec_command"]
        assert result["opened"] == [] and result["remediated"] == []
        rows = _rows(s, asset.id)
        assert "tool:run_shell" not in rows
        assert rows["tool:exec_command"].first_seen_at == first_seen
        assert rows["tool:exec_command"].evidence_reason == "renamed from run_shell"


def test_no_rename_is_inferred_from_an_incomplete_listing():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        result = es.reconcile(s, asset, mcp_payload([("exec_command", SHELL[1])],
                                                    run_id="run-2", complete=False))
        assert result["renamed"] == [] and result["held"] == ["tool:run_shell"]
        assert "tool:exec_command" in result["opened"]


def test_tool_that_stops_being_dangerous_is_closed_with_that_reason():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL, READ]))
        es.reconcile(s, asset, mcp_payload([SHELL, ("read_file", "Read a file in the docs folder")],
                                           dangerous={"run_shell": ["command_exec"]}, run_id="run-2"))
        row = _rows(s, asset.id)["tool:read_file"]
        assert row.state == es.REMEDIATED and row.evidence_reason == es.REASON_NOT_DANGEROUS


def test_surface_and_mcp_scans_never_close_each_other():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        es.reconcile(s, asset, surface_payload(["CVE-2026-0001"]))
        rows = _rows(s, asset.id)
        assert rows["tool:run_shell"].state == es.OPEN
        assert rows["cve:CVE-2026-0001"].state == es.OPEN
        es.reconcile(s, asset, mcp_payload([SHELL], run_id="run-2"))
        assert _rows(s, asset.id)["cve:CVE-2026-0001"].state == es.OPEN


def test_cve_outside_the_stored_top_list_is_held_not_closed():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, surface_payload(["CVE-2026-0001", "CVE-2026-0002"]))
        held = es.reconcile(s, asset, surface_payload(["CVE-2026-0002"], total=16, run_id="s-2"))
        assert held["held"] == ["cve:CVE-2026-0001"]
        assert _rows(s, asset.id)["cve:CVE-2026-0001"].state == es.OPEN
        closed = es.reconcile(s, asset, surface_payload(["CVE-2026-0002"], run_id="s-3"))
        assert closed["remediated"] == ["cve:CVE-2026-0001"]
        assert _rows(s, asset.id)["cve:CVE-2026-0001"].evidence_reason == es.REASON_CVE_GONE


def test_repeated_identical_scan_is_idempotent():
    payload = mcp_payload([SHELL])
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, payload)
        second = es.reconcile(s, asset, payload)
        assert second["opened"] == [] and second["regressed"] == []
        rows = list(_rows(s, asset.id).values())
        assert len(rows) == 2 and all(r.state == es.OPEN for r in rows)


def test_serialised_timestamps_carry_their_offset():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL]))
        es.reconcile(s, asset, mcp_payload([], run_id="run-2"))
        body = es.exposure_dict(_rows(s, asset.id)["tool:run_shell"])
        for name in ("first_seen_at", "last_seen_at", "remediated_at"):
            assert body[name] and body[name].endswith("+00:00"), (name, body[name])


def _client():
    from fastapi.testclient import TestClient
    from raqeeb import main
    client = TestClient(main.app)
    token = client.post("/api/login", data={"username": "nadia", "password": "password123"}).json()["token"]
    return client, {"Authorization": f"Bearer {token}"}


def test_exposures_endpoint_reports_states_reasons_and_filters():
    with db.session_scope() as s:
        asset = _fresh(s)
        es.reconcile(s, asset, mcp_payload([SHELL, READ]))
        es.reconcile(s, asset, mcp_payload([SHELL], run_id="run-2"))
        asset_id = asset.id
    client, headers = _client()
    body = client.get(f"/api/assets/{asset_id}/exposures", headers=headers).json()
    assert body["summary"] == {"open": 2, "remediated": 1, "regressed": 0, "exposed_now": 2}
    closed = next(e for e in body["exposures"] if e["key"] == "tool:read_file")
    assert closed["state"] == es.REMEDIATED and closed["exposed_now"] is False
    assert closed["evidence_run_id"] == "run-2" and closed["evidence_reason"] == es.REASON_REMOVED
    exposed = client.get(f"/api/assets/{asset_id}/exposures?state=exposed", headers=headers).json()
    assert {e["key"] for e in exposed["exposures"]} == {"tool:run_shell", es.AUTH_KEY}
    assert exposed["summary"]["remediated"] == 1        # always the whole asset


def test_regression_is_reported_through_the_existing_drift_alert():
    from raqeeb import main
    clean, back = mcp_payload([], run_id="run-2"), mcp_payload([SHELL], run_id="run-3")
    with db.session_scope() as s:
        asset = _fresh(s)
        user = s.query(m.User).filter_by(username="nadia").first()
        es.reconcile(s, asset, mcp_payload([SHELL]))
        es.reconcile(s, asset, clean)
        for payload in (clean, back):
            s.add(m.Run(user_id=user.id, run_id=payload["run_id"], target_type="mcp",
                        target_value=asset.value, report_json=json.dumps(payload)))
            s.commit()
        lifecycle = es.reconcile(s, asset, back)
        alert = main._maybe_raise_alert(s, user, asset, back, lifecycle=lifecycle)
        assert alert is not None and alert.kind == "regression"
        assert "returned after remediation: tool:run_shell" in alert.detail


def test_deleting_an_asset_removes_its_lifecycle_rows():
    with db.session_scope() as s:
        asset = _fresh(s)
        user_id = asset.user_id
        tmp = m.Asset(user_id=user_id, kind="mcp", value="127.0.0.1:9100", label="tmp", monitoring=True)
        s.add(tmp)
        s.commit()
        es.reconcile(s, tmp, mcp_payload([SHELL]))
        tmp_id = tmp.id
    client, headers = _client()
    assert client.delete(f"/api/assets/{tmp_id}", headers=headers).status_code == 200
    with db.session_scope() as s:
        assert s.query(m.ExposureState).filter_by(asset_id=tmp_id).count() == 0


def test_long_names_fit_the_columns_postgresql_enforces():
    long_name = "t" * 400
    with db.session_scope() as s:
        asset = _fresh(s)
        result = es.reconcile(s, asset, mcp_payload([(long_name, "Run any shell command")]))
        key = next(k for k in result["opened"] if k.startswith("tool:"))
        row = _rows(s, asset.id)[key]
        assert len(row.key) <= 255 and len(row.label) <= 255
