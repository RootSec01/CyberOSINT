"""Exposure lifecycle tests: an exposure opens, is proven closed, and is
recognised when it comes back — and an unobserved surface never claims a
remediation."""
import tempfile

import pytest
from sqlalchemy import create_engine

import db
import exposure_state as es
import models_db as m
from security import hash_password


def mcp_payload(tools, *, auth_required=False, fingerprint="fp-1",
                run_id="run-1", is_mcp=True):
    """A safe-proof scan payload in the shape ``_run_asset_scan`` stores."""
    return {
        "run_id": run_id,
        "kind": "safe_proof",
        "risk": {"level": "Critical"},
        "target": "127.0.0.1:9000",
        "safe_proof": {
            "is_mcp": is_mcp,
            "auth_required": auth_required,
            "manifest_fingerprint": fingerprint,
            "dangerous_tools": [
                {"name": name, "risk_flags": flags} for name, flags in tools
            ],
        },
    }


def surface_payload(cves, *, run_id="surface-1"):
    return {
        "run_id": run_id,
        "services": [{"port": 443, "service": "https"}],
        "vulnerabilities": [{"cve_id": c, "severity": "High"} for c in cves],
        "risk": {"level": "High"},
    }


# --- pure decision logic (no database) --------------------------------------

@pytest.mark.parametrize("previous,present,expected", [
    (None, True, es.OPEN),
    (None, False, None),
    (es.OPEN, True, es.OPEN),
    (es.OPEN, False, es.REMEDIATED),
    (es.REMEDIATED, True, es.REGRESSED),
    (es.REMEDIATED, False, es.REMEDIATED),
    (es.REGRESSED, True, es.REGRESSED),
    (es.REGRESSED, False, es.REMEDIATED),
])
def test_next_state_transitions(previous, present, expected):
    assert es.next_state(previous, present) == expected


def test_extract_exposures_reads_tools_and_auth():
    payload = mcp_payload([("run_shell", ["command_exec"]),
                           ("read_file", ["file_read"])])
    found = es.extract_exposures(payload)
    assert set(found) == {"tool:run_shell", "tool:read_file", es.AUTH_KEY}
    assert found["tool:run_shell"]["detail"] == "command_exec"
    assert found[es.AUTH_KEY]["kind"] == "auth"


def test_authenticated_server_has_no_anonymous_exposure():
    found = es.extract_exposures(mcp_payload([], auth_required=True))
    assert found == {}


def test_scope_refuses_unobserved_scans():
    assert es.exposure_scope({"skipped": True, "kind": "safe_proof"}) is None
    assert es.exposure_scope(mcp_payload([], is_mcp=False)) is None
    assert es.exposure_scope({}) is None
    assert es.exposure_scope(mcp_payload([]))[0] == "mcp"
    assert es.exposure_scope(surface_payload([]))[0] == "surface"


# --- lifecycle against the database -----------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/exposure.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="nadia", password_hash=hash_password("password123")))
        s.flush()
        uid = s.query(m.User).filter_by(username="nadia").first().id
        s.add(m.Asset(user_id=uid, kind="mcp", value="127.0.0.1:9000",
                      label="lab", monitoring=True))
    yield


def _asset(s):
    return s.query(m.Asset).filter_by(value="127.0.0.1:9000").first()


def _reset(s):
    s.query(m.ExposureState).delete()
    s.commit()


def _states(s, asset_id):
    return {r.key: r.state for r in
            s.query(m.ExposureState).filter_by(asset_id=asset_id).all()}


def test_full_lifecycle_open_remediated_regressed():
    exposed = mcp_payload([("run_shell", ["command_exec"])], fingerprint="fp-bad")
    clean = mcp_payload([], fingerprint="fp-good", run_id="run-2")
    again = mcp_payload([("run_shell", ["command_exec"])],
                        fingerprint="fp-bad", run_id="run-3")

    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)

        first = es.reconcile(s, asset, exposed)
        assert first["reconciled"] is True
        assert first["opened"] == ["tool:run_shell"] or \
            "tool:run_shell" in first["opened"]
        assert _states(s, asset.id)["tool:run_shell"] == es.OPEN

        second = es.reconcile(s, asset, clean)
        assert second["remediated"] == ["tool:run_shell"]
        row = s.query(m.ExposureState).filter_by(
            asset_id=asset.id, key="tool:run_shell").first()
        assert row.state == es.REMEDIATED
        assert row.remediated_at is not None
        # The evidence is the scan that proved closure, not the one that found it.
        assert row.evidence_run_id == "run-2"
        assert row.evidence_fingerprint == "fp-good"

        third = es.reconcile(s, asset, again)
        assert third["regressed"] == ["tool:run_shell"]
        row = s.query(m.ExposureState).filter_by(
            asset_id=asset.id, key="tool:run_shell").first()
        assert row.state == es.REGRESSED
        assert row.times_regressed == 1
        # A return is not a new finding: the original sighting is preserved.
        assert row.first_seen_at < row.regressed_at
        assert third["summary"]["exposed_now"] == 2   # the tool and anonymous access


def test_anonymous_access_survives_tool_removal():
    """The lifecycle demo's 'remediated' state is not risk-free: the tools are
    gone but anonymous enumeration remains, and it must stay open."""
    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)
        es.reconcile(s, asset, mcp_payload([("run_shell", ["command_exec"])]))
        es.reconcile(s, asset, mcp_payload([], run_id="run-2"))
        states = _states(s, asset.id)
        assert states["tool:run_shell"] == es.REMEDIATED
        assert states[es.AUTH_KEY] == es.OPEN


def test_unconfirmed_server_never_claims_remediation():
    """A scan that could not read the manifest proves nothing about it."""
    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)
        es.reconcile(s, asset, mcp_payload([("run_shell", ["command_exec"])]))

        result = es.reconcile(s, asset, mcp_payload([], is_mcp=False, run_id="run-2"))
        assert result["reconciled"] is False
        assert _states(s, asset.id)["tool:run_shell"] == es.OPEN


def test_skipped_scan_changes_nothing():
    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)
        es.reconcile(s, asset, mcp_payload([("run_shell", ["command_exec"])]))
        result = es.reconcile(s, asset, {"kind": "safe_proof", "skipped": True,
                                         "reason": "target not authorized"})
        assert result["reconciled"] is False
        assert _states(s, asset.id)["tool:run_shell"] == es.OPEN


def test_surface_scan_does_not_remediate_mcp_exposures():
    """Different surfaces observe different things — the same refusal
    ``drift.compute_drift`` makes when two scans are not comparable."""
    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)
        es.reconcile(s, asset, mcp_payload([("run_shell", ["command_exec"])]))

        result = es.reconcile(s, asset, surface_payload(["CVE-2026-0001"]))
        assert result["reconciled"] is True
        states = _states(s, asset.id)
        assert states["tool:run_shell"] == es.OPEN          # untouched
        assert states["cve:CVE-2026-0001"] == es.OPEN       # tracked separately


def test_exposures_endpoint_reports_states_and_filters():
    from fastapi.testclient import TestClient
    import main

    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)
        es.reconcile(s, asset, mcp_payload([("run_shell", ["command_exec"]),
                                            ("read_file", ["file_read"])]))
        # read_file is gone in the next scan; run_shell is not.
        es.reconcile(s, asset, mcp_payload([("run_shell", ["command_exec"])],
                                           run_id="run-2"))
        asset_id = asset.id

    client = TestClient(main.app)
    token = client.post("/api/login",
                        data={"username": "nadia", "password": "password123"}
                        ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    body = client.get(f"/api/assets/{asset_id}/exposures", headers=headers).json()
    assert body["summary"] == {"open": 2, "remediated": 1, "regressed": 0,
                               "exposed_now": 2}
    states = {e["key"]: e["state"] for e in body["exposures"]}
    assert states["tool:read_file"] == es.REMEDIATED
    assert states["tool:run_shell"] == es.OPEN
    closed = next(e for e in body["exposures"] if e["key"] == "tool:read_file")
    assert closed["exposed_now"] is False
    assert closed["remediated_at"] and closed["evidence_run_id"] == "run-2"

    exposed = client.get(f"/api/assets/{asset_id}/exposures?state=exposed",
                         headers=headers).json()
    assert {e["key"] for e in exposed["exposures"]} == {"tool:run_shell", es.AUTH_KEY}
    # The summary always describes the whole asset, not the filtered slice.
    assert exposed["summary"]["remediated"] == 1


def test_serialised_timestamps_carry_their_offset():
    """SQLite returns naive datetimes; without an offset a browser would read
    them as local time and misreport when an exposure was closed."""
    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)
        es.reconcile(s, asset, mcp_payload([("run_shell", ["command_exec"])]))
        es.reconcile(s, asset, mcp_payload([], run_id="run-2"))
        row = s.query(m.ExposureState).filter_by(key="tool:run_shell").first()
        body = es.exposure_dict(row)
        for field in ("first_seen_at", "last_seen_at", "remediated_at"):
            assert body[field], field
            assert body[field].endswith("+00:00"), (field, body[field])


def test_repeated_identical_scan_is_idempotent():
    payload = mcp_payload([("run_shell", ["command_exec"])])
    with db.session_scope() as s:
        asset = _asset(s)
        _reset(s)
        es.reconcile(s, asset, payload)
        second = es.reconcile(s, asset, payload)
        assert second["opened"] == [] and second["regressed"] == []
        rows = s.query(m.ExposureState).filter_by(asset_id=asset.id).all()
        assert len(rows) == 2                               # tool + anonymous
        assert all(r.state == es.OPEN for r in rows)
