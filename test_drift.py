"""Drift tests: the pure diff engine (surface + mcp) and the /drift endpoint."""
import copy
import json
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine

import db
import drift
import models_db as m
from security import hash_password


# --------------------------- pure engine tests ----------------------------

def test_surface_drift_detects_service_cve_and_risk_changes():
    prev = {
        "services": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
        "vulnerabilities": [{"cve_id": "CVE-2021-1", "severity": "High"}],
        "risk": {"level": "Medium"}, "vulnerability_count": 1,
    }
    cur = {
        "services": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
        "vulnerabilities": [{"cve_id": "CVE-2021-1"}, {"cve_id": "CVE-2022-2"}],
        "risk": {"level": "High"}, "vulnerability_count": 2,
    }
    d = drift.compute_drift(cur, prev)
    assert d["comparable"] is True and d["type"] == "surface"
    kinds = {c["kind"]: c for c in d["changes"]}
    assert "service_appeared" in kinds and "443/https" in kinds["service_appeared"]["detail"]
    assert "service_disappeared" in kinds and "22/ssh" in kinds["service_disappeared"]["detail"]
    assert "cve_appeared" in kinds and "CVE-2022-2" in kinds["cve_appeared"]["detail"]
    assert kinds["risk_changed"]["tone"] == "crit"  # Medium -> High is worse


def test_mcp_drift_detects_tool_auth_and_severity_changes():
    prev = {"kind": "safe_proof", "safe_proof": {
        "severity": "High", "auth_required": True, "tool_count": 3,
        "dangerous_tools": [{"name": "read_file", "risk_flags": ["filesystem"]}]}}
    cur = {"kind": "safe_proof", "safe_proof": {
        "severity": "Critical", "auth_required": False, "tool_count": 4,
        "dangerous_tools": [
            {"name": "read_file", "risk_flags": ["filesystem"]},
            {"name": "run_shell", "risk_flags": ["command_exec"]}]}}
    d = drift.compute_drift(cur, prev)
    assert d["comparable"] is True and d["type"] == "mcp"
    kinds = {c["kind"] for c in d["changes"]}
    assert "tool_appeared" in kinds       # run_shell is new
    assert "auth_changed" in kinds        # auth dropped
    assert "severity_changed" in kinds    # High -> Critical


def test_identical_reports_report_no_changes():
    rep = {"services": [{"port": 80, "service": "http"}],
           "vulnerabilities": [], "risk": {"level": "Low"}}
    d = drift.compute_drift(copy.deepcopy(rep), copy.deepcopy(rep))
    assert d["change_count"] == 0
    assert "No changes" in d["summary"]


def test_incomparable_when_scan_type_changes():
    surface = {"services": [], "vulnerabilities": [], "risk": {"level": "Low"}}
    mcp = {"kind": "safe_proof", "safe_proof": {"severity": "High", "dangerous_tools": []}}
    d = drift.compute_drift(mcp, surface)
    assert d["comparable"] is False and d["change_count"] == 0


# --------------------------- endpoint test --------------------------------

@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/drift.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    now = datetime.now(timezone.utc)
    with db.session_scope() as s:
        s.add(m.User(username="drifter", password_hash=hash_password("password123")))
        s.flush()
        uid = s.query(m.User).filter_by(username="drifter").first().id
        # asset with two scans (drift available)
        s.add(m.Asset(user_id=uid, kind="ip", value="203.0.113.9", monitoring=True))
        # asset with only one scan (drift unavailable)
        s.add(m.Asset(user_id=uid, kind="ip", value="203.0.113.50", monitoring=True))
        prev = {"services": [{"port": 22, "service": "ssh"}],
                "vulnerabilities": [], "risk": {"level": "Low"}, "vulnerability_count": 0}
        cur = {"services": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
               "vulnerabilities": [{"cve_id": "CVE-2024-9"}],
               "risk": {"level": "High"}, "vulnerability_count": 1}
        s.add_all([
            m.Run(user_id=uid, run_id="r1", target_type="ip", target_value="203.0.113.9",
                  risk_level="Low", report_json=json.dumps(prev),
                  created_at=now - timedelta(hours=2)),
            m.Run(user_id=uid, run_id="r2", target_type="ip", target_value="203.0.113.9",
                  risk_level="High", report_json=json.dumps(cur),
                  created_at=now - timedelta(hours=1)),
            m.Run(user_id=uid, run_id="r3", target_type="ip", target_value="203.0.113.50",
                  risk_level="Low", report_json=json.dumps(prev), created_at=now),
        ])
    yield


def _client_and_token():
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    tok = c.post("/api/login",
                 data={"username": "drifter", "password": "password123"}).json()["token"]
    return c, {"Authorization": f"Bearer {tok}"}


def _asset_id(value):
    with db.session_scope() as s:
        return s.query(m.Asset).filter_by(value=value).first().id


def test_drift_endpoint_reports_changes_between_last_two_runs():
    c, H = _client_and_token()
    r = c.get(f"/api/assets/{_asset_id('203.0.113.9')}/drift", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True
    assert body["type"] == "surface"
    assert body["change_count"] >= 1
    assert body["current_run"]["run_id"] == "r2"      # newest first
    assert body["previous_run"]["run_id"] == "r1"


def test_drift_endpoint_needs_two_scans():
    c, H = _client_and_token()
    r = c.get(f"/api/assets/{_asset_id('203.0.113.50')}/drift", headers=H)
    assert r.status_code == 200
    assert r.json()["available"] is False


def test_drift_endpoint_explains_new_mcp_metadata_and_legacy_limit():
    """Two stored reports flow through the real auth/DB/API path."""
    import safe_proof
    from fastapi.testclient import TestClient
    import main
    import copy

    base = {"is_mcp": True, "auth_required": True, "protocol_version": "2026-07-28",
            "server_info": {"name": "sample", "version": "1"},
            "tools": [{"name": "get_status", "description": "status"}]}
    newer = copy.deepcopy(base)
    newer["server_info"]["version"] = "2"
    newer["tools"][0]["description"] = "changed"
    prev = {"kind": "safe_proof", "safe_proof": safe_proof.build_safe_proof(base)}
    cur = {"kind": "safe_proof", "safe_proof": safe_proof.build_safe_proof(newer)}
    now = datetime.now(timezone.utc)
    with db.session_scope() as s:
        owner = s.query(m.User).filter_by(username="drifter").first()
        asset = m.Asset(user_id=owner.id, kind="mcp", value="http://127.0.0.1:9511/mcp")
        s.add(asset)
        s.flush()
        aid = asset.id
        s.add_all([
            m.Run(user_id=owner.id, run_id="mcp-before", target_type="mcp", target_value=asset.value,
                  report_json=json.dumps(prev), created_at=now-timedelta(hours=1)),
            m.Run(user_id=owner.id, run_id="mcp-after", target_type="mcp", target_value=asset.value,
                  report_json=json.dumps(cur), created_at=now),
        ])
    client, headers = _client_and_token()
    response = client.get(f"/api/assets/{aid}/drift", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["manifest_comparison"] == "typed"
    assert {"description_changed", "server_info_changed"} <= {c["kind"] for c in body["changes"]}
    assert body["previous_run"]["run_id"] == "mcp-before"
