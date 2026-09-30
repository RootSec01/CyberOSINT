"""Tests for the Safe Proof engine + the hard safety guards on canary invocation."""
import threading

import pytest

import safe_proof as sp
import mcp_protocol as mp
from mcp_labserver import make_server

_UNAUTH_DANGEROUS = {
    "is_mcp": True, "auth_required": False, "protocol_version": "2026-07-28",
    "verification_method": "server/discover",
    "url": "http://127.0.0.1:9401/mcp",
    "tools": [
        {"name": "run_shell_command", "risk_flags": ["command_exec"]},
        {"name": "read_file", "risk_flags": ["filesystem"]},
        {"name": "list_projects", "risk_flags": []},
    ],
}


def test_critical_when_unauth_and_dangerous():
    p = sp.build_safe_proof(_UNAUTH_DANGEROUS)
    assert p["exposure_verdict"] == "DECLARATION RISK DETECTED"
    assert p["severity"] == "Critical"
    # Declaration does not prove executable access.
    cmd = [s for s in p["attack_path"] if s["technique_id"] == "T1059"][0]
    assert cmd["evidence_tier"] == sp.INFERRED
    assert "arbitrary command execution on the host" in p["blast_radius"]["reachable"]


def test_authenticated_dangerous_is_high_and_inferred():
    server = {**_UNAUTH_DANGEROUS, "auth_required": True}
    p = sp.build_safe_proof(server)
    assert p["exposure_verdict"] == "DECLARATION RISK DETECTED"
    assert p["severity"] == "High"
    cmd = [s for s in p["attack_path"] if s["technique_id"] == "T1059"][0]
    assert cmd["evidence_tier"] == sp.INFERRED  # gated by auth, not proven reachable


def test_not_mcp_is_no_exposure():
    p = sp.build_safe_proof({"is_mcp": False, "url": "http://x/mcp"})
    assert p["exposure_verdict"] == "MCP NOT CONFIRMED" and p["severity"] == "None"


def test_safety_envelope_is_always_clean():
    for server in (_UNAUTH_DANGEROUS, {**_UNAUTH_DANGEROUS, "auth_required": True}):
        s = sp.build_safe_proof(server)["safety"]
        assert s["production_data_accessed"] is False
        assert s["destructive_action_performed"] is False
        assert s["dangerous_tool_invoked"] is False


def test_canary_upgrades_access_to_demonstrated():
    canary = {"ok": True, "tool": "list_projects", "marker": "CANARY-OK:modern:list_projects"}
    p = sp.build_safe_proof(_UNAUTH_DANGEROUS, canary=canary)
    access = p["attack_path"][0]
    assert access["evidence_tier"] == sp.DEMONSTRATED
    assert p["safety"]["canary_invoked"] is True
    assert p["safety"]["verification_method"] == "canary-lab"
    assert p["safety"]["dangerous_tool_invoked"] is None  # legacy record has no attestation


# ---- hard guards on the invocation channel --------------------------------

def test_canary_refuses_non_loopback():
    r = mp.safe_call_tool("https://real-target.example.com/mcp", "list_projects")
    assert r["ok"] is False and r["refused"] is True


def test_canary_refuses_dangerous_tool_name():
    r = mp.safe_call_tool("http://127.0.0.1:9999/mcp", "run_shell_command")
    assert r["ok"] is False and r["refused"] is True


# ---- end-to-end against the lab -------------------------------------------

def test_end_to_end_lab_demonstration():
    srv = make_server("modern", 9401)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import time; time.sleep(0.5)
    try:
        server = mp.verify_mcp_endpoint("http://127.0.0.1:9401/mcp")
        assert server["is_mcp"] is True
        # DEMONSTRATE reachability via the SAFE tool only
        canary = mp.safe_call_tool("http://127.0.0.1:9401/mcp", "list_projects")
        assert canary["ok"] is True and canary["marker"].startswith("CANARY-OK")
        # dangerous tool would be refused by the lab even if asked
        blocked = mp._rpc("http://127.0.0.1:9401/mcp", "tools/call",
                          {"name": "run_shell_command", "arguments": {}}, 5, None)
        assert "error" in (blocked["message"] or {})
        proof = sp.build_safe_proof(server, canary=canary)
        assert proof["exposure_verdict"] == "DECLARATION RISK DETECTED"
        assert proof["attack_path"][0]["evidence_tier"] == sp.DEMONSTRATED
        assert proof["safety"]["dangerous_tool_invoked"] is False
    finally:
        srv.shutdown()


def test_exposure_index_and_vector():
    p = sp.build_safe_proof(_UNAUTH_DANGEROUS)
    assert 0 <= p["exposure_index"] <= 100
    assert p["exposure_index"] >= 80          # unauth + command exec is severe
    assert p["exposure_vector"].startswith("AEV:1.0/AC:N/AU:N/")
    assert "CAP:CMD" in p["exposure_vector"]
    assert isinstance(p["attacker_narrative"], str) and p["attacker_narrative"]


def test_authenticated_lowers_index_and_flips_vector():
    p = sp.build_safe_proof({**_UNAUTH_DANGEROUS, "auth_required": True})
    assert "AU:R" in p["exposure_vector"]
    assert p["exposure_index"] < 90


def test_classifier_precision():
    assert sp._classify({"name": "execute_sql"}) == ["db_write"]
    assert sp._classify({"name": "read_file"}) == ["filesystem"]
    assert sp._classify({"name": "run_shell_command"}) == ["command_exec"]
    assert sp._classify({"name": "get_secrets"}) == ["secrets"]
