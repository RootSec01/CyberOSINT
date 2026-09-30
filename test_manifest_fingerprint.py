"""Manifest fingerprint tests — deterministic hashing + typed change detection.
Detects a silently changed MCP surface (tool poisoning / rug-pull) between scans."""
import manifest_fingerprint as mf
import safe_proof


SAFE = {"is_mcp": True, "auth_required": True, "protocol_version": "2026-07-28",
        "server_info": {"name": "srv", "version": "1.0"},
        "tools": [{"name": "list_projects", "description": "list", "inputSchema": {"type": "object", "properties": {}}},
                  {"name": "get_status", "description": "health", "inputSchema": {"type": "object", "properties": {}}}]}


def _clone(**over):
    import copy
    s = copy.deepcopy(SAFE)
    s.update(over)
    return s


def test_fingerprint_is_deterministic_and_order_independent():
    a = mf.fingerprint(SAFE)
    reordered = _clone(tools=list(reversed(SAFE["tools"])))
    assert a == mf.fingerprint(reordered)          # tool order does not change it
    assert a.startswith("sha256:")


def test_fingerprint_changes_when_tool_added():
    changed = _clone(tools=SAFE["tools"] + [{"name": "run_shell_command", "description": "exec"}])
    assert mf.fingerprint(changed) != mf.fingerprint(SAFE)


def test_diff_detects_tool_added_and_auth_disabled():
    current = _clone(auth_required=False,
                     tools=SAFE["tools"] + [{"name": "run_shell_command", "description": "exec"}])
    d = mf.diff(current, SAFE)
    assert d["changed"] is True and d["change_count"] >= 2
    kinds = {c["kind"] for c in d["changes"]}
    assert "tool_added" in kinds and "authentication_changed" in kinds
    auth = [c for c in d["changes"] if c["kind"] == "authentication_changed"][0]
    assert auth["tone"] == "crit"                  # auth turned off is worse


def test_diff_detects_description_and_schema_change():
    current = _clone(tools=[
        {"name": "list_projects", "description": "CHANGED", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "get_status", "description": "health",
         "inputSchema": {"type": "object", "properties": {"verbose": {"type": "boolean"}}}}])
    kinds = {c["kind"] for c in mf.diff(current, SAFE)["changes"]}
    assert "description_changed" in kinds and "schema_changed" in kinds


def test_diff_unchanged_when_identical():
    d = mf.diff(SAFE, _clone())
    assert d["changed"] is False and d["change_count"] == 0


def test_safe_proof_output_carries_fingerprint():
    server = {"is_mcp": True, "auth_required": False, "verification_method": "server/discover",
              "protocol_version": "2026-07-28",
              "tools": [{"name": "run_shell_command", "description": "execute a shell command"}]}
    proof = safe_proof.build_safe_proof(server)
    assert proof.get("manifest_fingerprint", "").startswith("sha256:")


def test_drift_reports_manifest_fingerprint_change():
    import drift
    prev = {"kind": "safe_proof", "safe_proof": {
        "severity": "Medium", "auth_required": True, "tool_count": 2,
        "manifest_fingerprint": "sha256:aaaaaaaa1111", "dangerous_tools": []}}
    cur = {"kind": "safe_proof", "safe_proof": {
        "severity": "Medium", "auth_required": True, "tool_count": 2,
        "manifest_fingerprint": "sha256:bbbbbbbb2222", "dangerous_tools": []}}
    d = drift.compute_drift(cur, prev)
    kinds = {c["kind"] for c in d["changes"]}
    assert "manifest_fingerprint_changed" in kinds
