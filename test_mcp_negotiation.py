"""Real interoperability tests for the MCP negotiation layer.

Spins up in-process modern and legacy lab servers and asserts that the
verifier negotiates each correctly — this is the P0 correctness proof and
the first automated test in the project.

Run:  pytest test_mcp_negotiation.py -v
"""

import threading

import pytest

import mcp_protocol as mp
from mcp_labserver import make_server

_PORTS = {"modern": 9101, "legacy": 9102, "auth": 9103, "safe": 9104}


def _run(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


@pytest.fixture(scope="module")
def servers():
    srvs = [
        _run(make_server("modern", _PORTS["modern"])),
        _run(make_server("legacy", _PORTS["legacy"])),
        _run(make_server("modern", _PORTS["auth"], auth_token="s3cr3t")),
        _run(make_server("modern", _PORTS["safe"], profile="safe")),
    ]
    yield
    for s in srvs:
        s.shutdown()


def _url(kind):
    return f"http://127.0.0.1:{_PORTS[kind]}/mcp"


def test_modern_uses_discover(servers):
    r = mp.verify_mcp_endpoint(_url("modern"))
    assert r["is_mcp"] is True
    assert r["verification_method"] == "server/discover"
    assert r["protocol_version"] == mp.MODERN_VERSION
    names = {t["name"] for t in r["tools"]}
    assert "run_shell_command" in names


def test_legacy_falls_back_to_initialize(servers):
    r = mp.verify_mcp_endpoint(_url("legacy"))
    assert r["is_mcp"] is True
    assert r["verification_method"] == "initialize"
    assert r["protocol_version"] == mp.LEGACY_VERSION
    assert r["fallback_reason"] is not None  # discover was tried and refused
    names = {t["name"] for t in r["tools"]}
    assert "execute_sql" in names


def test_legacy_only_scanner_would_have_missed_modern(servers):
    """The old approach (initialize only) fails on a strict modern server."""
    init = mp._rpc(_url("modern"), "initialize", {
        "protocolVersion": mp.LEGACY_VERSION,
        "capabilities": {}, "clientInfo": {"name": "x", "version": "1"},
    }, timeout=5, auth_token=None)
    assert "error" in (init["message"] or {})  # this is the false negative we fixed


def test_auth_required_is_reported_not_crashed(servers):
    r = mp.verify_mcp_endpoint(_url("auth"))
    assert r["auth_required"] is True
    assert r["is_mcp"] is True
    # with the right token it verifies fully
    ok = mp.verify_mcp_endpoint(_url("auth"), auth_token="s3cr3t")
    assert ok["auth_required"] is False
    assert ok["verification_method"] == "server/discover"


def test_safe_profile_has_no_dangerous_tools(servers):
    r = mp.verify_mcp_endpoint(_url("safe"))
    names = {t["name"] for t in r["tools"]}
    assert "run_shell_command" not in names
    assert "list_projects" in names


def test_dead_endpoint_is_not_mcp():
    r = mp.verify_mcp_endpoint("http://127.0.0.1:9109/mcp")  # nothing listening
    assert r["is_mcp"] is False
    assert r["errors"]
