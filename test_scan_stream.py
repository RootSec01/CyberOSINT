"""Tests for the live scan event stream (ordering + completeness)."""
import threading
import time

import pytest

import scan_stream as ss
from mcp_labserver import make_server


@pytest.fixture(scope="module")
def lab():
    srv = make_server("modern", 9801)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.5)
    yield
    srv.shutdown()


def _collect(**kw):
    return list(ss.mcp_scan_events("127.0.0.1", 9801, use_tls=False, **kw))


def test_stream_is_ordered_and_complete(lab):
    events = _collect(canary_allowed=True)
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs)                       # strictly ordered
    kinds = [e.get("kind") for e in events if e["type"] == "node"]
    assert "target" in kinds and "mcp_server" in kinds
    assert "tool" in kinds and "attack_step" in kinds and "blast" in kinds
    assert events[-1]["type"] == "done"
    assert events[-1]["result"]["exposure_verdict"] == "DECLARATION RISK DETECTED"


def test_first_node_is_target(lab):
    events = _collect()
    first_node = next(e for e in events if e["type"] == "node")
    assert first_node["kind"] == "target"


def test_dangerous_tools_are_toned(lab):
    events = _collect()
    tools = [e for e in events if e.get("kind") == "tool"]
    assert any(t["meta"]["dangerous"] for t in tools)


def test_sse_format():
    frame = ss.sse_format({"type": "stage", "seq": 1})
    assert frame.startswith("data: ") and frame.endswith("\n\n")


def test_canary_demonstrates_when_allowed(lab):
    events = _collect(canary_allowed=True)
    assert events[-1]["result"]["safety"]["verification_method"] == "canary-lab"
    # and NOT demonstrated when canary is disallowed
    ev2 = _collect(canary_allowed=False)
    assert ev2[-1]["result"]["safety"]["verification_method"] == "declaration"
