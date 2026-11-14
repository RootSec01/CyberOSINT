import json
import socket
import sys
from pathlib import Path

from evaluation import dvmcp

ROOT = Path(__file__).resolve().parent.parent

CHALLENGE = '''
import sys
sys.path.insert(0, {root!r})
from lab import server
server.serve("legacy", {port}, profile={profile!r})
'''


def free_port_base():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1] - 1


def test_expectations_cover_every_challenge_and_name_real_detectors():
    from benchmark.runner import CATEGORIES
    challenges = json.loads(dvmcp.EXPECTATIONS.read_text())["challenges"]
    assert [c["id"] for c in challenges] == list(range(1, 16))
    for challenge in challenges:
        assert challenge["in_scope"] == bool(challenge.get("expect_any"))
        assert set(challenge.get("expect_any", [])) <= set(CATEGORIES)


def test_scoring_separates_detected_missed_and_out_of_scope():
    listed = {"listed": True, "findings": ["rce"]}
    assert dvmcp.score({"in_scope": True, "expect_any": ["rce", "tool_poisoning"]}, listed) == "detected"
    assert dvmcp.score({"in_scope": True, "expect_any": ["tool_poisoning"]}, listed) == "missed"
    assert dvmcp.score({"in_scope": False}, listed) == "out_of_scope"
    assert dvmcp.score({"in_scope": True, "expect_any": ["rce"]}, {"listed": False}) == "not_scanned"


def test_a_challenge_is_started_scanned_and_stopped(tmp_path, monkeypatch):
    base = free_port_base()
    monkeypatch.setattr(dvmcp, "FIRST_PORT", base)
    home = tmp_path / "challenges" / "hard" / "challenge1"
    home.mkdir(parents=True)
    (home / "server.py").write_text(CHALLENGE.format(root=str(ROOT), port=base + 1, profile="dangerous"))

    seen = dvmcp.scan_challenge(tmp_path, 1, sys.executable)
    assert seen["listed"] and seen["tools"] == 5 and "rce" in seen["findings"]
    with socket.socket() as sock:
        assert sock.connect_ex(("127.0.0.1", base + 1)) != 0
    assert dvmcp.scan_challenge(tmp_path, 2, sys.executable) == {
        "started": False, "detail": "server.py not found"}
