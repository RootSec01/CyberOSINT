"""Copilot tests: the grounded fallback briefing, targeted questions, empty
evidence, suggested questions, and the endpoint. LLM path is not exercised
(no key in CI) — the fallback is the deterministic surface we can assert on."""
import json
import tempfile

import pytest
from sqlalchemy import create_engine

import copilot
import db
import models_db as m
from security import hash_password

CTX_MCP = {
    "asset": {"value": "127.0.0.1:9500", "kind": "mcp", "risk": "Critical",
              "monitoring": True, "last_scanned_at": None},
    "exposure": {"type": "mcp", "severity": "Critical", "auth_required": False,
                 "tool_count": 4, "dangerous_tools": ["run_shell_command", "read_file"]},
    "drift": {"available": True, "summary": "1 new dangerous tool(s)",
              "change_count": 1,
              "changes": [{"kind": "tool_appeared", "detail": "run_shell_command",
                           "tone": "crit"}]},
    "open_alerts": [{"severity": "Critical",
                     "title": "Exposure increased on 127.0.0.1:9500", "detail": "x"}],
}


def test_fallback_briefing_is_grounded():
    r = copilot.answer(CTX_MCP, "")
    assert r["grounded"] is True and r["mode"] == "offline"
    text = r["answer"]
    assert "127.0.0.1:9500" in text          # the actual asset
    assert "run_shell_command" in text        # the actual exposed tool
    assert "Recommended actions" in text


def test_fallback_targeted_fix_question():
    r = copilot.answer(CTX_MCP, "what should I do to fix this?")
    assert "authentication" in r["answer"].lower()  # auth_required is False


def test_fallback_no_evidence():
    ctx = {"asset": {"value": "x.example", "kind": "domain"},
           "exposure": {"type": "unknown"}, "drift": {"available": False},
           "open_alerts": []}
    assert "no scan evidence" in copilot.answer(ctx, "").get("answer").lower()


def test_suggested_questions_reflect_context():
    qs = copilot.suggested_questions(CTX_MCP)
    assert isinstance(qs, list) and 1 <= len(qs) <= 4
    assert any("changed" in q.lower() for q in qs)   # drift available


def test_offline_mode_never_calls_a_provider(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("provider must not be called in offline mode")
    monkeypatch.setattr(copilot, "_provider_call", boom)
    r = copilot.answer(CTX_MCP, "", mode="offline")
    assert r["mode"] == "offline" and r["answer"]


def test_redacted_mode_sends_stripped_context(monkeypatch):
    captured = {}

    def fake(provider, base_url, model, system, user_msg):
        captured["msg"] = user_msg
        return "ok answer"

    monkeypatch.setattr(copilot, "_provider_call", fake)
    r = copilot.answer(CTX_MCP, "brief me", mode="redacted", provider="openai")
    assert r["answer"] == "ok answer" and r["mode"] == "redacted"
    assert "127.0.0.1" not in captured["msg"]        # identifier stripped
    assert "run_shell_command" in captured["msg"]     # finding preserved


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/copilot.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="cara", password_hash=hash_password("password123")))
        s.flush()
        uid = s.query(m.User).filter_by(username="cara").first().id
        s.add(m.Asset(user_id=uid, kind="mcp", value="127.0.0.1:9500",
                      label="lab", monitoring=True))
        s.flush()
        report = {"kind": "safe_proof", "safe_proof": {
            "severity": "Critical", "auth_required": False, "tool_count": 4,
            "dangerous_tools": [{"name": "run_shell_command", "risk_flags": ["command_exec"]}]}}
        s.add(m.Run(user_id=uid, run_id="r1", target_type="mcp",
                    target_value="127.0.0.1:9500", risk_level="Critical",
                    report_json=json.dumps(report)))
    yield


def test_copilot_endpoint_answers_grounded():
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    tok = c.post("/api/login",
                 data={"username": "cara", "password": "password123"}).json()["token"]
    H = {"Authorization": f"Bearer {tok}"}
    with db.session_scope() as s:
        aid = s.query(m.Asset).filter_by(value="127.0.0.1:9500").first().id

    # Empty question -> full briefing, grounded on the actual exposed tool.
    r = c.post(f"/api/assets/{aid}/copilot", data={"question": ""}, headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["answer"] and "run_shell_command" in body["answer"]
    assert isinstance(body["suggestions"], list) and body["suggestions"]
    assert body["context"]["exposure_type"] == "mcp"

    # Fix-focused question -> concrete remediation (auth is currently off).
    r2 = c.post(f"/api/assets/{aid}/copilot",
                data={"question": "what should I fix first?"}, headers=H)
    assert "authentication" in r2.json()["answer"].lower()
