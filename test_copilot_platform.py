"""Platform-wide copilot tests: the portfolio fallback briefing, targeted
questions, privacy modes, suggested questions, the /api/copilot endpoint, and
tenant isolation. The LLM path is not exercised (no key in CI) — the
deterministic fallback is the surface we assert on."""
import json
import tempfile

import pytest
from sqlalchemy import create_engine

import copilot
import db
import models_db as m
from security import hash_password

PLATFORM_CTX = {
    "portfolio": {"asset_count": 3, "monitored_count": 2,
                  "risk_breakdown": {"Critical": 1, "High": 1, "Low": 1},
                  "open_alert_count": 1},
    "assets": [
        {"value": "10.0.0.5:9500", "kind": "mcp", "label": "agent-prod",
         "risk": "Critical", "monitoring": True, "last_scanned_at": None,
         "exposure": {"type": "mcp", "severity": "Critical", "auth_required": False,
                      "dangerous_tools": ["run_shell_command", "execute_sql"]}},
        {"value": "api.example.com", "kind": "domain", "label": "api",
         "risk": "High", "monitoring": True, "last_scanned_at": None,
         "exposure": {"type": "surface", "risk_level": "High",
                      "services": ["443/https"], "cves": ["CVE-2024-1234"]}},
        {"value": "blog.example.com", "kind": "domain", "label": "blog",
         "risk": "Low", "monitoring": False, "last_scanned_at": None,
         "exposure": {"type": "surface", "risk_level": "Low",
                      "services": ["80/http"], "cves": []}},
    ],
    "open_alerts": [{"severity": "Critical", "title": "Exposure increased on agent-prod",
                     "detail": "1 new dangerous tool", "asset": "agent-prod"}],
    "recent_changes": [{"asset": "agent-prod", "summary": "1 new dangerous tool(s)",
                        "escalations": ["run_shell_command"]}],
}


def test_platform_fallback_is_grounded():
    r = copilot.platform_answer(PLATFORM_CTX, "")
    assert r["grounded"] is True and r["mode"] == "offline"
    text = r["answer"]
    assert "3 asset" in text                     # portfolio count
    assert "10.0.0.5:9500" in text               # riskiest asset shown first
    assert "run_shell_command" in text            # actual exposed tool
    assert "Recommended priorities" in text


def test_platform_targeted_risk_question():
    r = copilot.platform_answer(PLATFORM_CTX, "what are my riskiest assets?")
    text = r["answer"]
    assert "Riskiest assets" in text
    # Critical asset must be listed before the High one.
    assert text.index("10.0.0.5:9500") < text.index("api.example.com")


def test_platform_fix_question_prioritises_open_mcp():
    r = copilot.platform_answer(PLATFORM_CTX, "what should my team fix first?")
    assert "authentication" in r["answer"].lower()   # an MCP endpoint is open


def test_platform_suggested_questions_reflect_context():
    qs = copilot.suggested_questions_platform(PLATFORM_CTX)
    assert isinstance(qs, list) and 1 <= len(qs) <= 4
    assert any("alert" in q.lower() for q in qs)     # open alerts present


def test_platform_offline_never_calls_provider(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("provider must not be called in offline mode")
    monkeypatch.setattr(copilot, "_provider_call", boom)
    r = copilot.platform_answer(PLATFORM_CTX, "", mode="offline")
    assert r["mode"] == "offline" and r["answer"]


def test_platform_redacted_sends_stripped_context(monkeypatch):
    captured = {}

    def fake(provider, base_url, model, system, user_msg):
        captured["msg"] = user_msg
        return "ok answer"

    monkeypatch.setattr(copilot, "_provider_call", fake)
    r = copilot.platform_answer(PLATFORM_CTX, "brief me", mode="redacted", provider="openai")
    assert r["answer"] == "ok answer" and r["mode"] == "redacted"
    assert "10.0.0.5" not in captured["msg"]         # identifiers stripped
    assert "api.example.com" not in captured["msg"]   # host stripped
    assert "run_shell_command" in captured["msg"]     # finding preserved
    assert "CVE-2024-1234" in captured["msg"]         # finding preserved


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/copilot_platform.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        # Two tenants; each with one asset + a scan.
        s.add(m.User(username="pam", password_hash=hash_password("password123")))
        s.add(m.User(username="quinn", password_hash=hash_password("password123")))
        s.flush()
        pam = s.query(m.User).filter_by(username="pam").first().id
        quinn = s.query(m.User).filter_by(username="quinn").first().id

        s.add(m.Asset(user_id=pam, kind="mcp", value="127.0.0.1:9500",
                      label="pam-agent", monitoring=True))
        s.add(m.Asset(user_id=quinn, kind="mcp", value="127.0.0.1:9600",
                      label="quinn-secret-agent", monitoring=True))
        s.flush()
        report = {"kind": "safe_proof", "safe_proof": {
            "severity": "Critical", "auth_required": False, "tool_count": 4,
            "dangerous_tools": [{"name": "run_shell_command", "risk_flags": ["command_exec"]}]}}
        s.add(m.Run(user_id=pam, run_id="r1", target_type="mcp",
                    target_value="127.0.0.1:9500", risk_level="Critical",
                    report_json=json.dumps(report)))
        # update the asset's cached risk so it appears in the breakdown
        a = s.query(m.Asset).filter_by(value="127.0.0.1:9500").first()
        a.last_risk_level = "Critical"
    yield


def test_platform_endpoint_answers_grounded():
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    tok = c.post("/api/login",
                 data={"username": "pam", "password": "password123"}).json()["token"]
    H = {"Authorization": f"Bearer {tok}"}

    r = c.post("/api/copilot", data={"question": ""}, headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["answer"] and "run_shell_command" in body["answer"]
    assert body["context"]["asset_count"] == 1
    assert isinstance(body["suggestions"], list) and body["suggestions"]


def test_platform_endpoint_isolated_between_tenants():
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    tok = c.post("/api/login",
                 data={"username": "pam", "password": "password123"}).json()["token"]
    H = {"Authorization": f"Bearer {tok}"}
    r = c.post("/api/copilot", data={"question": "list my assets"}, headers=H)
    body = r.json()
    # pam must never see quinn's asset in her platform briefing.
    assert "quinn-secret-agent" not in body["answer"]
    assert "127.0.0.1:9600" not in body["answer"]
    assert body["context"]["asset_count"] == 1
