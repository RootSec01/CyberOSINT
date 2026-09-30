"""Production preflight, demo segregation and read-only schema gates."""
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine

from deployment_config import DeploymentError, load_deployment


VALID = {
    "APP_ENV": "production", "DATABASE_URL": "postgresql+psycopg://u:p@db.example.net/app",
    "JWT_SECRET": "V6d9-8Vqaf3wGmQ2n7JdYp0kT3sQ8rHl",
    "OWNERSHIP_SECRET": "Z9aF8Nd2M3pX7vQ4bC6rS1tK5wL0hJgY",
    "REQUIRE_OWNERSHIP_PROOF": "true", "RATE_LIMIT_ENABLED": "true", "FORCE_HTTPS": "true",
    "CORS_ALLOW_ORIGINS": "https://osint.example.net", "WEB_CONCURRENCY": "1",
}


def test_valid_production():
    cfg = load_deployment(VALID)
    assert cfg.production and not cfg.demo_mode and cfg.database_kind == "postgres"


@pytest.mark.parametrize("key,value", [
    ("APP_ENV", "prod"), ("DATABASE_URL", "sqlite:///prod.db"),
    ("JWT_SECRET", "dev-only-insecure-secret-change-me"),
    ("OWNERSHIP_SECRET", "a" * 45), ("REQUIRE_OWNERSHIP_PROOF", "false"),
    ("RATE_LIMIT_ENABLED", "false"), ("FORCE_HTTPS", "false"),
    ("UNRESTRICTED_SCAN", "true"), ("WEB_CONCURRENCY", "2"),
    ("CORS_ALLOW_ORIGINS", "http://osint.example.net"),
    ("CORS_ALLOW_ORIGINS", "https://localhost"),
    ("CORS_ALLOW_ORIGINS", "https://user:pass@osint.example.net"),
    ("ALERT_WEBHOOK_URL", "http://hooks.example.net/alerts"),
    ("ALERT_WEBHOOK_URL", "https://hooks.example.net/alerts"),
])
def test_bad_production_rejected(key, value):
    with pytest.raises(DeploymentError):
        load_deployment({**VALID, key: value})


def test_allowlisted_webhook_path():
    cfg = load_deployment({**VALID, "ALERT_WEBHOOK_URL": "https://hooks.example.net/alerts",
                           "EGRESS_ALLOW_HOSTS": "hooks.example.net"})
    assert cfg.production


def test_invalid_config_stops_before_creating_database(tmp_path):
    path = tmp_path / "forbidden.db"
    env = {**os.environ, **VALID, "DATABASE_URL": f"sqlite:///{path}"}
    result = subprocess.run([sys.executable, "-c", "import main"], cwd=Path(__file__).parent,
                            env=env, capture_output=True, text=True)
    assert result.returncode != 0 and "PostgreSQL DATABASE_URL" in result.stderr
    assert not path.exists()


def test_schema_check_is_read_only_and_rejects_missing_table(tmp_path, monkeypatch):
    import db
    eng = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    monkeypatch.setattr(db, "engine", eng)
    with pytest.raises(RuntimeError, match="missing table"):
        db.check_production_schema()
    assert not __import__("sqlalchemy").inspect(eng).get_table_names()
    eng.dispose()


def test_schema_check_accepts_existing_schema(tmp_path, monkeypatch):
    import db
    eng = create_engine(f"sqlite:///{tmp_path / 'complete.db'}")
    monkeypatch.setattr(db, "engine", eng)
    db.init_db()
    db.check_production_schema()
    eng.dispose()


def test_simulated_feeds_only_demo(tmp_path, monkeypatch):
    import threat_feeds
    import pipeline
    monkeypatch.setenv("APP_ENV", "development")
    assert threat_feeds.load_threat_intel_for_target("8.8.8.8", None, str(Path(__file__).parent)) == {
        "public_feeds": [], "darkweb": []}
    assert pipeline._match_threat_intel("8.8.8.8", None, None) == {
        "public_feeds": [], "darkweb": []}
    monkeypatch.setattr(pipeline, "RUNS_ROOT", tmp_path)
    monkeypatch.setattr(pipeline, "_ip_from_shodan_search", lambda *_: None)
    monkeypatch.setattr(pipeline, "ingest_ip_shodan", lambda *_: None)
    monkeypatch.setattr(pipeline, "save_censys", lambda *_: None)
    actual = pipeline.run_ingestion("asn", "AS15169")
    assert actual["resolved_ip"] is None and not actual["simulation_used"]
    assert not actual["threat_intel"]["public_feeds"]
    monkeypatch.setenv("APP_ENV", "demo")
    demo = pipeline.run_ingestion("asn", "AS15169")
    assert demo["resolved_ip"] == "8.8.8.8" and demo["simulation_used"]
    assert "demo" in demo["source_provenance"]["resolved_ip"]


def test_lab_server_blocked_in_production(monkeypatch):
    import mcp_labserver
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError, match="disabled"):
        mcp_labserver.make_server("modern", 0)


def test_forwarded_proto_untrusted(monkeypatch):
    import main
    from fastapi.testclient import TestClient
    monkeypatch.setattr(main, "_FORCE_HTTPS", True)
    response = TestClient(main.app).get("/api/health", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 403
    assert response.json()["detail"] == "HTTPS required"
