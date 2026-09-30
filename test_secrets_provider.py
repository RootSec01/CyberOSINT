"""secrets_provider tests — env backend, file backend, fallback, presence."""
import json
import os
import tempfile

import secrets_provider as sp


def test_env_backend_reads_environment(monkeypatch):
    monkeypatch.setenv("SECRETS_BACKEND", "env")
    monkeypatch.setenv("MY_SECRET", "abc123")
    sp.reset_cache()
    assert sp.get_secret("MY_SECRET") == "abc123"
    assert sp.has_secret("MY_SECRET") is True
    assert sp.has_secret("NOT_SET_SECRET") is False


def test_file_backend_reads_json(monkeypatch):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "secrets.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"OPENAI_API_KEY": "sk-from-file"}, f)
    monkeypatch.setenv("SECRETS_BACKEND", "file")
    monkeypatch.setenv("SECRETS_FILE", path)
    sp.reset_cache()
    assert sp.get_secret("OPENAI_API_KEY") == "sk-from-file"


def test_file_backend_falls_back_to_env(monkeypatch):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "secrets.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"SOME_KEY": "x"}, f)
    monkeypatch.setenv("SECRETS_BACKEND", "file")
    monkeypatch.setenv("SECRETS_FILE", path)
    monkeypatch.setenv("ONLY_IN_ENV", "env-value")
    sp.reset_cache()
    # key absent from file -> falls back to the environment
    assert sp.get_secret("ONLY_IN_ENV") == "env-value"


def test_missing_file_is_safe(monkeypatch):
    monkeypatch.setenv("SECRETS_BACKEND", "file")
    monkeypatch.setenv("SECRETS_FILE", "/nonexistent/secrets.json")
    monkeypatch.setenv("FALLBACK_KEY", "ok")
    sp.reset_cache()
    assert sp.get_secret("FALLBACK_KEY") == "ok"
    assert sp.get_secret("NOPE") is None
