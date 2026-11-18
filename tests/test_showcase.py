import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lab.showcase import Unsafe, settings

ROOT = Path(__file__).resolve().parent.parent
GOOD = {
    "SHOWCASE_ADMIN_PASSWORD": "Admin-showcase-pass-71",
    "SHOWCASE_VIEWER_PASSWORD": "Viewer-showcase-pass-38",
    "SHOWCASE_JWT_SECRET": "5f0c2a9e1b7d4c3a8e6f2b1d9c7a5e3f0b8d6c4a2e9f7b5d",
    "SHOWCASE_OWNERSHIP_SECRET": "a1c3e5f7b9d2846e0c1f3a5b7d9e2c4f6a8b0d1e3c5f7a9b",
    "SHOWCASE_ORIGIN": "https://raqeeb.example.org:8443",
}


def test_settings_lock_the_showcase_down():
    public = settings(GOOD)
    assert public["admin"] == ("rami", GOOD["SHOWCASE_ADMIN_PASSWORD"])
    assert public["viewer"][0] == "viewer"
    locked = public["settings"]
    assert locked["LEGACY_API"] == "false" and locked["API_DOCS"] == "false"
    assert locked["FORCE_HTTPS"] == "true" and locked["RATE_LIMIT_ENABLED"] == "true"
    assert locked["CORS_ALLOW_ORIGINS"] == GOOD["SHOWCASE_ORIGIN"]
    assert locked["GUEST_USER"] == "viewer"


def test_the_visitor_account_needs_no_password_of_its_own():
    first = settings({**GOOD, "SHOWCASE_VIEWER_PASSWORD": ""})["viewer"][1]
    second = settings({**GOOD, "SHOWCASE_VIEWER_PASSWORD": ""})["viewer"][1]
    assert len(first) >= 30 and first != second


@pytest.mark.parametrize("change", [
    {"SHOWCASE_ADMIN_PASSWORD": ""},
    {"SHOWCASE_VIEWER_PASSWORD": "short-one"},
    {"SHOWCASE_VIEWER_PASSWORD": GOOD["SHOWCASE_ADMIN_PASSWORD"]},
    {"SHOWCASE_VIEWER_USER": "rami"},
    {"SHOWCASE_ADMIN_USER": "Not A Name"},
    {"SHOWCASE_JWT_SECRET": "a" * 64},
    {"SHOWCASE_OWNERSHIP_SECRET": ""},
    {"SHOWCASE_ORIGIN": "http://raqeeb.example.org:8443"},
])
def test_unsafe_settings_are_refused(change):
    with pytest.raises(Unsafe):
        settings({**GOOD, **change})


def test_showcase_stages_the_demo_with_a_read_only_viewer(tmp_path):
    code = ("import json, os; from lab.showcase import settings; from lab.tampering import run_demo; "
            "print(json.dumps(run_demo(public=settings(os.environ))))")
    env = {**os.environ, **GOOD, "PYTHONPATH": str(ROOT), "APP_ENV": "development"}
    done = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result == {"mode": "public_showcase", "servers": ["match", "deviation"], "viewer_read_only": True}


def test_showcase_has_no_route_out():
    compose = (ROOT / "deploy" / "compose.yaml").read_text()
    showcase = compose.split("  showcase:\n", 1)[1].split("\n  web:\n", 1)[0]
    assert "networks:\n      - showcase" in showcase and "ports" not in showcase and "env_file" not in showcase
    assert "networks:\n  showcase:\n    internal: true" in compose
    assert "target: app" in compose.split("  showcase:\n", 1)[0]
