import json
import shutil
import time
from pathlib import Path

from raqeeb import db, visits
from raqeeb import models as m
from raqeeb.security import hash_password
from tests.test_cases import signed_in

SAMPLE = Path(__file__).parent / "data" / "showcase-access.log"


def _log(tmp_path, *entries):
    path = tmp_path / "showcase.log"
    lines = SAMPLE.read_text().splitlines()
    for ts, uri, status, ip in entries:
        entry = json.loads(lines[0])
        entry.update(ts=ts, status=status)
        entry["request"].update(uri=uri, client_ip=ip, remote_ip=ip)
        lines.append(json.dumps(entry))
    path.write_text("\n".join(lines[1:]) + "\nnot json\n")
    return path


def test_a_visit_is_one_successful_entry_through_the_guest_door(tmp_path):
    now = time.time()
    path = _log(tmp_path, (now - 60, "/api/guest", 200, "203.0.113.7"), (now - 30, "/api/guest", 200, "203.0.113.7"),
                (now - 20, "/api/guest", 429, "198.51.100.2"), (now - 10, "/api/assets", 200, "198.51.100.2"),
                (now - 3 * 86400, "/api/guest", 200, "198.51.100.9"))
    seen = visits.recent(hours=24, path=path)
    assert seen["available"] and seen["total"] == 2 and seen["addresses"] == 1
    assert seen["visits"][0]["ip"] == "203.0.113.7" and seen["visits"][0]["ts"] > seen["visits"][1]["ts"]
    assert visits.recent(hours=24, path=tmp_path / "missing.log")["available"] is False


def test_rolled_logs_are_read_too(tmp_path):
    path = _log(tmp_path, (time.time() - 60, "/api/guest", 200, "203.0.113.7"))
    shutil.copy(path, tmp_path / "showcase-2026-11-18T21-00-00.000.log")
    assert visits.recent(path=path)["total"] == 2


def test_only_platform_administrators_see_demo_visitors(console, tmp_path, monkeypatch):
    monkeypatch.setenv("SHOWCASE_LOG", str(_log(tmp_path, (time.time() - 60, "/api/guest", 200, "203.0.113.7"))))
    with db.session_scope() as session:
        session.add(m.User(username="root", role="admin", password_hash=hash_password("password123")))
    assert console.get("/api/showcase/visits", headers=signed_in(console, "rami")).status_code == 403
    seen = console.get("/api/showcase/visits", headers=signed_in(console, "root")).json()
    assert seen["total"] == 1 and seen["visits"][0]["ip"] == "203.0.113.7"
