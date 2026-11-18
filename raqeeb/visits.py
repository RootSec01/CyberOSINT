"""Who opened the public showcase, read from the access log the web server keeps for it.

The showcase has no route to this installation, so its visits are taken from the log Caddy writes
for the showcase site and shares read-only with the app. A visit is one entry through /api/guest.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

SHOWN = 200


def log_path() -> Optional[Path]:
    value = os.getenv("SHOWCASE_LOG", "").strip()
    return Path(value) if value else None


def _lines(path: Path) -> list[str]:
    rolled = sorted(path.parent.glob(f"{path.stem}-*{path.suffix}"))
    lines: list[str] = []
    for part in [*rolled, path]:
        try:
            lines.extend(part.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
    return lines


def recent(hours: int = 24, path: Optional[Path] = None) -> dict:
    path = path or log_path()
    if not path or not path.exists():
        return {"available": False, "visits": [], "total": 0, "addresses": 0}
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    visits = []
    for line in _lines(path):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        request = entry.get("request") or {}
        if request.get("uri") != "/api/guest" or entry.get("status") != 200:
            continue
        moment = datetime.fromtimestamp(float(entry.get("ts") or 0), timezone.utc)
        if moment < since:
            continue
        agent = ((request.get("headers") or {}).get("User-Agent") or [""])[0]
        visits.append({"ts": moment.isoformat(timespec="seconds"),
                       "ip": request.get("client_ip") or request.get("remote_ip") or "",
                       "agent": agent[:200]})
    visits.sort(key=lambda visit: visit["ts"], reverse=True)
    return {"available": True, "visits": visits[:SHOWN], "total": len(visits),
            "addresses": len({visit["ip"] for visit in visits})}
