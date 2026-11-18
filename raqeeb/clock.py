"""Times written into reports and briefings, in the installation's time zone."""
from __future__ import annotations

import os
from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def zone() -> tzinfo:
    name = os.getenv("TIMEZONE", "").strip()
    if name:
        try:
            return ZoneInfo(name)
        except ZoneInfoNotFoundError:
            pass
    return datetime.now().astimezone().tzinfo or timezone.utc


def shown(moment) -> str:
    if moment is None:
        return "—"
    if isinstance(moment, str):
        moment = datetime.fromisoformat(moment.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    local = moment.astimezone(zone())
    return f"{local.strftime('%d %b %Y, %H:%M')} {local.tzname()}"


def now() -> str:
    return shown(datetime.now(timezone.utc))
