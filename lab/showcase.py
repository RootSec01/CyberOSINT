"""The tampering demo as a public showcase: visitors look around read-only, one administrator works.

The console runs in a network with no route out, and every server it can reach is a lab listener
in the same process. Each start begins from an empty database.
Run: python -m lab.showcase    (settings come from the environment; see deploy/env.example)
"""
from __future__ import annotations

import os
import re
import secrets
import sys
from typing import Mapping

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
SHORTEST_PASSWORD = 16
SHORTEST_SECRET = 32


class Unsafe(ValueError):
    pass


def _required(env: Mapping[str, str], name: str, shortest: int) -> str:
    value = (env.get(name) or "").strip()
    if len(value) < shortest or len(set(value)) < 10:
        raise Unsafe(f"{name} must be at least {shortest} varied characters")
    return value


def _username(env: Mapping[str, str], name: str, default: str) -> str:
    value = (env.get(name) or default).strip().lower()
    if not USERNAME.match(value):
        raise Unsafe(f"{name} is not a valid username")
    return value


def settings(env: Mapping[str, str]) -> dict:
    admin = _username(env, "SHOWCASE_ADMIN_USER", "rami")
    viewer = _username(env, "SHOWCASE_VIEWER_USER", "viewer")
    if admin == viewer:
        raise Unsafe("the administrator and the viewer need different usernames")
    admin_password = _required(env, "SHOWCASE_ADMIN_PASSWORD", SHORTEST_PASSWORD)
    viewer_password = (_required(env, "SHOWCASE_VIEWER_PASSWORD", SHORTEST_PASSWORD)
                       if (env.get("SHOWCASE_VIEWER_PASSWORD") or "").strip() else secrets.token_urlsafe(24))
    if admin_password == viewer_password:
        raise Unsafe("the administrator and the viewer need different passwords")
    origin = (env.get("SHOWCASE_ORIGIN") or "").strip().rstrip("/")
    if not origin.startswith("https://"):
        raise Unsafe("SHOWCASE_ORIGIN must be the https address the showcase is served on")
    return {
        "admin": (admin, admin_password),
        "viewer": (viewer, viewer_password),
        "host": "0.0.0.0",
        "settings": {
            "JWT_SECRET": _required(env, "SHOWCASE_JWT_SECRET", SHORTEST_SECRET),
            "OWNERSHIP_SECRET": _required(env, "SHOWCASE_OWNERSHIP_SECRET", SHORTEST_SECRET),
            "CORS_ALLOW_ORIGINS": origin,
            "PUBLIC_SITE_URL": origin,
            "GUEST_USER": viewer,
            "LEGACY_API": "false",
            "API_DOCS": "false",
            "FORCE_HTTPS": "true",
            "RATE_LIMIT_ENABLED": "true",
            "RATE_LIMIT_LOGIN": "10/minute",
        },
    }


def main() -> None:
    try:
        public = settings(os.environ)
    except Unsafe as exc:
        sys.exit(f"showcase: {exc}")
    from lab.tampering import run_demo
    run_demo(serve=True, port=int(os.getenv("SHOWCASE_PORT", "8000")), public=public)


if __name__ == "__main__":
    main()
