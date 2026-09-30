"""Validate deployment settings before importing components with side effects."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse

VALID_ENVS = {"development", "test", "demo", "production"}


class DeploymentError(ValueError):
    """Deployment settings are inconsistent or unsafe."""


@dataclass(frozen=True)
class Deployment:
    environment: str
    demo_mode: bool
    production: bool
    cors_origins: tuple[str, ...]
    rate_limit_enabled: bool
    force_https: bool
    scheduler_enabled: bool
    database_kind: str


def _flag(env: Mapping[str, str], name: str, default: str = "false") -> bool:
    value = str(env.get(name, default)).strip().lower()
    if value not in {"true", "false"}:
        raise DeploymentError(f"{name} must be true or false")
    return value == "true"


def _strong(value: str) -> bool:
    value = (value or "").strip()
    lowered = value.lower()
    return (len(value) >= 32 and len(set(value)) >= 12 and
            not any(part in lowered for part in
                    ("change-me", "placeholder", "example", "demo-only", "dev-only")))


def _public_https(url: str, *, origin: bool) -> str | None:
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
        if not host or parsed.scheme != "https" or parsed.username or parsed.password:
            return None
        if parsed.fragment or (origin and (parsed.path not in ("", "/") or parsed.query)):
            return None
        if host.lower() == "localhost" or host.lower().endswith(".localhost"):
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            pass
        if port is not None and port != 443:
            return None
        return host.lower()
    except ValueError:
        return None


def load_deployment(env: Mapping[str, str] | None = None) -> Deployment:
    env = os.environ if env is None else env
    mode = (env.get("APP_ENV") or "development").strip().lower()
    if mode not in VALID_ENVS:
        raise DeploymentError("APP_ENV must be development, test, demo, or production")
    origins = tuple(o.strip() for o in env.get("CORS_ALLOW_ORIGINS", "").split(",") if o.strip())
    rate = _flag(env, "RATE_LIMIT_ENABLED")
    https = _flag(env, "FORCE_HTTPS")
    scheduler = _flag(env, "SCHEDULER_ENABLED")
    db_url = env.get("DATABASE_URL", "sqlite:///./cyberosint.db").strip()
    kind = ("postgres" if db_url.startswith(("postgresql+", "postgresql://")) else
            "sqlite" if db_url.startswith("sqlite:") else "other")
    if mode == "production":
        if kind != "postgres" or not urlparse(db_url).hostname:
            raise DeploymentError("production requires a PostgreSQL DATABASE_URL")
        for name in ("JWT_SECRET", "OWNERSHIP_SECRET"):
            if not _strong(env.get(name, "")):
                raise DeploymentError(f"production requires a strong {name} (at least 32 characters)")
        if _flag(env, "UNRESTRICTED_SCAN"):
            raise DeploymentError("UNRESTRICTED_SCAN cannot be enabled in production")
        if not _flag(env, "REQUIRE_OWNERSHIP_PROOF"):
            raise DeploymentError("REQUIRE_OWNERSHIP_PROOF=true is required in production")
        if not rate or not https:
            raise DeploymentError("RATE_LIMIT_ENABLED=true and FORCE_HTTPS=true are required in production")
        if any(not _public_https(origin, origin=True) for origin in origins):
            raise DeploymentError("production CORS_ALLOW_ORIGINS must contain only public HTTPS origins")
        if env.get("WEB_CONCURRENCY", "1").strip() != "1" or env.get("UVICORN_WORKERS", "1").strip() != "1":
            raise DeploymentError("single worker required by the in-memory rate limiter")
        webhook = env.get("ALERT_WEBHOOK_URL", "").strip()
        if webhook:
            host = _public_https(webhook, origin=False)
            if not host:
                raise DeploymentError("ALERT_WEBHOOK_URL requires a public HTTPS host in production")
            allowed = {h.strip().lower() for h in env.get("EGRESS_ALLOW_HOSTS", "").split(",") if h.strip()}
            if host not in allowed:
                raise DeploymentError("ALERT_WEBHOOK_URL host must be in EGRESS_ALLOW_HOSTS")
    return Deployment(mode, mode == "demo", mode == "production", origins,
                      rate, https, scheduler, kind)


def demo_enabled(env: Mapping[str, str] | None = None) -> bool:
    return load_deployment(env).demo_mode
