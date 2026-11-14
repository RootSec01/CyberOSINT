"""Secret retrieval seam — environment by default, pluggable to a file/vault.

Production deployments should not keep API keys in a committed .env. This module
is the single place the rest of the app asks for a secret, so migrating to a real
secrets manager (HashiCorp Vault, AWS/GCP Secrets Manager, a mounted secrets
file, a Kubernetes secret) is one change here — no call sites move.

Backends (SECRETS_BACKEND):
  env   (default)   read from the process environment
  file              read from a JSON object at SECRETS_FILE (e.g. a mounted secret)

Any backend falls back to the environment when a key is absent, so a partial
migration is always safe. Secret VALUES are never logged or returned to clients;
callers surface presence only (see has_secret).
"""

from __future__ import annotations

import functools
import json
import os
from typing import Optional


def _backend() -> str:
    return os.getenv("SECRETS_BACKEND", "env").strip().lower()


@functools.lru_cache(maxsize=1)
def _file_secrets() -> dict:
    path = os.getenv("SECRETS_FILE", "").strip()
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    """Return a secret by name from the active backend, or the environment."""
    if _backend() == "file":
        val = _file_secrets().get(name)
        if val:
            return str(val)
    return os.getenv(name, default)


def has_secret(name: str) -> bool:
    """True if the secret is configured — used to surface presence, never value."""
    return bool(get_secret(name))


def reset_cache() -> None:
    """Clear the cached file backend (tests / hot-reload after rotation)."""
    _file_secrets.cache_clear()
