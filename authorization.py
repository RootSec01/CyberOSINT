"""Scoped authorization and audit logging for active reconnaissance.

Active checks (Nmap, ping, TCP connect, TLS retrieval, and MCP verification)
touch a remote host directly and therefore require explicit authorization.
This module replaces the previous binary ALLOW_ALL_IPS flag with a layered
model:

    1. Standing scope      -- CIDRs the operator has pre-authorized.
    2. Per-target grants    -- one-off, time-boxed approvals for a single host.
    3. Unrestricted mode    -- explicit global override, never the default,
                               and always recorded.

Every decision is written to an append-only audit log so the operator can
prove, after the fact, exactly what was authorized and when.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Optional

_BASE_DIR = Path(__file__).resolve().parent
_AUDIT_LOG = _BASE_DIR / "evidence" / "authorization_audit.log"
_GRANTS_FILE = _BASE_DIR / "evidence" / "active_grants.json"

_DEFAULT_GRANT_TTL_MINUTES = 60

_lock = threading.RLock()


class Decision(str, Enum):
    STANDING_SCOPE = "standing_scope"
    PER_TARGET_GRANT = "per_target_grant"
    UNRESTRICTED = "unrestricted"
    DENIED = "denied"


@dataclass(frozen=True)
class AuthResult:
    allowed: bool
    decision: Decision
    ip: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "decision": self.decision.value,
            "ip": self.ip,
            "reason": self.reason,
        }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _load_standing_scope() -> list[str]:
    raw = os.getenv("AUTHORIZED_CIDRS", "")
    return [c.strip() for c in raw.split(",") if c.strip()]


def _unrestricted_enabled() -> bool:
    return os.getenv("UNRESTRICTED_SCAN", "false").strip().lower() == "true"


def _valid_ip(ip_str: str) -> Optional[str]:
    try:
        return str(ip_address(ip_str))
    except ValueError:
        return None


def _in_scope(ip_str: str, cidrs: list[str]) -> bool:
    try:
        addr = ip_address(ip_str)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------

def _write_audit(entry: dict) -> None:
    entry = {"ts": _iso(_now()), **entry}
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        # Audit persistence is best-effort; a failed write must never abort
        # the caller, but it must also never silently downgrade a decision.
        pass


# --------------------------------------------------------------------------
# Per-target grants
# --------------------------------------------------------------------------

def _read_grants() -> dict[str, str]:
    try:
        with _GRANTS_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def _write_grants(grants: dict[str, str]) -> None:
    _GRANTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _GRANTS_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(grants, fh, indent=2)
    tmp.replace(_GRANTS_FILE)


def _prune_expired(grants: dict[str, str]) -> dict[str, str]:
    now = _now()
    live: dict[str, str] = {}
    for ip, expiry in grants.items():
        try:
            if datetime.fromisoformat(expiry) > now:
                live[ip] = expiry
        except ValueError:
            continue
    return live


def grant_target(ip_str: str, ttl_minutes: int = _DEFAULT_GRANT_TTL_MINUTES,
                 operator: str = "operator", reason: str = "") -> AuthResult:
    """Authorize active checks against a single IP for a bounded window.

    This is the operator asserting, on the record, that they are permitted to
    scan this specific host (e.g. an in-scope bug-bounty asset).
    """
    ip = _valid_ip(ip_str)
    if ip is None:
        result = AuthResult(False, Decision.DENIED, ip_str, "invalid IP address")
        _write_audit({"action": "grant", "operator": operator,
                      "reason": reason, **result.as_dict()})
        return result

    ttl = max(1, min(int(ttl_minutes), 1440))
    expiry = _now() + timedelta(minutes=ttl)

    with _lock:
        grants = _prune_expired(_read_grants())
        grants[ip] = _iso(expiry)
        _write_grants(grants)

    _write_audit({
        "action": "grant",
        "operator": operator,
        "reason": reason,
        "ip": ip,
        "ttl_minutes": ttl,
        "expires": _iso(expiry),
    })
    return AuthResult(True, Decision.PER_TARGET_GRANT, ip,
                      f"granted for {ttl} minute(s)")


def revoke_target(ip_str: str, operator: str = "operator",
                  reason: str = "") -> bool:
    ip = _valid_ip(ip_str)
    if ip is None:
        return False
    with _lock:
        grants = _prune_expired(_read_grants())
        removed = grants.pop(ip, None) is not None
        _write_grants(grants)
    _write_audit({"action": "revoke", "operator": operator, "reason": reason,
                  "ip": ip, "removed": removed})
    return removed


def _has_active_grant(ip_str: str) -> bool:
    with _lock:
        grants = _prune_expired(_read_grants())
        _write_grants(grants)
        return ip_str in grants


# --------------------------------------------------------------------------
# Authorization entry point
# --------------------------------------------------------------------------

def authorize(ip_str: str, action: str = "active_check") -> AuthResult:
    """Resolve whether an active check against ip_str is authorized.

    Resolution order: per-target grant, then standing scope, then the global
    unrestricted override. Anything else is denied. Every path is audited.
    """
    ip = _valid_ip(ip_str)
    if ip is None:
        result = AuthResult(False, Decision.DENIED, ip_str, "invalid IP address")
        _write_audit({"action": action, **result.as_dict()})
        return result

    if _has_active_grant(ip):
        result = AuthResult(True, Decision.PER_TARGET_GRANT, ip,
                            "active per-target grant")
        _write_audit({"action": action, **result.as_dict()})
        return result

    if _in_scope(ip, _load_standing_scope()):
        result = AuthResult(True, Decision.STANDING_SCOPE, ip,
                            "within authorized standing scope")
        _write_audit({"action": action, **result.as_dict()})
        return result

    if _unrestricted_enabled():
        result = AuthResult(True, Decision.UNRESTRICTED, ip,
                            "unrestricted scan mode is enabled")
        _write_audit({"action": action, **result.as_dict()})
        return result

    result = AuthResult(False, Decision.DENIED, ip,
                        "no grant, outside standing scope")
    _write_audit({"action": action, **result.as_dict()})
    return result


def scope_summary() -> dict:
    """Snapshot of the current authorization posture, for display in the UI."""
    with _lock:
        grants = _prune_expired(_read_grants())
        _write_grants(grants)
    return {
        "standing_scope": _load_standing_scope(),
        "active_grants": [
            {"ip": ip, "expires": expiry} for ip, expiry in grants.items()
        ],
        "unrestricted": _unrestricted_enabled(),
    }
