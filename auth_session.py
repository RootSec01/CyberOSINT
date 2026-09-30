"""Session auth via signed JWTs — replaces the single static admin token.

A user logs in with username + password; on success we issue a short-lived JWT
signed with JWT_SECRET. Every protected endpoint validates that token and loads
the current user. Roles ("admin"/"user") gate admin-only actions.

Env:
    JWT_SECRET            required in production (falls back to a dev value with a warning)
    JWT_TTL_MINUTES       session lifetime (default 720 = 12h)
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from db import get_db
from models_db import User

_ALGO = "HS256"


def _secret() -> str:
    return os.getenv("JWT_SECRET", "").strip() or "dev-only-insecure-secret-change-me"


def _ttl_minutes() -> int:
    try:
        return int(os.getenv("JWT_TTL_MINUTES", "720"))
    except ValueError:
        return 720


def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=_ttl_minutes()),
    }
    return jwt.encode(payload, _secret(), algorithm=_ALGO)


def _decode(token: str) -> dict:
    try:
        return jwt.decode(token, _secret(), algorithms=[_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid session token")


def _bearer_token(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def get_current_user(
    authorization: Optional[str] = Header(default=None),
    x_auth_token: Optional[str] = Header(default=None, alias="X-Auth-Token"),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency: resolve and validate the logged-in user, or 401."""
    token = _bearer_token(authorization) or x_auth_token
    if not token:
        raise HTTPException(status_code=401, detail="authentication required")
    payload = _decode(token)
    user = db.query(User).filter_by(id=int(payload.get("sub", 0))).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    return user


def require_admin_user(user: User = Depends(get_current_user)) -> User:
    """Dependency for admin-only endpoints (issuing/revoking scan grants)."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user


def authenticate(db: Session, username: str, password: str) -> Optional[User]:
    """Return the user if credentials are valid and the account is active."""
    from security import verify_password
    user = db.query(User).filter_by(username=(username or "").strip().lower()).first()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def user_from_token(db: Session, token: str) -> Optional[User]:
    """Resolve a user from a raw JWT (used where headers aren't available,
    e.g. an EventSource stream that can only pass a query-string token)."""
    if not token:
        return None
    try:
        payload = _decode(token)
    except HTTPException:
        return None
    user = db.query(User).filter_by(id=int(payload.get("sub", 0))).first()
    return user if user and user.is_active else None
