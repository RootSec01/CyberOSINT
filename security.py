"""Password hashing with bcrypt (used directly; passlib is unmaintained).

Passwords are never stored in plain text. bcrypt uses only the first 72 bytes
of a password, so we truncate to that boundary explicitly and safely.
"""

from __future__ import annotations

import bcrypt

_MAX = 72  # bcrypt hard limit, in bytes


def hash_password(plain: str) -> str:
    pw = plain.encode("utf-8")[:_MAX]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:_MAX], hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False
