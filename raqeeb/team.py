"""Who works together, and what each role may do."""
from __future__ import annotations

import re
from typing import Optional

from sqlalchemy.orm import Session

from raqeeb.models import Asset, Member, User
from raqeeb.security import hash_password

OWNER, ADMIN, ANALYST, VIEWER = "owner", "admin", "analyst", "viewer"
ASSIGNABLE = (ADMIN, ANALYST, VIEWER)

READ, WORK, MANAGE = "read", "work", "manage"
ALLOWED = {OWNER: (READ, WORK, MANAGE), ADMIN: (READ, WORK, MANAGE), ANALYST: (READ, WORK), VIEWER: (READ,)}
DOES = {WORK: "add servers, run scans or change findings and cases", MANAGE: "manage members or rules"}

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
SHORTEST_PASSWORD = 8


class Refused(ValueError):
    """A member change that the team's rules do not allow."""


def membership(db: Session, user: User) -> Optional[Member]:
    return db.query(Member).filter(Member.user_id == user.id).first()


def team_of(db: Session, user: User) -> int:
    """A team is named by its owner's user id. Someone nobody added is a team of one."""
    row = membership(db, user)
    return row.team_id if row else user.id


def role_of(db: Session, user: User) -> str:
    row = membership(db, user)
    return row.role if row else OWNER


def allows(db: Session, user: User, action: str) -> bool:
    return user.role == "admin" or action in ALLOWED[role_of(db, user)]


def people(db: Session, user: User) -> list[int]:
    """User ids whose servers this user works on: the whole team."""
    team = team_of(db, user)
    ids = {team} | {row.user_id for row in db.query(Member.user_id).filter(Member.team_id == team)}
    return sorted(ids)


def sees(db: Session, user: User, asset: Optional[Asset]) -> bool:
    return bool(asset) and (user.role == "admin" or asset.user_id in people(db, user))


def name_of(db: Session, user: Optional[User]) -> Optional[str]:
    if user is None:
        return None
    row = membership(db, user)
    return (row.display_name if row and row.display_name else None) or user.username


def _profile(db: Session, user: User) -> Member:
    row = membership(db, user)
    if row is None:
        row = Member(user_id=user.id, team_id=user.id, role=OWNER, created_by=user.username)
        db.add(row)
        db.flush()
    return row


def _checked_email(email: str) -> Optional[str]:
    email = email.strip()
    if email and not EMAIL.match(email):
        raise Refused("that is not an email address")
    return email or None


def update_profile(db: Session, user: User, *, display_name: str, email: str, title: str) -> Member:
    row = _profile(db, user)
    row.display_name = display_name.strip()[:120] or None
    row.email = _checked_email(email)
    row.title = title.strip()[:120] or None
    db.commit()
    return row


def add(db: Session, by: User, *, username: str, password: str, role: str,
        display_name: str = "", email: str = "") -> Member:
    username, role = username.strip().lower(), role.strip().lower()
    if not USERNAME.match(username):
        raise Refused("username needs 2 to 63 characters: letters, digits, dot, dash or underscore")
    if role not in ASSIGNABLE:
        raise Refused(f"role must be one of: {', '.join(ASSIGNABLE)}")
    if len(password) < SHORTEST_PASSWORD:
        raise Refused(f"the first password needs at least {SHORTEST_PASSWORD} characters")
    if role == ADMIN and role_of(db, by) != OWNER and by.role != "admin":
        raise Refused("only the owner can add an admin")
    if db.query(User).filter(User.username == username).first():
        raise Refused("that username is taken")
    _profile(db, by)
    account = User(username=username, password_hash=hash_password(password), role="user")
    db.add(account)
    db.flush()
    row = Member(user_id=account.id, team_id=team_of(db, by), role=role, created_by=by.username,
                 display_name=display_name.strip()[:120] or None, email=_checked_email(email))
    db.add(row)
    db.commit()
    return row


def _member_in_team(db: Session, by: User, user_id: int) -> Member:
    team = team_of(db, by)
    if user_id == team:
        raise Refused("the owner's role cannot be changed or removed")
    row = db.query(Member).filter(Member.user_id == user_id, Member.team_id == team).first()
    if row is None:
        raise LookupError("member not found")
    if row.role == ADMIN and role_of(db, by) != OWNER and by.role != "admin":
        raise Refused("only the owner can change or remove an admin")
    return row


def change_role(db: Session, by: User, user_id: int, role: str) -> Member:
    role = role.strip().lower()
    if role not in ASSIGNABLE:
        raise Refused(f"role must be one of: {', '.join(ASSIGNABLE)}")
    row = _member_in_team(db, by, user_id)
    if role == ADMIN and role_of(db, by) != OWNER and by.role != "admin":
        raise Refused("only the owner can make someone an admin")
    row.role = role
    db.commit()
    return row


def remove(db: Session, by: User, user_id: int) -> Member:
    """The account is switched off, never deleted: its name stays on what it did."""
    row = _member_in_team(db, by, user_id)
    account = db.query(User).filter(User.id == user_id).first()
    account.is_active = False
    for asset in db.query(Asset).filter(Asset.user_id == user_id):
        asset.user_id = row.team_id
    row.removed = True
    db.commit()
    return row


def roster(db: Session, user: User) -> list[dict]:
    team = team_of(db, user)
    owner = db.query(User).filter(User.id == team).first()
    listed = [member_dict(db, owner, db.query(Member).filter(Member.user_id == team).first())] if owner else []
    rows = db.query(Member, User).join(User, User.id == Member.user_id).filter(
        Member.team_id == team, Member.user_id != team).order_by(Member.id)
    return listed + [member_dict(db, account, row) for row, account in rows]


def member_dict(db: Session, account: User, row: Optional[Member]) -> dict:
    return {"id": account.id, "username": account.username,
            "display_name": (row.display_name if row else None) or account.username,
            "email": row.email if row else None, "title": row.title if row else None,
            "role": row.role if row else OWNER, "active": bool(account.is_active),
            "added_by": row.created_by if row else None}


def can_own_cases(db: Session, by: User, account: Optional[User]) -> bool:
    if account is None or not account.is_active or account.id not in people(db, by):
        return False
    return role_of(db, account) != VIEWER


def team_of_asset(db: Session, asset: Asset) -> int:
    row = db.query(Member.team_id).filter(Member.user_id == asset.user_id).first()
    return row[0] if row else asset.user_id
