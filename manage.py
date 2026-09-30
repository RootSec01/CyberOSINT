"""Admin CLI — the ONLY way user accounts are created (no public signup).

    python manage.py init-db
    python manage.py create-user --username rami --role admin
    python manage.py create-user --username client1
    python manage.py list-users
    python manage.py set-password --username rami
    python manage.py deactivate --username client1
"""

from __future__ import annotations

import argparse
import getpass
import sys

from db import init_db, session_scope
from models_db import User
from security import hash_password


def _prompt_password() -> str:
    p1 = getpass.getpass("password: ")
    p2 = getpass.getpass("confirm : ")
    if p1 != p2:
        print("passwords do not match")
        sys.exit(1)
    if len(p1) < 8:
        print("password must be at least 8 characters")
        sys.exit(1)
    return p1


def cmd_init_db(args) -> None:
    init_db()
    print("database initialized")


def cmd_create_user(args) -> None:
    init_db()
    username = args.username.strip().lower()
    if not username:
        print("username required")
        sys.exit(1)
    password = args.password or _prompt_password()
    with session_scope() as s:
        if s.query(User).filter_by(username=username).first():
            print(f"user '{username}' already exists")
            sys.exit(1)
        s.add(User(username=username,
                   password_hash=hash_password(password),
                   role=args.role))
    print(f"created {args.role} '{username}'")


def cmd_set_password(args) -> None:
    with session_scope() as s:
        user = s.query(User).filter_by(username=args.username.strip().lower()).first()
        if not user:
            print("user not found")
            sys.exit(1)
        user.password_hash = hash_password(args.password or _prompt_password())
    print("password updated")


def cmd_deactivate(args) -> None:
    with session_scope() as s:
        user = s.query(User).filter_by(username=args.username.strip().lower()).first()
        if not user:
            print("user not found")
            sys.exit(1)
        user.is_active = False
    print("user deactivated")


def cmd_list_users(args) -> None:
    init_db()
    with session_scope() as s:
        users = s.query(User).order_by(User.id).all()
        if not users:
            print("(no users yet — create one with create-user)")
            return
        for u in users:
            print(f"{u.id:3d}  {u.username:20s}  {u.role:6s}  active={u.is_active}")


def main() -> None:
    ap = argparse.ArgumentParser(description="CyberOSINT admin CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-db").set_defaults(func=cmd_init_db)

    p = sub.add_parser("create-user")
    p.add_argument("--username", required=True)
    p.add_argument("--password", default=None, help="omit to be prompted securely")
    p.add_argument("--role", choices=["admin", "user"], default="user")
    p.set_defaults(func=cmd_create_user)

    p = sub.add_parser("set-password")
    p.add_argument("--username", required=True)
    p.add_argument("--password", default=None)
    p.set_defaults(func=cmd_set_password)

    p = sub.add_parser("deactivate")
    p.add_argument("--username", required=True)
    p.set_defaults(func=cmd_deactivate)

    sub.add_parser("list-users").set_defaults(func=cmd_list_users)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
