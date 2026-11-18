"""Admin CLI — the ONLY way user accounts are created (no public signup).

    python -m raqeeb.manage init-db
    python -m raqeeb.manage create-user --username rami --role admin
    python -m raqeeb.manage create-user --username client1
    python -m raqeeb.manage list-users
    python -m raqeeb.manage set-password --username rami
    python -m raqeeb.manage deactivate --username client1
    python -m raqeeb.manage add-registry --owner rami --count 25 --every 360
    python -m raqeeb.manage remove-registry --owner rami
"""

from __future__ import annotations

import argparse
import getpass
import sys

from dotenv import load_dotenv
from sqlalchemy.engine import make_url

load_dotenv()

from raqeeb.db import DATABASE_URL, check_production_schema, init_db, session_scope  # noqa: E402
from raqeeb.deployment_config import load_deployment  # noqa: E402
from raqeeb.models import User  # noqa: E402
from raqeeb.security import hash_password  # noqa: E402


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


def _ready() -> None:
    if load_deployment().production:
        check_production_schema()
    else:
        init_db()


def cmd_init_db(args) -> None:
    _ready()
    print("database initialized")


def cmd_create_user(args) -> None:
    _ready()
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


def cmd_verify_audit(args) -> None:
    from raqeeb import seals
    with session_scope() as db:
        result = seals.check(db)
    if result["intact"]:
        print(f"audit chain intact: {result['sealed']} sealed entries, {result['unsealed']} written before sealing")
        return
    print(f"audit chain BROKEN at entry {result['broken_at']}: {result['reason']}")
    sys.exit(1)


TUNNELS = (".lhr.life", ".ngrok.io", ".ngrok-free.app", ".ngrok.app", ".trycloudflare.com", ".loca.lt",
           ".serveo.net", ".localhost.run", ".pinggy.link", ".devtunnels.ms")


def _ranked(endpoints, seed: str) -> list:
    """A seeded order with one endpoint per host, skipping short-lived tunnels to someone's own machine."""
    import hashlib
    unique = {e.url: e for e in endpoints if not e.host.endswith(TUNNELS)}
    order = sorted(unique.values(), key=lambda e: hashlib.sha256(f"{seed}:{e.url}".encode()).hexdigest())
    chosen, hosts = [], set()
    for endpoint in order:
        if endpoint.host not in hosts:
            hosts.add(endpoint.host)
            chosen.append(endpoint)
    return chosen


def _drop_asset(s, asset) -> None:
    from raqeeb import cases, listings, monitoring, register
    from raqeeb.models import Alert
    cases.forget_asset(s, asset.id)
    register.forget_asset(s, asset.id)
    listings.forget(s, asset.id)
    monitoring.forget(s, asset.id)
    s.query(Alert).filter(Alert.asset_id == asset.id).delete(synchronize_session=False)
    s.delete(asset)


def _owner(s, name: str) -> User:
    owner = s.query(User).filter_by(username=name.strip().lower()).first()
    if not owner:
        print(f"no user named {name}")
        sys.exit(1)
    return owner


def cmd_add_registry(args) -> None:
    """Monitor a seeded sample of open endpoints from the official MCP registry, one per host."""
    _ready()
    from observatory import registry
    from raqeeb import listings, monitoring, seals
    from raqeeb.models import Asset

    with session_scope() as s:
        owned = {a.value for a in s.query(Asset).filter_by(user_id=_owner(s, args.owner).id)}
    print("reading the official MCP registry ...", flush=True)
    candidates = [endpoint for entry in registry.iter_entries(listings.fetcher())
                  for endpoint in registry.open_endpoints(entry)]
    added = 0
    for endpoint in _ranked(candidates, args.seed):
        if added == args.count:
            break
        if endpoint.url in owned or not listings.public_address(endpoint.host):
            continue
        with session_scope() as s:
            owner = _owner(s, args.owner)
            asset = Asset(user_id=owner.id, kind="mcp", value=endpoint.url,
                          label=endpoint.server.split("/")[-1][:120] or endpoint.host)
            s.add(asset)
            s.flush()
            listings.record(s, asset, {"server": endpoint.server, "version": endpoint.version, "url": endpoint.url})
            monitoring.set_every(s, asset, owner, args.every)
            seals.record(s, action="registry_server_added", operator=owner.username, decision="listed",
                         detail=f"asset={asset.id};server={endpoint.server};version={endpoint.version}")
        added += 1
        print(f"  {endpoint.server}  {endpoint.url}")
    print(f"added {added} registry servers, read every {args.every} minutes; the scheduler reads them next")


def cmd_remove_registry(args) -> None:
    """Stop monitoring every server the owner added from the registry, with its scans and findings."""
    _ready()
    from raqeeb import seals
    from raqeeb.models import Asset, Listing

    with session_scope() as s:
        owner = _owner(s, args.owner)
        listed = (s.query(Asset).join(Listing, Listing.asset_id == Asset.id)
                  .filter(Asset.user_id == owner.id).all())
        for asset in listed:
            seals.record(s, action="registry_server_removed", operator=owner.username, decision="removed",
                         detail=f"asset={asset.id};endpoint={asset.value}")
            _drop_asset(s, asset)
        print(f"removed {len(listed)} registry servers")


def cmd_list_users(args) -> None:
    _ready()
    with session_scope() as s:
        users = s.query(User).order_by(User.id).all()
        print(f"database: {make_url(DATABASE_URL).render_as_string(hide_password=True)}")
        if not users:
            print("(no users yet — create one with create-user)")
            return
        for u in users:
            print(f"{u.id:3d}  {u.username:20s}  {u.role:6s}  active={u.is_active}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Raqeeb admin CLI")
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

    p = sub.add_parser("add-registry", help="monitor open endpoints listed in the official MCP registry")
    p.add_argument("--owner", required=True)
    p.add_argument("--count", type=int, default=25)
    p.add_argument("--every", type=int, default=360, choices=(60, 360, 1440), help="minutes between reads")
    p.add_argument("--seed", default="raqeeb-monitor")
    p.set_defaults(func=cmd_add_registry)

    p = sub.add_parser("remove-registry", help="stop monitoring every server added from the registry")
    p.add_argument("--owner", required=True)
    p.set_defaults(func=cmd_remove_registry)

    sub.add_parser("list-users").set_defaults(func=cmd_list_users)
    sub.add_parser("verify-audit").set_defaults(func=cmd_verify_audit)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
