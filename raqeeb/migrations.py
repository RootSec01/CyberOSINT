"""Reviewed schema migrations for databases that already hold data.

``init_db()`` creates every table on a fresh development database and is
disabled in production; ``prepare_production_schema`` initialises only an empty
schema and refuses an existing one. A database created before a table was
added therefore needs an explicit, reviewed step. Each migration here:

* adds exactly what it names and nothing else;
* is idempotent: running it again on a migrated database changes nothing;
* refuses to proceed when it finds a table of the same name whose columns do
  not match, instead of guessing;
* works on SQLite and PostgreSQL through SQLAlchemy, in one transaction.

Usage (dry run by default, prints what would happen)::

    python -m raqeeb.migrations            # list pending migrations
    python -m raqeeb.migrations --apply    # apply them, then run the readiness check

The project has no Alembic dependency; if it adopts one, these functions map
one-to-one onto revisions.
"""
from __future__ import annotations

import argparse
from typing import Callable, List, Tuple

from sqlalchemy import inspect
from sqlalchemy.engine import Connection, Engine


def _table_matches(conn: Connection, name: str) -> bool:
    from raqeeb.db import Base
    expected = set(Base.metadata.tables[name].columns.keys())
    found = {column["name"] for column in inspect(conn).get_columns(name)}
    if found != expected:
        missing, extra = sorted(expected - found), sorted(found - expected)
        raise RuntimeError(f"table {name} exists but differs (missing: {missing or '-'}, "
                           f"unexpected: {extra or '-'}); review it by hand")
    return True


def _needs_exposure_states(conn: Connection) -> bool:
    if inspect(conn).has_table("exposure_states"):
        _table_matches(conn, "exposure_states")
        return False
    return True


def _create_exposure_states(conn: Connection) -> None:
    from raqeeb import models  # noqa: F401  registers the table on Base
    from raqeeb.db import Base
    # Creates the table with its indexes and the (asset_id, key) unique constraint.
    Base.metadata.tables["exposure_states"].create(bind=conn)


#: (id, description, is it needed?, apply)
MIGRATIONS: List[Tuple[str, str, Callable[[Connection], bool], Callable[[Connection], None]]] = [
    ("0001_exposure_states", "add the exposure_states table (exposure lifecycle)",
     _needs_exposure_states, _create_exposure_states),
]


def pending(engine: Engine) -> List[str]:
    """Ids of migrations this database still needs. Read-only."""
    from raqeeb import models  # noqa: F401
    with engine.connect() as conn:
        return [mid for mid, _desc, needed, _apply in MIGRATIONS if needed(conn)]


def apply(engine: Engine) -> List[str]:
    """Apply every pending migration in one transaction; returns the ids applied."""
    from raqeeb import models  # noqa: F401
    done: List[str] = []
    with engine.begin() as conn:
        for mid, _desc, needed, run in MIGRATIONS:
            if needed(conn):
                run(conn)
                done.append(mid)
    return done


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="apply pending migrations (default: dry run)")
    args = parser.parse_args(argv)

    from raqeeb.db import check_production_schema, engine
    todo = pending(engine)
    descriptions = {mid: desc for mid, desc, _n, _a in MIGRATIONS}
    if not todo:
        print("Schema is up to date; nothing to apply.")
        return 0
    for mid in todo:
        print(f"pending  {mid}  {descriptions[mid]}")
    if not args.apply:
        print("Dry run. Re-run with --apply to apply.")
        return 0
    for mid in apply(engine):
        print(f"applied  {mid}")
    check_production_schema()
    print("Readiness check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
