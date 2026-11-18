"""Explicit creation of the PostgreSQL schema.

Run only as an administrator after setting the complete production environment.
After an upgrade that adds tables, run it with --new-tables: missing tables are created and
existing ones are never altered (the schema check still refuses missing columns).
"""
from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()
from raqeeb.deployment_config import load_deployment

config = load_deployment()
if not config.production:
    raise RuntimeError("APP_ENV=production is required")

from sqlalchemy import inspect  # noqa: E402
from raqeeb.db import Base, engine, check_production_schema  # noqa: E402
from raqeeb import models

import sys  # noqa: E402

adding = "--new-tables" in sys.argv[1:]
with engine.begin() as connection:
    existing = set(inspect(connection).get_table_names())
    expected = set(Base.metadata.tables)
    if existing & expected and not adding:
        raise RuntimeError("Existing application tables found; run with --new-tables after an upgrade")
    missing = [Base.metadata.tables[name] for name in sorted(expected - existing)]
    Base.metadata.create_all(bind=connection, tables=missing)

check_production_schema()
print(f"Production schema checked; created {len(missing)} table(s)")
