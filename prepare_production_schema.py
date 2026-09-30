"""One-time explicit initialization of a brand-new, empty PostgreSQL schema.

Run only as an administrator after setting the complete production environment.
Existing/partial schemas must be migrated separately; this script refuses them.
"""
from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()
from deployment_config import load_deployment

config = load_deployment()
if not config.production:
    raise RuntimeError("APP_ENV=production is required")

from sqlalchemy import inspect  # noqa: E402
from db import Base, engine, check_production_schema  # noqa: E402
import models_db  # noqa: F401,E402

with engine.begin() as connection:
    existing = set(inspect(connection).get_table_names())
    expected = set(Base.metadata.tables)
    if existing & expected:
        raise RuntimeError("Existing application tables found; use a reviewed migration instead")
    Base.metadata.create_all(bind=connection)

check_production_schema()
print("New production schema initialized and checked")
