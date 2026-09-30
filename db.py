"""Database engine and session management.

One switch runs the whole app on SQLite (local dev) or PostgreSQL (production
on the domain): set DATABASE_URL. Nothing else in the codebase changes.

    local  : (unset)  -> sqlite:///./cyberosint.db
    prod   : DATABASE_URL=postgresql+psycopg://user:pass@host:5432/dbname
"""

from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberosint.db")

# SQLite needs this to be usable from FastAPI's threadpool; Postgres does not.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,   # survives dropped Postgres connections in production
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

Base = declarative_base()


def init_db() -> None:
    """Create all tables. Safe to call repeatedly (no-op if they exist)."""
    import models_db  # noqa: F401 — registers models on Base before create_all
    if os.getenv("APP_ENV", "development").lower() == "production":
        raise RuntimeError("Production schema must be managed by migrations; init_db is disabled")
    Base.metadata.create_all(bind=engine)


def check_production_schema() -> None:
    """Read-only readiness check; never creates or alters production schema."""
    import models_db  # noqa: F401
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        inspector = inspect(conn)
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                raise RuntimeError(f"Production schema missing table: {table.name}")
            columns = {column["name"] for column in inspector.get_columns(table.name)}
            missing = set(table.columns.keys()) - columns
            if missing:
                raise RuntimeError(f"Production schema missing columns in {table.name}: {', '.join(sorted(missing))}")


@contextmanager
def session_scope():
    """Transactional scope for scripts/CLI: commit on success, rollback on error."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db():
    """FastAPI dependency: one session per request."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
