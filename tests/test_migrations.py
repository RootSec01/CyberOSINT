"""Reviewed migrations: an existing database gains exposure_states without losing
data, re-running is a no-op, and a conflicting table is refused rather than
guessed at. SQLite always; PostgreSQL too when TEST_POSTGRES_URL is set."""
import os
import tempfile

import pytest
from sqlalchemy import create_engine, inspect, text

from raqeeb import db, migrations
from raqeeb import models as m
from raqeeb.security import hash_password

BACKENDS = ["sqlite"] + (["postgresql"] if os.getenv("TEST_POSTGRES_URL") else [])


@pytest.fixture(params=BACKENDS)
def legacy(request, monkeypatch):
    """A populated database as it looked before exposure_states existed."""
    if request.param == "sqlite":
        eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/legacy.db", future=True)
    else:
        eng = create_engine(os.environ["TEST_POSTGRES_URL"], future=True)
        db.Base.metadata.drop_all(bind=eng)
    db.Base.metadata.create_all(bind=eng)
    with eng.begin() as conn:
        conn.execute(text("DROP TABLE exposure_states"))
        conn.execute(m.User.__table__.insert().values(username="legacy", role="user",
                                                       password_hash=hash_password("password123")))
    monkeypatch.setattr(db, "engine", eng)
    yield eng
    eng.dispose()


def test_pending_lists_the_missing_table_and_readiness_fails(legacy):
    assert migrations.pending(legacy) == ["0001_exposure_states"]
    with pytest.raises(RuntimeError, match="exposure_states"):
        db.check_production_schema()


def test_apply_adds_the_table_keeps_data_and_is_idempotent(legacy):
    assert migrations.apply(legacy) == ["0001_exposure_states"]
    assert migrations.pending(legacy) == []
    assert migrations.apply(legacy) == []
    db.check_production_schema()
    insp = inspect(legacy)
    uniques = {u["name"] for u in insp.get_unique_constraints("exposure_states")}
    assert "uq_exposure_asset_key" in uniques
    with legacy.connect() as conn:
        assert conn.execute(text("SELECT username FROM users")).scalar() == "legacy"


def test_a_conflicting_table_is_refused_not_altered(legacy):
    with legacy.begin() as conn:
        conn.execute(text("CREATE TABLE exposure_states (id INTEGER PRIMARY KEY, note TEXT)"))
    with pytest.raises(RuntimeError, match="differs"):
        migrations.pending(legacy)
    with pytest.raises(RuntimeError, match="differs"):
        migrations.apply(legacy)
    cols = {c["name"] for c in inspect(legacy).get_columns("exposure_states")}
    assert cols == {"id", "note"}


def test_cli_is_a_dry_run_unless_told_to_apply(legacy, capsys):
    assert migrations.main([]) == 0
    assert "pending  0001_exposure_states" in capsys.readouterr().out
    assert migrations.pending(legacy) == ["0001_exposure_states"]
    assert migrations.main(["--apply"]) == 0
    out = capsys.readouterr().out
    assert "applied  0001_exposure_states" in out and "Readiness check passed" in out
    assert migrations.main([]) == 0
    assert "up to date" in capsys.readouterr().out
