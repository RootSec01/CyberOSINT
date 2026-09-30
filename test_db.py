"""Tests for the DB layer, models, hashing, and user creation (isolated SQLite)."""
import tempfile

import pytest
from sqlalchemy import create_engine

import db
import models_db as m
from security import hash_password, verify_password


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/test_db.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    yield


def test_password_hash_roundtrip():
    h = hash_password("s3cret-password")
    assert h != "s3cret-password"
    assert verify_password("s3cret-password", h) is True
    assert verify_password("wrong", h) is False


def test_create_and_query_user():
    with db.session_scope() as s:
        s.add(m.User(username="rami", password_hash=hash_password("pw12345678"),
                     role="admin"))
    with db.session_scope() as s:
        u = s.query(m.User).filter_by(username="rami").first()
        assert u is not None and u.role == "admin" and u.is_active is True


def test_username_is_unique():
    import sqlalchemy.exc
    with db.session_scope() as s:
        s.add(m.User(username="dup", password_hash="x"))
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        with db.session_scope() as s:
            s.add(m.User(username="dup", password_hash="y"))


def test_run_is_scoped_to_user():
    with db.session_scope() as s:
        u = m.User(username="client1", password_hash="x")
        s.add(u)
        s.flush()
        s.add(m.Run(user_id=u.id, run_id="20260101T000000Z", target_type="ip",
                    target_value="8.8.8.8", risk_level="High"))
    with db.session_scope() as s:
        u = s.query(m.User).filter_by(username="client1").first()
        assert len(u.runs) == 1 and u.runs[0].target_value == "8.8.8.8"
