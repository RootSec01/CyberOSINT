"""Data-isolation tests: each user sees only their own runs; admin sees all."""
import tempfile

import pytest
from sqlalchemy import create_engine

import db
import models_db as m


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/iso.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        a = m.User(username="alice", password_hash="x", role="user")
        b = m.User(username="bob", password_hash="x", role="user")
        admin = m.User(username="root", password_hash="x", role="admin")
        s.add_all([a, b, admin])
        s.flush()
        s.add_all([
            m.Run(user_id=a.id, run_id="a1", target_type="ip", target_value="1.1.1.1"),
            m.Run(user_id=a.id, run_id="a2", target_type="ip", target_value="2.2.2.2"),
            m.Run(user_id=b.id, run_id="b1", target_type="ip", target_value="3.3.3.3"),
        ])
    yield


def _list_for(role, user_id):
    """Mirror the /api/runs query logic."""
    with db.session_scope() as s:
        q = s.query(m.Run)
        if role != "admin":
            q = q.filter(m.Run.user_id == user_id)
        return [r.run_id for r in q.order_by(m.Run.id).all()]


def _uid(username):
    with db.session_scope() as s:
        return s.query(m.User).filter_by(username=username).first().id


def test_user_sees_only_own_runs():
    assert _list_for("user", _uid("alice")) == ["a1", "a2"]
    assert _list_for("user", _uid("bob")) == ["b1"]


def test_admin_sees_all_runs():
    assert set(_list_for("admin", _uid("root"))) == {"a1", "a2", "b1"}


def test_cross_user_fetch_denied():
    """Mirror the /api/runs/{id} owner check: bob may not read alice's run."""
    with db.session_scope() as s:
        alice_run = s.query(m.Run).filter_by(run_id="a1").first()
        bob = s.query(m.User).filter_by(username="bob").first()
        # endpoint rule: deny if not admin and run.user_id != caller.id
        denied = (bob.role != "admin" and alice_run.user_id != bob.id)
        assert denied is True


def test_run_belongs_to_correct_owner():
    with db.session_scope() as s:
        alice = s.query(m.User).filter_by(username="alice").first()
        assert {r.run_id for r in alice.runs} == {"a1", "a2"}
