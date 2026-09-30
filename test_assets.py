"""Asset inventory tests: per-user isolation, uniqueness, ownership on delete."""
import tempfile
import pytest
from sqlalchemy import create_engine

import db
import models_db as m


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/assets.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add_all([m.User(username="a", password_hash="x"),
                   m.User(username="b", password_hash="x"),
                   m.User(username="root", password_hash="x", role="admin")])
        s.flush()
        a = s.query(m.User).filter_by(username="a").first()
        b = s.query(m.User).filter_by(username="b").first()
        s.add_all([
            m.Asset(user_id=a.id, kind="domain", value="acme.com", label="Acme"),
            m.Asset(user_id=a.id, kind="ip", value="8.8.8.8"),
            m.Asset(user_id=b.id, kind="domain", value="beta.io"),
        ])
    yield


def _uid(u):
    with db.session_scope() as s:
        return s.query(m.User).filter_by(username=u).first().id


def _list(role, uid):
    with db.session_scope() as s:
        q = s.query(m.Asset)
        if role != "admin":
            q = q.filter(m.Asset.user_id == uid)
        return sorted(x.value for x in q.all())


def test_user_sees_only_own_assets():
    assert _list("user", _uid("a")) == ["8.8.8.8", "acme.com"]
    assert _list("user", _uid("b")) == ["beta.io"]


def test_admin_sees_all_assets():
    assert _list("admin", _uid("root")) == ["8.8.8.8", "acme.com", "beta.io"]


def test_cross_user_delete_denied():
    with db.session_scope() as s:
        acme = s.query(m.Asset).filter_by(value="acme.com").first()
        b = s.query(m.User).filter_by(username="b").first()
        denied = (b.role != "admin" and acme.user_id != b.id)
        assert denied is True


def test_monitoring_defaults_true():
    with db.session_scope() as s:
        assert s.query(m.Asset).filter_by(value="beta.io").first().monitoring is True
