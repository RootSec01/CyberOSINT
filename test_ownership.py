"""Target ownership proof tests — token derivation, DNS TXT verification (with
an injected resolver, no real DNS), the endpoints, and the active-scan gate."""
import datetime
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

import db
import models_db as m
import ownership
from security import hash_password


def test_token_is_deterministic_and_scoped():
    t1 = ownership.expected_token(1, "example.com", secret="s")
    t2 = ownership.expected_token(1, "example.com", secret="s")
    assert t1 == t2 and len(t1) == 32
    assert ownership.expected_token(2, "example.com", secret="s") != t1   # per-user
    assert ownership.expected_token(1, "other.com", secret="s") != t1     # per-domain


def test_txt_record_format():
    rec = ownership.txt_record(1, "example.com")
    assert rec.startswith("cyberosint-verify=")


def test_verify_domain_found_and_not_found():
    want = ownership.txt_record(5, "acme.io")
    ok = ownership.verify_domain(5, "acme.io", resolver=lambda d: [want, "other=1"])
    assert ok["verified"] is True
    bad = ownership.verify_domain(5, "acme.io", resolver=lambda d: ["nope=1"])
    assert bad["verified"] is False


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/ownership.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="owen", password_hash=hash_password("password123")))
    yield


def _login():
    import main
    c = TestClient(main.app)
    tok = c.post("/api/login",
                 data={"username": "owen", "password": "password123"}).json()["token"]
    return c, {"Authorization": f"Bearer {tok}"}


def test_ownership_status_returns_required_record():
    c, H = _login()
    r = c.get("/api/ownership/example.com", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["required_record"].startswith("cyberosint-verify=")
    assert body["verified"] is False


def test_ownership_verify_records_proof(monkeypatch):
    import main
    monkeypatch.setattr(main.ownership, "verify_domain",
                        lambda uid, dom, resolver=None: {
                            "domain": dom, "verified": True,
                            "expected_record": "cyberosint-verify=x", "records_seen": 1})
    c, H = _login()
    r = c.post("/api/ownership/example.com/verify", headers=H)
    assert r.status_code == 200 and r.json()["verified"] is True
    # persisted + audited
    with db.session_scope() as s:
        row = s.query(m.OwnershipProof).filter_by(domain="example.com").first()
        assert row and row.verified is True
        audit = s.query(m.AuditEntry).filter_by(action="ownership_verify").first()
        assert audit is not None


def test_active_scan_gate_blocks_unverified_domain():
    import main
    saved = main._REQUIRE_OWNERSHIP
    main._REQUIRE_OWNERSHIP = True
    try:
        with db.session_scope() as s:
            user = s.query(m.User).filter_by(username="owen").first()
            # a domain with no verified proof -> active checks not allowed
            assert main._domain_ownership_ok(s, user, "domain", "unproven.com") is False
            # non-domain targets are not gated by ownership
            assert main._domain_ownership_ok(s, user, "ip", "1.2.3.4") is True
            # after a verified proof exists -> allowed
            s.add(m.OwnershipProof(user_id=user.id, domain="proven.com",
                                   token="t", verified=True,
                                   verified_at=datetime.datetime.now(datetime.timezone.utc)))
            s.flush()
            assert main._domain_ownership_ok(s, user, "domain", "proven.com") is True
    finally:
        main._REQUIRE_OWNERSHIP = saved
