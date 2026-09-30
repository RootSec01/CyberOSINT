"""End-to-end login/session tests: password -> JWT -> protected access + roles."""
import os
import tempfile

os.environ["JWT_SECRET"] = "test-secret"

import pytest
from sqlalchemy import create_engine
from fastapi import Depends, FastAPI, Form, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import db
import models_db as m
from security import hash_password
import auth_session as a


@pytest.fixture(scope="module", autouse=True)
def _bind_db():
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/auth.db",
                        connect_args={"check_same_thread": False}, future=True)
    db.engine = eng
    db.SessionLocal.configure(bind=eng)
    db.init_db()
    with db.session_scope() as s:
        s.add(m.User(username="rami", password_hash=hash_password("adminpass1"),
                     role="admin"))
        s.add(m.User(username="client1", password_hash=hash_password("clientpass1"),
                     role="user"))
    yield


app = FastAPI()


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...),
          d: Session = Depends(db.get_db)):
    user = a.authenticate(d, username, password)
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"token": a.create_access_token(user), "role": user.role}


@app.get("/me")
def me(user=Depends(a.get_current_user)):
    return {"username": user.username, "role": user.role}


@app.post("/admin-only")
def admin_only(user=Depends(a.require_admin_user)):
    return {"ok": True}


client = TestClient(app, raise_server_exceptions=False)


def _login(username, password):
    return client.post("/login", data={"username": username, "password": password})


def test_login_wrong_password_401():
    assert _login("rami", "nope").status_code == 401


def test_login_ok_returns_token():
    r = _login("rami", "adminpass1")
    assert r.status_code == 200 and r.json()["token"]


def test_protected_requires_token():
    assert client.get("/me").status_code == 401


def test_protected_with_token_ok():
    tok = _login("rami", "adminpass1").json()["token"]
    r = client.get("/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json()["username"] == "rami"


def test_admin_route_allows_admin():
    tok = _login("rami", "adminpass1").json()["token"]
    assert client.post("/admin-only",
                       headers={"Authorization": f"Bearer {tok}"}).status_code == 200


def test_admin_route_blocks_normal_user():
    tok = _login("client1", "clientpass1").json()["token"]
    assert client.post("/admin-only",
                       headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_tampered_token_rejected():
    assert client.get("/me",
                      headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401
