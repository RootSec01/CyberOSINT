import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


class StatefulServer(BaseHTTPRequestHandler):
    """Session-bound, paginated, answers tools/list as an event stream."""
    pages = {None: (["alpha", "beta"], "p2"), "p2": (["gamma"], None)}
    deleted = []

    def log_message(self, *args):
        pass

    def _send(self, status, payload=None, headers=()):
        body = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        self.deleted.append(self.headers.get("Mcp-Session-Id"))
        self._send(200)

    def do_POST(self):
        if self.path == "/moved":
            return self._send(308, headers=[("Location", "/mcp")])
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = request["method"]
        if method == "initialize":
            return self._send(200, {"jsonrpc": "2.0", "id": request["id"], "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "stateful", "version": "3.1.4"}}},
                headers=[("Mcp-Session-Id", "session-1"), ("Content-Type", "application/json")])
        if self.headers.get("Mcp-Session-Id") != "session-1":
            return self._send(400, {"jsonrpc": "2.0", "error": {"code": -32000}})
        if method == "notifications/initialized":
            return self._send(202)
        names, cursor = self.pages[request.get("params", {}).get("cursor")]
        result = {"tools": [{"name": n, "description": n.upper(), "inputSchema": {}} for n in names]}
        if cursor:
            result["nextCursor"] = cursor
        event = (b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
                 b"data: " + json.dumps({"jsonrpc": "2.0", "id": request["id"],
                                         "result": result}).encode() + b"\n\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(event)))
        self.end_headers()
        self.wfile.write(event)


@pytest.fixture
def stateful():
    StatefulServer.deleted = []
    server = HTTPServer(("127.0.0.1", 0), StatefulServer)
    yield serve(server)
    server.shutdown()


@pytest.fixture
def console():
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from raqeeb import db
    from raqeeb import models as m
    from raqeeb.security import hash_password
    engine = create_engine(f"sqlite:///{tempfile.mkdtemp()}/cases.db",
                           connect_args={"check_same_thread": False}, future=True)
    db.engine = engine
    db.SessionLocal.configure(bind=engine)
    db.init_db()
    with db.session_scope() as session:
        session.add_all([m.User(username=name, password_hash=hash_password("password123"))
                         for name in ("rami", "outsider")])
    from raqeeb import main
    return TestClient(main.app)
