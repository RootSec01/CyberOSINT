"""Authorized MCP lab servers for CyberOSINT — test corpus, CI fixtures, and demo.

Runs a mock MCP server in one of two eras so the negotiation layer can be
proven against BOTH:

  --mode modern   speaks 2026-07-28: implements `server/discover`, REJECTS
                  `initialize` with method-not-found (a strict stateless server).
  --mode legacy   speaks <=2025-11-25: `initialize` -> `initialized` -> tools/list,
                  and REJECTS `server/discover` (so negotiation falls back).

Optional posture knobs for building the validation corpus:
  --auth <token>  require `Authorization: Bearer <token>` (else 401).
  --profile       dangerous (default) | safe.

Binds to 127.0.0.1 only. Declares tools; never executes anything. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MODERN_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"
METHOD_NOT_FOUND = -32601

_TOOLS = {
    "dangerous": [
        {"name": "run_shell_command",
         "description": "Execute an arbitrary shell command on the host",
         "inputSchema": {"type": "object",
                         "properties": {"cmd": {"type": "string"}}}},
        {"name": "execute_sql",
         "description": "Run a raw SQL statement against the production database",
         "inputSchema": {"type": "object",
                         "properties": {"query": {"type": "string"}}}},
        {"name": "read_file",
         "description": "Read any file from the server filesystem",
         "inputSchema": {"type": "object",
                         "properties": {"path": {"type": "string"}}}},
        {"name": "list_projects",
         "description": "List project names (read-only, safe)",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "canary_ping",
         "description": "Return a synthetic marker (read-only canary)",
         "inputSchema": {"type": "object", "properties": {}}},
    ],
    "safe": [
        {"name": "list_projects",
         "description": "List project names (read-only, safe)",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "get_status",
         "description": "Return service health (read-only, safe)",
         "inputSchema": {"type": "object", "properties": {}}},
    ],
}


def _make_handler(mode: str, auth_token: str | None, profile: str):
    tools = _TOOLS[profile]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep test output clean
            pass

        def _send(self, status: int, obj: dict | None, extra_headers=None):
            data = json.dumps(obj).encode() if obj is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if data:
                self.wfile.write(data)

        def _result(self, req_id, result):
            self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": result})

        def _error(self, req_id, code, message):
            self._send(200, {"jsonrpc": "2.0", "id": req_id,
                             "error": {"code": code, "message": message}})

        def do_POST(self):
            if auth_token:
                got = self.headers.get("Authorization", "")
                if got != f"Bearer {auth_token}":
                    self._send(401, {"error": "unauthorized"},
                               {"WWW-Authenticate": 'Bearer realm="mcp"'})
                    return

            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                msg = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._error(None, -32700, "parse error")
                return

            method = msg.get("method")
            req_id = msg.get("id")

            if method == "notifications/initialized":
                self._send(202, None)
                return

            if method == "server/discover":
                if mode == "modern":
                    self._result(req_id, {
                        "protocolVersions": [MODERN_VERSION],
                        "capabilities": {"tools": {}},
                        "_meta": {"io.modelcontextprotocol/serverInfo":
                                  {"name": f"lab-{mode}", "version": "1.0"}},
                    })
                else:
                    self._error(req_id, METHOD_NOT_FOUND,
                                "server/discover not supported")
                return

            if method == "initialize":
                if mode == "legacy":
                    self._result(req_id, {
                        "protocolVersion": LEGACY_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": f"lab-{mode}", "version": "1.0"},
                    })
                else:
                    self._error(req_id, METHOD_NOT_FOUND,
                                "initialize removed in 2026-07-28")
                return

            if method == "tools/list":
                self._result(req_id, {"tools": tools})
                return

            if method == "tools/call":
                name = (msg.get("params") or {}).get("name")
                safe = {"list_projects", "get_status", "canary_ping",
                        "ping", "health"}
                if name in safe:
                    self._result(req_id, {"content": [
                        {"type": "text",
                         "text": f"CANARY-OK:{mode}:{name}"}]})
                else:
                    # dangerous tools are never actually executed in the lab
                    self._error(req_id, -32000,
                                "tool execution disabled in lab (non-canary)")
                return

            self._error(req_id, METHOD_NOT_FOUND, f"unknown method {method}")

    return Handler


def make_server(mode: str, port: int, auth_token: str | None = None,
                profile: str = "dangerous") -> HTTPServer:
    if os.getenv("APP_ENV", "development").lower() == "production":
        raise RuntimeError("lab MCP server is disabled in production")
    handler = _make_handler(mode, auth_token, profile)
    return HTTPServer(("127.0.0.1", port), handler)


def serve(mode: str, port: int, auth_token: str | None = None,
          profile: str = "dangerous"):
    srv = make_server(mode, port, auth_token, profile)
    auth = "bearer" if auth_token else "none"
    print(f"[lab-mcp] mode={mode} profile={profile} auth={auth} "
          f"-> http://127.0.0.1:{port}/mcp")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["modern", "legacy"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--auth", default=None, help="require this bearer token")
    ap.add_argument("--profile", choices=["dangerous", "safe"], default="dangerous")
    args = ap.parse_args()
    serve(args.mode, args.port, args.auth, args.profile)
