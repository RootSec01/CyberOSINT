import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from lab import server as lab_server
from observatory import probe as probing
from observatory import report
from observatory.__main__ import main, take_snapshot
from observatory.probe import probe
from observatory.registry import (OFFICIAL, Endpoint, build_sample, draw_sample,
                                  endpoint_id, open_endpoints)
from observatory.store import Archive, manifest_digest


def entry(name, url, *, latest=True, status="active", kind="streamable-http", **remote):
    return {"server": {"name": name, "version": "1.0.0",
                       "remotes": [{"type": kind, "url": url, **remote}]},
            "_meta": {OFFICIAL: {"status": status, "isLatest": latest}}}


def endpoint(url):
    return Endpoint(endpoint_id(url), url, "test/server", "1.0.0")


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def lab():
    servers = []

    def start(mode, **options):
        server = lab_server.make_server(mode, 0, **options)
        servers.append(server)
        return serve(server) + "/mcp"

    yield start
    for server in servers:
        server.shutdown()


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


def test_only_current_credential_free_https_remotes_are_eligible():
    assert [e.url for e in open_endpoints(entry("a/b", "https://mcp.example.com/mcp"))] == [
        "https://mcp.example.com/mcp"]
    rejected = [
        entry("old", "https://mcp.example.com/mcp", latest=False),
        entry("gone", "https://mcp.example.com/mcp", status="deleted"),
        entry("sse", "https://mcp.example.com/sse", kind="sse"),
        entry("plain", "http://mcp.example.com/mcp"),
        entry("template", "https://{tenant}.example.com/mcp"),
        entry("keyed", "https://mcp.example.com/mcp",
              headers=[{"name": "Authorization", "isRequired": True}]),
        entry("literal", "https://10.0.0.8/mcp"),
        entry("internal", "https://build.internal/mcp"),
        entry("userinfo", "https://user:pw@mcp.example.com/mcp"),
    ]
    assert all(open_endpoints(item) == [] for item in rejected)


def test_sample_is_reproducible_and_takes_one_endpoint_per_host():
    pool = [endpoint(f"https://host{i % 40}.example.com/mcp/{i}") for i in range(200)]
    first = draw_sample(pool, 25)
    assert first == draw_sample(list(reversed(pool)), 25)
    assert len({e.host for e in first}) == len(first) == 25
    assert draw_sample(pool, 25, seed="another study") != first


def test_build_sample_follows_cursors_and_reports_registry_totals():
    pages = {None: {"servers": [entry("a/one", "https://one.example.com/mcp"),
                                entry("a/old", "https://old.example.com/mcp", latest=False)],
                    "metadata": {"nextCursor": "c1"}},
             "c1": {"servers": [entry("a/two", "https://two.example.com/mcp")], "metadata": {}}}
    sample = build_sample(lambda params: pages[params.get("cursor")], size=10)
    assert (sample["records_read"], sample["current_servers"], sample["open_endpoints"]) == (3, 2, 2)
    assert [e["server"] for e in sample["endpoints"]] == ["a/one", "a/two"]


@pytest.mark.parametrize("mode, handshake", [("legacy", "initialize"), ("modern", "server/discover")])
def test_probe_lists_tools_in_both_protocol_eras(lab, mode, handshake):
    seen = probe(endpoint(lab(mode, profile="safe")), allow_private=True)
    assert (seen.outcome, seen.handshake, seen.tool_count) == ("ok", handshake, 2)
    assert {tool["name"] for tool in seen.tools} == {"list_projects", "get_status"}


def test_probe_stops_at_an_authentication_challenge(lab):
    seen = probe(endpoint(lab("legacy", auth_token="secret")), allow_private=True)
    assert (seen.outcome, seen.http_status, seen.tools) == ("auth_required", 401, None)


def test_probe_keeps_the_session_pages_through_tools_and_closes_it(stateful):
    seen = probe(endpoint(stateful + "/moved"), allow_private=True)
    assert seen.outcome == "ok"
    assert [tool["name"] for tool in seen.tools] == ["alpha", "beta", "gamma"]
    assert (seen.server_name, seen.server_version, seen.protocol_version) == (
        "stateful", "3.1.4", "2025-06-18")
    assert StatefulServer.deleted == ["session-1"]


def test_probe_refuses_private_addresses_and_reports_dead_hosts(monkeypatch):
    assert probe(endpoint("https://localhost/mcp")).outcome == "refused"
    monkeypatch.setattr(probing, "resolves_publicly", lambda host: None)
    assert probe(endpoint("https://gone.example.com/mcp")).detail == "dns"


def test_probe_gives_up_on_oversized_answers(stateful, monkeypatch):
    monkeypatch.setattr(probing, "MAX_BODY_BYTES", 64)
    seen = probe(endpoint(stateful + "/mcp"), allow_private=True)
    assert seen.outcome == "not_mcp" and seen.tools is None


def test_probe_reports_a_plain_web_server_as_not_mcp():
    class Plain(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), Plain)
    try:
        seen = probe(endpoint(serve(server) + "/mcp"), allow_private=True)
    finally:
        server.shutdown()
    assert seen.outcome == "not_mcp" and "HTTP 404" in seen.detail


def test_manifest_digest_ignores_tool_and_key_order():
    one = [{"name": "a", "description": "x", "inputSchema": {"type": "object", "properties": {}}},
           {"name": "b", "description": "y"}]
    two = [{"description": "y", "name": "b"},
           {"inputSchema": {"properties": {}, "type": "object"}, "description": "x", "name": "a"}]
    assert manifest_digest(one) == manifest_digest(two)
    two[0]["description"] = "y​"
    assert manifest_digest(one) != manifest_digest(two)


def test_snapshots_share_unchanged_manifests_and_surface_redeployments(lab, tmp_path, capsys):
    archive = Archive(tmp_path)
    safe = lab("legacy", profile="safe")
    target = [endpoint(safe)]

    first = take_snapshot(archive, target, "test", allow_private=True)
    first["started_at"] = "2026-11-13T00:00:00Z"
    archive.save_run(first)
    again = take_snapshot(archive, target, "test", allow_private=True)
    again["started_at"] = "2026-11-14T00:00:00Z"
    archive.save_run(again)
    assert report.manifest_changes(archive, first, again) == []
    assert len(list((tmp_path / "manifests").rglob("*.json"))) == 1

    exposed = lab_server.make_server("legacy", 0, profile="dangerous")
    try:
        redeployed = [Endpoint(target[0].id, serve(exposed) + "/mcp", "test/server", "1.0.0")]
        third = take_snapshot(archive, redeployed, "test", allow_private=True)
    finally:
        exposed.shutdown()
    third["started_at"] = "2026-11-15T00:00:00Z"
    archive.save_run(third)

    (change,) = report.manifest_changes(archive, again, third)
    assert change.added == ["canary_ping", "execute_sql", "read_file", "run_shell_command"]
    assert change.removed == ["get_status"] and change.redefined == []
    assert main(["--data", str(tmp_path), "status"]) == 0
    assert "1 of 1 comparable endpoints changed" in capsys.readouterr().out
