from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlsplit

import requests

from . import USER_AGENT
from .registry import Endpoint

LEGACY_PROTOCOL = "2025-11-25"
STATELESS_PROTOCOL = "2026-07-28"
CLIENT = {"name": "raqeeb-observatory", "version": "0.1"}

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_TOOL_PAGES = 5
MAX_REDIRECTS = 2
CONNECT_TIMEOUT = 6
READ_TIMEOUT = 12


@dataclass
class Observation:
    id: str
    url: str
    outcome: str
    detail: str = ""
    http_status: Optional[int] = None
    handshake: Optional[str] = None
    protocol_version: Optional[str] = None
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    tool_count: Optional[int] = None
    truncated: bool = False
    manifest: Optional[str] = None
    elapsed_ms: int = 0
    tools: Optional[list] = field(default=None, repr=False)

    def as_record(self) -> dict:
        record = asdict(self)
        del record["tools"]
        return record


@dataclass
class Reply:
    status: Optional[int] = None
    message: Optional[dict] = None
    failure: str = ""
    session_id: Optional[str] = None
    challenged: bool = False

    @property
    def result(self) -> Optional[dict]:
        result = (self.message or {}).get("result")
        return result if isinstance(result, dict) else None

    def describe(self) -> str:
        if self.failure:
            return self.failure
        error = (self.message or {}).get("error")
        if isinstance(error, dict):
            return f"jsonrpc {error.get('code')}"
        return f"HTTP {self.status}"


class OutOfTime(Exception):
    pass


def resolves_publicly(host: str) -> Optional[bool]:
    """None when the name does not resolve; False when any address is not globally routable."""
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    return all(ipaddress.ip_address(answer[4][0]).is_global for answer in answers)


def _failure_name(error: requests.RequestException) -> str:
    if isinstance(error, requests.exceptions.SSLError):
        return "tls"
    if isinstance(error, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(error, requests.exceptions.ConnectionError):
        return "connect"
    return type(error).__name__


class Conversation:
    def __init__(self, http: requests.Session, url: str, deadline: float, allow_private: bool):
        self.http = http
        self.url = url
        self.deadline = deadline
        self.allow_private = allow_private
        self.headers: dict[str, str] = {}
        self._next_id = 0

    def call(self, method: str, params: Optional[dict] = None, *, notify: bool = False) -> Reply:
        body: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            self._next_id += 1
            body["id"] = self._next_id
        try:
            return self._post(body, expect_id=None if notify else body["id"])
        except OutOfTime:
            return Reply(failure="timeout")
        except requests.RequestException as error:
            return Reply(failure=_failure_name(error))

    def end_session(self) -> None:
        if "Mcp-Session-Id" not in self.headers or time.monotonic() > self.deadline:
            return
        try:
            self.http.delete(self.url, headers=self.headers, timeout=(CONNECT_TIMEOUT, 5),
                             allow_redirects=False).close()
        except requests.RequestException:
            pass

    def _post(self, body: dict, expect_id: Optional[int]) -> Reply:
        for _ in range(MAX_REDIRECTS + 1):
            if time.monotonic() > self.deadline:
                raise OutOfTime
            response = self.http.post(self.url, json=body, headers=self.headers, stream=True,
                                      timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                                      allow_redirects=False)
            with response:
                target = self._redirect_target(response)
                if target:
                    self.url = target
                    continue
                reply = Reply(status=response.status_code,
                              session_id=response.headers.get("Mcp-Session-Id"),
                              challenged=response.status_code in (401, 403)
                              or "WWW-Authenticate" in response.headers)
                if expect_id is not None or response.status_code >= 400:
                    reply.message = self._read_message(response, expect_id)
                return reply
        return Reply(failure="redirect loop")

    def _redirect_target(self, response: requests.Response) -> Optional[str]:
        if response.status_code not in (301, 302, 307, 308):
            return None
        target = urljoin(self.url, response.headers.get("Location", ""))
        parts = urlsplit(target)
        if target == self.url or not parts.hostname:
            return None
        if not self.allow_private:
            if parts.scheme != "https" or not resolves_publicly(parts.hostname):
                return None
        return target

    def _read_message(self, response: requests.Response, expect_id: Optional[int]) -> Optional[dict]:
        if "text/event-stream" in response.headers.get("Content-Type", "").lower():
            return self._read_event_stream(response, expect_id)
        body = bytearray()
        for chunk in response.iter_content(16384):
            body.extend(chunk)
            if len(body) > MAX_BODY_BYTES:
                return None
            if time.monotonic() > self.deadline:
                raise OutOfTime
        return _as_message(bytes(body))

    def _read_event_stream(self, response: requests.Response, expect_id: Optional[int]) -> Optional[dict]:
        seen = 0
        for line in response.iter_lines(chunk_size=4096):
            seen += len(line) + 1
            if seen > MAX_BODY_BYTES:
                return None
            if time.monotonic() > self.deadline:
                raise OutOfTime
            if not line.startswith(b"data:"):
                continue
            message = _as_message(line[5:].strip())
            if message is None or not ({"result", "error"} & message.keys()):
                continue
            if expect_id is None or message.get("id") in (expect_id, None):
                return message
        return None


def _as_message(raw: bytes) -> Optional[dict]:
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _stateless_meta() -> dict:
    return {"io.modelcontextprotocol/protocolVersion": STATELESS_PROTOCOL,
            "io.modelcontextprotocol/clientInfo": CLIENT,
            "io.modelcontextprotocol/clientCapabilities": {}}


def _server_identity(result: dict) -> tuple[Optional[str], Optional[str]]:
    info = result.get("serverInfo")
    if not isinstance(info, dict):
        info = (result.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo")
    if not isinstance(info, dict):
        return None, None
    name, version = info.get("name"), info.get("version")
    return (str(name)[:200] if name is not None else None,
            str(version)[:80] if version is not None else None)


def _list_tools(talk: Conversation, stateless: bool) -> tuple[Optional[list], bool, Reply]:
    tools: list = []
    cursor = None
    for _ in range(MAX_TOOL_PAGES):
        params: dict = {"_meta": _stateless_meta()} if stateless else {}
        if cursor:
            params["cursor"] = cursor
        reply = talk.call("tools/list", params)
        result = reply.result
        if result is None:
            return (tools or None), False, reply
        page = result.get("tools")
        if isinstance(page, list):
            tools.extend(page)
        cursor = result.get("nextCursor")
        if not cursor:
            return tools, False, reply
    return tools, True, reply


def probe(endpoint: Endpoint, *, budget: float = 40.0, allow_private: bool = False) -> Observation:
    """Handshake and tools/list only. Sends no credentials and never calls a tool."""
    started = time.monotonic()
    seen = Observation(id=endpoint.id, url=endpoint.url, outcome="unreachable")

    def finish(outcome: str, detail: str = "", reply: Optional[Reply] = None) -> Observation:
        seen.outcome, seen.detail = outcome, detail
        if reply is not None:
            seen.http_status = reply.status
        seen.elapsed_ms = int((time.monotonic() - started) * 1000)
        return seen

    if not allow_private:
        public = resolves_publicly(endpoint.host)
        if public is None:
            return finish("unreachable", "dns")
        if not public:
            return finish("refused", "address is not publicly routable")

    with requests.Session() as http:
        http.headers.update({"User-Agent": USER_AGENT, "Content-Type": "application/json",
                             "Accept": "application/json, text/event-stream"})
        talk = Conversation(http, endpoint.url, started + budget, allow_private)

        hello = talk.call("initialize", {"protocolVersion": LEGACY_PROTOCOL,
                                         "capabilities": {}, "clientInfo": CLIENT})
        if hello.failure:
            return finish("unreachable", hello.failure)
        if hello.challenged:
            return finish("auth_required", "initialize", hello)

        stateless = False
        if hello.result is not None:
            seen.handshake = "initialize"
            seen.protocol_version = str(hello.result.get("protocolVersion") or LEGACY_PROTOCOL)[:40]
            talk.headers["MCP-Protocol-Version"] = seen.protocol_version
            if hello.session_id:
                talk.headers["Mcp-Session-Id"] = hello.session_id
            talk.call("notifications/initialized", notify=True)
        else:
            talk.headers["Mcp-Method"] = "server/discover"
            hello_again = talk.call("server/discover", {"_meta": _stateless_meta()})
            if hello_again.failure:
                return finish("unreachable", hello_again.failure)
            if hello_again.challenged:
                return finish("auth_required", "server/discover", hello_again)
            if hello_again.result is None:
                return finish("not_mcp", f"initialize: {hello.describe()}; "
                                         f"server/discover: {hello_again.describe()}", hello_again)
            stateless = True
            seen.handshake = "server/discover"
            versions = hello_again.result.get("protocolVersions")
            newest = max(map(str, versions)) if isinstance(versions, list) and versions else None
            seen.protocol_version = str(hello_again.result.get("protocolVersion")
                                        or newest or STATELESS_PROTOCOL)[:40]
            talk.headers["Mcp-Method"] = "tools/list"
            hello = hello_again

        seen.server_name, seen.server_version = _server_identity(hello.result)
        tools, truncated, last = _list_tools(talk, stateless)
        talk.end_session()

        if tools is None:
            if last.challenged:
                return finish("auth_required", "tools/list", last)
            return finish("handshake_only", f"tools/list: {last.describe()}", last)
        seen.tools, seen.tool_count, seen.truncated = tools, len(tools), truncated
        return finish("ok", "", last)
