from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PROTOCOL = "2025-06-18"
CLIENT = {"name": "raqeeb-reference", "version": "0.1"}
MAX_TOOL_PAGES = 5


@dataclass
class Listing:
    outcome: str
    detail: str = ""
    protocol_version: Optional[str] = None
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    tools: Optional[list] = field(default=None, repr=False)


class Session:
    """One MCP server process spoken to over newline-delimited JSON-RPC."""

    def __init__(self, command: list[str], cwd: Path, env: dict[str, str]):
        self.process = subprocess.Popen(
            command, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True)
        self.inbox: queue.Queue = queue.Queue()
        self._next_id = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for raw in self.process.stdout:
            try:
                message = json.loads(raw)
            except ValueError:
                continue
            if isinstance(message, dict):
                self.inbox.put(message)
        self.inbox.put(None)

    def _send(self, message: dict) -> None:
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def call(self, method: str, params: dict, deadline: float) -> Optional[dict]:
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                message = self.inbox.get(timeout=remaining)
            except queue.Empty:
                return None
            if message is None:
                return None
            if message.get("id") == self._next_id and ({"result", "error"} & message.keys()):
                return message

    def has_exited(self) -> bool:
        try:
            self.process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            return False
        return True

    def close(self) -> None:
        try:
            if hasattr(os, "killpg"):
                os.killpg(self.process.pid, signal.SIGKILL)
            else:  # Windows: no process groups from start_new_session
                self.process.kill()
        except ProcessLookupError:
            pass
        self.process.wait()


def list_tools(command: list[str], *, cwd: Path, env: dict[str, str], timeout: float = 25.0) -> Listing:
    """Start a server, complete the handshake and read tools/list. No tool is called."""
    deadline = time.monotonic() + timeout
    try:
        session = Session(command, cwd, env)
    except OSError as error:
        return Listing("not_started", str(error))
    try:
        hello = session.call("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                            "clientInfo": CLIENT}, deadline)
        if hello is None:
            return Listing("exited" if session.has_exited() else "no_answer", "initialize")
        if "result" not in hello:
            return Listing("refused", f"initialize: jsonrpc {hello['error'].get('code')}")
        result = hello["result"] or {}
        info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
        listing = Listing("listed", protocol_version=result.get("protocolVersion"),
                          server_name=info.get("name"), server_version=info.get("version"))
        session.notify("notifications/initialized")

        tools: list = []
        cursor = None
        for _ in range(MAX_TOOL_PAGES):
            page = session.call("tools/list", {"cursor": cursor} if cursor else {}, deadline)
            if page is None or "result" not in page:
                code = (page or {}).get("error", {}).get("code", "no answer")
                return Listing("no_tools", f"tools/list: {code}", listing.protocol_version,
                               listing.server_name, listing.server_version)
            tools.extend(page["result"].get("tools") or [])
            cursor = page["result"].get("nextCursor")
            if not cursor:
                break
        listing.tools = tools
        return listing
    except (BrokenPipeError, OSError):
        return Listing("exited", "pipe closed")
    finally:
        session.close()
