"""Discovery and risk assessment for exposed Model Context Protocol servers.

The module operates in two stages:

    Discovery (passive)      -- query Shodan, Censys, and Certificate
                                Transparency for endpoints whose fingerprints
                                match MCP over Streamable HTTP. No packet is
                                sent to the target.

    Verification (authorized) -- perform the standard MCP handshake
                                (initialize -> tools/list) against a
                                discovered endpoint to enumerate the tools it
                                advertises. This touches the host directly and
                                is gated by the authorization layer. No tool is
                                ever invoked; only capability metadata is read.

Each discovered server is scored by an exposure model that weighs missing
authentication and the privilege of the tools it exposes.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import requests

try:
    from shodan import Shodan
except ImportError:  # pragma: no cover
    Shodan = None  # type: ignore

from authorization import authorize
import mcp_protocol

_SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
_CENSYS_TOKEN = (
    os.getenv("CENSYS_API_TOKEN", "").strip()
    or os.getenv("CENSYS_API_SECRET", "").strip()
)

_HTTP_TIMEOUT = 8
_USER_AGENT = "CyberOSINT-MCP-Discovery/1.0"
_WELL_KNOWN_PATH = "/.well-known/mcp.json"
_COMMON_MCP_PATHS = ("/mcp", "/sse", "/mcp/sse", "/api/mcp")

# Shodan search fingerprints for Streamable HTTP MCP endpoints.
_SHODAN_QUERIES = (
    'http.html:"jsonrpc" "mcp"',
    'http.component:"mcp"',
    '"Mcp-Session-Id"',
    'http.title:"MCP Server"',
)

# Tool capability -> privilege classification. Order matters: the first match
# wins, most dangerous first.
_RISK_PATTERNS = (
    ("command_exec", ("exec", "shell", "command", "run_", "subprocess", "eval", "terminal")),
    ("db_write", ("sql", "query", "database", "insert", "update", "delete", "drop", "mutate")),
    ("filesystem", ("file", "read_file", "write_file", "fs_", "path", "directory")),
    ("network", ("http", "fetch", "request", "url", "curl", "webhook")),
    ("secrets", ("secret", "token", "credential", "env", "key", "password")),
)


@dataclass
class MCPTool:
    name: str
    description: str = ""
    risk_flags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"name": self.name, "description": self.description,
                "risk_flags": self.risk_flags}


@dataclass
class MCPServer:
    endpoint: str
    host: str
    port: int
    transport: str = "streamable_http"
    discovered_via: list[str] = field(default_factory=list)
    auth_required: Optional[bool] = None
    verified: bool = False
    protocol_version: Optional[str] = None
    verification_method: Optional[str] = None
    fallback_reason: Optional[str] = None
    tools: list[MCPTool] = field(default_factory=list)
    server_info: dict = field(default_factory=dict)
    exposure_score: float = 0.0
    confidence: float = 0.0
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "host": self.host,
            "port": self.port,
            "transport": self.transport,
            "discovered_via": self.discovered_via,
            "auth_required": self.auth_required,
            "verified": self.verified,
            "protocol_version": self.protocol_version,
            "verification_method": self.verification_method,
            "fallback_reason": self.fallback_reason,
            "tools": [t.as_dict() for t in self.tools],
            "server_info": self.server_info,
            "exposure_score": self.exposure_score,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "notes": self.notes,
        }


def _classify_tool(name: str, description: str) -> list[str]:
    haystack = f"{name} {description}".lower()
    flags: list[str] = []
    for label, needles in _RISK_PATTERNS:
        if any(n in haystack for n in needles):
            flags.append(label)
    return flags


# --------------------------------------------------------------------------
# Stage 1: passive discovery
# --------------------------------------------------------------------------

def _shodan_discover(target_host: str) -> list[MCPServer]:
    if not (_SHODAN_API_KEY and Shodan):
        return []
    try:
        api = Shodan(_SHODAN_API_KEY)
    except Exception:
        return []

    found: dict[str, MCPServer] = {}
    for query in _SHODAN_QUERIES:
        scoped = f'{query} hostname:"{target_host}"' if target_host else query
        try:
            res = api.search(scoped, limit=25)
        except Exception:
            continue
        for match in res.get("matches", []):
            ip = match.get("ip_str")
            port = match.get("port")
            if not ip or not port:
                continue
            key = f"{ip}:{port}"
            server = found.get(key) or MCPServer(
                endpoint=f"https://{ip}:{port}",
                host=ip,
                port=int(port),
            )
            if "shodan" not in server.discovered_via:
                server.discovered_via.append("shodan")
            found[key] = server
    return list(found.values())


def _censys_discover(target_host: str) -> list[MCPServer]:
    if not _CENSYS_TOKEN or not target_host:
        return []
    url = "https://search.censys.io/api/v2/hosts/search"
    params = {"q": f'services.http.response.body: "jsonrpc" and name: {target_host}'}
    headers = {"Authorization": f"Bearer {_CENSYS_TOKEN}",
               "User-Agent": _USER_AGENT}
    try:
        r = requests.get(url, params=params, headers=headers, timeout=_HTTP_TIMEOUT)
        if r.status_code != 200:
            return []
        hits = r.json().get("result", {}).get("hits", [])
    except (requests.RequestException, ValueError):
        return []

    servers: list[MCPServer] = []
    for hit in hits:
        ip = hit.get("ip")
        if not ip:
            continue
        for svc in hit.get("services", []):
            port = svc.get("port")
            if not port:
                continue
            servers.append(MCPServer(
                endpoint=f"https://{ip}:{port}",
                host=ip,
                port=int(port),
                discovered_via=["censys"],
            ))
    return servers


def _crtsh_subdomains(domain: str) -> list[str]:
    """Certificate Transparency lookup for subdomains that hint at MCP hosts."""
    if not domain:
        return []
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    try:
        r = requests.get(url, headers={"User-Agent": _USER_AGENT}, timeout=_HTTP_TIMEOUT)
        if r.status_code != 200:
            return []
        rows = r.json()
    except (requests.RequestException, ValueError):
        return []

    names: set[str] = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain) and any(
                h in name for h in ("mcp", "agent", "ai", "tool", "llm")
            ):
                names.add(name)
    return sorted(names)


def _merge(*groups: Iterable[MCPServer]) -> list[MCPServer]:
    merged: dict[str, MCPServer] = {}
    for group in groups:
        for server in group:
            key = f"{server.host}:{server.port}"
            existing = merged.get(key)
            if existing is None:
                merged[key] = server
            else:
                for src in server.discovered_via:
                    if src not in existing.discovered_via:
                        existing.discovered_via.append(src)
    return list(merged.values())


# --------------------------------------------------------------------------
# Stage 2: authorized passive verification
# --------------------------------------------------------------------------

def _resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host if _looks_like_ip(host) else None


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _mcp_request(endpoint_url: str, method: str, params: dict,
                 session_id: Optional[str] = None) -> tuple[Optional[dict], Optional[str], int]:
    """Send one JSON-RPC request over Streamable HTTP. Returns (body, session, status)."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": _USER_AGENT,
        "Mcp-Method": method,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    try:
        r = requests.post(endpoint_url, json=payload, headers=headers,
                          timeout=_HTTP_TIMEOUT)
    except requests.RequestException:
        return None, None, 0

    returned_session = r.headers.get("Mcp-Session-Id")
    body: Optional[dict] = None
    text = r.text.strip()
    if text.startswith("event:") or "data:" in text:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    body = json.loads(line[5:].strip())
                    break
                except ValueError:
                    continue
    else:
        try:
            body = r.json()
        except ValueError:
            body = None
    return body, returned_session, r.status_code


def _apply_verification(server: MCPServer, result: dict) -> None:
    """Map a mcp_protocol negotiation result onto an MCPServer in place."""
    if not result.get("is_mcp"):
        for err in result.get("errors", []):
            server.notes.append(err)
        return

    server.verified = True
    server.transport = "streamable_http"
    server.endpoint = result.get("url", server.endpoint)
    server.auth_required = result.get("auth_required", server.auth_required)
    server.server_info = result.get("server_info") or {}
    server.protocol_version = result.get("protocol_version")
    server.verification_method = result.get("verification_method")
    server.fallback_reason = result.get("fallback_reason")

    if server.verification_method:
        note = f"verified via {server.verification_method}"
        if server.protocol_version:
            note += f" (protocol {server.protocol_version})"
        server.notes.append(note)
    if server.fallback_reason:
        server.notes.append(f"fallback: {server.fallback_reason}")

    for raw in result.get("tools", []):
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        desc = str(raw.get("description", ""))
        server.tools.append(
            MCPTool(name=name, description=desc,
                    risk_flags=_classify_tool(name, desc))
        )
    for err in result.get("errors", []):
        server.notes.append(err)


def _verify_endpoint(server: MCPServer) -> None:
    """Negotiate the MCP protocol (server/discover -> initialize) over TLS."""
    result = mcp_protocol.verify_host(
        server.host, server.port, use_tls=True,
        timeout=_HTTP_TIMEOUT, paths=list(_COMMON_MCP_PATHS),
    )
    _apply_verification(server, result)


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def _score_server(server: MCPServer) -> None:
    """Exposure score in [0, 10]. Higher means more dangerous exposure."""
    score = 0.0

    if server.auth_required is False:
        score += 5.0
    elif server.auth_required is None:
        score += 1.0

    weights = {"command_exec": 3.0, "secrets": 2.5, "db_write": 2.0,
               "filesystem": 1.5, "network": 1.0}
    tool_component = 0.0
    for tool in server.tools:
        tool_component = max(
            tool_component,
            max((weights.get(f, 0.0) for f in tool.risk_flags), default=0.0),
        )
    score += tool_component

    confidence = 0.3 * len(set(server.discovered_via))
    if server.verified:
        confidence += 0.4
    if server.tools:
        confidence += 0.2

    server.exposure_score = round(min(score, 10.0), 1)
    server.confidence = round(min(confidence, 1.0), 2)


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def discover(target: str, target_type: str = "domain",
             verify: bool = True) -> dict[str, Any]:
    """Discover exposed MCP servers for a target and, when authorized, verify them.

    target_type is one of: domain, ip. Verification runs only against hosts the
    authorization layer approves; discovery itself is always passive.
    """
    target = (target or "").strip()
    domain = target if target_type == "domain" else ""

    shodan_hits = _shodan_discover(target)
    censys_hits = _censys_discover(target)

    crtsh_hits: list[MCPServer] = []
    for sub in _crtsh_subdomains(domain):
        ip = _resolve_host(sub)
        if ip:
            crtsh_hits.append(MCPServer(
                endpoint=f"https://{ip}:443",
                host=ip,
                port=443,
                discovered_via=["crtsh"],
                notes=[f"candidate subdomain {sub}"],
            ))

    servers = _merge(shodan_hits, censys_hits, crtsh_hits)

    for server in servers:
        if verify:
            auth = authorize(server.host, action="mcp_verify")
            if auth.allowed:
                _verify_endpoint(server)
            else:
                server.notes.append(f"verification skipped: {auth.reason}")
        _score_server(server)

    servers.sort(key=lambda s: s.exposure_score, reverse=True)

    return {
        "target": target,
        "target_type": target_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "server_count": len(servers),
        "servers": [s.as_dict() for s in servers],
    }


def verify_direct(host: str, port: int, use_tls: bool = True) -> dict[str, Any]:
    """Verify a single known MCP endpoint directly, bypassing passive discovery.

    Useful when the operator already knows a candidate address (e.g. from an
    internal inventory, a client report, or local testing) and wants to run
    the same authorized handshake and scoring pipeline against it directly.
    """
    server = MCPServer(
        endpoint=f"{'https' if use_tls else 'http'}://{host}:{port}",
        host=host,
        port=port,
        discovered_via=["direct"],
    )
    auth = authorize(host, action="mcp_verify_direct")
    if not auth.allowed:
        server.notes.append(f"verification skipped: {auth.reason}")
        _score_server(server)
        return {"server": server.as_dict(), "authorized": False, "reason": auth.reason}

    if use_tls:
        _verify_endpoint(server)
    else:
        _verify_endpoint_plain(server)

    _score_server(server)
    return {"server": server.as_dict(), "authorized": True, "reason": auth.reason}


def _verify_endpoint_plain(server: MCPServer) -> None:
    """Same negotiation as _verify_endpoint but over plain HTTP, for local
    testing where TLS is not configured."""
    result = mcp_protocol.verify_host(
        server.host, server.port, use_tls=False,
        timeout=_HTTP_TIMEOUT, paths=list(_COMMON_MCP_PATHS),
    )
    _apply_verification(server, result)
