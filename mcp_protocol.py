"""MCP protocol negotiation layer for CyberOSINT verification.

Fixes the P0 correctness blocker: the old verifier spoke only the legacy
`initialize` handshake, which the 2026-07-28 MCP spec removed (SEP-2575).
A modern strict server would reject `initialize`, so the scanner would report
"no MCP here" for an endpoint that is actually exposed — a false negative.

This module negotiates both eras:

  1. MODERN (2026-07-28): call `server/discover`; protocol version, client info
     and client capabilities travel in `params._meta` on every request. No
     session, no initialize.
  2. LEGACY (<= 2025-11-25): fall back to `initialize` -> `notifications/initialized`.

Every result records HOW it was verified (protocol_version, verification_method,
fallback_reason) so each finding carries defensible evidence.

Passive/non-destructive by design: it only calls discovery/list methods
(`server/discover`, `initialize`, `tools/list`). It NEVER invokes a tool.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import requests

MODERN_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"

_CLIENT_INFO = {"name": "CyberOSINT-Scanner", "version": "2.0"}
_JSONRPC_METHOD_NOT_FOUND = -32601
_DEFAULT_PATHS = ["/mcp", "/sse", "/mcp/sse", "/api/mcp", "/"]


# --------------------------------------------------------------------------
# Low-level JSON-RPC over Streamable HTTP (accepts JSON or SSE responses)
# --------------------------------------------------------------------------

def _modern_meta() -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientInfo": _CLIENT_INFO,
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _parse_body(resp: requests.Response) -> Optional[dict]:
    """Return the JSON-RPC message whether the server replied JSON or SSE."""
    ctype = (resp.headers.get("content-type") or "").lower()
    text = resp.text or ""
    if "text/event-stream" in ctype:
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            try:
                obj = json.loads(payload)
            except ValueError:
                continue
            if isinstance(obj, dict) and (
                "result" in obj or "error" in obj or "jsonrpc" in obj
            ):
                return obj
        return None
    try:
        obj = resp.json()
        return obj if isinstance(obj, dict) else None
    except ValueError:
        return None


def _rpc(url: str, method: str, params: Optional[dict], timeout: int,
         auth_token: Optional[str], notify: bool = False) -> dict:
    """Send one JSON-RPC call. Returns a normalized envelope, never raises."""
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if not notify:
        body["id"] = 1
    if params is not None:
        body["params"] = params

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "CyberOSINT-Scanner/2.0",
        "Mcp-Method": method,  # 2026-07-28 header-based routing hint
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        resp = requests.post(url, json=body, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        return {"transport_error": str(exc), "status": None, "message": None}

    return {
        "transport_error": None,
        "status": resp.status_code,
        "message": _parse_body(resp),
        "www_authenticate": resp.headers.get("www-authenticate"),
    }


# --------------------------------------------------------------------------
# Version extraction helpers (tolerant of shape differences)
# --------------------------------------------------------------------------

def _extract_version(result: dict) -> Optional[str]:
    if not isinstance(result, dict):
        return None
    if isinstance(result.get("protocolVersion"), str):
        return result["protocolVersion"]
    versions = result.get("protocolVersions")
    if isinstance(versions, list) and versions:
        return str(sorted(versions, reverse=True)[0])
    meta = result.get("_meta") or {}
    v = meta.get("io.modelcontextprotocol/protocolVersion")
    return str(v) if v else None


def _extract_server_info(result: dict) -> Optional[dict]:
    if not isinstance(result, dict):
        return None
    if isinstance(result.get("serverInfo"), dict):
        return result["serverInfo"]
    meta = result.get("_meta") or {}
    si = meta.get("io.modelcontextprotocol/serverInfo")
    return si if isinstance(si, dict) else None


def _list_tools(url: str, era: str, timeout: int,
                auth_token: Optional[str]) -> tuple[list, Optional[str]]:
    params = {"_meta": _modern_meta()} if era == "modern" else {}
    r = _rpc(url, "tools/list", params, timeout, auth_token)
    if r["transport_error"]:
        return [], r["transport_error"]
    msg = r["message"] or {}
    if "error" in msg:
        return [], f"tools/list error {msg['error'].get('code')}"
    tools = ((msg.get("result") or {}).get("tools")) or []
    return (tools if isinstance(tools, list) else []), None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def verify_mcp_endpoint(url: str, timeout: int = 10,
                        auth_token: Optional[str] = None) -> dict:
    """Verify one exact MCP endpoint URL, negotiating modern then legacy.

    Returns evidence:
      is_mcp, protocol_version, verification_method, fallback_reason,
      auth_required, server_info, tools, errors
    """
    out = {
        "url": url,
        "is_mcp": False,
        "protocol_version": None,
        "verification_method": None,   # "server/discover" | "initialize" | None
        "fallback_reason": None,
        "auth_required": False,
        "server_info": None,
        "tools": [],
        "errors": [],
    }

    # ---- Attempt 1: MODERN via server/discover -------------------------
    disc = _rpc(url, "server/discover", {"_meta": _modern_meta()},
                timeout, auth_token)

    if disc["transport_error"]:
        out["errors"].append(f"discover transport: {disc['transport_error']}")
    elif disc["status"] in (401, 403):
        out["auth_required"] = True
        out["is_mcp"] = True  # something is guarding an MCP endpoint here
        out["verification_method"] = "server/discover"
        out["errors"].append("401 Unauthorized (auth required before discovery)")
        return out
    else:
        msg = disc["message"] or {}
        if "result" in msg:
            result = msg["result"] or {}
            out["is_mcp"] = True
            out["verification_method"] = "server/discover"
            out["protocol_version"] = _extract_version(result) or MODERN_VERSION
            out["server_info"] = _extract_server_info(result)
            tools, terr = _list_tools(url, "modern", timeout, auth_token)
            out["tools"] = tools
            if terr:
                out["errors"].append(terr)
            return out
        # decide whether to fall back
        if "error" in msg:
            code = (msg["error"] or {}).get("code")
            if code == _JSONRPC_METHOD_NOT_FOUND:
                out["fallback_reason"] = "server/discover not implemented (-32601)"
            else:
                out["fallback_reason"] = f"server/discover error {code}"
        elif disc["status"] in (404, 405, 501):
            out["fallback_reason"] = f"server/discover HTTP {disc['status']}"
        else:
            out["fallback_reason"] = f"server/discover no result (HTTP {disc['status']})"

    # ---- Attempt 2: LEGACY via initialize ------------------------------
    init = _rpc(url, "initialize", {
        "protocolVersion": LEGACY_VERSION,
        "capabilities": {},
        "clientInfo": _CLIENT_INFO,
    }, timeout, auth_token)

    if init["transport_error"]:
        out["errors"].append(f"initialize transport: {init['transport_error']}")
        return out
    if init["status"] in (401, 403):
        out["auth_required"] = True
        out["is_mcp"] = True
        out["verification_method"] = "initialize"
        out["errors"].append("401 Unauthorized on initialize")
        return out

    imsg = init["message"] or {}
    if "result" in imsg:
        result = imsg["result"] or {}
        out["is_mcp"] = True
        out["verification_method"] = "initialize"
        out["protocol_version"] = _extract_version(result) or LEGACY_VERSION
        out["server_info"] = _extract_server_info(result)
        # complete the legacy handshake, then list
        _rpc(url, "notifications/initialized", {}, timeout, auth_token, notify=True)
        tools, terr = _list_tools(url, "legacy", timeout, auth_token)
        out["tools"] = tools
        if terr:
            out["errors"].append(terr)
        return out

    if "error" in imsg:
        out["errors"].append(
            f"initialize error {(imsg['error'] or {}).get('code')}")
    else:
        out["errors"].append(
            f"initialize no result (HTTP {init['status']})")
    return out


def verify_host(host: str, port: int, use_tls: bool = True, timeout: int = 10,
                auth_token: Optional[str] = None,
                paths: Optional[list[str]] = None) -> dict:
    """Try common MCP paths on host:port; return first that verifies as MCP."""
    scheme = "https" if use_tls else "http"
    last = None
    for path in (paths or _DEFAULT_PATHS):
        url = f"{scheme}://{host}:{port}{path}"
        res = verify_mcp_endpoint(url, timeout=timeout, auth_token=auth_token)
        last = res
        if res["is_mcp"]:
            return res
    return last or {"is_mcp": False, "errors": ["no endpoint responded"]}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python mcp_protocol.py <mcp_endpoint_url>")
        raise SystemExit(2)
    print(json.dumps(verify_mcp_endpoint(sys.argv[1]), indent=2))


# --------------------------------------------------------------------------
# Safe canary invocation — the ONLY path that ever calls a tool.
# Two hard guards make it impossible to weaponize:
#   1) loopback targets only (127.0.0.1 / localhost / ::1)
#   2) a read-only safe-tool allowlist; dangerous tools are refused outright.
# Used solely to DEMONSTRATE that the invocation channel is open, harmlessly.
# --------------------------------------------------------------------------

import urllib.parse as _urlparse

_SAFE_CANARY_TOOLS = {"list_projects", "get_status", "canary_ping", "ping", "health"}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _is_loopback(url: str) -> bool:
    host = (_urlparse.urlparse(url).hostname or "").lower()
    return host in _LOOPBACK_HOSTS


def safe_call_tool(url: str, tool_name: str, era: str = "modern",
                   timeout: int = 10, auth_token: Optional[str] = None) -> dict:
    """Invoke ONE safe, read-only tool on a loopback lab server, or refuse.

    Never calls a dangerous tool and never touches a non-loopback target.
    Returns {ok, refused?, marker?, reason?}.
    """
    if not _is_loopback(url):
        return {"ok": False, "refused": True,
                "reason": "canary invocation is restricted to loopback lab targets"}
    if tool_name not in _SAFE_CANARY_TOOLS:
        return {"ok": False, "refused": True,
                "reason": f"'{tool_name}' is not on the safe canary allowlist"}

    params = {"name": tool_name, "arguments": {}}
    if era == "modern":
        params["_meta"] = _modern_meta()
    record = {"tool": tool_name, "invoked": True,
              "request": {"method": "tools/call", "params": params},
              "safety": {"production_data_accessed": None,
                         "destructive_action_performed": None,
                         "dangerous_tool_invoked": False}}
    r = _rpc(url, "tools/call", params, timeout, auth_token)
    if r["transport_error"]:
        return {**record, "ok": False, "reason": r["transport_error"]}
    msg = r["message"] or {}
    if "error" in msg:
        return {**record, "ok": False, "error": msg["error"],
                "reason": "JSON-RPC error"}
    result = msg.get("result")
    if not isinstance(result, dict):
        return {**record, "ok": False, "result": result,
                "reason": "Missing or malformed tool result"}
    content = result.get("content")
    if not isinstance(content, list):
        return {**record, "ok": False, "result": result,
                "reason": "Missing or malformed result content"}
    marker = next((block.get("text") for block in content
                   if isinstance(block, dict) and block.get("type") == "text"
                   and isinstance(block.get("text"), str)), None)
    return {**record, "ok": result.get("isError") is not True,
            "result": result, "marker": marker}
