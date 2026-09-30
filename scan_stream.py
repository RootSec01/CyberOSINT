"""Live scan event stream — feeds the real-time attack graph.

Emits an ORDERED sequence of small events as a scan actually progresses, so the
UI can draw the graph node-by-node instead of showing a silent spinner. Each
node names its parent, so the front-end draws the edge as the node arrives.

Event shapes (all JSON-serialisable dicts):
  {"type":"stage","stage":<slug>,"message":<str>,"seq":<int>}
  {"type":"node","id":<str>,"kind":<str>,"label":<str>,"parent":<str|None>,
   "tone":<str>,"meta":<dict>,"seq":<int>}
  {"type":"done","result":<dict>,"seq":<int>}
  {"type":"error","message":<str>,"seq":<int>}

The MCP path is fully deterministic (works against the lab with no external
API), which is why it is unit-tested end to end.
"""

from __future__ import annotations

import json
import time
from typing import Iterator, Optional

import mcp_protocol
import safe_proof

_SAFE_CANARY = {"list_projects", "get_status", "canary_ping", "ping", "health"}
_TONE = {"command_exec": "crit", "db_write": "high", "secrets": "high",
         "filesystem": "med", "network": "low"}


def sse_format(event: dict) -> str:
    """Render one event as an SSE frame."""
    return f"data: {json.dumps(event, default=str)}\n\n"


class _Seq:
    def __init__(self):
        self.n = 0

    def next(self) -> int:
        self.n += 1
        return self.n


def mcp_scan_events(host: str, port: int, use_tls: bool = False,
                    canary_allowed: bool = False,
                    delay: float = 0.0) -> Iterator[dict]:
    """Yield ordered live-graph events for an MCP verification + safe proof."""
    seq = _Seq()

    def stage(slug, message):
        return {"type": "stage", "stage": slug, "message": message, "seq": seq.next()}

    def node(nid, kind, label, parent=None, tone="mist", meta=None):
        return {"type": "node", "id": nid, "kind": kind, "label": label,
                "parent": parent, "tone": tone, "meta": meta or {}, "seq": seq.next()}

    def pause():
        if delay:
            time.sleep(delay)

    scheme = "https" if use_tls else "http"
    endpoint = f"{scheme}://{host}:{port}/mcp"

    yield stage("resolve", f"Resolving target {host}:{port}")
    yield node("target", "target", f"{host}:{port}", tone="signal",
               meta={"scheme": scheme})
    pause()

    yield stage("verify", "Negotiating MCP protocol (discover → initialize)")
    server = mcp_protocol.verify_host(host, int(port), use_tls=use_tls)
    pause()

    if not server.get("is_mcp"):
        yield node("miss", "info", "No MCP server verified", parent="target")
        yield {"type": "done", "result": {"is_mcp": False}, "seq": seq.next()}
        return

    yield node("mcp", "mcp_server",
               f"MCP server · {server.get('protocol_version') or 'unknown'}",
               parent="target",
               tone="crit" if server.get("auth_required") is False else "high",
               meta={"protocol_version": server.get("protocol_version"),
                     "verification_method": server.get("verification_method"),
                     "auth_required": server.get("auth_required")})
    pause()

    # tools appear one by one, tinted by capability
    yield stage("tools", f"Enumerating {len(server.get('tools') or [])} declared tools")
    for i, tool in enumerate(server.get("tools") or []):
        flags = safe_proof._classify(tool)
        danger = next((f for f in ("command_exec", "secrets", "db_write",
                                   "filesystem", "network") if f in flags), None)
        yield node(f"tool{i}", "tool", tool.get("name", "tool"), parent="mcp",
                   tone=_TONE.get(danger, "mist"),
                   meta={"risk_flags": flags,
                         "dangerous": bool(danger in
                                           ("command_exec", "secrets", "db_write",
                                            "filesystem"))})
        pause()

    # optional safe canary (loopback-only, enforced inside safe_call_tool)
    canary = None
    if canary_allowed:
        for tool in (server.get("tools") or []):
            if tool.get("name") in _SAFE_CANARY:
                yield stage("canary", f"Safe canary probe: {tool['name']}")
                canary = mcp_protocol.safe_call_tool(
                    server.get("url") or endpoint, tool["name"])
                pause()
                break

    yield stage("proof", "Reasoning verified blast radius")
    proof = safe_proof.build_safe_proof(server, canary=canary)
    pause()

    # attack path drawn step by step, chained
    prev = "mcp"
    for step in proof["attack_path"]:
        nid = f"step{step['order']}"
        tone = {"OBSERVED": "signal", "PROVEN": "crit", "DEMONSTRATED": "high",
                "INFERRED": "mist"}.get(step["evidence_tier"], "mist")
        yield node(nid, "attack_step",
                   f"{step['technique_id']} · {step['title']}", parent=prev,
                   tone=tone, meta={"tier": step["evidence_tier"],
                                    "technique": step["technique_name"]})
        prev = nid
        pause()

    for i, asset in enumerate(proof["blast_radius"]["reachable"]):
        yield node(f"blast{i}", "blast", asset, parent="mcp", tone="crit")
        pause()

    yield {"type": "done", "result": proof, "seq": seq.next()}


def graph_scan_events(host: str, port: int, use_tls: bool = False,
                      canary_allowed: bool = False,
                      delay: float = 0.0):
    """Emit the branching Executable-Evidence graph as ordered live events.

    Nodes arrive in build order (spine → capabilities → impacts → downstream),
    each carrying its parent, edge class, tier and full evidence. The client
    draws each node, then any edge whose endpoints now both exist.
    """
    seq = _Seq()

    def stage(slug, message):
        return {"type": "stage", "stage": slug, "message": message, "seq": seq.next()}

    scheme = "https" if use_tls else "http"
    endpoint = f"{scheme}://{host}:{port}/mcp"

    yield stage("resolve", f"Resolving target {host}:{port}")
    server = mcp_protocol.verify_host(host, int(port), use_tls=use_tls)

    if not server.get("is_mcp"):
        yield {"type": "node", "id": "target", "kind": "access",
               "label": f"{host}:{port}", "tone": "signal", "seq": seq.next()}
        yield {"type": "done", "result": {"is_mcp": False}, "seq": seq.next()}
        return

    yield stage("verify", "Negotiating MCP protocol (discover → initialize)")

    canary = None
    if canary_allowed:
        for tool in (server.get("tools") or []):
            if tool.get("name") in _SAFE_CANARY:
                yield stage("canary", f"Safe canary probe: {tool['name']}")
                canary = mcp_protocol.safe_call_tool(
                    server.get("url") or endpoint, tool["name"])
                break

    yield stage("proof", "Reasoning verified blast radius")
    proof = safe_proof.build_safe_proof(server, canary=canary)
    graph = proof.get("graph") or {"nodes": [], "edges": []}

    parent, ecls = {}, {}
    for e in graph["edges"]:
        parent[e["to"]] = e["from"]
        ecls[e["to"]] = e["cls"]

    last_stage = None
    for n in graph["nodes"]:
        # a light stage line as each phase begins, for the status strip
        phase = {"access": "Mapping target", "agent": "Agent verified",
                 "step": "Access assessment", "cap": "Enumerating capabilities",
                 "impact": "Deriving impact", "down": "Reasoning downstream"}.get(n["kind"])
        if phase and phase != last_stage:
            last_stage = phase
            yield stage(n["kind"], phase)
        yield {
            "type": "node", "seq": seq.next(),
            "id": n["id"], "kind": n["kind"], "label": n["label"],
            "tone": n["tone"], "tier": n.get("tier"), "tid": n.get("tid"),
            "danger": n.get("danger", False), "capKey": n.get("capKey"),
            "sub": n.get("sub"), "parent": parent.get(n["id"]),
            "edge": ecls.get(n["id"]), "evidence": n.get("evidence"),
        }
        if delay:
            time.sleep(delay)

    yield {"type": "done", "result": proof, "seq": seq.next()}
