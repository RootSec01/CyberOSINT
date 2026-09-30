"""Versioned, deterministic, passive fingerprint of MCP declarations.

A hash is a change indicator, not a signature and not evidence of tool behavior.
The snapshot is saved with each new report to permit typed before/after drift.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List
import redaction

SNAPSHOT_SCHEMA = "mcp-manifest-v2"


def _norm(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _norm(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    return value


def _norm_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(tool, dict):
        return {"name": "<malformed>", "_malformed": _norm(tool)}
    result = {k: _norm(v) for k, v in tool.items()
              if k not in ("inputSchema", "input_schema", "outputSchema", "output_schema")}
    result["name"] = str(tool.get("name", ""))
    result["description"] = str(tool.get("description", ""))
    result["input_schema"] = _norm(tool.get("inputSchema", tool.get("input_schema", {})))
    result["output_schema"] = _norm(tool.get("outputSchema", tool.get("output_schema", {})))
    return result


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      default=str)


def normalize(server: Dict[str, Any]) -> Dict[str, Any]:
    """Include advertised metadata, schemas, annotations and security hints.

    The allowlisted root fields exclude scan-time URL, timestamps, and results.
    Tool declarations and server_info are preserved without key filtering.
    """
    tools = [_norm_tool(t) for t in (server.get("tools") or [])]
    tools.sort(key=lambda t: (t["name"], _canonical(t)))
    return {"protocol_version": server.get("protocol_version"),
            "server_info": _norm(server.get("server_info") or {}),
            "auth_required": server.get("auth_required"),
            "tools": tools}


def snapshot_for_storage(server: Dict[str, Any]) -> Dict[str, Any]:
    """Comparable snapshot; store digests of values instead of raw metadata.

    Names remain human-readable after privacy redaction. If redaction collapses
    two names or digest-only fields hide a typed difference, the raw fingerprint
    still reports an unclassified change.
    """
    view = normalize(server)
    info = view["server_info"]
    view["server_info"] = ({k: "sha256:" + hashlib.sha256(_canonical(v).encode()).hexdigest()
                            for k, v in info.items()} if isinstance(info, dict) else
                           "sha256:" + hashlib.sha256(_canonical(info).encode()).hexdigest())
    for tool in view["tools"]:
        tool["name"] = redaction.redact_text(tool["name"])
        for field in list(tool):
            if field != "name":
                tool[field] = "sha256:" + hashlib.sha256(
                    _canonical(tool[field]).encode("utf-8")).hexdigest()
    view["tools"].sort(key=lambda t: (t["name"], _canonical(t)))
    return view

def fingerprint(server: Dict[str, Any]) -> str:
    canonical = _canonical(normalize(server))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def auth_change_tone(old: Any, new: Any) -> str:
    """Unknown is never silently treated as an improvement."""
    if new is None:
        return "warn"
    if new is False:
        return "crit"
    if old is None:
        return "info"
    return "good" if old is False and new is True else "warn"


def _tool_map(norm: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    counts: Dict[str, int] = {}
    out = {}
    for tool in norm["tools"]:
        name = tool["name"]
        counts[name] = counts.get(name, 0) + 1
        out[(name, counts[name])] = tool
    return out


def diff(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Typed explanation whose changed/summary cannot contradict its checksum."""
    c, p = normalize(current), normalize(previous)
    cf, pf = fingerprint(current), fingerprint(previous)
    changes: List[Dict[str, str]] = []

    def add(kind, detail, tone):
        changes.append({"kind": kind, "detail": detail, "tone": tone})

    if c["auth_required"] != p["auth_required"]:
        add("authentication_changed",
            f"auth_required {p['auth_required']} → {c['auth_required']}",
            auth_change_tone(p["auth_required"], c["auth_required"]))
    if c["protocol_version"] != p["protocol_version"]:
        add("protocol_changed", f"{p['protocol_version']} → {c['protocol_version']}", "info")

    ci, pi = c["server_info"], p["server_info"]
    if isinstance(ci, dict) and isinstance(pi, dict):
        for key in sorted(set(ci) | set(pi)):
            if ci.get(key) != pi.get(key) or (key in ci) != (key in pi):
                add("server_info_changed", f"server_info.{key} changed", "warn")
    elif ci != pi:
        add("server_info_changed", "server_info changed", "warn")

    cm, pm = _tool_map(c), _tool_map(p)
    for name, occurrence in sorted(set(cm) - set(pm)):
        add("tool_added", f"{name} (occurrence {occurrence})", "warn")
    for name, occurrence in sorted(set(pm) - set(cm)):
        add("tool_removed", f"{name} (occurrence {occurrence})", "info")
    for name, occurrence in sorted(set(cm) & set(pm)):
        a, b = cm[(name, occurrence)], pm[(name, occurrence)]
        label = f"{name} (occurrence {occurrence})"
        for field, kind in (("description", "description_changed"),
                            ("input_schema", "schema_changed"),
                            ("output_schema", "output_schema_changed"),
                            ("annotations", "annotations_changed")):
            if a.get(field) != b.get(field):
                add(kind, f"{label}: {field} changed", "warn")
        for field in sorted((set(a) | set(b)) - {
                "name", "description", "input_schema", "output_schema", "annotations"}):
            if a.get(field) != b.get(field) or (field in a) != (field in b):
                add("tool_metadata_changed", f"{label}: {field} changed", "warn")

    if (cf != pf) != bool(changes):
        # Never claim an unchanged manifest if an as-yet-unknown field differs.
        add("unclassified_manifest_change", "Manifest content changed; review declaration", "warn")
    return {"previous_fingerprint": pf, "current_fingerprint": cf,
            "changed": cf != pf, "changes": changes, "change_count": len(changes),
            "summary": _summarise(changes) if changes else "manifest unchanged",
            "snapshot_schema": SNAPSHOT_SCHEMA}


def _summarise(changes: List[Dict[str, str]]) -> str:
    counts: Dict[str, int] = {}
    for change in changes:
        counts[change["kind"]] = counts.get(change["kind"], 0) + 1
    labels = {"tool_added": "tool(s) added", "tool_removed": "tool(s) removed",
              "description_changed": "description change(s)",
              "schema_changed": "input schema change(s)",
              "output_schema_changed": "output schema change(s)",
              "annotations_changed": "annotation change(s)",
              "tool_metadata_changed": "tool metadata change(s)",
              "server_info_changed": "server metadata change(s)",
              "authentication_changed": "authentication change",
              "protocol_changed": "protocol change"}
    return ", ".join(f"{n} {labels.get(k, k)}" for k, n in counts.items())
