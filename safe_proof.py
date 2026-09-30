"""Passive MCP evidence report. Declarations are observations, impacts are hypotheses.
Canary outcomes are supplied observations, never synthesized by this module.
"""

from __future__ import annotations

import re
import json
import hashlib
from datetime import datetime, timezone

from typing import Optional

import mcp_detectors
import manifest_fingerprint
import redaction
import copy

OBSERVED = "OBSERVED"
PROVEN = OBSERVED  # compatibility for Python callers; new reports emit OBSERVED
DEMONSTRATED = "DEMONSTRATED"
INFERRED = "INFERRED"

# risk_flag -> (ATT&CK id, name, asset the capability reaches, inferred next moves)
_TECHNIQUE = {
    "command_exec": ("T1059", "Command and Scripting Interpreter",
                     "arbitrary command execution on the host",
                     [("T1005", "Data from Local System"),
                      ("T1552", "Unsecured Credentials"),
                      ("T1021", "Remote Services / lateral movement")]),
    "db_write": ("T1565", "Data Manipulation",
                 "read/write access to the backing database",
                 [("T1485", "Data Destruction")]),
    "secrets": ("T1552", "Unsecured Credentials",
                "stored credentials, tokens and API keys",
                [("T1078", "Valid Accounts"),
                 ("T1021", "Remote Services / lateral movement")]),
    "filesystem": ("T1005", "Data from Local System",
                   "the host filesystem",
                   [("T1083", "File and Directory Discovery")]),
    "network": ("T1090", "Proxy / internal pivot",
                "the internal network reachable from the host",
                [("T1021", "Remote Services / lateral movement")]),
}
_DANGEROUS = {"command_exec", "db_write", "secrets", "filesystem"}
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}

# Keyword classifier — used only when a tool arrives without risk_flags
# (e.g. straight from verify_mcp_endpoint rather than classified discovery).
# Ordered so the most specific capability wins first. Each entry lists whole
# tokens matched on word boundaries — so "execute_sql" is db_write, not command
# exec (the old substring match saw "exec" inside "execute" and over-flagged).
_CLASSIFY = [
    ("db_write", ("sql", "database", "db", "query", "insert", "update",
                  "delete", "drop", "mutation", "table", "record")),
    ("secrets", ("secret", "secrets", "credential", "credentials", "token", "key", "keys",
                 "apikey", "password", "env", "vault", "cert")),
    ("filesystem", ("file", "files", "path", "directory", "dir", "filesystem",
                    "fs", "disk", "read", "write", "download", "upload")),
    ("command_exec", ("shell", "command", "cmd", "exec", "execute", "run",
                      "terminal", "bash", "sh", "system", "eval", "spawn",
                      "subprocess", "process")),
    ("network", ("http", "fetch", "request", "url", "curl", "proxy", "socket",
                 "connect", "send")),
]

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _classify(tool: dict) -> list:
    existing = tool.get("risk_flags")
    if existing:
        return sorted(set(existing))
    name = str(tool.get("name", "")).lower()
    desc = str(tool.get("description", "")).lower()
    # name tokens are authoritative; description only supports
    name_tokens = set(_TOKEN_RE.findall(name))
    all_tokens = name_tokens | set(_TOKEN_RE.findall(desc))
    flags = set()
    for flag, kws in _CLASSIFY:
        kws = set(kws)
        # a hit in the tool NAME is strong; a hit only in description is weaker
        if name_tokens & kws:
            flags.add(flag)
        elif all_tokens & kws and flag in ("secrets", "db_write"):
            flags.add(flag)
    # command_exec requires an explicit exec-family token in the NAME, so a
    # read/query tool is never mislabelled as arbitrary command execution
    if "command_exec" in flags and not (name_tokens & {
            "shell", "command", "cmd", "exec", "terminal", "powershell",
            "bash", "sh", "system", "eval", "spawn", "subprocess"}):
        flags.discard("command_exec")
    return sorted(flags)


def _dangerous_tools(tools: list) -> list:
    out = []
    for t in tools or []:
        flags = set(_classify(t))
        if flags & _DANGEROUS:
            out.append({"name": t.get("name"), "risk_flags": sorted(flags),
                        "description": t.get("description", "")})
    return out


def _access_step(auth_required, protocol_version, method, canary) -> dict:
    if auth_required is False:
        title, ev = "Unauthenticated enumeration", "Enumeration reported no authentication requirement."
    elif auth_required is True:
        title, ev = "Authentication required", "Discovery reported an authentication requirement; no HTTP status inferred."
    else:
        title, ev = "Authentication state unknown", "Discovery did not establish the authentication requirement."
    demonstrated = bool(canary and canary.get("ok") is True)
    if demonstrated:
        ev += " A supplied canary record reports success for that tool only; other tool access is not established."
    return {"order": 1, "title": title, "technique_id": "T1190",
            "technique_name": "Access assessment (not an exploited vulnerability)",
            "evidence_tier": DEMONSTRATED if demonstrated else OBSERVED,
            "evidence": ev}


def build_safe_proof(server: dict, canary: Optional[dict] = None,
                     authorization: Optional[dict] = None) -> dict:
    """Summarize observations and potential impact from a discovery result. Invokes nothing."""
    tools = server.get("tools") or []
    auth_required = server.get("auth_required")
    protocol_version = server.get("protocol_version")
    method = server.get("verification_method")
    target = server.get("url") or server.get("endpoint") or server.get("host")

    if not server.get("is_mcp") and not server.get("verified"):
        return {
            "target": target, "is_mcp": False, "report_schema": "safe-proof-v2",
            "exposure_verdict": "MCP NOT CONFIRMED", "severity": "None",
            "summary": "No MCP/agentic server verified at this target.",
            "attack_path": [], "blast_radius": {"reachable": []},
            "dangerous_tools": [],
            "mcp_findings": [], "mcp_findings_summary": {"count": 0,
                "worst_severity": "None", "by_category": {}, "categories": []},
            "manifest_fingerprint": None,
            "safety": _safety(False, "declaration", authorization),
        }

    dangerous = _dangerous_tools(tools)
    steps = [_access_step(auth_required, protocol_version, method, canary)]

    # Step 2 — declarations observed during enumeration
    if tools:
        steps.append({
            "order": 2, "title": "Tool capability enumeration",
            "technique_id": "T1518", "technique_name": "Software Discovery",
            "evidence_tier": PROVEN,
            "evidence": f"{len(tools)} tool(s) declared via tools/list, "
                        f"{len(dangerous)} carrying dangerous capability",
        })

    # Steps 3..N — capability and impact are inferred, not executable access
    reachable, inferred_moves = [], {}
    order = len(steps)
    for tool in dangerous:
        for flag in tool["risk_flags"]:
            if flag not in _TECHNIQUE:
                continue
            tid, tname, asset, nexts = _TECHNIQUE[flag]
            order += 1
            steps.append({
                "order": order,
                "title": f"Potential capability: {tool['name']} → {asset}",
                "technique_id": tid, "technique_name": tname,
                "evidence_tier": INFERRED,
                "evidence": (f"tool '{tool['name']}' declared ({flag}); capability inferred "
                             "from metadata. Invocation and authorization were not tested."),
            })
            if asset not in reachable:
                reachable.append(asset)
            for nid, nname in nexts:
                inferred_moves[nid] = nname

    # Final INFERRED consequences (blast-radius expansion) — reasoned, not run
    for nid, nname in inferred_moves.items():
        order += 1
        steps.append({
            "order": order, "title": f"Downstream: {nname}",
            "technique_id": nid, "technique_name": nname,
            "evidence_tier": INFERRED,
            "evidence": "hypothetical consequence if the declared capabilities are executable; not tested",
        })

    verdict, severity = _verdict(server.get("is_mcp") or server.get("verified"),
                                 bool(dangerous), auth_required)
    canary_used = bool(canary and canary.get("ok") is True)
    analysis = _analyze(steps, dangerous, auth_required, canary)
    mcp_findings = mcp_detectors.run_detectors(server)
    finding_summary = mcp_detectors.summarize(mcp_findings)
    severity = max((severity, finding_summary["worst_severity"]), key=lambda v: _SEVERITY_RANK.get(v, 0))
    if mcp_findings:
        verdict = "DECLARATION RISK DETECTED"
    mfp = manifest_fingerprint.fingerprint(server)
    bundle = _evidence_bundle(target, canary)
    graph = build_attack_graph(server, auth_required, canary, bundle)

    return {
        "target": target,
        "report_schema": "safe-proof-v2",
        "is_mcp": True,
        "protocol_version": protocol_version,
        "verification_method": method,
        "auth_required": auth_required,
        "exposure_verdict": verdict,
        "severity": severity,
        "exposure_index": analysis["exposure_index"],
        "confidence": analysis["confidence"],
        "confidence_label": analysis["confidence_label"],
        "attacker_narrative": analysis["attacker_narrative"],
        "exposure_vector": analysis["exposure_vector"],
        "steps_to_impact": analysis["steps_to_impact"],
        "dangerous_tools": dangerous,
        "mcp_findings": mcp_findings,
        "mcp_findings_summary": finding_summary,
        "manifest_fingerprint": mfp,
        "manifest_fingerprint_schema": manifest_fingerprint.SNAPSHOT_SCHEMA,
        "manifest_snapshot_schema": manifest_fingerprint.SNAPSHOT_SCHEMA,
        "manifest_snapshot": manifest_fingerprint.snapshot_for_storage(server),
        "tool_count": len(tools),
        "attack_path": steps,
        "blast_radius": {"reachable": reachable, "evidence_level": INFERRED, "scope": "potential impact; not verified access"},
        "graph": graph,
        "evidence_bundle": bundle,
        "safety": _safety(canary_used,
                          "canary-lab" if canary is not None and not canary.get("refused") else "declaration",
                          authorization, canary),
        "summary": _summary(verdict, severity, dangerous, auth_required, target),
    }


def _verdict(is_mcp, has_dangerous, auth_required) -> tuple:
    if not is_mcp:
        return "MCP NOT CONFIRMED", "None"
    if has_dangerous:
        return "DECLARED SENSITIVE CAPABILITIES", "Critical" if auth_required is False else "High"
    if auth_required is None:
        return "AUTHENTICATION UNKNOWN", "Medium"
    if auth_required is False:
        return "UNAUTHENTICATED ENUMERATION", "Medium"
    return "NO FLAGGED DECLARATIONS", "Low"


def _safety(canary_used, method, authorization, canary=None) -> dict:
    # A report generator cannot attest to side effects of an external invocation.
    supplied = (canary or {}).get("safety") or {}
    passive = canary is None or (canary or {}).get("refused") is True
    out = {key: False if passive else supplied.get(key) if isinstance(supplied.get(key), bool) else None
           for key in ("production_data_accessed", "destructive_action_performed", "dangerous_tool_invoked")}
    out.update(verification_method=method, canary_invoked=(canary or {}).get("invoked", True if canary_used else False if passive else None),
               canary_tool=(canary or {}).get("tool"), authorization=authorization,
               scope="reported scan activity only; unknown values are not safety attestations")
    return out


def _summary(verdict, severity, dangerous, auth_required, target) -> str:
    return (f"{verdict} ({severity}) at {target}: {len(dangerous)} declaration(s) classified "
            "as sensitive. Overall severity includes detector findings. Declarations do not "
            "prove executable access, backend behavior, or safety of unclassified tools.")


def worst_severity(proofs: list) -> str:
    return max((p.get("severity", "None") for p in proofs),
               key=lambda s: _SEVERITY_RANK.get(s, 0), default="None")


# --- Executable Evidence layer: run-level evidence + a branching graph ------

_TONE_OF = {"command_exec": "crit", "secrets": "high", "db_write": "high",
            "filesystem": "med", "network": "low"}
_NOT_DONE = ["No production files accessed", "No destructive command executed"]


def _evidence_bundle(target: str, canary: Optional[dict]) -> dict:
    record = redaction.redact(copy.deepcopy(canary)) if canary is not None else None
    request = (record or {}).get("request")
    result = (record or {}).get("result", (record or {}).get("marker"))
    return {"schema": "canary-evidence-v2", "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_fingerprint": "sha256:" + hashlib.sha256((target or "").encode()).hexdigest(),
            "canary_id": (record or {}).get("marker"),
            "canary_action": json.dumps(request, ensure_ascii=False, sort_keys=True) if request else None,
            "canary_result": result, "canary_record": record,
            "status": "NOT_EXECUTED" if canary is None else "REFUSED" if canary.get("refused") is True
                      else "SUCCEEDED" if canary.get("ok") is True else "FAILED"}


def build_attack_graph(server: dict, auth_required, canary: Optional[dict],
                       bundle: dict) -> dict:
    """A real branching graph: spine → enumeration → each capability → impact →
    downstream. Every node carries auditable evidence."""
    unauth = auth_required is False
    nodes, edges = [], []

    def add(nid, kind, label, tone, ev, **extra):
        ev = dict(ev)
        ev.setdefault("notDone", ["Report generation invoked no tools; supplied canary outcome is recorded separately"])
        ev["timestamp"] = bundle["timestamp"]
        ev["target_fingerprint"] = bundle["target_fingerprint"]
        nodes.append({"id": nid, "kind": kind, "label": label, "tone": tone,
                      "evidence": ev, **extra})

    def link(a, b, cls):
        edges.append({"from": a, "to": b, "cls": cls})

    target = server.get("url") or server.get("host") or "target"
    proto = server.get("protocol_version")
    method = server.get("verification_method")

    add("target", "access", target, "signal",
        {"verdict": "Reachable", "disc": "endpoint reachable"})
    add("mcp", "agent", "MCP server", "crit" if unauth else "high",
        {"verdict": "MCP verified", "tier": "OBSERVED",
         "disc": f"server/{method} → protocolVersions:[{proto}]",
         "reach": "handshake completed", "verify": "protocol negotiated"},
        tier="OBSERVED", sub=proto)
    link("target", "mcp", "spine")

    access = _access_step(auth_required, proto, method, canary)
    add("unauth", "step", access["title"], "high" if unauth else "low",
        {"verdict": access["title"], "disc": access["evidence"],
         "verify": "See supplied canary record; no dangerous capability verification",
         "canary": bundle["canary_id"], "action": bundle["canary_action"],
         "result": bundle["canary_result"], "tier": access["evidence_tier"]},
        tid="T1190", tier=access["evidence_tier"])
    link("mcp", "unauth", "spine")

    tools = server.get("tools") or []
    add("enum", "step", "Tool enumeration", "crit",
        {"verdict": "Tools enumerated", "tier": "OBSERVED",
         "disc": f"tools/list → {len(tools)} tools",
         "reach": "declared capabilities read", "verify": "declaration parsed"},
        tid="T1518", tier="OBSERVED")
    link("unauth", "enum", "spine")

    for i, t in enumerate(tools):
        flags = _classify(t)
        danger = bool(set(flags) & _DANGEROUS)
        top = next((f for f in ("command_exec", "secrets", "db_write",
                                "filesystem", "network") if f in flags), "low")
        cid = f"cap{i}"
        add(cid, "cap", t.get("name", "tool"), _TONE_OF.get(top, "low"),
            {"verdict": "Sensitive capability inferred" if danger else "Unclassified tool; safety unknown",
             "disc": f"declared in tools/list as '{t.get('name')}'",
             "reach": "Tool invocation and authorization not tested",
             "verify": "Declared metadata only; no behavioral verification",
             "tier": ("INFERRED" if danger else "OBSERVED")},
            danger=danger, capKey=cid)
        link("enum", cid, "attack" if danger else "tool")
        if not danger:
            continue
        for f in flags:
            if f not in _TECHNIQUE:
                continue
            tid, tname, asset, nexts = _TECHNIQUE[f]
            iid = f"imp{i}"
            add(iid, "impact", asset, "crit",
                {"verdict": f"Potential impact: {asset}", "tier": "INFERRED",
                 "disc": f"'{t.get('name')}' → {asset}",
                 "reach": "hypothesis conditional on executable capability",
                 "verify": "not executed (safe)"},
                tid=tid, tier="INFERRED", capKey=cid)
            link(cid, iid, "attack")
            for j, (nid, nname) in enumerate(nexts[:2]):
                did = f"dn{i}_{j}"
                add(did, "down", nname, "mist",
                    {"verdict": "Inferred next move", "tier": "INFERRED",
                     "disc": "reasoned from declared capabilities; not established",
                     "reach": "attacker's logical progression",
                     "verify": "not executed — reasoning only"},
                    tid=nid, tier="INFERRED", capKey=cid)
                link(iid, did, "infer")
            break

    # Hash content, not topology. This is an integrity checksum, not a signature.
    canonical = {"schema": "safe-proof-evidence-v2", "server": server,
                 "canary": bundle.get("canary_record"), "nodes": nodes, "edges": edges}
    # Collection time is excluded so identical evidence has a stable checksum.
    canonical = copy.deepcopy(canonical)
    for node in canonical["nodes"]:
        node["evidence"].pop("timestamp", None)
    ehash = "sha256:" + hashlib.sha256(json.dumps(canonical, sort_keys=True,
               ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    for n in nodes:
        n["evidence"]["evidence_hash"] = ehash
    return {"nodes": nodes, "edges": edges, "evidence_hash": ehash,
            "hash_schema": "safe-proof-evidence-v2", "hash_kind": "content checksum; not a digital signature"}


# --- creative layer: one comparable number, an executive story, a vector ---

_CAP_RANK = ["command_exec", "secrets", "db_write", "filesystem", "network"]
_CAP_WEIGHT = {"command_exec": 30, "secrets": 25, "db_write": 22,
               "filesystem": 14, "network": 8}
_CAP_CODE = {"command_exec": "CMD", "secrets": "SEC", "db_write": "DB",
             "filesystem": "FS", "network": "NET"}
_CAP_PHRASE = {
    "command_exec": "arbitrary command execution on the host",
    "secrets": "access to stored credentials",
    "db_write": "read/write control of the database",
    "filesystem": "read access to the host filesystem",
    "network": "a pivot into the internal network",
}


def _all_flags(dangerous: list) -> list:
    seen = []
    for t in dangerous:
        for f in t.get("risk_flags", []):
            if f not in seen:
                seen.append(f)
    return [c for c in _CAP_RANK if c in seen]


def _analyze(steps, dangerous, auth_required, canary) -> dict:
    flags = _all_flags(dangerous)
    unauth = auth_required is False

    # Exposure index 0-100
    access = 40 if unauth else (12 if auth_required else 22)
    cap = min(sum(_CAP_WEIGHT.get(f, 0) for f in flags), 55)
    demo = 5 if (canary and canary.get("ok")) else 0
    index = min(100, access + cap + demo)

    # Confidence from strongest evidence present
    tiers = {s["evidence_tier"] for s in steps}
    if DEMONSTRATED in tiers:
        confidence, clabel = 0.98, "Canary demonstrated (heuristic)"
    elif PROVEN in tiers and unauth:
        confidence, clabel = 0.95, "Observed (heuristic)"
    elif PROVEN in tiers:
        confidence, clabel = 0.8, "Observed (heuristic)"
    else:
        confidence, clabel = 0.6, "Inferred"

    top = flags[0] if flags else None
    # steps to the first proven dangerous capability
    danger_tids = {"T1059", "T1565", "T1552", "T1005"}
    k = next((s["order"] for s in steps if s["technique_id"] in danger_tids), None)

    narrative = ("Declared capabilities suggest potential impact if callable. "
                 "Neither dangerous invocation nor downstream impact was tested." if flags else
                 "No sensitive capability classified from the declarations. This does not establish that the tools are safe.")

    # Agentic Exposure Vector (comparable fingerprint, CVSS-style)
    br = ("H" if len({_CAP_PHRASE[f] for f in flags}) >= 3
          else "M" if len(flags) >= 1 else "L")
    pr = ("D" if (canary and canary.get("ok")) else
          "P" if (PROVEN in tiers) else "I")
    vector = (f"AEV:1.0/AC:N/AU:{'N' if unauth else 'R' if auth_required is True else 'U'}/"
              f"CAP:{_CAP_CODE.get(top, 'NONE')}/BR:{br}/PR:{pr}")

    return {
        "exposure_index": index,
        "confidence": confidence,
        "confidence_label": clabel,
        "attacker_narrative": narrative,
        "exposure_vector": vector,
        "steps_to_impact": None,
    }
