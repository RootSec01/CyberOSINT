"""MCP threat detectors — the modern MCP vulnerability class, reported as
DEFENSIBLE, evidence-graded findings (not over-claimed vulnerabilities).

Given a discovery result (server metadata + declared tools + input schemas), this
module reasons about MCP-specific weaknesses a port/CVE scanner never sees. It is
PURE and PASSIVE: it inspects declarations already gathered by mcp_protocol; it
never calls a tool, never sends a payload, never touches production data.

Every finding is graded so a reviewer, a CISO or a judge can trust exactly what
was and was not established — the language never claims more than the evidence:

  evidence_level:
    OBSERVED      a protocol/metadata fact we saw directly (tool advertised, no
                  auth challenge, an injection string present, a literal secret).
    INFERRED      reasoned from schema/description (capability implied; a path
                  argument unconstrained by schema) — NOT confirmed behaviour.
    DEMONSTRATED  a safe read-only canary ran in an authorized lab (loopback).
    VERIFIED      a vulnerability confirmed safely & methodically — reserved; the
                  external, non-executing path never reaches this level.
  verification_status: always NOT_EXECUTED here (no dangerous tool is invoked).
  confidence: 0..1, per finding.

Detector categories (slug → defensible title), each mapped to MITRE ATT&CK and
OWASP LLM Top 10:

  rce               "Exposed Command-Execution Capability"           (T1059 / LLM01)
  auth_bypass       "Unauthenticated Sensitive Capability Exposure"  (T1190 / LLM08)
  path_traversal    "Potential Unconstrained Filesystem Path"        (T1083 / LLM06)
  secrets_leakage   "Secrets / Credential Exposure"                  (T1552 / LLM06)
  prompt_injection  "Prompt-Injection Markers in Declaration"        (LLM01)
  tool_poisoning    "Deceptive or Hidden Tool Declaration"           (T1036 / LLM09)
"""

from __future__ import annotations

import re
import hashlib
import json
from typing import Any, Dict, List, Optional

from secret_signals import contains_secret_shape

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}
EVIDENCE_LEVELS = ("OBSERVED", "INFERRED", "DEMONSTRATED", "VERIFIED")

# --- text signals -----------------------------------------------------------

# Model-directed instruction injection (OWASP LLM01). Whole-phrase, case-insensitive.
_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(?:all\s+)?(?:previous|prior|above)",
    r"forget\s+(?:everything|all|previous)",
    r"you\s+are\s+now\b",
    r"\bact\s+as\b",
    r"new\s+instructions?\s*:",
    r"system\s*prompt",
    r"</?\s*system\s*>",
    r"</?\s*important\s*>",
    r"do\s+not\s+(?:tell|inform|mention|reveal)\s+the\s+user",
    r"without\s+(?:telling|informing|notifying)\s+the\s+user",
    r"before\s+(?:using|calling)\s+(?:any\s+)?other\s+tools?",
    r"exfiltrat",
    r"\boverride\b.*\b(?:auth|security|policy|restriction)",
    r"send\s+(?:it|them|the\s+\w+)?\s*to\s+(?:https?://|[\w.-]+@)",
]
_INJECTION_RE = [re.compile(p, re.I | re.S) for p in _INJECTION_PATTERNS]

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_HIDDEN_CHARS_RE = re.compile(r"[​‌‍﻿\U000e0000-\U000e007f]")

# Explicit command/code-execution tokens (strong signal when in the tool NAME).
_EXEC_NAME_TOKENS = {"shell", "command", "cmd", "exec", "execute", "terminal",
                     "powershell", "bash", "sh", "system", "eval", "spawn",
                     "subprocess", "run"}
_DANGER_VERBS = re.compile(
    r"\b(shell|command|execute|exec|eval|spawn|subprocess|rm\s|delete|drop\s+table|"
    r"credential|secret|token|api[_\s-]?key|password|\.env|private\s+key)\b", re.I)
_BENIGN_FIRST = {"get", "list", "show", "read", "status", "health", "ping", "info",
                 "help", "describe", "search", "lookup", "weather", "time", "echo",
                 "hello", "fetch", "summary"}
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _first_token(name: str) -> str:
    m = re.match(r"[a-z0-9]+", str(name).lower())
    return m.group(0) if m else ""


def _tool_text(tool: Dict[str, Any]) -> str:
    parts = [str(tool.get("name", "")), str(tool.get("description", ""))]
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    for pname, pdef in props.items():
        parts.append(str(pname))
        if isinstance(pdef, dict):
            parts.append(str(pdef.get("description", "")))
    return "\n".join(parts)


def _schema_props(tool: Dict[str, Any]) -> Dict[str, Any]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def _finding(fid, category, severity, title, *, finding_type, evidence_level,
             confidence, observed_facts, inference, tool, tid, owasp, rec,
             verification_status="NOT_EXECUTED"):
    return {
        "id": fid,
        "category": category,
        "finding_type": finding_type,
        "severity": severity,
        "title": title,
        "evidence_level": evidence_level,
        "confidence": round(float(confidence), 2),
        "observed_facts": observed_facts,
        "inference": inference,
        "verification_status": verification_status,
        "affected_tool": tool,
        "technique_id": tid,
        "owasp_llm": owasp,
        "recommendation": rec,
        # one-line human summary kept for back-compat / compact UIs
        "evidence": inference or (observed_facts[0] if observed_facts else ""),
    }


# --- individual detectors ---------------------------------------------------

def _detect_rce(tool, flags, unauth, auth_required=None) -> Optional[dict]:
    if "command_exec" not in flags:
        return None
    name = str(tool.get("name", ""))
    desc = str(tool.get("description", ""))
    name_tokens = set(_TOKEN_RE.findall(name.lower()))
    explicit = bool(name_tokens & _EXEC_NAME_TOKENS) or bool(
        re.search(r"\b(shell|command|execute|exec|eval)\b", desc, re.I))
    facts = [f"tool '{name}' advertised via tools/list",
             "capability classified as command execution"]
    if explicit:
        facts.append("name/description explicitly reference shell/command execution")
    if unauth:
        facts.append("no authentication challenge observed before enumeration")
    return _finding(
        "rce", "rce", "Critical" if unauth else "High",
        "Exposed Command-Execution Capability",
        finding_type="exposed_command_execution_capability",
        evidence_level="OBSERVED" if explicit else "INFERRED",
        confidence=0.92 if explicit else 0.70,
        observed_facts=facts,
        inference=("The declaration advertises a command/code-execution capability. "
                   + ("Enumeration succeeded without an authentication challenge. " if unauth
                      else "Enumeration required authentication. " if auth_required is True
                      else "Authentication state is unknown. ")
                   + "Tool invocation and arbitrary execution were NOT tested."),
        tool=name, tid="T1059", owasp="LLM01",
        rec="Remove the command-execution tool from the exposed surface, or gate it "
            "behind strict authorization and an allowlist of non-shell operations.")


def _detect_path_traversal(tool, flags, unauth) -> Optional[dict]:
    if "filesystem" not in flags:
        return None
    props = _schema_props(tool)
    path_params = [n for n in props
                   if re.search(r"path|file|dir|filename|location", str(n), re.I)]
    if not path_params:
        return None
    unconstrained = []
    for n in path_params:
        pdef = props.get(n) or {}
        if not isinstance(pdef, dict) or (not pdef.get("enum") and not pdef.get("pattern")):
            unconstrained.append(n)
    if not unconstrained:
        return None
    name = str(tool.get("name", ""))
    facts = [f"tool '{name}' has a filesystem capability",
             f"path argument(s) {unconstrained} declared with no enum/pattern constraint"]
    if unauth:
        facts.append("no authentication challenge observed before enumeration")
    return _finding(
        "path_traversal", "path_traversal", "High" if unauth else "Medium",
        "Potential Unconstrained Filesystem Path",
        finding_type="potential_unconstrained_path",
        evidence_level="INFERRED", confidence=0.55,
        observed_facts=facts,
        inference="The schema does not constrain the path, so directory traversal "
                  "(e.g. ../) is not prevented at the interface. Backend validation "
                  "may still exist; traversal was NOT confirmed.",
        tool=name, tid="T1083", owasp="LLM06",
        rec="Constrain path arguments to an allowlist or a validated base directory; "
            "reject '..' and absolute paths server-side.")


def _detect_secrets(tool, flags, unauth) -> Optional[dict]:
    name = str(tool.get("name", ""))
    text = _tool_text(tool)
    literal = contains_secret_shape(text)
    if "secrets" not in flags and not literal:
        return None
    facts = []
    if "secrets" in flags:
        facts.append(f"tool '{name}' capability classified as secrets/credential access")
    if literal:
        facts.append("declaration text contains a value matching a secret pattern")
    return _finding(
        "secrets_leakage", "secrets_leakage", "High" if unauth else "Medium",
        "Secrets / Credential Exposure",
        finding_type="secrets_exposure",
        evidence_level="OBSERVED" if literal else "INFERRED",
        confidence=0.90 if literal else 0.70,
        observed_facts=facts,
        inference=("A credential-shaped value appears in the declaration; its validity "
                   "was not validated. Tool invocation was not tested." if literal else
                   "The declaration suggests credential access; no literal credential "
                   "was observed and tool invocation was not tested."),
        tool=name, tid="T1552", owasp="LLM06",
        rec="Do not expose credential-returning tools externally; move secrets to a "
            "vault and scrub secret-shaped values from tool metadata.")


def _detect_prompt_injection(tool, unauth) -> Optional[dict]:
    text = _tool_text(tool)
    name = str(tool.get("name", ""))
    for rx in _INJECTION_RE:
        m = rx.search(text)
        if m:
            frag = m.group(0)[:80]
            return _finding(
                "prompt_injection", "prompt_injection", "High",
                "Prompt-Injection Markers in Declaration",
                finding_type="prompt_injection_markers",
                evidence_level="OBSERVED", confidence=0.85,
                observed_facts=[f"tool '{name}' declaration contains model-directed "
                                f"instruction text: “{frag}…”"],
                inference="Tool metadata carries text that could steer an agent "
                          "(prompt injection). Impact depends on the consuming agent.",
                tool=name, tid="T1059.004", owasp="LLM01",
                rec="Treat tool metadata as untrusted; strip/curate descriptions before "
                    "presenting them to an agent, and pin a trusted tool manifest.")
    return None


def _detect_tool_poisoning(tool, flags) -> Optional[dict]:
    name = str(tool.get("name", ""))
    desc = str(tool.get("description", ""))
    text = _tool_text(tool)
    facts = []
    hidden = False
    if _HIDDEN_CHARS_RE.search(text):
        facts.append("contains hidden zero-width / unicode-tag characters"); hidden = True
    if _HTML_COMMENT_RE.search(desc):
        facts.append("hides content inside an HTML comment"); hidden = True
    mismatch = _first_token(name) in _BENIGN_FIRST and bool(_DANGER_VERBS.search(desc))
    if mismatch:
        facts.append("benign-looking name but description grants a dangerous capability")
    if not facts:
        return None
    return _finding(
        "tool_poisoning", "tool_poisoning", "High",
        "Deceptive or Hidden Tool Declaration",
        finding_type="tool_poisoning",
        evidence_level="OBSERVED" if hidden else "INFERRED",
        confidence=0.80 if hidden else 0.65,
        observed_facts=[f"tool '{name}' " + r for r in facts],
        inference="The declaration is hidden or contradicts the tool's name, a "
                  "hallmark of tool poisoning / rug-pull.",
        tool=name, tid="T1036", owasp="LLM09",
        rec="Reject tools whose metadata is hidden or contradicts their name; require "
            "a reviewed, signed tool manifest before an agent may load them.")


# --- orchestration ----------------------------------------------------------

def run_detectors(server: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run every MCP detector over a discovery result. Returns evidence-graded
    findings sorted by severity (most severe first). Pure/passive."""
    import safe_proof  # lazy: reuse the shared capability classifier, avoid cycle

    tools = server.get("tools") or []
    auth_required = server.get("auth_required")
    unauth = auth_required is False

    findings: List[Dict[str, Any]] = []

    # metadata-level prompt injection (server_info text, not tied to a tool)
    si = server.get("server_info") or {}
    si_text = "\n".join(str(v) for v in si.values()) if isinstance(si, dict) else str(si)
    for rx in _INJECTION_RE:
        if rx.search(si_text):
            findings.append(_finding(
                "prompt_injection:server_info", "prompt_injection", "High",
                "Prompt-Injection Markers in Server Metadata",
                finding_type="prompt_injection_markers",
                evidence_level="OBSERVED", confidence=0.85,
                observed_facts=["server_info advertised by the endpoint contains "
                                "model-directed instruction text"],
                inference="Server-advertised metadata carries text that could steer "
                          "a consuming agent.",
                tool=None, tid="T1059.004", owasp="LLM01",
                rec="Treat server-advertised metadata as untrusted input to any agent."))
            break

    occurrence_counts: Dict[str, int] = {}
    for tool in tools:
        # Identity includes declaration content; list reordering does not change IDs.
        digest = hashlib.sha256(json.dumps(tool, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False).encode("utf-8")).hexdigest()
        occurrence_counts[digest] = occurrence_counts.get(digest, 0) + 1
        occurrence = occurrence_counts[digest]
        flags = set(safe_proof._classify(tool))
        for det in (
            _detect_rce(tool, flags, unauth, auth_required),
            _detect_path_traversal(tool, flags, unauth),
            _detect_secrets(tool, flags, unauth),
            _detect_prompt_injection(tool, unauth),
            _detect_tool_poisoning(tool, flags),
        ):
            if det:
                det["id"] = f"{det['category']}:{digest}:{occurrence}"
                findings.append(det)

    # auth_bypass is a server-level finding: any dangerous capability + no auth
    if unauth:
        dangerous_names = [t.get("name") for t in tools
                           if set(safe_proof._classify(t)) & safe_proof._DANGEROUS]
        if dangerous_names:
            findings.append(_finding(
                "auth_bypass", "auth_bypass", "Critical",
                "Unauthenticated Sensitive Capability Exposure",
                finding_type="unauthenticated_sensitive_capability",
                evidence_level="OBSERVED", confidence=0.98,
                observed_facts=["tools/list succeeded with no credential presented",
                                f"{len(dangerous_names)} sensitive tool(s) advertised: "
                                f"{', '.join(str(n) for n in dangerous_names[:5])}"],
                inference="Sensitive capabilities were advertised during unauthenticated "
                          "enumeration. Tool invocation and its authorization controls "
                          "were not tested; this does not establish an authentication bypass.",
                tool=None, tid="T1190", owasp="LLM08",
                rec="Require authentication on the MCP endpoint before any tool is "
                    "listed or callable; fail closed when no credential is presented."))

    findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 0), f["confidence"]),
                  reverse=True)
    return findings


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compact roll-up for storage/UI: counts by category and evidence level."""
    by_cat: Dict[str, int] = {}
    by_level: Dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
        lvl = f.get("evidence_level", "INFERRED")
        by_level[lvl] = by_level.get(lvl, 0) + 1
    worst = max((f["severity"] for f in findings),
                key=lambda s: SEVERITY_RANK.get(s, 0), default="None")
    return {"count": len(findings), "worst_severity": worst, "by_category": by_cat,
            "by_evidence_level": by_level, "categories": sorted(by_cat),
            "verification": "NOT_EXECUTED"}
