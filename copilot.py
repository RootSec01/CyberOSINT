"""AI Copilot — a grounded, privacy-aware assistant for one asset.

It answers ONLY from evidence already collected (latest scan, drift, open alerts)
and never invents CVEs, tools, or findings. Three privacy modes, chosen per user
from the UI:

  offline   Everything stays local; the deterministic briefing is returned and
            NO data ever leaves the platform. (default)
  redacted  Findings are sent to a hosted provider AFTER identifiers/secrets are
            stripped (see redaction.py): IPs, hosts, emails, keys, tokens.
  local     Sent to a provider inside the customer's own network (Ollama / vLLM
            via an OpenAI-compatible base_url); data does not leave their perimeter.

Providers: OpenAI and Anthropic now, plus any OpenAI-compatible endpoint via
base_url ('custom'/'local'). Adding another provider is one branch here. If a
provider is unavailable or errors, the local briefing is returned — the feature
never hard-fails, and in redacted mode the fallback stays local (no leak).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

TEMP = float(os.getenv("OPENAI_TEMPERATURE", "0.2"))
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
LOCAL_MODEL = os.getenv("LOCAL_MODEL", "llama3")

try:
    from openai import OpenAI  # type: ignore
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore

try:
    from anthropic import Anthropic  # type: ignore
except Exception:  # pragma: no cover
    Anthropic = None  # type: ignore

import redaction
import secrets_provider

VALID_MODES = {"offline", "redacted", "local"}
VALID_PROVIDERS = {"openai", "anthropic", "custom"}

_SYSTEM = (
    "You are a defensive security copilot embedded in an EASM platform. "
    "Answer ONLY from the provided JSON evidence about a single asset (latest "
    "scan, drift vs the previous scan, open alerts). Never invent CVEs, tools, "
    "ports, or findings not in the evidence. If the evidence does not answer the "
    "question, say so plainly. Be concise and defensive-only; never provide "
    "exploit steps or offensive commands. Prefer concrete, prioritised actions."
)


# ----------------------------- prompt helpers -----------------------------

def suggested_questions(context: Dict[str, Any]) -> List[str]:
    exp = context.get("exposure") or {}
    qs = ["What is my current risk and why?"]
    if (context.get("drift") or {}).get("available"):
        qs.append("What changed since the last scan?")
    if exp.get("type") == "mcp" and exp.get("dangerous_tools"):
        qs.append("Which exposed tools are dangerous and how do I contain them?")
    if exp.get("type") == "surface" and exp.get("cves"):
        qs.append("Which vulnerabilities should I patch first?")
    qs.append("What should I do next?")
    seen, out = set(), []
    for q in qs:
        if q not in seen:
            seen.add(q); out.append(q)
    return out[:4]


def _user_msg(context: Dict[str, Any], question: str) -> str:
    payload = json.dumps(context, indent=2, default=str)
    default_q = ("Give a short executive briefing: current risk, what changed, "
                 "and what to do next.")
    return (f"Evidence for the asset:\n{payload}\n\n"
            f"Question: {question or default_q}\n\n"
            "Answer in short paragraphs and bullet points grounded strictly in "
            "the evidence.")


# --------------------------- deterministic briefing -----------------------

def _exposure_lines(exp: Dict[str, Any]) -> List[str]:
    t = exp.get("type")
    lines: List[str] = []
    if t == "mcp":
        lines.append(f"MCP server severity: {exp.get('severity') or 'unknown'}; "
                     f"authentication required: {exp.get('auth_required')}.")
        dt = exp.get("dangerous_tools") or []
        lines.append(f"{len(dt)} dangerous tool(s) exposed: {', '.join(dt)}."
                     if dt else "No dangerous tools were observed in the latest scan.")
    elif t == "surface":
        lines.append(f"Overall risk: {exp.get('risk_level') or 'unknown'}.")
        svc = exp.get("services") or []
        if svc:
            lines.append(f"{len(svc)} exposed service(s): {', '.join(svc)}.")
        cves = exp.get("cves") or []
        lines.append((f"{len(cves)} correlated CVE(s): {', '.join(cves[:8])}"
                      + (" …" if len(cves) > 8 else "") + ".")
                     if cves else "No CVEs were correlated from OSINT for this asset.")
    else:
        lines.append("No scan evidence is available yet for this asset.")
    return lines


def _actions(context: Dict[str, Any]) -> List[str]:
    exp = context.get("exposure") or {}
    t = exp.get("type")
    acts: List[str] = []
    if t == "mcp":
        if exp.get("auth_required") is False:
            acts.append("Require authentication on the MCP endpoint — it is currently open.")
        if exp.get("dangerous_tools"):
            acts.append("Remove or gate high-impact tools (shell/exec, file, database) behind explicit authorization.")
        acts.append("Restrict network exposure of the MCP server to trusted callers only.")
    elif t == "surface":
        if exp.get("cves"):
            acts.append("Patch services mapped to known CVEs, prioritising HIGH/CRITICAL.")
        if exp.get("services"):
            acts.append("Close or firewall any exposed service that is not strictly required.")
        acts.append("Enforce MFA on remote-access services and disable weak/legacy protocols.")
    acts.append("Keep this asset under monitoring so any change re-triggers a scan and alert.")
    return acts


def _fallback_answer(context: Dict[str, Any], question: str) -> str:
    a = context.get("asset") or {}
    exp = context.get("exposure") or {}
    drift = context.get("drift") or {}
    alerts = context.get("open_alerts") or []
    q = (question or "").lower()

    risk = a.get("risk") or exp.get("severity") or exp.get("risk_level") or "unknown"
    head = f"{a.get('value', 'this asset')} ({a.get('kind', '?')}) — current risk: {risk}."

    want_drift = any(k in q for k in ("chang", "drift", "since", "different"))
    want_fix = any(k in q for k in ("fix", "remed", "should", "do", "harden", "contain", "mitigat"))
    want_risk = any(k in q for k in ("risk", "bad", "sever", "expos", "danger"))
    focused = want_drift or want_fix or want_risk

    parts: List[str] = [head]
    if not focused or want_risk:
        parts.append("Exposure:")
        parts += [f"• {l}" for l in _exposure_lines(exp)]
    if (not focused or want_drift) and drift.get("available"):
        if drift.get("change_count"):
            parts.append(f"Since the previous scan: {drift.get('summary')}.")
            crit = [c for c in (drift.get("changes") or []) if c.get("tone") == "crit"]
            parts += [f"• escalation — {c['kind'].replace('_', ' ')}: {c['detail']}" for c in crit]
        else:
            parts.append("No changes since the previous scan.")
    if not focused and alerts:
        parts.append(f"Open alerts: {len(alerts)} unacknowledged. Most recent — {alerts[0].get('title')}.")
    if not focused or want_fix:
        parts.append("Recommended actions:")
        parts += [f"• {x}" for x in _actions(context)]
    return "\n".join(parts)


# ------------------------------ provider calls ----------------------------

def _provider_call(provider: str, base_url, model, system: str, user_msg: str):
    """Call the selected provider. Returns text, or None to trigger fallback."""
    provider = (provider or "openai").lower()
    try:
        if provider == "anthropic":
            if not (secrets_provider.get_secret("ANTHROPIC_API_KEY") and Anthropic):
                return None
            client = Anthropic()
            msg = client.messages.create(
                model=model or ANTHROPIC_MODEL, max_tokens=900, temperature=TEMP,
                system=system, messages=[{"role": "user", "content": user_msg}])
            text = "".join(getattr(b, "text", "") for b in msg.content
                           if getattr(b, "type", "") == "text")
            return text.strip() or None

        if provider == "custom":   # OpenAI-compatible local endpoint (Ollama/vLLM)
            if not (OpenAI and base_url):
                return None
            client = OpenAI(base_url=base_url, api_key=secrets_provider.get_secret("OPENAI_API_KEY") or "local")
            use_model = model or LOCAL_MODEL
        else:                      # openai (optionally via a custom base_url)
            if not (secrets_provider.get_secret("OPENAI_API_KEY") and OpenAI):
                return None
            client = OpenAI(base_url=base_url) if base_url else OpenAI()
            use_model = model or OPENAI_MODEL

        completion = client.chat.completions.create(
            model=use_model, temperature=TEMP,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user_msg}])
        return (completion.choices[0].message.content or "").strip() or None
    except Exception:
        return None


# -------------------------------- entry point -----------------------------

def answer(context: Dict[str, Any], question: str = "", *,
           mode: str = "offline", provider: str = "openai",
           base_url=None, model=None) -> Dict[str, Any]:
    """Answer a copilot question under the given privacy mode.

    offline  -> deterministic local briefing, nothing leaves the platform.
    redacted -> sensitive identifiers stripped, then sent to the provider.
    local    -> sent as-is to a provider inside the customer's network.
    Any provider miss/error falls back to the local briefing.
    """
    mode = (mode or "offline").lower()

    if mode == "offline":
        return {"answer": _fallback_answer(context, question),
                "model": "offline", "grounded": True, "mode": "offline"}

    send_ctx = redaction.redact_context(context) if mode == "redacted" else context
    # 'local' forces the OpenAI-compatible custom path (customer's own endpoint).
    call_provider = "custom" if mode == "local" else provider
    text = _provider_call(call_provider, base_url, model, _SYSTEM,
                          _user_msg(send_ctx, question))
    if text:
        return {"answer": text, "grounded": True, "mode": mode,
                "provider": call_provider,
                "model": model or (ANTHROPIC_MODEL if call_provider == "anthropic"
                                   else LOCAL_MODEL if call_provider == "custom"
                                   else OPENAI_MODEL)}

    return {"answer": _fallback_answer(context, question),
            "model": "rule-based", "grounded": True, "mode": mode, "fallback": True}


# ==========================================================================
# Platform-wide copilot — answers across the WHOLE portfolio, not one asset.
# Reuses the same three privacy modes, redaction, and provider calls; only the
# grounding context (all assets + all open alerts + recent changes) and the
# deterministic briefing differ.
# ==========================================================================

_PLATFORM_SYSTEM = (
    "You are a defensive security copilot embedded in an EASM platform. "
    "Answer ONLY from the provided JSON evidence about the customer's whole "
    "asset portfolio (assets, their latest exposure, open alerts, recent "
    "changes). Never invent assets, CVEs, tools, ports, or findings not in the "
    "evidence. If the evidence does not answer the question, say so plainly. Be "
    "concise and defensive-only; never provide exploit steps or offensive "
    "commands. Prioritise across the portfolio: name the riskiest assets and the "
    "highest-impact actions first."
)

_RISK_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1,
              "None": 0, "Info": 0, "Informational": 0, "Unauthorized": 0}


def _risk_rank(level) -> int:
    return _RISK_RANK.get(str(level or "None"), 0)


def suggested_questions_platform(context: Dict[str, Any]) -> List[str]:
    pf = context.get("portfolio") or {}
    qs = ["What are my riskiest assets right now?"]
    if pf.get("open_alert_count"):
        qs.append("What open alerts need my attention?")
    if (context.get("recent_changes") or []):
        qs.append("What changed across my assets recently?")
    qs.append("What should my team fix first?")
    seen, out = set(), []
    for q in qs:
        if q not in seen:
            seen.add(q); out.append(q)
    return out[:4]


def _user_msg_platform(context: Dict[str, Any], question: str) -> str:
    payload = json.dumps(context, indent=2, default=str)
    default_q = ("Give a short executive briefing across the whole portfolio: "
                 "overall exposure, the riskiest assets, what changed, and the "
                 "highest-priority actions.")
    return (f"Evidence for the whole asset portfolio:\n{payload}\n\n"
            f"Question: {question or default_q}\n\n"
            "Answer in short paragraphs and bullet points grounded strictly in "
            "the evidence. Prioritise the riskiest assets first.")


def _platform_fallback_answer(context: Dict[str, Any], question: str) -> str:
    pf = context.get("portfolio") or {}
    assets = context.get("assets") or []
    alerts = context.get("open_alerts") or []
    changes = context.get("recent_changes") or []
    q = (question or "").lower()

    want_change = any(k in q for k in ("chang", "drift", "since", "recent", "new"))
    want_alert = any(k in q for k in ("alert", "attention", "urgent", "notif"))
    want_fix = any(k in q for k in ("fix", "remed", "should", "priorit", "first",
                                    "harden", "contain", "mitigat", "do"))
    want_risk = any(k in q for k in ("risk", "riskiest", "worst", "expos",
                                     "danger", "bad", "sever"))
    focused = want_change or want_alert or want_fix or want_risk

    breakdown = pf.get("risk_breakdown") or {}
    bd = ", ".join(f"{k}: {v}" for k, v in breakdown.items() if v) or "no scans yet"
    head = (f"Portfolio: {pf.get('asset_count', 0)} asset(s), "
            f"{pf.get('monitored_count', 0)} monitored — risk breakdown: {bd}. "
            f"{pf.get('open_alert_count', 0)} open alert(s).")

    parts: List[str] = [head]

    # riskiest assets (already sorted by the caller, highest first)
    if not focused or want_risk:
        top = [a for a in assets if _risk_rank(a.get("risk")) > 0][:5]
        if top:
            parts.append("Riskiest assets:")
            for a in top:
                exp = a.get("exposure") or {}
                extra = ""
                if exp.get("type") == "mcp" and exp.get("dangerous_tools"):
                    extra = f" — dangerous tools: {', '.join(exp['dangerous_tools'][:4])}"
                elif exp.get("type") == "surface" and exp.get("cves"):
                    extra = f" — {len(exp['cves'])} CVE(s)"
                parts.append(f"• {a.get('value')} ({a.get('kind')}) — {a.get('risk') or 'unknown'}{extra}")
        else:
            parts.append("No scored assets yet — run a scan to populate risk.")

    if (not focused or want_change) and changes:
        parts.append("Recent changes:")
        for c in changes[:5]:
            parts.append(f"• {c.get('asset')}: {c.get('summary')}")

    if (not focused or want_alert) and alerts:
        parts.append(f"Open alerts ({len(alerts)}):")
        for al in alerts[:5]:
            parts.append(f"• [{al.get('severity')}] {al.get('title')}"
                         + (f" — {al.get('asset')}" if al.get('asset') else ""))

    if not focused or want_fix:
        parts.append("Recommended priorities:")
        acts: List[str] = []
        if any((a.get("exposure") or {}).get("type") == "mcp"
               and (a.get("exposure") or {}).get("auth_required") is False for a in assets):
            acts.append("Require authentication on any open MCP endpoint first — those are directly reachable.")
        if any((a.get("exposure") or {}).get("dangerous_tools") for a in assets):
            acts.append("Gate high-impact MCP tools (shell/exec, file, database) behind explicit authorization.")
        if any((a.get("exposure") or {}).get("cves") for a in assets):
            acts.append("Patch assets with correlated CVEs, prioritising HIGH/CRITICAL.")
        if pf.get("open_alert_count"):
            acts.append("Triage open alerts — each marks an increase in exposure since the last scan.")
        if pf.get("monitored_count", 0) < pf.get("asset_count", 0):
            acts.append("Enable monitoring on unmonitored assets so changes re-trigger scans and alerts.")
        acts.append("Re-scan the riskiest assets to confirm current posture.")
        parts += [f"• {x}" for x in acts]

    if len(parts) == 1:
        parts.append("No portfolio evidence is available yet — add and scan assets to begin.")
    return "\n".join(parts)


def platform_answer(context: Dict[str, Any], question: str = "", *,
                    mode: str = "offline", provider: str = "openai",
                    base_url=None, model=None) -> Dict[str, Any]:
    """Answer a portfolio-wide copilot question under the given privacy mode.

    Same guarantees as answer(): offline stays fully local; redacted strips
    identifiers before the provider call; local uses the customer's own
    endpoint; any provider miss/error falls back to the local briefing.
    """
    mode = (mode or "offline").lower()

    if mode == "offline":
        return {"answer": _platform_fallback_answer(context, question),
                "model": "offline", "grounded": True, "mode": "offline"}

    send_ctx = redaction.redact_context(context) if mode == "redacted" else context
    call_provider = "custom" if mode == "local" else provider
    text = _provider_call(call_provider, base_url, model, _PLATFORM_SYSTEM,
                          _user_msg_platform(send_ctx, question))
    if text:
        return {"answer": text, "grounded": True, "mode": mode,
                "provider": call_provider,
                "model": model or (ANTHROPIC_MODEL if call_provider == "anthropic"
                                   else LOCAL_MODEL if call_provider == "custom"
                                   else OPENAI_MODEL)}

    return {"answer": _platform_fallback_answer(context, question),
            "model": "rule-based", "grounded": True, "mode": mode, "fallback": True}
