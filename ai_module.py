# ai_module.py — AI severity classification & safe remediation
# -----------------------------------------------------------
# - Uses OpenAI Chat Completions if OPENAI_API_KEY is set and `openai`
#   package is installed.
# - Otherwise falls back to a local, rule-based engine.
# - Always returns defensive guidance and NON-EXECUTABLE pseudo-code.

import os
import json
from typing import Dict, List, Any, Optional

LLM_ON = bool(os.getenv("OPENAI_API_KEY"))
MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
TEMP = float(os.getenv("OPENAI_TEMPERATURE", "0.2"))

try:
    from openai import OpenAI  # type: ignore
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore


DEFAULT_PSEUDO_CODE = """# Non-executable pseudo-code for lab-only OSINT verification

target = "<lab_target_ip_or_domain>"

# 1) Discover exposed services (discovery only, no exploitation)
discovered_ports = discover_open_ports(target)
for port in discovered_ports:
    banner = grab_application_banner(target, port)
    cve_candidates = lookup_cves_for_banner(banner)
    if cve_candidates:
        record_service_evidence(
            target=target,
            port=port,
            banner=banner,
            cves=cve_candidates,
            notes="verification only; no exploit payloads"
        )

# 2) Correlate results with local threat intelligence feeds
ti_hits = correlate_with_threat_feeds(
    indicator=target,
    ports=discovered_ports,
    include_public_feeds=True,
    include_darkweb_simulated=False,
)
for hit in ti_hits:
    store_threat_intel_hit(hit)

# 3) Perform lab-safe connectivity checks (only against authorised ranges)
if ip_is_in_authorized_lab_range(target):
    icmp_result = safe_ping(target, max_probes=3)
    tcp_results = safe_tcp_connect_scan(
        target,
        ports=[22, 80, 443, 3389],
        timeout_seconds=2,
    )
    tls_metadata = fetch_tls_certificate_metadata(
        target,
        port=443,
        verify_hostname=False,
    )
    write_lab_verification_log(
        target=target,
        icmp_result=icmp_result,
        tcp_results=tcp_results,
        tls_metadata=tls_metadata,
    )

# 4) Build final report for blue-team / instructor review
build_osint_attack_surface_report(
    target=target,
    discovered_ports=discovered_ports,
    correlated_cves=cve_candidates,
    threat_intel_hits=ti_hits,
    lab_verification_logs=[icmp_result, tcp_results, tls_metadata],
    include_remediation_guidance=True,
)

"""


# ------------------------ Rule-based fallback ---------------------------

def _infer_severity_from_result(result: Dict[str, Any]) -> str:
    risk_level = (result.get("risk_level") or "").lower()
    if risk_level in ("critical", "high"):
        return "High"
    if risk_level in ("medium", "moderate"):
        return "Medium"
    if risk_level in ("low",):
        return "Low"

    cvss = result.get("cvss_max") or result.get("risk_score")
    try:
        cvss_f = float(cvss)
    except Exception:
        cvss_f = 0.0

    if cvss_f >= 8.0:
        return "High"
    if cvss_f >= 5.0:
        return "Medium"
    if cvss_f > 0.0:
        return "Low"
    return "Informational"


def _fallback_recommend(result: Dict[str, Any]) -> Dict[str, Any]:
    sev = _infer_severity_from_result(result)
    vulns = result.get("vulnerabilities") or []
    open_ports = result.get("open_ports") or []

    high_or_crit = [
        v for v in vulns
        if str(v.get("severity", "")).upper() in ("HIGH", "CRITICAL")
        or (v.get("score") or v.get("cvss_score") or 0) >= 7.0
    ]

    summary_parts: List[str] = []
    if high_or_crit:
        summary_parts.append(
            f"{len(high_or_crit)} vulnerability entries are rated HIGH or CRITICAL."
        )
    if open_ports:
        summary_parts.append(
            f"{len(open_ports)} internet-facing services were identified from OSINT data."
        )
    if not summary_parts:
        summary_parts.append(
            "No strong evidence of exploitable issues from OSINT alone; treat as informational and continue monitoring."
        )

    strategy = " ".join(summary_parts)

    remediation: List[str] = [
        "Review all externally reachable services and close or restrict any ports that are not strictly required.",
        "Apply the latest vendor patches for services mapped to known CVEs, prioritising any HIGH/CRITICAL items.",
        "Enforce strong authentication (MFA) on all remote-access services and remove legacy or weak protocols.",
        "Enable host-based and network firewalls to limit access to administration interfaces and management ports.",
        "Continuously monitor logs for repeated login attempts, scanning activity, or unexpected geographic access patterns.",
    ]

    if high_or_crit:
        remediation.append(
            "Create a short-term remediation plan for HIGH/CRITICAL findings and track completion with clear owners and due dates."
        )

    return {
        "severity": sev,
        "strategy": strategy,
        "remediation": remediation,
        "pseudo_code": DEFAULT_PSEUDO_CODE,
    }


# ------------------------ LLM-based recommendations ---------------------

def _llm_recommend(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ask an LLM for structured remediation advice.
    The prompt enforces defensive-only content and non-executable pseudo-code.
    """
    if not (LLM_ON and OpenAI):
        return _fallback_recommend(result)

    client = OpenAI()

    sys_prompt = (
        "You are a defensive security analyst. "
        "You receive OSINT correlation results for an asset and must: "
        "(1) classify overall severity, "
        "(2) summarise key observations, "
        "(3) propose 3-7 concrete remediation steps, and "
        "(4) output NON-EXECUTABLE pseudo-code describing only lab-safe verification "
        "and evidence-collection logic. "
        "Never include exploit payloads, offensive tooling names, or commands that "
        "could be executed directly. Focus purely on verification, logging, and "
        "defensive hardening."
    )

    user_payload = json.dumps(result, indent=2, default=str)
    user_msg = (
        "Here is a JSON document describing OSINT correlation output:\n\n"
        f"{user_payload}\n\n"
        "Respond ONLY as a JSON object with the following keys:\n"
        "  - severity: string (High/Medium/Low/Informational)\n"
        "  - strategy: short paragraph with key observations and focus areas\n"
        "  - remediation: array of 3-7 short actionable defensive steps\n"
        "  - pseudo_code: multi-line string containing NON-EXECUTABLE pseudo-code "
        "for lab-only verification (no exploits or payloads).\n"
    )

    try:
        completion = client.chat.completions.create(
            model=MODEL,
            temperature=TEMP,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_msg},
            ],
        )
        content = completion.choices[0].message.content or ""
    except Exception:
        return _fallback_recommend(result)

    try:
        data = json.loads(content)
    except Exception:
        return _fallback_recommend(result)

    severity = data.get("severity") or _infer_severity_from_result(result)
    strategy = data.get("strategy") or ""
    remediation = data.get("remediation") or []
    pseudo_code = data.get("pseudo_code") or DEFAULT_PSEUDO_CODE

    if not isinstance(remediation, list):
        remediation = [str(remediation)]
    remediation = [str(x) for x in remediation]

    return {
        "severity": str(severity),
        "strategy": str(strategy),
        "remediation": remediation,
        "pseudo_code": str(pseudo_code),
    }


# ------------------------ Public entry points ---------------------------

def recommend_for_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a single correlation result with AI / rule-based recommendations.
    """
    if LLM_ON:
        return _llm_recommend(result)
    return _fallback_recommend(result)


def recommend_for_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich a list of correlation results (batch) with recommendations.
    """
    enriched: List[Dict[str, Any]] = []
    for r in results:
        rec = recommend_for_result(r)
        enriched.append({**r, **rec})
    return enriched
