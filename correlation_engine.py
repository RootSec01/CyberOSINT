# correlation_engine.py
from __future__ import annotations

import json
import os
from glob import glob
from typing import Dict, Any, List, Optional

from cve_lookup import query_cves_for_service, assess_service


def _load_json(path: str) -> Any:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None


def _load_first_matching(pattern: str) -> Optional[Any]:
    matches = sorted(glob(pattern))
    for p in matches:
        data = _load_json(p)
        if data is not None:
            return data
    return None


def _normalize_shodan_services(shodan_data: Any) -> List[Dict[str, Any]]:
    """
    Normalize Shodan host data into a list of services: port, service, version.
    Expects either a single host dict or a dict with a 'matches' list.
    """
    services: List[Dict[str, Any]] = []
    if not shodan_data:
        return services

    if isinstance(shodan_data, dict) and shodan_data.get("data"):
        records = shodan_data.get("data") or []
    elif isinstance(shodan_data, dict) and shodan_data.get("matches"):
        records = shodan_data.get("matches") or []
    elif isinstance(shodan_data, list):
        records = shodan_data
    else:
        records = []

    for rec in records:
        port = rec.get("port")
        transport = rec.get("transport") or ""
        product = rec.get("product") or rec.get("http", {}).get("server")
        service = product or rec.get("_shodan", {}).get("module") or "unknown"
        version = rec.get("version") or rec.get("ssl", {}).get("version")

        if port is None:
            continue

        services.append(
            {
                "port": int(port),
                "transport": transport,
                "service": str(service),
                "version": str(version) if version else None,
            }
        )

    unique: Dict[tuple, Dict[str, Any]] = {}
    for s in services:
        key = (s["port"], s["service"], s.get("version"))
        unique[key] = s
    return list(unique.values())


def _risk_level_from_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score <= 0.0:
        return None
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def analyze_run(run_dir: str) -> Dict[str, Any]:
    """
    Correlate collected OSINT for a given run directory and compute
    vulnerability findings and overall risk score.
    """
    run_dir = os.path.abspath(run_dir)
    meta = _load_json(os.path.join(run_dir, "meta.json")) or {}
    target_value = meta.get("target_value")

    shodan_data = (
        _load_first_matching(os.path.join(run_dir, "shodan*.json"))
        or {}
    )
    services = _normalize_shodan_services(shodan_data)

    vulnerabilities: List[Dict[str, Any]] = []
    for s in services:
        service = s.get("service") or ""
        version = s.get("version")
        port = s.get("port")
        if not service:
            continue

        # Record the applicability decision on the port itself, so a service
        # that yields no CVEs shows WHY (generic token, missing version, ...).
        assessment = assess_service(service, version)
        s["cve_lookup"] = {
            "queryable": assessment["queryable"],
            "match_type": assessment["match_type"],
            "confidence": assessment["confidence"],
            "reason": assessment["reason"],
        }
        if not assessment["queryable"]:
            continue

        cves = query_cves_for_service(service, version, max_results=5)
        for c in cves:
            score = c.get("score") or c.get("cvss_score")
            severity = c.get("severity")
            vulnerabilities.append(
                {
                    "id": c.get("id") or c.get("cve_id"),
                    "cve_id": c.get("cve_id") or c.get("id"),
                    "port": port,
                    "service": service,
                    "version": version,
                    "score": score,
                    "severity": severity,
                    "description": c.get("description"),
                    "published": c.get("published"),
                    "url": c.get("url"),
                    "source": c.get("source") or "NVD",
                    "match_type": c.get("match_type"),
                    "confidence": c.get("confidence"),
                    "cpe_query": c.get("cpe_query"),
                }
            )

    scores = [
        float(v["score"])
        for v in vulnerabilities
        if v.get("score") is not None
    ]
    cvss_max: Optional[float] = max(scores) if scores else None
    overall_risk_level = _risk_level_from_score(cvss_max)

    result: Dict[str, Any] = {
        "ip": meta.get("resolved_ip") or meta.get("target_value"),
        "target_value": target_value,
        "organization": meta.get("org"),
        "open_ports": services,
        "vulnerabilities": vulnerabilities,
        "cvss_max": cvss_max,
        "risk_score": cvss_max,
        "risk_level": overall_risk_level,
    }

    return result
