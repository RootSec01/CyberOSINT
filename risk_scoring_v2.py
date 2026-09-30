"""Exploit-Weighted Risk Score (EWRS) v2 — two separate domains + priority tier.

The previous model blended four weighted components into one number, which had
three defects:

  * the MCP component (20%) was never fed by score_findings(), so it was dead
    weight — the score silently claimed an agentic dimension it never used;
  * the age component rewarded *old* CVEs (days-since-publication), which is not
    a risk signal — a 2018 CVE is not inherently more dangerous than a 2024 one;
  * capability exposure and CVE severity were mixed into one opaque number.

v2 keeps two scores in their own domains and combines them only at the DECISION
layer as an explicit priority tier with human-readable reasons:

  CVE severity score (0-10) = CVSS, escalated by real-world exploitation (KEV),
      plus a bounded dwell bonus for exposures left unremediated (0 until run
      history is persisted).
  Capability exposure score (0-10) = auth posture + most-privileged reachable
      tool — scored separately for MCP/agentic findings.
  priority_tier(...) = P0/P1/P2/P3 with the reasons that set it.

The CISA KEV catalog is fetched once and cached on disk.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

import requests

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_PATH = Path(__file__).resolve().parent / "evidence" / "kev_cache.json"
_CACHE_TTL_SECONDS = 24 * 3600
_HTTP_TIMEOUT = 10

# Most-privileged reachable tool -> weight on the 0-10 capability scale.
_MCP_TOOL_WEIGHTS = {
    "command_exec": 10.0,
    "secrets": 8.5,
    "db_write": 7.0,
    "filesystem": 5.5,
    "network": 3.5,
}
_DANGEROUS_FLAGS = {"command_exec", "secrets", "db_write"}

PRIORITY_RANK = {"P0-Critical": 0, "P1-High": 1, "P2-Medium": 2, "P3-Low": 3}


@dataclass(frozen=True)
class RiskBreakdown:
    ewrs: float                    # kept name for API/UI compatibility (= cve_score)
    cvss_component: float
    kev_uplift: float
    dwell_bonus: float
    known_exploited: bool
    priority_tier: str
    reasons: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ewrs": self.ewrs,
            "cve_score": self.ewrs,
            "components": {
                "cvss": self.cvss_component,
                "kev_uplift": self.kev_uplift,
                "dwell": self.dwell_bonus,
            },
            "known_exploited": self.known_exploited,
            "priority_tier": self.priority_tier,
            "reasons": self.reasons,
        }


# --------------------------------------------------------------------------
# CISA KEV catalog (cached)
# --------------------------------------------------------------------------

def _load_cache() -> Optional[dict]:
    try:
        with _CACHE_PATH.open("r", encoding="utf-8") as f:
            cached = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if time.time() - cached.get("_fetched_at", 0) > _CACHE_TTL_SECONDS:
        return None
    return cached


def _save_cache(cve_dates: dict) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {"_fetched_at": time.time(), "cves": cve_dates}
        tmp = _CACHE_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(payload, f)
        tmp.replace(_CACHE_PATH)
    except OSError:
        pass


def _fetch_kev_catalog() -> dict:
    try:
        r = requests.get(_KEV_URL, timeout=_HTTP_TIMEOUT)
        if r.status_code != 200:
            return {}
        data = r.json()
    except (requests.RequestException, ValueError):
        return {}
    entries = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if cve_id:
            entries[cve_id] = vuln.get("dateAdded") or ""
    return entries


def _kev_index() -> dict:
    cached = _load_cache()
    if cached is not None:
        return cached.get("cves", {})
    fresh = _fetch_kev_catalog()
    if fresh:
        _save_cache(fresh)
        return fresh
    try:
        with _CACHE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f).get("cves", {})
    except (OSError, json.JSONDecodeError):
        return {}


def is_known_exploited(cve_id: str) -> bool:
    return bool(cve_id) and cve_id.upper() in _kev_index()


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def _cve_score(cvss: float, exploited: bool,
               dwell_days: Optional[int] = None) -> tuple:
    """CVE severity on 0-10, escalated by KEV and (optionally) dwell time."""
    score = cvss
    kev_uplift = 0.0
    if exploited:
        # Confirmed in-the-wild exploitation makes a finding top-priority
        # regardless of base CVSS (the CISA KEV / EPSS thesis).
        score = max(min(cvss + 2.0, 10.0), 9.0)
        kev_uplift = round(score - cvss, 2)
    dwell_bonus = 0.0
    if dwell_days and dwell_days > 0:
        dwell_bonus = round(min(dwell_days / 180.0, 0.5), 2)  # up to +0.5
        score = min(10.0, score + dwell_bonus)
    return round(score, 2), kev_uplift, dwell_bonus


def score_capability_exposure(auth_required: Optional[bool],
                              risk_flags: Optional[list]) -> float:
    """Capability exposure on 0-10 for an MCP/agentic finding (separate domain)."""
    if auth_required is False:
        auth_base = 5.0
    elif auth_required is None:
        auth_base = 1.0
    else:
        auth_base = 0.0
    tool = max((_MCP_TOOL_WEIGHTS.get(f, 0.0) for f in (risk_flags or [])),
               default=0.0)
    return round(min(auth_base + tool * 0.5, 10.0), 2)


def priority_tier(cve_score: float, exploited: bool,
                  capability_flags: Optional[list] = None,
                  auth_required: Optional[bool] = None) -> tuple:
    """Return (tier, reasons). Escalators are explicit, not blended into a number."""
    flags = set(capability_flags or [])
    dangerous = flags & _DANGEROUS_FLAGS
    reasons: list = []

    tier = "P3-Low"
    if cve_score >= 7.0:
        tier = "P2-Medium"
        reasons.append(f"CVSS severity {cve_score}")
    if cve_score >= 9.0:
        tier = "P1-High"

    if dangerous:
        if auth_required is False:
            tier = "P0-Critical"
            reasons.append("unauthenticated dangerous capability: "
                           + ", ".join(sorted(dangerous)))
        else:
            if PRIORITY_RANK[tier] > PRIORITY_RANK["P1-High"]:
                tier = "P1-High"
            reasons.append("dangerous capability (auth required): "
                           + ", ".join(sorted(dangerous)))

    if exploited:
        tier = "P0-Critical"
        reasons.append("CISA KEV: actively exploited in the wild")

    if not reasons:
        reasons.append(f"base severity {cve_score}")
    return tier, reasons


def score_vulnerability(
    cve_id: str,
    cvss_base: float,
    published_date: Optional[str] = None,   # kept for compat; not a risk signal
    mcp_risk_flags: Optional[list] = None,
    auth_required: Optional[bool] = None,
    dwell_days: Optional[int] = None,
) -> RiskBreakdown:
    """Compute the CVE severity score and priority tier for one finding."""
    cvss = max(0.0, min(float(cvss_base or 0.0), 10.0))
    exploited = is_known_exploited(cve_id)
    score, kev_uplift, dwell_bonus = _cve_score(cvss, exploited, dwell_days)
    tier, reasons = priority_tier(score, exploited, mcp_risk_flags, auth_required)
    return RiskBreakdown(
        ewrs=score,
        cvss_component=round(cvss, 2),
        kev_uplift=kev_uplift,
        dwell_bonus=dwell_bonus,
        known_exploited=exploited,
        priority_tier=tier,
        reasons=reasons,
    )


def score_findings(vulnerabilities: list) -> list:
    """Attach a risk breakdown to each finding; sort by priority tier then score."""
    scored = []
    for v in vulnerabilities:
        cve_id = v.get("cve_id") or v.get("id") or ""
        try:
            cvss = float(v.get("score") or v.get("cvss_score") or 0.0)
        except (TypeError, ValueError):
            cvss = 0.0
        breakdown = score_vulnerability(
            cve_id=cve_id,
            cvss_base=cvss,
            published_date=v.get("published"),
            mcp_risk_flags=v.get("risk_flags"),
            auth_required=v.get("auth_required"),
        )
        enriched = dict(v)
        enriched["risk"] = breakdown.as_dict()
        scored.append(enriched)

    scored.sort(key=lambda item: (
        PRIORITY_RANK.get(item["risk"]["priority_tier"], 9),
        -item["risk"]["ewrs"],
    ))
    return scored
