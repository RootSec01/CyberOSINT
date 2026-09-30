"""Drift detection — what changed between two scans of the same asset.

Given the two most recent stored reports for one asset, produce a structured,
human-readable diff. Two report shapes are supported and normalised into a
comparable snapshot first:

  surface  (domain/ip/cidr/asn/org)  -> services, mapped CVEs, overall risk.
  mcp      (Safe Proof)              -> declared dangerous tools + their
                                        capabilities, auth posture, severity.

The engine is pure (no I/O, no DB): main.py loads the two report_json blobs and
hands them here, so it is trivially unit-testable and reused by any surface that
already holds two reports.
"""

from __future__ import annotations

from typing import Any, Dict, List
import manifest_fingerprint as manifest

# Shared severity ordering for surface risk levels and MCP severities.
_RANK = {
    "Critical": 4, "High": 3, "Medium": 2, "Low": 1,
    "None": 0, "Info": 0, "Informational": 0,
}


def _rank(level: Any) -> int:
    return _RANK.get(str(level or "None"), 0)


def _snapshot(report: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a stored report payload into a comparable snapshot."""
    report = report or {}
    proof = report.get("safe_proof")
    if proof or report.get("kind") == "safe_proof":
        proof = proof or report
        tools = proof.get("dangerous_tools") or []
        return {
            "type": "mcp",
            "severity": proof.get("severity"),
            "auth_required": proof.get("auth_required"),
            "tool_count": proof.get("tool_count"),
            "exposure_index": proof.get("exposure_index"),
            "manifest_fingerprint": proof.get("manifest_fingerprint"),
            "manifest_fingerprint_schema": proof.get("manifest_fingerprint_schema"),
            "manifest_snapshot_schema": proof.get("manifest_snapshot_schema"),
            "manifest_snapshot": proof.get("manifest_snapshot"),
            # tool name -> sorted capability flags
            "dangerous_tools": {
                t.get("name"): sorted(t.get("risk_flags") or [])
                for t in tools if t.get("name")
            },
        }

    services = report.get("services") or []
    vulns = report.get("vulnerabilities") or []
    return {
        "type": "surface",
        "risk_level": (report.get("risk") or {}).get("level"),
        "vulnerability_count": report.get("vulnerability_count"),
        # "port/service" -> service row
        "services": {
            f"{s.get('port')}/{s.get('service')}": s for s in services
        },
        # cve id -> severity label
        "cves": {
            (v.get("cve_id") or v.get("id")): (
                v.get("severity")
                or (v.get("risk") or {}).get("priority_tier")
            )
            for v in vulns if (v.get("cve_id") or v.get("id"))
        },
    }


def _change(kind: str, detail: str, tone: str) -> Dict[str, str]:
    # tone: crit (worse) | warn (notable) | good (improved) | info (neutral)
    return {"kind": kind, "detail": detail, "tone": tone}


def compute_drift(current: Dict[str, Any],
                  previous: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two report payloads (current vs previous). Returns a diff dict.

    Shape: {comparable, type, changes:[{kind,detail,tone}], change_count,
            summary}. When the two scans are of different kinds the result is
            marked not comparable rather than guessed.
    """
    c = _snapshot(current)
    p = _snapshot(previous)

    if c["type"] != p["type"]:
        return {"comparable": False, "type": None,
                "reason": f"scan types differ ({p['type']} -> {c['type']})",
                "changes": [], "change_count": 0,
                "summary": "not comparable: scan type changed"}

    changes: List[Dict[str, str]] = []
    comparison_limits: List[str] = []
    manifest_comparison = None

    if c["type"] == "surface":
        cs, ps = set(c["services"]), set(p["services"])
        for k in sorted(cs - ps):
            changes.append(_change("service_appeared", k, "warn"))
        for k in sorted(ps - cs):
            changes.append(_change("service_disappeared", k, "info"))

        cc, pc = set(c["cves"]), set(p["cves"])
        for k in sorted(cc - pc):
            changes.append(_change("cve_appeared", k, "crit"))
        for k in sorted(pc - cc):
            changes.append(_change("cve_resolved", k, "good"))

        if c["risk_level"] != p["risk_level"]:
            worse = _rank(c["risk_level"]) > _rank(p["risk_level"])
            changes.append(_change(
                "risk_changed",
                f"{p['risk_level'] or 'None'} \u2192 {c['risk_level'] or 'None'}",
                "crit" if worse else "good"))

    else:  # mcp
        ct, pt = set(c["dangerous_tools"]), set(p["dangerous_tools"])
        for k in sorted(ct - pt):
            changes.append(_change("tool_appeared", k, "crit"))
        for k in sorted(pt - ct):
            changes.append(_change("tool_disappeared", k, "good"))
        for k in sorted(ct & pt):
            if c["dangerous_tools"][k] != p["dangerous_tools"][k]:
                changes.append(_change(
                    "tool_capability_changed",
                    f"{k}: {p['dangerous_tools'][k]} \u2192 "
                    f"{c['dangerous_tools'][k]}", "warn"))

        if c["auth_required"] != p["auth_required"]:
            # auth_required going False (or None) is worse than True
            worse = (c["auth_required"] is False) and (p["auth_required"] is not False)
            changes.append(_change(
                "auth_changed",
                f"auth_required {p['auth_required']} \u2192 {c['auth_required']}",
                manifest.auth_change_tone(p["auth_required"], c["auth_required"])))

        if c["severity"] != p["severity"]:
            worse = _rank(c["severity"]) > _rank(p["severity"])
            changes.append(_change(
                "severity_changed",
                f"{p['severity'] or 'None'} \u2192 {c['severity'] or 'None'}",
                "crit" if worse else "good"))

        # Compare versioned, privacy-safe declaration snapshots when both exist.
        cfp, pfp = c.get("manifest_fingerprint"), p.get("manifest_fingerprint")
        cs, ps = c.get("manifest_snapshot"), p.get("manifest_snapshot")
        valid_snapshots = (isinstance(cs, dict) and isinstance(ps, dict) and
                           c.get("manifest_snapshot_schema") == manifest.SNAPSHOT_SCHEMA and
                           p.get("manifest_snapshot_schema") == manifest.SNAPSHOT_SCHEMA)
        if valid_snapshots:
            manifest_comparison = "typed"
            for change in manifest.diff(cs, ps)["changes"]:
                if change["kind"] == "authentication_changed":
                    continue  # already included as auth_changed above
                changes.append(change)
            if cfp and pfp and cfp != pfp and cs == ps:
                changes.append(_change("unclassified_manifest_change",
                    "Fingerprint changed, but stored redacted metadata has no typed difference", "warn"))
        else:
            manifest_comparison = "fingerprint_only" if cfp and pfp else "unavailable"
            comparison_limits.append(
                "Stored declaration snapshot missing or incompatible; detailed manifest changes unavailable.")
        same_fp_schema = c.get("manifest_fingerprint_schema") == p.get("manifest_fingerprint_schema")
        if cfp and pfp and not same_fp_schema:
            changes.append(_change("manifest_version_changed",
                "Fingerprint algorithm changed; old and new hash values are not comparable", "warn"))
            comparison_limits.append("Old and new fingerprint versions differ; comparison by raw hashes is unavailable.")
        elif cfp and pfp and cfp != pfp:
            short = f"{pfp.split(':')[-1][:8]} → {cfp.split(':')[-1][:8]}"
            changes.append(_change("manifest_fingerprint_changed", short, "warn"))
        elif bool(cfp) != bool(pfp):
            changes.append(_change("manifest_visibility_changed",
                "Manifest fingerprint became available" if cfp else "Manifest fingerprint no longer available", "warn"))

    return {
        "comparable": True,
        "type": c["type"],
        "changes": changes,
        "change_count": len(changes),
        "summary": (_summarise(changes) if changes else
                    "No tracked changes; manifest detail unavailable." if comparison_limits else
                    "No changes since the previous scan."),
        "manifest_comparison": manifest_comparison,
        "comparison_limits": comparison_limits,
    }


def _summarise(changes: List[Dict[str, str]]) -> str:
    if not changes:
        return "No changes since the previous scan."
    counts: Dict[str, int] = {}
    for ch in changes:
        counts[ch["kind"]] = counts.get(ch["kind"], 0) + 1
    label = {
        "service_appeared": "new service(s)",
        "service_disappeared": "service(s) removed",
        "cve_appeared": "new CVE(s)",
        "cve_resolved": "CVE(s) resolved",
        "risk_changed": "risk level change",
        "tool_appeared": "new dangerous tool(s)",
        "tool_disappeared": "dangerous tool(s) removed",
        "tool_capability_changed": "capability change(s)",
        "auth_changed": "auth posture change",
        "severity_changed": "severity change",
        "manifest_fingerprint_changed": "manifest fingerprint change",
        "manifest_visibility_changed": "manifest evidence coverage change",
        "manifest_version_changed": "fingerprint version change",
        "server_info_changed": "server metadata change(s)",
        "description_changed": "tool description change(s)",
        "schema_changed": "input schema change(s)",
        "output_schema_changed": "output schema change(s)",
        "annotations_changed": "annotation change(s)",
        "tool_metadata_changed": "tool metadata change(s)",
        "protocol_changed": "protocol change",
        "unclassified_manifest_change": "unclassified manifest change",
    }
    parts = [f"{n} {label.get(k, k)}" for k, n in counts.items()]
    return ", ".join(parts)
