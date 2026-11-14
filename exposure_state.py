"""Per-exposure remediation lifecycle: open -> remediated -> regressed.

Why this module exists
----------------------
The platform tells an operator when exposure *increases*. ``_maybe_raise_alert``
in ``main.py`` raises an :class:`~models_db.Alert` only for drift changes with a
``crit`` tone, and the improvements ``drift.compute_drift`` already computes
("dangerous tool removed", "CVE resolved", tone ``good``) are summarised and then
dropped. The only lifecycle flag in the data is ``Alert.acknowledged``, which
records that an operator read the bell — not that the exposure is gone.

Two questions therefore had no answer anywhere in the database:

* Is this specific exposure closed, and what proved it?
* Has this exposure been here before, or is it genuinely new?

This module answers both. It keeps one row per exposure per asset and moves it
through three states, each transition stamped with the scan that proved it:

===============  ==========================================================
``open``         seen in the most recent scan that observed its surface
``remediated``   previously open, absent from a scan that *did* observe it
``regressed``    remediated earlier, then seen again
===============  ==========================================================

``regressed`` is an *open* state: it means "exposed right now, and this is not
the first time". Anything counting live exposure counts ``open`` + ``regressed``
(:data:`OPEN_STATES`).

Honesty rules
-------------
Most of this file is guards rather than logic, because an absence only proves
remediation when the scan actually looked:

* A scan that was skipped, was unauthorized, or could not confirm an MCP server
  (``is_mcp`` false) reconciles nothing at all. Silence is not closure.
* Exposure kinds are scoped to the surface that produced them, so an OSINT
  surface scan never "remediates" MCP tool exposures and vice versa — the same
  refusal ``drift.compute_drift`` makes when two scans are of different kinds.
* Only exposures that carry a stable identity across scans are tracked:
  dangerous tools by name, anonymous access, and CVEs. Discovered services are
  deliberately excluded — they churn, and a noisy "remediated" is worse than no
  claim at all.

The module is import-light and its decision logic (:func:`next_state`,
:func:`extract_exposures`, :func:`exposure_scope`) is pure, so it can be tested
without a database or a network.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

OPEN = "open"
REMEDIATED = "remediated"
REGRESSED = "regressed"

#: States meaning "exposed right now".
OPEN_STATES: Tuple[str, ...] = (OPEN, REGRESSED)

#: Exposure kinds observable by an MCP safe-proof scan.
MCP_KINDS: Tuple[str, ...] = ("tool", "auth")
#: Exposure kinds observable by an OSINT surface scan.
SURFACE_KINDS: Tuple[str, ...] = ("cve",)

#: Stable key for anonymous reachability of an MCP endpoint.
AUTH_KEY = "auth:anonymous"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _proof_of(payload: Any) -> Optional[Dict[str, Any]]:
    """The safe-proof block of a scan payload, in either of its two shapes."""
    if not isinstance(payload, dict):
        return None
    proof = payload.get("safe_proof")
    if isinstance(proof, dict):
        return proof
    if payload.get("kind") == "safe_proof":
        return payload
    return None


def exposure_scope(payload: Any) -> Optional[Tuple[str, Tuple[str, ...]]]:
    """``(scan_type, kinds)`` when this scan observed its target, else ``None``.

    ``None`` is the refusal to draw any conclusion: the caller must leave every
    stored exposure exactly as it was. It is returned for a skipped or
    unauthorized scan, for an MCP target that could not be confirmed, and for a
    payload that carries no recognisable surface.
    """
    if not isinstance(payload, dict) or payload.get("skipped"):
        return None

    proof = _proof_of(payload)
    if proof is not None:
        # An unconfirmed MCP server says nothing about the tools seen last
        # time: the manifest was never read, so their absence is not evidence.
        if not proof.get("is_mcp"):
            return None
        return "mcp", MCP_KINDS

    if payload.get("services") is not None or payload.get("vulnerabilities") is not None:
        return "surface", SURFACE_KINDS

    return None


def extract_exposures(payload: Any) -> Dict[str, Dict[str, Optional[str]]]:
    """The exposures a scan payload shows as present, keyed by stable identity.

    Keys are ``tool:<name>``, ``auth:anonymous`` or ``cve:<id>`` — chosen so the
    same exposure keeps the same key across scans, which is what makes
    "disappeared" and "came back" distinguishable from "new".
    """
    scope = exposure_scope(payload)
    if scope is None:
        return {}
    scan_type, _kinds = scope
    out: Dict[str, Dict[str, Optional[str]]] = {}

    if scan_type == "mcp":
        proof = _proof_of(payload) or {}
        for tool in proof.get("dangerous_tools") or []:
            name = (tool or {}).get("name")
            if not name:
                continue
            flags = sorted(str(f) for f in (tool.get("risk_flags") or []) if f)
            out[f"tool:{name}"] = {
                "kind": "tool",
                "label": str(name),
                "detail": ", ".join(flags) or None,
            }
        # Authentication posture is an exposure in its own right: the lifecycle
        # demo's "remediated" state still allows anonymous enumeration, and that
        # must stay visible rather than vanish with the dangerous tools.
        if proof.get("auth_required") is False:
            out[AUTH_KEY] = {
                "kind": "auth",
                "label": "Unauthenticated access to the MCP endpoint",
                "detail": None,
            }
        return out

    for vuln in payload.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        cve = vuln.get("cve_id") or vuln.get("id")
        if not cve:
            continue
        severity = vuln.get("severity") or (vuln.get("risk") or {}).get("priority_tier")
        out[f"cve:{cve}"] = {
            "kind": "cve",
            "label": str(cve),
            "detail": str(severity) if severity else None,
        }
    return out


def next_state(previous: Optional[str], present_now: bool) -> Optional[str]:
    """The state an exposure moves to given what the latest scan saw.

    ``previous`` is ``None`` for an exposure never recorded before; the return
    value is then ``None`` when it is still absent — nothing happened, and
    nothing is stored.
    """
    if previous is None:
        return OPEN if present_now else None
    if present_now:
        return REGRESSED if previous == REMEDIATED else previous
    return REMEDIATED if previous in OPEN_STATES else previous


def state_summary(rows: Any) -> Dict[str, int]:
    """Counts per state plus ``exposed_now`` (open + regressed)."""
    counts = {OPEN: 0, REMEDIATED: 0, REGRESSED: 0}
    for row in rows or []:
        state = getattr(row, "state", None)
        if state in counts:
            counts[state] += 1
    counts["exposed_now"] = counts[OPEN] + counts[REGRESSED]
    return counts


def reconcile(db_session: Any, asset: Any, payload: Any,
              *, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Move this asset's exposure rows to match what ``payload`` observed.

    Returns a summary of the transitions. ``reconciled`` is ``False`` when the
    scan was not entitled to draw conclusions, in which case nothing is written.
    """
    from models_db import ExposureState

    empty = {"reconciled": False, "opened": [], "remediated": [], "regressed": []}

    scope = exposure_scope(payload)
    if scope is None:
        empty["reason"] = "scan did not observe this surface"
        return empty
    if getattr(asset, "id", None) is None:
        empty["reason"] = "asset is not persisted"
        return empty

    _scan_type, kinds = scope
    stamp = now or _utcnow()
    current = extract_exposures(payload)
    run_id = str(payload.get("run_id") or "") or None
    fingerprint = (_proof_of(payload) or {}).get("manifest_fingerprint")

    rows = (
        db_session.query(ExposureState)
        .filter(ExposureState.asset_id == asset.id,
                ExposureState.kind.in_(kinds))
        .all()
    )
    by_key = {row.key: row for row in rows}

    opened: list[str] = []
    remediated: list[str] = []
    regressed: list[str] = []

    for key, meta in current.items():
        row = by_key.get(key)
        if row is None:
            db_session.add(ExposureState(
                user_id=asset.user_id, asset_id=asset.id, key=key,
                kind=str(meta["kind"]), label=str(meta["label"]),
                detail=meta.get("detail"), state=OPEN,
                first_seen_at=stamp, last_seen_at=stamp,
                evidence_run_id=run_id, evidence_fingerprint=fingerprint,
            ))
            opened.append(key)
            continue

        target = next_state(row.state, True)
        if target == REGRESSED and row.state != REGRESSED:
            row.times_regressed = (row.times_regressed or 0) + 1
            row.regressed_at = stamp
            regressed.append(key)
        row.state = target or OPEN
        row.label = str(meta["label"])
        row.detail = meta.get("detail")
        row.last_seen_at = stamp
        row.evidence_run_id = run_id
        row.evidence_fingerprint = fingerprint

    for key, row in by_key.items():
        if key in current:
            continue
        target = next_state(row.state, False)
        if target == REMEDIATED and row.state != REMEDIATED:
            row.state = REMEDIATED
            row.remediated_at = stamp
            # The scan that proved closure, not the one that found it.
            row.evidence_run_id = run_id
            row.evidence_fingerprint = fingerprint
            remediated.append(key)

    db_session.commit()

    live = (
        db_session.query(ExposureState)
        .filter(ExposureState.asset_id == asset.id)
        .all()
    )
    summary = state_summary(live)
    return {
        "reconciled": True,
        "opened": sorted(opened),
        "remediated": sorted(remediated),
        "regressed": sorted(regressed),
        "summary": summary,
    }


def exposure_dict(row: Any) -> Dict[str, Any]:
    """Serialise one exposure row for the API."""
    def _iso(value: Any) -> Optional[str]:
        """ISO-8601 that always carries its offset.

        Every timestamp here is written as UTC-aware, but SQLite hands it back
        naive. Serialised without an offset, a browser would read it as local
        time and report an exposure as closed hours before it was.
        """
        if not isinstance(value, datetime):
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "key": row.key,
        "kind": row.kind,
        "label": row.label,
        "detail": row.detail,
        "state": row.state,
        "exposed_now": row.state in OPEN_STATES,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "remediated_at": _iso(row.remediated_at),
        "regressed_at": _iso(row.regressed_at),
        "times_regressed": row.times_regressed or 0,
        "evidence_run_id": row.evidence_run_id,
        "evidence_fingerprint": row.evidence_fingerprint,
    }


#: Display order: what is exposed now comes first, returns before first-timers.
SORT_RANK = {REGRESSED: 0, OPEN: 1, REMEDIATED: 2}


def sort_key(row: Any) -> tuple:
    last_seen = getattr(row, "last_seen_at", None)
    return (SORT_RANK.get(getattr(row, "state", ""), 9),
            -(last_seen.timestamp() if isinstance(last_seen, datetime) else 0))
