"""Per-exposure remediation lifecycle: open -> remediated -> regressed.

Why this module exists
----------------------
Alerts are escalation-only: ``_maybe_raise_alert`` fires when drift shows a
``crit`` change, and the improvements drift already computes are summarised and
then dropped. ``Alert.acknowledged`` only records that an operator read the bell.
Two questions had no answer in the database:

* Is this specific exposure closed, and what proved it?
* Has this exposure been here before, or is it genuinely new?

This module keeps one row per exposure per asset and moves it through three
states, each transition stamped with the scan and manifest that proved it:

===============  ==========================================================
``open``         seen in the most recent scan that observed its surface
``remediated``   previously open, absent from a scan whose evidence is
                 sufficient to prove the absence
``regressed``    remediated earlier, then seen again (an *open* state)
===============  ==========================================================

It is an extension of the existing monitoring, not a parallel workflow
---------------------------------------------------------------------
* What a scan shows as present is read through :func:`raqeeb.drift.snapshot`,
  the same normalisation drift alerts use, so the two can never disagree.
* Tool identity and redefinition come from the stored ``manifest_snapshot``
  (``raqeeb.manifest_fingerprint``), the same evidence drift compares.
* Regressions are reported through the existing drift alert in ``main.py``;
  this module never raises an alert of its own.

Evidence rules
--------------
Presence is always evidence. Absence is evidence only when the scan could have
seen the exposure, so each kind has its own sufficiency test
(:func:`observe`). When it fails, the stored state is *held*, never closed:

* a skipped, unauthorized or simulated scan, or an unconfirmed MCP server,
  reconciles nothing at all;
* MCP tools close only when ``tools/list`` was read to the last page without an
  error and a manifest fingerprint exists. A server that starts demanding
  authentication before listing tools has not removed them;
* anonymous access closes only when the scan observed ``auth_required: true``;
  an unknown posture proves nothing;
* CVEs close only when the stored list is the complete list. Reports keep the
  top 15 scored CVEs, so a CVE that merely fell out of the top 15 is not fixed;
* an OSINT surface scan never closes MCP exposures, and vice versa.

Identity across scans
---------------------
Keys are ``tool:<name>``, ``auth:anonymous`` and ``cve:<id>``. For tools the
manifest digest of the declaration (everything except the name) is stored too:

* same name, different declaration: the exposure stays the same row and the
  change is recorded (``definition changed``);
* a dangerous tool that disappears while a new one appears with an identical
  declaration is a rename: the row moves to the new key with its history;
* a tool still in the manifest but no longer declaring a dangerous capability
  is remediated with that reason, distinct from a tool that was removed.

The decision logic (:func:`observe`, :func:`next_state`, :func:`match_renames`)
is pure and tested without a database or a network.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from raqeeb import drift, redaction

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

# Why a row is in its current state; shown in the API and the UI.
REASON_OBSERVED = "observed"
REASON_REDEFINED = "definition changed"
REASON_REMOVED = "tool removed from manifest"
REASON_NOT_DANGEROUS = "tool no longer declares a dangerous capability"
REASON_ABSENT_TOOL = "dangerous tool no longer declared"
REASON_AUTH_REQUIRED = "authentication now required"
REASON_CVE_GONE = "CVE no longer reported"


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


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def declaration_digests(proof: Dict[str, Any]) -> Dict[str, str]:
    """Redacted tool name -> digest of its declaration without the name.

    Built from the stored ``manifest_snapshot``, whose fields are already
    per-field digests, so no raw metadata is read or kept here. Several tools
    sharing a name are folded into one digest.
    """
    snapshot = proof.get("manifest_snapshot") or {}
    grouped: Dict[str, List[str]] = {}
    for tool in snapshot.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        body = {k: v for k, v in tool.items() if k != "name"}
        grouped.setdefault(str(tool.get("name", "")), []).append(_canonical(body))
    return {name: "sha256:" + hashlib.sha256("\n".join(sorted(parts)).encode("utf-8")).hexdigest()
            for name, parts in grouped.items()}


@dataclass
class Observation:
    """What one scan entitles us to conclude.

    ``present`` maps key -> metadata for every exposure the scan saw.
    ``can_close`` lists the kinds whose absence this scan proves; any other kind
    in ``kinds`` is held. ``limits`` says, in words, why something was held.
    """
    scan_type: str
    kinds: Tuple[str, ...]
    present: Dict[str, Dict[str, Optional[str]]] = field(default_factory=dict)
    can_close: Tuple[str, ...] = ()
    limits: List[str] = field(default_factory=list)
    fingerprint: Optional[str] = None
    declared_names: Optional[set] = None   # every tool name in the manifest, when known


def observe(payload: Any) -> Optional[Observation]:
    """The observation a scan supports, or ``None`` when it supports nothing.

    ``None`` is the refusal to draw any conclusion: the caller must leave every
    stored exposure exactly as it was.
    """
    if not isinstance(payload, dict) or payload.get("skipped"):
        return None

    proof = _proof_of(payload)
    if proof is not None:
        # An unconfirmed MCP server says nothing about the tools seen last time.
        if not proof.get("is_mcp"):
            return None
        snap = drift.snapshot(payload)
        digests = declaration_digests(proof)
        obs = Observation("mcp", MCP_KINDS, fingerprint=proof.get("manifest_fingerprint"))
        for name, flags in sorted(snap["dangerous_tools"].items()):
            # Column limits are enforced by PostgreSQL (not by SQLite).
            obs.present[f"tool:{name}"[:255]] = {
                "kind": "tool", "label": str(name)[:255],
                "detail": (", ".join(str(f) for f in flags if f) or None),
                "definition": digests.get(redaction.redact_text(str(name))),
            }
        if snap["auth_required"] is False:
            obs.present[AUTH_KEY] = {"kind": "auth", "label": "Unauthenticated access to the MCP endpoint",
                                     "detail": None, "definition": None}

        closable: List[str] = []
        listing = proof.get("tool_listing") or {}
        if listing.get("complete") is True and obs.fingerprint:
            closable.append("tool")
            if proof.get("manifest_snapshot"):
                obs.declared_names = set(digests)
        elif listing.get("complete") is False:
            obs.limits.append("tools/list was not read to the end ("
                              + (listing.get("reason") or "incomplete") + "); missing tools are held, not closed")
        else:
            obs.limits.append("tool listing completeness unknown; missing tools are held, not closed")
        if snap["auth_required"] is True or snap["auth_required"] is False:
            closable.append("auth")
        else:
            obs.limits.append("authentication posture unknown; anonymous access is held, not closed")
        obs.can_close = tuple(closable)
        return obs

    if payload.get("services") is None and payload.get("vulnerabilities") is None:
        return None
    if payload.get("simulation_used"):
        return None   # simulated data proves neither presence nor absence

    snap = drift.snapshot(payload)
    obs = Observation("surface", SURFACE_KINDS)
    for cve, severity in sorted(snap["cves"].items()):
        obs.present[f"cve:{cve}"[:255]] = {"kind": "cve", "label": str(cve)[:255],
                                            "detail": str(severity)[:255] if severity else None,
                                            "definition": None}
    listed = len(payload.get("vulnerabilities") or [])
    total = payload.get("vulnerability_count")
    if isinstance(total, int) and total <= listed and payload.get("sources"):
        obs.can_close = ("cve",)
    elif not payload.get("sources"):
        obs.limits.append("no data source answered; missing CVEs are held, not closed")
    else:
        obs.limits.append(f"report keeps {listed} of {total} CVEs; missing CVEs are held, not closed")
    return obs


def next_state(previous: Optional[str], present_now: bool) -> Optional[str]:
    """The state an exposure moves to given what the latest scan saw.

    ``previous`` is ``None`` for an exposure never recorded before; the return
    value is then ``None`` when it is still absent: nothing is stored.
    """
    if previous is None:
        return OPEN if present_now else None
    if present_now:
        return REGRESSED if previous == REMEDIATED else previous
    return REMEDIATED if previous in OPEN_STATES else previous


def match_renames(missing: Dict[str, Optional[str]], new: Dict[str, Optional[str]]) -> Dict[str, str]:
    """old key -> new key for tools whose declaration is identical but renamed.

    ``missing`` and ``new`` map tool keys to declaration digests. A digest must
    be known and unique on both sides; anything ambiguous is not a rename.
    """
    def unique(side: Dict[str, Optional[str]]) -> Dict[str, str]:
        seen: Dict[str, List[str]] = {}
        for key, digest in side.items():
            if digest:
                seen.setdefault(digest, []).append(key)
        return {digest: keys[0] for digest, keys in seen.items() if len(keys) == 1}

    old_by, new_by = unique(missing), unique(new)
    return {old_by[d]: new_by[d] for d in old_by.keys() & new_by.keys()}


def state_summary(rows: Any) -> Dict[str, int]:
    """Counts per state plus ``exposed_now`` (open + regressed)."""
    counts = {OPEN: 0, REMEDIATED: 0, REGRESSED: 0}
    for row in rows or []:
        state = getattr(row, "state", None)
        if state in counts:
            counts[state] += 1
    counts["exposed_now"] = counts[OPEN] + counts[REGRESSED]
    return counts


def _closure_reason(kind: str, label: str, obs: Observation) -> str:
    if kind == "auth":
        return REASON_AUTH_REQUIRED
    if kind == "cve":
        return REASON_CVE_GONE
    if obs.declared_names is None:
        return REASON_ABSENT_TOOL
    if redaction.redact_text(label) in obs.declared_names:
        return REASON_NOT_DANGEROUS
    return REASON_REMOVED


def reconcile(db_session: Any, asset: Any, payload: Any,
              *, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Move this asset's exposure rows to match what ``payload`` proves.

    Returns the transitions. ``reconciled`` is ``False`` when the scan was not
    entitled to draw conclusions, in which case nothing is written. ``held``
    lists open exposures that were missing but could not be closed.
    """
    from raqeeb.models import ExposureState

    result: Dict[str, Any] = {"reconciled": False, "opened": [], "remediated": [],
                              "regressed": [], "renamed": [], "held": [], "limits": []}
    obs = observe(payload)
    if obs is None:
        result["reason"] = "scan did not observe this surface"
        return result
    if getattr(asset, "id", None) is None:
        result["reason"] = "asset is not persisted"
        return result

    stamp = now or _utcnow()
    run_id = str(payload.get("run_id") or "") or None
    rows = (db_session.query(ExposureState)
            .filter(ExposureState.asset_id == asset.id, ExposureState.kind.in_(obs.kinds))
            .all())
    by_key = {row.key: row for row in rows}

    # Renames first, so a renamed tool is neither "remediated" nor "new". Only a
    # complete listing can show that the old name is really gone.
    missing_open = {k: r.definition_digest for k, r in by_key.items()
                    if r.kind == "tool" and r.state in OPEN_STATES and k not in obs.present
                    and "tool" in obs.can_close}
    new_tools = {k: m.get("definition") for k, m in obs.present.items()
                 if m["kind"] == "tool" and k not in by_key}
    for old_key, new_key in sorted(match_renames(missing_open, new_tools).items()):
        row = by_key.pop(old_key)
        row.key, row.label = new_key, obs.present[new_key]["label"]
        row.evidence_reason = f"renamed from {old_key.split(':', 1)[1]}"[:255]
        by_key[new_key] = row
        result["renamed"].append(f"{old_key} -> {new_key}")

    for key, meta in obs.present.items():
        row = by_key.get(key)
        if row is None:
            db_session.add(ExposureState(
                user_id=asset.user_id, asset_id=asset.id, key=key,
                kind=str(meta["kind"]), label=str(meta["label"]), detail=(meta.get("detail") or None) and meta["detail"][:255],
                state=OPEN, first_seen_at=stamp, last_seen_at=stamp,
                evidence_run_id=run_id, evidence_fingerprint=obs.fingerprint,
                definition_digest=meta.get("definition"), evidence_reason=REASON_OBSERVED,
            ))
            result["opened"].append(key)
            continue
        target = next_state(row.state, True)
        if target == REGRESSED and row.state != REGRESSED:
            row.times_regressed = (row.times_regressed or 0) + 1
            row.regressed_at = stamp
            result["regressed"].append(key)
        definition = meta.get("definition")
        if not (row.evidence_reason or "").startswith("renamed from") or target == REGRESSED:
            row.evidence_reason = REASON_OBSERVED
        if definition and row.definition_digest and definition != row.definition_digest:
            row.evidence_reason = REASON_REDEFINED
        row.state = target or OPEN
        row.label, row.detail = str(meta["label"]), (meta.get("detail") or None) and meta["detail"][:255]
        row.last_seen_at = stamp
        row.evidence_run_id, row.evidence_fingerprint = run_id, obs.fingerprint
        if definition:
            row.definition_digest = definition

    for key, row in by_key.items():
        if key in obs.present or row.state not in OPEN_STATES:
            continue
        if row.kind not in obs.can_close:
            result["held"].append(key)
            continue
        row.state = REMEDIATED
        row.remediated_at = stamp
        # The scan that proved closure, not the one that found it.
        row.evidence_run_id, row.evidence_fingerprint = run_id, obs.fingerprint
        row.evidence_reason = _closure_reason(row.kind, row.label, obs)
        result["remediated"].append(key)

    db_session.commit()
    live = db_session.query(ExposureState).filter(ExposureState.asset_id == asset.id).all()
    for name in ("opened", "remediated", "regressed", "held"):
        result[name] = sorted(result[name])
    result.update(reconciled=True, summary=state_summary(live), limits=list(obs.limits))
    return result


def _iso(value: Any) -> Optional[str]:
    """ISO-8601 that always carries its offset (SQLite hands back naive UTC)."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def exposure_dict(row: Any) -> Dict[str, Any]:
    """Serialise one exposure row for the API."""
    return {
        "id": row.id, "asset_id": row.asset_id, "key": row.key, "kind": row.kind,
        "label": row.label, "detail": row.detail, "state": row.state,
        "exposed_now": row.state in OPEN_STATES,
        "first_seen_at": _iso(row.first_seen_at), "last_seen_at": _iso(row.last_seen_at),
        "remediated_at": _iso(row.remediated_at), "regressed_at": _iso(row.regressed_at),
        "times_regressed": row.times_regressed or 0,
        "evidence_run_id": row.evidence_run_id,
        "evidence_fingerprint": row.evidence_fingerprint,
        "evidence_reason": row.evidence_reason,
        "definition_digest": row.definition_digest,
    }


#: Display order: what is exposed now comes first, returns before first-timers.
SORT_RANK = {REGRESSED: 0, OPEN: 1, REMEDIATED: 2}


def sort_key(row: Any) -> tuple:
    last_seen = getattr(row, "last_seen_at", None)
    return (SORT_RANK.get(getattr(row, "state", ""), 9),
            -(last_seen.timestamp() if isinstance(last_seen, datetime) else 0))
