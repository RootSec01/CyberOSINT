"""Offline tests for EWRS v2: dead-MCP fixed, age no longer inflates, KEV->P0."""
import risk_scoring_v2 as rs


def _no_kev(monkeypatch):
    monkeypatch.setattr(rs, "is_known_exploited", lambda cid: False)


def test_kev_forces_p0(monkeypatch):
    monkeypatch.setattr(rs, "is_known_exploited", lambda cid: True)
    b = rs.score_vulnerability("CVE-2024-1", 5.0)
    assert b.known_exploited is True
    assert b.priority_tier == "P0-Critical"
    assert b.ewrs >= 9.0
    assert any("KEV" in r for r in b.reasons)


def test_non_kev_critical_is_p1(monkeypatch):
    _no_kev(monkeypatch)
    b = rs.score_vulnerability("CVE-2024-2", 9.5)
    assert b.priority_tier == "P1-High"
    assert b.ewrs == 9.5


def test_medium_and_low(monkeypatch):
    _no_kev(monkeypatch)
    assert rs.score_vulnerability("c", 7.0).priority_tier == "P2-Medium"
    assert rs.score_vulnerability("c", 4.0).priority_tier == "P3-Low"


def test_old_cve_not_inflated(monkeypatch):
    """The removed age bug: publication date must not change the score."""
    _no_kev(monkeypatch)
    old = rs.score_vulnerability("c", 5.0, published_date="2015-01-01")
    new = rs.score_vulnerability("c", 5.0, published_date="2024-01-01")
    assert old.ewrs == new.ewrs  # was 1.5pts higher for the old one before


def test_dead_mcp_component_now_live(monkeypatch):
    """Capability flags used to be dropped by score_findings; now they escalate."""
    _no_kev(monkeypatch)
    findings = [
        {"cve_id": "c1", "score": 4.0},  # low, no capability
        {"cve_id": "c2", "score": 4.0, "risk_flags": ["command_exec"],
         "auth_required": False},        # dangerous, unauth
    ]
    scored = rs.score_findings(findings)
    tiers = {f["cve_id"]: f["risk"]["priority_tier"] for f in scored}
    assert tiers["c2"] == "P0-Critical"      # capability now counts
    assert tiers["c1"] == "P3-Low"
    assert scored[0]["cve_id"] == "c2"       # sorted P0 first


def test_capability_score_is_separate():
    assert rs.score_capability_exposure(False, ["command_exec"]) == 10.0
    assert rs.score_capability_exposure(True, ["network"]) == 1.75
    assert rs.score_capability_exposure(None, []) == 1.0


def test_reasons_are_present(monkeypatch):
    _no_kev(monkeypatch)
    b = rs.score_vulnerability("c", 9.2, mcp_risk_flags=["db_write"], auth_required=True)
    assert b.reasons and isinstance(b.reasons, list)
