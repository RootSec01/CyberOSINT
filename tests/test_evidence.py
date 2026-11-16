import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from raqeeb import db, evidence, paths
from raqeeb import models as m
from tests.test_cases import SHELL, Lab, get, signed_in

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def own_key_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.delenv(evidence.KEY_ENV, raising=False)


@pytest.fixture
def lab(console):
    running = Lab(console, signed_in(console, "rami"))
    yield running
    running.server.shutdown()
    running.server.server_close()


def bundle_of(lab):
    reference = lab.scan([SHELL])["scan_reference"]
    answer = lab.client.get(f"/api/scans/{reference}/evidence", headers=lab.headers)
    assert answer.status_code == 200, answer.text
    assert answer.headers["content-disposition"] == f'attachment; filename="{reference}.evidence.json"'
    return reference, answer.json()


def test_a_scan_exports_signed_evidence_that_verifies(lab):
    reference, bundle = bundle_of(lab)
    key = get(lab.client, lab.headers, "/api/evidence/key")

    assert bundle["format"] == "raqeeb-evidence/1" and bundle["scan"]["reference"] == reference
    assert bundle["issuer"] == key and key["algorithm"] == "Ed25519" and len(key["key_id"]) == 16
    assert [tool["name"] for tool in bundle["declared_tools"]] == ["run_shell_command"]
    assert bundle["findings"] and {f["last_scan"] for f in bundle["findings"]} == {reference}
    assert bundle["provenance"]["verdict"] == "unknown"
    assert evidence.verify(bundle) == (True, f"intact, signed by key {key['key_id']}; "
                                             "compare this key id with the one the operator publishes")
    assert evidence.verify(bundle, key["key_id"].upper())[0]
    trail = get(lab.client, lab.headers, "/api/audit", action="evidence_exported")["entries"]
    assert reference in trail[0]["detail"] and key["key_id"] in trail[0]["detail"]


def test_any_change_after_signing_is_detected(lab):
    _, bundle = bundle_of(lab)
    for change in (lambda b: b["scan"].update(severity="Low"),
                   lambda b: b["findings"].pop(),
                   lambda b: b["declared_tools"][0].update(description="Harmless"),
                   lambda b: b.update(issued_at="2020-01-01T00:00:00+00:00")):
        altered = json.loads(json.dumps(bundle))
        change(altered)
        intact, reason = evidence.verify(altered)
        assert not intact and "changed after signing" in reason


def test_a_bundle_signed_by_another_key_is_not_mistaken_for_ours(lab, monkeypatch):
    _, bundle = bundle_of(lab)
    ours = bundle["issuer"]["key_id"]
    monkeypatch.setenv(evidence.KEY_ENV, base64.b64encode(os.urandom(32)).decode())
    forged = evidence.sign({name: bundle[name] for name in ("scan", "declared_tools", "provenance", "findings", "method")})

    assert evidence.verify(forged)[0] and forged["issuer"]["key_id"] != ours
    intact, reason = evidence.verify(forged, ours)
    assert not intact and "not the expected" in reason
    assert evidence.verify({"format": "other"}) == (False, "not a raqeeb-evidence/1 bundle")
    assert not evidence.verify({"format": "raqeeb-evidence/1"})[0]


def test_the_console_checks_an_uploaded_bundle(lab):
    reference, bundle = bundle_of(lab)
    check = lambda body: lab.client.post("/api/evidence/verify", headers=lab.headers, content=body).json()
    assert check(json.dumps(bundle)) | {"reason": ""} == {"valid": True, "reason": "", "signed_here": True, "scan": reference}
    bundle["scan"]["severity"] = "Low"
    assert (check(json.dumps(bundle))["valid"], check(json.dumps(bundle))["signed_here"]) == (False, False)
    assert lab.client.post("/api/evidence/verify", headers=lab.headers, content="not json").status_code == 422


def test_the_key_is_created_once_private_to_its_owner(lab):
    first = get(lab.client, lab.headers, "/api/evidence/key")
    stored = paths.EVIDENCE_DIR / evidence.KEY_FILE
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert get(lab.client, lab.headers, "/api/evidence/key") == first


def test_a_bundle_verifies_from_the_command_line_without_the_platform(lab, tmp_path):
    reference, bundle = bundle_of(lab)
    saved = tmp_path / "bundle.json"
    saved.write_text(json.dumps(bundle), encoding="utf-8")
    run = lambda *extra: subprocess.run([sys.executable, "-m", "raqeeb.evidence", "verify", str(saved), *extra],
                                        cwd=ROOT, capture_output=True, text=True, timeout=60)
    good = run("--key", bundle["issuer"]["key_id"])
    assert good.returncode == 0 and good.stdout.startswith(f"VALID {reference}: intact")
    assert run("--key", "0" * 16).returncode == 1
    bundle["scan"]["tool_count"] = 99
    saved.write_text(json.dumps(bundle), encoding="utf-8")
    bad = run()
    assert bad.returncode == 1 and bad.stdout.startswith(f"INVALID {reference}")


def test_evidence_is_closed_to_other_teams(console, lab):
    reference, _ = bundle_of(lab)
    other = signed_in(console, "outsider")
    assert console.get(f"/api/scans/{reference}/evidence", headers=other).status_code == 404


def test_the_audit_chain_notices_an_edited_or_removed_entry(lab):
    reference, _ = bundle_of(lab)
    finding = get(lab.client, lab.headers, "/api/findings")["findings"][0]["reference"]
    lab.client.post(f"/api/findings/{finding}/status", headers=lab.headers, data={"status": "acknowledged"})
    before = get(lab.client, lab.headers, "/api/audit/integrity")
    assert before["intact"] and before["sealed"] >= 2 and before["unsealed"] == 0 and len(before["head"]) == 64

    with db.session_scope() as session:
        entry = session.query(m.AuditEntry).filter(m.AuditEntry.action == "finding_status").one()
        edited, entry.decision = entry.id, "risk_accepted"
    after = get(lab.client, lab.headers, "/api/audit/integrity")
    assert (after["intact"], after["broken_at"]) == (False, edited)

    with db.session_scope() as session:
        session.query(m.AuditEntry).filter(m.AuditEntry.id == edited).delete()
    removed = get(lab.client, lab.headers, "/api/audit/integrity")
    assert not removed["intact"] and removed["reason"] == "a sealed entry was removed"
