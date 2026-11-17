from lab.tampering import _altered
from tests.test_cases import REASON, SHELL, STATUS, get, lab, post, shipped, signed_in  # noqa: F401


def test_a_case_report_carries_the_evidence_an_investigator_needs(lab):
    altered, name = _altered(shipped())
    scan = lab.scan(altered)
    reference = scan["cases"][0]
    post(lab.client, lab.headers, f"/api/cases/{reference}/close", reason="mitigated", note=REASON)
    answer = lab.client.get(f"/api/cases/{reference}/report", headers=lab.headers)
    assert answer.status_code == 200
    assert answer.headers["content-disposition"] == f'attachment; filename="{reference}-report.html"'
    page = answer.text
    for part in (reference, scan["scan_reference"], name, "Differs from the published release",
                 "True positive, mitigated", REASON, "Raqeeb opened this case automatically",
                 "python3 -m raqeeb.evidence verify", "Audit chain", "Intact", "Case timeline"):
        assert part in page, part
    assert 'class="added"' in page
    assert get(lab.client, lab.headers, "/api/audit", action="report_exported")["entries"]


def test_a_server_report_lists_findings_and_scans(lab):
    scan = lab.scan([STATUS, SHELL])
    answer = lab.client.get(f"/api/assets/{lab.asset}/report", headers=lab.headers)
    assert answer.status_code == 200 and "files-report.html" in answer.headers["content-disposition"]
    assert "run_shell_command" in answer.text and scan["scan_reference"] in answer.text
    assert "Not requested" in answer.text


def test_reports_stay_inside_the_team(console, lab):
    scan = lab.scan([SHELL])
    other = signed_in(console, "outsider")
    assert console.get(f"/api/cases/{scan['cases'][0]}/report", headers=other).status_code == 404
    assert console.get(f"/api/assets/{lab.asset}/report", headers=other).status_code == 404


def test_every_closure_reason_closes_a_case(lab):
    reasons = get(lab.client, lab.headers, "/api/case-rules")["closure_reasons"]
    assert {"fixed", "mitigated", "benign_positive", "false_positive", "inconclusive", "other"} <= set(reasons)
    scan = lab.scan([SHELL])
    reference = scan["cases"][0]
    for reason in reasons:
        closed = post(lab.client, lab.headers, f"/api/cases/{reference}/close", reason=reason, note=REASON)
        assert closed.status_code == 200 and closed.json()["closure_reason"] == reason
        post(lab.client, lab.headers, f"/api/cases/{reference}/reopen", note=REASON)
