"""Redaction tests: identifiers/secrets are stripped, findings are preserved,
and the original object is never mutated."""
import redaction as R


def test_redacts_sensitive_identifiers():
    s = ("host web.corp.internal ip 10.1.2.3 mail admin@corp.com "
         "key sk-ABCDEFGHIJKLMNOPQRSTUVWX "
         "jwt eyJhbGciOiJI.eyJzdWIiOiI.sflKxwRJSM")
    out = R.redact_text(s)
    for leaked in ("web.corp.internal", "10.1.2.3", "admin@corp.com",
                   "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
                   "eyJhbGciOiJI.eyJzdWIiOiI.sflKxwRJSM"):
        assert leaked not in out
    assert "[REDACTED_IP]" in out
    assert "[REDACTED_EMAIL]" in out
    assert "[REDACTED_HOST]" in out


def test_preserves_findings():
    s = "run_shell_command CVE-2024-1234 Critical 3 tools"
    assert R.redact_text(s) == s          # nothing sensitive -> unchanged


def test_redact_context_is_deep_and_nonmutating():
    ctx = {"asset": {"value": "127.0.0.1:9500"},
           "exposure": {"dangerous_tools": ["run_shell_command"]},
           "open_alerts": [{"title": "Exposure increased on 127.0.0.1:9500"}]}
    red = R.redact_context(ctx)
    blob = str(red)
    assert "127.0.0.1" not in blob                 # identifier gone
    assert "run_shell_command" in blob             # finding kept
    assert ctx["asset"]["value"] == "127.0.0.1:9500"  # original intact


def test_redacts_url_and_connection_credentials():
    s = ("db postgres://admin:S3cretPass@db.internal:5432/prod "
         "url https://user:tok12345@api.example.com/x")
    out = R.redact_text(s)
    assert "S3cretPass" not in out and "tok12345" not in out
    assert "[REDACTED_CREDENTIALS]@" in out


def test_entropy_catches_unknown_token():
    tok = "Zx9Q2p7Lk4Rf8Wm1Nb6Vc3Ht5Yj0Dg2Sa"   # unknown format, high entropy
    out = R.redact_text(f"authToken {tok} end")
    assert tok not in out and "[REDACTED_SECRET]" in out


def test_entropy_spares_normal_findings():
    s = "run_shell_command execute_sql CVE-2024-1234 Critical"
    assert R.redact_text(s) == s


def test_nested_json_is_redacted():
    obj = {"a": {"b": ["10.0.0.1", {"c": "admin@corp.com"}]}, "tool": "read_file"}
    blob = str(R.redact(obj))
    assert "10.0.0.1" not in blob and "admin@corp.com" not in blob
    assert "read_file" in blob
