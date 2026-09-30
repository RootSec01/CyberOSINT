"""Offline unit tests for CPE-based CVE applicability (no network)."""
import cve_lookup as cl


def test_generic_tokens_are_skipped():
    for tok in ["auto", "unknown", "http", "", "tcp", "server"]:
        a = cl.assess_service(tok, "1.2.3")
        assert a["queryable"] is False
        assert a["match_type"] == "skipped-generic"


def test_vercel_without_version_is_skipped():
    # the real false-positive case: keyword engine flagged Next.js CVEs here
    a = cl.assess_service("Vercel", None)
    assert a["queryable"] is False  # 'vercel' is a hosting token, not a CPE product


def test_no_version_is_skipped():
    a = cl.assess_service("nginx", None)
    assert a["queryable"] is False
    assert a["match_type"] == "skipped-no-version"


def test_known_product_with_version_builds_cpe():
    a = cl.assess_service("nginx", "1.18.0")
    assert a["queryable"] is True
    assert a["cpe"] == "cpe:2.3:a:*:nginx:1.18.0:*:*:*:*:*:*:*"
    assert a["match_type"] == "cpe-version"
    assert a["confidence"] == 0.9


def test_apache_alias_maps_to_http_server():
    a = cl.assess_service("Apache httpd", "2.4.49")
    assert a["product"] == "http_server"
    assert ":http_server:2.4.49:" in a["cpe"]


def test_heuristic_product_lower_confidence():
    a = cl.assess_service("SomeVendorApp", "3.2.1")
    assert a["queryable"] is True
    assert a["match_type"] == "cpe-version-heuristic"
    assert a["confidence"] == 0.6


def test_version_is_cleaned_from_banner():
    assert cl._clean_version("1.18.0 (Ubuntu)") == "1.18.0"
    assert cl._clean_version("unknown") is None


def test_cvss_extraction_prefers_v31():
    cve = {"metrics": {"cvssMetricV31": [
        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}
    assert cl._extract_cvss(cve) == (9.8, "CRITICAL")
