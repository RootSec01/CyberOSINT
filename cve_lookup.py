"""NVD CVE lookup with CPE version-applicability matching.

Fixes the P0-2 false-positive blocker. The old client used NVD `keywordSearch`,
a full-text search over CVE *descriptions*: a service string like "auto" or
"Vercel" matched any CVE whose prose contained that word — including CVEs that
explicitly state the detected product is NOT affected. This module instead:

  * refuses to query generic tokens that carry no product identity;
  * refuses to query when no version is known (applicability can't be verified);
  * queries by CPE 2.3 match string with a wildcard vendor
    (cpe:2.3:a:*:<product>:<version>:*...) so NVD applies real version-range
    applicability logic instead of description text matching;
  * tags every finding with match_type, confidence, and the exact CPE query
    used, as defensible evidence.

Public surface is unchanged: query_cves_for_service(service, version, max_results).
assess_service(service, version) exposes the queryability decision (used by the
correlation engine to record WHY a service produced no CVEs).
"""

import os
import re
import time
import requests
from typing import List, Dict, Any, Tuple, Optional

NVD_BASE_URL = os.getenv(
    "NVD_API_BASE",
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

_MAX_RETRIES = 3
_BACKOFF_SECONDS = 2.0
_HTTP_TIMEOUT = 15

# Tokens that identify no specific product. Querying them produced the
# description-text noise (the "auto"/"unknown" 1999-CVE problem).
_GENERIC_TOKENS = {
    "", "unknown", "auto", "none", "null", "generic", "n/a", "na",
    "http", "https", "www", "web", "webserver", "web server", "server",
    "tcp", "udp", "ssl", "tls", "ssl/tls", "proxy", "gateway", "service",
    "product", "banner", "default", "cdn", "vercel", "cloudflare",
    "cloudflare-nginx", "akamai", "amazon", "amazons3", "aws",
}

# Colloquial product name -> official NVD CPE product token where they differ.
# Vendor stays wildcard, so only the product token must be right.
_PRODUCT_ALIASES = {
    "apache": "http_server",
    "apache httpd": "http_server",
    "httpd": "http_server",
    "apache http server": "http_server",
    "nginx": "nginx",
    "openssh": "openssh",
    "microsoft iis httpd": "internet_information_services",
    "microsoft-iis": "internet_information_services",
    "iis": "internet_information_services",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "exim smtpd": "exim",
    "postfix smtpd": "postfix",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "openssl": "openssl",
    "lighttpd": "lighttpd",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "bind": "bind",
}

_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def _slug_product(raw: str) -> str:
    s = raw.strip().lower()
    if s in _PRODUCT_ALIASES:
        return _PRODUCT_ALIASES[s]
    s = re.sub(r"\b(httpd|daemon|service|server)\b", " ", s).strip()
    s = re.sub(r"[^a-z0-9._-]+", "_", s).strip("_")
    return s


def _clean_version(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    m = _VERSION_RE.search(str(raw))
    return m.group(0) if m else None


def assess_service(service: str, version: Optional[str]) -> Dict[str, Any]:
    """Decide whether a detected service is specific enough for CVE lookup."""
    raw = (service or "").strip()
    low = raw.lower()
    ver = _clean_version(version)

    if low in _GENERIC_TOKENS:
        return {"queryable": False, "product": None, "version": ver, "cpe": None,
                "match_type": "skipped-generic", "confidence": 0.0,
                "reason": f"generic token '{raw}' carries no product identity"}

    product = _slug_product(raw)
    if not product or len(product) < 2:
        return {"queryable": False, "product": None, "version": ver, "cpe": None,
                "match_type": "skipped-unresolved", "confidence": 0.0,
                "reason": f"could not resolve a product from '{raw}'"}

    if not ver:
        return {"queryable": False, "product": product, "version": None,
                "cpe": None, "match_type": "skipped-no-version", "confidence": 0.0,
                "reason": f"no version for '{raw}'; applicability cannot be verified"}

    aliased = low in _PRODUCT_ALIASES
    cpe = f"cpe:2.3:a:*:{product}:{ver}:*:*:*:*:*:*:*"
    return {"queryable": True, "product": product, "version": ver, "cpe": cpe,
            "match_type": "cpe-version" if aliased else "cpe-version-heuristic",
            "confidence": 0.9 if aliased else 0.6,
            "reason": "product+version resolved to a CPE match string"}


def _extract_cvss(cve: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Extract a CVSS score and severity, preferring v3.1, then v3.0, then v2."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not arr:
            continue
        item = arr[0]
        cvss_data = item.get("cvssData") or {}
        score = cvss_data.get("baseScore") or item.get("baseScore")
        severity = cvss_data.get("baseSeverity") or item.get("baseSeverity")
        if score is not None:
            try:
                return float(score), str(severity or "")
            except (TypeError, ValueError):
                continue
    return None, None


def _english_desc(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value") or ""
    return descriptions[0].get("value") if descriptions else ""


def _request_with_retry(params: Dict[str, Any], headers: Dict[str, str]) -> Optional[dict]:
    """GET the NVD endpoint, retrying with backoff on rate limiting (429)."""
    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.get(NVD_BASE_URL, params=params, headers=headers,
                                timeout=_HTTP_TIMEOUT)
        except requests.RequestException:
            return None
        if resp.status_code == 429:
            time.sleep(_BACKOFF_SECONDS * (attempt + 1))
            continue
        try:
            resp.raise_for_status()
            return resp.json()
        except (requests.HTTPError, ValueError):
            return None
    return None


def query_cves_for_service(
    service: str,
    version: Optional[str] = None,
    max_results: int = 5,
) -> List[Dict[str, Any]]:
    """Query NVD for CVEs whose CPE applicability covers this service+version."""
    a = assess_service(service, version)
    if not a["queryable"]:
        return []

    params = {
        "virtualMatchString": a["cpe"],
        "resultsPerPage": max(int(max_results), 20),
    }
    headers: Dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    data = _request_with_retry(params, headers)
    if data is None:
        return []

    results: List[Dict[str, Any]] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or "UNKNOWN"
        score, severity = _extract_cvss(cve)
        results.append({
            "id": cve_id,
            "cve_id": cve_id,
            "score": score,
            "cvss_score": score,
            "severity": severity,
            "source": "NVD",
            "description": _english_desc(cve),
            "published": cve.get("published"),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "match_type": a["match_type"],
            "confidence": a["confidence"],
            "cpe_query": a["cpe"],
        })

    # most severe applicable CVEs first, then truncate
    results.sort(key=lambda r: (r["score"] is not None, r["score"] or 0.0),
                 reverse=True)
    return results[:max_results]
