# pipeline.py - OSINT ingestion for IP / domain / CIDR / ASN / Organization
# -----------------------------------------------------------------------
# - Normalises the target (IP / domain / CIDR / ASN / org)
# - Pulls OSINT from Shodan / Censys (read-only APIs)
# - Generates Google-dork style queries (no scraping)
# - Matches local threat-intel feeds
# - Saves raw artifacts under evidence/runs/<run_id>/
#
# Entry point used by main.py:
#   run_ingestion(target_type, target_value) -> meta dict

import os
import json
import datetime
import ipaddress
import socket
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests
from shodan import Shodan
from dotenv import load_dotenv
from deployment_config import demo_enabled

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
RUNS_ROOT = BASE_DIR / "evidence" / "runs"

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
CENSYS_TOKEN = (
    os.getenv("CENSYS_API_TOKEN", "").strip()
    or os.getenv("CENSYS_API_SECRET", "").strip()
)

# Fallback IPs for demo when Shodan search is not available or returns nothing
ASN_FALLBACK_IPS = {
    "AS15169": "8.8.8.8",  # Google
    "AS13335": "1.1.1.1",  # Cloudflare
}

ORG_FALLBACK_IPS = {
    "google llc": "8.8.8.8",
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1",
}


def _ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_name(value: str) -> str:
    return "".join(
        c if c.isalnum() or c in ("-", "_", ".") else "_" for c in value
    )


def _save(out_dir: Path, name: str, data: Any) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ------------------------- Shodan helpers -------------------------------

def _shodan_client() -> Optional[Shodan]:
    if not SHODAN_API_KEY:
        return None
    try:
        return Shodan(SHODAN_API_KEY)
    except Exception:
        return None


def ingest_ip_shodan(ip: str, out_dir: Path) -> Optional[str]:
    """
    Fetch a single host record from Shodan for an IP and save it as shodan_ip.json.
    Returns the artifact name if successful.
    """
    api = _shodan_client()
    if not api:
        return None
    try:
        host = api.host(ip)
    except Exception:
        return None
    _save(out_dir, "shodan_ip.json", host)
    return "shodan_ip.json"


def _ip_from_shodan_search(query: str) -> Optional[str]:
    """
    Find a representative IP from a Shodan search query (asn: / org:).
    """
    api = _shodan_client()
    if not api:
        return None
    try:
        res = api.search(query, limit=1)
    except Exception:
        return None
    matches = res.get("matches") or []
    if not matches:
        return None
    return matches[0].get("ip_str")


# ------------------------- Censys helpers -------------------------------

def save_censys(ip: str, out_dir: Path) -> Optional[str]:
    """
    Save basic host information from Censys v2 Hosts API if a token is configured.
    Returns artifact name if successful.
    """
    if not CENSYS_TOKEN:
        return None

    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    headers = {"Authorization": f"Bearer {CENSYS_TOKEN}"}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception:
        return None

    _save(out_dir, "censys_ip.json", data)
    return "censys_ip.json"


# ------------------------- Google-dork concepts -------------------------

def save_google_dorks(target: str, out_dir: Path) -> str:
    """
    We do NOT scrape Google. Instead we generate useful dork queries that
    an analyst can run manually. This still demonstrates 'Google dork concepts'
    without automated crawling.
    """
    queries = [
        f'"{target}" site:pastebin.com',
        f'"{target}" site:github.com',
        f'"{target}" filetype:sql OR filetype:cfg OR filetype:env',
        f'"{target}" inurl:login OR inurl:signin',
        f'"{target}" "index of" "backup"',
        f'"{target}" "vpn" OR "rdp" OR "ssh"',
    ]
    payload = {
        "target": target,
        "generated_at": _ts(),
        "queries": queries,
    }
    _save(out_dir, "dorks.json", payload)
    return "dorks.json"


# ------------------------ Threat-intel correlation ----------------------

def _load_feed(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if isinstance(data, list):
        return data
    return []


def _match_indicator(
    indicator: str,
    ip: Optional[str],
    domain: Optional[str],
    org: Optional[str],
) -> bool:
    ind_norm = (indicator or "").lower()
    if ip and ip == indicator:
        return True
    if domain and domain.lower() in ind_norm:
        return True
    if org and org.lower() in ind_norm:
        return True
    return False


def _match_threat_intel(
    ip: Optional[str],
    domain: Optional[str],
    org_or_target: Optional[str],
) -> Dict[str, List[Dict[str, Any]]]:
    public_hits: List[Dict[str, Any]] = []
    dark_hits: List[Dict[str, Any]] = []

    feeds_dir = BASE_DIR / "datasets"
    public_feed = feeds_dir / "public_feed.json"
    dark_feed = feeds_dir / "darkweb_simulated.json"

    public_entries = _load_feed(public_feed) if demo_enabled() else []
    dark_entries = _load_feed(dark_feed) if demo_enabled() else []

    for entry in public_entries:
        ind = entry.get("indicator") or entry.get("ip") or entry.get("domain")
        if not ind:
            continue
        if _match_indicator(str(ind), ip, domain, org_or_target):
            public_hits.append(entry)

    for entry in dark_entries:
        ind = entry.get("indicator") or entry.get("ip") or entry.get("domain")
        if not ind:
            continue
        if _match_indicator(str(ind), ip, domain, org_or_target):
            dark_hits.append(entry)

    return {
        "public_feeds": public_hits,
        "darkweb": dark_hits,
    }


# ------------------------------ Ingestion -------------------------------

def _resolve_for_cidr(cidr: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    hosts = list(net.hosts())
    if hosts:
        return str(hosts[0])
    return str(net.network_address)


def _normalise_asn(value: str) -> str:
    value = value.strip().upper()
    if value.startswith("AS"):
        return value
    return f"AS{value}"


def run_ingestion(target_type: str, target_value: str) -> Dict[str, Any]:
    """
    Main ingestion entry point used by main.py.

    It:
    - Creates a new run directory
    - Resolves the target to a representative IP when possible
      (CIDR / ASN / Org -> pick one IP for demo)
    - Pulls OSINT from Shodan & Censys
    - Generates Google-dork queries for domain/org style targets
    - Matches against local public + dark-web feeds
    """
    target_type = (target_type or "").lower()
    target_value = (target_value or "").strip()

    ts = _ts()
    safe = _safe_name(f"{target_type}_{target_value}")
    run_id = f"{ts}_{safe}"
    out_dir = RUNS_ROOT / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    artifacts: List[str] = []
    sources: List[str] = []
    resolved_ip: Optional[str] = None
    resolved_domain: Optional[str] = None
    org_hint: Optional[str] = None
    provenance: Dict[str, str] = {}
    simulation_used = False

    try:
        if target_type == "ip":
            resolved_ip = target_value
            art = ingest_ip_shodan(resolved_ip, out_dir)
            if art:
                artifacts.append(art)
                sources.append("shodan")
            art = save_censys(resolved_ip, out_dir)
            if art:
                artifacts.append(art)
                sources.append("censys")

        elif target_type == "domain":
            resolved_domain = target_value
            try:
                resolved_ip = socket.gethostbyname(target_value)
            except Exception:
                resolved_ip = None

            if resolved_ip:
                art = ingest_ip_shodan(resolved_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("shodan")
                art = save_censys(resolved_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("censys")

            artifacts.append(save_google_dorks(target_value, out_dir))
            sources.append("google_dorks")

        elif target_type == "cidr":
            rep_ip = _resolve_for_cidr(target_value)
            resolved_ip = rep_ip
            if rep_ip:
                art = ingest_ip_shodan(rep_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("shodan")
                art = save_censys(rep_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("censys")

        elif target_type == "asn":
            asn = _normalise_asn(target_value)
            rep_ip = _ip_from_shodan_search(f"asn:{asn}")

            # Fallback if Shodan search did not return anything
            if not rep_ip and demo_enabled():
                rep_ip = ASN_FALLBACK_IPS.get(asn)
                if rep_ip:
                    simulation_used = True
                    provenance["resolved_ip"] = "demo fallback (not a verified ASN asset)"

            resolved_ip = rep_ip
            org_hint = asn

            if rep_ip:
                art = ingest_ip_shodan(rep_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("shodan")
                art = save_censys(rep_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("censys")

        elif target_type in ("org", "organization"):
            org_hint = target_value
            rep_ip = _ip_from_shodan_search(f'org:"{target_value}"')

            # Fallback if Shodan search did not return anything
            if not rep_ip and demo_enabled():
                rep_ip = ORG_FALLBACK_IPS.get(target_value.strip().lower())
                if rep_ip:
                    simulation_used = True
                    provenance["resolved_ip"] = "demo fallback (not a verified organization asset)"

            resolved_ip = rep_ip

            if rep_ip:
                art = ingest_ip_shodan(rep_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("shodan")
                art = save_censys(rep_ip, out_dir)
                if art:
                    artifacts.append(art)
                    sources.append("censys")

            artifacts.append(save_google_dorks(target_value, out_dir))
            sources.append("google_dorks")

        # Threat intel (local feeds)
        ti = _match_threat_intel(resolved_ip, resolved_domain, org_hint or target_value)
        if ti["public_feeds"] or ti["darkweb"]:
            _save(out_dir, "threat_feeds.json", ti)
            artifacts.append("threat_feeds.json")
            sources.append("demo_sample_feeds")
            provenance["demo_sample_feeds"] = "bundled simulated data"
            simulation_used = True

    except Exception as e:
        with (out_dir / "errors.log").open("a", encoding="utf-8") as f:
            f.write(f"[{_ts()}] ingestion error: {e}\n")

    for source in sources:
        if source == "shodan":
            provenance[source] = "Shodan API host record"
        elif source == "censys":
            provenance[source] = "Censys API host record"
        elif source == "google_dorks":
            provenance[source] = "generated queries only; no search results"
    meta: Dict[str, Any] = {
        "run_id": run_id,
        "run_dir": str(out_dir),
        "target_type": target_type,
        "target_value": target_value,
        "created_at": ts,
        "resolved_ip": resolved_ip,
        "resolved_domain": resolved_domain,
        "threat_intel": _load_json(out_dir / "threat_feeds.json") or {
            "public_feeds": [],
            "darkweb": [],
        },
        "artifacts": artifacts,
        "sources": list(dict.fromkeys(sources)),
        "source_provenance": provenance,
        "simulation_used": simulation_used,
    }
    _save(out_dir, "meta.json", meta)
    return meta
