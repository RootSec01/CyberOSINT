from __future__ import annotations

import hashlib
import ipaddress
import time
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Iterator
from urllib.parse import urlsplit

import requests

from . import USER_AGENT

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"
OFFICIAL = "io.modelcontextprotocol.registry/official"
SAMPLE_SEED = "raqeeb-observatory-2026-11"

Page = dict
FetchPage = Callable[[dict], Page]


@dataclass(frozen=True)
class Endpoint:
    id: str
    url: str
    server: str
    version: str

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()

    def as_dict(self) -> dict:
        return asdict(self)


def endpoint_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:12]


def http_fetcher(base_url: str = REGISTRY_URL, attempts: int = 4) -> FetchPage:
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    def fetch(params: dict) -> Page:
        for attempt in range(attempts):
            response = session.get(base_url, params=params, timeout=30)
            if response.status_code == 429 or response.status_code >= 500:
                retry_after = response.headers.get("Retry-After", "")
                time.sleep(int(retry_after) if retry_after.isdigit() else 2 ** attempt)
                continue
            response.raise_for_status()
            return response.json()
        response.raise_for_status()
        raise RuntimeError(f"registry kept answering {response.status_code}")

    return fetch


def iter_entries(fetch: FetchPage, page_size: int = 100, pause: float = 0.2) -> Iterator[dict]:
    params = {"limit": page_size, "version": "latest"}
    while True:
        try:
            page = fetch(params)
        except requests.HTTPError as error:
            # Older registry builds reject the version filter; isLatest is checked again later.
            if "version" in params and error.response is not None and error.response.status_code == 400:
                del params["version"]
                continue
            raise
        yield from page.get("servers") or []
        cursor = (page.get("metadata") or {}).get("nextCursor")
        if not cursor:
            return
        params["cursor"] = cursor
        time.sleep(pause)


def _is_current(entry: dict) -> bool:
    official = (entry.get("_meta") or {}).get(OFFICIAL) or {}
    return official.get("status") == "active" and official.get("isLatest") is True


def _needs_credentials(remote: dict) -> bool:
    return any(header.get("isRequired") or header.get("isSecret")
               for header in remote.get("headers") or [])


def _is_named_public_host(host: str) -> bool:
    if not host or "." not in host or host.endswith((".local", ".internal", ".localhost")):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def open_endpoints(entry: dict) -> list[Endpoint]:
    """Remote endpoints a client can reach with no template values and no credentials."""
    if not _is_current(entry):
        return []
    server = entry.get("server") or {}
    found = []
    for remote in server.get("remotes") or []:
        url = str(remote.get("url") or "")
        parts = urlsplit(url)
        if remote.get("type") != "streamable-http" or parts.scheme != "https":
            continue
        if "{" in url or parts.username or _needs_credentials(remote):
            continue
        if not _is_named_public_host((parts.hostname or "").lower()):
            continue
        found.append(Endpoint(endpoint_id(url), url, str(server.get("name") or ""),
                              str(server.get("version") or "")))
    return found


def draw_sample(endpoints: Iterable[Endpoint], size: int, seed: str = SAMPLE_SEED) -> list[Endpoint]:
    """Seeded pick, one endpoint per hostname so no operator is over-represented."""
    unique = {endpoint.url: endpoint for endpoint in endpoints}
    ranked = sorted(unique.values(),
                    key=lambda e: hashlib.sha256(f"{seed}:{e.url}".encode()).hexdigest())
    chosen, hosts = [], set()
    for endpoint in ranked:
        if endpoint.host in hosts:
            continue
        hosts.add(endpoint.host)
        chosen.append(endpoint)
        if len(chosen) == size:
            break
    return sorted(chosen, key=lambda e: e.url)


def build_sample(fetch: FetchPage, size: int, seed: str = SAMPLE_SEED,
                 progress: Callable[[int], None] | None = None) -> dict:
    records = current = 0
    candidates: list[Endpoint] = []
    for entry in iter_entries(fetch):
        records += 1
        if _is_current(entry):
            current += 1
            candidates.extend(open_endpoints(entry))
        if progress and records % 2000 == 0:
            progress(records)
    chosen = draw_sample(candidates, size, seed)
    return {
        "registry": REGISTRY_URL,
        "drawn_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": seed,
        "records_read": records,
        "current_servers": current,
        "open_endpoints": len({c.url for c in candidates}),
        "distinct_hosts": len({c.host for c in candidates}),
        "endpoints": [endpoint.as_dict() for endpoint in chosen],
    }
