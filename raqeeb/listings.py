"""Servers whose operators publish an open endpoint in the official MCP registry.

A listing is the operator's own statement that any MCP client may connect to that endpoint
without credentials. Raqeeb reads it the way such a client does: handshake and tool list,
no tool call. A listing is confirmed against the registry when the server is added.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable, Optional
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from observatory import registry
from raqeeb import register
from raqeeb.models import Asset, Attestation, Listing, User

SEARCH_LIMIT = 30
SLOWEST_EVERY = 60
STATEMENT = "I own this server, or I hold written permission from its owner to scan it."

_fetch: Optional[Callable[[dict], dict]] = None


def fetcher() -> Callable[[dict], dict]:
    global _fetch
    if _fetch is None:
        _fetch = registry.http_fetcher(attempts=2)
    return _fetch


def search(text: str) -> list[dict]:
    text = text.strip()
    if len(text) < 2:
        raise register.Rejected("type at least two characters")
    page = fetcher()({"search": text, "limit": SEARCH_LIMIT, "version": "latest"})
    found = []
    for entry in page.get("servers") or []:
        server = entry.get("server") or {}
        for endpoint in registry.open_endpoints(entry):
            found.append({"server": endpoint.server, "version": endpoint.version, "url": endpoint.url,
                          "title": server.get("title") or endpoint.server,
                          "description": (server.get("description") or "")[:240]})
    return found


def confirm(url: str) -> dict:
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or not parts.hostname:
        raise register.Rejected("a registry endpoint is an https URL")
    for candidate in search(parts.hostname):
        if candidate["url"] == url.strip():
            return candidate
    raise register.Rejected("this URL is not an open endpoint of a current entry in the official MCP registry")


def public_address(host: str) -> bool:
    """True only when every address the host resolves to is publicly routable."""
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses)


def record(db: Session, asset: Asset, entry: dict) -> Listing:
    row = Listing(asset_id=asset.id, server=entry["server"], version=entry["version"], url=entry["url"])
    db.add(row)
    db.commit()
    return row


def attest(db: Session, asset: Asset, by: User) -> Attestation:
    row = Attestation(asset_id=asset.id, username=by.username, statement=STATEMENT)
    db.add(row)
    db.commit()
    return row


def listing(db: Session, asset: Asset) -> Optional[Listing]:
    return db.query(Listing).filter(Listing.asset_id == asset.id).first()


def basis(db: Session, asset: Asset) -> dict:
    """Why Raqeeb may read this server."""
    found = listing(db, asset)
    if found:
        return {"kind": "registry", "text": f"Listed as an open endpoint in the official MCP registry: "
                                            f"{found.server} {found.version}",
                "since": register._stamp(found.confirmed_at)}
    said = db.query(Attestation).filter(Attestation.asset_id == asset.id).first()
    if said:
        return {"kind": "attested", "text": f"{said.username}: {said.statement}", "since": register._stamp(said.at)}
    return {"kind": "local", "text": "Loopback lab server", "since": None}


def forget(db: Session, asset_id: int) -> None:
    db.query(Listing).filter(Listing.asset_id == asset_id).delete()
    db.query(Attestation).filter(Attestation.asset_id == asset_id).delete()
