"""Target ownership proof via DNS TXT — the legal gate before active scanning.

Before the platform runs any active check (Nmap/ZAP/TCP) against a domain a
customer claims, the customer must prove control of it by publishing a DNS TXT
record:

    cyberosint-verify=<token>

The token is deterministic per (user, domain), so it is stable to display and to
re-check. Verification is a passive DNS lookup — no packet is ever sent to the
target host itself. This keeps active scanning authorized and defensible when the
platform is sold as a service.
"""

from __future__ import annotations

import hashlib
import os
from typing import Callable, List, Optional

TXT_PREFIX = "cyberosint-verify="


def expected_token(user_id: int, domain: str, secret: Optional[str] = None) -> str:
    secret = secret or os.getenv("OWNERSHIP_SECRET") or os.getenv("JWT_SECRET") or ""
    raw = f"{user_id}:{(domain or '').strip().lower()}:{secret}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def txt_record(user_id: int, domain: str) -> str:
    """The exact TXT value the customer must publish at the domain apex."""
    return TXT_PREFIX + expected_token(user_id, domain)


def _lookup_txt(domain: str) -> List[str]:
    """Passive DNS TXT lookup. Returns [] on any resolver error."""
    try:
        import dns.resolver  # dnspython
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        out: List[str] = []
        for rec in answers:
            if hasattr(rec, "strings"):
                out.append(b"".join(rec.strings).decode("utf-8", "ignore"))
            else:
                out.append(str(rec).strip('"'))
        return out
    except Exception:
        return []


def verify_domain(user_id: int, domain: str,
                  resolver: Optional[Callable[[str], List[str]]] = None) -> dict:
    """Check whether the domain publishes the expected ownership TXT record.

    `resolver` is injectable for tests (returns a list of TXT strings)."""
    domain = (domain or "").strip().lower()
    want = expected_token(user_id, domain)
    lookup = resolver or _lookup_txt
    records = lookup(domain) or []
    found = any(want in rec.replace('"', "") for rec in records)
    return {
        "domain": domain,
        "verified": bool(found),
        "expected_record": TXT_PREFIX + want,
        "records_seen": len(records),
    }
