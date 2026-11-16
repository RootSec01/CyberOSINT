"""Signed evidence for one scan, and a check that needs nothing but this file's verify().

Verify a bundle without a running Raqeeb:  python3 -m raqeeb.evidence verify bundle.json [--key KEY_ID]
Show this installation's key:               python3 -m raqeeb.evidence key
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

FORMAT = "raqeeb-evidence/1"
KEY_ENV = "EVIDENCE_SIGNING_KEY"
KEY_FILE = "signing_key"


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def _key_path() -> Path:
    from raqeeb.paths import EVIDENCE_DIR
    return EVIDENCE_DIR / KEY_FILE


def signing_key() -> Ed25519PrivateKey:
    """The installation's key: from the environment, else a file created on first use."""
    configured = os.getenv(KEY_ENV, "").strip()
    if configured:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(configured))
    path = _key_path()
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle, "w") as out:
        out.write(base64.b64encode(seed).decode())
    return key


def issuer() -> dict:
    public = _raw(signing_key().public_key())
    return {"key_id": key_id(public), "public_key": base64.b64encode(public).decode(), "algorithm": "Ed25519"}


def sign(content: dict) -> dict:
    """Wrap content with who signed it and when; the signature covers everything but itself."""
    body = {"format": FORMAT, "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "issuer": issuer(), **content}
    body["signature"] = base64.b64encode(signing_key().sign(_canonical(body))).decode()
    return body


def verify(bundle: dict, expected_key_id: Optional[str] = None) -> tuple[bool, str]:
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT:
        return False, f"not a {FORMAT} bundle"
    try:
        public = base64.b64decode(bundle["issuer"]["public_key"])
        signature = base64.b64decode(bundle["signature"])
    except (KeyError, TypeError, ValueError):
        return False, "issuer key or signature is missing or unreadable"
    signed_by = key_id(public)
    if expected_key_id and expected_key_id.strip().lower() != signed_by:
        return False, f"signed by key {signed_by}, not the expected {expected_key_id.strip().lower()}"
    body = {name: value for name, value in bundle.items() if name != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, _canonical(body))
    except (InvalidSignature, ValueError):
        return False, "signature does not match the content: the bundle was changed after signing"
    if expected_key_id:
        return True, f"intact, signed by the expected key {signed_by}"
    return True, f"intact, signed by key {signed_by}; compare this key id with the one the operator publishes"


def for_scan(db, scan, asset) -> dict:
    from raqeeb import register
    from raqeeb.models import Finding, Run

    stored = db.query(Run).filter(Run.id == scan.run_row).first() if scan.run_row else None
    proof = (json.loads(stored.report_json).get("safe_proof") or {}) if stored and stored.report_json else {}
    seen = (db.query(Finding).filter(Finding.asset_id == asset.id)
            .filter((Finding.first_scan == scan.reference) | (Finding.last_scan == scan.reference))
            .order_by(Finding.id).all())
    assessment = proof.get("provenance") or {}
    return sign({
        "scan": register.scan_dict(scan, asset),
        "declared_tools": register.declared_tools(db, scan.declarations),
        "provenance": {name: assessment.get(name) for name in
                       ("verdict", "package", "versions", "added", "absent", "redefined", "differences")}
        if assessment else None,
        "findings": [register.finding_dict(finding, asset) for finding in seen],
        "method": "Handshake and tool list only. No tool was called. Credentials in stored text are removed.",
    })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("verify", help="check a bundle's signature")
    check.add_argument("bundle", type=Path)
    check.add_argument("--key", help="key id the bundle must be signed by")
    commands.add_parser("key", help="print this installation's key id and public key")
    args = parser.parse_args()
    if args.command == "key":
        print(json.dumps(issuer(), indent=2))
        return
    try:
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        sys.exit(f"cannot read {args.bundle}: {error}")
    intact, reason = verify(bundle, args.key)
    reference = (bundle.get("scan") or {}).get("reference", "") if isinstance(bundle, dict) else ""
    print(f"{'VALID' if intact else 'INVALID'} {reference}: {reason}")
    sys.exit(0 if intact else 1)


if __name__ == "__main__":
    main()
