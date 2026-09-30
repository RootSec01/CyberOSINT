"""Redaction — strip sensitive identifiers before anything leaves the platform.

Used by the 'redacted' AI mode. Findings (tool names, severities, CVE ids,
counts, change kinds) are preserved; identifiers and secrets are replaced with
tags. Defence in depth, not regex alone:

  1. Structured patterns  — private keys, URL/connection-string credentials,
     known key formats (OpenAI/Anthropic/AWS/GitHub/Slack), JWTs, key=value
     secrets, emails, IPv4/IPv6, MAC, hostnames/FQDNs.
  2. Entropy sweep        — any leftover long, high-entropy token (unknown API
     keys, hashes, base64 blobs) is caught even if no pattern matched it.

Everything is pure and operates on a deep copy (recursive over nested JSON), so
stored evidence is never mutated. Never logs or returns the original secret.
"""

from __future__ import annotations

import copy
import math
import re
from collections import Counter
from typing import Any

# 1) Structured patterns — order matters (most specific / most dangerous first).
_PATTERNS = [
    (re.compile(r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----",
                re.S), "[REDACTED_PRIVATE_KEY]"),
    # scheme://user:pass@host  and  postgres://u:p@host / mongodb+srv://u:p@host
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s:/@]+:[^\s:/@]+@"),
     r"\1[REDACTED_CREDENTIALS]@"),
    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{16,}"), "[REDACTED_SECRET]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_SECRET]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED_SECRET]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SECRET]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
     "[REDACTED_JWT]"),
    # key = value / key: value secrets (stop at ; , whitespace, quotes, &)
    (re.compile(r"(?i)\b(?:bearer|token|api[_-]?key|secret|password|passwd|pwd|"
                r"connection[_-]?string|conn[_-]?str)\b\s*[=:]\s*[^\s;,\"'&]+"),
     "[REDACTED_SECRET]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "[REDACTED_IP]"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"), "[REDACTED_IPV6]"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "[REDACTED_MAC]"),
    (re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
     "[REDACTED_HOST]"),
]

# 2) Entropy sweep — long secret-charset runs that no pattern named.
_CANDIDATE = re.compile(r"[A-Za-z0-9+/_=\-]{20,}")
_ENTROPY_MIN = 3.5


def _entropy(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact_high_entropy(text: str) -> str:
    def repl(m: "re.Match[str]") -> str:
        s = m.group(0)
        has_digit = any(c.isdigit() for c in s)
        has_alpha = any(c.isalpha() for c in s)
        # Real secrets mix classes or are very long; this spares normal words,
        # CVE ids, and tool names (all < 20 chars or single-class & short).
        if _entropy(s) >= _ENTROPY_MIN and ((has_digit and has_alpha) or len(s) >= 32):
            return "[REDACTED_SECRET]"
        return s
    return _CANDIDATE.sub(repl, text)


def redact_text(text: str) -> str:
    """Return `text` with every sensitive identifier/secret replaced by a tag."""
    if not text:
        return text
    out = text
    for pattern, tag in _PATTERNS:
        out = pattern.sub(tag, out)
    out = _redact_high_entropy(out)
    return out


def redact(obj: Any) -> Any:
    """Recursively redact all string values in a dict/list/str structure."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def redact_context(context: dict) -> dict:
    """Return a redacted deep copy of a copilot context (original untouched)."""
    return redact(copy.deepcopy(context))
