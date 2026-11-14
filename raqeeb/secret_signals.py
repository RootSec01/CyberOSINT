"""Passive credential-shape detection, separate from privacy redaction.

A match establishes only a recognizable shape, never a live/valid credential.
Identifiers, entropy-only strings and existing redaction tags are not evidence
of a credential. No values are returned, logged or tested against a service.
"""
from __future__ import annotations
import re

_SECRET_PATTERNS = tuple(re.compile(pattern, flags) for pattern, flags in (
    (r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----', re.S),
    (r'[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:[^\s:/@]+@', 0),
    (r'\bsk-ant-[A-Za-z0-9_-]{16,}\b', 0),
    (r'\bsk-[A-Za-z0-9]{20,}\b', 0),
    (r'\bAKIA[0-9A-Z]{16}\b', 0),
    (r'\bgh[pousr]_[A-Za-z0-9]{20,}\b', 0),
    (r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b', 0),
    (r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b', 0),
    (r'''\b(?:bearer|token|api[_-]?key|secret|password|passwd|pwd|connection[_-]?string|conn[_-]?str)\b\s*[=:]\s*[^\s;,"'&]+''', re.I),
))
_REDACTED_TAG = re.compile(r'\[REDACTED_[A-Z_]+\]')


def contains_secret_shape(text: str) -> bool:
    """Recognizable credential syntax; deliberately not a validity verdict."""
    # Already-sanitized values must not create a fresh observation.
    text = _REDACTED_TAG.sub('', text)
    return any(pattern.search(text) for pattern in _SECRET_PATTERNS)
