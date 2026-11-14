"""Canonical form, digest and on-disk store for the tools an MCP server declares."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from raqeeb import manifest_fingerprint


def canonical_tools(tools: list) -> list:
    return manifest_fingerprint.normalize({"tools": tools})["tools"]


def pack(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def tools_digest(tools: list) -> str:
    return hashlib.sha256(pack(canonical_tools(tools)).encode("utf-8")).hexdigest()


def by_name(canonical: list) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for tool in canonical:
        grouped.setdefault(tool.get("name", ""), []).append(tool)
    return grouped


def compare(before: list, after: list) -> tuple[list[str], list[str], list[str]]:
    """Tool names added, removed and redefined between two canonical manifests."""
    old, new = by_name(before), by_name(after)
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    redefined = sorted(name for name in old.keys() & new.keys() if old[name] != new[name])
    return added, removed, redefined


def write_atomically(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    draft = path.with_name(f"{path.name}.{os.getpid()}-{threading.get_ident()}.part")
    draft.write_text(text, encoding="utf-8")
    os.replace(draft, path)


def write_json(path: Path, document) -> None:
    write_atomically(path, json.dumps(document, indent=1, ensure_ascii=False) + "\n")


class ManifestStore:
    """Tool declarations kept once per distinct content, addressed by digest."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def path(self, digest: str) -> Path:
        return self.root / digest[:2] / f"{digest}.json"

    def save(self, tools: list) -> str:
        digest = tools_digest(tools)
        path = self.path(digest)
        if not path.exists():
            write_atomically(path, json.dumps(canonical_tools(tools), indent=1, sort_keys=True,
                                              ensure_ascii=False, default=str) + "\n")
        return digest

    def load(self, digest: str) -> list:
        return json.loads(self.path(digest).read_text(encoding="utf-8"))
