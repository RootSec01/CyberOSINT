from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Optional

from raqeeb.declarations import ManifestStore, write_json

from .stdio import Listing

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "data"
CATALOG = HERE / "catalog.json"


class Library:
    """Index of package releases and the manifest each one declared."""

    def __init__(self, root: Path = DATA_DIR):
        self.root = Path(root)
        self.manifests = ManifestStore(self.root / "manifests")
        self._index_path = self.root / "index.json"
        self.packages: dict = {}
        self._tools: dict[str, list] = {}
        if self._index_path.exists():
            self.packages = json.loads(self._index_path.read_text(encoding="utf-8"))["packages"]

    def save(self) -> None:
        ordered = {name: {**entry, "versions": dict(sorted(
            entry["versions"].items(), key=lambda item: item[1]["published"]))}
            for name, entry in sorted(self.packages.items())}
        write_json(self._index_path, {"packages": ordered})

    def has(self, package: str, version: str) -> bool:
        return version in self.packages.get(package, {}).get("versions", {})

    def record(self, package: str, ecosystem: str, version: str, published: str,
               listing: Listing) -> None:
        release = {"published": published, "outcome": listing.outcome}
        if listing.detail:
            release["detail"] = listing.detail
        if listing.tools is not None:
            release.update(server_name=listing.server_name, server_version=listing.server_version,
                           protocol_version=listing.protocol_version,
                           tool_count=len(listing.tools),
                           manifest=self.manifests.save(listing.tools))
        entry = self.packages.setdefault(package, {"ecosystem": ecosystem, "versions": {}})
        entry["versions"][version] = release

    def releases(self, package: Optional[str] = None) -> Iterator[tuple[str, str, dict]]:
        """(package, version, release) for every release that listed its tools, oldest first."""
        for name, entry in sorted(self.packages.items()):
            if package and name != package:
                continue
            listed = [(v, r) for v, r in entry["versions"].items() if r.get("manifest")]
            for version, release in sorted(listed, key=lambda item: item[1]["published"]):
                yield name, version, release

    def tools(self, digest: str) -> list:
        if digest not in self._tools:
            self._tools[digest] = self.manifests.load(digest)
        return self._tools[digest]

    def by_digest(self) -> dict[str, list[tuple[str, str]]]:
        found: dict[str, list[tuple[str, str]]] = {}
        for name, version, release in self.releases():
            found.setdefault(release["manifest"], []).append((name, version))
        return found


def load_catalog(path: Path = CATALOG) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["packages"]
