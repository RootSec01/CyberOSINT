from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from raqeeb.declarations import compare

from .store import Archive


@dataclass
class ManifestChange:
    id: str
    url: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    redefined: list[str] = field(default_factory=list)


def outcome_counts(run: dict) -> Counter:
    return Counter(observation["outcome"] for observation in run["observations"])


def manifest_changes(archive: Archive, earlier: dict, later: dict) -> list[ManifestChange]:
    """Endpoints that listed tools in both runs and whose declarations differ."""
    before = {o["id"]: o for o in earlier["observations"] if o.get("manifest")}
    changes = []
    for observation in later["observations"]:
        previous = before.get(observation["id"])
        if not previous or not observation.get("manifest"):
            continue
        if previous["manifest"] == observation["manifest"]:
            continue
        added, removed, redefined = compare(
            archive.load_manifest(previous["manifest"]),
            archive.load_manifest(observation["manifest"]))
        changes.append(ManifestChange(observation["id"], observation["url"],
                                      added, removed, redefined))
    return changes


def comparable(earlier: dict, later: dict) -> int:
    before = {o["id"] for o in earlier["observations"] if o.get("manifest")}
    return sum(1 for o in later["observations"] if o.get("manifest") and o["id"] in before)
