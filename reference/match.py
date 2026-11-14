from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raqeeb.declarations import by_name, canonical_tools, compare, tools_digest

from .library import Library

MATCH = "match"
SUBSET = "subset"
DEVIATION = "deviation"
UNKNOWN = "unknown"

MIN_SHARED_TOOLS = 3
MIN_SHARED_FRACTION = 0.6


@dataclass
class Identification:
    """How a server's declared tools relate to what published packages declare.

    match      identical to at least one published release
    subset     every declared tool is identical to the release's; some of its tools are absent
    deviation  mostly the release's tools, but some were added or redefined
    unknown    no published release in the library resembles it
    """
    verdict: str
    package: Optional[str] = None
    versions: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    redefined: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {key: value for key, value in vars(self).items() if value not in (None, [])}


def identify(library: Library, tools: list) -> Identification:
    observed = canonical_tools(tools)
    if not observed:
        return Identification(UNKNOWN)

    releases = library.by_digest()
    exact = releases.get(tools_digest(tools))
    if exact:
        package = exact[-1][0]
        return Identification(MATCH, package, [v for name, v in exact if name == package])

    observed_names = by_name(observed).keys()
    containing: list[tuple[str, str]] = []
    absent_from_newest: list[str] = []
    closest: Optional[tuple] = None
    for digest, published in releases.items():
        added, absent, redefined = compare(library.manifests.load(digest), observed)
        if not added and not redefined:
            containing.extend(published)
            absent_from_newest = absent
            continue
        shared = len(observed_names) - len(added)
        if shared < MIN_SHARED_TOOLS or shared / len(observed_names) < MIN_SHARED_FRACTION:
            continue
        # Common names such as read_file prove nothing; one byte-identical tool does.
        if shared == len(redefined):
            continue
        distance = (len(added) + len(redefined), len(absent))
        if closest is None or distance <= closest[0]:
            closest = (distance, published, added, absent, redefined)

    if containing:
        package = containing[-1][0]
        return Identification(SUBSET, package, [v for name, v in containing if name == package],
                              absent=absent_from_newest)
    if closest is None:
        return Identification(UNKNOWN)
    _, published, added, absent, redefined = closest
    package = published[-1][0]
    return Identification(DEVIATION, package, [v for name, v in published if name == package],
                          added, absent, redefined)
