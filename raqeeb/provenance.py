"""Where a scanned server's declarations stand against what package publishers shipped."""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from raqeeb.declarations import by_name, canonical_tools

EXCERPT = 4000
COMPARED_FIELDS = ("description", "input_schema", "output_schema", "annotations")


@lru_cache(maxsize=1)
def _library():
    try:
        from reference.library import Library
    except ImportError:
        return None
    library = Library()
    return library if library.packages else None


def _excerpt(value) -> object:
    return value[:EXCERPT] if isinstance(value, str) else value


def _differences(published: list, observed: list, added: list[str], redefined: list[str]) -> list[dict]:
    theirs, ours = by_name(published), by_name(observed)
    found = []
    for name in redefined:
        before, after = theirs[name][0], ours[name][0]
        fields = [{"field": field, "published": _excerpt(before.get(field)),
                   "observed": _excerpt(after.get(field))}
                  for field in COMPARED_FIELDS if before.get(field) != after.get(field)]
        other = sorted(key for key in before.keys() | after.keys()
                       if key not in COMPARED_FIELDS and before.get(key) != after.get(key))
        found.append({"tool": name, "change": "redefined", "fields": fields, "other_fields": other})
    for name in added:
        found.append({"tool": name, "change": "added",
                      "observed": {"description": _excerpt(ours[name][0].get("description"))}})
    return found


def assess(tools: Optional[list]) -> dict:
    """Verdict for one tools/list result, with the differing text when it deviates."""
    library = _library()
    if library is None:
        return {"verdict": "unavailable"}

    from reference.match import DEVIATION, identify
    found = identify(library, tools or [])
    result = found.as_dict()
    result["library"] = {"packages": len(library.packages),
                         "releases": sum(1 for _ in library.releases())}
    if found.verdict == DEVIATION:
        result["differences"] = _differences(library.tools(found.manifest),
                                             canonical_tools(tools), found.added, found.redefined)
    return result


def alert_text(assessment: dict) -> Optional[str]:
    """One line for an alert, or None when the declarations do not deviate."""
    if assessment.get("verdict") != "deviation":
        return None
    parts = [f"{len(assessment[key])} {label}: {', '.join(assessment[key][:5])}"
             for key, label in (("redefined", "redefined"), ("added", "added")) if assessment.get(key)]
    return f"Closest published release {assessment['package']}@{assessment['versions'][-1]}. " + "; ".join(parts)
