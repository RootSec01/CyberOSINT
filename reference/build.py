from __future__ import annotations

import os
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

from . import npm
from .library import Library
from .stdio import Listing, list_tools


def observe_release(package: str, version: str, args: list[str], env: dict[str, str]) -> Listing:
    """Install one release in a throwaway directory and read what it declares."""
    with tempfile.TemporaryDirectory(prefix="raqeeb-reference-") as scratch:
        root = Path(scratch)
        entry = npm.install(package, version, root / "install")
        if entry is None:
            return Listing("install_failed")
        workdir = root / "work"
        home = root / "home"
        workdir.mkdir()
        home.mkdir()
        command = ["node", str(entry), *(a.replace("{workdir}", str(workdir)) for a in args)]
        isolated = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), **env}
        return list_tools(command, cwd=workdir, env=isolated)


def build(library: Library, catalog: list[dict], *, only: Optional[str] = None,
          latest: Optional[int] = None, workers: int = 4,
          report: Callable[[str], None] = print) -> int:
    if shutil.which("npm") is None or shutil.which("node") is None:
        raise RuntimeError("node and npm are required to build the reference library")
    recorded = 0
    for item in catalog:
        package = item["package"]
        if only and package != only:
            continue
        versions = npm.published_versions(package)
        if latest:
            versions = versions[-latest:]
        missing = [(v, when) for v, when in versions if not library.has(package, v)]
        if not missing:
            report(f"{package}: up to date ({len(versions)} releases)")
            continue

        def observe(release: tuple[str, str]) -> Listing:
            return observe_release(package, release[0], item.get("args", []), item.get("env", {}))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for (version, when), listing in zip(missing, pool.map(observe, missing)):
                library.record(package, "npm", version, when, listing)
                recorded += 1
        library.save()
        listed = sum(1 for _ in library.releases(package))
        report(f"{package}: {len(missing)} new, {listed} of {len(versions)} releases listed tools")
    return recorded
