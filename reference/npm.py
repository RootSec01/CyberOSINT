from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Optional

STABLE = re.compile(r"^\d+\.\d+\.\d+$")


def published_versions(package: str) -> list[tuple[str, str]]:
    """Stable versions with their publication time, oldest first."""
    done = subprocess.run(["npm", "view", package, "time", "--json"],
                          capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise RuntimeError(f"npm view {package}: {done.stderr.strip()[:200]}")
    times = json.loads(done.stdout)
    return sorted(((version, when) for version, when in times.items() if STABLE.match(version)),
                  key=lambda item: item[1])


def install(package: str, version: str, into: Path) -> Optional[Path]:
    """Install without running install scripts; return the server's entry script."""
    done = subprocess.run(
        ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-save",
         "--loglevel=error", "--prefix", str(into), f"{package}@{version}"],
        capture_output=True, text=True, timeout=300)
    if done.returncode != 0:
        return None
    home = into / "node_modules" / package
    try:
        manifest = json.loads((home / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entry = manifest.get("bin")
    if isinstance(entry, dict):
        entry = next(iter(entry.values()), None)
    entry = entry or manifest.get("main")
    return (home / entry).resolve() if entry else None
