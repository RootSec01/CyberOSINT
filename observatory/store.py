from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from raqeeb.declarations import ManifestStore, write_json

DATA_DIR = Path(__file__).resolve().parent / "data"


class Archive:
    """Runs refer to manifests by digest, so an unchanged server costs no new file."""

    def __init__(self, root: Path = DATA_DIR):
        self.root = Path(root)
        self.manifests = ManifestStore(self.root / "manifests")

    @property
    def sample_path(self) -> Path:
        return self.root / "sample.json"

    def save_sample(self, sample: dict) -> Path:
        write_json(self.sample_path, sample)
        return self.sample_path

    def load_sample(self) -> dict:
        return json.loads(self.sample_path.read_text(encoding="utf-8"))

    def excluded_hosts(self) -> set[str]:
        path = self.root / "excluded_hosts.txt"
        if not path.exists():
            return set()
        lines = (line.split("#")[0].strip().lower() for line in path.read_text().splitlines())
        return {line for line in lines if line}

    def save_manifest(self, tools: list) -> str:
        return self.manifests.save(tools)

    def load_manifest(self, digest: str) -> list:
        return self.manifests.load(digest)

    def save_run(self, run: dict) -> Path:
        stamp = run["started_at"].replace("-", "").replace(":", "")[:13] + "Z"
        path = self.root / "runs" / f"{stamp}-{run['vantage']}.json"
        write_json(path, run)
        return path

    def run_paths(self) -> list[Path]:
        return sorted((self.root / "runs").glob("*.json"))

    def load_run(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def previous_run(self, run: dict) -> Optional[dict]:
        earlier = [self.load_run(p) for p in self.run_paths()]
        earlier = [r for r in earlier if r["started_at"] < run["started_at"]]
        same_vantage = [r for r in earlier if r["vantage"] == run["vantage"]]
        pool = same_vantage or earlier
        return pool[-1] if pool else None
