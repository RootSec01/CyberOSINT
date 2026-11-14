from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Optional

import manifest_fingerprint

DATA_DIR = Path(__file__).resolve().parent / "data"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    draft = path.with_name(f"{path.name}.{os.getpid()}-{threading.get_ident()}.part")
    draft.write_text(text, encoding="utf-8")
    os.replace(draft, path)


def canonical_tools(tools: list) -> list:
    return manifest_fingerprint.normalize({"tools": tools})["tools"]


def manifest_digest(tools: list) -> str:
    packed = json.dumps(canonical_tools(tools), sort_keys=True, ensure_ascii=False,
                        separators=(",", ":"), default=str)
    return hashlib.sha256(packed.encode("utf-8")).hexdigest()


class Archive:
    """Runs reference manifests by digest, so an unchanged server costs no new file."""

    def __init__(self, root: Path = DATA_DIR):
        self.root = Path(root)

    @property
    def sample_path(self) -> Path:
        return self.root / "sample.json"

    def save_sample(self, sample: dict) -> Path:
        _write(self.sample_path, json.dumps(sample, indent=1, ensure_ascii=False) + "\n")
        return self.sample_path

    def load_sample(self) -> dict:
        return json.loads(self.sample_path.read_text(encoding="utf-8"))

    def excluded_hosts(self) -> set[str]:
        path = self.root / "excluded_hosts.txt"
        if not path.exists():
            return set()
        lines = (line.split("#")[0].strip().lower() for line in path.read_text().splitlines())
        return {line for line in lines if line}

    def _manifest_path(self, digest: str) -> Path:
        return self.root / "manifests" / digest[:2] / f"{digest}.json"

    def save_manifest(self, tools: list) -> str:
        digest = manifest_digest(tools)
        path = self._manifest_path(digest)
        if not path.exists():
            _write(path, json.dumps(canonical_tools(tools), indent=1, sort_keys=True,
                                    ensure_ascii=False, default=str) + "\n")
        return digest

    def load_manifest(self, digest: str) -> list:
        return json.loads(self._manifest_path(digest).read_text(encoding="utf-8"))

    def save_run(self, run: dict) -> Path:
        stamp = run["started_at"].replace("-", "").replace(":", "")[:13] + "Z"
        path = self.root / "runs" / f"{stamp}-{run['vantage']}.json"
        _write(path, json.dumps(run, indent=1, ensure_ascii=False) + "\n")
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
