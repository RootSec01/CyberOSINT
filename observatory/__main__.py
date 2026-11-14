from __future__ import annotations

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import report
from .probe import Observation, probe
from .registry import Endpoint, build_sample, http_fetcher
from .store import DATA_DIR, Archive


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cmd_sample(archive: Archive, args: argparse.Namespace) -> int:
    if archive.sample_path.exists() and not args.redraw:
        print(f"{archive.sample_path} already exists; the sample is drawn once. "
              "Pass --redraw only to start a new study.")
        return 1
    sample = build_sample(http_fetcher(), args.size,
                          progress=lambda n: print(f"  read {n} registry records", flush=True))
    path = archive.save_sample(sample)
    print(f"registry records read   {sample['records_read']}")
    print(f"current servers         {sample['current_servers']}")
    print(f"open remote endpoints   {sample['open_endpoints']} on {sample['distinct_hosts']} hosts")
    print(f"sampled                 {len(sample['endpoints'])} -> {path}")
    return 0


def take_snapshot(archive: Archive, endpoints: list[Endpoint], vantage: str,
                  workers: int = 8, allow_private: bool = False) -> dict:
    started_at = _utc_now()

    def observe(endpoint: Endpoint) -> Observation:
        seen = probe(endpoint, allow_private=allow_private)
        if seen.tools is not None:
            seen.manifest = archive.save_manifest(seen.tools)
        return seen

    observations = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for done, seen in enumerate(pool.map(observe, endpoints), start=1):
            observations.append(seen.as_record())
            if done % 50 == 0 or done == len(endpoints):
                print(f"  {done}/{len(endpoints)}", flush=True)
    return {"started_at": started_at, "finished_at": _utc_now(), "vantage": vantage,
            "observations": observations}


def cmd_snapshot(archive: Archive, args: argparse.Namespace) -> int:
    if not archive.sample_path.exists():
        print("No sample yet. Run: python3 -m observatory sample")
        return 1
    excluded = archive.excluded_hosts()
    endpoints = [Endpoint(**e) for e in archive.load_sample()["endpoints"]]
    endpoints = [e for e in endpoints if e.host not in excluded]
    if args.limit:
        endpoints = endpoints[:args.limit]
    run = take_snapshot(archive, endpoints, args.vantage, args.workers)
    path = archive.save_run(run)
    print(f"saved {path}")
    _print_summary(archive, run)
    return 0


def _print_summary(archive: Archive, run: dict) -> None:
    counts = report.outcome_counts(run)
    print(f"\n{run['started_at']}  vantage={run['vantage']}  endpoints={sum(counts.values())}")
    for outcome, count in counts.most_common():
        print(f"  {outcome:<15}{count:>5}")
    earlier = archive.previous_run(run)
    if earlier is None:
        print("\nFirst run on record; changes appear from the second run on.")
        return
    changes = report.manifest_changes(archive, earlier, run)
    print(f"\nagainst {earlier['started_at']} ({earlier['vantage']}): "
          f"{len(changes)} of {report.comparable(earlier, run)} comparable endpoints changed")
    for change in changes:
        parts = [f"+{len(change.added)}" if change.added else "",
                 f"-{len(change.removed)}" if change.removed else "",
                 f"~{len(change.redefined)}" if change.redefined else ""]
        print(f"  {change.url}  {' '.join(p for p in parts if p)}")


def cmd_status(archive: Archive, args: argparse.Namespace) -> int:
    paths = archive.run_paths()
    if not paths:
        print("No runs recorded yet.")
        return 1
    print(f"{len(paths)} run(s) on record")
    _print_summary(archive, archive.load_run(paths[-1]))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="observatory", description="Record what public MCP servers declare over time.")
    parser.add_argument("--data", type=Path, default=DATA_DIR, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)

    sample = commands.add_parser("sample", help="draw the fixed endpoint sample from the registry")
    sample.add_argument("--size", type=int, default=500)
    sample.add_argument("--redraw", action="store_true")
    sample.set_defaults(run=cmd_sample)

    snapshot = commands.add_parser("snapshot", help="record what every sampled endpoint declares")
    snapshot.add_argument("--vantage", default="local", help="label for where this run was made")
    snapshot.add_argument("--limit", type=int, help="only the first N endpoints (trial runs)")
    snapshot.add_argument("--workers", type=int, default=8)
    snapshot.set_defaults(run=cmd_snapshot)

    status = commands.add_parser("status", help="summarise the latest run")
    status.set_defaults(run=cmd_status)

    args = parser.parse_args(argv)
    return args.run(Archive(args.data), args)


if __name__ == "__main__":
    sys.exit(main())
