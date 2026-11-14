from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from raqeeb.declarations import compare

from .library import CATALOG, DATA_DIR, Library, load_catalog
from .match import identify


def cmd_build(library: Library, args: argparse.Namespace) -> int:
    from .build import build
    recorded = build(library, load_catalog(args.catalog), only=args.package,
                     latest=args.latest, workers=args.workers)
    print(f"{recorded} release(s) recorded")
    return 0


def cmd_history(library: Library, args: argparse.Namespace) -> int:
    previous = None
    for _, version, release in library.releases(args.package):
        manifest = library.manifests.load(release["manifest"])
        change = ""
        if previous is not None and previous != manifest:
            added, removed, redefined = compare(previous, manifest)
            parts = [f"+{', '.join(added)}" if added else "",
                     f"-{', '.join(removed)}" if removed else "",
                     f"~{len(redefined)} redefined" if redefined else ""]
            change = "  ".join(part for part in parts if part)
        elif previous is not None:
            change = "unchanged"
        print(f"{release['published'][:10]}  {version:<12}{release['tool_count']:>3} tools  {change}")
        previous = manifest
    if previous is None:
        print(f"No listed releases for {args.package}")
        return 1
    return 0


def cmd_summary(library: Library, args: argparse.Namespace) -> int:
    attempted = sum(len(entry["versions"]) for entry in library.packages.values())
    listed = transitions = changed = gained_tools = descriptions_only = 0
    previous_package = previous = None
    for package, _, release in library.releases():
        listed += 1
        manifest = library.manifests.load(release["manifest"])
        if package == previous_package:
            transitions += 1
            if manifest != previous:
                changed += 1
                added, removed, redefined = compare(previous, manifest)
                gained_tools += bool(added)
                descriptions_only += not added and not removed
        previous_package, previous = package, manifest
    print(f"packages                      {len(library.packages)}")
    print(f"releases attempted            {attempted}")
    print(f"releases that listed tools    {listed}")
    print(f"distinct manifests            {len(library.by_digest())}")
    print(f"release-to-release steps      {transitions}")
    print(f"  declarations changed        {changed}")
    print(f"  gained at least one tool    {gained_tools}")
    print(f"  only redefined existing     {descriptions_only}")
    return 0


def cmd_identify(library: Library, args: argparse.Namespace) -> int:
    tools = json.loads(args.manifest.read_text(encoding="utf-8"))
    if isinstance(tools, dict):
        tools = tools.get("tools") or (tools.get("result") or {}).get("tools") or []
    print(json.dumps(identify(library, tools).as_dict(), indent=1))
    return 0


def cmd_survey(library: Library, args: argparse.Namespace) -> int:
    from observatory.store import Archive
    archive = Archive(args.observatory)
    paths = archive.run_paths()
    if not paths:
        print("No observatory runs recorded yet.")
        return 1
    run = archive.load_run(paths[-1])
    verdicts: Counter = Counter()
    for observation in run["observations"]:
        if not observation.get("manifest"):
            continue
        found = identify(library, archive.load_manifest(observation["manifest"]))
        verdicts[found.verdict] += 1
        if found.package:
            detail = " ".join(f"{label}{len(names)}" for label, names in
                              (("+", found.added), ("-", found.absent), ("~", found.redefined)) if names)
            print(f"{found.verdict:<10}{observation['url']}  {found.package}@{found.versions[-1]}  {detail}")
    print(f"\n{run['started_at']}  {sum(verdicts.values())} endpoints with declared tools")
    for verdict, count in verdicts.most_common():
        print(f"  {verdict:<11}{count:>5}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reference", description="What published MCP server packages declare, by version.")
    parser.add_argument("--data", type=Path, default=DATA_DIR, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="install new releases and record their tools")
    build.add_argument("--catalog", type=Path, default=CATALOG)
    build.add_argument("--package", help="only this package")
    build.add_argument("--latest", type=int, help="only the newest N releases of each package")
    build.add_argument("--workers", type=int, default=4)
    build.set_defaults(run=cmd_build)

    summary = commands.add_parser("summary", help="size of the library and how often releases change")
    summary.set_defaults(run=cmd_summary)

    history = commands.add_parser("history", help="how a package's declared tools changed")
    history.add_argument("package")
    history.set_defaults(run=cmd_history)

    one = commands.add_parser("identify", help="compare a tools/list result with the library")
    one.add_argument("manifest", type=Path)
    one.set_defaults(run=cmd_identify)

    survey = commands.add_parser("survey", help="identify every server in the latest observatory run")
    survey.add_argument("--observatory", type=Path,
                        default=DATA_DIR.parent.parent / "observatory" / "data", help=argparse.SUPPRESS)
    survey.set_defaults(run=cmd_survey)

    args = parser.parse_args(argv)
    return args.run(Library(args.data), args)


if __name__ == "__main__":
    sys.exit(main())
