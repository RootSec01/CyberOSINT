"""Score the declaration detectors on MCPTox poisoned tools and on real published tools.

Each poisoned tool is declared on its own server, next to the names of that server's real
tools, as an agent would see it. The split into development and held-out servers, and
what counts as an alarm, are fixed in mcptox_split.json and mcptox_protocol.json.

Usage: python3 -m evaluation.mcptox --benchmark /path/to/MCPTox-Benchmark
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from raqeeb import mcp_detectors
from raqeeb.declarations import pack
from reference.library import Library

HERE = Path(__file__).resolve().parent
PROTOCOL = HERE / "mcptox_protocol.json"
SPLIT = HERE / "mcptox_split.json"
RESULTS = HERE / "mcptox_results.json"
ALARMS = {"tool_poisoning", "prompt_injection"}
NO_ARGUMENTS = {"type": "object", "properties": {}}


def alarmed_tools(tools: list) -> set[str]:
    findings = mcp_detectors.run_detectors({"auth_required": True, "tools": tools})
    return {finding["affected_tool"] for finding in findings
            if finding["category"] in ALARMS and finding["affected_tool"]}


def poisoned_cases(benchmark: Path) -> list[dict]:
    servers = json.loads((benchmark / "response_all.json").read_text(encoding="utf-8"))["servers"]
    entries = json.loads((benchmark / "pure_tool.json").read_text(encoding="utf-8"))
    cases = []
    for server in entries:
        for entry_id, entry in server.items():
            real_names = servers[entry["server_name"]]["tool_names"]
            neighbours = [{"name": name, "description": "", "inputSchema": NO_ARGUMENTS}
                          for name in real_names if name != entry["tool_name"]]
            poisoned = {"name": entry["tool_name"], "description": entry["tool_content"],
                        "inputSchema": NO_ARGUMENTS}
            cases.append({"id": entry_id, "server": entry["server_name"],
                          "template": entry["paradigm"], "tools": neighbours + [poisoned],
                          "poisoned": entry["tool_name"]})
    return cases


def score_poisoned(cases: list[dict]) -> dict:
    total, caught, missed = Counter(), Counter(), []
    for case in cases:
        total[case["template"]] += 1
        if case["poisoned"] in alarmed_tools(case["tools"]):
            caught[case["template"]] += 1
        else:
            missed.append(case["id"])
    detected = sum(caught.values())
    return {"servers": len({case["server"] for case in cases}),
            "poisoned_tools": len(cases), "detected": detected,
            "recall": _rate(detected, len(cases)),
            "by_template": {name: {"poisoned_tools": total[name], "detected": caught[name],
                                   "recall": _rate(caught[name], total[name])}
                            for name in sorted(total)},
            "missed_entries": sorted(missed)}


def score_published(library: Library, packages: set[str]) -> dict:
    """False alarms over every distinct tool the packages ever shipped, judged in its manifest."""
    alarmed: dict[str, bool] = defaultdict(bool)
    names: dict[str, tuple[str, str]] = {}
    scored: set[str] = set()
    for package, _, release in library.releases():
        if package not in packages or release["manifest"] in scored:
            continue
        scored.add(release["manifest"])
        tools = library.tools(release["manifest"])
        flagged = alarmed_tools(tools)
        for tool in tools:
            key = pack(tool)
            names[key] = (package, tool["name"])
            alarmed[key] |= tool["name"] in flagged
    false_alarms = sorted({names[key] for key, hit in alarmed.items() if hit})
    count = sum(alarmed.values())
    return {"packages": len(packages), "published_tools": len(alarmed), "false_alarms": count,
            "false_alarm_rate": _rate(count, len(alarmed)),
            "false_alarm_tools": [f"{package}: {tool}" for package, tool in false_alarms]}


def _rate(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def evaluate(benchmark: Path, library: Library) -> dict:
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    split = json.loads(SPLIT.read_text(encoding="utf-8"))
    development_servers = set(split["poisoned"]["development_servers"])
    development_packages = set(split["clean"]["development_packages"])

    cases = poisoned_cases(benchmark)
    held_out_cases = [case for case in cases if case["server"] not in development_servers]
    development_cases = [case for case in cases if case["server"] in development_servers]
    all_packages = set(library.packages)

    revision = subprocess.run(["git", "-C", str(benchmark), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
    return {
        "benchmark": protocol["benchmark"], "benchmark_commit": revision,
        "expected_commit": protocol["commit"],
        "held_out": {**score_poisoned(held_out_cases),
                     "clean": score_published(library, all_packages - development_packages)},
        "development": {**score_poisoned(development_cases),
                        "clean": score_published(library, all_packages & development_packages)},
        "first_run": protocol["first_run"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, required=True,
                        help="checkout of the MCPTox-Benchmark repository")
    parser.add_argument("--output", type=Path, default=RESULTS)
    args = parser.parse_args()
    result = evaluate(args.benchmark.resolve(), Library())
    args.output.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    for label in ("held_out", "development"):
        part = result[label]
        clean = part["clean"]
        print(f"{label:<12} servers {part['servers']:>2}  poisoned {part['poisoned_tools']:>3}"
              f"  detected {part['detected']:>3}  recall {part['recall']:.1%}"
              f"  | published tools {clean['published_tools']:>4}  false alarms {clean['false_alarms']:>2}")
        for template, row in part["by_template"].items():
            print(f"  {template:<12} {row['detected']:>3} of {row['poisoned_tools']:>3}  {row['recall']:.1%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
