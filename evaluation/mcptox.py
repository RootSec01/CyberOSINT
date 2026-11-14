"""Score the declaration detectors on MCPTox poisoned tools and on real published tools.

The protocol (what counts as an alarm, which sets are scored) is in mcptox_protocol.json and
was written before the detectors were run on the benchmark.

Usage: python3 -m evaluation.mcptox --benchmark /path/to/MCPTox-Benchmark
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from raqeeb import mcp_detectors
from raqeeb.declarations import pack
from reference.library import Library

HERE = Path(__file__).resolve().parent
PROTOCOL = HERE / "mcptox_protocol.json"
RESULTS = HERE / "mcptox_results.json"
ALARMS = {"tool_poisoning", "prompt_injection"}


def raises_alarm(tool: dict) -> bool:
    findings = mcp_detectors.run_detectors({"auth_required": True, "tools": [tool]})
    return any(finding["category"] in ALARMS for finding in findings)


def poisoned_tools(benchmark: Path) -> list[tuple[str, str, dict]]:
    """(entry id, attack template, declaration) for every poisoned tool in the benchmark."""
    servers = json.loads((benchmark / "pure_tool.json").read_text(encoding="utf-8"))
    return [(entry_id, entry["paradigm"],
             {"name": entry["tool_name"], "description": entry["tool_content"],
              "inputSchema": {"type": "object", "properties": {}}})
            for server in servers for entry_id, entry in server.items()]


def published_tools(library: Library) -> list[dict]:
    distinct = {}
    for digest in library.by_digest():
        for tool in library.tools(digest):
            distinct[pack(tool)] = tool
    return list(distinct.values())


def _rate(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def evaluate(benchmark: Path, library: Library) -> dict:
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    positives = poisoned_tools(benchmark)
    caught = {entry_id for entry_id, _, tool in positives if raises_alarm(tool)}
    total = Counter(template for _, template, _ in positives)
    hit = Counter(template for entry_id, template, _ in positives if entry_id in caught)

    negatives = published_tools(library)
    false_alarms = sorted(tool["name"] for tool in negatives if raises_alarm(tool))

    revision = subprocess.run(["git", "-C", str(benchmark), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
    return {
        "benchmark": protocol["benchmark"], "benchmark_commit": revision,
        "expected_commit": protocol["commit"],
        "poisoned_tools": len(positives), "detected": len(caught),
        "recall": _rate(len(caught), len(positives)),
        "by_template": {template: {"poisoned_tools": total[template], "detected": hit[template],
                                   "recall": _rate(hit[template], total[template])}
                        for template in sorted(total)},
        "published_tools": len(negatives), "false_alarms": len(false_alarms),
        "false_alarm_rate": _rate(len(false_alarms), len(negatives)),
        "false_alarm_tools": false_alarms,
        "missed_entries": sorted(entry_id for entry_id, _, _ in positives if entry_id not in caught),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, required=True,
                        help="checkout of the MCPTox-Benchmark repository")
    parser.add_argument("--output", type=Path, default=RESULTS)
    args = parser.parse_args()
    result = evaluate(args.benchmark.resolve(), Library())
    args.output.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(f"poisoned tools   {result['poisoned_tools']:>5}  detected {result['detected']:>5}"
          f"  recall {result['recall']:.1%}")
    for template, row in result["by_template"].items():
        print(f"  {template:<14} {row['poisoned_tools']:>5}  detected {row['detected']:>5}"
              f"  recall {row['recall']:.1%}")
    print(f"published tools  {result['published_tools']:>5}  false alarms {result['false_alarms']:>3}"
          f"  rate {result['false_alarm_rate']:.2%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
