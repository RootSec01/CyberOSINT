"""Aggregate figures across runs from one vantage: how many servers change, how, and what they declare."""
from __future__ import annotations

from collections import Counter

from . import report
from .store import Archive


def _share(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole else 0.0


def _day_to_day(archive: Archive, earlier: dict, later: dict) -> dict:
    changes = report.manifest_changes(archive, earlier, later)
    comparable = report.comparable(earlier, later)
    return {"from": earlier["started_at"], "to": later["started_at"], "comparable": comparable,
            "changed": len(changes), "share": _share(len(changes), comparable),
            "servers_adding_tools": sum(1 for c in changes if c.added),
            "servers_removing_tools": sum(1 for c in changes if c.removed),
            "servers_redefining_tools": sum(1 for c in changes if c.redefined),
            "tools_added": sum(len(c.added) for c in changes),
            "tools_removed": sum(len(c.removed) for c in changes),
            "tools_redefined": sum(len(c.redefined) for c in changes)}


def _whole_period(runs: list[dict]) -> dict:
    listed = [{o["id"]: o["manifest"] for o in run["observations"] if o.get("manifest")} for run in runs]
    always = set(listed[0]).intersection(*listed[1:])
    changed = sum(1 for endpoint in always if len({run[endpoint] for run in listed}) > 1)
    return {"from": runs[0]["started_at"], "to": runs[-1]["started_at"], "runs": len(runs),
            "listed_tools_in_every_run": len(always), "changed_at_least_once": changed,
            "share": _share(changed, len(always))}


def _outcomes(run: dict) -> dict:
    counts = Counter(o["outcome"] for o in run["observations"])
    failing = sum(1 for o in run["observations"]
                  if o["outcome"] == "not_mcp" and (o.get("http_status") or 0) >= 500)
    return {"endpoints": sum(counts.values()), **dict(sorted(counts.items())),
            "not_mcp_server_error": failing, "not_mcp_other": counts.get("not_mcp", 0) - failing}


def _declarations(archive: Archive, run: dict) -> dict:
    from raqeeb.mcp_detectors import run_detectors

    servers = tools = 0
    servers_with: Counter = Counter()
    tools_with: Counter = Counter()
    for observation in run["observations"]:
        if not observation.get("manifest"):
            continue
        declared = archive.load_manifest(observation["manifest"])
        servers += 1
        tools += len(declared)
        findings = run_detectors({"tools": declared, "auth_required": False})
        for rule in {(f["category"], f["title"]) for f in findings}:
            servers_with[rule] += 1
        for rule in Counter((f["category"], f["title"]) for f in findings if f.get("affected_tool")).items():
            tools_with[rule[0]] += rule[1]
    rules = [{"category": category, "finding": title, "servers": count,
              "share_of_servers": _share(count, servers), "tools": tools_with.get((category, title), 0)}
             for (category, title), count in servers_with.most_common()]
    return {"run": run["started_at"], "servers": servers, "tools": tools, "rules": rules,
            "note": "Counts of what the rules match in public declarations. They are not confirmed weaknesses."}


def analyse(archive: Archive, vantage: str) -> dict:
    runs = [run for run in map(archive.load_run, archive.run_paths()) if run["vantage"] == vantage]
    if not runs:
        raise ValueError(f"no runs recorded from vantage {vantage!r}")
    return {"vantage": vantage, "runs": [run["started_at"] for run in runs],
            "latest": _outcomes(runs[-1]),
            "day_to_day": [_day_to_day(archive, a, b) for a, b in zip(runs, runs[1:])],
            "period": _whole_period(runs) if len(runs) > 1 else None,
            "declarations": _declarations(archive, runs[-1])}


def summary(result: dict) -> str:
    latest = result["latest"]
    lines = [f"{len(result['runs'])} run(s) from {result['vantage']}, latest {result['runs'][-1]}",
             f"  listed tools without credentials  {latest.get('ok', 0)} of {latest['endpoints']}",
             f"  asked for authentication          {latest.get('auth_required', 0)}",
             f"  not answering as MCP              {latest.get('not_mcp', 0)} "
             f"({latest['not_mcp_server_error']} with a server error)",
             f"  unreachable                       {latest.get('unreachable', 0)}", ""]
    for step in result["day_to_day"]:
        lines.append(f"{step['from'][:10]} to {step['to'][:10]}: {step['changed']} of {step['comparable']} changed "
                     f"({step['share']:.1%}); servers adding {step['servers_adding_tools']}, "
                     f"removing {step['servers_removing_tools']}, redefining {step['servers_redefining_tools']}")
    period = result["period"]
    if period:
        lines.append(f"whole period: {period['changed_at_least_once']} of {period['listed_tools_in_every_run']} "
                     f"changed at least once ({period['share']:.1%})")
    declared = result["declarations"]
    lines += ["", f"rules over {declared['servers']} servers and {declared['tools']} tools (matches, not confirmed weaknesses):"]
    lines += [f"  {rule['servers']:>4} servers ({rule['share_of_servers']:.1%})  {rule['tools']:>5} tools  {rule['finding']}"
              for rule in declared["rules"]]
    return "\n".join(lines)
