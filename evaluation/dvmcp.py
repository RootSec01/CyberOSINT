"""Scan every Damn Vulnerable MCP Server challenge and score the result against expectations.

The expectations were written before any challenge was started. Only the handshake and
tools/list are sent; no challenge tool is called.

Usage: python3 -m evaluation.dvmcp --lab /path/to/damn-vulnerable-MCP-server
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from raqeeb import mcp_protocol, safe_proof

HERE = Path(__file__).resolve().parent
EXPECTATIONS = HERE / "dvmcp_expectations.json"
RESULTS = HERE / "dvmcp_results.json"
FIRST_PORT = 9000


def _wait_for_port(port: int, process: subprocess.Popen, seconds: float = 30.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and process.poll() is None:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


def _child_env(home: str, lab: Path) -> dict:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "PYTHONPATH": str(lab)}
    if os.name == "nt":
        # Windows cannot start Python (or open sockets) without these.
        for key in ("SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "USERPROFILE"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def scan_challenge(lab: Path, number: int, python: str) -> dict:
    scripts = list(lab.glob(f"challenges/*/challenge{number}/server.py"))
    if len(scripts) != 1:
        return {"started": False, "detail": "server.py not found"}
    port = FIRST_PORT + number
    with tempfile.TemporaryDirectory(prefix="raqeeb-dvmcp-") as home:
        process = subprocess.Popen(
            [python, str(scripts[0])], cwd=scripts[0].parent,
            env=_child_env(home, lab),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not _wait_for_port(port, process):
                return {"started": False, "detail": "did not listen in time"}
            server = mcp_protocol.verify_host("127.0.0.1", port, use_tls=False, paths=["/mcp"])
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
    if not server.get("is_mcp"):
        return {"started": True, "listed": False, "detail": "; ".join(server.get("errors") or [])}
    proof = safe_proof.build_safe_proof(server)
    return {"started": True, "listed": True, "tools": len(server.get("tools") or []),
            "severity": proof["severity"],
            "findings": sorted(proof["mcp_findings_summary"]["by_category"])}


def score(expected: dict, seen: dict) -> str:
    if not seen.get("listed"):
        return "not_scanned"
    if not expected["in_scope"]:
        return "out_of_scope"
    return "detected" if set(expected["expect_any"]) & set(seen["findings"]) else "missed"


def evaluate(lab: Path, python: str) -> dict:
    expectations = json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
    rows = []
    for expected in expectations["challenges"]:
        seen = scan_challenge(lab, expected["id"], python)
        rows.append({"id": expected["id"], "name": expected["name"],
                     "in_scope": expected["in_scope"],
                     "expected_any": expected.get("expect_any", []),
                     "outcome": score(expected, seen), **seen})
    in_scope = [row for row in rows if row["in_scope"]]
    revision = subprocess.run(["git", "-C", str(lab), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
    return {"lab": expectations["lab"], "lab_commit": revision,
            "expected_commit": expectations["commit"],
            "in_scope": len(in_scope),
            "detected": sum(row["outcome"] == "detected" for row in in_scope),
            "missed": sum(row["outcome"] == "missed" for row in in_scope),
            "out_of_scope": sum(row["outcome"] == "out_of_scope" for row in rows),
            "not_scanned": sum(row["outcome"] == "not_scanned" for row in rows),
            "challenges": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, required=True, help="checkout of the lab repository")
    parser.add_argument("--python", default=sys.executable,
                        help="interpreter that has the lab's requirements installed")
    parser.add_argument("--output", type=Path, default=RESULTS)
    args = parser.parse_args()
    # Each challenge starts in its own directory, so a relative interpreter path must be pinned
    # first. abspath keeps a virtualenv's bin/python symlink; resolve() would follow it out.
    python = os.path.abspath(args.python) if os.sep in args.python else args.python
    result = evaluate(args.lab.resolve(), python)
    args.output.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    for row in result["challenges"]:
        print(f"{row['id']:>2}  {row['outcome']:<13}{row['name']:<42}{', '.join(row.get('findings', []))}")
    print(f"\nin scope {result['in_scope']}: detected {result['detected']}, missed {result['missed']}; "
          f"out of scope {result['out_of_scope']}; not scanned {result['not_scanned']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
