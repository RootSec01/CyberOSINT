# nmap_integration.py
import os
import subprocess
from typing import Dict, Any, List


def run_nmap_basic(
    ip: str,
    out_dir: str,
    ports: str = "22,80,443,3389",
    extra_args: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Run a very small, non-destructive Nmap scan against a lab IP.
    This function assumes the caller has already checked that the IP
    is allowed for active testing.
    """
    cmd = ["nmap", "-sV", "-Pn", "-T4", f"-p{ports}", "--open", ip]
    if extra_args:
        cmd.extend(extra_args)

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"nmap_{ip.replace('.', '_')}.txt")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:
        return {
            "enabled": False,
            "error": str(e),
            "command": cmd,
        }

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(proc.stdout)
    except Exception:
        # Failing to write the file should not break the API.
        pass

    # Provide a short preview for the UI
    preview_lines = proc.stdout.splitlines()[:25]

    return {
        "enabled": True,
        "command": cmd,
        "exit_code": proc.returncode,
        "preview": preview_lines,
        "output_path": out_path,
    }
