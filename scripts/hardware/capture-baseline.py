#!/usr/bin/env python3
"""Collect read-only facts; never infer a hardware validation PASS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone


def command(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return {"command": argv, "returncode": result.returncode,
                "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": argv, "returncode": None, "error": str(error)}


def read_text(path):
    try:
        return Path(path).read_bytes().decode("utf-8", errors="replace").replace("\0", "\n").strip()
    except OSError:
        return None


def target_size(architecture, compatible):
    """Device-tree identifiers select records, not proof of physical execution."""
    if architecture != "aarch64":
        return None
    identifiers = (compatible or "").splitlines()
    if "apple,j413" in identifiers:
        return "13-inch"
    if "apple,j415" in identifiers:
        return "15-inch"
    return None


def repository_facts(config, database_dir):
    content = read_text(config)
    repositories = [] if content is None else re.findall(r"^\s*\[([^]]+)\]", content, re.M)
    databases = []
    for path in sorted(Path(database_dir).glob("*.db")):
        try:
            databases.append({"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                              "mtime_ns": path.stat().st_mtime_ns})
        except OSError as error:
            databases.append({"name": path.name, "error": str(error)})
    return {"configured_repositories": [name for name in repositories if name != "options"],
            "config_available": content is not None, "sync_databases": databases,
            "note": "Local sync databases only; not a complete repository snapshot."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--operator", required=True, help="Operator name or pseudonym")
    parser.add_argument("--execution-context", choices=["physical", "virtual", "emulated", "unknown"], default="unknown")
    parser.add_argument("--require-m2-air", action="store_true")
    args = parser.parse_args()
    architecture = platform.machine()
    compatible = read_text("/proc/device-tree/compatible")
    size = target_size(architecture, compatible)
    record = {
        "schema_version": 1, "record_type": "environment-baseline",
        "collected_at": datetime.now(timezone.utc).isoformat(), "operator": args.operator,
        "execution_context": args.execution_context, "architecture": architecture,
        "machine_model": read_text("/proc/device-tree/model"), "device_tree_compatible": compatible,
        "m2_air_size": size, "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
        "kernel": platform.release(), "os_release": read_text("/etc/os-release"),
        "packages": command(["pacman", "-Q"]),
        "repositories": repository_facts("/etc/pacman.conf", "/var/lib/pacman/sync"),
        "graphics": command(["hyprctl", "version"]),
        "audio": command(["wpctl", "status"]),
        "overlay_revision": command(["git", "-C", str(Path(__file__).resolve().parents[2]), "rev-parse", "HEAD"]),
        "overlay_changes": command(["git", "-C", str(Path(__file__).resolve().parents[2]), "status", "--porcelain"]),
        "validation_result": "NOT RUN",
        "limitations": ["Environment facts do not prove boot, rendering, speaker safety, sleep, recovery or performance.",
                        "Execution context is operator-supplied and requires independent review.",
                        "Repository artifacts must be retained separately for reproducible rebuilds."]}
    encoded = json.dumps(record, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as output:
            output.write(encoded)
    else:
        sys.stdout.write(encoded)
    if args.require_m2_air and (size is None or args.execution_context != "physical"):
        print("Not a declared physical M2 Air baseline; hardware gates remain NOT RUN.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
