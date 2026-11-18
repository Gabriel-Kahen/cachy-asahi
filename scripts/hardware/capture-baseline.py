#!/usr/bin/env python3
"""Collect read-only facts; never infer a hardware validation PASS."""
import argparse
from functools import cache
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
from datetime import datetime, timezone
from types import ModuleType


SCOPES = {"pacman": "local", "hyprctl": "hypr", "wpctl": "audio", "git": "local"}
COMPLETE = {"observed", "query-warning", "query-failed", "query-denied"}


@cache
def session_probe():
    # Offline snapshot readers also import target_size from this file alone.
    path = Path(__file__).with_name("session_probe.py")
    probe = ModuleType("baseline_session_probe")
    probe.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), vars(probe))
    return probe


def command(argv, contexts):
    probe = session_probe()
    row = {"command": argv, "returncode": None}
    scope = SCOPES[argv[0]]
    if scope not in contexts:
        return dict(row, error="local-endpoint-unavailable")
    env, sockets = contexts[scope]
    before = [probe.socket_snapshot(path, owner) for path, owner in sockets]
    if any(identity is None for identity in before):
        return dict(row, error="local-endpoint-unavailable")
    actual = ["/usr/bin/" + argv[0], *argv[1:]]
    if argv[0] == "git":
        actual[1:1] = ["-c", "core.fsmonitor=false"]
        env = dict(env, GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    reason, code, stdout, stderr = probe.query(actual, 20, env)
    if before != [probe.socket_snapshot(path, owner) for path, owner in sockets]:
        return dict(row, error="local-endpoint-changed")
    if code is None or reason not in COMPLETE:
        return dict(row, error=reason)
    return dict(row, returncode=code, stdout=stdout.decode("utf-8", errors="replace").strip(),
                stderr=stderr.decode("utf-8", errors="replace").strip())


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
    has_j413 = "apple,j413" in identifiers
    has_j415 = "apple,j415" in identifiers
    if has_j413 and has_j415:
        return None
    if has_j413:
        return "13-inch"
    if has_j415:
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


def write_private(path, encoded):
    path = Path(os.path.abspath(path))
    if not path.name:
        raise ValueError("output filename required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    try:
        for part in path.parts[1:-1]:
            try:
                child = os.open(part, flags, dir_fd=parent)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(fd, 0o600)
            if os.fstat(fd).st_mode & 0o777 != 0o600:
                raise ValueError("output filesystem did not apply private permissions")
            output.write(encoded)
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New private file for the raw baseline")
    parser.add_argument("--operator", required=True, help="Operator name or pseudonym")
    parser.add_argument("--execution-context", choices=["physical", "virtual", "emulated", "unknown"], default="unknown")
    parser.add_argument("--require-m2-air", action="store_true")
    args = parser.parse_args()
    architecture = platform.machine()
    compatible = read_text("/proc/device-tree/compatible")
    size = target_size(architecture, compatible)
    contexts = session_probe().contexts(os.environ)
    record = {
        "schema_version": 1, "record_type": "environment-baseline",
        "collected_at": datetime.now(timezone.utc).isoformat(), "operator": args.operator,
        "execution_context": args.execution_context, "architecture": architecture,
        "machine_model": read_text("/proc/device-tree/model"), "device_tree_compatible": compatible,
        "m2_air_size": size, "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
        "kernel": platform.release(), "os_release": read_text("/etc/os-release"),
        "packages": command(["pacman", "-Q"], contexts),
        "repositories": repository_facts("/etc/pacman.conf", "/var/lib/pacman/sync"),
        "graphics": command(["hyprctl", "version"], contexts),
        "audio": command(["wpctl", "status"], contexts),
        "overlay_revision": command(["git", "-C", str(Path(__file__).resolve().parents[2]), "rev-parse", "HEAD"], contexts),
        "overlay_changes": command(["git", "-C", str(Path(__file__).resolve().parents[2]), "status", "--porcelain"], contexts),
        "validation_result": "NOT RUN",
        "limitations": ["Environment facts do not prove boot, rendering, speaker safety, sleep, recovery or performance.",
                        "Execution context is operator-supplied and requires independent review.",
                        "Repository artifacts must be retained separately for reproducible rebuilds."]}
    encoded = json.dumps(record, indent=2) + "\n"
    if args.output:
        try:
            write_private(args.output, encoded)
        except (OSError, ValueError) as error:
            print("Baseline output refused: " + (getattr(error, "strerror", None) or str(error)), file=sys.stderr)
            return 1
    else:
        sys.stdout.write(encoded)
    if args.require_m2_air and (size is None or args.execution_context != "physical"):
        print("Not a declared physical M2 Air baseline; hardware gates remain NOT RUN.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
