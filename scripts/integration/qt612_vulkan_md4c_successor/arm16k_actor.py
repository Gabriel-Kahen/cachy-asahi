#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the successor VM inside its offline rootless container."""

import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import time


OUT = Path("/out")
CGROUP = Path("/sys/fs/cgroup")
TOOL_ROOT = Path("/usr/bin")
GIB = 1 << 30


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pin(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        start = os.fstat(stream.fileno())
        need(stat.S_ISREG(start.st_mode), f"Expected a regular file: {path}")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    end = path.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns")
    need(all(getattr(start, field) == getattr(after, field) == getattr(end, field) for field in fields),
         f"File changed during read: {path}")
    return dict(bytes=start.st_size, sha256=digest)


def command(tool, *args):
    return subprocess.run([TOOL_ROOT / tool, *args], capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=60, check=True).stdout


def inspect_chain(path, fresh=False):
    chain = json.loads(command("qemu-img", "info", "--output=json", "--backing-chain", path))
    need(len(chain) == 2, "Expected exactly one disposable child and one raw backing")
    top, backing = chain
    need(top["filename"] == str(path) and top["format"] == "qcow2"
         and top["virtual-size"] == 16 * GIB
         and top["backing-filename"] == top["full-backing-filename"] == "/inputs/scratch.raw"
         and top["backing-filename-format"] == "raw"
         and not top["dirty-flag"] and not top["format-specific"]["data"]["corrupt"]
         and not top.get("snapshots") and not top.get("encrypted")
         and backing["filename"] == "/inputs/scratch.raw" and backing["format"] == "raw"
         and backing["virtual-size"] == 16 * GIB and not backing["dirty-flag"]
         and (not fresh or path.stat().st_size <= 1 << 20),
         "Unexpected successor disk chain")
    return chain


def run(plan):
    limits = plan["limits"]
    need({item.name for item in OUT.iterdir()} == {"result.raw"}, "Expected a fresh run directory")
    need((CGROUP / "memory.max").read_text().strip() == str(limits["container_bytes"])
         and (CGROUP / "memory.swap.max").read_text().strip() == "0",
         "Container memory/no-swap limits differ")
    quota, period = (CGROUP / "cpu.max").read_text().split()
    need(int(quota) == limits["vcpus"] * int(period), "Container CPU quota differs")
    need({item.name for item in Path("/sys/class/net").iterdir()} == {"lo"}, "Container has a network device")
    for filename, expected in plan["tools"].items():
        need(pin(TOOL_ROOT / filename) == expected, f"Image tool differs: {filename}")

    result = OUT / "result.raw"
    overlay = OUT / "overlay.qcow2"
    need(pin(result) == plan["result_template"], "Result disk template differs")
    command("qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw", "-b",
            "/inputs/scratch.raw", overlay)
    initial = inspect_chain(overlay, fresh=True)
    deadline = time.monotonic() + limits["qemu_seconds"]
    previous = deadline - limits["qemu_seconds"]
    peak_overlay = overlay.stat().st_size
    lowest_free = os.statvfs(OUT).f_bavail * os.statvfs(OUT).f_frsize

    def stop(signum, _frame):
        raise InterruptedError(f"Actor interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cap = limits["overlay_bytes"]
    resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
    reason = None
    with (OUT / "serial.log").open("xb") as serial:
        proc = subprocess.Popen(plan["qemu_argv"], stdin=subprocess.DEVNULL,
                                stdout=serial, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while proc.poll() is None:
                time.sleep(0.5)
                usage = os.statvfs(OUT)
                lowest_free = min(lowest_free, usage.f_bavail * usage.f_frsize)
                peak_overlay = max(peak_overlay, overlay.stat().st_size)
                need(lowest_free >= limits["host_disk_reserve_bytes"], "Host disk reserve exhausted")
                need(serial.tell() <= limits["serial_bytes"], "Serial capture exceeded its ceiling")
                need(result.stat().st_size == limits["result_bytes"], "Result disk size changed")
                need(time.monotonic() < deadline, "QEMU deadline expired")
        except (OSError, ValueError) as error:
            reason = str(error)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=15)

    fsck = subprocess.run([TOOL_ROOT / "e2fsck", "-fn", result], capture_output=True, timeout=60)
    (OUT / "result-fsck.log").write_bytes(fsck.stdout + fsck.stderr)
    final = inspect_chain(overlay)
    actor = dict(kind="QTBASE_SUCCESSOR16K_ACTOR_V1", nonce=plan["nonce"], qemu_exit=proc.returncode,
                 process_reaped=True, error=reason, elapsed_seconds=round(time.monotonic() - previous, 3),
                 peak_overlay_bytes=max(peak_overlay, overlay.stat().st_size), lowest_host_free_bytes=lowest_free,
                 memory_peak_bytes=int((CGROUP / "memory.peak").read_text()),
                 initial_chain=initial, final_chain=final, fsck_exit=fsck.returncode)
    (OUT / "actor.json").write_text(json.dumps(actor, sort_keys=True) + "\n")
    return 0 if proc.returncode == fsck.returncode == 0 and reason is None else 2


if __name__ == "__main__":
    os.umask(0o077)
    try:
        body = Path("/input-plan.json").read_bytes()
        need(len(body) <= 128 << 10 and hashlib.sha256(body).hexdigest() == sys.argv[1], "Plan digest differs")
        plan = json.loads(body)
        need(plan["kind"] == "QTBASE_SUCCESSOR16K_PLAN_V1" and pin(Path(__file__)) == plan["actor"],
             "Actor source or plan differs")
        sys.exit(run(plan))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
