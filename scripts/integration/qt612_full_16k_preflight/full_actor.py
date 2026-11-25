# SPDX-License-Identifier: MIT
"""Run only a separately issued full-target Qtbase continuation."""

import argparse
import os
from pathlib import Path
from runpy import run_path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace


F = SimpleNamespace(**run_path(str(Path(__file__).with_name("full_capsule.py"))))
C, T, B = F.C, F.T, F.B
SOURCE, INPUTS, OUT = Path("/src"), Path("/inputs"), Path("/out")
HANDOFF, PLAN, SELECTION = (Path("/" + name) for name in ("handoff.json", "plan.json", "selection.json"))


def require_absence(nonce):
    token = ("qtbase-full-" + nonce).encode()
    for _ in range(2):
        end = time.monotonic() + 3
        with os.scandir("/proc") as processes:
            for count, entry in enumerate(processes, 1):
                C.need(count <= 131072 and time.monotonic() < end, "Owned process census exhausted")
                if not entry.name.isdecimal():
                    continue
                path = Path(entry.path)
                try:
                    if path.stat().st_uid != os.getuid():
                        continue
                    with (path / "cmdline").open("rb") as stream:
                        body = stream.read(131073)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                C.need(len(body) <= 131072 and token not in body.split(b"\0"), "Owned QEMU survived")
        time.sleep(0.02)


def verify_runtime(plan):
    root = Path("/sys/fs/cgroup")
    with (root / "memory.max").open() as stream:
        memory = stream.read(32)
    with (root / "memory.swap.max").open() as stream:
        swap = stream.read(32)
    with (root / "cpu.max").open() as stream:
        cpu = stream.read(64).split()
    C.need(memory == f"{plan['limits']['actor_memory_bytes']}\n" and swap == "0\n"
           and len(cpu) == 2 and all(value.isdecimal() for value in cpu)
           and int(cpu[1]) > 0 and int(cpu[0]) == 4 * int(cpu[1]),
           "Exact no-swap memory and CPU limits required")


def run(handoff, runner):
    plan, policy = runner.plan, runner.actor
    nonce = plan["nonce"]
    result, overlay = OUT / "result.raw", OUT / "overlay.qcow2"
    C.need(T.ordinary(OUT) == OUT and stat.S_IMODE(OUT.lstat().st_mode) == 0o700
           and {node.name for node in OUT.iterdir()} == {"result.raw"}
           and stat.S_IMODE(B.clean_file(result).st_mode) == 0o600, "Fresh private result clone required")
    F.verify_result_template(result, plan)
    uuid = plan["result_uuid"]
    runner.verify_tools()
    F.verify_inputs(INPUTS, plan)
    require_absence(nonce)
    start = F.capacity(OUT, plan)
    C.need(start["fits"] and time.time() < runner.issued["expires_utc"], "Full-build admission is no longer current")
    runner.watch = B.AllocationWatch(runner.runtime, policy, OUT, runner.deadline)
    before = runner.watch.record()
    C.need(before["free"] >= policy["admission_disk_bytes"] and runner.runtime.GUARD is None,
           "Unused owned runtime and current disk admission required")
    runner.runtime.GUARD = runner.watch
    try:
        create = runner.phase("overlay-create", policy["overlay_create"], 10)
        initial = B.clean_file(overlay).st_size
        F.K.inspect_overlay(overlay, {"bytes": initial}, "/inputs/gui.qcow2", "qcow2")
        inspect = runner.phase("overlay-inspect", policy["overlay_inspect"], 10)
        chain = T.read(OUT / "overlay-inspect.stdout", cap=16 * 1024)
        F.validate_chain(chain, {name: plan["inputs"][name]["bytes"] for name in
                                ("gui.qcow2", "core.qcow2", "scratch.raw")} | {"overlay.qcow2": initial})
        C.need(time.time() < runner.issued["expires_utc"], "Full-build entry window closed before QEMU")
        qemu = runner.phase("qemu", plan["qemu_argv"], plan["qemu_seconds"], file_cap=policy["child_file_size_cap"])
        require_absence(nonce)
        serial = T.read(OUT / "qemu.stdout", cap=policy["serial_combined_cap"])
        passed, phase = F.terminal(serial, nonce)
        fsck = runner.phase("fsck-result", ["/usr/bin/e2fsck", "-fn", str(result)], 60)
        C.need(F.result_uuid(result, policy["result_disk_bytes"]) == uuid, "Result UUID changed")
        F.verify_inputs(INPUTS, plan)
        F.verify_source(SOURCE, handoff)
        runner.verify_tools()
        end = F.capacity(OUT, plan)
        C.need(end["free_bytes"] >= policy["watched_tree"][2], "Live disk reserve exhausted")
        overlay_pin = T.read(overlay, cap=policy["child_file_size_cap"], collect=False)
        F.K.inspect_overlay(overlay, overlay_pin, "/inputs/gui.qcow2", "qcow2")
        result_pin = T.read(result, cap=policy["result_disk_bytes"], collect=False)
        C.need(overlay_pin["bytes"] >= initial and
               (not passed or overlay_pin["bytes"] > initial and result_pin != plan["inputs"]["result.raw"]),
               "Completed full build requires an original result and changed child")
        after = runner.watch.record()
        report = dict(kind="QTBASE_FULL16K_ACTOR_RESULT_V1", status="PASS_QTBASE_ALL_FOR_REVIEW" if passed else "HOLD",
                      phase=phase, nonce=nonce, authority_sha256=runner.authority_sha,
                      handoff_sha256=runner.handoff_sha, plan_sha256=handoff["plan"]["sha256"], tools=runner.tools,
                      watched_tree=policy["watched_tree"], watched_paths=policy["watched_paths"],
                      capacity_before=start, capacity_after=end,
                      allocation=dict(before=before, after=after, peak=runner.watch.peak, samples=runner.watch.samples),
                      qemu=qemu, serial=T.pin(serial), fsck_result=fsck, overlay_create=create, overlay_inspect=inspect,
                      overlay_inspect_stdout=T.pin(chain), overlay_initial_eof=initial, result_disk=result_pin,
                      overlay=overlay_pin, result_uuid=uuid,
                      native_Qt_full_build="NOT_RUN", physical_M2="NOT_RUN", Root_acceptance=None,
                      host_cgroup_memory_peak_bytes=cgroup_peak(plan["limits"]["actor_memory_bytes"]))
        stored = T.encoded(report)
        C.need(len(stored) <= 16 * 1024, "Finite full-build actor report required")
        report_path = OUT / "actor-result.json"
        created = False
        try:
            with report_path.open("xb") as file:
                created = True
                file.write(stored)
            runner.watch.record()
        except (OSError, ValueError, KeyboardInterrupt):
            if created:
                report_path.unlink()
            raise
        return 0 if passed else 2
    finally:
        runner.runtime.GUARD = None


def cgroup_peak(limit):
    with Path("/sys/fs/cgroup/memory.peak").open() as stream:
        body = stream.read(32)
    C.need(body.endswith("\n") and body[:-1].isdecimal() and 0 < int(body) <= limit,
           "Expected bounded original actor memory peak")
    return int(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    try:
        start = time.monotonic()
        C.need(os.environ.get("CACHY_ASAHI_QTBASE_FULL16K_ACTOR") == "1"
               and sys.flags.isolated and sys.dont_write_bytecode and __debug__,
               "Explicit isolated full-target actor required")
        os.umask(0o077)
        F.Q.O.actor_boundary(dict(inputs=INPUTS, output=OUT, handoff=HANDOFF, plan=PLAN, selection=SELECTION))
        body, _ = C.external(HANDOFF, 64 * 1024, args.handoff_sha256)
        handoff = C.json_body(body, canonical=True)
        plan = C.json_body(C.read(PLAN, 64 * 1024, handoff["plan"])[0], canonical=True)
        F.verify_documents(handoff, plan, SOURCE)
        raw = C.read(SELECTION, 16 * 1024)[0]
        issued = F.verify_selection(raw, args.authority_sha256, handoff, plan, args.handoff_sha256)
        verify_runtime(plan)
        runner = B.Runner(plan, handoff, args.handoff_sha256, args.authority_sha256, issued,
                          start + plan["attach_seconds"] - 90)
        return run(handoff, runner)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        sys.exit("Full Qtbase actor refused or held")


if __name__ == "__main__":
    raise SystemExit(main())
