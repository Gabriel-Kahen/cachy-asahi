# SPDX-License-Identifier: MIT
"""Run the QtCore capsule inside the expressly issued, owned offline actor."""

import argparse
import os
from pathlib import Path
import re
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import capsule as C

B, O, T = C.B, C.O, C.T
OUT, INPUTS, SOURCE = B.OUT, B.INPUTS, B.SOURCE
HANDOFF, PLAN, SELECTION = B.HANDOFF, B.PLAN, B.SELECTION


def terminal(serial, nonce):
    lines = [line for line in serial.splitlines() if line.startswith(b"QTCORE_LINK_TERMINAL ")]
    T.need(len(lines) == 1, "Exactly one original QtCore guest terminal required")
    pattern = rb"QTCORE_LINK_TERMINAL " + nonce.encode("ascii") + rb" (PASS|HOLD) ([a-z][a-z0-9_-]{0,31})"
    marker = re.fullmatch(pattern, lines[0])
    T.need(marker is not None and (marker[1] == b"HOLD" or marker[2] == b"complete"),
           "Exact same-nonce QtCore terminal required")
    return marker[1] == b"PASS", marker[2].decode("ascii")


def require_absence(nonce):
    token = ("qtcore-" + nonce).encode("ascii")
    for _ in range(2):
        deadline = time.monotonic() + 3
        with os.scandir("/proc") as entries:
            for count, entry in enumerate(entries, 1):
                T.need(count <= 131072 and time.monotonic() < deadline, "Owned QEMU census exhausted")
                if not entry.name.isdecimal():
                    continue
                path = Path(entry.path)
                try:
                    if path.stat().st_uid != os.getuid():
                        continue
                    with (path / "cmdline").open("rb") as stream:
                        command = stream.read(131073)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                T.need(len(command) <= 131072 and token not in command.split(b"\0"), "Surviving owned QtCore QEMU")
        time.sleep(0.02)


def memory_peak():
    try:
        with Path("/sys/fs/cgroup/memory.peak").open() as stream:
            raw = stream.read(64)
    except (FileNotFoundError, PermissionError):
        return None
    T.need(re.fullmatch(r"[1-9][0-9]{0,15}\n", raw) is not None, "Invalid actor memory peak counter")
    peak = int(raw)
    T.need(peak <= C.LIMITS["actor_memory_bytes"], "Actor memory peak exceeds the inspected cgroup limit")
    return peak


class LinkRunner(B.Runner):
    def run(self):
        result = OUT / "result.raw"
        T.need({path.name for path in OUT.iterdir()} == {"result.raw"}
               and stat.S_IMODE(B.clean_file(result).st_mode) == 0o600, "Fresh attempt-owned result clone required")
        C.check_pinned_file(result, self.plan["inputs"]["result.raw"])
        uuid = C.result_uuid(result)
        T.need(uuid == self.plan["result_uuid"], "Exact sealed result UUID required")
        self.verify_tools()
        self.verify_inputs()
        nonce = self.plan["nonce"]
        require_absence(nonce)
        before_capacity = C.capacity(OUT)
        T.need(before_capacity["fits"] and time.time() < self.issued["expires_utc"],
               "Fresh actor capacity and Root entry required")
        self.watch = B.AllocationWatch(self.runtime, self.actor, OUT, self.deadline)
        before = self.watch.record()
        T.need(before["free"] >= C.DISK_GATE and self.runtime.GUARD is None, "Unused owned runtime and live disk gate required")
        self.runtime.GUARD = self.watch
        try:
            create = self.phase("overlay-create", self.actor["overlay_create"], 10)
            overlay = OUT / "overlay.qcow2"
            initial_eof = B.clean_file(overlay).st_size
            inspect = self.phase("overlay-inspect", self.actor["overlay_inspect"], 10)
            inspect_output = T.read(OUT / "overlay-inspect.stdout", cap=16 << 10)
            C.P.validate_empty_overlay(inspect_output, initial_eof)
            T.need(time.time() < self.issued["expires_utc"], "Root entry window closed before QEMU")
            qemu = self.phase("qemu", self.plan["qemu_argv"], self.plan["qemu_seconds"],
                              file_cap=self.actor["child_file_size_cap"])
            require_absence(nonce)
            serial = T.read(OUT / "qemu.stdout", cap=self.actor["serial_combined_cap"])
            passed, phase = terminal(serial, nonce)
            fsck = self.phase("fsck-result", ["/usr/bin/e2fsck", "-fn", str(result)], 60)
            T.need(C.result_uuid(result) == uuid, "Original result UUID changed")
            self.verify_inputs()
            self.verify_tools()
            C.verify_source(self.data, SOURCE)
            after_capacity = C.capacity(OUT)
            T.need(after_capacity["free_bytes"] >= self.watch.tree[2], "Live reserve fell below the sealed minimum")
            overlay_pin = T.read(overlay, cap=self.actor["child_file_size_cap"], collect=False)
            result_pin = T.read(result, cap=self.actor["result_disk_bytes"], collect=False)
            T.need(overlay_pin["bytes"] >= initial_eof, "Original overlay shrank unexpectedly")
            if passed:
                T.need(overlay_pin["bytes"] > initial_eof and result_pin != self.plan["inputs"]["result.raw"],
                       "QtCore PASS requires a changed overlay and result disk")
            after = self.watch.record()
        finally:
            self.runtime.GUARD = None
        report = dict(kind="QTCORE_LINK_ACTOR_RESULT_V1", status="PASS_QTCORE_LINK_FOR_ROOT_REVIEW" if passed else "HOLD",
                      phase=phase, nonce=nonce, authority_sha256=self.authority_sha, handoff_sha256=self.handoff_sha,
                      plan_sha256=self.data["plan"]["sha256"], tools=self.tools, watched_tree=self.actor["watched_tree"],
                      watched_paths=self.actor["watched_paths"], capacity_before=before_capacity,
                      capacity_after=after_capacity, allocation=dict(before=before, after=after, peak=self.watch.peak,
                                                                    samples=self.watch.samples),
                      qemu=qemu, serial=T.pin(serial), fsck_result=fsck, overlay_create=create, overlay_inspect=inspect,
                      overlay_inspect_stdout=T.pin(inspect_output), overlay_initial_eof=initial_eof,
                      result_disk=result_pin, overlay=overlay_pin, result_uuid=uuid,
                      host_cgroup_memory_peak_bytes=memory_peak(), native_Qt_full_build="NOT_RUN",
                      physical_M2="NOT_RUN", Root_acceptance=None)
        body = T.encoded(report)
        T.need(len(body) <= 16 << 10, "Bounded actor report required")
        with (OUT / "actor-result.json").open("xb") as stream:
            stream.write(body)
        self.watch.record()
        return 0 if passed else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    T.need(os.environ.get("CACHY_ASAHI_QTBASE16K_ACTOR") == "1" and sys.flags.isolated
           and sys.dont_write_bytecode and __debug__, "Explicit isolated QtCore actor required")
    os.umask(0o077)
    deadline = time.monotonic() + C.ATTACH_SECONDS - 90
    O.actor_boundary(dict(inputs=INPUTS, output=OUT, handoff=HANDOFF, plan=PLAN, selection=SELECTION))
    data = C.load_handoff(HANDOFF, args.handoff_sha256)
    C.verify_source(data, SOURCE)
    plan = C.load_plan(PLAN, data["plan"]["sha256"])
    issued = C.verify_selection(T.read(SELECTION, cap=128 << 10), args.authority_sha256, data, plan,
                               args.handoff_sha256)
    return LinkRunner(plan, data, args.handoff_sha256, args.authority_sha256, issued, deadline).run()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit("QtCore actor refused: " + str(error)) from None
