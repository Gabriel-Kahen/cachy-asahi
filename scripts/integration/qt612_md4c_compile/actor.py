# SPDX-License-Identifier: MIT
"""Root-owned, bounded continuation of a sealed Q3 scratch disk."""

import argparse
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time
from uuid import UUID

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import (ATTACH_SECONDS, O, P, T, capacity, check_pinned_file, load_envelope, read_plan,
                    verify_selection, verify_source)

validate_empty_overlay = P.validate_empty_overlay

OUT = Path("/out")
INPUTS = Path("/inputs")
SOURCE = Path("/src")
HANDOFF = Path("/handoff.json")
PLAN = Path("/plan.json")
SELECTION = Path("/selection.json")
LABELS = ("overlay-create", "overlay-inspect", "qemu", "fsck-result")
BLOCKS = ("tree_allocated", "overlay_allocated", "overlay_eof", "result_allocated")
ALLOWED = {"result.raw", "overlay.qcow2", "actor-result.json"} | {
    label + "." + ext for label in LABELS for ext in ("stdout", "stderr", "json", "log")}


def clean_file(path):
    info = path.lstat()
    T.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Expected one ordinary file: " + path.name)
    return info


def result_uuid(path, size):
    info = clean_file(path)
    T.need(info.st_size == size, "Result image geometry differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        current = os.fstat(fd)
        T.need((current.st_dev, current.st_ino, current.st_size) == (info.st_dev, info.st_ino, size),
               "Result inode changed while reading superblock")
        data = os.pread(fd, 1024, 1024)
    finally:
        os.close(fd)
    T.need(len(data) == 1024 and data[56:58] == b"\x53\xef" and data[120:136].rstrip(b"\0") == b"QT16K_MD4C"
           and struct.unpack_from("<I", data, 24)[0] == 2
           and struct.unpack_from("<I", data, 4)[0] * 4096 == size
           and struct.unpack_from("<I", data, 336)[0] == 0,
           "Expected fixed 4K-block ext4 result volume")
    return str(UUID(bytes=data[104:120]))


def terminal(serial, nonce):
    rows = [line for line in serial.splitlines() if line.startswith(b"QTMD4C16K ")]
    T.need(len(rows) == 1, "Exactly one bounded guest terminal marker required")
    marker = re.fullmatch(rb"QTMD4C16K " + nonce.encode() + rb" (PASS|HOLD) (boot|storage|compile|complete)", rows[0])
    T.need(marker is not None and (marker[1] == b"HOLD" or marker[2] == b"complete"),
           "Guest terminal marker or stage differs")
    return marker[1] == b"PASS", marker[2].decode()


def require_absence(nonce):
    token = ("qtmd4c-" + nonce).encode()
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
                        cmdline = stream.read(131073)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                T.need(len(cmdline) <= 131072 and token not in cmdline.split(b"\0"), "Possible surviving owned QEMU")
        time.sleep(0.02)


class AllocationWatch:
    def __init__(self, runtime, actor, out, deadline):
        self.runtime, self.actor, self.out, self.deadline = runtime, actor, out, deadline
        self.tree = (out, *actor["watched_tree"][1:])
        self.paths = tuple((out / Path(name).name, cap) for name, cap in actor["watched_paths"])
        original = clean_file(out / "result.raw")
        self.result_identity = (original.st_dev, original.st_ino)
        self.overlay_identity = None
        self.last, self.samples, self.peak = 0, 0, None

    def __call__(self):
        if time.monotonic() - self.last >= 0.5:
            self.record()

    def record(self):
        T.need(time.monotonic() < self.deadline, "Actual actor time envelope exhausted")
        leaves = {path.name for path in self.out.iterdir()}
        T.need(leaves <= ALLOWED and "result.raw" in leaves, "Unexpected writable actor output")
        for leaf in leaves:
            clean_file(self.out / leaf)
        result = clean_file(self.out / "result.raw")
        T.need((result.st_dev, result.st_ino) == self.result_identity and result.st_size == self.actor["result_disk_bytes"],
               "Original result clone inode or geometry changed")
        overlay = clean_file(self.out / "overlay.qcow2") if "overlay.qcow2" in leaves else None
        identity = (overlay.st_dev, overlay.st_ino) if overlay else None
        T.need(self.overlay_identity is None or identity == self.overlay_identity,
               "Owned overlay inode changed")
        self.overlay_identity = identity
        volumes = os.statvfs(self.out)
        tree = self.runtime.allocated(self.out, deadline=self.deadline)
        self.runtime.component_limits(self.out, self.paths)
        row = dict(tree_allocated=tree, overlay_allocated=overlay.st_blocks * 512 if overlay else 0,
                   overlay_eof=overlay.st_size if overlay else 0, result_allocated=result.st_blocks * 512,
                   free=volumes.f_bavail * volumes.f_frsize)
        T.need(row["tree_allocated"] <= self.tree[1] and row["free"] >= self.tree[2]
               and row["overlay_eof"] <= self.actor["child_file_size_cap"],
               "Owned output allocation, overlay file bound, or live reserve failed")
        if self.peak is None:
            self.peak = row.copy()
        else:
            for key in BLOCKS:
                self.peak[key] = max(row[key], self.peak[key])
            self.peak["free"] = min(row["free"], self.peak["free"])
        self.last, self.samples = time.monotonic(), self.samples + 1
        return row


class Runner:
    def __init__(self, plan, data, handoff_sha, authority_sha, issued, deadline):
        self.plan, self.data = plan, data
        self.handoff_sha, self.authority_sha, self.issued = handoff_sha, authority_sha, issued
        self.deadline = deadline
        self.runtime = O.module(O.PERL / "runtime.py")
        self.actor = plan["actor"]
        self.tools = self.actor["profile"]["tools"]
        self.watch = None

    def verify_tools(self):
        observed = O.tool_pins() | {"/usr/bin/qemu-img": self.runtime.image_tool_pin("/usr/bin/qemu-img")}
        T.need(observed == self.tools, "Exact six immutable image tool bytes required")

    def verify_inputs(self):
        names = set(self.plan["inputs"]) - {"result.raw"}
        T.need({path.name for path in INPUTS.iterdir()} == names, "Exact read-only compiler inputs required")
        for name in sorted(names):
            path = INPUTS / name
            info = clean_file(path)
            T.need(stat.S_IMODE(info.st_mode) == 0o444, "Expected read-only operand: " + name)
            check_pinned_file(path, self.plan["inputs"][name])

    def phase(self, label, argv, seconds, *, file_cap=None):
        self.watch.record()
        self.runtime.command(argv, OUT, label, seconds=seconds,
                             deadline=min(self.deadline, time.monotonic() + seconds),
                             child_file_size_cap=file_cap, watched_tree=self.watch.tree, watched_paths=self.watch.paths)
        self.watch.record()
        path = OUT / (label + ".json")
        receipt = self.runtime.receipt(path)
        T.need(self.runtime.natural(receipt) and receipt["argv"] == argv
               and receipt["child_file_size_cap"] == file_cap, "Exact natural retirement required: " + label)
        return T.read(path, cap=128 << 10, collect=False)

    def run(self):
        result = OUT / "result.raw"
        T.need({path.name for path in OUT.iterdir()} == {"result.raw"}
               and stat.S_IMODE(clean_file(result).st_mode) == 0o600, "Fresh attempt-owned result clone required")
        check_pinned_file(result, self.plan["inputs"]["result.raw"])
        uuid = result_uuid(result, self.actor["result_disk_bytes"])
        T.need(uuid == self.data["result_uuid"], "Result clone must use the sealed UUID")
        self.verify_tools()
        self.verify_inputs()
        nonce = self.plan["nonce"]
        require_absence(nonce)
        before_capacity = capacity(OUT)
        T.need(before_capacity["fits"] and time.time() < self.issued["expires_utc"],
               "Fresh actor admission or Root authority window expired")
        self.watch = AllocationWatch(self.runtime, self.actor, OUT, self.deadline)
        before = self.watch.record()
        T.need(before["free"] >= self.actor["admission_disk_bytes"], "Actor disk admission changed before creation")
        prior_guard = self.runtime.GUARD
        T.need(prior_guard is None, "Expected unused owned runtime")
        self.runtime.GUARD = self.watch
        try:
            create = self.phase("overlay-create", self.actor["overlay_create"], 10)
            overlay = OUT / "overlay.qcow2"
            initial_eof = clean_file(overlay).st_size
            inspect = self.phase("overlay-inspect", self.actor["overlay_inspect"], 10)
            overlay_inspect = T.read(OUT / "overlay-inspect.stdout", cap=16 << 10)
            validate_empty_overlay(overlay_inspect, initial_eof)
            T.need(time.time() < self.issued["expires_utc"], "Root authority expired before QEMU")
            qemu = self.phase("qemu", self.plan["qemu_argv"], self.plan["qemu_seconds"],
                              file_cap=self.actor["child_file_size_cap"])
            require_absence(nonce)
            serial = T.read(OUT / "qemu.stdout", cap=self.actor["serial_combined_cap"])
            passed, phase = terminal(serial, nonce)
            fsck = self.phase("fsck-result", ["/usr/bin/e2fsck", "-fn", str(result)], 60)
            T.need(result_uuid(result, self.actor["result_disk_bytes"]) == uuid, "Result UUID changed")
            self.verify_inputs()
            self.verify_tools()
            verify_source(self.data, base=SOURCE)
            after_capacity = capacity(OUT)
            T.need(after_capacity["free_bytes"] >= self.watch.tree[2], "Live reserve fell below the sealed minimum")
            old_overlay = clean_file(overlay)
            overlay_pin = T.read(overlay, cap=self.actor["child_file_size_cap"], collect=False)
            T.need(old_overlay.st_ino == clean_file(overlay).st_ino and overlay_pin["bytes"] > 0,
                   "Expected retained original overlay")
            result_pin = T.read(result, cap=self.actor["result_disk_bytes"], collect=False)
            after = self.watch.record()
        finally:
            self.runtime.GUARD = prior_guard
        report = dict(kind="QT_MD4C_ACTOR_RESULT_V1",
                      status="PASS_QT_MD4C_IMPORTER_OBJECT_FOR_ROOT_REVIEW" if passed else "HOLD",
                      phase=phase, nonce=nonce, authority_sha256=self.authority_sha, handoff_sha256=self.handoff_sha,
                      plan_sha256=self.data["plan"]["sha256"], tools=self.tools,
                      watched_tree=self.actor["watched_tree"], watched_paths=self.actor["watched_paths"],
                      capacity_before=before_capacity, capacity_after=after_capacity,
                      allocation=dict(before=before, after=after, peak=self.watch.peak, samples=self.watch.samples),
                      qemu=qemu, serial=T.pin(serial), fsck_result=fsck, overlay_create=create,
                      overlay_inspect=inspect, overlay_inspect_stdout=T.pin(overlay_inspect), overlay_initial_eof=initial_eof,
                      result_disk=result_pin, overlay=overlay_pin, result_uuid=uuid,
                      native_Qt_full_build="NOT_RUN", physical_M2="NOT_RUN", Root_acceptance=None)
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
           and sys.dont_write_bytecode and __debug__, "Explicit isolated Qtbase actor required")
    os.umask(0o077)
    deadline = time.monotonic() + ATTACH_SECONDS - 90
    O.actor_boundary(dict(inputs=INPUTS, output=OUT, handoff=HANDOFF, plan=PLAN, selection=SELECTION))
    data = load_envelope(HANDOFF, args.handoff_sha256)
    verify_source(data, base=SOURCE)
    plan = read_plan(PLAN, data["plan"])
    issued = verify_selection(T.read(SELECTION, cap=128 << 10), args.authority_sha256,
                              data, plan, args.handoff_sha256, live=True)
    return Runner(plan, data, args.handoff_sha256, args.authority_sha256, issued, deadline).run()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit("Compile actor refused: " + str(error)) from None
