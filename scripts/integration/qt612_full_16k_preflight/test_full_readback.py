# SPDX-License-Identifier: MIT
"""Exercise the independent full Qtbase reader with inert carrier fixtures."""

from pathlib import Path
from runpy import run_path
import stat
import struct
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import full_readback as R


def no_actor(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Passive reader fixture attempted an actor operation: " + event)


sys.addaudithook(no_actor)
FIXTURE = run_path(str(HERE.parent / "qt612_base_16k_link_preflight/test_readback.py"))
C = R.C
NONCE, HANDOFF, PLAN, AUTHORITY = "b" * 32, "d" * 64, "e" * 64, "f" * 64
UUID = FIXTURE["RESULT_UUID"]
GIB = R.GIB
CLUSTER = 65536


def put(directory, name, raw):
    (directory / name).write_bytes(raw)
    return C.pin(raw)


def overlay_bytes(backing):
    header = bytearray(CLUSTER * 4)
    struct.pack_into(">4sIQIIQIIQQIIQ", header, 0, b"QFI\xfb", 3, 136, len(backing), 16,
                     16 * GIB, 0, 32, CLUSTER, CLUSTER * 2, 1, 0, 0)
    struct.pack_into(">QQQII", header, 72, 0, 0, 0, 4, 112)
    struct.pack_into(">II5s", header, 112, 0xE2792ACA, 5, b"qcow2")
    header[136:136 + len(backing)] = backing
    return bytes(header)


def chain():
    qcow = {"type": "qcow2", "data": {"compat": "1.1", "compression-type": "zlib", "lazy-refcounts": False,
                                        "refcount-bits": 16, "corrupt": False, "extended-l2": False}}
    paths = ("/out/overlay.qcow2", "/inputs/gui.qcow2", "/inputs/core.qcow2", "/inputs/scratch.raw")
    rows = []
    for index, path in enumerate(paths):
        raw = index == len(paths) - 1
        file = {"filename": path, "format": "file", "actual-size": 3 * CLUSTER,
                "virtual-size": 16 * GIB if raw else 3 * CLUSTER, "children": [], "dirty-flag": False,
                "format-specific": {"type": "file", "data": {}}}
        row = {"filename": path, "format": "raw" if raw else "qcow2", "actual-size": 3 * CLUSTER,
               "virtual-size": 16 * GIB, "children": [{"name": "file", "info": file}], "dirty-flag": False}
        if not raw:
            row |= {"cluster-size": CLUSTER, "format-specific": qcow, "backing-filename": paths[index + 1],
                    "full-backing-filename": paths[index + 1],
                    "backing-filename-format": "raw" if index == len(paths) - 2 else "qcow2"}
        rows.append(row)
    return rows


def original_actor(output, passed=True):
    result = put(output, "result.raw", b"model result")
    overlay = put(output, "overlay.qcow2", overlay_bytes(b"/inputs/gui.qcow2"))
    policy = dict(profile={"tools": {}}, watched_tree=["/out", 5 * GIB, 2 * GIB],
                  watched_paths=[["/out/overlay.qcow2", 4 * GIB], ["/out/result.raw", result["bytes"]]],
                  child_file_size_cap=4 * GIB, admission_disk_bytes=7 * GIB, serial_combined_cap=65536,
                  result_disk_bytes=result["bytes"], overlay_create=["model-create"], overlay_inspect=["model-inspect"])
    plan = dict(nonce=NONCE, result_uuid=UUID, actor=policy, qemu_argv=["model-qemu"], qemu_seconds=600,
                limits=dict(actor_memory_bytes=8 * GIB, result_disk_bytes=result["bytes"]),
                inputs={"result.raw": C.pin(b"model seed!!"),
                        "gui.qcow2": dict(bytes=3 * CLUSTER), "core.qcow2": dict(bytes=3 * CLUSTER),
                        "scratch.raw": dict(bytes=16 * GIB)})
    start = dict(tree_allocated=2, overlay_allocated=0, overlay_eof=0, result_allocated=1, free=64 * GIB)
    end = start | dict(tree_allocated=8192, overlay_allocated=4096, overlay_eof=overlay["bytes"])
    cap = dict(free_bytes=64 * GIB, memory_available_bytes=16 * GIB, allowed_cpus=4,
               required_bytes=7 * GIB, minimum_memory_bytes=10 * GIB, minimum_cpus=4, fits=True)
    phase = "complete" if passed else "build"
    status = "PASS" if passed else "HOLD"
    report = dict(kind=R.ACTOR_KIND, status=R.ACTOR_PASS if passed else "HOLD", phase=phase, nonce=NONCE,
                  authority_sha256=AUTHORITY, handoff_sha256=HANDOFF, plan_sha256=PLAN, tools={},
                  watched_tree=policy["watched_tree"], watched_paths=policy["watched_paths"],
                  capacity_before=cap, capacity_after=cap.copy(),
                  allocation=dict(before=start, after=end, peak=end.copy(), samples=5), result_disk=result, overlay=overlay,
                  result_uuid=UUID, overlay_initial_eof=3 * CLUSTER, native_Qt_full_build="NOT_RUN",
                  physical_M2="NOT_RUN", Root_acceptance=None, host_cgroup_memory_peak_bytes=12345)
    for label, field, argv, size_cap, stdout in (
        ("overlay-create", "overlay_create", policy["overlay_create"], None, b"created"),
        ("overlay-inspect", "overlay_inspect", policy["overlay_inspect"], None, C.wire(chain())),
        ("qemu", "qemu", plan["qemu_argv"], policy["child_file_size_cap"],
         f"boot\nQTBASE_FULL16K_TERMINAL {NONCE} {status} {phase}\n".encode()),
        ("fsck-result", "fsck_result", ["/usr/bin/e2fsck", "-fn", "/out/result.raw"], None, b"clean"),
    ):
        report[field] = put(output, label + ".json", C.wire(FIXTURE["natural_record"](argv, size_cap)))
        stdout_pin = put(output, label + ".stdout", stdout)
        put(output, label + ".stderr", b"")
        put(output, label + ".log", stdout)
        if label == "overlay-inspect":
            report["overlay_inspect_stdout"] = stdout_pin
        if label == "qemu":
            report["serial"] = stdout_pin
    return plan, report


def evidence_disk(disk, name, body):
    FIXTURE["empty_ext4"](disk)
    block = 4096

    def directory(entries):
        raw = bytearray(block)
        offset = 0
        for index, (number, label, kind) in enumerate(entries):
            size = block - offset if index == len(entries) - 1 else (8 + len(label) + 3) & ~3
            struct.pack_into("<IHBB", raw, offset, number, size, len(label), kind)
            raw[offset + 8:offset + 8 + len(label)] = label
            offset += size
        return raw

    def inode(mode, size, links, extent):
        raw = bytearray(256)
        struct.pack_into("<H", raw, 0, mode)
        struct.pack_into("<I", raw, 4, size)
        struct.pack_into("<H", raw, 26, links)
        struct.pack_into("<I", raw, 32, 0x80000)
        struct.pack_into("<HHHHI", raw, 40, 0xF30A, 1, 4, 0, 0)
        struct.pack_into("<IHHI", raw, 52, 0, 1, 0, extent)
        return raw

    with disk.open("r+b") as stream:
        for offset, raw in (
            (1024 + 120, b"QT16K_FULL".ljust(16, b"\0")),
            (3 * block + 256, inode(stat.S_IFDIR | 0o755, block, 4, 4)),
            (3 * block + 768, inode(stat.S_IFDIR | 0o700, block, 2, 6)),
            (3 * block + 1024, inode(stat.S_IFREG | 0o600, len(body), 1, 7)),
            (4 * block, directory(((2, b".", 2), (2, b"..", 2), (3, b"lost+found", 2), (4, b"evidence", 2)))),
            (6 * block, directory(((4, b".", 2), (2, b"..", 2), (5, name.encode(), 1)))),
            (7 * block, body),
        ):
            stream.seek(offset)
            stream.write(raw)
    return C.read(disk, disk.stat().st_size, collect=False)[1]


class FullReadbackTests(unittest.TestCase):
    def review(self, output, plan, report):
        digest = put(output, "actor-result.json", C.wire(report))["sha256"]
        return R.review_actor(output, plan, digest, HANDOFF, AUTHORITY, PLAN)

    def test_exact_owned_pass_and_hold(self):
        for passed in (False, True):
            with self.subTest(passed=passed), TemporaryDirectory() as temp:
                output = Path(temp)
                plan, record = original_actor(output, passed)
                report = self.review(output, plan, record)
                self.assertEqual(report["status"], "ACTOR_PASS" if passed else "HOLD")
                self.assertEqual(report["result_disk"], record["result_disk"])
                self.assertEqual(report["host_cgroup_memory_peak_bytes"], 12345)

    def test_reworded_status_or_missing_original_retirement_refuses(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            plan, record = original_actor(output)
            with self.assertRaisesRegex(ValueError, "actor and serial"):
                self.review(output, plan, record | {"status": "HOLD"})
            receipt = FIXTURE["natural_record"](plan["qemu_argv"], 4 * GIB, group_census="UNKNOWN")
            record["qemu"] = put(output, "qemu.json", C.wire(receipt))
            with self.assertRaisesRegex(ValueError, "natural owned command retirement"):
                self.review(output, plan, record)

    def test_resealed_allocation_and_final_overlay_mutations_refuse(self):
        with TemporaryDirectory() as temp:
            output = Path(temp)
            plan, record = original_actor(output)
            ample = record["allocation"]["peak"].copy()
            record["allocation"]["peak"]["free"] = 1
            with self.assertRaisesRegex(ValueError, "reviewed bound"):
                self.review(output, plan, record)
            record["allocation"]["before"]["free"] = record["allocation"]["peak"]["free"] = 6 * GIB
            with self.assertRaisesRegex(ValueError, "lacks the reviewed admission reserve"):
                self.review(output, plan, record)
            record["allocation"]["before"]["free"] = ample["free"]
            record["allocation"]["peak"] = ample
            record["overlay"] = put(output, "overlay.qcow2", overlay_bytes(b"/inputs/core.qcow2"))
            with self.assertRaisesRegex(ValueError, "exact immutable backing path"):
                self.review(output, plan, record)

    def test_ext4_hold_and_missing_pass_evidence(self):
        with TemporaryDirectory() as temp:
            disk = Path(temp) / "disk.raw"
            FIXTURE["empty_ext4"](disk)
            with disk.open("r+b") as stream:
                stream.seek(1024 + 120)
                stream.write(b"QT16K_FULL".ljust(16, b"\0"))
            pin = C.read(disk, disk.stat().st_size, collect=False)[1]
            self.assertEqual(R.read_evidence(disk, pin, UUID, {"result.json": 256}, False, GIB), {})
            with self.assertRaisesRegex(ValueError, "evidence namespace"):
                R.read_evidence(disk, pin, UUID, {"result.json": 256}, True, GIB)
            with self.assertRaisesRegex(ValueError, "sealed UUID and label"):
                R.read_evidence(disk, pin, "11111111-2222-4333-aaaa-555555555555", {"result.json": 256}, False, GIB)

    def test_exact_ext4_evidence_bytes_and_budget(self):
        with TemporaryDirectory() as temp:
            disk = Path(temp) / "result.raw"
            name = R.G.LIBRARIES[0]
            body = b"model evidence"
            pin = evidence_disk(disk, name, body)
            self.assertEqual(R.read_evidence(disk, pin, UUID, {name: 32}, True, 32), {name: body})
            with self.assertRaisesRegex(ValueError, "Aggregate full Qtbase evidence"):
                R.read_evidence(disk, pin, UUID, {name: 32}, True, len(body) - 1)
            with self.assertRaisesRegex(ValueError, "Bounded ordinary full Qtbase evidence file"):
                R.read_evidence(disk, pin, UUID, {name: 4}, True, 32)

    def test_guest_result_must_bind_original_plan_and_status(self):
        guest = dict(kind=R.G.PLAN_KIND, nonce=NONCE, target=R.G.TARGET, inventory=R.G.INVENTORY,
                     all_commands=R.G.ALL_COMMANDS, dry_run=R.G.DRY_RUN, inherited=R.G.INHERITED,
                     limits=dict(guest_build_seconds=600, build_log_bytes=256, artifact_bytes=GIB,
                                 guest_min_free_bytes=GIB))
        raw = R.G.wire_plan(guest)
        plan = dict(nonce=NONCE, result_uuid=UUID, limits=guest["limits"], guest_plan=C.pin(raw))
        digest = plan["guest_plan"]["sha256"]
        actor = dict(status="HOLD", phase="build", result_disk={"bytes": 64 << 20})
        result = dict(kind="QTBASE_FULL16K_GUEST_RESULT_V1", status="HOLD", phase="inputs", nonce=NONCE,
                      plan_sha256=digest, target="all", failure_code="INPUT_CHECK_FAILED")
        with TemporaryDirectory() as temp, patch.object(R.F, "result_uuid", return_value=UUID), \
             patch.object(R, "read_evidence", return_value={"result.json": C.wire(result)}) as captured, \
             patch.object(R.G, "verify_evidence", return_value={"status": "FIXTURE_PASS"}) as checker:
            artifact = Path(temp)
            put(artifact, R.GUEST_PLAN, raw)
            observed = R.review_guest(artifact, artifact, plan, actor)
            self.assertEqual((observed["status"], observed["worker"]), ("HOLD", result))
            worker_pass = {key: value for key, value in result.items() if key != "failure_code"}
            worker_pass.update(status="PASS", phase="complete")
            captured.return_value = {"result.json": C.wire(worker_pass)}
            observed = R.review_guest(artifact, artifact, plan, actor | {"phase": "cleanup"})
            self.assertEqual((observed["status"], observed["worker"]), ("HOLD", worker_pass))
            checker.assert_not_called()
            captured.return_value = {"result.json": C.wire(result | {"plan_sha256": HANDOFF})}
            with self.assertRaisesRegex(ValueError, "sealed plan or outer HOLD"):
                R.review_guest(artifact, artifact, plan, actor)
            observed = R.review_guest(artifact, artifact, plan, actor | {"status": "ACTOR_PASS"})
            self.assertEqual(observed, checker.return_value)
            checker.assert_called_once_with(captured.return_value, guest, digest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
