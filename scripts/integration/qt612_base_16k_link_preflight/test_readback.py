# SPDX-License-Identifier: MIT
"""Passive models for the QtCore actor, raw result storage, and ELF reader."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import stat
import struct
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import UUID


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in (
        "os.system", "os.exec", "os.fork", "os.posix_spawn", "os.kill", "os.killpg",
    ):
        raise AssertionError("Passive reader model attempted an actor operation: " + event)


sys.addaudithook(fence)
spec = importlib.util.spec_from_file_location("qtcore_readback_tested", Path(__file__).with_name("readback.py"))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

NONCE = "b" * 32
MANIFEST = "a" * 64
PLAN = "e" * 64
HANDOFF = "d" * 64
AUTHORITY = "f" * 64
RESULT_UUID = "7e11fe11-00be-4d26-8eca-450ed47ef831"


def shared_elf(*, machine=183, kind=3, align=16384, permission=5, soname=R.SONAME):
    """Model the binary layout and metadata a real link must expose."""
    data = bytearray(1024)
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, b"\x7fELF\x02\x01\x01".ljust(16, b"\0"), kind,
                     machine, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<II6Q", data, 64, 1, permission, 0, 16384, 16384, len(data), len(data), align)
    struct.pack_into("<II6Q", data, 120, 2, 4, 384, 16384 + 384, 16384 + 384, 80, 80, 8)
    strings = b"\0" + soname.encode() + b"\0libc.so.6\0"
    data[768:768 + len(strings)] = strings
    for index, (tag, value) in enumerate(((5, 16384 + 768), (10, len(strings)),
                                          (14, 1), (1, len(soname) + 2), (0, 0))):
        struct.pack_into("<qQ", data, 384 + index * 16, tag, value)
    return bytes(data)


def guest_result(status="PASS", phase="complete", **delta):
    return R.wire(dict(kind="QTCORE_LINK_RESULT_V1", status=status, phase=phase, nonce=NONCE, plan_sha256=MANIFEST,
                       architecture="aarch64", page_size=16384, uid=1000, gid=1000) | delta)


def metrics(**delta):
    return R.wire(dict(compile_exit=0, elapsed_ms=42000, peak_child_rss_kib=2048, log_complete=True) | delta)


def empty_ext4(path):
    """Minimal raw ext4 partly populated with two model directory inodes."""
    block = 4096
    superblock = bytearray(1024)
    for offset, value in ((0, 16), (4, R.RESULT_BYTES // block), (24, 2),
                          (32, R.RESULT_BYTES // block), (40, 16), (96, 0x42)):
        struct.pack_into("<I", superblock, offset, value)
    for offset, value in ((56, 0xEF53), (58, 1), (88, 256)):
        struct.pack_into("<H", superblock, offset, value)
    superblock[104:120] = UUID(RESULT_UUID).bytes
    superblock[120:136] = b"QT16K_CORE".ljust(16, b"\0")

    def inode(mode, links, extent):
        raw = bytearray(256)
        struct.pack_into("<H", raw, 0, stat.S_IFDIR | mode)
        struct.pack_into("<I", raw, 4, block)
        struct.pack_into("<H", raw, 26, links)
        struct.pack_into("<I", raw, 32, 0x80000)
        struct.pack_into("<HHHHI", raw, 40, 0xF30A, 1, 4, 0, 0)
        struct.pack_into("<IHHI", raw, 52, 0, 1, 0, extent)
        return raw

    def directory(rows):
        data = bytearray(block)
        cursor = 0
        for index, (number, name) in enumerate(rows):
            length = ((8 + len(name) + 3) & ~3) if index + 1 < len(rows) else block - cursor
            struct.pack_into("<IHBB", data, cursor, number, length, len(name), 2)
            data[cursor + 8:cursor + 8 + len(name)] = name
            cursor += length
        return data

    with path.open("xb") as stream:
        stream.truncate(R.RESULT_BYTES)
        for offset, raw in ((1024, superblock), (block + 8, struct.pack("<I", 3)),
                            (3 * block + 256, inode(0o755, 3, 4)), (3 * block + 512, inode(0o700, 2, 5)),
                            (4 * block, directory(((2, b"."), (2, b".."), (3, b"lost+found")))),
                            (5 * block, directory(((3, b"."), (2, b".."))))):
            stream.seek(offset)
            stream.write(raw)


def put(directory, name, raw):
    (directory / name).write_bytes(raw)
    return R.pin(raw)


def natural_record(argv, size_cap=None, **delta):
    return dict(argv=argv, exit=0, ownership="REAPED", group_census="EMPTY_TWICE", passed=True, reaped=True,
                output_complete=True, timeout=False, command_timed_out=False, original_budget_overrun=False,
                emergency_retirement=False, emergency_retirement_cap_seconds=None, signals=[], error=None,
                command_cancelled=[], operation_seconds=2.0, operation_cap_seconds=7.0, child_file_size_cap=size_cap) | delta


def model_actor(output, *, terminal="HOLD link", report_status="HOLD"):
    policy = dict(profile=dict(tools={}), watched_tree=["/out", 4 * R.GIB + 96 * R.MIB, 2 * R.GIB],
                  watched_paths=[["/out/overlay.qcow2", 4 * R.GIB], ["/out/result.raw", R.RESULT_BYTES]],
                  child_file_size_cap=4 * R.GIB, admission_disk_bytes=6 * R.GIB + 96 * R.MIB,
                  serial_combined_cap=R.MIB, result_disk_bytes=R.RESULT_BYTES, overlay_create=["model-create"],
                  overlay_inspect=["model-inspect"])
    disk = put(output, "result.raw", b"model disk")
    overlay = put(output, "overlay.qcow2", b"model overlay")
    start = dict(tree_allocated=8192, overlay_allocated=0, overlay_eof=0, result_allocated=4096, free=64 * R.GIB)
    end = start | dict(overlay_allocated=4096, overlay_eof=overlay["bytes"])
    capacity = dict(free_bytes=64 * R.GIB, memory_available_bytes=16 * R.GIB, allowed_cpus=4,
                    required_bytes=policy["admission_disk_bytes"], minimum_memory_bytes=8 * R.GIB,
                    minimum_cpus=4, fits=True)
    plan = dict(nonce=NONCE, qemu_argv=["model-qemu"], qemu_seconds=7200, actor=policy,
                result_uuid=RESULT_UUID, guest_payload={"MANIFEST.sha256": MANIFEST},
                inputs={"result.raw": R.pin(b"model template")})
    report = dict(kind="QTCORE_LINK_ACTOR_RESULT_V1", status=report_status, phase=terminal.split()[1], nonce=NONCE,
                  authority_sha256=AUTHORITY, handoff_sha256=HANDOFF, plan_sha256=PLAN, tools={},
                  watched_tree=policy["watched_tree"], watched_paths=policy["watched_paths"],
                  capacity_before=capacity, capacity_after=capacity,
                  allocation=dict(before=start, after=end, peak=end, samples=5), result_disk=disk, overlay=overlay,
                  result_uuid=RESULT_UUID, overlay_initial_eof=8192, native_Qt_full_build="NOT_RUN",
                  physical_M2="NOT_RUN", Root_acceptance=None, host_cgroup_memory_peak_bytes=12345)
    for label, field, argv, size_cap, stdout in (
        ("overlay-create", "overlay_create", policy["overlay_create"], None, b"created"),
        ("overlay-inspect", "overlay_inspect", policy["overlay_inspect"], None, b"model geometry"),
        ("qemu", "qemu", plan["qemu_argv"], policy["child_file_size_cap"],
         f"\r\nQTCORE_LINK_TERMINAL {NONCE} {terminal}\r\n".encode()),
        ("fsck-result", "fsck_result", ["/usr/bin/e2fsck", "-fn", "/out/result.raw"], None, b"clean"),
    ):
        report[field] = put(output, label + ".json", R.wire(natural_record(argv, size_cap)))
        stdout_pin = put(output, label + ".stdout", stdout)
        put(output, label + ".stderr", b"")
        put(output, label + ".log", stdout)
        if label == "overlay-inspect":
            report["overlay_inspect_stdout"] = stdout_pin
        if label == "qemu":
            report["serial"] = stdout_pin
    return plan, report


def model_scope(capsule, attempt, code, *, plan_sha=PLAN, authority_sha=AUTHORITY):
    cid, group = "a" * 64, "/user.slice/" + R.SITE_SCOPE
    meta = dict(nonce=NONCE, cid=cid, scope=R.SITE_SCOPE, scope_group=group,
                authority_sha256=authority_sha, handoff_sha256=HANDOFF, plan_sha256=plan_sha)
    host_pin = put(attempt, "host-result.json", R.wire(dict(
        kind="QTCORE_LINK_HOST_RETIREMENT_V1", natural=True, exit_code=code,
        container_removed=True, absent_twice=True, **meta)))
    closure = capsule / "post-scope.json"
    closure_pin = put(capsule, closure.name, R.wire(dict(
        kind="QTCORE_LINK_POST_SCOPE_V1", host_result=host_pin,
        observations=[dict(scope_absent=True, container_absent=True)] * 2, **meta)))
    put(capsule / "root-run.claim", "attempt.path", (str(attempt) + "\n").encode())
    for name, body in (("run.cid", cid), ("scope.path", group + "\n"), ("run.attach-exit", f"{code}\n"),
                       ("run.absence-1", ""), ("run.absence-2", "")):
        put(attempt, name, body.encode())
    return closure, closure_pin["sha256"], meta


class ReaderControls(unittest.TestCase):
    def test_shared_binary_load_geometry_and_identity(self):
        facts = R.linked_core(shared_elf())
        self.assertEqual((facts["type"], facts["architecture"], facts["soname"], facts["geometry_16k"]),
                         ("ET_DYN", "aarch64", R.SONAME, True))
        self.assertEqual(facts["needed"], ["libc.so.6"])
        for changes in (dict(machine=62), dict(kind=2), dict(kind=1), dict(align=4096),
                        dict(permission=4), dict(soname="libQt6Gui.so.6")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                R.linked_core(shared_elf(**changes))

    def test_guest_pass_joins_exact_graph_inventory_binary_aliases_and_metrics(self):
        commands = b"model Ninja commands\n"
        inventory = b"package 1\n" * 356
        files = {"result.json": guest_result(), "metrics.json": metrics(), "core.commands": commands,
                 "inventory.before": inventory, "inventory.after": inventory, "aliases.txt": R.ALIASES,
                 R.ELF_NAME: shared_elf(), "build.log":
                     b"[320/321] Linking CXX shared library lib/libQt6Core.so.6.12.0\n"
                     b"[321/321] Creating library symlink lib/libQt6Core.so.6 lib/libQt6Core.so\n"}
        with patch.object(R, "CORE_COMMANDS", tuple(R.pin(commands).values())), \
             patch.object(R, "INVENTORY", tuple(R.pin(inventory).values())):
            elf, measured = R.guest_facts(files, NONCE, "PASS", "complete", MANIFEST)
            self.assertEqual((elf["soname"], measured["elapsed_ms"]), (R.SONAME, 42000))
            for name, body, error in (
                ("core.commands", b"bad", "command closure"),
                ("inventory.after", b"bad", "356-package"),
                (R.ELF_NAME, shared_elf(align=4096), "16K load geometry"),
                ("aliases.txt", b"bad", "symlink chain"),
                ("build.log", b"only claimed\n", "link and symlink steps"),
                ("metrics.json", metrics(log_complete=False), "complete log"),
                ("result.json", guest_result(plan_sha256=PLAN), "guest payload"),
            ):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, error):
                    R.guest_facts(files | {name: body}, NONCE, "PASS", "complete", MANIFEST)
            with self.assertRaisesRegex(ValueError, "Missing exact original"):
                R.guest_facts({name: body for name, body in files.items() if name != R.ELF_NAME},
                              NONCE, "PASS", "complete", MANIFEST)

    def test_raw_ext4_and_early_hold_remain_read_only(self):
        with TemporaryDirectory() as directory:
            disk = Path(directory) / "result.raw"
            empty_ext4(disk)
            before = R.identity(disk.lstat())
            _, disk_pin = R.read(disk, R.RESULT_BYTES, collect=False)
            self.assertEqual(R.result_files(disk, disk_pin, RESULT_UUID, False), {})
            self.assertEqual(R.identity(disk.lstat()), before)
            with self.assertRaisesRegex(ValueError, "result namespace"):
                R.result_files(disk, disk_pin, RESULT_UUID, True)
            with self.assertRaisesRegex(ValueError, "sealed UUID"):
                R.result_files(disk, disk_pin, str(UUID(int=0)), False)

    def test_original_serial_cannot_alias_or_duplicate_nonce(self):
        selected = f"QTCORE_LINK_TERMINAL {NONCE} PASS complete\r\n".encode()
        self.assertEqual(R.serial_state(selected, NONCE), ("PASS", "complete"))
        self.assertEqual(R.serial_state(selected.replace(b"PASS complete", b"HOLD storage"), NONCE),
                         ("HOLD", "storage"))
        for bad in (selected * 2, selected.replace(b"complete", b"boot"), selected.replace(NONCE.encode(), b"c" * 32)):
            with self.assertRaises(ValueError):
                R.serial_state(bad, NONCE)

    def test_actor_holds_partial_guest_and_rejects_retirement_or_report_switch(self):
        with TemporaryDirectory() as directory:
            output = Path(directory)
            plan, report = model_actor(output)
            actor_pin = put(output, "actor-result.json", R.wire(report))
            with patch.object(R, "result_files", return_value={"metrics.json": metrics(compile_exit=124)}):
                result = R.verify_actor(output, plan, PLAN, actor_pin["sha256"],
                                       lambda raw, eof: self.assertEqual((raw, eof), (b"model geometry", 8192)))
                self.assertEqual((result["status"], result["metrics"]["compile_exit"], result["elf"]),
                                 ("HOLD", 124, None))
                for field, value, error in (
                    ("status", R.ACTOR_PASS, "terminal marker"),
                    ("plan_sha256", MANIFEST, "sealed attempt"),
                    ("host_cgroup_memory_peak_bytes", 7 * R.GIB, "memory peak"),
                ):
                    changed = put(output, "actor-result.json", R.wire(report | {field: value}))
                    with self.assertRaisesRegex(ValueError, error):
                        R.verify_actor(output, plan, PLAN, changed["sha256"], lambda *_: None)
                changed = deepcopy(report)
                changed["qemu"] = put(output, "qemu.json", R.wire(natural_record(
                    plan["qemu_argv"], plan["actor"]["child_file_size_cap"], emergency_retirement=True)))
                changed_pin = put(output, "actor-result.json", R.wire(changed))
                with self.assertRaisesRegex(ValueError, "natural owned command"):
                    R.verify_actor(output, plan, PLAN, changed_pin["sha256"], lambda *_: None)

    def test_actor_pass_cannot_use_unchanged_result_template(self):
        with TemporaryDirectory() as directory:
            output = Path(directory)
            plan, report = model_actor(output, terminal="PASS complete", report_status=R.ACTOR_PASS)
            plan["inputs"]["result.raw"] = report["result_disk"]
            actor_pin = put(output, "actor-result.json", R.wire(report))
            with self.assertRaisesRegex(ValueError, "unchanged result template"):
                R.verify_actor(output, plan, PLAN, actor_pin["sha256"], lambda *_: None)

    def test_scope_closure_joins_original_exit_claim_and_twice_absence(self):
        with TemporaryDirectory() as directory:
            capsule = Path(directory)
            attempt = capsule / "issued.model"
            attempt.mkdir(mode=0o700)
            (attempt / "output").mkdir()
            (capsule / "root-run.claim").mkdir()
            closure, closure_sha, meta = model_scope(capsule, attempt, 2)
            args = (attempt / "output", closure, closure_sha, PLAN, meta | dict(status="HOLD"))
            self.assertEqual(R.verify_host_scope(*args)["cid"], meta["cid"])
            put(attempt, "run.attach-exit", b"0\n")
            with self.assertRaisesRegex(ValueError, "run.attach-exit"):
                R.verify_host_scope(*args)

    def test_incomplete_actor_requires_nonzero_scope_and_bounded_original_diagnostics(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            attempt = root / "issued.model"
            output = attempt / "output"
            attempt.mkdir(mode=0o700)
            output.mkdir()
            (root / "root-run.claim").mkdir()
            plan = dict(nonce=NONCE, actor=dict(child_file_size_cap=4 * R.GIB, serial_combined_cap=R.MIB))
            plan_path = root / "PLAN.UNISSUED.json"
            plan_pin = put(root, plan_path.name, R.wire(plan))
            selection = b"already externally selected\n"
            selection_pin = put(attempt, "selection.json", selection)
            handoff = dict(plan=plan_pin)
            checked = set()

            def verify_selection(raw, sha, data, selected_plan, handoff_sha, *, live):
                self.assertEqual((raw, sha, data, selected_plan, handoff_sha, live),
                                 (selection, selection_pin["sha256"], handoff, plan, HANDOFF, False))
                checked.add("selection")

            def verify_source(data, source):
                self.assertEqual((data, source), (handoff, root / "source"))
                checked.add("source")

            capsule = dict(PLAN_LEAF=plan_path.name, HANDOFF_LEAF="HANDOFF.UNISSUED.json",
                           load_handoff=lambda _path, _sha: handoff, verify_selection=verify_selection,
                           verify_source=verify_source)
            diagnostic = put(output, "qemu.stderr", b"allocation limit\n")
            for code in (3, 0):
                closure, closure_sha, _ = model_scope(root, attempt, code, plan_sha=plan_pin["sha256"],
                                                       authority_sha=selection_pin["sha256"])
                args = (output, plan_path, plan, plan_pin["sha256"], capsule, HANDOFF, selection_pin["sha256"],
                        closure, closure_sha)
                if code == 0:
                    with self.assertRaisesRegex(ValueError, "natural nonzero"):
                        R.incomplete_actor(*args)
                    continue
                joined = R.incomplete_actor(*args)
                self.assertEqual((joined["status"], joined["evidence"], joined["post_scope"]["exit_code"], checked),
                                 ("HOLD_NO_COMPLETE_ACTOR_REPORT", {"qemu.stderr": diagnostic}, 3,
                                  {"selection", "source"}))
                put(output, "actor-result.json", b"present\n")
                with self.assertRaisesRegex(ValueError, "bounded original diagnostics"):
                    R.incomplete_actor(*args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
