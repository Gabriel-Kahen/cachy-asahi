# SPDX-License-Identifier: MIT
"""Actor-fenced controls. Runtime children are represented by in-memory models."""

import copy
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent))
import actor as A
import common as C

SIZE = 64 << 20
NONCE = "1" * 32
UUID_TEXT = "11111111-1111-4111-8111-111111111111"
PLAN_PIN = {"bytes": 256, "sha256": "c" * 64}


def disk(path, label=b"QT16K_MD4C"):
    superblock = bytearray(1024)
    struct.pack_into("<I", superblock, 4, SIZE // 4096)
    struct.pack_into("<I", superblock, 24, 2)
    superblock[56:58] = b"\x53\xef"
    superblock[104:120] = UUID(UUID_TEXT).bytes
    superblock[120:120 + len(label)] = label
    with path.open("xb") as file:
        file.truncate(SIZE)
        file.seek(1024)
        file.write(superblock)
    path.chmod(0o600)


class ModelRuntime:
    GUARD = None

    def __init__(self, natural_status=True, passed=True):
        self.natural_status, self.passed = natural_status, passed
        self.calls = []

    def allocated(self, out, **_):
        return sum(file.lstat().st_blocks * 512 for file in out.iterdir())

    def component_limits(self, _, paths):
        for path, cap in paths:
            if path.exists() and path.stat().st_blocks * 512 > cap:
                raise ValueError("component allocated cap")

    def receipt(self, path):
        return json.loads(path.read_text())

    def natural(self, receipt):
        return receipt["naturally_retired"]

    def command(self, argv, out, label, **kwargs):
        self.calls.append((label, argv, kwargs))
        self.GUARD()
        serial = b""
        if label == "overlay-create":
            (out / "overlay.qcow2").write_bytes(b"a" * 4096)
        if label == "qemu":
            terminal = "PASS complete" if self.passed else "HOLD compile"
            serial = f"QTMD4C16K {NONCE} {terminal}\n".encode()
        if label == "overlay-inspect":
            serial = b"model of independent qemu-img inspection"
        (out / (label + ".stdout")).write_bytes(serial)
        (out / (label + ".json")).write_text(json.dumps(dict(
            argv=argv, child_file_size_cap=kwargs["child_file_size_cap"],
            naturally_retired=self.natural_status or label != "qemu")), encoding="utf-8")


def actor_model():
    return dict(profile={"tools": {}},
                watched_tree=["/out", 2_248_146_944, 2 << 30],
                watched_paths=[["/out/overlay.qcow2", 2 << 30], ["/out/result.raw", SIZE]],
                overlay_create=["/usr/bin/qemu-img", "create"],
                overlay_inspect=["/usr/bin/qemu-img", "info"], result_disk_bytes=SIZE,
                serial_combined_cap=1 << 20, child_file_size_cap=2 << 30, admission_disk_bytes=4_395_630_592)


class ActorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name)
        disk(self.out / "result.raw")
        patch = mock.patch.object(A, "OUT", self.out)
        patch.start()
        self.addCleanup(patch.stop)

    def runner(self, runtime):
        plan = dict(actor=actor_model(), inputs={"result.raw": {"model": True}}, nonce=NONCE,
                    qemu_argv=["/usr/bin/qemu-system-aarch64", "-nic", "none"], qemu_seconds=2100)
        with mock.patch.object(A.O, "module", return_value=runtime):
            runner = A.Runner(plan, {"result_uuid": UUID_TEXT, "plan": PLAN_PIN}, "a" * 64, "b" * 64,
                              {"expires_utc": int(time.time()) + 60}, time.monotonic() + 60)
        for target, name, fields in (
            (A, "check_pinned_file", {}),
            (A, "require_absence", {}),
            (A, "capacity", {"return_value": {"fits": True, "free_bytes": 8 << 30}}),
            (A, "validate_empty_overlay", {}),
            (A, "verify_source", {}),
            (runner, "verify_inputs", {}),
            (runner, "verify_tools", {}),
        ):
            patch = mock.patch.object(target, name, **fields)
            patch.start()
            self.addCleanup(patch.stop)
        return runner

    def test_exact_serial_marker(self):
        self.assertEqual(A.terminal(f"boot output\nQTMD4C16K {NONCE} PASS complete\r\n".encode(), NONCE),
                         (True, "complete"))
        self.assertEqual(A.terminal(f"QTMD4C16K {NONCE} HOLD storage\n".encode(), NONCE), (False, "storage"))
        for text in (f"QTMD4C16K {NONCE} PASS compile\n", f"QTMD4C16K {NONCE} PASS complete\n" * 2,
                     f"QTMD4C16K {'a' * 32} PASS complete\n", "nothing"):
            with self.assertRaises(ValueError):
                A.terminal(text.encode(), NONCE)

    def test_result_uuid_label_and_geometry(self):
        self.assertEqual(A.result_uuid(self.out / "result.raw", SIZE), UUID_TEXT)
        disk(self.out / "other", b"QT16K_RESULT")
        with self.assertRaisesRegex(ValueError, "ext4 result volume"):
            A.result_uuid(self.out / "other", SIZE)
        with self.assertRaisesRegex(ValueError, "geometry"):
            A.result_uuid(self.out / "result.raw", SIZE - 4096)

    def test_watched_input_limits_and_private_paths(self):
        runtime = ModelRuntime()
        ops = actor_model() | {"child_file_size_cap": 4096}
        watch = A.AllocationWatch(runtime, ops, self.out, time.monotonic() + 60)
        before = watch.record()
        self.assertEqual(before["overlay_eof"], 0)
        overlay = self.out / "overlay.qcow2"
        with overlay.open("xb") as file:
            file.truncate(4097)
        with self.assertRaisesRegex(ValueError, "overlay file bound"):
            watch.record()
        overlay.unlink()
        (self.out / "stray.write").touch()
        with self.assertRaisesRegex(ValueError, "Unexpected writable"):
            watch.record()

    def test_capped_natural_paths_and_report(self):
        runtime = ModelRuntime()
        self.assertEqual(self.runner(runtime).run(), 0)
        self.assertEqual([name for name, _, _ in runtime.calls], list(A.LABELS))
        self.assertEqual([entry[2]["child_file_size_cap"] for entry in runtime.calls], [None, None, 2 << 30, None])
        for _, _, arguments in runtime.calls:
            self.assertEqual(arguments["watched_tree"], (self.out, 2_248_146_944, 2 << 30))
            self.assertEqual(arguments["watched_paths"],
                             ((self.out / "overlay.qcow2", 2 << 30), (self.out / "result.raw", SIZE)))
        self.assertEqual(runtime.calls[-1][1], ["/usr/bin/e2fsck", "-fn", str(self.out / "result.raw")])
        report = json.loads((self.out / "actor-result.json").read_text())
        self.assertEqual(report["kind"], "QT_MD4C_ACTOR_RESULT_V1")
        self.assertEqual(report["status"], "PASS_QT_MD4C_IMPORTER_OBJECT_FOR_ROOT_REVIEW")
        self.assertEqual(report["result_uuid"], UUID_TEXT)
        self.assertEqual(report["plan_sha256"], PLAN_PIN["sha256"])
        self.assertEqual(report["result_disk"]["bytes"], SIZE)
        self.assertEqual(report["overlay_initial_eof"], 4096)
        self.assertGreaterEqual(report["allocation"]["samples"], 9)
        self.assertIsNone(runtime.GUARD)
        A.require_absence.assert_has_calls([mock.call(NONCE), mock.call(NONCE)])

    def test_unknown_qemu_retirement_stops_before_fsck(self):
        runtime = ModelRuntime(natural_status=False)
        with self.assertRaisesRegex(ValueError, "natural retirement"):
            self.runner(runtime).run()
        self.assertEqual([name for name, _, _ in runtime.calls], list(A.LABELS[:-1]))
        self.assertFalse((self.out / "actor-result.json").exists())
        self.assertTrue((self.out / "qemu.json").is_file())
        self.assertIsNone(runtime.GUARD)

    def test_natural_hold_never_passes(self):
        runtime = ModelRuntime(passed=False)
        self.assertEqual(self.runner(runtime).run(), 2)
        report = json.loads((self.out / "actor-result.json").read_text())
        self.assertEqual((report["status"], report["phase"]), ("HOLD", "compile"))

    def test_previous_overlay_refused_before_any_child(self):
        (self.out / "overlay.qcow2").touch()
        runtime = ModelRuntime()
        with self.assertRaisesRegex(ValueError, "Fresh attempt-owned"):
            self.runner(runtime).run()
        self.assertEqual(runtime.calls, [])

    def test_main_requires_explicit_actor_flag(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "argv",
            ["actor.py", "--handoff-sha256", "a" * 64, "--authority-sha256", "b" * 64]), \
             mock.patch.object(A.O, "actor_boundary") as boundary:
            with self.assertRaisesRegex(ValueError, "Explicit isolated"):
                A.main()
            boundary.assert_not_called()

    def test_plan_binds_guest_storage_and_exact_qemu_controls(self):
        prep = C.P
        originals = {name: {"bytes": size, "sha256": "1" * 64} for name, size in
                     {"Image": 4096, "boot.raw": 2 << 20, "scratch.raw": prep.WORK}.items()}
        selected = originals | {"result.raw": {"bytes": prep.RESULT, "sha256": "2" * 64}}
        tools = {name: {"bytes": 4096, "sha256": "4" * 64} for name in
                 prep.TOOL_NAMES | {"/usr/bin/qemu-img"}}
        profile = dict(kind=prep.TOOL_PROFILE_KIND, actor_image=C.IMAGE, tools=tools)
        guest = {name: "5" * 64 for name in
                 ("headers.commands", "pch.commands", "importer.commands", "operands.sha256")}
        guest["guest.sh"] = C.T.pin((C.HERE / "guest.sh").read_bytes())["sha256"]
        guest["MANIFEST.sha256"] = C.T.pin(prep.checksums(guest))["sha256"]
        argv = prep.continuation_argv(NONCE, guest["MANIFEST.sha256"], "22222222-2222-4222-8222-222222222222")
        plan = dict(kind="QT612_MD4C_COMPILE_CONTINUATION_UNISSUED_V1", authority=None, guest_invoked=False,
                    original_reflink_fallback=False, q3_closure_sha256="6" * 64, q3_postclose_operands=originals,
                    inputs=selected, nonce=NONCE, guest_payload=guest,
                    actor=prep.actor_policy(profile, sum(pin["bytes"] for pin in originals.values())),
                    command_slots={"headers": 6, "pch": 1, "importer": 1}, requested_outputs=[prep.PCH, prep.IMPORTER],
                    qemu_seconds=2100, qemu_argv=argv, retained_native_disk_gate=14 << 30,
                    build_scope="QT_MD4C_IMPORTER_OBJECT_ONLY")
        path = self.out / "plan.json"

        def selected_plan(value):
            raw = prep.canonical(value)
            path.write_bytes(raw)
            return C.read_plan(path, C.T.pin(raw))

        self.assertEqual(selected_plan(plan), plan)
        changed = copy.deepcopy(plan)
        changed["qemu_argv"][argv.index("-nic") + 1] = "user"
        with self.assertRaisesRegex(ValueError, "offline QEMU"):
            selected_plan(changed)
        changed = copy.deepcopy(plan)
        changed["actor"]["child_file_size_cap"] += 512
        with self.assertRaisesRegex(ValueError, "bounded actor policy"):
            selected_plan(changed)

    def test_explicit_predecessor_pins_and_scope_survive_authority_binding(self):
        data = dict(result_uuid=C.P.result_uuid(NONCE), scope="review.scope", plan=PLAN_PIN,
                    prior_closures={"configure": {"path": "/evidence/configure.json", "bytes": 1, "sha256": "5" * 64}})
        plan = dict(nonce=NONCE, q3_closure_sha256="5" * 64)
        handoff = "a" * 64
        expected = C.binding(data, plan, handoff)
        selected = expected | dict(issuer="Root", approved=True, created_utc=100, expires_utc=200)
        raw = C.T.encoded(selected)
        self.assertEqual(C.verify_selection(raw, C.T.pin(raw)["sha256"], data, plan, handoff, live=False), selected)
        tampered = C.T.encoded(selected | {"scope": "other.scope"})
        with self.assertRaisesRegex(ValueError, "differs from the sealed"):
            C.verify_selection(tampered, C.T.pin(tampered)["sha256"], data, plan, handoff, live=False)
        with self.assertRaisesRegex(ValueError, "configure closure"):
            C.binding(data, plan | {"q3_closure_sha256": "6" * 64}, handoff)


if __name__ == "__main__":
    sys.addaudithook(A.O.passive_fence)
    unittest.main()
