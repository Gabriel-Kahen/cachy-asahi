# SPDX-License-Identifier: MIT
"""Offline source, admission, and owned actor boundary fixtures."""

import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parent))
import full_actor as A
import full_capsule as F
import full_guest as G
import full_readback as R
import seal_full as S


NONCE = "a3" * 16
PIN = F.C.pin(b"x")


def staged_authority(handoff, plan, digest):
    now = int(time.time())
    return F.unsupplied_selection(handoff, plan, digest) | dict(
        issuer="Root", approved=True, created_utc=now - 10, expires_utc=now + 30)


class CapsuleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.source = self.root / "source"
        self.runner = dict(kind="ROOT_QTGUI_LINK_RUNNER_PROFILE_V1", actor_image=F.Q.IMAGE, vcpus=4,
                           tools={name: PIN for name in F.P.TOOL_NAMES | {"/usr/bin/qemu-img"}},
                           docker=dict(path="/tools/docker", endpoint="unix:///run/user/1000/docker.sock", **PIN))
        self.enterContext(patch.object(F, "RUNNER_PIN", F.C.pin(F.C.wire(self.runner))))
        records = {name: F.C.pin((F.Q.ROOT / name).read_bytes()) | {"mode": 0o444}
                   for name in F.Q.SOURCE_FILES}
        self.enterContext(patch.object(F, "HISTORICAL_SOURCE", F.C.pin(F.C.wire(records))["sha256"]))
        self.records = S.stage_source(self.source, F.Q.ROOT, records)
        self.limits = F.DEFAULT_LIMITS.copy()
        self.pieces = F.payload(NONCE, self.limits, self.source, self.records)
        self.pins = F.LOWER | {"boot.raw": F.C.file_pin(F.Q.BOOT_BYTES, "1" * 64),
                              "result.raw": F.C.file_pin(self.limits["result_disk_bytes"], "2" * 64)}
        self.plan = F.canonical_plan(NONCE, self.pins, self.limits, self.runner, self.pieces)
        self.handoff = dict(kind="QTBASE_FULL16K_HANDOFF_UNISSUED_V1", authority=None, scope=F.SCOPE,
                            plan=F.C.pin(F.C.wire(self.plan)), runner=self.runner, source=self.records,
                            source_tree_sha256=F.C.pin(F.C.wire(self.records))["sha256"])
        self.digest = F.C.pin(F.C.wire(self.handoff))["sha256"]
        for name, data in {F.PLAN: F.C.wire(self.plan), F.HANDOFF: F.C.wire(self.handoff),
                           F.GUEST: self.pieces[F.GUEST],
                           "binding.UNISSUED.json": F.C.wire(
                               F.unsupplied_selection(self.handoff, self.plan, self.digest))}.items():
            F.K.save(self.root / name, data)

    def test_exact_capsule_and_guest_caps_agree(self):
        self.assertEqual(F.load_capsule(self.root, self.digest), (self.handoff, self.plan))
        guest = G.read_plan(self.root / F.GUEST, self.plan["guest_plan"]["sha256"])
        self.assertEqual(guest["dry_run"], {"gui": F.DRY_GUI, "all": F.DRY_ALL})
        self.assertEqual(len(G.evidence_caps(guest)), 29)
        self.assertFalse(F.unsupplied_selection(self.handoff, self.plan, self.digest)["approved"])
        cmdline = self.plan["qemu_argv"][self.plan["qemu_argv"].index("-append") + 1]
        self.assertIn("root=PARTUUID=" + NONCE[:8], cmdline)
        self.assertIn("cachy_qt_full_guest_plan=" + self.plan["guest_plan"]["sha256"], cmdline)
        self.assertEqual(self.plan["actor"]["child_file_size_cap"], 4 * F.GIB)

    def test_resealed_dry_run_or_argv_mutation_refused(self):
        for key, replacement in (("dry_run_receipt", PIN), ("qemu_argv", ["/bin/false"])):
            with self.subTest(key=key):
                plan = self.plan | {key: replacement}
                changed = self.handoff | {"plan": F.C.pin(F.C.wire(plan))}
                with self.assertRaisesRegex(ValueError, "plan changed"):
                    F.verify_documents(changed, plan, self.source)
        with self.assertRaisesRegex(ValueError, "resource limit"):
            F.limit_shape(self.limits | {"overlay_file_bytes": F.MAX_OVERLAY_FILE_BYTES + 1})
        with self.assertRaisesRegex(ValueError, "headroom|reserve"):
            F.limit_shape(self.limits | {"artifact_bytes": sum(F.INHERITED[role]["bytes"]
                                                               for role in ("core", "dbus", "gui"))})
        with self.assertRaisesRegex(ValueError, "headroom|reserve"):
            F.limit_shape(self.limits | {"qemu_seconds": self.limits["guest_build_seconds"] + F.MIN_QEMU_SLACK_SECONDS - 1})

    def test_explicit_eight_gib_joins_all_outer_disk_bounds(self):
        limits = self.limits | {"overlay_file_bytes": F.MAX_OVERLAY_FILE_BYTES}
        plan = F.canonical_plan(NONCE, self.pins, limits, self.runner, self.pieces)
        policy = plan["actor"]
        self.assertEqual(policy["child_file_size_cap"], 8 * F.GIB)
        self.assertEqual(policy["watched_paths"][0], ["/out/overlay.qcow2", 8 * F.GIB])
        self.assertEqual(policy["watched_tree"], ["/out", 10 * F.GIB + 128 * F.MIB, 2 * F.GIB])
        self.assertEqual(policy["admission_disk_bytes"], 12 * F.GIB + 128 * F.MIB)
        self.assertEqual(plan["guest_plan"], self.plan["guest_plan"])
        self.assertEqual(plan["qemu_argv"], self.plan["qemu_argv"])

    def test_resealed_source_mutation_and_extra_symlink_refused(self):
        for name, error in ((F.DRY_RUN_SOURCE, "observed dry run"), (sorted(F.Q.SOURCE_FILES)[0], "historical runtime")):
            with self.subTest(name=name):
                target = self.source / name
                before = target.read_bytes()
                target.chmod(0o644)
                target.write_bytes(b"changed")
                target.chmod(0o444)
                with self.assertRaisesRegex(ValueError, error):
                    F.verify_source(self.source, {"source": F.source_manifest(self.source)})
                target.chmod(0o644)
                target.write_bytes(before)
                target.chmod(0o444)
        self.source.chmod(0o755)
        (self.source / "unexpected").symlink_to(self.root / F.GUEST)
        self.source.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "source leaf"):
            F.load_capsule(self.root, self.digest)

    def test_selection_scope_window_and_binding(self):
        issued = staged_authority(self.handoff, self.plan, self.digest)
        raw = F.C.wire(issued)
        self.assertEqual(F.verify_selection(raw, F.C.pin(raw)["sha256"], self.handoff, self.plan, self.digest), issued)
        for changed in (issued | {"scope": F.Q.SCOPE}, issued | {"dry_run_receipt": PIN},
                        issued | {"created_utc": 1, "expires_utc": 2}):
            raw = F.C.wire(changed)
            with self.assertRaises(ValueError):
                F.verify_selection(raw, F.C.pin(raw)["sha256"], self.handoff, self.plan, self.digest)

    def test_preflight_capacity_then_exact_template(self):
        available = {"fits": True}
        (self.root / "templates").mkdir(mode=0o700)
        template = self.root / "templates/result.raw"
        F.K.save(template, b"fixture")
        template.parent.chmod(0o555)
        with (patch.object(F, "capacity", return_value=available),
              patch.object(F, "verify_inputs") as verify_inputs,
              patch.object(F, "verify_result_template") as check_template):
            report = F.preflight(self.root, self.digest)
            self.assertEqual(report["full_build"], "NOT RUN")
            verify_inputs.assert_called_once_with(self.root / "inputs", self.plan)
            check_template.assert_called_once_with(template, self.plan)
            available["fits"] = False
            with self.assertRaisesRegex(ValueError, "admission limits"):
                F.preflight(self.root, self.digest)
            self.assertEqual(verify_inputs.call_count, 1)

    def test_whole_input_pins_and_boot_identity(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        boot = bytearray(512)
        struct.pack_into("<I", boot, 440, int(NONCE[:8], 16))
        boot[450], boot[510:] = 0x83, b"\x55\xaa"
        struct.pack_into("<II", boot, 454, F.P.OFFSET // 512, (F.Q.BOOT_BYTES - F.P.OFFSET) // 512)
        items = {name: name.encode() for name in F.INPUTS - {"boot.raw", "result.raw"}} | {"boot.raw": bytes(boot)}
        for name, body in items.items():
            F.K.save(inputs / name, body)
        inputs.chmod(0o555)
        plan = self.plan | {"inputs": {name: F.C.pin(body) for name, body in items.items()}}
        with patch.object(F.K, "inspect_overlay"), patch.object(F, "verify_boot_payload"):
            F.verify_inputs(inputs, plan)
            path = inputs / "gui.qcow2"
            path.chmod(0o644)
            path.write_bytes(b"changed")
            path.chmod(0o444)
            with self.assertRaisesRegex(ValueError, "original file pin"):
                F.verify_inputs(inputs, plan)
            with self.assertRaisesRegex(ValueError, "boot partition identity"):
                F.boot_identity(inputs / "boot.raw", "b5" * 16)

    @unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs"), "ext4 fixture tools unavailable")
    def test_boot_partition_payload_pins(self):
        part = self.root / "part.raw"
        part.touch()
        with part.open("r+b") as stream:
            stream.truncate(8 << 20)
        subprocess.run(["mke2fs", "-Fq", "-t", "ext4", "-b", "4096", "-O", "^orphan_file", str(part)],
                       check=True, capture_output=True)
        edits = [f"mkdir {F.PAYLOAD}"]
        for name, body in self.pieces.items():
            path, entry = self.root / name, f"{F.PAYLOAD}/{name}"
            if not path.exists():
                path.write_bytes(body)
            mode = "0100555" if name == "guest-init.sh" else "0100444"
            edits.extend((f"write {path} {entry}", f"set_inode_field {entry} mode {mode}"))
        commands = self.root / "debugfs.commands"
        commands.write_text("\n".join(edits) + "\n")
        subprocess.run(["debugfs", "-w", "-f", str(commands), str(part)], check=True, capture_output=True)
        boot = self.root / "boot.raw"
        with boot.open("xb") as stream:
            stream.seek(F.P.OFFSET)
            stream.write(part.read_bytes())
        with patch.object(F.Q, "BOOT_BYTES", boot.stat().st_size):
            pins = self.plan["guest_payload"]
            F.verify_boot_payload(boot, pins)
            with self.assertRaisesRegex(ValueError, "original boot payload file"):
                F.verify_boot_payload(boot, pins | {"guest-init.sh": PIN})

    @unittest.skipUnless(all(shutil.which(name) for name in ("mke2fs", "e2fsck", "debugfs")),
                         "ext4 fixture tools unavailable")
    def test_result_template_freshness(self):
        def run(name, args, cwd):
            subprocess.run([name, *map(str, args)], cwd=cwd, check=True, capture_output=True)

        disk = self.root / "result.raw"
        plan = self.plan | {"limits": self.limits | {"result_disk_bytes": 8 << 20}}
        S.stage_result(disk, SimpleNamespace(run=run), plan)
        for dirty in (False, True):
            plan["inputs"] = self.pins | {"result.raw": F.C.pin(disk.read_bytes())}
            if dirty:
                with self.assertRaises(ValueError):
                    F.verify_result_template(disk, plan)
            else:
                F.verify_result_template(disk, plan)
                disk.chmod(0o600)
                run("debugfs", ["-w", "-R", "mkdir /unexpected", disk], self.root)


class ActorTests(unittest.TestCase):
    def run_fixture(self, passed, *, late_failure=False, pin_failure=False):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp).resolve()
            result, overlay = out / "result.raw", out / "overlay.qcow2"
            result.write_bytes(b"original")
            result.chmod(0o600)
            policy = dict(result_disk_bytes=8, admission_disk_bytes=20, watched_tree=["/out", 4096, 1],
                          watched_paths=[["/out/overlay.qcow2", 512], ["/out/result.raw", 8]],
                          child_file_size_cap=512, serial_combined_cap=1024, overlay_create=["create"],
                          overlay_inspect=["info"])
            plan = dict(nonce=NONCE, actor=policy, result_uuid="original-uuid", qemu_argv=["qemu"], qemu_seconds=10,
                        limits={"actor_memory_bytes": 4096},
                        inputs={name: F.C.pin(b"original") for name in ("gui.qcow2", "core.qcow2", "scratch.raw", "result.raw")})
            calls = []
            volume = dict(fits=True, free_bytes=20)

            class Watch:
                peak = {"free": 20}
                samples = 0

                def record(self):
                    self.samples += 1
                    if late_failure and self.samples == 3:
                        raise ValueError("private allocation detail")
                    return self.peak

            def phase(label, argv, seconds, *, file_cap=None):
                calls.append((label, file_cap))
                if label == "overlay-create":
                    overlay.write_bytes(b"initial")
                elif label == "overlay-inspect":
                    (out / "overlay-inspect.stdout").write_bytes(b"chain fixture")
                elif label == "qemu":
                    outcome = "PASS complete" if passed else "HOLD cleanup"
                    (out / "qemu.stdout").write_text(f"QTBASE_FULL16K_TERMINAL {NONCE} {outcome}\n")
                    if passed:
                        overlay.write_bytes(b"built overlay")
                        result.write_bytes(b"new-data")
                return PIN

            runner = SimpleNamespace(plan=plan, actor=policy, phase=phase, verify_tools=lambda: None,
                                     issued={"expires_utc": time.time() + 60}, deadline=time.monotonic() + 60,
                                     runtime=SimpleNamespace(GUARD=None), tools={}, authority_sha="1" * 64,
                                     handoff_sha="2" * 64)
            with (patch.object(A, "OUT", out), patch.object(A, "require_absence") as absent,
                  patch.object(A, "cgroup_peak", return_value=1024),
                  patch.object(A.B, "AllocationWatch", return_value=Watch()),
                  patch.object(A.F, "capacity", return_value=volume),
                  patch.object(A.F, "verify_result_template"),
                  patch.object(A.F, "result_uuid", return_value="original-uuid"),
                  patch.object(A.F, "validate_chain"), patch.object(A.F.K, "inspect_overlay"),
                  patch.object(A.F, "verify_source"),
                  patch.object(A.F, "verify_inputs",
                               side_effect=[None, ValueError("changed")] if pin_failure else None) as verify_inputs):
                report_path = out / "actor-result.json"
                if late_failure or pin_failure:
                    with self.assertRaises(ValueError):
                        A.run({"plan": PIN}, runner)
                    self.assertFalse(report_path.exists())
                else:
                    self.assertEqual(A.run({"plan": PIN}, runner), 0 if passed else 2)
                    report = json.loads(report_path.read_bytes())
                    self.assertEqual(report.keys(), F.C.ACTOR_KEYS)
                    self.assertEqual(report["status"], "PASS_QTBASE_ALL_FOR_REVIEW" if passed else "HOLD")
                    self.assertEqual(report["phase"], "complete" if passed else "cleanup")
                self.assertEqual(verify_inputs.call_count, 2)
                self.assertEqual(absent.call_count, 2)
                self.assertEqual(calls, [("overlay-create", None), ("overlay-inspect", None),
                                         ("qemu", 512), ("fsck-result", None)])
                self.assertIsNone(runner.runtime.GUARD)

    def test_pass_and_cleanup_hold(self):
        self.run_fixture(True)
        self.run_fixture(False)

    def test_postrun_pin_and_final_ceiling_fail_closed(self):
        self.run_fixture(True, late_failure=True)
        self.run_fixture(True, pin_failure=True)

    def test_cli_diagnostics_do_not_echo_private_paths(self):
        with (patch.object(sys, "argv", ["actor", "--handoff-sha256", "a", "--authority-sha256", "b"]),
              patch.dict(os.environ, {"CACHY_ASAHI_QTBASE_FULL16K_ACTOR": "1"}),
              patch.object(A.F.Q.O, "actor_boundary", side_effect=ValueError("/private/attack detail"))):
            with self.assertRaisesRegex(SystemExit, "^Full Qtbase actor refused or held$"):
                A.main()
        with (patch.object(sys, "argv", ["reader", "--capsule", "/", "--authority", "/", "--output", "/",
                                       "--handoff-sha256", "a", "--authority-sha256", "b", "--actor-result-sha256", "c"]),
              patch.object(sys, "addaudithook") as fence,
              patch.object(R, "readback", side_effect=ValueError("/private/attack detail"))):
            with self.assertRaisesRegex(SystemExit, "^Full Qtbase readback refused$"):
                R.main()
            fence.assert_called_once_with(R.C.audit_fence)


if __name__ == "__main__":
    unittest.main()
