#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert Qt629 unissued preparation, packing and retirement controls."""

from pathlib import Path
from runpy import run_path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


S = run_path(str(Path(__file__).with_name("controller.py")))
C, H = S["C"], S["H"]
ROOT = Path(__file__).resolve().parents[3]
NONCE = "a" * 32


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.preview = self.root / "preview"
        self.preview.mkdir()
        self.legacy_media = {"keys": {"preview-test": {"not_before": 1, "not_after": 10000}}}
        (self.preview / "manifest.json").write_bytes(C.wire(self.legacy_media))
        self.base = {name: C.pin((ROOT / leaf).read_bytes()) for name, (leaf, _, _) in H["BASE"].items()}
        self.worker_paths = {name: ROOT / leaf for name, (leaf, _, _) in H["BASE"].items()}
        self.rehashed = []
        self.legacy = dict(selection=lambda: (self.worker_paths, self.base), T=object(),
                           O=SimpleNamespace(rehash=lambda _, root, media: self.rehashed.append((root, media)),
                                             TRUST_ALLOWANCE=5820))
        self.handoff = self.root / "handoff.json"
        self.old = dict(nonce="b" * 32, control={}, control_boot={}, references={}, source={}, actor_image="fixture")
        self.pin = C.pin(b"selected predecessor fixture")
        self.originals = {}
        for index, role in enumerate(S["FIXED_MEDIA"].values()):
            path = self.root / role
            body = bytes([index + 1])
            path.write_bytes(body)
            self.originals[role] = dict(path=str(path), **C.pin(body))
        self.run = self.root / "retained"
        self.init = self.run / "output/asahi629/init.readback"
        self.init.parent.mkdir(parents=True)
        init = b'[[ $$ == 1 && $# == 0 && $EUID == 0 ]]\nexport_evidence /trial-work/evidence /trial-export/evidence\n'
        self.init.write_bytes(init)
        self.enterContext(patch.dict(H["PID1"], C.pin(init)))
        self.enterContext(patch.dict(S["R"]["ORIGINALS"], {
            role: {"bytes": row["bytes"], "sha256": row["sha256"]} for role, row in self.originals.items()
        }))
        self.enterContext(patch.dict(S["prepare"].__globals__,
                                     retained_controller=lambda _: (self.legacy, self.old, self.pin),
                                     selected_originals=lambda *_: (self.originals, self.pin, "b" * 32)))
        self.enterContext(patch.object(S["time"], "time", return_value=100))
        self.enterContext(patch.object(S["secrets"], "token_hex", return_value=NONCE))

    def prepare(self, **overrides):
        fields = dict(run=self.run, preview=self.preview, handoff=self.handoff, handoff_sha=self.pin["sha256"],
                      qt_source=ROOT, r132={}, output=self.root / "preparation")
        return S["prepare"](**(fields | overrides))

    def test_unissued_draft_binds_fixed_worker_pid1_plan_and_media(self):
        report = self.prepare()
        file = Path(report["path"])
        raw = file.read_bytes()
        record = C.json_body(raw, canonical=True)
        self.assertEqual(C.pin(raw), {name: report[name] for name in ("bytes", "sha256")})
        self.assertEqual(self.rehashed, [(self.preview, self.legacy_media)])
        self.assertEqual(record["nonce"], NONCE)
        self.assertIsNone(record["authority"])
        self.assertIsNone(record["display"]["source"])
        self.assertEqual(record["display"]["package_inventory"], 629)
        stage = file.parent / "stage"
        draft = (stage / "guest-plan.UNISSUED.json").read_bytes()
        self.assertEqual(record["staged"]["draft_plan"], C.pin(draft))
        self.assertEqual(record["staged"]["init"], C.pin((stage / "guest-init.sh").read_bytes()))
        value = C.json_body(draft, canonical=True)
        self.assertEqual(value["kind"], S["DRAFT"])
        self.assertEqual(value["code"]["asahi-guest.py"], record["staged"]["worker"])
        for name in S["TEST_MEDIA"] | S["WESTON_MEDIA"]:
            self.assertIsNone(value["qt_media"]["qt-replacement/" + name])
            self.assertFalse((stage / "inputs/qt-replacement" / name).exists())
        self.assertFalse((stage / "code/plan.json").exists())

    def test_incomplete_test_or_display_input_cannot_select_stage(self):
        with self.assertRaisesRegex(ValueError, "fully selected"):
            self.prepare(wayland_socket="/run/qt629-wl/wayland-0")
        self.assertFalse((self.root / "preparation").exists())

    def test_fresh_output_and_nonce_are_required(self):
        with patch.object(S["secrets"], "token_hex", return_value="b" * 32):
            with self.assertRaisesRegex(ValueError, "Fresh Qt trial nonce"):
                self.prepare()
        report = self.prepare()
        body = Path(report["path"]).read_bytes()
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(Path(report["path"]).read_bytes(), body)


class PackTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.stage = self.root / "stage"
        self.target = self.root / "packed"
        self.base = {"kind": H["KIND"], "nonce": NONCE, "media": {}, "manifest": C.pin(C.wire({})),
                     "code": {name: C.pin(b"old worker") for name in H["BASE"]}}

    def pack(self, include_display=True, rebound_display=False):
        code = self.base["code"].keys() | H["GUEST_ENTRY"]["SOURCES"] | H["WESTON_SOURCES"]
        payload = {"code/" + name: b"reviewed code" for name in code}
        names = S["FIXED_MEDIA"].keys() | S["TEST_MEDIA"]
        if include_display:
            names |= S["WESTON_MEDIA"]
        payload |= {"inputs/qt-replacement/" + name: b"synthetic input" for name in names}
        plan = self.base | {"qt_replacement": {"wayland_socket": S["DISPLAY_SOCKET"], "project_review": {}},
                            "code": {name.removeprefix("code/"): C.pin(body) for name, body in payload.items()
                                     if name.startswith("code/")},
                            "qt_media": {name.removeprefix("inputs/"): C.pin(body) for name, body in payload.items()
                                         if name.startswith("inputs/")}}
        payload["code/plan.json"] = C.wire(plan)
        for leaf, body in payload.items():
            S["put"](self.stage / leaf, body)
        receipt = dict(authority=None, kind="QT629_HOST_STAGE_UNISSUED_V1", path=str(self.stage),
                       plan=C.pin(payload["code/plan.json"]), worker=plan["code"]["asahi-guest.py"],
                       files={name: C.pin(body) for name, body in payload.items()})

        def base_copy(_preview, base_plan, root):
            files = {"inputs/manifest.json": S["put"](root / "inputs/manifest.json", b"original manifest")}
            for leaf in base_plan["code"]:
                files["code/" + leaf] = S["put"](root / "code" / leaf, b"old worker")
            files["code/plan.json"] = S["put"](root / "code/plan.json", C.wire(base_plan))
            return files, {}, {"code", "inputs"}

        def checked_copy(src, dest, pin):
            S["put"](dest, C.read(src, pin["bytes"], pin)[0])

        legacy = dict(copy_transport=base_copy, C=SimpleNamespace(checked_copy=checked_copy))
        display = dict(fixture=S["DISPLAY"], socket=S["DISPLAY_SOCKET"], package_inventory=629,
                       intake_receipt=C.pin(b"approved Weston receipt"), source=C.pin(b"reviewed code"),
                       media={name: C.pin(b"synthetic input") for name in S["WESTON_MEDIA"]})
        if rebound_display:
            display["media"][S["WESTON_ARCHIVE"]] = C.pin(b"different verified archive")
        return S["pack_inputs"](legacy, self.root, self.base, self.target, self.stage, receipt, display=display)

    def test_pack_joins_complete_code_media_and_original_manifest(self):
        plan, (files, aliases, directories) = self.pack()
        self.assertEqual(aliases, {})
        self.assertEqual((self.target / "inputs/manifest.json").read_bytes(), b"original manifest")
        self.assertEqual(C.json_body((self.target / "code/plan.json").read_bytes()), plan)
        self.assertIn("inputs/qt-replacement", directories)
        self.assertIn("inputs/qt-replacement/" + S["WESTON_ARCHIVE"], files)

    def test_pack_refuses_socket_only_stage_without_weston_inputs(self):
        with self.assertRaisesRegex(ValueError, "allowlist"):
            self.pack(include_display=False)
        self.assertFalse(self.target.exists())

    def test_pack_refuses_different_weston_intake_even_with_all_names(self):
        with self.assertRaisesRegex(ValueError, "verified intake"):
            self.pack(rebound_display=True)
        self.assertFalse(self.target.exists())


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.disk = C.file_pin(S["E"]["RESULT_BYTES"], "1" * 64)
        self.terminal = self.root / "stopped.json"

    def write(self, *, held, removed=True, twice=True, exit_code=0):
        observations = [dict(event=event, qemu=[], outer_containers=[])
                        for event in ("absence-first", "absence-second")]
        row = dict(nonce=NONCE, target_submounts=[], keyrings=dict.fromkeys(S["R"]["TRUST_HOMES"], "removed"),
                   qemu=dict(exit=exit_code, reaped=True, output_complete=True, timeout=False, signals=[]),
                   outer_container=dict(id="c" * 64, exit=0, removed=removed),
                   observations=observations if twice else observations[:1])
        body = C.wire(dict(kind=S["STOPPED"], disk=self.disk, nonce=NONCE, held=held, retirement=row))
        self.terminal.write_bytes(body)
        return C.pin(body)["sha256"]

    def test_stopped_receipt_distinguishes_natural_completion_from_held_export(self):
        natural = self.write(held=False)
        self.assertFalse(S["stopped"](self.terminal, natural, NONCE, self.disk)[0])
        with self.assertRaisesRegex(ValueError, "Natural owned QEMU retirement"):
            S["stopped"](self.terminal, self.write(held=False, exit_code=1), NONCE, self.disk)
        held = self.write(held=True, exit_code=1)
        with (patch.dict(H, export_result=lambda *_args, **kwargs: dict(forwarded=kwargs["held"],
                                                                         forwarded_nonce=kwargs["expected_nonce"])),
              patch.dict(S["export_stopped"].__globals__, require_result_uuid=lambda *_: None)):
            report = S["export_stopped"](disk_path=self.root / "result.raw", disk_pin=self.disk,
                                         retirement=self.terminal, retirement_sha=held, nonce=NONCE,
                                         bundle=self.root / "bundle")
        self.assertTrue(report["held"] and report["forwarded"])
        self.assertEqual(report["forwarded_nonce"], NONCE)

    @unittest.skipUnless(shutil.which("mke2fs"), "e2fsprogs unavailable")
    def test_empty_hold_disk_requires_ext4_uuid_for_the_stopped_nonce(self):
        for matches, uuid in ((False, "36e72e0f-4497-ef06-b149-38cd3a56fc41"),
                              (True, "b538a478-95e5-ddf8-a1e6-60651a662436")):
            with self.subTest(matches=matches):
                disk = self.root / f"result-{matches}.raw"
                with disk.open("xb") as stream:
                    stream.truncate(S["E"]["RESULT_BYTES"])
                subprocess.run(["mke2fs", "-q", "-t", "ext4", "-b", "4096", "-O", "^orphan_file",
                                "-U", uuid, "-L", "OV583_RESULT", str(disk)], check=True, capture_output=True)
                _, self.disk = C.read(disk, S["E"]["RESULT_BYTES"], collect=False)
                qt, asahi = self.root / "qt", self.root / "asahi"
                args = dict(disk_path=disk, disk_pin=self.disk, retirement=self.terminal,
                            retirement_sha=self.write(held=True, exit_code=1), nonce=NONCE,
                            bundle=qt, asahi_bundle=asahi)
                if matches:
                    report = S["export_stopped"](**args)
                    self.assertFalse(report["actor_directory_present"])
                    self.assertEqual(report["evidence"], {})
                else:
                    with self.assertRaisesRegex(ValueError, "ext4 UUID differs from the run nonce"):
                        S["export_stopped"](**args)
                    self.assertFalse(qt.exists())
                    self.assertFalse(asahi.exists())

    def test_refuses_incomplete_absence_or_different_nonce_before_export(self):
        for kwargs in ({"removed": False}, {"twice": False}):
            digest = self.write(held=True, **kwargs)
            with self.assertRaisesRegex(ValueError, "two owned absence"):
                S["stopped"](self.terminal, digest, NONCE, self.disk)
        with self.assertRaisesRegex(ValueError, "Expected exact stopped"):
            S["stopped"](self.terminal, self.write(held=True), "d" * 32, self.disk)


if __name__ == "__main__":
    unittest.main()
