#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert assembly tests using fresh synthetic, unmounted result carriers."""

from pathlib import Path
from runpy import run_path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
M = run_path(str(HERE / "receipt.py"))
F = run_path(str(HERE / "test_readback.py"))
H, E, R, C = (M[key] for key in ("H", "E", "R", "C"))
NONCE = F["NONCE"]


@unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs"), "e2fsprogs unavailable")
class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.expected, original_bodies, self.raw = F["fixture"]()
        self.originals, self.test_inputs = {}, {}
        self.bundle = self.root / "bundle"
        self.observation = self.root / "stopped.json"
        self.enterContext(patch.dict(R["ORIGINALS"], self.expected["original_inputs"]))
        self.enterContext(patch.dict(R["P"]["PINS"], self.expected["original_inputs"]))
        inputs = self.root / "originals"
        inputs.mkdir()
        for role, body in original_bodies.items():
            path = inputs / role
            path.write_bytes(body)
            self.originals[role] = path
        for name in E["TEST_FILES"]:
            path = inputs / name
            path.write_bytes(self.raw[name])
            self.test_inputs[name] = path, C.pin(self.raw[name])
        self.times = {row["event"]: row["at_ns"] for row in self.expected["chronology"]}

    def make_disk(self, **owner_changes):
        source = self.root / "tree"
        source.mkdir()
        cleanup = C.wire(dict(completed=True, target_submounts=[],
                              keyrings=dict.fromkeys(R["TRUST_HOMES"], "removed")))
        actor_terminal = C.json_body(self.raw["transaction.jsonl"].splitlines()[-1])
        del actor_terminal["phase"], actor_terminal["at_ns"]
        owner = dict(status=R["P"]["PASS629"], nonce=NONCE, cleanup=C.pin(cleanup),
                     inventory=dict(rollback=self.expected["original_inputs"]["rollback_lock"]),
                     platform=dict(rollback=C.pin(self.raw["baseline-platform.json"])),
                     trust_retired_at_ns=self.times["trust-retired"],
                     qt_checkpoint=dict(nonce=NONCE, transaction=actor_terminal,
                                        runtime_probe=C.pin(self.raw["runtime-probes.json"]))) | owner_changes
        asahi = dict.fromkeys(H["ASAHI_FILES"], b"synthetic Asahi operating evidence\n")
        asahi |= {"result.json": C.wire(owner), "cleanup.json": cleanup, "rollback.lock": self.raw["baseline.lock"]}
        members = {f"evidence/{name}": body for name, body in asahi.items()}
        members.update({f"{E['ACTOR_DIR']}/{name}": self.raw[name] for name in E["ACTOR_FILES"]})
        for relative, body in members.items():
            path = source / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(0o600)
        disk = self.root / "result.raw"
        with disk.open("xb") as stream:
            stream.truncate(E["RESULT_BYTES"])
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-b", "4096", "-O", "^orphan_file",
                        "-d", str(source), str(disk)], check=True, capture_output=True)
        ownership = self.root / "ownership.debugfs"
        ownership.write_text("".join(f"set_inode_field /{path.relative_to(source)} {field} 0\n"
                                     for path in source.rglob("*") for field in ("uid", "gid")))
        subprocess.run(["debugfs", "-w", "-f", str(ownership), str(disk)], check=True, capture_output=True)
        return disk, C.read(disk, E["RESULT_BYTES"], collect=False)[1]

    def observed(self, pin, *, nonce=NONCE):
        return dict(kind=M["STOPPED"], nonce=nonce, disk=pin, held=False,
                    retirement=self.expected["retirement"] | {"nonce": nonce},
                    host_times={name: self.times[name] for name in M["HOST_TIMES"]})

    def assemble(self, disk, row, *, nonce=NONCE, digest=None):
        body = C.wire(row)
        self.observation.write_bytes(body)
        return M["assemble"](disk_path=disk, observation=self.observation, nonce=nonce,
                             observation_sha=digest or C.pin(body)["sha256"], bundle=self.bundle,
                             originals=self.originals, test_inputs=self.test_inputs)

    def assert_unpublished(self):
        self.assertFalse(self.bundle.exists())
        self.assertEqual(list(self.root.glob(".qt629-receipt.*")), [])

    def test_assembles_exact_receipt_after_pass_and_preserves_source(self):
        disk, pin = self.make_disk()
        before = C.identity(disk.lstat())
        report = self.assemble(disk, self.observed(pin))
        body = (self.bundle / "receipt.json").read_bytes()
        self.assertEqual(body, C.wire(self.expected))
        self.assertEqual(report["receipt"], C.pin(body))
        self.assertEqual(report["stopped_observation"], C.pin(self.observation.read_bytes()))
        self.assertEqual(R["readback"](self.bundle, report["receipt"]["sha256"])["untouched_rows"], 628)
        self.assertEqual(C.identity(disk.lstat()), before)
        self.assertEqual(C.read(disk, E["RESULT_BYTES"], collect=False)[1], pin)

    def test_rejects_rebound_outer_nonce_for_exact_foreign_disk(self):
        disk, pin = self.make_disk()
        foreign = "e" * 32
        with self.assertRaisesRegex(ValueError, "Stopped guest evidence nonce differs"):
            self.assemble(disk, self.observed(pin, nonce=foreign), nonce=foreign)
        self.assert_unpublished()

    def test_refuses_actor_journal_from_another_guest_with_matching_owner_nonce(self):
        rows = [C.json_body(line) for line in self.raw["transaction.jsonl"].splitlines()]
        rows[0]["nonce"] = "e" * 32
        self.raw["transaction.jsonl"] = F["jsonl"](rows)
        disk, pin = self.make_disk()
        with self.assertRaisesRegex(ValueError, "Stopped guest evidence nonce differs"):
            self.assemble(disk, self.observed(pin))
        self.assert_unpublished()

    def test_refuses_missing_times_retirement_or_selected_observation(self):
        pin = C.file_pin(E["RESULT_BYTES"], "1" * 64)
        path = self.root / "missing.raw"
        row = self.observed(pin)
        with self.assertRaisesRegex(ValueError, "External digest differs"):
            self.assemble(path, row, digest="0" * 64)
        with self.assertRaisesRegex(ValueError, "Held result cannot supply"):
            self.assemble(path, row | {"held": True})
        retired = row["retirement"]
        with self.assertRaisesRegex(ValueError, "observed absent twice"):
            self.assemble(path, row | {"retirement": retired | {"observations": retired["observations"][:1]}})
        del row["host_times"]["vm-exited"]
        with self.assertRaisesRegex(ValueError, "Unexpected host chronology"):
            self.assemble(path, row)
        self.assert_unpublished()

    def test_refuses_to_infer_guest_cleanup_timestamp(self):
        disk, pin = self.make_disk(trust_retired_at_ns=None)
        with self.assertRaisesRegex(ValueError, "witnessed cleanup"):
            self.assemble(disk, self.observed(pin))
        self.assert_unpublished()

    def test_refuses_conflicting_exact_disk_pin(self):
        disk, pin = self.make_disk()
        with self.assertRaisesRegex(ValueError, "Exact original file pin"):
            self.assemble(disk, self.observed(pin | {"sha256": "0" * 64}))
        self.assert_unpublished()

    def test_refuses_invalid_observed_host_chronology(self):
        disk, pin = self.make_disk()
        row = self.observed(pin)
        row["host_times"]["vm-exited"] = self.times["trust-retired"] - 1
        with self.assertRaisesRegex(ValueError, "Misordered chronology"):
            self.assemble(disk, row)
        self.assert_unpublished()

    def test_invalid_runtime_evidence_is_refused_before_receipt_publication(self):
        name = "runtime-probes.json"
        runtime = C.json_body(self.raw[name])
        runtime["checks"]["vulkan_qrhi"]["steps"][0]["argv"].insert(len(R["PROBE_PREFIX"]), "QT_PLUGIN_PATH=/tmp/extra")
        self.raw[name] = C.wire(runtime)
        disk, pin = self.make_disk()
        with self.assertRaisesRegex(ValueError, "Runtime probe launch environment differs: vulkan_qrhi"):
            self.assemble(disk, self.observed(pin))
        self.assert_unpublished()

    def test_publication_preserves_existing_destination(self):
        disk, pin = self.make_disk()
        self.bundle.mkdir()
        marker = self.bundle / "kept.txt"
        marker.write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            self.assemble(disk, self.observed(pin))
        self.assertEqual(list(self.bundle.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b"original")
        self.assertEqual(list(self.root.glob(".qt629-receipt.*")), [])


if __name__ == "__main__":
    unittest.main()
