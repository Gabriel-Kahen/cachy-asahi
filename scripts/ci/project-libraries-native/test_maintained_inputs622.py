# SPDX-License-Identifier: MIT
"""Verify the maintained input boundary and inert original-producer receipts."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import maintained_inputs622 as maintained
from inputs622 import load


class MaintainedInputs(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.spec = maintained.locked()
        self.binding = self.spec["baseline"]
        self.packet = maintained.packet_tools(self.binding)
        self.inputs = self.packet.load(maintained.ROOT / maintained.INPUTS, self.binding["input_lock_sha256"])
        self.pins = maintained.transport_pins(self.inputs)

    def prepared(self):
        source = maintained.stage_producer(self.root, self.binding, self.packet)
        return maintained.PreparedMaintained(source, self.root / "alarm-cache", self.root / "extension",
                                             self.root / "expected341.lock", self.root / "expected346.lock",
                                             self.root / "recipes")

    def test_exact_original_operand_counts_and_producer_snapshot(self):
        self.assertEqual(len(self.pins), 501)
        self.assertEqual(sum(name.endswith(".sig") for name in self.pins), 249)
        self.assertEqual(len(maintained.extension_pins()), 10)
        self.assertEqual(sum(pin["bytes"] for pin in maintained.extension_pins().values()), 24202822)
        item = self.prepared()
        files = {p.relative_to(item.producer_source).as_posix() for p in item.producer_source.rglob("*") if p.is_file()}
        self.assertEqual(len(files), 89)
        self.assertIn(maintained.PRODUCER, files)
        self.assertIn(self.packet.RECIPES_LOCK, files)
        self.assertNotIn(maintained.HELD_CHECKER, files)
        self.assertFalse(any(name.startswith(self.packet.KERNEL) for name in files))
        self.assertEqual(self.packet.capture(item.producer_source / maintained.CHECKER),
                         self.packet.capture(maintained.ROOT / maintained.HELD_CHECKER))

    def test_producer_rejects_same_size_checker_drift(self):
        held = maintained.ROOT / maintained.HELD_CHECKER
        capture = self.packet.capture
        body, mode = capture(held)
        checker = self.root / "drifted-checker.py"
        checker.write_bytes(bytes([body[0] ^ 1]) + body[1:])
        checker.chmod(mode)

        def capture_with_drift(path):
            return capture(checker if path == held else path)

        with patch.object(self.packet, "capture", side_effect=capture_with_drift) as read:
            with self.assertRaisesRegex(ValueError, "producer byte/mode pin"):
                maintained.stage_producer(self.root, self.binding, self.packet)
            read.assert_any_call(held)

    def test_exact_tiff_extension_inventory(self):
        base = self.packet.read(maintained.ROOT / maintained.BASE_LOCK)
        tiff = maintained.derive_locks(base, self.spec["extension"], self.packet)
        self.assertEqual(len(tiff.splitlines()), 346)
        self.assertEqual(self.packet.sha(tiff), self.spec["extension"]["tiff_packages_lock_sha256"])
        old = set(base.splitlines())
        new = set(tiff.splitlines())
        self.assertEqual(old - new, {b"jbigkit 2.1-8"})
        self.assertEqual(new - old, {b"cachy-asahi-jbigkit 2.2-1.1", b"cmake 4.4.4-1", b"cppdap 1.58.0-3",
                                     b"jsoncpp 1.9.8-1", b"libuv 1.52.1-2", b"rhash 1.4.6-1"})

    def test_retained_subset_and_full_cache_are_distinct_finite_namespaces(self):
        pins = {name: {} for name in ("a", "b", "c")}
        lock = dict(transport_files=3, retained_files=2, retained_names_sha256=hashlib.sha256(b"a\nb\n").hexdigest())
        for name in ("a", "b"):
            (self.root / name).touch()
        self.assertEqual(maintained.selected_cache_pins(self.root, lock, pins, full=False), {"a": {}, "b": {}})
        with self.assertRaisesRegex(ValueError, "full maintained cache"):
            maintained.selected_cache_pins(self.root, lock, pins, full=True)
        (self.root / "b").rename(self.root / "c")
        with self.assertRaisesRegex(ValueError, "retained baseline membership"):
            maintained.selected_cache_pins(self.root, lock, pins, full=False)
        (self.root / "b").touch()
        self.assertEqual(maintained.selected_cache_pins(self.root, lock, pins, full=True), pins)

    def test_nonordinary_cache_inputs_refuse(self):
        original = self.root / "actual"
        original.touch()
        alias = self.root / "alias"
        for join in (lambda: alias.symlink_to(original), lambda: os.link(original, alias)):
            join()
            with self.assertRaisesRegex(ValueError, "single-link ordinary"):
                maintained.cache_names(self.root)
            alias.unlink()

    def inert_receipts(self, target, *, mode):
        target.mkdir()
        item = self.prepared_item
        original_sha = self.packet.HELPERS[maintained.PRODUCER][0]
        image = "sha256:" + "1" * 64
        result = dict(mode=mode, reviewed_inputs_sha256=self.binding["input_lock_sha256"],
                      reviewed_recipes_sha256=self.binding["recipe_lock_sha256"], hardware_validation="NOT RUN",
                      bootstrap_script_sha256=original_sha, verified_signed_packages=248)
        if mode == "build":
            result.update(status="native-builds-and-byte-comparison-pass", native_build="PASS")
        else:
            result.update(status="signed-input-audit-pass", native_build="NOT RUN")
        files = {
            "result.json": result,
            "cache-checksums.json": {name: pin["sha256"] for name, pin in self.pins.items()},
            "bootstrap.json": dict(status="image-provisioned", image_id=image,
                                   inputs_sha256=self.binding["input_lock_sha256"],
                                   packages_lock_sha256=self.binding["packages_lock_sha256"]),
            "runner.json": dict(commit="a" * 40, runner_arch="ARM64", uid=os.getuid(),
                                bootstrap_script_sha256=original_sha),
        }
        if mode == "audit":
            signer = self.inputs["signer_fingerprint"]
            names = [row["filename"] for row in (self.inputs["rootfs"], *self.inputs["packages"])]
            files.update({
                "acquisition.json": {"counts": dict(total=501, pass_=501, fail=0, pending=0)},
                "package-audit.json": {name: {} for name in names[1:]},
                "rootfs-inventory.json": self.inputs["rootfs_packages"],
                "signatures.json": {name: {"exit_code": 0,
                    "status": f"[GNUPG:] VALIDSIG {signer} 2026-11-25 1 0 4 0 1 10 00 {signer}\n",
                    "command": [str(item.cache / (name + ".sig")), str(item.cache / name)]} for name in names},
            })
            counts = files["acquisition.json"]["counts"]
            counts["pass"] = counts.pop("pass_")
        for name, value in files.items():
            (target / name).write_text(json.dumps(value))
        (target / "image-id").write_text(image + "\n")
        (target / "inputs.lock.json").write_bytes(self.packet.read(item.producer_source / maintained.INPUTS))
        (target / "packages.lock").write_bytes(self.packet.read(maintained.ROOT / maintained.BASE_LOCK))
        return image

    def test_bootstrap_requires_same_job_successful_command_and_image(self):
        self.prepared_item = self.prepared()
        report = {}

        def run(argv, *, cwd):
            self.assertEqual(cwd, self.prepared_item.producer_source)
            self.assertEqual(argv[4], "build")
            self.assertEqual(argv[-4:], ["--cache", str(self.prepared_item.cache), "--output", str(self.root / "producer")])
            self.inert_receipts(Path(argv[-1]), mode="build")
            return subprocess.CompletedProcess(argv, 0)

        image = maintained.bootstrap_maintained(self.prepared_item, self.root, report, run_producer=run, commit="a" * 40)
        self.assertEqual(image, "sha256:" + "1" * 64)
        self.assertEqual(report["maintained_base"]["pinned_objects"], 501)

    def test_bootstrap_refuses_unjoined_commit_and_false_success(self):
        self.prepared_item = self.prepared()

        def other_process(argv, *, cwd):
            return subprocess.CompletedProcess(["unexpected"], 0)

        with self.assertRaisesRegex(ValueError, "natural exit"):
            maintained.bootstrap_maintained(self.prepared_item, self.root, {}, run_producer=other_process, commit="a" * 40)

        def different_commit(argv, *, cwd):
            self.inert_receipts(Path(argv[-1]), mode="build")
            return subprocess.CompletedProcess(argv, 0)

        with self.assertRaisesRegex(ValueError, "same-job"):
            maintained.bootstrap_maintained(self.prepared_item, self.root, {}, run_producer=different_commit, commit="b" * 40)

    def failure_receipts(self, output):
        output.mkdir()
        tag = "cachy-asahi-fish-config-1"
        record = {"status": "failed", "mode": "build", "native_build": "NOT RUN", "hardware_validation": "NOT RUN",
                  "reviewed_inputs_sha256": self.binding["input_lock_sha256"],
                  "reviewed_recipes_sha256": self.binding["recipe_lock_sha256"],
                  "bootstrap_script_sha256": self.packet.HELPERS[maintained.PRODUCER][0],
                  "verified_signed_packages": 248,
                  "error": f"command failed (1); see {output / (tag + '-driver.log')}"}
        (output / "result.json").write_text(json.dumps(record))
        acquisition = {"schema_version": 1, "acquisition": "PASS", "signature_authentication": "NOT RUN",
                       "counts": {"total": 501, "pass": 501, "fail": 0, "pending": 0},
                       "inputs": {name: {"status": "PASS", "expected_bytes": row["bytes"],
                                        "expected_sha256": row["sha256"]} for name, row in self.pins.items()}}
        (output / "acquisition.json").write_text(json.dumps(acquisition))
        context = output / "context"
        context.mkdir()
        config = context / "pacman.conf"
        config.write_bytes(maintained.PACMAN_CONFIG)
        config.chmod(0o600)
        recipe = output / tag
        recipe.mkdir()
        (recipe / "build.log").write_bytes(b"RAW_PRIVATE_DIAGNOSTIC\n"
            b"error: config file /etc/pacman.conf could not be read: Permission denied\n")
        return (json.dumps(record, sort_keys=True) + "\n").encode()

    def test_natural_producer_failure_projects_only_exact_receipt_mode_and_marker(self):
        self.prepared_item = self.prepared()
        observer = load(maintained.ROOT / "scripts/port/kernel-native-job/job.py", "_622_failure_fixture")
        report = {}

        def run(argv, *, cwd):
            return subprocess.CompletedProcess(argv, 1, self.failure_receipts(Path(argv[-1])))

        with self.assertRaisesRegex(ValueError, "maintained producer natural exit"):
            maintained.bootstrap_maintained(self.prepared_item, self.root, report, run_producer=run,
                commit="a" * 40, observe_failure=observer.observe_producer_failure)
        note = report["maintained_producer_failure"]
        self.assertEqual((note["exit_code"], note["pacman_conf_mode"], note["pacman_permission"]), (1, 0o600, "OBSERVED"))
        self.assertEqual(note["observation"]["diagnostic"]["phase"], "BUILD")
        self.assertEqual(note["command"], {"role": "RECIPE_BUILD", "recipe": "cachy-asahi-fish-config", "attempt": 1, "exit_code": 1})
        emitted = json.dumps(report)
        for private in (str(self.root), "RAW_PRIVATE_DIAGNOSTIC", "Permission denied", "rootfs.tar.gz", "pacman.conf could"):
            self.assertNotIn(private, emitted)

    def test_unjoined_failure_does_not_supply_mode_stage_or_log_marker(self):
        self.prepared_item = self.prepared()
        observer = load(maintained.ROOT / "scripts/port/kernel-native-job/job.py", "_622_invalid_failure_fixture")
        report = {}

        def run(argv, *, cwd):
            self.failure_receipts(Path(argv[-1]))
            return subprocess.CompletedProcess(argv, 1, b"other producer stdout\n")

        with self.assertRaisesRegex(ValueError, "maintained producer natural exit"):
            maintained.bootstrap_maintained(self.prepared_item, self.root, report, run_producer=run,
                commit="a" * 40, observe_failure=observer.observe_producer_failure)
        note = report["maintained_producer_failure"]
        self.assertEqual(note["observation"]["availability"], "REFUSED")
        self.assertEqual(note["pacman_permission"], "NOT_OBSERVED")
        self.assertIsNone(note["pacman_conf_mode"])
        self.assertIsNone(note["command"])

    def test_audit_requires_each_exact_signature_and_its_actual_operands(self):
        self.prepared_item = self.prepared()
        output = self.root / "maintained-audit"
        self.inert_receipts(output, mode="audit")
        signatures = output / "signatures.json"
        rows = json.loads(signatures.read_bytes())
        first = next(iter(rows.values()))
        expected_command = first["command"][:]
        arguments = (output, self.prepared_item.cache, self.prepared_item.producer_source, self.binding, self.packet)
        maintained.verify_audit(*arguments)

        first["command"][-1] = "different archive"
        signatures.write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError, "operands"):
            maintained.verify_audit(*arguments)

        first["command"] = expected_command
        first["status"] = first["status"].replace(self.inputs["signer_fingerprint"], "2" * 40)
        signatures.write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError, "pinned primary fingerprint"):
            maintained.verify_audit(*arguments)


if __name__ == "__main__":
    unittest.main()
