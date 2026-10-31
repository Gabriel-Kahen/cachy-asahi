# SPDX-License-Identifier: MIT
"""Disposable retained fixture bundles; no machine, install, crypto, or recovery acceptance."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import snapshot_compare as c

old = c.module("comparison_capture_fixture", HERE / "test_target_snapshot.py")


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.capture = old.SnapshotTests()
        self.capture.setUp()
        self.addCleanup(self.capture.doCleanups)
        self.root = self.capture.root
        self.counter = 0
        self.before = self.bundle("before")
        self.after = self.bundle("after")
        self.proposal = {"schema_version": 1, "kind": "explicit-snapshot-change-set",
                         "baseline_snapshot": self.before["snapshot"], "candidate_snapshot": self.after["snapshot"],
                         **{key: [] for key in ("packages", "assets", "runtime", "configuration_ownership")}}

    def save(self, name, value):
        path = self.root / name
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        path.write_bytes(data)
        return c.snapshot.reference(path, data)

    def load(self, ref):
        return json.loads(Path(ref["path"]).read_bytes())

    def replace(self, ref, value):
        new = self.save(Path(ref["path"]).name, value)
        ref.clear()
        ref.update(new)

    def freeze_recovery(self, document, directory):
        if isinstance(document, list):
            return [self.freeze_recovery(value, directory) for value in document]
        if not isinstance(document, dict):
            return document
        if {"path", "sha256", "size"} <= set(document):
            self.counter += 1
            path = directory / (str(self.counter) + ".bin")
            data = Path(document["path"]).read_bytes()
            path.write_bytes(data)
            return document | c.snapshot.reference(path, data)
        return {key: self.freeze_recovery(value, directory) for key, value in document.items()}

    def bundle(self, name):
        self.capture.output = self.root / name
        receipt = self.capture.run_fixture()
        output = self.capture.output
        collection_ref = c.snapshot.reference(output / "collection.json", (output / "collection.json").read_bytes())
        mappings = []
        for index, row in enumerate(receipt["sources"]):
            data = Path(row["path"]).read_bytes()
            target = output / ("input-" + str(index) + ".bin")
            target.write_bytes(data)
            mappings.append({"source_path": row["path"], "retained": c.snapshot.reference(target, data)})
        inputs = self.save(name + "-inputs.json", {"schema_version": 1, "kind": "collector-retained-input-map",
                                                   "collection": collection_ref, "files": mappings})
        snapshot = self.load(receipt["snapshot"])
        package_records = [row["metadata"] for row in snapshot["packages"]]
        recovery = copy.deepcopy(self.capture.packet.receipt)
        recovery["inputs"]["image_inventory"] = self.save(name + "-inventory.json", {"packages": snapshot["packages"]})
        recovery["packages"] = [self.archive(row) for row in package_records]
        recovery["planned_count"] = recovery["verified_count"] = len(package_records)
        recovery = self.freeze_recovery(recovery, output)
        recovery_ref = self.save(name + "-recovery.json", recovery)
        assets = snapshot["boot_assets"] + snapshot["configuration_backups"]
        context = {"schema_version": 1, "kind": "snapshot-comparison-context", "snapshot": receipt["snapshot"],
                   "machine_id": "lab-m2-air-01", "model": snapshot["model"],
                   "configuration_ownership": [{"path": "/etc/asahi.conf" if row["role"] == "system-configuration" else "/home/operator/.config/session.conf",
                                                "role": row["role"], "owner": {"kind": "user", "id": "uid:1000"}, "artifact": row["artifact"]}
                                               for row in snapshot["configuration_backups"]],
                   "recovery": {"receipts": [recovery_ref], "assets": assets}}
        return {"snapshot": receipt["snapshot"], "collection": collection_ref, "inputs": inputs,
                "context": self.save(name + "-context.json", context)}

    def archive(self, metadata):
        # Extend the original fixture's simple MIT archive to actual dependency metadata.
        simple = {key: metadata[key] for key in ("NAME", "VERSION", "ARCH")}
        simple["LICENSE"] = ["MIT"]
        row = self.capture.packet.archive(simple)
        mapping = {"NAME": "pkgname", "VERSION": "pkgver", "ARCH": "arch", "LICENSE": "license",
                   "DEPENDS": "depend", "PROVIDES": "provides", "CONFLICTS": "conflict", "REPLACES": "replaces"}
        data = "".join(mapping[key] + " = " + value + "\n" for key in mapping for value in metadata.get(key, [])).encode()
        path = Path(row["archive"]["path"])
        with tarfile.open(path, "w:xz") as archive:
            member = tarfile.TarInfo(".PKGINFO")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        row["archive"].update(c.snapshot.reference(path, path.read_bytes()))
        row["observed_image_metadata"] = metadata
        row["inspection"] = self.capture.packet.save(path.name + ".inspection.json",
            c.preflight.recovery.auth.coverage.authenticate.observe(path, c.preflight.recovery.expected(metadata)))
        return row

    def candidate(self):
        self.after = self.bundle("candidate")
        self.proposal["candidate_snapshot"] = self.after["snapshot"]

    def change_package(self, name="mesa", version="2-1", metadata=None):
        old_dir = next(self.capture.db.glob(name + "-*/desc")).parent
        fields = c.snapshot.capture.parse_desc((old_dir / "desc").read_bytes())
        fields["VERSION"] = [version]
        if metadata:
            fields.update(metadata)
        new_dir = old_dir.with_name(name + "-" + version)
        if new_dir != old_dir:
            old_dir.rename(new_dir)
        (new_dir / "desc").write_text("".join("%" + key + "%\n" + "\n".join(values) + "\n\n" for key, values in fields.items()))
        self.candidate()

    def contract(self):
        return self.save("comparison.json", {"schema_version": 1, "kind": "retained-Asahi-snapshot-comparison",
                                              "before": self.before, "after": self.after,
                                              "proposed_changes": self.save("changes.json", self.proposal)})

    def run_comparison(self):
        return c.Comparison().run(self.contract())

    def conditions(self, report):
        return {row["code"] for row in report["findings"]}

    def expect_change(self, category, key):
        comparison = c.Comparison()
        before = comparison.bundle(self.before, "before")[category].get(key)
        after = comparison.bundle(self.after, "after")[category].get(key)
        self.proposal[category].append({"key": key, "from": before, "to": after})

    def test_unchanged_retained_metadata_only(self):
        report = self.run_comparison()
        self.assertEqual(report["status"], "UNCHANGED", report["findings"])
        self.assertTrue(report["comparison_data_admitted"])
        for key in ("hardware_accepted", "boot_accepted", "recovery_accepted", "installation_accepted",
                    "fresh_signature_verification", "configuration_ownership_verified", "installed_payload_authenticated",
                    "system_mutation", "dependency_transaction_accepted"):
            self.assertIs(report[key], False, key)

    def test_intended_protected_update(self):
        self.change_package()
        self.expect_change("packages", "mesa")
        report = self.run_comparison()
        self.assertEqual(report["status"], "INTENDED_CHANGE", report["findings"])
        self.assertTrue(report["comparison_data_admitted"])

    def test_unexpected_protected_update(self):
        self.change_package()
        report = self.run_comparison()
        self.assertEqual(report["status"], "UNEXPECTED_DRIFT", report["findings"])
        self.assertFalse(report["comparison_data_admitted"])

    def test_boot_firmware_audio_and_speaker_drift(self):
        for name in ("m1n1", "linux-firmware", "asahi-audio", "speakersafetyd"):
            with self.subTest(package=name):
                directory = self.capture.db / (name + "-1-1")
                fields = c.snapshot.capture.parse_desc((directory / "desc").read_bytes())
                fields["PROVIDES"] = ["unexpected-platform-provider"]
                (directory / "desc").write_text("".join("%" + key + "%\n" + "\n".join(values) + "\n\n" for key, values in fields.items()))
                self.after = self.bundle("candidate-" + name)
                self.proposal["candidate_snapshot"] = self.after["snapshot"]
                report = self.run_comparison()
                self.assertEqual(report["status"], "UNEXPECTED_DRIFT")
                self.assertTrue(any(row.get("key") == name and row["status"] == "UNEXPECTED_DRIFT" for row in report["findings"]))

    def test_running_kernel_package_version_update(self):
        self.change_package(name="linux-asahi")
        self.expect_change("packages", "linux-asahi")
        self.assertEqual(self.run_comparison()["status"], "UNEXPECTED_DRIFT")
        self.expect_change("runtime", "kernel_package_version")
        self.assertEqual(self.run_comparison()["status"], "INTENDED_CHANGE")

    def test_same_version_dependency_metadata_drift(self):
        self.change_package(version="1-1", metadata={"DEPENDS": ["unexpected-dependency>=1"]})
        self.assertEqual(self.run_comparison()["status"], "UNEXPECTED_DRIFT")

    def test_version_only_allowance_does_not_hide_metadata_drift(self):
        self.change_package(metadata={"CONFLICTS": ["asahi-audio"]})
        self.expect_change("packages", "mesa")
        del self.proposal["packages"][0]["to"]["CONFLICTS"]
        self.assertEqual(self.run_comparison()["status"], "UNEXPECTED_DRIFT")

    def test_nonprotected_addition_cannot_hide(self):
        directory = self.capture.db / "unreviewed-helper-1-1"
        directory.mkdir()
        (directory / "desc").write_bytes(b"%NAME%\nunreviewed-helper\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n%LICENSE%\nMIT\n")
        self.candidate()
        self.assertEqual(self.run_comparison()["status"], "UNEXPECTED_DRIFT")

    def test_config_byte_drift(self):
        source = next(row["source"] for row in self.capture.contract["selected_files"] if row["role"] == "user-configuration")
        Path(source["path"]).write_bytes(b"operator modified session config")
        source.update(c.snapshot.reference(Path(source["path"]), Path(source["path"]).read_bytes()))
        self.candidate()
        self.assertEqual(self.run_comparison()["status"], "UNEXPECTED_DRIFT")

    def test_config_ownership_drift(self):
        context = self.load(self.after["context"])
        context["configuration_ownership"][0]["owner"] = {"kind": "package", "id": "mesa"}
        self.replace(self.after["context"], context)
        self.assertEqual(self.run_comparison()["status"], "UNEXPECTED_DRIFT")

    def test_exact_declared_configuration_transition(self):
        context = self.load(self.after["context"])
        row = context["configuration_ownership"][0]
        row["owner"] = {"kind": "package", "id": "mesa"}
        self.replace(self.after["context"], context)
        self.expect_change("configuration_ownership", row["path"])
        self.assertEqual(self.run_comparison()["status"], "INTENDED_CHANGE")

    def test_missing_ownership_blocks(self):
        context = self.load(self.after["context"])
        context["configuration_ownership"].pop()
        self.replace(self.after["context"], context)
        report = self.run_comparison()
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertIn("configuration-ownership-missing", self.conditions(report))

    def test_machine_pseudonym_mismatch(self):
        context = self.load(self.after["context"])
        context["machine_id"] = "another-m2-air"
        self.replace(self.after["context"], context)
        self.assertEqual(self.run_comparison()["status"], "INCOMPATIBLE_BASELINE")

    def test_machine_size_mismatch(self):
        self.capture.compatible.write_bytes(b"apple,j415\0apple,t8112\0")
        self.candidate()
        self.assertEqual(self.run_comparison()["status"], "INCOMPATIBLE_BASELINE")

    def test_stale_proposal_snapshot_binding(self):
        self.proposal["baseline_snapshot"] = self.after["snapshot"]
        self.assertEqual(self.run_comparison()["status"], "INCOMPATIBLE_BASELINE")

    def test_wrong_proposal_from_cannot_admit(self):
        self.change_package()
        self.expect_change("packages", "mesa")
        self.proposal["packages"][0]["from"]["VERSION"] = ["wrong-1"]
        self.assertEqual(self.run_comparison()["status"], "UNEXPECTED_DRIFT")

    def test_missing_bound_object(self):
        Path(self.after["snapshot"]["path"]).unlink()
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_symlinked_snapshot(self):
        path = Path(self.after["snapshot"]["path"])
        moved = path.with_suffix(".moved")
        path.rename(moved)
        path.symlink_to(moved)
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_symlinked_ancestor(self):
        path = Path(self.after["snapshot"]["path"])
        moved = path.parent.with_name("moved-after")
        path.parent.rename(moved)
        path.parent.symlink_to(moved, target_is_directory=True)
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_hardlinked_bound_object(self):
        os.link(self.after["snapshot"]["path"], self.root / "extra-link")
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_incomplete_retained_input_map(self):
        inputs = self.load(self.after["inputs"])
        inputs["files"].pop()
        self.replace(self.after["inputs"], inputs)
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_extra_retained_input_map(self):
        inputs = self.load(self.after["inputs"])
        inputs["files"].append({"source_path": "/not-collected", "retained": self.save("extra", b"unbound")})
        self.replace(self.after["inputs"], inputs)
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_retained_source_hash_tamper(self):
        inputs = self.load(self.after["inputs"])
        Path(inputs["files"][0]["retained"]["path"]).write_bytes(b"corrupt")
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_retained_descriptor_forgery(self):
        target = self.load(self.after["snapshot"])
        target["packages"][0]["metadata"]["LICENSE"] = ["forged"]
        self.replace(self.after["snapshot"], target)
        receipt = self.load(self.after["collection"])
        receipt["snapshot"] = self.after["snapshot"]
        self.replace(self.after["collection"], receipt)
        inputs = self.load(self.after["inputs"])
        inputs["collection"] = self.after["collection"]
        self.replace(self.after["inputs"], inputs)
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_retained_original_machine_paths_unneeded(self):
        import shutil
        shutil.rmtree(self.capture.target)
        self.assertEqual(self.run_comparison()["status"], "UNCHANGED")

    def test_stale_recovery_inventory(self):
        self.change_package()
        context = self.load(self.after["context"])
        context["recovery"]["receipts"] = self.load(self.before["context"])["recovery"]["receipts"]
        self.replace(self.after["context"], context)
        self.expect_change("packages", "mesa")
        report = self.run_comparison()
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertIn("stale-recovery-inventory", self.conditions(report))

    def test_stale_recovery_assets(self):
        context = self.load(self.after["context"])
        context["recovery"]["assets"] = self.load(self.before["context"])["recovery"]["assets"]
        self.replace(self.after["context"], context)
        report = self.run_comparison()
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertIn("stale-recovery-asset", self.conditions(report))

    def test_stale_recovery_package_metadata(self):
        context = self.load(self.after["context"])
        reference = context["recovery"]["receipts"][0]
        receipt = self.load(reference)
        receipt["packages"][0]["version"] = "stale-1"
        self.replace(reference, receipt)
        self.replace(self.after["context"], context)
        self.assertIn("stale-recovery-package", self.conditions(self.run_comparison()))

    def test_missing_recovery_archive(self):
        context = self.load(self.after["context"])
        receipt = self.load(context["recovery"]["receipts"][0])
        Path(receipt["packages"][0]["archive"]["path"]).unlink()
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_stale_recovery_inspection(self):
        context = self.load(self.after["context"])
        receipt_ref = context["recovery"]["receipts"][0]
        receipt = self.load(receipt_ref)
        inspection = self.load(receipt["packages"][0]["inspection"])
        inspection["metadata"]["pkgver"] = ["stale-1"]
        self.replace(receipt["packages"][0]["inspection"], inspection)
        self.replace(receipt_ref, receipt)
        self.replace(self.after["context"], context)
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_duplicate_failed_recovery_row_cannot_mask_later_pass(self):
        context = self.load(self.after["context"])
        receipt_ref = context["recovery"]["receipts"][0]
        receipt = self.load(receipt_ref)
        duplicate = copy.deepcopy(receipt["packages"][0])
        duplicate["status"] = "FAIL"
        receipt["packages"].insert(0, duplicate)
        receipt["planned_count"] += 1
        receipt["status"] = "FAIL-incomplete-recovery-archive-data"
        self.replace(receipt_ref, receipt)
        self.replace(self.after["context"], context)
        report = self.run_comparison()
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertTrue(any("duplicate/unknown recovery" in row.get("reason", "") for row in report["findings"]))

    def test_symlinked_recovery_signature(self):
        context = self.load(self.after["context"])
        receipt = self.load(context["recovery"]["receipts"][0])
        path = Path(receipt["packages"][0]["signature"]["path"])
        moved = path.with_suffix(".moved")
        path.rename(moved)
        path.symlink_to(moved)
        self.assertEqual(self.run_comparison()["status"], "MISSING_EVIDENCE")

    def test_missing_required_protected_package(self):
        import shutil
        shutil.rmtree(self.capture.db / "speakersafetyd-1-1")
        self.candidate()
        self.assertIn("required-platform-package-missing", self.conditions(self.run_comparison()))

    def test_source_drift_at_final_recheck(self):
        ref = self.contract()
        original = c.snapshot.Reader.recheck
        def changed(reader):
            Path(self.after["snapshot"]["path"]).write_bytes(b"changed after comparison")
            return original(reader)
        with patch.object(c.snapshot.Reader, "recheck", changed):
            report = c.Comparison().run(ref)
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertIn("input-drift-before-report", self.conditions(report))

    def test_duplicate_proposal_key_refused(self):
        self.change_package()
        self.expect_change("packages", "mesa")
        self.proposal["packages"].append(copy.deepcopy(self.proposal["packages"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate/empty"):
            self.run_comparison()

    def test_duplicate_json_key_refused(self):
        ref = self.save("duplicate.json", b'{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            c.Comparison().run(ref)

    def test_byte_and_time_bounds(self):
        ref = self.contract()
        with patch.object(c, "MAX_BYTES", 10), self.assertRaises(ValueError):
            c.Comparison().run(ref)
        with patch.object(c.snapshot, "SECONDS", -1), self.assertRaises(ValueError):
            c.Comparison().run(ref)

    def test_real_cli_preserves_every_input_and_has_exit_codes(self):
        for expected in (0, 2, 1):
            if expected == 2:
                context = self.load(self.after["context"])
                context["recovery"]["receipts"] = []
                self.replace(self.after["context"], context)
            ref = self.contract()
            before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
            result = subprocess.run([sys.executable, "-B", str(HERE / "snapshot_compare.py"), "--contract", ref["path"],
                                     "--contract-sha256", ref["sha256"] if expected != 1 else "0" * 64],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, expected, result.stderr + result.stdout[:1500])
            self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
            if expected != 1:
                self.assertFalse(json.loads(result.stdout)["hardware_accepted"])


if __name__ == "__main__":
    unittest.main()
