# SPDX-License-Identifier: MIT
"""Read-only local file fixtures; no physical target or package operation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


s = module("snapshot_test", HERE / "target_snapshot.py")
old = module("old_snapshot_fixture", HERE / "test_recovery_preflight.py")


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.packet = old.PreflightTests()
        self.packet.setUp()
        self.addCleanup(self.packet.doCleanups)
        self.root = self.packet.root
        self.target = self.root / "fixture-target"
        self.target.mkdir()
        self.compatible = self.target / "sys/firmware/devicetree/base/compatible"
        self.compatible.parent.mkdir(parents=True)
        self.compatible.write_bytes(b"apple,j413\0apple,t8112\0")
        self.db = self.target / "var/lib/pacman/local"
        self.db.mkdir(parents=True)
        (self.db / "ALPM_DB_VERSION").write_bytes(b"9\n")
        self.descriptors = []
        for record in self.packet.records:
            directory = self.db / (record["NAME"][0] + "-" + record["VERSION"][0])
            directory.mkdir()
            path = directory / "desc"
            path.write_text("".join("%" + key + "%\n" + "\n".join(values) + "\n\n" for key, values in record.items()))
            self.descriptors.append(path)
        self.module_path = "usr/lib/modules/fixture-asahi/pkgbase"
        pkgbase = self.target / self.module_path
        pkgbase.parent.mkdir(parents=True)
        pkgbase.write_bytes(b"linux-asahi\n")
        self.kernel_files = self.db / "linux-asahi-1-1/files"
        self.kernel_files.write_text("%FILES%\n" + self.module_path + "\n")
        self.runtime = {"architecture": "aarch64", "page_size": 16384, "kernel_release": "fixture-asahi"}
        self.contract = {"schema_version": 1, "mode": "fixture", "fixture_root": str(self.target),
                         "fixture_runtime": self.save("fixture-runtime.json", self.runtime),
                         "selected_files": [{"role": row["role"], "source": row["artifact"]}
                                            for row in self.packet.snapshot["boot_assets"] + self.packet.snapshot["configuration_backups"]],
                         "preflight": {"prepared_update": self.packet.contract()["prepared_update"], "recovery_receipts": []}}
        self.output = self.root / "collected"

    def save(self, name, value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        path = self.root / name
        path.write_bytes(data)
        return s.reference(path, data)

    def run_fixture(self):
        return s.run(self.save("collector-contract.json", self.contract), self.output)

    def test_complete_private_capture_preserves_inputs(self):
        before = {str(path): path.read_bytes() for path in self.target.rglob("*") if path.is_file()}
        report = self.run_fixture()
        snapshot = json.loads((self.output / "snapshot.json").read_text())
        self.assertEqual(report["scope"], "SYNTHETIC_FIXTURE")
        self.assertFalse(report["hardware_accepted"])
        self.assertFalse(report["backup_completeness_accepted"])
        self.assertTrue(snapshot["captured_at"].startswith("SYNTHETIC-FIXTURE"))
        self.assertEqual(len(snapshot["packages"]), len(self.packet.records))
        self.assertEqual((len(snapshot["boot_assets"]), len(snapshot["configuration_backups"])), (4, 2))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in self.output.rglob("*") if path.is_file()))
        self.assertFalse((self.output / "INCOMPLETE").exists())
        self.assertTrue(all(Path(path).read_bytes() == data for path, data in before.items()))

    def test_15_inch_adapter_matches_without_edit(self):
        self.compatible.write_bytes(b"apple,j415\0apple,t8112\0")
        self.run_fixture()
        report = old.p.run(json.loads((self.output / "preflight-contract.json").read_text()))
        self.assertEqual(report["model"], {"compatible": "apple,j415", "air_size_inches": 15})
        self.assertEqual({row["code"] for row in report["conditions"]}, {"exact-recovery-archive-missing"})

    def test_complete_synthetic_two_stage_data_binding_remains_unaccepted(self):
        self.contract["preflight"]["recovery_receipts"] = self.packet.contract()["recovery_receipts"]
        self.run_fixture()
        report = old.p.run(json.loads((self.output / "preflight-contract.json").read_text()))
        self.assertTrue(report["software_data_bound"])
        self.assertFalse(report["hardware_accepted"])
        self.assertFalse(report["fresh_signature_verification"])

    def test_ambiguous_similar_non_m2_empty_models_refused(self):
        for data in (b"apple,j413\0apple,j415\0apple,t8112\0", b"apple,j413-other\0apple,t8112\0",
                     b"apple,j413\0apple,t8103\0", b"apple,j413\0apple,t8112\0\0"):
            with self.subTest(data=data):
                self.compatible.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "M2 Air"):
                    self.run_fixture()
                self.assertFalse(self.output.exists())

    def test_generic_runtime_refused(self):
        self.runtime["page_size"] = 4096
        self.contract["fixture_runtime"] = self.save("runtime4k.json", self.runtime)
        with self.assertRaisesRegex(ValueError, "16K"):
            self.run_fixture()

    def test_live_non_arm_refused_before_selected_reads(self):
        self.contract = {"schema_version": 1, "mode": "live", "selected_files": [{"role": "kernel", "source": {"path": "/never-read"}}]}
        with patch.object(s, "live_runtime", return_value={"architecture": "x86_64", "kernel_release": "host", "page_size": 4096}):
            with self.assertRaisesRegex(ValueError, "not a supported Apple ARM"):
                self.run_fixture()
        self.assertFalse(self.output.exists())

    def test_live_cannot_override_root(self):
        self.contract["mode"] = "live"
        with self.assertRaisesRegex(ValueError, "contract fields"):
            self.run_fixture()

    def test_descriptor_identity_mismatch_refused(self):
        path = self.descriptors[0]
        path.write_text(path.read_text().replace("%NAME%\n", "%NAME%\nwrong-"))
        with self.assertRaisesRegex(ValueError, "directory/descriptor"):
            self.run_fixture()

    def test_database_lock_refused(self):
        (self.db.parent / "db.lck").write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "database lock"):
            self.run_fixture()

    def test_unowned_kernel_module_metadata_refused(self):
        self.kernel_files.write_bytes(b"%FILES%\nusr/lib/modules/other/pkgbase\n")
        with self.assertRaisesRegex(ValueError, "not owned"):
            self.run_fixture()

    def test_wrong_pkgbase_refused(self):
        (self.target / self.module_path).write_bytes(b"generic-linux\n")
        with self.assertRaisesRegex(ValueError, "package identity mismatch"):
            self.run_fixture()

    def test_selected_hash_tamper_refused(self):
        Path(self.contract["selected_files"][0]["source"]["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "reference size/hash"):
            self.run_fixture()

    def test_unselected_user_file_not_collected(self):
        (self.root / "unselected-user-secret").write_bytes(b"not selected")
        self.run_fixture()
        self.assertFalse(any(b"not selected" in path.read_bytes() for path in self.output.rglob("*") if path.is_file()))

    def test_missing_roles_reach_preflight_as_missing(self):
        self.contract["selected_files"] = []
        self.run_fixture()
        report = old.p.run(json.loads((self.output / "preflight-contract.json").read_text()))
        self.assertIn("retained-asset-missing", {row["code"] for row in report["conditions"]})

    def test_directory_backup_refused(self):
        self.contract["selected_files"][0]["source"]["path"] = str(self.root)
        with self.assertRaisesRegex(ValueError, "regular bounded"):
            self.run_fixture()

    def test_source_symlink_and_ancestor_refused(self):
        data = self.compatible.read_bytes()
        self.compatible.unlink()
        other = self.root / "compatible-source"
        other.write_bytes(data)
        self.compatible.symlink_to(other)
        with self.assertRaises(OSError):
            self.run_fixture()
        self.compatible.unlink()
        self.compatible.write_bytes(data)
        alias = self.root / "fixture-alias"
        alias.symlink_to(self.target, target_is_directory=True)
        self.contract["fixture_root"] = str(alias)
        with self.assertRaises(OSError):
            self.run_fixture()

    def test_hardlinked_selected_file_refused(self):
        os.link(Path(self.contract["selected_files"][0]["source"]["path"]), self.root / "extra-hardlink")
        with self.assertRaisesRegex(ValueError, "single-link"):
            self.run_fixture()

    def test_source_drift_keeps_incomplete_output(self):
        original, calls = s.Reader.recheck, [0]
        def changed(reader):
            calls[0] += 1
            if calls[0] == 2:
                self.descriptors[0].write_bytes(self.descriptors[0].read_bytes() + b"\n")
            return original(reader)
        with patch.object(s.Reader, "recheck", changed):
            with self.assertRaisesRegex(ValueError, "drift|bound"):
                self.run_fixture()
        self.assertTrue((self.output / "INCOMPLETE").exists())
        self.assertFalse((self.output / "snapshot.json").exists())

    def test_duplicate_name_with_valid_directory_identity_refused(self):
        folder = self.db / "mesa-2-1"
        folder.mkdir()
        (folder / "desc").write_bytes(b"%NAME%\nmesa\n\n%VERSION%\n2-1\n\n%ARCH%\naarch64\n")
        with self.assertRaisesRegex(ValueError, "duplicate package"):
            self.run_fixture()

    def test_missing_descriptor_is_not_skipped(self):
        self.descriptors[0].unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_fixture()

    def test_non_arm_package_is_not_skipped(self):
        path = self.descriptors[0]
        path.write_bytes(path.read_bytes().replace(b"aarch64", b"x86_64"))
        with self.assertRaisesRegex(ValueError, "wrong architecture"):
            self.run_fixture()

    def test_file_drift_during_read_is_refused(self):
        path = self.root / "changing-file"
        path.write_bytes(b"initial bytes")
        original, calls = s.os.read, [0]
        def changed(fd, amount):
            result = original(fd, amount)
            calls[0] += 1
            if calls[0] == 1:
                path.write_bytes(b"changed bytes")
            return result
        with patch.object(s.os, "read", changed):
            with self.assertRaisesRegex(ValueError, "changed during read"):
                s.Reader().read(path, 4096)

    def test_output_replacement_cannot_publish_snapshot(self):
        original = s.save_at
        moved = self.root / "moved-owned-output"
        def replaced(fd, name, data):
            original(fd, name, data)
            if name == "collection.json":
                self.output.rename(moved)
                self.output.mkdir(mode=0o700)
        with patch.object(s, "save_at", replaced):
            with self.assertRaisesRegex(ValueError, "output pathname identity"):
                self.run_fixture()
        self.assertTrue((moved / "INCOMPLETE").exists())
        self.assertFalse((self.output / "snapshot.json").exists())

    def test_output_parent_replacement_is_refused(self):
        parent = self.root / "private-parent"
        parent.mkdir(mode=0o700)
        self.output = parent / "collected"
        moved = self.root / "moved-parent"
        original = s.save_at
        def replaced(fd, name, data):
            original(fd, name, data)
            if name == "collection.json":
                parent.rename(moved)
                parent.mkdir(mode=0o700)
        with patch.object(s, "save_at", replaced):
            with self.assertRaisesRegex(ValueError, "output pathname identity"):
                self.run_fixture()
        self.assertTrue((moved / "collected/INCOMPLETE").exists())
        self.assertFalse((self.output / "snapshot.json").exists())

    def test_inventory_addition_before_output_refused(self):
        original = s.Reader.recheck
        def changed(reader):
            result = original(reader)
            (self.db / "new-package").mkdir(exist_ok=True)
            return result
        with patch.object(s.Reader, "recheck", changed):
            with self.assertRaisesRegex(ValueError, "inventory drift"):
                self.run_fixture()
        self.assertFalse(self.output.exists())

    def test_existing_output_and_public_parent_refused(self):
        self.output.mkdir()
        marker = self.output / "user-data"
        marker.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.run_fixture()
        self.assertEqual(marker.read_bytes(), b"preserve")
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "0700"):
            self.run_fixture()

    def test_output_symlink_parent_refused(self):
        alias = self.root / "output-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.output = alias / "new"
        with self.assertRaises(OSError):
            self.run_fixture()

    def test_byte_and_time_bounds(self):
        for name, value, reason in (("LIMIT", 100, "aggregate"), ("SECONDS", -1, "deadline")):
            with patch.object(s, name, value):
                with self.assertRaisesRegex(ValueError, reason):
                    self.run_fixture()

    def test_real_two_stage_cli_without_rewrite(self):
        ref = self.save("cli-contract.json", self.contract)
        first = subprocess.run([sys.executable, "-B", str(HERE / "target_snapshot.py"), "--contract", ref["path"],
                                "--contract-sha256", ref["sha256"], "--output", str(self.output)], capture_output=True, text=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        adapter = self.output / "preflight-contract.json"
        report = self.output / "preflight-report.json"
        second = subprocess.run([sys.executable, "-B", str(Path(old.p.__file__)), "--contract", str(adapter),
                                 "--contract-sha256", hashlib.sha256(adapter.read_bytes()).hexdigest(), "--output", str(report)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(second.returncode, 2, second.stderr)
        result = json.loads(report.read_text())
        self.assertEqual({row["code"] for row in result["conditions"]}, {"exact-recovery-archive-missing"})
        self.assertFalse(result["hardware_accepted"])


if __name__ == "__main__":
    unittest.main()
