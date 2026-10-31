# SPDX-License-Identifier: MIT
"""Real disposable file captures, always labeled synthetic; no physical checks."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


b = module("retained_bundle_tests", HERE / "retained_bundle.py")
c = module("retained_bundle_comparison_tests", HERE / "snapshot_compare.py")
old = module("retained_bundle_capture_fixtures", HERE / "test_target_snapshot.py")


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = old.SnapshotTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.capture_ref = self.save("capture-request.json", self.fixture.contract)
        self.request = {"schema_version": 1, "kind": "retained-Asahi-snapshot-bundle-capture",
                        "capture_contract": self.capture_ref, "machine_id": "operator-m2-air-01",
                        "configuration_ownership": [], "recovery_receipts": [], "recovery_assets": []}
        self.output = self.root / "bundle"

    def save(self, name, value):
        data = value if isinstance(value, bytes) else b.s.encoded(value)
        path = self.root / name
        path.write_bytes(data)
        return b.s.reference(path, data)

    def load(self, ref):
        return json.loads(Path(ref["path"]).read_bytes())

    def request_ref(self):
        return self.save("bundle-request.json", self.request)

    def run_bundle(self):
        return b.run(self.request_ref(), self.output)

    def complete_assertions(self):
        self.request["configuration_ownership"] = [
            {"path": "/etc/operator-asahi.conf" if role == "system-configuration" else "/home/operator/.config/session.conf",
             "role": role, "owner": {"kind": "user", "id": "uid:1000"}} for role in sorted(b.CONFIG)]
        self.request["recovery_receipts"] = self.fixture.packet.contract()["recovery_receipts"]
        self.request["recovery_assets"] = sorted(b.s.ROLES)

    def pair(self):
        first = self.run_bundle()
        self.output = self.root / "second-bundle"
        second = self.run_bundle()
        return first, second

    def compare(self, first, second):
        proposal = self.save("explicit-no-changes.json", {"schema_version": 1, "kind": "explicit-snapshot-change-set",
            "baseline_snapshot": first["bundle"]["snapshot"], "candidate_snapshot": second["bundle"]["snapshot"],
            **{key: [] for key in ("packages", "assets", "runtime", "configuration_ownership")}})
        contract = self.save("comparison.json", {"schema_version": 1, "kind": "retained-Asahi-snapshot-comparison",
                                                "before": first["bundle"], "after": second["bundle"], "proposed_changes": proposal})
        return c.Comparison().run(contract)

    def test_complete_raw_map_and_private_independent_copies(self):
        request_ref = self.request_ref()
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = b.run(request_ref, self.output)
        manifest = self.load(result["bundle_reference"])
        self.assertEqual(manifest, result["bundle"])
        collection = self.load(manifest["collection"])
        mapping = self.load(manifest["inputs"])
        self.assertEqual(mapping["collection"], manifest["collection"])
        by_path = {row["source_path"]: row["retained"] for row in mapping["files"]}
        self.assertEqual(set(by_path), {row["path"] for row in collection["sources"]})
        for source in collection["sources"]:
            retained = by_path[source["path"]]
            self.assertEqual(Path(retained["path"]).read_bytes(), before[source["path"]])
            self.assertNotEqual(os.stat(source["path"]).st_ino, os.stat(retained["path"]).st_ino)
            self.assertEqual(retained["sha256"], source["sha256"])
        self.assertTrue(all(Path(path).read_bytes() == data for path, data in before.items()))
        self.assertEqual(result["scope"], "SYNTHETIC_FIXTURE")
        self.assertFalse(result["hardware_accepted"])
        self.assertFalse(result["recovery_accepted"])
        self.assertFalse((self.output / "INCOMPLETE").exists())
        for path in self.output.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_unknown_ownership_recovery_stays_missing(self):
        first, second = self.pair()
        context = self.load(first["bundle"]["context"])
        self.assertEqual(context["configuration_ownership"], [])
        self.assertEqual(context["recovery"], {"assets": [], "receipts": []})
        self.assertIn("recovery-package-references", first["missing_evidence"])
        report = self.compare(first, second)
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertFalse(report["comparison_data_admitted"])
        self.assertNotIn("bundle-evidence-refused", {row["code"] for row in report["findings"]})

    def test_known_assertions_consume_directly_and_remain_unaccepted(self):
        self.complete_assertions()
        first, second = self.pair()
        self.assertEqual(first["missing_evidence"], [])
        report = self.compare(first, second)
        self.assertEqual(report["status"], "UNCHANGED", report["findings"])
        self.assertTrue(report["comparison_data_admitted"])
        for key in ("hardware_accepted", "recovery_accepted", "fresh_signature_verification", "configuration_ownership_verified"):
            self.assertIs(report[key], False)

    def test_all_original_input_paths_can_disappear(self):
        self.complete_assertions()
        first, second = self.pair()
        preserve = {self.root / "bundle", self.root / "second-bundle"}
        for path in self.root.iterdir():
            if path in preserve:
                continue
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        self.assertEqual(self.compare(first, second)["status"], "UNCHANGED")

    def test_wrapper_source_hash_is_in_collector_and_producer_maps(self):
        result = self.run_bundle()
        collector = self.load(result["bundle"]["collection"])
        key = "scripts/platform/retained_bundle.py"
        self.assertEqual(collector["source_code_sha256"][key], hashlib.sha256((HERE / "retained_bundle.py").read_bytes()).hexdigest())
        self.assertEqual(len(collector["source_code_sha256"]), 5)
        self.assertEqual(result["source_code_sha256"], collector["source_code_sha256"])

    def test_legacy_capture_api_and_four_hashes_are_preserved(self):
        self.fixture.run_fixture()
        collection = json.loads((self.fixture.output / "collection.json").read_bytes())
        self.assertEqual(len(collection["source_code_sha256"]), 4)
        self.assertFalse((self.fixture.output / "retained-inputs.json").exists())

    def test_fixture_never_calls_live_probe(self):
        with patch.object(b.s, "live_runtime", side_effect=AssertionError("must not probe host")):
            self.assertEqual(self.run_bundle()["scope"], "SYNTHETIC_FIXTURE")

    def test_fixture_cannot_request_live_scope_override(self):
        self.request["scope"] = "OBSERVED_LIVE_METADATA"
        with self.assertRaisesRegex(ValueError, "request fields"):
            self.run_bundle()
        self.assertFalse(self.output.exists())

    def test_recovery_originals_and_claims_are_preserved(self):
        self.complete_assertions()
        result = self.run_bundle()
        context = self.load(result["bundle"]["context"])
        derivative = result["recovery_reference_derivatives"][0]
        original = self.load(derivative["source"])
        retained = self.load(derivative["retained_original"])
        relocated = self.load(context["recovery"]["receipts"][0])
        self.assertEqual(original, retained)
        self.assertEqual(original["status"], relocated["status"])
        self.assertEqual(original["packages"][0]["signature_verification"], relocated["packages"][0]["signature_verification"])
        self.assertNotEqual(original["packages"][0]["archive"]["path"], relocated["packages"][0]["archive"]["path"])
        self.assertEqual(original["packages"][0]["archive"]["sha256"], relocated["packages"][0]["archive"]["sha256"])

    def test_input_race_during_retention_prevents_capture_publication(self):
        original = b.s.save_at
        changed = [False]
        def mutate(fd, name, data):
            original(fd, name, data)
            if name == "0.bin" and not changed[0]:
                changed[0] = True
                path = self.fixture.descriptors[0]
                path.write_bytes(path.read_bytes() + b"\n")
        with patch.object(b.s, "save_at", mutate), self.assertRaisesRegex(ValueError, "drift|bound|changed"):
            self.run_bundle()
        self.assertTrue((self.output / "INCOMPLETE").exists())
        self.assertTrue((self.output / "capture/INCOMPLETE").exists())
        self.assertFalse((self.output / "capture/snapshot.json").exists())
        self.assertFalse((self.output / "bundle.json").exists())

    def test_retention_uses_bytes_from_capture_read_not_later_reread(self):
        original = b.s.save_at
        source = self.fixture.descriptors[0]
        expected = source.read_bytes()
        copied = []
        def inspect(fd, name, data):
            if name.endswith(".bin") and data == expected:
                copied.append(data)
            return original(fd, name, data)
        with patch.object(b.s, "save_at", inspect):
            result = self.run_bundle()
        self.assertTrue(copied)
        mapping = self.load(result["bundle"]["inputs"])
        retained = next(row["retained"] for row in mapping["files"] if row["source_path"] == str(source))
        self.assertEqual(Path(retained["path"]).read_bytes(), expected)

    def test_incomplete_retained_map_cannot_publish(self):
        original = b.s.save_at
        def incomplete(fd, name, data):
            if name == "retained-inputs.json":
                value = json.loads(data)
                value["files"].pop()
                data = b.s.encoded(value)
            return original(fd, name, data)
        with patch.object(b.s, "save_at", incomplete), self.assertRaisesRegex(ValueError, "map incomplete"):
            self.run_bundle()
        self.assertTrue((self.output / "INCOMPLETE").exists())
        self.assertFalse((self.output / "bundle.json").exists())

    def test_supplement_input_drift_prevents_bundle_publication(self):
        self.complete_assertions()
        source = Path(self.request["recovery_receipts"][0]["path"])
        original = b.s.save_at
        def changed(fd, name, data):
            result = original(fd, name, data)
            if name == "context.json":
                source.write_bytes(source.read_bytes() + b"\n")
            return result
        with patch.object(b.s, "save_at", changed), self.assertRaisesRegex(ValueError, "drift|bound|changed"):
            self.run_bundle()
        self.assertTrue((self.output / "INCOMPLETE").exists())
        self.assertFalse((self.output / "bundle.json").exists())

    def test_partial_marker_refused_by_comparator(self):
        self.complete_assertions()
        first, second = self.pair()
        (self.output / "INCOMPLETE").write_bytes(b"partial")
        report = self.compare(first, second)
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertTrue(any("publication is incomplete" in row.get("reason", "") for row in report["findings"]))

    def test_missing_producer_manifest_refused(self):
        first, second = self.pair()
        (self.output / "bundle.json").unlink()
        self.assertEqual(self.compare(first, second)["status"], "MISSING_EVIDENCE")

    def test_marker_appearing_at_final_comparison_recheck_blocks(self):
        self.complete_assertions()
        first, second = self.pair()
        original = c.Reader.recheck
        def changed(reader):
            result = original(reader)
            (self.output / "INCOMPLETE").write_bytes(b"publication no longer complete")
            return result
        with patch.object(c.Reader, "recheck", changed):
            self.assertEqual(self.compare(first, second)["status"], "MISSING_EVIDENCE")

    def test_unknown_source_producer_cannot_hide_in_hash_map(self):
        result = self.run_bundle()
        collector = self.load(result["bundle"]["collection"])
        collector["source_code_sha256"]["scripts/platform/unreviewed-wrapper.py"] = "0" * 64
        data = b.s.encoded(collector)
        path = Path(result["bundle"]["collection"]["path"])
        path.write_bytes(data)
        result["bundle"]["collection"] = b.s.reference(path, data)
        with self.assertRaisesRegex(ValueError, "collector code map"):
            c.Comparison().bundle(result["bundle"], "before")

    def test_publication_write_failure_stays_incomplete(self):
        original = b.s.save_at
        def broken(fd, name, data):
            if name == "bundle.json":
                raise OSError("injected publication failure")
            return original(fd, name, data)
        with patch.object(b.s, "save_at", broken), self.assertRaises(OSError):
            self.run_bundle()
        self.assertTrue((self.output / "INCOMPLETE").exists())
        self.assertFalse((self.output / "bundle.json").exists())

    def test_marker_removal_failure_is_not_admissible(self):
        original = b.s.os.unlink
        calls = [0]
        def broken(name, *args, **kwargs):
            if name == "INCOMPLETE":
                calls[0] += 1
                if calls[0] == 2:
                    raise OSError("injected final marker failure")
            return original(name, *args, **kwargs)
        with patch.object(b.s.os, "unlink", broken), self.assertRaises(OSError):
            self.run_bundle()
        self.assertTrue((self.output / "INCOMPLETE").exists())
        bundle = json.loads((self.output / "bundle.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "publication is incomplete"):
            c.Comparison().bundle(bundle, "before")

    def test_output_replacement_cannot_publish(self):
        original = b.s.run
        moved = self.root / "moved-output"
        def replaced(*args, **kwargs):
            receipt = original(*args, **kwargs)
            self.output.rename(moved)
            self.output.mkdir(mode=0o700)
            return receipt
        with patch.object(b.s, "run", replaced), self.assertRaisesRegex(ValueError, "output pathname identity"):
            self.run_bundle()
        self.assertTrue((moved / "INCOMPLETE").exists())
        self.assertFalse((self.output / "bundle.json").exists())

    def test_existing_output_is_preserved(self):
        self.output.mkdir(mode=0o700)
        marker = self.output / "user-owned"
        marker.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.run_bundle()
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_source_symlink_is_refused(self):
        source = self.fixture.descriptors[0]
        moved = source.with_suffix(".moved")
        source.rename(moved)
        source.symlink_to(moved)
        with self.assertRaises(OSError):
            self.run_bundle()
        self.assertFalse((self.output / "bundle.json").exists())

    def test_symlinked_retained_copy_is_refused_offline(self):
        first, second = self.pair()
        ref = self.load(second["bundle"]["inputs"])["files"][0]["retained"]
        path = Path(ref["path"])
        moved = path.with_suffix(".moved")
        path.rename(moved)
        path.symlink_to(moved)
        self.assertEqual(self.compare(first, second)["status"], "MISSING_EVIDENCE")

    def test_source_database_lock_is_refused(self):
        (self.fixture.target / "var/lib/pacman/db.lck").write_bytes(b"owned elsewhere")
        with self.assertRaisesRegex(ValueError, "lock present"):
            self.run_bundle()
        self.assertFalse((self.output / "bundle.json").exists())

    def test_output_inside_source_inventory_refused_before_write(self):
        self.output = self.fixture.db / "unwanted-evidence"
        with self.assertRaisesRegex(ValueError, "source inventory"):
            self.run_bundle()
        self.assertFalse(self.output.exists())

    def test_unknown_owner_or_unselected_role_is_not_invented(self):
        self.request["configuration_ownership"] = [{"role": "system-configuration", "path": "/etc/example",
                                                     "owner": {"kind": "package", "id": "not-installed"}}]
        with self.assertRaisesRegex(ValueError, "installed package"):
            self.run_bundle()
        self.assertTrue((self.output / "INCOMPLETE").exists())

    def test_symlinked_request_refused(self):
        ref = self.request_ref()
        path = Path(ref["path"])
        moved = path.with_suffix(".moved")
        path.rename(moved)
        path.symlink_to(moved)
        with self.assertRaises(OSError):
            b.run(ref, self.output)
        self.assertFalse(self.output.exists())

    def test_reader_retention_is_opt_in_and_bounded(self):
        path = Path(self.capture_ref["path"])
        old_reader = b.s.Reader()
        old_reader.read(path, 8 * b.MIB)
        self.assertIsNone(old_reader.retained)
        reader = b.s.Reader(retain=True)
        reader.read(path, 8 * b.MIB)
        self.assertEqual(reader.retained[str(path)], path.read_bytes())
        with self.assertRaisesRegex(ValueError, "aggregate"):
            b.s.Reader(retain=True, maximum=10).read(path, 8 * b.MIB)
        with self.assertRaisesRegex(ValueError, "aggregate bound"):
            b.s.Reader(maximum=1024 * b.MIB)

    def test_real_cli_capture_and_direct_comparison(self):
        reports = []
        for name in ("cli-before", "cli-after"):
            ref = self.request_ref()
            result = subprocess.run([sys.executable, "-B", str(HERE / "retained_bundle.py"), "--request", ref["path"],
                                     "--request-sha256", ref["sha256"], "--output", str(self.root / name)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            reports.append(json.loads(result.stdout))
        report = self.compare(*reports)
        self.assertEqual(report["status"], "MISSING_EVIDENCE")
        self.assertFalse(report["hardware_accepted"])


if __name__ == "__main__":
    unittest.main()
