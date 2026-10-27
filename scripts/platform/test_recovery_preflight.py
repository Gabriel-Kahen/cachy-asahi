# SPDX-License-Identifier: MIT
"""Real local archives/snapshots; retained crypto statuses are synthetic, never fresh crypto."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("preflight_test", Path(__file__).with_name("recovery_preflight.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.records = [{"NAME": [name], "VERSION": ["3.14.7-1" if name == "python" else "1-1"],
                         "ARCH": ["aarch64"], "LICENSE": ["MIT"]}
                        for name in sorted(p.PLATFORM | {"python", "protected-extra"})]
        self.image = self.save("image.json", {"packages": [{"metadata": row} for row in self.records]})
        graph = [{"name": row["NAME"][0], "version": row["VERSION"][0]} for row in self.records]
        tuple_ref = self.save("tuple.json", {"input_sha256": {"image": self.image["sha256"]},
                                             "proposed_installed_dependency_graph": graph})
        strict = self.save("strict.json", {"image_inventory": self.image, "tuple_report": tuple_ref})
        final = copy.deepcopy(self.records)
        next(row for row in final if row["NAME"] == ["python"])["VERSION"] = ["3.14.8-1"]
        self.update = {"schema_version": 1, "kind": "private-Asahi-metadata-transaction-prepare",
                       "proposal_kind": "unadopted-coordinated-python-change", "adopted": False,
                       "input_references": {"strict_contract": strict,
                                            "change": {"name": "python", "from": "3.14.7-1", "to": "3.14.8-1"}},
                       "status": "PASS-private-metadata-prepare", "all_protected_versions_preserved": True,
                       "all_targets_satisfied": True,
                       "proposed_final_inventory": [{"name": row["NAME"][0], "version": row["VERSION"][0],
                                                     "repo": "core", "metadata": row | {"repo": "core"}}
                                                    for row in final],
                       "protected_preservation": [{"name": row["NAME"][0], "original": row["VERSION"][0],
                                                    "expected": "3.14.8-1" if row["NAME"] == ["python"] else "1-1",
                                                    "final": "3.14.8-1" if row["NAME"] == ["python"] else "1-1",
                                                    "preserved": True} for row in self.records]}
        for key in ("commit_called", "host_database_used", "hardware_accepted", "installation_accepted", "dependency_transaction_accepted"):
            self.update[key] = False
        self.snapshot = {"schema_version": 1, "kind": "operator-supplied-offline-Asahi-target-snapshot",
                         "model": {"compatible": "apple,j413", "air_size_inches": 13},
                         "device_tree_compatible": self.save("compatible", b"apple,j413\0apple,t8112\0"),
                         "captured_at": "synthetic-fixture-no-hardware", "packages": [{"metadata": copy.deepcopy(row)} for row in self.records],
                         "runtime": {"architecture": "aarch64", "page_size": 16384, "kernel_release": "fixture-asahi",
                                     "kernel_package_version": "1-1"},
                         "boot_assets": [{"role": role, "artifact": self.save(role, b"fixture-asahi\n" if role == "kernel-release" else b"retained fixture bytes")}
                                         for role in sorted(p.BOOT_ROLES)],
                         "configuration_backups": [{"role": role, "artifact": self.save(role, b"private configuration fixture")}
                                                   for role in sorted(p.CONFIG_ROLES)]}
        self.certificate = self.save("key.gpg", b"synthetic certificate fixture")
        self.enterContext(patch.dict(p.recovery.auth.KEYS, {"alarm": (p.recovery.auth.KEYS["alarm"][0], self.certificate["sha256"])}))
        self.receipt = {"schema_version": 1, "kind": "exact-superseded-recovery-archive-data",
                        "status": "PASS-all-exact-old-recovery-archive-data",
                        "inputs": {"image_inventory": self.image, "certificate": self.certificate},
                        "packages": [self.archive(row) for row in self.records]}
        self.receipt.update(planned_count=len(self.records), verified_count=len(self.records))
        for key in ("system_mutation", "installation_accepted", "hardware_accepted", "image_payload_correspondence_accepted", "independent_owner_trust_accepted"):
            self.receipt[key] = False

    def save(self, name, value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        path = self.root / name
        path.write_bytes(data)
        return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def archive(self, metadata):
        name, version, arch = (metadata[key][0] for key in ("NAME", "VERSION", "ARCH"))
        filename = f"{name}-{version}-{arch}.pkg.tar.xz"
        path = self.root / filename
        with tarfile.open(path, "w:xz") as members:
            for member_name, data in ((".PKGINFO", f"pkgname = {name}\npkgver = {version}\narch = {arch}\nlicense = MIT\n".encode()),
                                      (f"usr/share/{name}/data", b"preserved payload fixture")):
                info = tarfile.TarInfo(member_name)
                info.size = len(data)
                members.addfile(info, io.BytesIO(data))
        index_url = f"https://{p.recovery.HOST}/aarch64/packages/{name[0]}/{name}/"
        index = self.save(name + ".html", f'<a href="{filename}">data</a><a href="{filename}.sig">sig</a>'.encode())
        archive = self.save(filename, path.read_bytes()) | {"url": index_url + filename}
        signature = self.save(filename + ".sig", b"synthetic retained signature") | {"url": index_url + filename + ".sig"}
        signer = p.recovery.auth.KEYS["alarm"][0]
        return {"name": name, "version": version, "arch": arch, "observed_image_metadata": metadata,
                "status": "PASS-signed-old-archive-data-matches-image-metadata", "index_url": index_url,
                "operator_index": index, "actual_index_links": {"archive": archive["url"], "signature": signature["url"]},
                "archive": archive, "signature": signature,
                "inspection": self.save(name + ".inspection.json", p.recovery.auth.coverage.authenticate.observe(path, p.recovery.expected(metadata))),
                "signature_verification": {"status": "cryptographic-signature-valid", "primary_fingerprint": signer,
                                           "independent_owner_trust_accepted": False},
                "signature_observation": {"exit": 0, "reason": "exit", "gpg_status":
                                          f"[GNUPG:] VALIDSIG {signer} 2026-10-12 1791763200 0 4 0 1 10 00 {signer}\n"}}

    def contract(self):
        return {"schema_version": 1, "target_snapshot": self.save("snapshot.json", self.snapshot),
                "prepared_update": self.save("update.json", self.update),
                "recovery_receipts": [self.save("receipt.json", self.receipt)]}

    def run_fixture(self):
        return p.run(self.contract())

    def codes(self, report):
        return {row["code"] for row in report["conditions"]}

    def test_real_archives_join_and_remain_hardware_unaccepted(self):
        report = self.run_fixture()
        self.assertTrue(report["software_data_bound"])
        self.assertFalse(report["hardware_accepted"])
        self.assertFalse(report["recovery_accepted"])
        self.assertFalse(report["fresh_signature_verification"])
        self.assertTrue(all(row["result"] == "NOT RUN" for row in report["physical_checks"]))
        self.assertEqual(len(report["recovery_archives_rehashed_and_reinspected"]), len(self.records))

    def test_15_inch_identity_is_separate(self):
        self.snapshot["model"] = {"compatible": "apple,j415", "air_size_inches": 15}
        self.snapshot["device_tree_compatible"] = self.save("compatible15", b"apple,j415\0apple,t8112\0")
        self.assertTrue(self.run_fixture()["software_data_bound"])

    def test_wrong_model_size_blocks(self):
        self.snapshot["model"]["air_size_inches"] = 15
        self.assertIn("target-model-mismatch", self.codes(self.run_fixture()))

    def test_ambiguous_model_property_blocks(self):
        self.snapshot["device_tree_compatible"] = self.save("ambiguous", b"apple,j413\0apple,j415\0")
        self.assertIn("target-model-mismatch", self.codes(self.run_fixture()))

    def test_kernel_version_and_release_mismatch_blocks(self):
        self.snapshot["runtime"]["kernel_package_version"] = "wrong"
        self.snapshot["runtime"]["kernel_release"] = "stale"
        self.assertTrue({"running-kernel-package-mismatch", "running-kernel-release-mismatch"} <= self.codes(self.run_fixture()))

    def test_generic_runtime_blocks(self):
        self.snapshot["runtime"]["page_size"] = 4096
        self.assertIn("target-runtime-mismatch", self.codes(self.run_fixture()))

    def test_missing_configuration_and_boot_recovery_artifacts_block(self):
        self.snapshot["boot_assets"] = []
        self.snapshot["configuration_backups"] = []
        report = self.run_fixture()
        self.assertEqual(sum(row["code"] == "retained-asset-missing" for row in report["conditions"]), 6)

    def test_current_catalog_fields_do_not_look_like_platform_change(self):
        for row in self.update["proposed_final_inventory"]:
            row["metadata"].update(FILENAME=["observed-file.pkg.tar.xz"], CSIZE=["123"], SHA256SUM=["0" * 64])
        self.assertTrue(self.run_fixture()["software_data_bound"])

    def test_final_repo_annotation_must_match_envelope(self):
        self.update["proposed_final_inventory"][0]["metadata"]["repo"] = "extra"
        with self.assertRaisesRegex(ValueError, "repository annotation"):
            self.run_fixture()

    def test_inventory_envelope_cannot_alias_another_package(self):
        self.update["proposed_final_inventory"][0]["name"] = "other-name"
        with self.assertRaisesRegex(ValueError, "envelope"):
            self.run_fixture()

    def test_protected_subset_is_refused(self):
        self.update["protected_preservation"] = [row for row in self.update["protected_preservation"] if row["name"] != "protected-extra"]
        with self.assertRaisesRegex(ValueError, "whole strict protected graph"):
            self.run_fixture()

    def test_non_python_protected_exemption_is_refused(self):
        row = next(row for row in self.update["protected_preservation"] if row["name"] == "mesa")
        row.update(expected="2-1", final="2-1")
        package = next(row for row in self.update["proposed_final_inventory"] if row["name"] == "mesa")
        package["version"] = "2-1"
        package["metadata"]["VERSION"] = ["2-1"]
        with self.assertRaisesRegex(ValueError, "unexpected protected"):
            self.run_fixture()

    def test_installed_metadata_drift_blocks_reprepare(self):
        next(row for row in self.snapshot["packages"] if row["metadata"]["NAME"] == ["mesa"])["metadata"]["DEPENDS"] = ["changed-dependency"]
        self.assertIn("target-baseline-metadata-mismatch", self.codes(self.run_fixture()))

    def test_extra_user_package_blocks_unprepared_dependency_set(self):
        self.snapshot["packages"].append({"metadata": {"NAME": ["user-package"], "VERSION": ["1-1"], "ARCH": ["any"]}})
        self.assertIn("target-baseline-metadata-mismatch", self.codes(self.run_fixture()))

    def test_same_version_protected_metadata_change_blocks(self):
        next(row for row in self.update["proposed_final_inventory"] if row["name"] == "protected-extra")["metadata"]["DEPENDS"] = ["unexpected-dependency"]
        self.assertIn("protected-package-metadata-change", self.codes(self.run_fixture()))

    def test_bad_receipt_signature_file_is_refused(self):
        Path(self.receipt["packages"][0]["signature"]["path"]).write_bytes(b"changed-signature")
        with self.assertRaisesRegex(ValueError, "reinspection refused"):
            self.run_fixture()

    def test_retained_archive_symlink_is_refused(self):
        path = Path(self.receipt["packages"][0]["archive"]["path"])
        data = path.read_bytes()
        path.unlink()
        other = self.root / "other-retained-data"
        other.write_bytes(data)
        path.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "reinspection refused"):
            self.run_fixture()

    def test_missing_recovery_archive_is_specific(self):
        self.receipt["packages"] = [row for row in self.receipt["packages"] if row["name"] != "mesa"]
        self.receipt.update(planned_count=len(self.records)-1, verified_count=len(self.records)-1)
        report = self.run_fixture()
        missing = [row for row in report["conditions"] if row["code"] == "exact-recovery-archive-missing"]
        self.assertEqual([row["package"] for row in missing], ["mesa"])

    def test_partial_receipt_preserves_missing_archive_diagnostic(self):
        next(row for row in self.receipt["packages"] if row["name"] == "mesa")["status"] = "FAIL"
        self.receipt.update(status="FAIL-incomplete-recovery-archive-data", verified_count=len(self.records)-1)
        self.assertIn("exact-recovery-archive-missing", self.codes(self.run_fixture()))

    def test_inconsistent_receipt_success_count_is_refused(self):
        self.receipt["verified_count"] -= 1
        with self.assertRaisesRegex(ValueError, "completion counts"):
            self.run_fixture()

    def test_archive_hash_drift_refused(self):
        Path(self.receipt["packages"][0]["archive"]["path"]).write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "reinspection refused"):
            self.run_fixture()

    def test_corrupt_xz_with_rebound_hash_refused(self):
        row = self.receipt["packages"][0]
        row["archive"].update(self.save(Path(row["archive"]["path"]).name, b"not an xz archive"))
        with self.assertRaisesRegex(ValueError, "reinspection refused"):
            self.run_fixture()

    def test_stale_signature_status_is_refused(self):
        self.receipt["packages"][0]["signature_observation"]["gpg_status"] += "[GNUPG:] KEYEXPIRED 123\n"
        with self.assertRaisesRegex(ValueError, "reinspection refused"):
            self.run_fixture()

    def test_receipt_baseline_swap_is_refused(self):
        self.receipt["inputs"]["image_inventory"] = self.save("wrong-baseline.json", {"packages": []})
        with self.assertRaisesRegex(ValueError, "receipt/baseline"):
            self.run_fixture()

    def test_missing_retained_file_is_refused(self):
        Path(self.snapshot["configuration_backups"][0]["artifact"]["path"]).unlink()
        with self.assertRaises(OSError):
            self.run_fixture()

    def test_worker_timeout_is_controlled(self):
        with patch.object(p.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 0.01)):
            with self.assertRaisesRegex(ValueError, "deadline"):
                self.run_fixture()

    def test_duplicate_json_is_refused(self):
        contract = self.contract()
        contract["target_snapshot"] = self.save("duplicate.json", b'{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            p.run(contract)

    def test_cli_blocked_exit_2_and_private_report(self):
        # No receipt avoids altering canonical trust pins in the real child CLI.
        contract = self.contract()
        contract["recovery_receipts"] = []
        ref = self.save("contract.json", contract)
        output = self.root / "preflight.json"
        command = [sys.executable, str(Path(p.__file__)), "--contract", ref["path"], "--contract-sha256", ref["sha256"], "--output", str(output)]
        before = {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()}
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(json.loads(output.read_text())["hardware_accepted"])
        self.assertTrue(all((self.root / name).read_bytes() == data for name, data in before.items()))
        again = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(again.returncode, 1)
        self.assertIn("refused", again.stderr)


if __name__ == "__main__":
    unittest.main()
