# SPDX-License-Identifier: MIT
"""Finite local archives/receipts only; no network, package mutation or binaries."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("test_coverage_helper", Path(__file__).with_name("archive_coverage.py"))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir(mode=0o700)
        self.filename = "example-1-1-any.pkg.tar.xz"
        self.archive = self.cache / self.filename
        pkginfo = b"pkgname = example\npkgver = 1-1\narch = any\nlicense = MIT\n"
        with tarfile.open(self.archive, "w:xz") as archive:
            for name, data in ((".PKGINFO", pkginfo), ("usr/share/example/config", b"config"),
                               ("usr/share/licenses/example/LICENSE", b"MIT fixture notice"),
                               ("usr/share/libalpm/hooks/example.hook", b"[Trigger]\nType = Path\n")):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.signature = self.cache / (self.filename + ".sig")
        self.signature.write_bytes(b"retained signature fixture")
        self.metadata = {"NAME": ["example"], "VERSION": ["1-1"], "ARCH": ["any"],
                         "FILENAME": [self.filename], "SHA256SUM": [coverage.hash_file(self.archive)],
                         "CSIZE": [str(self.archive.stat().st_size)], "LICENSE": ["MIT"]}
        self.receipt = {"status": "signed-platform-archives-retained-not-installation-accepted",
                        "system_mutation": False, "hardware_accepted": False, "installation_accepted": False,
                        "packages": [{"metadata": self.metadata,
                                      "archive": {"sha256": coverage.hash_file(self.archive), "bytes": self.archive.stat().st_size},
                                      "signature": {"sha256": coverage.hash_file(self.signature), "bytes": self.signature.stat().st_size},
                                      "verification": {"status": "cryptographic-signature-valid",
                                                       "primary_fingerprint": coverage.COMMUNITY_SIGNER,
                                                       "independent_owner_trust_accepted": False}}]}
        self.transaction = {"schema_version": 1, "kind": "private-Asahi-metadata-transaction-prepare",
                            "status": "FAIL-incomplete-or-policy-rejected",
                            "proposed_final_inventory": [{"name": "example", "version": "1-1", "repo": "asahi-alarm",
                                                          "metadata": self.metadata}]}

    def ref(self, name, value):
        path = self.root / name
        data = json.dumps(value).encode()
        path.write_bytes(data)
        return {"path": str(path), "sha256": sha(data), "size": len(data)}

    def contract(self):
        return {"schema_version": 1, "transaction_report": self.ref("transaction.json", self.transaction),
                "sources": [{"kind": "community", "receipt": self.ref("receipt.json", self.receipt), "cache": str(self.cache)}]}

    def row(self, contract=None):
        return coverage.run(contract or self.contract())["packages"][0]

    def test_exact_archive_rehash_inspection_and_tentative_classification(self):
        report = coverage.run(self.contract())
        row = report["packages"][0]
        self.assertEqual(row["status"], "retained-authenticated-exact-archive-inspected")
        self.assertTrue(row["cache_bytes_rehashed"])
        self.assertTrue(report["candidate_inventory_tentative"])
        self.assertEqual(row["inspection"]["license_declaration"], ["MIT"])
        self.assertEqual(len(row["inspection"]["license_notice_files"]), 1)
        self.assertEqual(len(row["inspection"]["hooks_and_scriptlets"]), 1)
        self.assertIn("usr/share/example/config", row["inspection"]["installed_paths"])
        for key in ("installation_accepted", "hardware_accepted", "source_grants_complete", "fresh_signature_verification",
                    "complete_baseline_archive_authentication", "system_mutation"):
            self.assertIs(report[key], False)

    def test_same_baseline_identity_is_not_image_payload_authentication(self):
        self.transaction["proposed_final_inventory"][0]["metadata"] = {k: v for k, v in self.metadata.items()
                                                                       if k not in {"FILENAME", "SHA256SUM", "CSIZE"}}
        row = self.row()
        self.assertEqual(row["status"], "retained-authenticated-same-identity-image-payload-unverified")
        self.assertIs(row["image_payload_correspondence_accepted"], False)

    def test_mismatched_version_or_hash_does_not_inherit_receipt(self):
        for field, value in (("VERSION", ["2-1"]), ("SHA256SUM", ["0" * 64]), ("CSIZE", ["1"])):
            with self.subTest(field=field):
                candidate = {**self.metadata, field: value}
                if field == "VERSION":
                    candidate["FILENAME"] = ["example-2-1-any.pkg.tar.xz"]
                self.transaction["proposed_final_inventory"][0].update(metadata=candidate, version=candidate["VERSION"][0])
                self.assertEqual(self.row()["status"], "missing-exact-retained-authentication")

    def test_misclassified_candidate_filename_refused(self):
        self.transaction["proposed_final_inventory"][0]["metadata"] = {**self.metadata, "FILENAME": ["different.pkg.tar.xz"]}
        with self.assertRaisesRegex(ValueError, "candidate archive identity/pins"):
            self.row()

    def test_absent_cache_and_wrong_cached_archive_or_signature_refused(self):
        for name in (self.filename, self.filename + ".sig"):
            path = self.cache / name
            data = path.read_bytes()
            for replacement in (None, b"tampered"):
                with self.subTest(name=name, replacement=replacement):
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    row = self.row()
                    self.assertEqual(row["status"], "retained-authentication-cache-or-inspection-failed")
                    path.write_bytes(data)

    def test_failed_or_missing_package_signature_observation_not_accepted(self):
        package = self.receipt["packages"][0]
        for verification in ({}, {"status": "failed"}):
            with self.subTest(verification=verification):
                package["verification"] = verification
                self.assertEqual(self.row()["status"], "missing-exact-retained-authentication")

    def test_wrong_signer_or_claimed_owner_trust_refused(self):
        verification = self.receipt["packages"][0]["verification"]
        for field, value in (("primary_fingerprint", "A" * 40), ("independent_owner_trust_accepted", True)):
            with self.subTest(field=field):
                previous = verification[field]
                verification[field] = value
                with self.assertRaisesRegex(ValueError, "signer/trust"):
                    self.row()
                verification[field] = previous

    def test_receipt_missing_tampered_or_failed_refused(self):
        contract = self.contract()
        path = Path(contract["sources"][0]["receipt"]["path"])
        data = path.read_bytes()
        path.unlink()
        with self.assertRaises(OSError):
            coverage.run(contract)
        path.write_bytes(data[:-1] + b" ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            coverage.run(contract)
        self.receipt["status"] = "capture-incomplete"
        with self.assertRaisesRegex(ValueError, "capture incomplete"):
            self.row()

    def test_transaction_report_pin_and_candidate_identity_refused(self):
        contract = self.contract()
        contract["transaction_report"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            coverage.run(contract)
        self.transaction["proposed_final_inventory"][0]["version"] = "2-1"
        with self.assertRaisesRegex(ValueError, "transaction identity"):
            self.row()

    def test_candidate_license_differs_from_archive_refused(self):
        self.transaction["proposed_final_inventory"][0]["metadata"] = {**self.metadata, "LICENSE": ["GPL"]}
        row = self.row()
        self.assertEqual(row["status"], "retained-authentication-cache-or-inspection-failed")
        self.assertIn("PKGINFO mismatch: license", row["failures"][0]["error"])

    def test_duplicate_candidate_refused(self):
        self.transaction["proposed_final_inventory"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate candidate"):
            self.row()

    def test_cache_symlink_refused_and_cache_never_changed(self):
        contract = self.contract()
        before = {path.name: path.read_bytes() for path in self.cache.iterdir()}
        coverage.run(contract)
        self.assertEqual({path.name: path.read_bytes() for path in self.cache.iterdir()}, before)
        linked = self.root / "linked"
        linked.symlink_to(self.cache, target_is_directory=True)
        contract["sources"][0]["cache"] = str(linked)
        with self.assertRaisesRegex(ValueError, "unsafe cache"):
            coverage.run(contract)

    def test_duplicate_sources_attempt_same_tampered_archive_only_once(self):
        contract = self.contract()
        contract["sources"] *= 8
        budget = self.archive.stat().st_size + self.signature.stat().st_size
        data = self.archive.read_bytes()
        self.archive.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        with patch.object(coverage, "TOTAL_LIMIT", budget), patch.object(coverage, "hash_file", wraps=coverage.hash_file) as hashing:
            report = coverage.run(contract)
        self.assertEqual(report["packages"][0]["status"], "retained-authentication-cache-or-inspection-failed")
        archive_reads = [call for call in hashing.call_args_list if call.args[0] == self.archive]
        self.assertEqual(len(archive_reads), 1)
        self.assertEqual(report["retained_rehash_upper_bound_bytes"], budget)

    def test_distinct_fallback_caches_are_prebudgeted_before_any_rehash(self):
        contract = self.contract()
        original_source = contract["sources"][0]
        budget = self.archive.stat().st_size + self.signature.stat().st_size
        data = self.archive.read_bytes()
        for index in range(1, 8):
            cache = self.root / f"fallback-{index}"
            cache.mkdir()
            (cache / self.filename).write_bytes(bytes([data[0] ^ 1]) + data[1:])
            (cache / (self.filename + ".sig")).write_bytes(self.signature.read_bytes())
            contract["sources"].append({**original_source, "cache": str(cache)})
        with patch.object(coverage, "TOTAL_LIMIT", budget), patch.object(coverage, "hash_file") as hashing:
            with self.assertRaisesRegex(ValueError, "retained-byte work budget exceeded"):
                coverage.run(contract)
        hashing.assert_not_called()

    def generic_contract(self):
        item = {"name": "example", "version": "1-1", "arch": "any", "filename": self.filename,
                "sha256": coverage.hash_file(self.archive), "size": self.archive.stat().st_size,
                "signature_sha256": coverage.hash_file(self.signature), "signature_size": self.signature.stat().st_size,
                "depends": [], "provides": [], "conflicts": [], "replaces": [], "license": ["MIT"]}
        lock = {"scope": "GENERIC-desktop-data-authentication", "signer_fingerprint": coverage.authenticate.SIGNER,
                "packages": [item]}
        lock_ref = self.ref("lock.json", lock)
        fingerprint = coverage.authenticate.SIGNER
        self.generic_receipt = {"status": "PASS-233-authenticated-generic-archives", "scope": lock["scope"],
                                "archive_lock_sha256": lock_ref["sha256"], "signer_fingerprint": fingerprint,
                                "packages": [{"name": item["name"], "version": item["version"], "status": "PASS-authenticated-data",
                                              "archive_sha256": item["sha256"], "signature_sha256": item["signature_sha256"],
                                              "gpg": {"exit": 0, "status": f"[GNUPG:] VALIDSIG {fingerprint} 2026-10-12 1791763200 0 4 0 1 10 00 {fingerprint}\n"}}]}
        return {"schema_version": 1, "transaction_report": self.ref("transaction.json", self.transaction),
                "sources": [{"kind": "generic", "lock": lock_ref, "receipt": self.ref("generic.json", self.generic_receipt),
                             "cache": str(self.cache)}]}

    def test_generic_receipt_only_contributes_individually_bound_candidate(self):
        contract = self.generic_contract()
        row = self.row(contract)
        self.assertEqual(row["status"], "retained-authenticated-exact-archive-inspected")
        self.assertEqual(row["retained_authentication"]["kind"], "generic")
        self.assertIs(row["installation_accepted"], False)

    def test_generic_wrong_version_hash_lock_or_gpg_observation_refused(self):
        for mutation in ("version", "hash", "lock", "gpg"):
            with self.subTest(mutation=mutation):
                contract = self.generic_contract()
                receipt = self.generic_receipt
                if mutation == "version":
                    receipt["packages"][0]["version"] = "2-1"
                elif mutation == "hash":
                    receipt["packages"][0]["archive_sha256"] = "0" * 64
                elif mutation == "lock":
                    receipt["archive_lock_sha256"] = "0" * 64
                else:
                    receipt["packages"][0]["gpg"]["exit"] = 1
                contract["sources"][0]["receipt"] = self.ref("generic.json", receipt)
                with self.assertRaises(ValueError):
                    coverage.run(contract)

    def test_generic_failed_individual_does_not_inherit_global_pass(self):
        contract = self.generic_contract()
        self.generic_receipt["packages"][0]["status"] = "FAIL"
        contract["sources"][0]["receipt"] = self.ref("generic.json", self.generic_receipt)
        self.assertEqual(self.row(contract)["status"], "missing-exact-retained-authentication")


if __name__ == "__main__":
    unittest.main()
