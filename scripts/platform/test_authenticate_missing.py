# SPDX-License-Identifier: MIT
"""Tiny exact archive/database fixtures with mocked HTTPS/GPG; no installation."""
import contextlib
import base64
import gzip
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

spec = importlib.util.spec_from_file_location("test_missing", Path(__file__).with_name("authenticate_missing.py"))
missing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(missing)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Response(io.BytesIO):
    def __init__(self, data=b"data", *, url="https://ca.us.mirror.archlinuxarm.org/file", status=200, headers=None):
        super().__init__(data)
        self.url, self.status, self.headers = url, status, headers or {}


class MissingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "artifacts/platform").mkdir(parents=True, mode=0o700)
        self.key_bytes = {"alarm": b"alarm key fixture", "community": b"community key fixture"}
        self.enterContext(patch.object(missing, "ROOT", self.root))
        self.enterContext(patch.object(missing, "EXPECTED_MISSING", 1))
        self.enterContext(patch.object(missing, "KEYS", {label: (missing.KEYS[label][0], sha(data))
                                                       for label, data in self.key_bytes.items()}))
        self.keys = {}
        for label, data in self.key_bytes.items():
            path = self.root / (label + ".gpg")
            path.write_bytes(data)
            self.keys[label] = self.ref(path)
        self.archives = {}
        self.metadata = {name: self.make_archive(name, version, arch) for name, version, arch in
                         (("example", "1-1", "any"), ("python", "3.14.8-1", "aarch64"))}
        self.transaction = {"kind": "private-Asahi-metadata-transaction-prepare", "status": "FAIL-incomplete-or-policy-rejected",
                            "proposed_final_inventory": [{"name": "example", "version": "1-1", "repo": "extra", "metadata": self.metadata["example"]}]}
        self.transaction_ref = self.json_ref("transaction.json", self.transaction)
        self.coverage = {"kind": "offline-candidate-retained-archive-coverage", "transaction_report": self.transaction_ref,
                         "transaction_status": self.transaction["status"], "installation_accepted": False,
                         "hardware_accepted": False, "source_grants_complete": False,
                         "packages": [{"name": "example", "version": "1-1", "arch": "any", "repo": "extra",
                                       "status": "missing-exact-retained-authentication", "candidate_archive": self.candidate(self.metadata["example"])}]}
        database = self.root / "core.db"
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            data = "".join(f"%{key}%\n" + "\n".join(value) + "\n\n" for key, value in self.metadata["python"].items()).encode()
            member = tarfile.TarInfo("python-3.14.8-1/desc")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        database.write_bytes(gzip.compress(raw.getvalue()))
        self.database_ref = self.ref(database)

    def ref(self, path):
        data = path.read_bytes()
        return {"path": str(path), "size": len(data), "sha256": sha(data)}

    def json_ref(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return self.ref(path)

    def make_archive(self, name, version, arch):
        path = self.root / f"{name}-{version}-{arch}.pkg.tar.xz"
        pkg = f"pkgname = {name}\npkgver = {version}\narch = {arch}\nlicense = MIT\n".encode()
        with tarfile.open(path, "w:xz") as archive:
            for filename, data in ((".PKGINFO", pkg), (f"usr/share/{name}/data", b"data")):
                member = tarfile.TarInfo(filename)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.archives[path.name] = path
        return {"NAME": [name], "VERSION": [version], "ARCH": [arch], "FILENAME": [path.name],
                "SHA256SUM": [sha(path.read_bytes())], "CSIZE": [str(path.stat().st_size)], "LICENSE": ["MIT"]}

    def candidate(self, metadata):
        item = missing.archive_spec(metadata, "extra", "test")
        return {"filename": item["filename"], "sha256": item["sha256"], "bytes": item["size"],
                "url": item["url"], "signature_url": item["url"] + ".sig", "network_availability": "NOT CHECKED"}

    def contract(self):
        return {"schema_version": 1, "coverage_report": self.json_ref("coverage.json", self.coverage),
                "transaction_report": self.transaction_ref, "keys": self.keys,
                "additional_python": {"database": self.database_ref, "name": "python", "version": "3.14.8-1"}}

    def status(self, digest="10", primary=None):
        signer = missing.KEYS["alarm"][0]
        return f"[GNUPG:] VALIDSIG {signer} 2026-10-12 1791763200 0 4 0 1 {digest} 00 {primary or signer}\n".encode()

    def fake_download(self, url, target, maximum, expected=None, exact_size=None):
        data = b"signature fixture" if target.name.endswith(".sig") else self.archives[target.name].read_bytes()
        target.write_bytes(data)
        os.chmod(target, 0o600)
        return self.ref(target)

    def fake_verify(self, directory, certificate, archive, signature, signer):
        return ({"status": "cryptographic-signature-valid", "primary_fingerprint": signer,
                 "independent_owner_trust_accepted": False, "fresh_verification": True}, {"exit": 0})

    def test_plan_exact_missing_plus_additional_python_first(self):
        packages, budget = missing.plan(self.contract())
        self.assertEqual([(p["name"], p["scope"]) for p in packages],
                         [("python", "additional-coordinated-python-target"), ("example", "missing-exact-tentative-candidate")])
        self.assertEqual(budget, sum(p["size"] + missing.SIGNATURE_LIMIT for p in packages))

    def epoch_metadata(self, filename="grub-2.2.16-3-aarch64.pkg.tar.xz"):
        return {"NAME": ["grub"], "VERSION": ["2:2.16-3"], "ARCH": ["aarch64"],
                "FILENAME": [filename], "CSIZE": ["9800024"],
                "SHA256SUM": ["e43b968d72cde70752ca82450a72fb65644c1a324c03eaee820446c9ba5827da"]}

    def test_epoch_full_and_omitted_declared_names_preserve_full_identity(self):
        for repo in ("core", "extra", "asahi-alarm"):
            for version in ("2:2.16-3", "2.16-3"):
                filename = f"grub-{version}-aarch64.pkg.tar.xz"
                metadata = self.epoch_metadata(filename)
                item = missing.archive_spec(metadata, repo, "test")
                self.assertEqual((item["filename"], item["version"], item["arch"]),
                                 (filename, "2:2.16-3", "aarch64"))
                self.assertEqual(item["metadata"], metadata)
                self.assertTrue(item["url"].endswith("/" + filename))
                self.assertEqual((item["sha256"], item["size"]),
                                 (metadata["SHA256SUM"][0], int(metadata["CSIZE"][0])))

    def test_declared_dotted_epoch_is_only_asahi_and_no_alternate_is_guessed(self):
        metadata = self.epoch_metadata()
        item = missing.archive_spec(metadata, "asahi-alarm", "test")
        self.assertEqual(item["url"], "https://github.com/asahi-alarm/asahi-alarm/releases/download/aarch64/"
                         "grub-2.2.16-3-aarch64.pkg.tar.xz")
        for repo in ("core", "extra"):
            with self.subTest(repo=repo), self.assertRaisesRegex(ValueError, "filename"):
                missing.archive_spec(metadata, repo, "test")
        for filename in ("grub-2_2.16-3-aarch64.pkg.tar.xz", "grub-2-2.16-3-aarch64.pkg.tar.xz",
                         "grub-3.2.16-3-aarch64.pkg.tar.xz", "grub-2.2.16-3-any.pkg.tar.xz",
                         "other-2.2.16-3-aarch64.pkg.tar.xz", "../grub-2.2.16-3-aarch64.pkg.tar.xz"):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                missing.archive_spec(self.epoch_metadata(filename), "asahi-alarm", "test")

    def test_epoch_requires_one_ascii_decimal_prefix_and_noncolon_version(self):
        for version in (":2.16-3", "x:2.16-3", "-2:2.16-3", "+2:2.16-3", "2:",
                        "2:2:16-3", "2::2.16-3", "2.0:2.16-3", "٢:2.16-3", "2:../2.16-3"):
            metadata = self.epoch_metadata(f"grub-{version}-aarch64.pkg.tar.xz")
            metadata["VERSION"] = [version]
            with self.subTest(version=version), self.assertRaises(ValueError):
                missing.archive_spec(metadata, "asahi-alarm", "test")

    def test_exact_archive_field_types_names_and_architectures_are_required(self):
        for key in ("NAME", "VERSION", "ARCH", "FILENAME", "SHA256SUM", "CSIZE"):
            for value in (None, False, 3, {}, [], [None], [False], [3], [{}], [[]], ["one", "two"]):
                metadata = self.epoch_metadata(); metadata[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    missing.archive_spec(metadata, "asahi-alarm", "test")
        metadata = self.epoch_metadata(); metadata["ARCH"] = ["x86_64"]
        with self.assertRaises(ValueError): missing.archive_spec(metadata, "asahi-alarm", "test")

    def test_non_epoch_metadata_retains_only_its_original_canonical_filename(self):
        metadata = self.metadata["example"]
        item = missing.archive_spec(metadata, "extra", "test")
        self.assertEqual((item["filename"], item["version"]), ("example-1-1-any.pkg.tar.xz", "1-1"))
        for filename in ("example-0.1-1-any.pkg.tar.xz", "example-0:1-1-any.pkg.tar.xz"):
            with self.assertRaises(ValueError):
                missing.archive_spec(dict(metadata, FILENAME=[filename]), "asahi-alarm", "test")

    def test_epoch_filename_keeps_full_pkginfo_name_version_and_arch_checks(self):
        metadata = self.make_archive("grub", "2:2.16-3", "aarch64")
        source = self.root / metadata["FILENAME"][0]
        path = self.root / "grub-2.2.16-3-aarch64.pkg.tar.xz"; source.rename(path)
        metadata["FILENAME"] = [path.name]
        item = missing.archive_spec(metadata, "asahi-alarm", "test")
        expected = missing.expected(item["metadata"])
        missing.coverage.authenticate.observe(path, expected)
        for key, value in (("version", "2.16-3"), ("name", "other"), ("arch", "any")):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "PKGINFO mismatch"):
                missing.coverage.authenticate.observe(path, dict(expected, **{key: value}))

    def test_epoch_filename_does_not_relax_signature_pins_or_status(self):
        signature = b"signature fixture"; metadata = self.epoch_metadata()
        metadata["PGPSIG"] = [base64.b64encode(signature).decode("ascii")]
        item = missing.archive_spec(metadata, "asahi-alarm", "test")
        self.assertEqual(item["signature_pin"], {"size": len(signature), "sha256": sha(signature)})
        url = item["url"] + ".sig"
        with patch.object(missing.urllib.request, "urlopen", return_value=Response(b"different fixture", url=url)):
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                missing.download(url, self.root / "epoch.sig", missing.SIGNATURE_LIMIT,
                                 item["signature_pin"]["sha256"])
        with self.assertRaises(ValueError):
            missing.signature_status(self.status(primary="A" * 40), missing.KEYS["alarm"][0])

    def test_plan_coverage_pin_transaction_binding_and_candidate_drift_refused(self):
        contract = self.contract()
        contract["coverage_report"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            missing.plan(contract)
        self.coverage["transaction_report"] = {**self.transaction_ref, "sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "transaction binding"):
            missing.plan(self.contract())
        self.coverage["transaction_report"] = self.transaction_ref
        self.coverage["packages"][0]["candidate_archive"]["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "archive binding"):
            missing.plan(self.contract())

    def test_plan_missing_count_additional_version_and_key_pins_refused(self):
        contract = self.contract()
        with patch.object(missing, "EXPECTED_MISSING", 2), self.assertRaisesRegex(ValueError, "missing archive count"):
            missing.plan(contract)
        contract["additional_python"]["version"] = "3.14.7-1"
        with self.assertRaisesRegex(ValueError, "Python target"):
            missing.plan(contract)
        contract["additional_python"]["version"] = "3.14.8-1"
        contract["keys"]["alarm"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "certificate source pin"):
            missing.plan(contract)

    def test_plan_aggregate_budget_refused_without_creating_output(self):
        with patch.object(missing, "BYTE_LIMIT", 1), self.assertRaisesRegex(ValueError, "aggregate"):
            missing.plan(self.contract())
        self.assertEqual(list((self.root / "artifacts/platform").iterdir()), [])

    def test_signature_status_wrong_primary_weak_expired_duplicate_refused(self):
        bad = [self.status(primary="A" * 40), self.status(digest="2"), self.status() * 2,
               self.status() + b"[GNUPG:] EXPKEYSIG expired\n", b"[GNUPG:] NODATA 1\n"]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                missing.signature_status(data, missing.KEYS["alarm"][0])
        self.assertIs(missing.signature_status(self.status(), missing.KEYS["alarm"][0])["independent_owner_trust_accepted"], False)

    def test_failed_gpg_status_preserved_and_public_scratch_removed(self):
        outcome = {"reason": "exit", "returncode": 1, "stdout": b"[GNUPG:] BADSIG wrong\n", "stderr": b"bad signature\n"}
        with patch.object(missing.capture, "bounded_command", side_effect=[(b"", b""), (b"public fixture", b"")]), \
             patch.object(missing.process, "bounded_process", return_value=outcome) as command:
            with self.assertRaises(missing.SignatureFailure) as caught:
                missing.verify(self.root, self.root / "alarm.gpg", self.root / "archive", self.root / "sig", missing.KEYS["alarm"][0])
        self.assertEqual(caught.exception.observation["gpg_status"], "[GNUPG:] BADSIG wrong\n")
        self.assertEqual(command.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        self.assertIn("--homedir", command.call_args.args[0])
        self.assertFalse(list(self.root.glob("public-gpg-*")))

    def test_download_valid_hash_size_private_and_no_partial(self):
        target = self.root / "download"
        with patch.object(missing.urllib.request, "urlopen", return_value=Response(headers={"Content-Length": "4"})):
            ref = missing.download("https://ca.us.mirror.archlinuxarm.org/data", target, 4, sha(b"data"), 4)
        self.assertEqual(ref["sha256"], sha(b"data"))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertFalse(target.with_name("download.partial").exists())

    def test_download_redirect_byte_hash_and_size_refusal_cleans_partial(self):
        cases = [(Response(url="https://attacker.example/data"), 4, None, None),
                 (Response(data=b"12345"), 4, None, None), (Response(), 4, "0" * 64, 4),
                 (Response(), 4, None, 3), (Response(headers={"Content-Length": "5"}), 4, None, None)]
        target = self.root / "download"
        for response, maximum, digest, size in cases:
            with self.subTest(response=response), patch.object(missing.urllib.request, "urlopen", return_value=response):
                with self.assertRaises(ValueError):
                    missing.download("https://ca.us.mirror.archlinuxarm.org/data", target, maximum, digest, size)
                self.assertFalse(target.exists())
                self.assertFalse(target.with_name("download.partial").exists())

    def test_download_non_https_and_deadline_refused(self):
        with patch.object(missing.urllib.request, "urlopen") as opener:
            with self.assertRaisesRegex(ValueError, "source refused"):
                missing.download("http://ca.us.mirror.archlinuxarm.org/data", self.root / "target", 4)
            opener.assert_not_called()
        with patch.object(missing.urllib.request, "urlopen", return_value=Response()), patch.object(missing.time, "monotonic", side_effect=[0, 601]):
            with self.assertRaisesRegex(ValueError, "deadline"):
                missing.download("https://ca.us.mirror.archlinuxarm.org/data", self.root / "target", 4)
        self.assertFalse((self.root / "target.partial").exists())

    def test_run_python_immutable_receipt_first_and_all_data_only(self):
        output = self.root / "artifacts/platform/run"
        order = []
        def download(*args, **kwargs):
            order.append(args[1].name)
            if args[1].name.startswith("example"):
                self.assertTrue((output / "python-receipt.json").exists())
            return self.fake_download(*args, **kwargs)
        with patch.object(missing, "download", side_effect=download), patch.object(missing, "verify", side_effect=self.fake_verify), contextlib.redirect_stdout(io.StringIO()) as printed:
            result = missing.run(self.contract(), output, "a" * 64)
        self.assertTrue(order[0].startswith("python-3.14.8-1"))
        self.assertEqual(result["verified_count"], 2)
        self.assertEqual(result["status"], "PASS-all-planned-archive-data-authenticated")
        python = json.loads((output / "python-receipt.json").read_text())
        self.assertEqual(python["status"], "signed-coordinated-python-candidate-data")
        self.assertEqual(python["metadata"], self.metadata["python"])
        self.assertEqual(python["pkginfo"]["sha256"], sha(python["pkginfo"]["text"].encode()))
        self.assertEqual(python["source_db"], self.database_ref)
        self.assertIs(python["installation_accepted"], False)
        self.assertIs(result["complete_baseline_archive_authentication"], False)
        self.assertIn("python_receipt", printed.getvalue())
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        evidence = list((output / "observations").iterdir()) + [output / "python-receipt.json"]
        self.assertEqual(result["evidence_bytes"], sum(path.stat().st_size for path in evidence))

    def test_aggregate_evidence_quota_refuses_before_writes_and_keeps_all_failures(self):
        output = self.root / "artifacts/platform/run"
        python = self.archives[self.metadata["python"]["FILENAME"][0]]
        inspection = missing.coverage.authenticate.observe(python, missing.expected(self.metadata["python"]))
        quota = len((json.dumps(inspection, indent=2, sort_keys=True) + "\n").encode())
        with patch.object(missing, "EVIDENCE_LIMIT", quota), patch.object(missing, "download", side_effect=self.fake_download), \
             patch.object(missing, "verify", side_effect=self.fake_verify):
            result = missing.run(self.contract(), output, "a" * 64)
        self.assertEqual(result["status"], "FAIL-incomplete-archive-authentication")
        self.assertEqual(result["verified_count"], 0)
        self.assertEqual(result["evidence_bytes"], quota)
        self.assertEqual([failure["name"] for failure in result["failures"]], ["python", "example"])
        self.assertTrue(all("aggregate evidence bound" in failure["diagnostic"] for failure in result["failures"]))
        self.assertEqual([path.name for path in (output / "observations").iterdir()], ["python.json"])
        self.assertFalse((output / "python-receipt.json").exists())
        self.assertEqual(json.loads((output / "authentication-receipt.json").read_text())["failures"], result["failures"])

    def test_output_space_preflight_reserves_all_evidence_and_atomic_receipts(self):
        output = self.root / "artifacts/platform/limited"
        budget = 100
        needed = budget + missing.EVIDENCE_LIMIT + 2 * missing.JSON_LIMIT + 256 * missing.MIB
        with patch.object(missing.shutil, "disk_usage", return_value=shutil_usage(needed - 1)), self.assertRaisesRegex(ValueError, "reserve"):
            missing.destination(output, budget)
        self.assertFalse(output.exists())

    def test_run_failed_python_retained_and_remaining_candidate_still_processed(self):
        output = self.root / "artifacts/platform/run"
        def download(*args, **kwargs):
            if args[1].name.startswith("python"):
                raise ValueError("Python download mismatch")
            return self.fake_download(*args, **kwargs)
        with patch.object(missing, "download", side_effect=download), patch.object(missing, "verify", side_effect=self.fake_verify):
            result = missing.run(self.contract(), output, "a" * 64)
        self.assertEqual(result["status"], "FAIL-incomplete-archive-authentication")
        self.assertEqual(result["planned_count"], 2)
        self.assertEqual(result["verified_count"], 1)
        self.assertEqual(result["failures"][0]["name"], "python")
        self.assertEqual(len(result["packages"]), 2)
        self.assertFalse((output / "python-receipt.json").exists())
        self.assertEqual(json.loads((output / "authentication-receipt.json").read_text())["failures"], result["failures"])

    def test_destination_existing_symlink_outside_and_low_space_refused(self):
        parent = self.root / "artifacts/platform"
        existing = parent / "exists"
        existing.mkdir()
        linked = parent / "link"
        linked.symlink_to(existing, target_is_directory=True)
        for target in (existing, linked, self.root / "outside"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                missing.destination(target, 100)
        with patch.object(missing.shutil, "disk_usage", return_value=shutil_usage(1)), self.assertRaisesRegex(ValueError, "reserve"):
            missing.destination(parent / "low", 100)

    def test_destination_parent_traversal_refused_before_any_directory_creation(self):
        parent = self.root / "artifacts/platform"
        escaped = parent / ".." / ".." / ".." / "outside-workspace"
        with patch.object(missing.os, "mkdir") as mkdir:
            with self.assertRaisesRegex(ValueError, "canonical private output"):
                missing.destination(escaped, 100)
            mkdir.assert_not_called()

    def test_destination_requires_private_owned_parent_before_creation(self):
        parent = self.root / "artifacts/platform"
        os.chmod(parent, 0o755)
        with self.assertRaisesRegex(ValueError, "private owned output parent"):
            missing.destination(parent / "public", 100)
        self.assertFalse((parent / "public").exists())
        os.chmod(parent, 0o700)
        real_fstat = missing.os.fstat
        def wrong_owner(fd):
            info = list(real_fstat(fd))
            info[4] += 1
            return os.stat_result(info)
        with patch.object(missing.os, "fstat", side_effect=wrong_owner):
            with self.assertRaisesRegex(ValueError, "private owned output parent"):
                missing.destination(parent / "other-owner", 100)
        self.assertFalse((parent / "other-owner").exists())

    def test_destination_parent_swap_is_refused_before_directory_creation(self):
        parent = self.root / "artifacts/platform"
        moved = parent.with_name("original-platform")
        def changed_parent(_):
            parent.rename(moved)
            parent.mkdir(mode=0o700)
            return shutil_usage(10 * 1024**3)
        with patch.object(missing.shutil, "disk_usage", side_effect=changed_parent):
            with self.assertRaisesRegex(ValueError, "output parent identity changed"):
                missing.destination(parent / "run", 100)
        self.assertFalse((parent / "run").exists())
        self.assertFalse((moved / "run").exists())

    def test_destination_competing_output_symlink_cannot_create_outside(self):
        parent = self.root / "artifacts/platform"
        output, outside = parent / "run", self.root / "outside"
        def competing_output(_):
            output.symlink_to(outside, target_is_directory=True)
            return shutil_usage(10 * 1024**3)
        with patch.object(missing.shutil, "disk_usage", side_effect=competing_output):
            with self.assertRaises(FileExistsError):
                missing.destination(output, 100)
        self.assertFalse(outside.exists())
        self.assertTrue(output.is_symlink())


def shutil_usage(free):
    return missing.shutil._ntuple_diskusage(free, 0, free)


if __name__ == "__main__":
    unittest.main()
