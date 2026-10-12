# SPDX-License-Identifier: MIT
"""Tiny operator-listing/archive fixtures; network and crypto are mocked."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("test_recovery", Path(__file__).with_name("recovery_inputs.py"))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Response(io.BytesIO):
    def __init__(self, data=b"data", url=None, status=200, headers=None):
        super().__init__(data)
        self.url = url or f"https://{recovery.HOST}/source"
        self.status, self.headers = status, headers or {}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "artifacts/platform").mkdir(parents=True)
        self.enterContext(patch.object(recovery, "ROOT", self.root))
        self.enterContext(patch.object(recovery, "OLD_COUNT", 2))
        certificate = self.root / "key.gpg"
        certificate.write_bytes(b"public key fixture")
        self.certificate = self.ref(certificate)
        self.enterContext(patch.dict(recovery.auth.KEYS, {"alarm": (recovery.auth.KEYS["alarm"][0], self.certificate["sha256"])}))
        self.metadata = [self.make_archive(name) for name in ("example", "other")]
        self.image = {"kind": "observed-image-local-package-metadata", "hardware_accepted": False,
                      "dependency_transaction_accepted": False, "packages": [{"metadata": p} for p in self.metadata]}
        self.image_ref = self.json_ref("image.json", self.image)
        self.availability = {"kind": "protected-exact-version-current-catalog-availability",
                             "inputs": {"image_inventory": self.image_ref}, "old_archive_url_or_hash_guessed": False,
                             "hardware_accepted": False, "installation_accepted": False,
                             "packages": [{"name": p["NAME"][0], "protected_version": "1-1", "arch": "any",
                                           "current_catalog_exact_version": False} for p in self.metadata]}

    def ref(self, path):
        data = path.read_bytes()
        return {"path": str(path), "size": len(data), "sha256": sha(data)}

    def json_ref(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data))
        return self.ref(path)

    def contract(self):
        return {"schema_version": 1, "image_inventory": self.image_ref,
                "old_availability": self.json_ref("availability.json", self.availability), "certificate": self.certificate}

    def make_archive(self, name, version="1-1"):
        path = self.root / f"{name}-1-1-any.pkg.tar.xz"
        data = f"pkgname = {name}\npkgver = {version}\narch = any\nlicense = MIT\n".encode()
        with tarfile.open(path, "w:xz") as archive:
            for filename, payload in ((".PKGINFO", data), (f"usr/share/{name}/data", b"data")):
                member = tarfile.TarInfo(filename)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return {"NAME": [name], "VERSION": ["1-1"], "ARCH": ["any"], "LICENSE": ["MIT"]}

    def listing(self, filename):
        return f'<a href="./{filename}">archive</a><a href="./{filename}.sig">signature</a>'.encode()

    def fake_fetch(self, url, target, maximum, **kwargs):
        if target.name.endswith(".html"):
            name = target.stem
            data = self.listing(f"{name}-1-1-any.pkg.tar.xz")
        elif target.name.endswith(".sig"):
            data = b"signature fixture"
        else:
            data = (self.root / target.name).read_bytes()
        recovery.need(len(data) <= maximum, "fixture observed byte bound exceeded")
        target.write_bytes(data)
        return {**self.ref(target), "url": url, "predeclared_sha256": None, "hash_provenance": "observed-post-download-only"}

    def fake_verify(self, *args):
        signer = recovery.auth.KEYS["alarm"][0]
        return {"status": "cryptographic-signature-valid", "primary_fingerprint": recovery.auth.KEYS["alarm"][0],
                "fresh_verification": True, "independent_owner_trust_accepted": False}, {
                    "exit": 0, "reason": "exit", "gpg_status": f"[GNUPG:] VALIDSIG {signer} 2026-10-12 1791763200 0 4 0 1 10 00 {signer}\n"}

    def test_exact_links_require_real_archive_and_signature_anchors(self):
        url = f"https://{recovery.HOST}/aarch64/packages/p/python/"
        name = "python-3.14.7-1-aarch64.pkg.tar.xz"
        links = recovery.exact_links(self.listing(name), url, name)
        self.assertEqual(links, {"archive": url + name, "signature": url + name + ".sig"})
        for data in (name.encode(), f'<a href="./{name}">archive only</a>'.encode(),
                     self.listing("python-3.14.8-1-aarch64.pkg.tar.xz")):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, "actual exact"):
                recovery.exact_links(data, url, name)

    def test_links_foreign_http_query_fragment_credentials_traversal_and_wrong_arch_refused(self):
        url = f"https://{recovery.HOST}/aarch64/packages/p/python/"
        filename = "python-3.14.7-1-aarch64.pkg.tar.xz"
        hrefs = [f"https://attacker.example/{filename}", url.replace("https:", "http:") + filename,
                 "./" + filename + "?download=true", "./" + filename + "#fragment",
                 f"https://user:secret@{recovery.HOST}/aarch64/packages/p/python/{filename}",
                 "../python/" + filename, "./python-3.14.7-1-x86_64.pkg.tar.xz"]
        for href in hrefs:
            html = f'<a href="{href}">archive</a><a href="./{filename}.sig">sig</a>'.encode()
            with self.subTest(href=href), self.assertRaises(ValueError):
                recovery.exact_links(html, url, filename)

    def test_duplicate_href_and_index_byte_limits_refused(self):
        filename = "python-3.14.7-1-aarch64.pkg.tar.xz"
        url = f"https://{recovery.HOST}/aarch64/packages/p/python/"
        html = f'<a href="./{filename}" href="./other">archive</a>'.encode()
        with self.assertRaisesRegex(ValueError, "duplicate anchor"):
            recovery.exact_links(html, url, filename)
        with patch.object(recovery, "INDEX_LIMIT", 5), self.assertRaisesRegex(ValueError, "index byte"):
            recovery.exact_links(self.listing(filename), url, filename)

    def test_epoch_encoded_href_retains_actual_url(self):
        filename = "librsvg-2:2.62.4-1-aarch64.pkg.tar.xz"
        encoded = filename.replace(":", "%3A")
        url = f"https://{recovery.HOST}/aarch64/packages/l/librsvg/"
        self.assertEqual(recovery.exact_links(self.listing(encoded), url, filename)["archive"], url + encoded)

    def test_plan_cross_binds_exact_old_image_versions_and_certificate(self):
        packages = recovery.plan(self.contract())
        self.assertEqual([p["name"] for p in packages], ["example", "other"])
        self.assertEqual(packages[0]["index_url"], f"https://{recovery.HOST}/aarch64/packages/e/example/")
        self.availability["packages"][0]["protected_version"] = "2-1"
        with self.assertRaisesRegex(ValueError, "image identity"):
            recovery.plan(self.contract())

    def test_plan_ambiguous_count_and_image_hash_binding_refused(self):
        contract = self.contract()
        contract["image_inventory"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            recovery.plan(contract)
        self.image_ref["sha256"] = sha((self.root / "image.json").read_bytes())
        self.availability["packages"][0]["current_catalog_exact_version"] = 0
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            recovery.plan(self.contract())
        self.availability["packages"][0]["current_catalog_exact_version"] = True
        with self.assertRaisesRegex(ValueError, "exact superseded"):
            recovery.plan(self.contract())

    def test_fetch_same_host_https_and_observed_hash_without_prepin(self):
        target = self.root / "fetched"
        with patch.object(recovery.urllib.request, "urlopen", return_value=Response(headers={"Content-Length": "4"})):
            ref = recovery.fetch(f"https://{recovery.HOST}/source", target, 4)
        self.assertEqual(ref["sha256"], sha(b"data"))
        self.assertIs(ref["predeclared_sha256"], None)
        self.assertEqual(ref["hash_provenance"], "observed-post-download-only")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_fetch_redirect_byte_cap_short_response_and_deadline_refused(self):
        target = self.root / "fetched"
        for response in (Response(url="https://attacker.example/source"), Response(data=b"12345"),
                         Response(headers={"Content-Length": "3"}), Response(url=f"http://{recovery.HOST}/source")):
            with self.subTest(response=response), patch.object(recovery.urllib.request, "urlopen", return_value=response):
                with self.assertRaises(ValueError):
                    recovery.fetch(f"https://{recovery.HOST}/source", target, 4)
                self.assertFalse(target.exists())
                self.assertFalse((self.root / "fetched.partial").exists())
        with patch.object(recovery.urllib.request, "urlopen", return_value=Response()), patch.object(recovery.time, "monotonic", side_effect=[0, 601]):
            with self.assertRaisesRegex(ValueError, "deadline"):
                recovery.fetch(f"https://{recovery.HOST}/source", target, 4)

    def test_successful_old_archive_data_is_not_image_payload_or_installation_proof(self):
        output = self.root / "artifacts/platform/recovery"
        with patch.object(recovery, "fetch", side_effect=self.fake_fetch), patch.object(recovery.auth, "verify", side_effect=self.fake_verify):
            result = recovery.run(self.contract(), output, "a" * 64)
        self.assertEqual(result["verified_count"], 2)
        self.assertEqual(result["status"], "PASS-all-exact-old-recovery-archive-data")
        self.assertEqual(result["cache_bytes"], sum(path.stat().st_size for path in (output / "cache").iterdir()))
        self.assertEqual(result["metadata_bytes"], sum(path.stat().st_size for directory in ("indexes", "observations")
                                                      for path in (output / directory).iterdir()))
        for key in ("installation_accepted", "hardware_accepted", "image_payload_correspondence_accepted",
                    "old_archive_prehashes_known", "source_distribution", "complete_baseline_archive_authentication"):
            self.assertIs(result[key], False)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_crypto_failure_status_retained_and_later_package_processed(self):
        output = self.root / "artifacts/platform/recovery"
        def verify(directory, certificate, archive, signature, signer):
            if archive.name.startswith("example"):
                raise recovery.auth.SignatureFailure("invalid signature", {"gpg_status": "BADSIG", "exit": 1})
            return self.fake_verify()
        with patch.object(recovery, "fetch", side_effect=self.fake_fetch), patch.object(recovery.auth, "verify", side_effect=verify):
            result = recovery.run(self.contract(), output, "a" * 64)
        self.assertEqual(result["status"], "FAIL-incomplete-recovery-archive-data")
        self.assertEqual(result["verified_count"], 1)
        self.assertEqual(len(result["packages"]), 2)
        self.assertEqual(result["packages"][0]["signature_observation"]["gpg_status"], "BADSIG")

    def test_wrong_signed_package_metadata_refused(self):
        self.make_archive("example", version="2-1")
        output = self.root / "artifacts/platform/recovery"
        with patch.object(recovery, "fetch", side_effect=self.fake_fetch), patch.object(recovery.auth, "verify", side_effect=self.fake_verify):
            result = recovery.run(self.contract(), output, "a" * 64)
        self.assertEqual(result["verified_count"], 1)
        self.assertIn("PKGINFO mismatch: pkgver", result["failures"][0]["diagnostic"])

    def test_aggregate_cache_quota_caps_actual_fetch_before_any_overflow(self):
        output = self.root / "artifacts/platform/recovery"
        quota = (self.root / "example-1-1-any.pkg.tar.xz").stat().st_size
        with patch.object(recovery, "CACHE_LIMIT", quota), patch.object(recovery, "fetch", side_effect=self.fake_fetch), \
             patch.object(recovery.auth, "verify", side_effect=self.fake_verify):
            result = recovery.run(self.contract(), output, "a" * 64)
        self.assertEqual(result["status"], "FAIL-incomplete-recovery-archive-data")
        self.assertLessEqual(result["cache_bytes"], quota)
        self.assertEqual(len(result["failures"]), 2)
        self.assertFalse((output / "cache/example-1-1-any.pkg.tar.xz.sig").exists())

    def test_aggregate_metadata_quota_refuses_inspection_before_write(self):
        output = self.root / "artifacts/platform/recovery"
        quota = len(self.listing("example-1-1-any.pkg.tar.xz"))
        with patch.object(recovery, "METADATA_LIMIT", quota), patch.object(recovery, "fetch", side_effect=self.fake_fetch), \
             patch.object(recovery.auth, "verify", side_effect=self.fake_verify):
            result = recovery.run(self.contract(), output, "a" * 64)
        self.assertEqual(result["metadata_bytes"], quota)
        self.assertEqual(len(result["failures"]), 2)
        self.assertFalse(list((output / "observations").iterdir()))

    def test_destination_refuses_outside_traversal_symlink_and_insufficient_reserve(self):
        parent = self.root / "artifacts/platform"
        existing = parent / "existing"
        existing.mkdir()
        link = parent / "link"
        link.symlink_to(existing, target_is_directory=True)
        for target in (self.root / "outside", parent / ".." / "escape", link / "child", existing):
            with self.subTest(target=target), self.assertRaises(ValueError):
                recovery.destination(target)
        free = recovery.CACHE_LIMIT + recovery.METADATA_LIMIT + 2 * recovery.RECEIPT_LIMIT + 256 * recovery.MIB - 1
        usage = recovery.shutil._ntuple_diskusage(free, 0, free)
        with patch.object(recovery.shutil, "disk_usage", return_value=usage), self.assertRaisesRegex(ValueError, "reserve"):
            recovery.destination(parent / "low")
        self.assertFalse((parent / "low").exists())

    def prior_run(self, *, fail_other=False):
        output = self.root / "artifacts/platform/prior"
        def verify(directory, certificate, archive, signature, signer):
            if fail_other and archive.name.startswith("other"):
                raise ValueError("previous unavailable signature")
            return self.fake_verify()
        with patch.object(recovery, "fetch", side_effect=self.fake_fetch), patch.object(recovery.auth, "verify", side_effect=verify):
            result = recovery.run(self.contract(), output, "a" * 64)
        contract = self.contract()
        contract["previous_receipt"] = self.ref(output / "recovery-receipt.json")
        return contract, result

    def test_resume_successful_previous_rows_do_not_make_http_or_crypto_calls(self):
        contract, prior = self.prior_run()
        old_path = Path(contract["previous_receipt"]["path"])
        old_bytes = old_path.read_bytes()
        output = self.root / "artifacts/platform/resume"
        with patch.object(recovery, "fetch") as fetch, patch.object(recovery.auth, "verify") as verify:
            result = recovery.run(contract, output, "b" * 64)
        fetch.assert_not_called(); verify.assert_not_called()
        self.assertEqual(result["verified_count"], 2)
        self.assertEqual(result["external_retained_cache_bytes"], prior["cache_bytes"])
        self.assertEqual(result["external_retained_metadata_bytes"], prior["metadata_bytes"])
        self.assertEqual(old_path.read_bytes(), old_bytes)
        self.assertFalse(list((output / "cache").iterdir()))
        for row in result["packages"]:
            self.assertIs(row["signature_verification"]["fresh_verification"], False)
            self.assertIs(row["fresh_signature_verification_this_run"], False)
            self.assertTrue(row["prior_data_rehashed_and_metadata_reinspected"])
            self.assertEqual(row["retained_signature_verification_receipt"], contract["previous_receipt"])

    def test_resume_only_retries_failed_rows_and_charges_external_data(self):
        contract, prior = self.prior_run(fail_other=True)
        output = self.root / "artifacts/platform/resume"
        with patch.object(recovery, "fetch", side_effect=self.fake_fetch) as fetch, patch.object(recovery.auth, "verify", side_effect=self.fake_verify) as verify:
            result = recovery.run(contract, output, "b" * 64)
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(fetch.call_count, 3)
        self.assertTrue(all("/other/" in call.args[0] for call in fetch.call_args_list))
        self.assertEqual(result["verified_count"], 2)
        retained = prior["packages"][0]
        self.assertEqual(result["external_retained_cache_bytes"], retained["archive"]["size"] + retained["signature"]["size"])
        self.assertEqual(result["cache_bytes"], result["external_retained_cache_bytes"]
                         + sum(path.stat().st_size for path in (output / "cache").iterdir()))
        self.assertEqual(result["previous_failures"], prior["failures"])
        self.assertEqual(result["packages"][1]["previous_failure"], prior["packages"][1]["failure"])

    def test_resume_wrong_previous_hash_or_input_pins_refused_before_output(self):
        contract, _ = self.prior_run()
        contract["previous_receipt"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            recovery.plan(contract)
        prior_path = Path(contract["previous_receipt"]["path"])
        prior = json.loads(prior_path.read_text())
        prior["inputs"]["certificate"]["sha256"] = "0" * 64
        contract["previous_receipt"] = self.json_ref("altered-prior.json", prior)
        with self.assertRaisesRegex(ValueError, "input/classification binding"):
            recovery.run(contract, self.root / "artifacts/platform/refused", "b" * 64)
        self.assertFalse((self.root / "artifacts/platform/refused").exists())

    def test_resume_completed_tampered_bytes_fail_without_http_restart(self):
        contract, prior = self.prior_run()
        archive = Path(prior["packages"][0]["archive"]["path"])
        data = archive.read_bytes()
        archive.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        with patch.object(recovery, "fetch") as fetch, patch.object(recovery.auth, "verify") as verify:
            result = recovery.run(contract, self.root / "artifacts/platform/resume", "b" * 64)
        fetch.assert_not_called(); verify.assert_not_called()
        self.assertEqual(result["status"], "FAIL-incomplete-recovery-archive-data")
        self.assertEqual(result["verified_count"], 1)
        self.assertIn("hash mismatch", result["failures"][0]["diagnostic"])

    def test_resume_external_cache_and_metadata_must_fit_global_quotas(self):
        contract, prior = self.prior_run()
        for field, total in (("CACHE_LIMIT", prior["cache_bytes"]), ("METADATA_LIMIT", prior["metadata_bytes"])):
            with self.subTest(field=field), patch.object(recovery, field, total - 1), \
                 patch.object(recovery, "fetch") as fetch, patch.object(recovery.auth, "verify") as verify:
                with self.assertRaisesRegex(ValueError, "aggregate previous retained quota"):
                    recovery.run(contract, self.root / "artifacts/platform/refused", "b" * 64)
                fetch.assert_not_called(); verify.assert_not_called()
                self.assertFalse((self.root / "artifacts/platform/refused").exists())

    def clock_fixture(self):
        state = {"now": 0.0, "sleeps": []}
        def sleep(seconds):
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, 60)
            state["now"] += seconds
            state["sleeps"].append(seconds)
        self.enterContext(patch.object(recovery.time, "monotonic", side_effect=lambda: state["now"]))
        self.enterContext(patch.object(recovery.time, "sleep", side_effect=sleep))
        return state

    def test_request_pacing_spaces_successive_packages_and_caps_429_retries(self):
        state = self.clock_fixture()
        times = []
        count = 0
        def open_(url, **kwargs):
            nonlocal count
            count += 1
            times.append(state["now"])
            if count <= 2:
                raise urllib.error.HTTPError(url, 429, "rate limited", {"Retry-After": "9999"}, io.BytesIO())
            return Response()
        client, attempts = recovery.Requests(1000), []
        with patch.object(recovery.urllib.request, "urlopen", side_effect=open_):
            client.open(f"https://{recovery.HOST}/index", attempts).close()
            client.open(f"https://{recovery.HOST}/archive", attempts).close()
        self.assertEqual(times, [0, 60, 120, 121])
        self.assertEqual([attempt["retry_after_seconds"] for attempt in attempts if attempt["status"] == 429], [60, 60])
        self.assertEqual([attempt["status"] for attempt in attempts], [429, 429, 200, 200])

    def test_repeated_429_records_three_attempts_and_paces_next_failed_package(self):
        state = self.clock_fixture()
        times = []
        def open_(url, **kwargs):
            times.append(state["now"])
            raise urllib.error.HTTPError(url, 429, "rate limited", {"Retry-After": "2"}, io.BytesIO())
        client = recovery.Requests(1000)
        with patch.object(recovery.urllib.request, "urlopen", side_effect=open_):
            for index in range(2):
                attempts = []
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    client.open(f"https://{recovery.HOST}/package-{index}", attempts)
                caught.exception.close()
                self.assertEqual(len(attempts), 3)
        self.assertEqual(times, [0, 2, 4, 6, 8, 10])


if __name__ == "__main__":
    unittest.main()
