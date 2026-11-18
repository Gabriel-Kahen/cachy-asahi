# SPDX-License-Identifier: MIT
"""Actor-fenced tests of the portable Qtbase preparation interface."""

import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import prepare as P


def ref(path, raw):
    path.write_bytes(raw)
    return dict(path=str(path), **P.T.pin(raw))


class Preparation(unittest.TestCase):
    def test_pinned_external_request_and_unissued_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            references = {key: ref(root / key, key.encode()) for key in P.REQUEST_FIELDS}
            request_path = root / "request.json"
            request = dict(kind=P.REQUEST_KIND, **references)
            request_pin = ref(request_path, P.T.encoded(request))
            self.assertEqual(P.read_request(request_path, request_pin["sha256"]), references)
            with self.assertRaisesRegex(ValueError, "external request digest"):
                P.read_request(request_path, "0" * 64)
            issued = ref(request_path, P.T.encoded(dict(request, Root_authority="Root")))
            with self.assertRaisesRegex(ValueError, "preparation request"):
                P.read_request(request_path, issued["sha256"])
            alias = dict(references["proposal"], path="relative")
            malformed = ref(request_path, P.T.encoded(dict(request, proposal=alias)))
            with self.assertRaises(ValueError):
                P.read_request(request_path, malformed["sha256"])

    def test_exact_349_to_356_join_refuses_replacements(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = {f"baseline{i:03}": "1-1" for i in range(349)}
            extras = {f"extra{i}": "2-1" for i in range(7)}

            def lock(path, inventory):
                return ref(path, "".join(f"{k} {v}\n" for k, v in sorted(inventory.items())).encode())

            before = lock(root / "expected349.lock", baseline)
            after_path = root / "expected356.lock"
            proposal = dict(expected356_lock=lock(after_path, baseline | extras),
                            expected_archives={k: {"version": v} for k, v in extras.items()})
            P.verify_locks({"baseline_inventory": before}, proposal)
            proposal["expected356_lock"] = lock(after_path, baseline | extras | {"baseline001": "3-1"})
            with self.assertRaisesRegex(ValueError, "Exact 349 to 356"):
                P.verify_locks({"baseline_inventory": before}, proposal)

    def test_external_original_digest_is_checked_before_archive_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "original"
            archived = ref(path, b"authentic archive")
            path.write_bytes(b"corrupted archive")
            with self.assertRaisesRegex(ValueError, "Changed pinned bytes"):
                P.hook_masks(archived, set(), [])


    def test_original_boot_audit_rejects_duplicate_leaf(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as archive:
                for _ in range(2):
                    entry = tarfile.TarInfo("model/evidence/bootstrap/package-audit.json")
                    entry.size = 2
                    archive.addfile(entry, io.BytesIO(b"{}"))
            original = ref(Path(directory) / "original", output.getvalue())
            with self.assertRaisesRegex(ValueError, "Unique bounded original hook-audit"):
                P.hook_masks(original, set(), [])


    def test_root_qualification_and_two_test_observations_must_join(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "build-one", root / "build-two"
            first.mkdir()
            second.mkdir()
            package = ref(first / P.MD4C, b"the selected package")
            matching = ref(second / P.MD4C, b"the selected package")
            original = ref(root / "original", b"archive bytes")
            sig = ref(root / "md4c.sig", b"detached signature bytes")
            cert = ref(root / "md4c.gpg", b"public certificate bytes")
            native = dict(status="CLOSED_R7_MD4C_HOSTED_REPRODUCIBLE_PAIR_PASS", issuer="Root",
                          native_pair="PASS", comparison="PASS_BYTE_IDENTICAL", builds=2,
                          attempt=1, host_machine="aarch64", host_page_size=4096, archive=P.pair(original),
                          package=P.MD4C, package_archive=P.pair(package), release="CLOSE_ONLY",
                          expected_packages=349, authenticated_inputs=517)
            native.update(dict.fromkeys(("original_custody_pass", "exact_host_runner_terminal",
                "independent_finisher_replay", "owned_storage_absent", "controller_empty_twice",
                "dedicated_daemon_container_image_empty_twice", "scope_cleanup_observed"), True))
            native_path = root / "qualified.json"
            signed_path = root / "verified.json"
            native_ref = ref(native_path, P.T.encoded(native))
            fp = "F" * 40
            line = f"[GNUPG:] VALIDSIG {fp} 2026-11-18 12 0 4 0 22 10 00 {fp}"
            signed = dict(issuer="Root", status="PASS_MD4C_R7_EXACT_ARCHIVES_SCOPED_TEST_ONLY",
                          scope="only the pinned md4c R7 build pair", purpose="offline Qt build staging",
                          release="CLOSE_ONLY", production=False, private_signer_removed=True,
                          native_receipt=native_ref, signature=sig, trust=cert,
                          fingerprint=fp, created_epoch=10, expires_epoch=20,
                          observations=[dict(archive=archive, exit=0, validsig=line)
                                        for archive in (package, matching)])
            trust = dict(native_qualification=native_ref, test_verification=ref(signed_path, P.T.encoded(signed)),
                         reference=dict(archive=package, signature=sig, filename=P.MD4C), certificate=cert,
                         signer=dict(fingerprint=fp, created=10, expires=20))
            P.verify_qualification(trust, original)
            bad = signed | dict(observations=[signed["observations"][0], dict(signed["observations"][1], exit=1)])
            trust["test_verification"] = ref(signed_path, P.T.encoded(bad))
            with self.assertRaisesRegex(ValueError, "successful TEST signature observation"):
                P.verify_qualification(trust, original)
            trust["native_qualification"] = ref(native_path, P.T.encoded(dict(native, native_pair="HOLD")))
            with self.assertRaisesRegex(ValueError, "two-build native md4c PASS"):
                P.verify_qualification(trust, original)


if __name__ == "__main__":
    sys.addaudithook(P.O.passive_fence)
    unittest.main()
