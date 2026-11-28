# SPDX-License-Identifier: MIT
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import preflight


class PreflightTests(unittest.TestCase):
    def test_reads_pinned_r12_kernel_and_embedded_signature(self):
        kernel, signature, _, _ = preflight.kernel_inputs()
        self.assertEqual(kernel["filename"], preflight.KERNEL)
        self.assertEqual(kernel["size"], 69887600)
        self.assertEqual(hashlib.sha256(signature).hexdigest(), kernel["signature_sha256"])

    def test_refuses_modified_input_lock(self):
        with patch.object(preflight, "producer_blob", return_value=b"{}"):
            with self.assertRaisesRegex(ValueError, "input lock SHA-256 mismatch"):
                preflight.kernel_inputs()

    def test_transport_success_with_wrong_bytes_requires_exact_fallback(self):
        pin = {"filename": "fixture", "size": 4, "sha256": hashlib.sha256(b"good").hexdigest()}
        attempts = []

        def get(url, path, limit):
            self.assertFalse(path.exists())
            self.assertEqual(limit, 4)
            path.write_bytes(b"good" if url == "fallback" else b"evil")
            return 0, "200"

        with tempfile.TemporaryDirectory() as directory, patch.object(preflight, "download", side_effect=get):
            result = preflight.acquire(pin, ("primary", "fallback"), Path(directory), attempts)
            self.assertEqual(result.read_bytes(), b"good")
        self.assertEqual([row["matched_pin"] for row in attempts], [False, True])

    def test_missing_archive_remains_hold_without_invoking_signature_verifier(self):
        with patch.object(preflight, "download", return_value=(22, "404")) as download:
            report = preflight.recheck()
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["native_build"], "NOT RUN")
        self.assertNotIn("keyring_attempts", report)
        self.assertEqual(download.call_count, 5)
        self.assertTrue(all(not row["matched_pin"] for row in report["kernel_attempts"]))
        self.assertTrue(all(not call.args[1].parent.exists() for call in download.call_args_list))


if __name__ == "__main__":
    unittest.main()
