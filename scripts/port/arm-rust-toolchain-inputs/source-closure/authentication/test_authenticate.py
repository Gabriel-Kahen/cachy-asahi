"""Rejection controls independent of the two real opaque-source positive replays."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("source_authenticate", HERE / "authenticate.py")
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)
MANIFEST = json.loads((HERE / "manifest.json").read_text())
RECORDED = json.loads((HERE / "receipts/initial-signature-results.json").read_text())


class Controls(unittest.TestCase):
    def test_wrong_primary_rejected(self):
        with self.assertRaises(ValueError):
            AUTH.accepted_signature(0, RECORDED["rust"]["status"], ["0" * 40])

    def test_failure_exit_rejected_even_with_validsig(self):
        with self.assertRaises(ValueError):
            AUTH.accepted_signature(1, RECORDED["rust"]["status"], RECORDED["rust"]["allowed"])

    def test_multiple_signatures_rejected(self):
        with self.assertRaises(ValueError):
            AUTH.accepted_signature(0, RECORDED["rust"]["status"] * 2, RECORDED["rust"]["allowed"])

    def test_expired_or_revoked_status_rejected(self):
        for status in ("EXPKEYSIG", "REVKEYSIG", "BADSIG", "ERRSIG"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                AUTH.accepted_signature(0, RECORDED["rust"]["status"] +
                                        f"[GNUPG:] {status} key\n", RECORDED["rust"]["allowed"])

    def test_changed_pinned_key_rejected(self):
        pin = MANIFEST["materials"]["materials/rust-release-key.asc"]
        with tempfile.TemporaryDirectory(dir="/tmp") as folder:
            changed = Path(folder) / "changed.asc"
            changed.write_bytes((HERE / "materials/rust-release-key.asc").read_bytes() + b"\n")
            with self.assertRaises(ValueError):
                AUTH.check_pin(changed, pin)

    def test_real_math_rejects_unrelated_bytes(self):
        spec = MANIFEST["signatures"]["rust"]
        with tempfile.TemporaryDirectory(dir="/tmp") as folder:
            source = Path(folder) / "unsigned-data"
            source.write_bytes(b"source signature negative control\n")
            with self.assertRaises(ValueError):
                AUTH.verify_signature((HERE / spec["key"]).read_bytes(),
                                      (HERE / spec["signature"]).read_bytes(), source,
                                      spec["allowed_primary_fingerprints"])

    def test_original_sources_have_fixed_exact_byte_pins(self):
        for spec in MANIFEST["signatures"].values():
            with tempfile.TemporaryDirectory(dir="/tmp") as folder:
                source = Path(folder) / spec["archive"]
                source.write_bytes(b"different opaque source")
                with self.assertRaises(ValueError):
                    AUTH.check_pin(source, spec)

    def test_actual_status_accepts_only_declared_primaries(self):
        for name, record in RECORDED.items():
            result = AUTH.accepted_signature(record["exit"], record["status"],
                                             MANIFEST["signatures"][name]["allowed_primary_fingerprints"])
            self.assertEqual(record["primary"], result["primary_fingerprint"])

    def test_successor_archive_cannot_diverge_from_parent(self):
        parent = json.loads((HERE.parent / "source-inputs.json").read_text())
        original = MANIFEST["signatures"]["rust"]
        for key, value in (("archive", "different.tar.xz"), ("bytes", 1), ("sha256", "0" * 64)):
            with self.subTest(field=key), self.assertRaises(ValueError):
                AUTH.check_archive_binding({**original, key: value}, parent)

    def test_fifo_and_device_symlink_rejected_without_reading(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as folder:
            fifo, link = Path(folder) / "fifo", Path(folder) / "link"
            os.mkfifo(fifo)
            link.symlink_to("/dev/zero")
            for path in (fifo, link):
                with self.subTest(path=path.name), self.assertRaises(ValueError):
                    AUTH.check_pin(path, {"bytes": 1, "sha256": "0" * 64})

    def test_host_loader_environment_is_not_forwarded(self):
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "/invalid/control.so"}), \
                mock.patch.object(AUTH.subprocess, "run") as invoked:
            AUTH.run(["/usr/bin/gpg", "--version"])
            self.assertEqual(invoked.call_args.kwargs["env"],
                             {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"})

    def test_removed_history_payload_cannot_silently_reappear(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as folder:
            base = Path(folder)
            manifest = {"history_redactions": {"copy.js": {"sha256": "0" * 64}}}
            AUTH.check_redactions(base, manifest)
            (base / "copy.js").write_bytes(b"redaction control data")
            with self.assertRaises(ValueError):
                AUTH.check_redactions(base, manifest)


if __name__ == "__main__":
    unittest.main()
