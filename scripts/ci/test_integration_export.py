"""Exporter boundaries; local temporary files only, no native/build claims."""
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "integration_export", Path(__file__).with_name("integration_export.py"))
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = self.root / "raw"
        self.raw.mkdir()
        self.output = self.root / "public"

    def put(self, name, data=b"public failure diagnostic\n"):
        path = self.raw / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def export(self):
        result = exporter.export_evidence(self.raw, self.output)
        self.assertEqual(result, json.loads((self.output / exporter.MANIFEST).read_bytes()))
        self.assertLessEqual(sum(p.stat().st_size for p in self.output.rglob("*") if p.is_file()),
                             exporter.TOTAL_LIMIT)
        return result

    def test_public_failure_is_preserved_with_exact_hashes(self):
        data = b'{"lifecycle":"FAIL","reason":"deliberate fixture failure"}\n'
        self.put("lifecycle/result.json", data)
        self.put("desktop/stderr.log")
        result = self.export()
        self.assertEqual(result["evidence_export"], "PASS")
        self.assertEqual(result["accepted_bytes"], len(data) + len(b"public failure diagnostic\n"))
        receipt = next(item for item in result["accepted"] if item["path"].endswith("result.json"))
        self.assertEqual(receipt["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual((self.output / receipt["path"]).read_bytes(), data)

    def test_nested_sensitive_state_is_never_read_or_copied(self):
        names = ("gpg", ".gnupg", "private-keys-v1.d", "secret", "home", "scratch",
                 "rootfs", "dependency-cache", "PRIVATE", "test-secret-state", "secretKey")
        for name in names:
            self.put(f"repository/nested/{name}/invisible.txt", b"SECRET_PAYLOAD")
        self.put("repository/result.json", b'{"status":"FAIL"}')
        # The walk must prune before opening any sensitive directory, not just
        # remove its contents from the eventual manifest.
        original_open = exporter.os.open

        def guarded_open(path, *args, **kwargs):
            self.assertNotIn(str(path), names)
            return original_open(path, *args, **kwargs)

        with patch.object(exporter.os, "open", side_effect=guarded_open):
            result = self.export()
        self.assertEqual(len(result["rejected"]), len(names))
        self.assertEqual(result["evidence_export"], "FAIL")
        self.assertEqual(len(result["accepted"]), 1)
        self.assertNotIn(b"SECRET_PAYLOAD", (self.output / exporter.MANIFEST).read_bytes())
        self.assertFalse(any(p.name == "invisible.txt" for p in self.output.rglob("*")))

    def test_symlinks_fifo_and_hardlinks_cannot_escape_tree(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"OUTSIDE_SECRET")
        (self.raw / "file.log").symlink_to(outside)
        (self.raw / "directory").symlink_to(self.root, target_is_directory=True)
        os.link(outside, self.raw / "hardlink.txt")
        os.mkfifo(self.raw / "pipe.log")
        result = self.export()
        self.assertEqual({item["reason"] for item in result["rejected"]},
                         {"symlink", "nonregular-file", "hardlinked-file"})
        self.assertEqual(result["accepted"], [])
        self.assertNotIn(b"OUTSIDE_SECRET", (self.output / exporter.MANIFEST).read_bytes())

    def test_input_symlink_or_symlinked_parent_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.raw, target_is_directory=True)
        for raw in (link, link / "."):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                exporter.export_evidence(raw, self.output)
        self.assertFalse(self.output.exists())

    def test_overlap_existing_output_and_traversal_through_link_rejected(self):
        for output in (self.raw, self.raw / "public", self.root):
            with self.subTest(output=output), self.assertRaises((ValueError, FileExistsError)):
                exporter.export_evidence(self.raw, output)
        self.output.mkdir()
        marker = self.output / "retained.txt"
        marker.write_bytes(b"untouched")
        with self.assertRaises(FileExistsError):
            exporter.export_evidence(self.raw, self.output)
        self.assertEqual(marker.read_bytes(), b"untouched")
        link = self.root / "linked"
        link.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(ValueError):
            exporter.export_evidence(self.raw, link / "child")
        with self.assertRaises(ValueError):
            exporter.export_evidence(self.raw / ".." / "raw", self.root / "traversal")
        with self.assertRaises(ValueError):
            exporter.export_evidence(self.raw, self.root / "new" / ".." / "traversal")

    def test_private_key_and_credential_strings_in_public_named_logs_rejected(self):
        contents = (
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET_PAYLOAD",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_PAYLOAD",
            b"-----BEGIN RSA PRIVATE KEY-----\nSECRET_PAYLOAD",
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nSECRET_PAYLOAD",
            b"(protected-private-key (rsa (d SECRET_PAYLOAD)))",
            b"secret_subkey SECRET_PAYLOAD",
            b"password = SECRET_PAYLOAD", b'{"private_key":"SECRET_PAYLOAD"}',
            b"Authorization: Bearer SECRET_PAYLOAD", b"gpg --export-secret-keys",
            b'{"token":"SECRET_PAYLOAD"}', b"api-key = SECRET_PAYLOAD",
        )
        for index, content in enumerate(contents):
            self.put(f"results/{index}.log", content)
        result = self.export()
        self.assertEqual(len(result["rejected"]), len(contents))
        self.assertEqual(result["accepted"], [])
        self.assertNotIn(b"SECRET_PAYLOAD", (self.output / exporter.MANIFEST).read_bytes())

    def test_nonutf8_binary_invalid_json_and_all_archives_rejected(self):
        contents = {"binary.txt": b"text\x00payload", "bad.log": b"\xff\xfe",
                    "invalid.json": b"not JSON", "built.pkg.tar.zst": b"MIT package",
                    "root.tar.gz": b"rootfs", "public.csv": b"a,b\n",
                    exporter.MANIFEST: b"{}"}
        for name, content in contents.items():
            self.put(name, content)
        result = self.export()
        self.assertEqual(len(result["rejected"]), len(contents))
        self.assertEqual(result["accepted"], [])

    def test_oversized_file_reports_size_without_truncating(self):
        self.put("large.log", b"x" * (exporter.FILE_LIMIT + 1))
        result = self.export()
        self.assertEqual(result["rejected"], [{"path": "large.log", "bytes": exporter.FILE_LIMIT + 1,
                                               "reason": "per-file-byte-limit"}])
        self.assertFalse((self.output / "large.log").exists())

    def test_manifest_is_charged_to_total_budget_and_files_not_truncated(self):
        self.put("a.txt", b"a" * 2000)
        self.put("b.txt", b"b" * 2000)
        with patch.object(exporter, "TOTAL_LIMIT", 4096):
            result = self.export()
        self.assertEqual(result["accepted_bytes"], 2000)
        self.assertEqual((self.output / "a.txt").read_bytes(), b"a" * 2000)
        self.assertEqual(result["rejected"][0]["reason"], "total-byte-limit-including-manifest")
        self.assertFalse((self.output / "b.txt").exists())

    def test_entry_depth_and_path_budgets_are_explicit(self):
        self.put("first.txt")
        self.put("second.txt")
        with patch.object(exporter, "ENTRY_LIMIT", 1):
            result = self.export()
        self.assertTrue(result["inventory_limit_exceeded"])
        self.assertIn("entry-limit-exceeded", result["rejected"][0]["reason"])
        self.output = self.root / "depth-public"
        self.put("nested/too/deep/result.log")
        with patch.object(exporter, "DEPTH_LIMIT", 1):
            result = self.export()
        self.assertTrue(any("depth-limit-exceeded" in item["reason"] for item in result["rejected"]))
        self.output = self.root / "path-public"
        self.put("long/" + "x" * 100 + ".log")
        with patch.object(exporter, "PATH_LIMIT", 80):
            result = self.export()
        self.assertTrue(any(item["path"].startswith("[path-sha256:") for item in result["rejected"]))

    def test_file_modified_between_stat_and_open_is_rejected(self):
        target = self.put("result.log")
        original_open = exporter.os.open

        def race(path, *args, **kwargs):
            if str(path) == "result.log":
                target.write_bytes(b"changed")
            return original_open(path, *args, **kwargs)

        with patch.object(exporter.os, "open", side_effect=race):
            result = self.export()
        self.assertEqual(result["accepted"], [])
        self.assertEqual(result["rejected"][0]["reason"], "file-changed-during-read")

    def test_cli_rejections_fail_with_retained_safe_diagnostics(self):
        self.put("good.log")
        self.put("nested/secret.log", b"SECRET_PAYLOAD")
        with patch("sys.stdout"):
            code = exporter.main(["--raw", str(self.raw), "--output", str(self.output)])
        self.assertEqual(code, 1)
        self.assertTrue((self.output / "good.log").exists())
        self.assertTrue((self.output / exporter.MANIFEST).exists())


if __name__ == "__main__":
    unittest.main()
