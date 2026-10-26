#!/usr/bin/env python3
"""Offline hostile-input tests. No network, Cargo, or crate execution."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("audit_cargo", Path(__file__).with_name("audit-cargo.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cachy-update-audit-test-", dir="/tmp")
        self.root = Path(self.temp.name)
        self.entry = {"name": "fixture", "version": "1.0.0", "source": audit.REGISTRY}

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, extra=(), manifest=None):
        manifest = manifest or b'[package]\nname="fixture"\nversion="1.0.0"\nlicense="MIT"\n'
        members = [("fixture-1.0.0/Cargo.toml", manifest, tarfile.REGTYPE, 0o644),
                   ("fixture-1.0.0/LICENSE", b"Copyright fixture\nPermission is hereby granted...", tarfile.REGTYPE, 0o644)]
        members.extend(extra)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as tar:
            for path, data, kind, mode in members:
                member = tarfile.TarInfo(path)
                member.type, member.mode = kind, mode
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                member.linkname = "/tmp/outside" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                tar.addfile(member, io.BytesIO(data))
        data = output.getvalue()
        self.entry["checksum"] = audit.digest(data)
        path = self.root / "input.crate"
        path.write_bytes(data)
        return path

    def test_valid_notice_and_inert_build_script_hash(self):
        path = self.archive([("fixture-1.0.0/build.rs", b'panic!("never execute");', tarfile.REGTYPE, 0o755)])
        files = audit.inspect_archive(path, self.entry)
        row = audit.crate_metadata(files, self.entry)
        self.assertEqual(row["declared_spdx"], "MIT")
        self.assertFalse(row["license_evidence_blockers"])
        self.assertEqual(row["build_scripts"][0]["execution"], "NOT RUN")
        self.assertEqual(row["build_scripts"][0]["sha256"], audit.digest(files["build.rs"]))

    def test_checksum_mismatch(self):
        path = self.archive()
        self.entry["checksum"] = "0" * 64
        with self.assertRaisesRegex(audit.AuditError, "checksum"):
            audit.inspect_archive(path, self.entry)

    def test_links_special_modes_duplicate_and_traversal(self):
        cases = [("../outside", tarfile.REGTYPE, 0o644),
                 ("/fixture-1.0.0/absolute", tarfile.REGTYPE, 0o644),
                 ("fixture-1.0.0/../outside", tarfile.REGTYPE, 0o644),
                 ("fixture-1.0.0/a//b", tarfile.REGTYPE, 0o644),
                 ("fixture-1.0.0/a\\b", tarfile.REGTYPE, 0o644),
                 ("fixture-1.0.0/a\nb", tarfile.REGTYPE, 0o644),
                 ("fixture-1.0.0/link", tarfile.SYMTYPE, 0o644),
                 ("fixture-1.0.0/link", tarfile.LNKTYPE, 0o644),
                 ("fixture-1.0.0/fifo", tarfile.FIFOTYPE, 0o644),
                 ("fixture-1.0.0/setuid", tarfile.REGTYPE, 0o4755),
                 ("fixture-1.0.0/Cargo.toml", tarfile.REGTYPE, 0o644)]
        for path, kind, mode in cases:
            with self.subTest(path=path, kind=kind):
                archive = self.archive([(path, b"bad", kind, mode)])
                with self.assertRaises(audit.AuditError):
                    audit.inspect_archive(archive, self.entry)
        self.assertFalse((self.root / "outside").exists())

    def test_file_parent_collision(self):
        path = self.archive([("fixture-1.0.0/a", b"file", tarfile.REGTYPE, 0o644),
                             ("fixture-1.0.0/a/b", b"file", tarfile.REGTYPE, 0o644)])
        with self.assertRaisesRegex(audit.AuditError, "directory"):
            audit.inspect_archive(path, self.entry)

    def test_bounds(self):
        path = self.archive()
        for field, value in (("MAX_FILE", 1), ("MAX_MEMBERS", 1), ("MAX_EXPANDED", 1), ("MAX_ARCHIVE", 1)):
            with self.subTest(field=field), patch.object(audit, field, value):
                with self.assertRaises(audit.AuditError):
                    audit.inspect_archive(path, self.entry)

    def test_archive_deadline(self):
        path = self.archive()
        with patch.object(audit.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(audit.AuditError, "deadline"):
                audit.inspect_archive(path, self.entry)

    def test_hidden_metadata_and_gzip_bomb_bound(self):
        import gzip
        data = gzip.compress(b"\x00" * 1024 * 1024)
        path = self.root / "bomb.crate"
        path.write_bytes(data)
        self.entry["checksum"] = audit.digest(data)
        with patch.object(audit, "MAX_EXPANDED", 65536):
            with self.assertRaisesRegex(audit.AuditError, "complete tar stream"):
                audit.inspect_archive(path, self.entry)

    def test_missing_license_is_not_approval(self):
        files = audit.inspect_archive(self.archive(), self.entry)
        del files["LICENSE"]
        row = audit.crate_metadata(files, self.entry)
        self.assertEqual(row["declared_spdx"], "MIT")
        self.assertTrue(row["license_evidence_blockers"])
        self.assertEqual(row["license_acceptance"], "NOT REVIEWED")

    def test_embedded_archives_and_binary_inputs_are_not_hidden(self):
        files = audit.inspect_archive(self.archive(), self.entry)
        files.update({"native.tar.xz": b"\xfd7zXZ\x00opaque", "lib/target.a": b"!<arch>\nopaque"})
        row = audit.crate_metadata(files, self.entry)
        self.assertEqual(row["embedded_archives"][0]["path"], "native.tar.xz")
        self.assertEqual(row["prebuilt_binary_inputs"][0]["path"], "lib/target.a")
        self.assertEqual(row["embedded_archives"][0]["review"], "NOT REVIEWED")

    def embedded_gettext(self, extra=()):
        import lzma
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as tar:
            for path, data, kind in [("gettext-1.0/COPYING", b"GPL fixture", tarfile.REGTYPE),
                                     ("gettext-1.0/gettext-runtime/intl/COPYING.LIB", b"LGPL fixture", tarfile.REGTYPE), *extra]:
                member = tarfile.TarInfo(path)
                member.type = kind
                member.linkname = "/tmp/outside"
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                tar.addfile(member, io.BytesIO(data))
        return lzma.compress(out.getvalue())

    def test_embedded_gettext_notices_only_retained(self):
        row = audit.inspect_gettext(self.embedded_gettext(), self.root, self.entry)
        self.assertEqual(row["data_inspection"], "PASS")
        self.assertEqual(len(row["license_notices"]), 2)
        self.assertEqual(row["license_review"], "INCOMPLETE")
        self.assertTrue((self.root / "embedded/fixture-1.0.0/gettext-1.0/COPYING").is_file())

    def test_embedded_gettext_hostile_and_decompression_bounds(self):
        cases = [("../outside", b"bad", tarfile.REGTYPE), ("gettext-1.0/link", b"", tarfile.SYMTYPE)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(audit.AuditError):
                audit.inspect_gettext(self.embedded_gettext([case]), self.root, self.entry)
        with patch.object(audit, "MAX_EXPANDED", 1024), self.assertRaises(audit.AuditError):
            audit.inspect_gettext(self.embedded_gettext(), self.root, self.entry)

    def test_missing_license_file_and_bad_build_path(self):
        for field in ('license-file="../LICENSE"', 'build="../build.rs"'):
            manifest = ('[package]\nname="fixture"\nversion="1.0.0"\n' + field).encode()
            files = audit.inspect_archive(self.archive(manifest=manifest), self.entry)
            with self.assertRaises(audit.AuditError):
                audit.crate_metadata(files, self.entry)

    def test_manifest_identity_bound_to_lock(self):
        files = audit.inspect_archive(self.archive(), self.entry)
        files["Cargo.toml"] = files["Cargo.toml"].replace(b'"fixture"', b'"other"')
        with self.assertRaisesRegex(audit.AuditError, "identity"):
            audit.crate_metadata(files, self.entry)

    def test_safe_vendoring_checksums_and_no_execution_bit(self):
        path = self.archive([("fixture-1.0.0/build.rs", b"inert", tarfile.REGTYPE, 0o755)])
        files = audit.inspect_archive(path, self.entry)
        (self.root / "vendor").mkdir()
        source = Path(audit.retain_sources(files, self.entry, self.root))
        checksums = json.loads((source / ".cargo-checksum.json").read_text())
        self.assertEqual(checksums["package"], self.entry["checksum"])
        self.assertEqual(checksums["files"]["build.rs"], audit.digest(b"inert"))
        self.assertEqual((source / "build.rs").stat().st_mode & 0o111, 0)

    def test_reserved_vendor_checksum_refused_before_writes(self):
        with self.assertRaises(audit.AuditError):
            audit.retain_sources({".cargo-checksum.json": b"evil"}, self.entry, self.root)
        self.assertFalse((self.root / "vendor").exists())

    def test_bundle_reproducible_with_distinct_cache_paths(self):
        files = audit.inspect_archive(self.archive(), self.entry)
        results = []
        for dirname in ("first", "second"):
            cache = self.root / dirname
            (cache / "vendor").mkdir(parents=True)
            source = audit.retain_sources(files, self.entry, cache)
            row = {"name": "fixture", "version": "1.0.0", "archive_sha256": self.entry["checksum"],
                   "retained_archive": str(cache / "archives/input.crate"), "retained_source": source,
                   **audit.crate_metadata(files, self.entry)}
            report = {"cache": str(cache), "source_checksum_closure": "PASS", "registry_sources": [row]}
            result = audit.vendor_bundle(report, b"fixture lock", cache)
            results.append(result["sha256"])
            with tarfile.open(result["path"], "r:gz") as tar:
                names = tar.getnames()
                self.assertIn("LICENSES/fixture-1.0.0/LICENSE", names)
                self.assertIn("LICENSES/fixture-1.0.0/Cargo.toml", names)
                self.assertIn("vendor/fixture-1.0.0/.cargo-checksum.json", names)
                manifest = tar.extractfile("cargo-audit.json").read()
                self.assertNotIn(str(cache).encode(), manifest)
                self.assertTrue(all(m.isfile() and m.uid == m.gid == m.mtime == 0 and m.mode == 0o644 for m in tar))
        self.assertEqual(*results)

    def test_lock_pins_and_non_registry_sources(self):
        for source in (audit.REGISTRY, "git+https://example.invalid/repo"):
            data = ('version=4\n[[package]]\nname="fixture"\nversion="1.0.0"\nsource="' + source +
                    '"\nchecksum="' + "0" * 64 + '"\n').encode()
            with self.assertRaisesRegex(audit.AuditError, "pin"):
                audit.lock_entries(data)
            if source == audit.REGISTRY:
                self.assertEqual(len(audit.lock_entries(data, audit.digest(data))), 1)
            else:
                with self.assertRaisesRegex(audit.AuditError, "source"):
                    audit.lock_entries(data, audit.digest(data))

    def test_cache_symlink_and_hardlink_refused(self):
        target = self.archive()
        symlink = self.root / "symlink"
        symlink.symlink_to(target)
        with self.assertRaises(OSError):
            audit.read_regular(symlink, audit.MAX_ARCHIVE)
        import os
        os.link(target, self.root / "hardlink")
        with self.assertRaises(audit.AuditError):
            audit.read_regular(target, audit.MAX_ARCHIVE)

    def test_redirect_external_host_refused(self):
        handler = audit.StaticCratesOnly()
        with self.assertRaises(audit.AuditError):
            handler.redirect_request(None, None, 302, "redirect", {}, "https://evil.invalid/a")


if __name__ == "__main__":
    unittest.main()
