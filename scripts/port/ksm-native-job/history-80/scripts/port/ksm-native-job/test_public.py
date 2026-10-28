# SPDX-License-Identifier: MIT
"""Curated export fixtures only; no build, Docker, GPG or installation."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("ksm_public_fixture", Path(__file__).with_name("public.py"))
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)


class PublicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.output = self.root / "public"
        self.binding = {"source_commit": "a" * 40, "run_id": "123", "image_id": "sha256:" + "b" * 64,
                        "packet_sha256": "c" * 64, "inputs_sha256": public.INPUTS_SHA256, "packages_sha256": public.PACKAGES_SHA256,
                        "recipe_map_sha256": public.RECIPE_MAP_SHA256}
        recipe = Path(public.__file__).resolve().parents[3] / "packages/tools/cachy-asahi-ksmctl"
        self.payload = {path: (recipe / Path(path).name).read_bytes() for path in public.PAYLOAD}
        self.filename = public.NAME + "-" + public.VERSION + "-any.pkg.tar.xz"
        data = self.archive()
        self.refs = []
        for number in (1, 2):
            directory = self.root / f"private-build-{number}"
            directory.mkdir()
            path = directory / self.filename
            path.write_bytes(data)
            self.refs.append(self.ref(path))
        self.acceptance = {"schema_version": 1, "status": "PASS", "scope": public.SCOPE, "binding": self.binding,
                           "producer": {"status": "PASS", "cleanup": "PASS"},
                           "builds": [{"status": "PASS", "filename": self.filename, "sha256": self.refs[0]["sha256"],
                                       "provenance_sha256": digit * 64, "container_cleanup": "PASS"} for digit in ("1", "2")],
                           "comparison": {"status": "PASS", "archives_equal": True, "metadata_equal": True,
                                          "payload_equal": True, "buildinfo_equal": True},
                           "lifecycle": {"status": "PASS", "cleanup": "PASS"},
                           "source_notices": {"gpl15_recipe_snapshot": True, "notice_preserved": True, "license_preserved": True},
                           "cleanup": {"status": "PASS", "absence_verified": True}}

    def ref(self, path):
        data = path.read_bytes()
        return {"path": str(path), "size": len(data), "sha256": public.sha(data)}

    def acceptance_ref(self):
        path = self.root / "private-acceptance.json"
        path.write_text(json.dumps(self.acceptance))
        return self.ref(path)

    def archive(self, *, version=public.VERSION, arch="any", codec="xz", payload=None, extra=None):
        raw = io.BytesIO()
        fields = f"pkgname = {public.NAME}\npkgver = {version}\narch = {arch}\nlicense = {public.LICENSE}\ndepend = python>=3.11\n".encode()
        with tarfile.open(fileobj=raw, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
            nodes = [(".PKGINFO", fields, 0o644), (".BUILDINFO", b"format = 2\n", 0o644), (".MTREE", b"mtree fixture", 0o644)]
            nodes.extend((path, data, public.PAYLOAD[path][0]) for path, data in (payload or self.payload).items())
            nodes.extend(extra or [])
            for name, data, mode in nodes:
                info = tarfile.TarInfo(name); info.size = len(data); info.mode = mode
                archive.addfile(info, io.BytesIO(data))
        return lzma.compress(raw.getvalue()) if codec == "xz" else gzip.compress(raw.getvalue(), mtime=0)

    def replace_archives(self, data, filename=None):
        filename = filename or self.filename
        for number in range(2):
            path = Path(self.refs[number]["path"]).with_name(filename)
            path.write_bytes(data)
            self.refs[number] = self.ref(path)
            self.acceptance["builds"][number].update(filename=filename, sha256=self.refs[number]["sha256"])

    def export(self, **kwargs):
        return public.export(self.acceptance_ref(), self.refs, self.output, self.binding, **kwargs)

    def test_only_two_exact_packages_and_constructed_evidence_are_exported(self):
        (self.root / "controller.log").write_text("PRIVATE RAW SECRET")
        result = self.export()
        files = sorted(str(path.relative_to(self.output)) for path in self.output.rglob("*") if path.is_file())
        self.assertEqual(files, ["build-1/" + self.filename, "build-2/" + self.filename, "evidence.json"])
        for number, ref in enumerate(self.refs, 1):
            path = self.output / f"build-{number}" / self.filename
            self.assertEqual(path.read_bytes(), Path(ref["path"]).read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        encoded = (self.output / "evidence.json").read_bytes()
        self.assertLessEqual(len(encoded), public.EVIDENCE_LIMIT)
        self.assertNotIn(b"PRIVATE", encoded)
        self.assertNotIn(str(self.root).encode(), encoded)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.output / "evidence.json").stat().st_mode & 0o777, 0o644)
        self.assertIs(result["published"], False)
        self.assertIs(result["source_grants_complete"], False)
        self.assertEqual(result["hardware"], "NOT RUN")
        self.assertEqual(result["performance"], "NOT RUN")

    def test_gzip_exact_accepted_package_format(self):
        filename = self.filename.removesuffix("xz") + "gz"
        self.replace_archives(self.archive(codec="gz"), filename)
        self.assertEqual(self.export()["packages"][0]["file"], "build-1/" + filename)

    def test_any_failed_acceptance_or_cleanup_blocks_creation(self):
        original = copy.deepcopy(self.acceptance)
        for area, field in (("producer", "status"), ("producer", "cleanup"), ("lifecycle", "status"),
                            ("lifecycle", "cleanup"), ("cleanup", "status"), ("comparison", "status")):
            with self.subTest(area=area, field=field):
                self.acceptance = copy.deepcopy(original)
                self.acceptance[area][field] = "FAIL"
                with self.assertRaises(ValueError): self.export()
                self.assertFalse(self.output.exists())
        self.acceptance = original
        self.acceptance["builds"][1]["container_cleanup"] = "FAIL"
        with self.assertRaises(ValueError): self.export()
        self.assertFalse(self.output.exists())

    def test_comparison_notice_and_absence_flags_must_be_boolean_true(self):
        original = copy.deepcopy(self.acceptance)
        for area, fields in (("source_notices", list(original["source_notices"])),
                             ("comparison", [key for key in original["comparison"] if key != "status"]),
                             ("cleanup", ["absence_verified"])):
            for field in fields:
                for wrong in (False, 1, "PASS"):
                    with self.subTest(area=area, field=field, wrong=wrong):
                        self.acceptance = copy.deepcopy(original)
                        self.acceptance[area][field] = wrong
                        with self.assertRaises(ValueError): self.export()
                        self.assertFalse(self.output.exists())

    def test_unknown_raw_fields_and_misclassified_status_refused(self):
        for field, value in (("raw_controller_log", "PRIVATE"), ("secret_key", "PRIVATE"), ("schema_version", True),
                             ("scope", "stable"), ("status", "IN_PROGRESS")):
            original = copy.deepcopy(self.acceptance)
            self.acceptance[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.export()
            self.assertFalse(self.output.exists())
            self.acceptance = original

    def test_same_job_source_binding_and_reviewed_map_drift_refused(self):
        acceptance = self.acceptance_ref()
        for field, value in (("source_commit", "f" * 40), ("run_id", "124"), ("image_id", "sha256:" + "f" * 64),
                             ("packet_sha256", "f" * 64), ("recipe_map_sha256", "f" * 64)):
            binding = {**self.binding, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                public.export(acceptance, self.refs, self.output, binding)
            self.assertFalse(self.output.exists())

    def test_corrupt_archive_hash_and_size_refused(self):
        refs = copy.deepcopy(self.refs)
        for field, value in (("sha256", "0" * 64), ("size", refs[0]["size"] + 1), ("size", public.PACKAGE_LIMIT + 1)):
            candidate = copy.deepcopy(refs); candidate[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                public.export(self.acceptance_ref(), candidate, self.output, self.binding)
            self.assertFalse(self.output.exists())

    def test_symlink_and_hardlink_archive_refused(self):
        original = Path(self.refs[0]["path"])
        for link_type in ("symlink", "hardlink"):
            link = self.root / link_type / self.filename
            link.parent.mkdir()
            if link_type == "symlink": link.symlink_to(original)
            else: os.link(original, link)
            refs = [{**self.refs[0], "path": str(link)}, self.refs[1]]
            with self.subTest(link_type=link_type), self.assertRaises(ValueError):
                public.export(self.acceptance_ref(), refs, self.output, self.binding)
            link.unlink()
            self.assertFalse(self.output.exists())

    def test_exact_package_version_arch_and_notice_bytes_required(self):
        for data in (self.archive(version="0.2.0-1"), self.archive(arch="x86_64"),
                     self.archive(payload={**self.payload, next(path for path in public.PAYLOAD if path.endswith("/NOTICE")): b"changed notice"})):
            with self.subTest(sha=public.sha(data)):
                self.replace_archives(data)
                with self.assertRaises(ValueError): self.export()
                self.assertFalse(self.output.exists())

    def test_scriptlets_hooks_unknown_payload_and_duplicate_members_refused(self):
        for path in (".INSTALL", "usr/share/libalpm/hooks/run.hook", "secret-signing-key", "usr/bin/" + public.NAME):
            with self.subTest(path=path):
                self.replace_archives(self.archive(extra=[(path, b"unreviewed", 0o644)]))
                with self.assertRaises(ValueError): self.export()
                self.assertFalse(self.output.exists())

    def test_distinct_provenance_and_equal_actual_build_bytes_required(self):
        self.acceptance["builds"][1]["provenance_sha256"] = self.acceptance["builds"][0]["provenance_sha256"]
        with self.assertRaises(ValueError): self.export()
        self.assertFalse(self.output.exists())

    def test_cancellation_before_creation_exports_nothing(self):
        with self.assertRaises(public.Cancelled): self.export(cancelled=lambda: True)
        self.assertFalse(self.output.exists())

    def test_cancellation_during_package_copy_removes_partial_output(self):
        real_write = os.write
        state = {"cancelled": False}
        def write(fd, data):
            count = real_write(fd, data[:3])
            state["cancelled"] = True
            return count
        with patch.object(public.os, "write", side_effect=write):
            with self.assertRaises(public.Cancelled): self.export(cancelled=lambda: state["cancelled"])
        self.assertFalse(self.output.exists())

    def test_fsync_failure_removes_all_curated_partial_files(self):
        with patch.object(public.os, "fsync", side_effect=OSError("fixture storage failure")):
            with self.assertRaises(OSError): self.export()
        self.assertFalse(self.output.exists())

    def test_cancellation_after_evidence_fsync_removes_completed_looking_output(self):
        real_fsync = os.fsync
        state = {"files": 0, "cancelled": False}
        def fsync(fd):
            real_fsync(fd)
            if os.fstat(fd).st_mode & 0o170000 == 0o100000:
                state["files"] += 1
                if state["files"] == 3:
                    state["cancelled"] = True
        with patch.object(public.os, "fsync", side_effect=fsync):
            with self.assertRaises(public.Cancelled): self.export(cancelled=lambda: state["cancelled"])
        self.assertEqual(state["files"], 3)
        self.assertFalse(self.output.exists())

    def test_mid_second_package_write_failure_removes_first_and_partial_second(self):
        real_write = os.write
        count = 0
        def write(fd, data):
            nonlocal count
            count += 1
            if count == 2:
                real_write(fd, data[:3])
                raise OSError("fixture second-package failure")
            return real_write(fd, data)
        with patch.object(public.os, "write", side_effect=write):
            with self.assertRaises(OSError): self.export()
        self.assertFalse(self.output.exists())

    def test_input_same_size_overwrite_after_capture_does_not_change_exported_bytes(self):
        original = Path(self.refs[0]["path"]).read_bytes()
        real_write = os.write
        changed = False
        def write(fd, data):
            nonlocal changed
            if not changed:
                Path(self.refs[0]["path"]).write_bytes(b"X" * len(original))
                changed = True
            return real_write(fd, data)
        with patch.object(public.os, "write", side_effect=write): self.export()
        self.assertEqual((self.output / "build-1" / self.filename).read_bytes(), original)

    def test_existing_or_public_parent_and_symlink_output_refused(self):
        self.output.mkdir()
        with self.assertRaises(ValueError): self.export()
        self.output.rmdir()
        self.output.symlink_to(self.root / "outside", target_is_directory=True)
        with self.assertRaises(ValueError): self.export()
        self.output.unlink()
        os.chmod(self.root, 0o755)
        with self.assertRaisesRegex(ValueError, "private owned output parent"): self.export()
        self.assertFalse(self.output.exists())

    def after_written(self, action, *, fail=False):
        real_fsync = os.fsync
        acted = False
        def fsync(fd):
            nonlocal acted
            real_fsync(fd)
            if not acted and os.fstat(fd).st_mode & 0o170000 == 0o040000:
                acted = True
                action()
                if fail:
                    raise OSError("fixture failure after namespace substitution")
        return patch.object(public.os, "fsync", side_effect=fsync)

    def test_source_ancestor_symlink_swap_at_open_is_refused(self):
        real_open = os.open
        source = Path(self.refs[0]["path"]).parent
        moved = self.root / "saved-source"
        target = self.root / "foreign-source"
        target.mkdir()
        (target / self.filename).write_bytes(Path(self.refs[0]["path"]).read_bytes())
        def opened(path, flags, *args, **kwargs):
            if path == source.name:
                source.rename(moved)
                source.symlink_to(target, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(public.os, "open", side_effect=opened):
            with self.assertRaises(ValueError): self.export()
        self.assertFalse(self.output.exists())
        self.assertTrue((target / self.filename).exists())

    def test_source_metadata_same_bytes_mode_change_during_capture_refused(self):
        path = Path(self.refs[0]["path"])
        real_read = os.read
        changed = False
        def read(fd, count):
            nonlocal changed
            data = real_read(fd, count)
            if not changed:
                os.fchmod(fd, 0o600)
                changed = True
            return data
        with patch.object(public.os, "read", side_effect=read):
            with self.assertRaisesRegex(ValueError, "metadata drift"):
                public.capture(self.refs[0], public.PACKAGE_LIMIT, lambda: False)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.output.exists())

    def test_output_ancestor_symlink_swap_at_open_creates_nothing_foreign(self):
        parent = self.root / "output-parent"
        parent.mkdir(mode=0o700)
        self.output = parent / "public"
        foreign = self.root / "foreign-parent"
        foreign.mkdir(mode=0o700)
        real_open = os.open
        def opened(path, flags, *args, **kwargs):
            if path == parent.name:
                parent.rename(self.root / "saved-parent")
                parent.symlink_to(foreign, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(public.os, "open", side_effect=opened):
            with self.assertRaises(OSError): self.export()
        self.assertEqual(list(foreign.iterdir()), [])

    def test_root_swap_before_cleanup_retains_foreign_tree_and_own_failure(self):
        saved = self.root / "saved-root"
        def swap():
            self.output.rename(saved)
            self.output.mkdir(mode=0o700)
            (self.output / "foreign").write_bytes(b"unowned")
        with self.after_written(swap, fail=True):
            with self.assertRaisesRegex(ValueError, "identity changed"): self.export()
        self.assertEqual((self.output / "foreign").read_bytes(), b"unowned")
        self.assertEqual(json.loads((saved / "evidence.json").read_bytes())["status"], "FAIL-curated-development-export")
        self.assertTrue((saved / "build-1" / self.filename).exists())

    def test_child_swap_before_cleanup_retains_foreign_directory(self):
        saved = self.root / "saved-child"
        def swap():
            (self.output / "build-1").rename(saved)
            (self.output / "build-1").mkdir(mode=0o700)
            (self.output / "build-1" / "foreign").write_bytes(b"unowned")
        with self.after_written(swap, fail=True):
            with self.assertRaisesRegex(ValueError, "identity changed"): self.export()
        self.assertEqual((self.output / "build-1" / "foreign").read_bytes(), b"unowned")
        self.assertTrue((saved / self.filename).exists())
        self.assertEqual(json.loads((self.output / "evidence.json").read_bytes())["status"], "FAIL-curated-development-export")

    def test_package_name_swap_before_cleanup_does_not_unlink_replacement(self):
        saved = self.root / "saved-package"
        def swap():
            path = self.output / "build-1" / self.filename
            path.rename(saved)
            path.write_bytes(b"unowned")
        with self.after_written(swap, fail=True):
            with self.assertRaisesRegex(ValueError, "identity changed"): self.export()
        self.assertEqual((self.output / "build-1" / self.filename).read_bytes(), b"unowned")
        self.assertTrue(saved.exists())
        self.assertEqual(json.loads((self.output / "evidence.json").read_bytes())["status"], "FAIL-curated-development-export")

    def test_evidence_name_swap_preserves_foreign_bytes_invalidates_owned_inode(self):
        saved = self.root / "saved-evidence"
        def swap():
            path = self.output / "evidence.json"
            path.rename(saved)
            path.write_bytes(b"unowned evidence")
        with self.after_written(swap, fail=True):
            with self.assertRaisesRegex(ValueError, "identity changed"): self.export()
        self.assertEqual((self.output / "evidence.json").read_bytes(), b"unowned evidence")
        self.assertEqual(json.loads(saved.read_bytes())["status"], "FAIL-curated-development-export")

    def test_final_package_same_size_tamper_or_wrong_mode_never_passes(self):
        for mutation in ("bytes", "mode", "directory-mode"):
            def tamper():
                path = self.output / "build-1" / self.filename
                if mutation == "bytes": path.write_bytes(b"X" * path.stat().st_size)
                elif mutation == "mode": path.chmod(0o600)
                else: path.parent.chmod(0o755)
            with self.subTest(mutation=mutation), self.after_written(tamper):
                with self.assertRaises(ValueError): self.export()
            self.assertFalse(self.output.exists())

    def test_final_hardlink_drift_refused_without_touching_external_link(self):
        link = self.root / "external-package"
        with self.after_written(lambda: os.link(self.output / "build-1" / self.filename, link)):
            with self.assertRaisesRegex(ValueError, "file identity/mode drift"): self.export()
        self.assertTrue(link.exists())
        self.assertFalse(self.output.exists())

    def test_unexpected_foreign_file_prevents_cleanup_and_invalidates_evidence(self):
        with self.after_written(lambda: (self.output / "foreign.log").write_bytes(b"unowned")):
            with self.assertRaisesRegex(ValueError, "unexpected public root contents"): self.export()
        self.assertEqual((self.output / "foreign.log").read_bytes(), b"unowned")
        self.assertEqual(json.loads((self.output / "evidence.json").read_bytes())["status"], "FAIL-curated-development-export")

    def test_restrictive_umask_directory_mode_is_checked_before_pass(self):
        acceptance = self.acceptance_ref()
        old = os.umask(0o777)
        try:
            with self.assertRaisesRegex(ValueError, "private owned output parent/directory"):
                public.export(acceptance, self.refs, self.output, self.binding)
        finally:
            os.umask(old)
        self.assertFalse(self.output.exists())

    def test_consistent_but_unreviewed_inputs_or_package_pins_refused(self):
        for key in ("inputs_sha256", "packages_sha256"):
            original = self.binding[key]
            self.binding[key] = "deadbeef" * 8
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "reviewed inputs"):
                self.export()
            self.assertFalse(self.output.exists())
            self.binding[key] = original


if __name__ == "__main__":
    unittest.main()
