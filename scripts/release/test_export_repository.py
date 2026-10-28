#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Real local filesystem/signature tests; stable acceptance is explicitly modeled."""
import argparse
import fcntl
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


e = module("export_repository", "export_repository.py")
fixture = module("export_fixture", "test_release.py")
fixture.r = e.r


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.ReleaseTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixture.ReleaseTests.tearDownClass.__func__(cls)

    def setUp(self):
        fixture.ReleaseTests.setUp(self)
        (self.root / ".release.lock").touch()
        self.endpoint = self.base / "endpoint"
        self.endpoint.mkdir()

    put = fixture.ReleaseTests.put
    ref = fixture.ReleaseTests.ref
    save_spec = fixture.ReleaseTests.save_spec
    stage = fixture.ReleaseTests.stage

    def promote(self, rid="fixture-1"):
        self.release_spec["release_id"] = rid
        self.stage()
        gates = self.inputs / "gates.json"
        e.r.write(gates, {"schema_version": 1, "synthetic": True, "marker": "MODELED stable gate; NOT accepted"})
        with mock.patch.object(e.r, "gates_check", side_effect=lambda *args: e.r.load(args[-1])):
            e.r.promote(argparse.Namespace(release_id=rid, gates=str(gates)), self.root, self.key, self.env)

    def export(self, apply=True):
        # Cryptographic verification, complete release semantics and Source association
        # remain real. Only hardware/promotion gate acceptance is modeled.
        with mock.patch.object(e.r, "gates_check", side_effect=lambda *args: e.r.load(args[-1])):
            return e.export(self.root, self.endpoint, self.home, self.key, apply)

    def snapshot(self, root):
        return {str(p.relative_to(root)): ("link", os.readlink(p)) if p.is_symlink() else
                ("file", p.read_bytes()) for p in root.rglob("*") if p.is_file() or p.is_symlink()}

    def unchanged_failure(self, callback):
        before = self.snapshot(self.endpoint)
        with self.assertRaises((e.r.Error, OSError)):
            callback()
        self.assertEqual(self.snapshot(self.endpoint), before)

    def add_sources(self):
        def material(name, raw):
            (self.inputs / name).write_bytes(raw)
            return dict(self.ref(name), id=name, bytes=len(raw))
        recipe = material("recipe.txt", b"# Original synthetic MIT recipe; never executed\n")
        record = {"package": {"name": "fixture", "version": "1.0-1", "arch": "any", "sha256": self.digest},
                  "recipe_key": "PKGBUILD", "review_status": "INCOMPLETE synthetic source record",
                  "bundle": material("source.tar", b"opaque synthetic Source bundle\n"),
                  "notices": [material("NOTICE", b"Original fixture MIT notice\n")], "recipe": recipe,
                  "source_map": material("source-map.json", e.encoded({"PKGBUILD": recipe["sha256"]})),
                  "authorization": material("review.txt", b"Existing synthetic review; no Source/legal acceptance\n")}
        self.put("source-index.json", {"schema_version": 1, "purpose": "release-source-delivery", "synthetic": True,
                                      "packages": [record]})
        self.release_spec["source_delivery"] = {"schema_version": 1,
            "index": dict(self.ref("source-index.json"), id="source-index.json")}
        provenance = e.r.load(self.inputs / "provenance.json")
        provenance["recipe_sha256"] = recipe["sha256"]
        self.put("provenance.json", provenance)
        self.release_spec["packages"][0]["provenance"] = self.ref("provenance.json")

    def test_plan_preserves_source_and_empty_destination(self):
        self.promote()
        before = self.snapshot(self.root)
        result = self.export(False)
        self.assertEqual(result["status"], "planned-local-endpoint")
        self.assertFalse(result["network_published"])
        self.assertEqual(list(self.endpoint.iterdir()), [])
        self.assertEqual(self.snapshot(self.root), before)

    def test_complete_signed_bundle_source_delivery_and_repository_aliases(self):
        self.add_sources()
        self.promote()
        before = self.snapshot(self.root)
        result = self.export()
        current = self.endpoint / "current"
        self.assertEqual(self.snapshot(current / "release"), self.snapshot(self.root / "stable/fixture-1"))
        self.assertEqual((current / "release/evidence/source.tar").read_bytes(), b"opaque synthetic Source bundle\n")
        self.assertEqual((current / "release/repo/fixture.db").read_bytes(),
                         (current / "release/repo/fixture.db.tar.gz").read_bytes())
        self.assertEqual((current / "promotion.json.sig").read_bytes(), (self.root / "promotions/fixture-1.json.sig").read_bytes())
        self.assertFalse(result["trust_changed"])
        self.assertEqual(self.snapshot(self.root), before)

    def test_idempotent_export_and_successive_retained_generation(self):
        self.promote()
        first = self.export()
        before = self.snapshot(self.endpoint)
        self.assertEqual(self.export()["generation"], first["generation"])
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.promote("fixture-2")
        second = self.export()
        self.assertNotEqual(first["generation"], second["generation"])
        self.assertEqual(e.r.load(self.endpoint / "current/release/release.json")["release_id"], "fixture-2")
        self.assertTrue((self.endpoint / "generations" / first["generation"] / "release/release.json").is_file())

    def test_withdrawal_generation_removes_live_repo_and_retains_signed_incident(self):
        self.promote()
        first = self.export()
        reason = self.inputs / "incident.txt"
        reason.write_text("Synthetic withdrawal drill.\n")
        e.r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(reason)), self.root, self.key, self.env)
        result = self.export()
        self.assertIsNone(result["selected_release"])
        self.assertFalse((self.endpoint / "current/release").exists())
        self.assertEqual((self.endpoint / "current/withdrawals/fixture-1.json.sig").read_bytes(),
                         (self.root / "withdrawals/fixture-1.json.sig").read_bytes())
        self.assertTrue((self.endpoint / "generations" / first["generation"]).is_dir())

    def test_selected_withdrawn_release_refuses_and_preserves_endpoint(self):
        self.promote()
        self.export()
        reason = self.inputs / "incident.txt"
        reason.write_text("Synthetic incident.\n")
        e.r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(reason)), self.root, self.key, self.env)
        (self.root / "stable/current").symlink_to("fixture-1")
        self.unchanged_failure(self.export)

    def test_partial_withdrawal_refuses_and_preserves_endpoint(self):
        self.promote()
        self.export()
        reason = self.inputs / "incident.txt"
        reason.write_text("Synthetic incident.\n")
        e.r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(reason)), self.root, self.key, self.env)
        (self.root / "withdrawals/fixture-1.json.sig").unlink()
        self.unchanged_failure(self.export)

    def test_real_gate_rejects_synthetic_stable_with_no_output(self):
        self.promote()
        self.unchanged_failure(lambda: e.export(self.root, self.endpoint, self.home, self.key, True))

    def test_wrong_key_and_missing_promotion_signature(self):
        self.promote()
        self.export()
        self.unchanged_failure(lambda: e.export(self.root, self.endpoint, self.home, "F" * 40, True))
        (self.root / "promotions/fixture-1.json.sig").unlink()
        self.unchanged_failure(self.export)

    def test_cross_release_signed_promotion_is_rejected(self):
        self.promote()
        self.export()
        path = self.root / "promotions/fixture-1.json"
        saved = e.r.load(path)
        saved["release_id"] = "foreign"
        e.r.write(path, saved)
        Path(str(path) + ".sig").unlink()
        e.r.sign(path, self.key, self.env)
        self.unchanged_failure(self.export)

    def test_complete_foreign_release_cannot_be_relabelled_as_selection(self):
        self.promote()
        self.export()
        self.promote("fixture-2")
        shutil.rmtree(self.root / "stable/fixture-1")
        shutil.copytree(self.root / "stable/fixture-2", self.root / "stable/fixture-1", symlinks=True)
        for suffix in ("", ".sig"):
            shutil.copyfile(self.root / ("promotions/fixture-2.json" + suffix),
                            self.root / ("promotions/fixture-1.json" + suffix))
        current = self.root / "stable/current"
        current.unlink()
        current.symlink_to("fixture-1")
        self.unchanged_failure(self.export)

    def test_package_tamper_and_foreign_symlink_are_rejected(self):
        self.promote()
        self.export()
        package = self.root / "stable/fixture-1/repo" / self.archive.name
        original = package.read_bytes()
        package.write_bytes(original + b"altered")
        self.unchanged_failure(self.export)
        package.unlink()
        package.symlink_to(self.archive)
        self.unchanged_failure(self.export)

    def test_writable_or_hardlinked_source_is_not_deployed(self):
        self.promote()
        self.export()
        path = self.root / "stable/fixture-1/release.json"
        path.chmod(0o666)
        self.unchanged_failure(self.export)
        path.chmod(0o644)
        os.link(path, self.inputs / "foreign-hardlink")
        self.unchanged_failure(self.export)

    def test_consumed_source_directory_permissions_are_checked_before_payload_reads(self):
        self.promote()
        self.export()
        original = e.r.sha
        def no_source_read(path):
            if Path(path).is_relative_to(self.root):
                self.fail("Source payload read before directory permission refusal")
            return original(path)
        for name in ("stable", "stable/fixture-1", "promotions"):
            with self.subTest(directory=name):
                path = self.root / name
                mode = path.stat().st_mode & 0o777
                path.chmod(0o777)
                try:
                    with mock.patch.object(e.r, "sha", side_effect=no_source_read):
                        self.unchanged_failure(lambda: self.export(False))
                        self.unchanged_failure(self.export)
                finally:
                    path.chmod(mode)

    def test_withdrawal_directory_permissions_are_checked_before_signature_reads(self):
        self.promote()
        self.export()
        reason = self.inputs / "incident.txt"
        reason.write_text("Synthetic withdrawal directory boundary.\n")
        e.r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(reason)), self.root, self.key, self.env)
        (self.root / "withdrawals").chmod(0o777)
        with mock.patch.object(e.r, "verify_signature", side_effect=AssertionError("unexpected signature read")):
            self.unchanged_failure(lambda: self.export(False))
            self.unchanged_failure(self.export)

    def test_path_escape_foreign_endpoint_and_nested_symlink(self):
        self.promote()
        self.export()
        alias = self.base / "alias"
        alias.symlink_to(self.endpoint, target_is_directory=True)
        self.unchanged_failure(lambda: e.export(self.root, alias, self.home, self.key, True))
        self.unchanged_failure(lambda: e.export(self.root, str(self.endpoint) + "/../endpoint", self.home, self.key, True))
        (self.endpoint / "foreign").write_text("preserve")
        self.unchanged_failure(self.export)

    def test_unmanaged_selection_is_not_overwritten(self):
        self.promote()
        (self.endpoint / "current").symlink_to("../inputs")
        self.unchanged_failure(self.export)

    def test_double_leading_slash_cannot_hide_source_endpoint_overlap(self):
        self.promote()
        nested = self.root / "nested-endpoint"
        nested.mkdir()
        before = self.snapshot(self.root)
        for path in (nested, "/" + str(nested)):
            with self.subTest(endpoint=str(path)), self.assertRaises(e.r.Error):
                with mock.patch.object(e.r, "verify_release", side_effect=AssertionError("unexpected release read")):
                    e.export(self.root, path, self.home, self.key, True)
            self.assertEqual(self.snapshot(self.root), before)
        for value in ("/" + str(self.root), "/" + str(self.home)):
            with self.subTest(alias=value), self.assertRaises(e.r.Error):
                e.canonical(value)
        self.assertEqual(e.canonical(self.root), self.root)
        self.assertEqual(e.canonical(self.home), self.home)

    def test_copy_failure_preserves_old_selection_and_cleans_temporary_tree(self):
        self.promote()
        self.export()
        self.promote("fixture-2")
        original = e.copy_file
        count = 0
        def failed(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("injected local copy interruption")
            return original(*args)
        with mock.patch.object(e, "copy_file", side_effect=failed):
            self.unchanged_failure(self.export)

    def test_source_change_during_copy_preserves_old_selection(self):
        self.promote()
        self.export()
        self.promote("fixture-2")
        original = e.copy_file
        changed = False
        def drift(*args):
            nonlocal changed
            original(*args)
            if not changed:
                changed = True
                current = self.root / "stable/current"
                current.unlink()
                current.symlink_to("fixture-1")
        with mock.patch.object(e, "copy_file", side_effect=drift):
            self.unchanged_failure(self.export)

    def test_reused_generation_rechecks_withdrawal_before_selection(self):
        self.promote()
        first = self.export()
        self.promote("fixture-2")
        second = self.export()
        current = self.endpoint / "current"
        current.unlink()
        current.symlink_to(first["selection"])
        original = e.generation_check
        withdrawn = False
        reason = self.inputs / "incident.txt"
        reason.write_text("Synthetic noncooperative withdrawal during generation reuse.\n")
        def drift(directory, plan):
            nonlocal withdrawn
            original(directory, plan)
            if directory.name == second["generation"] and not withdrawn:
                withdrawn = True
                e.r.withdraw(argparse.Namespace(release_id="fixture-2", reason=str(reason)),
                             self.root, self.key, self.env)
        with mock.patch.object(e, "generation_check", side_effect=drift):
            self.unchanged_failure(self.export)
        self.assertTrue(withdrawn)
        self.assertEqual(os.readlink(current), first["selection"])

    def test_reused_generation_final_source_refusal_preserves_first_cause(self):
        self.promote()
        self.export()
        original = e.describe
        calls = 0
        def refused(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise e.r.Error("injected final Source refusal")
            return original(*args)
        before = self.snapshot(self.endpoint)
        with mock.patch.object(e, "describe", side_effect=refused):
            with self.assertRaisesRegex(e.r.Error, "^injected final Source refusal$"):
                self.export()
        self.assertEqual(calls, 2)
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_post_commit_sync_failure_reports_materialized_uncertainty(self):
        self.promote()
        original = e.sync_directory
        def failed(path):
            if path == self.endpoint:
                raise OSError("injected endpoint sync failure")
            original(path)
        with mock.patch.object(e, "sync_directory", side_effect=failed):
            result = self.export()
        self.assertEqual(result["status"], "materialized-local-endpoint")
        self.assertTrue(result["durability_uncertain"])
        self.assertTrue((self.endpoint / "current/release/repo/fixture.db").is_file())

    def test_pointer_commit_failure_retains_old_live_generation(self):
        self.promote()
        first = self.export()
        self.promote("fixture-2")
        with mock.patch.object(e.os, "replace", side_effect=OSError("injected selection interruption")):
            with self.assertRaises(OSError):
                self.export()
        self.assertEqual(os.readlink(self.endpoint / "current"), first["selection"])
        self.assertEqual(e.r.load(self.endpoint / "current/release/release.json")["release_id"], "fixture-1")
        self.assertEqual(len(list((self.endpoint / "generations").iterdir())), 2)
        self.assertFalse(any(p.name.startswith(".") for p in self.endpoint.iterdir()))

    def test_no_release_and_busy_release_lock_refuse(self):
        self.unchanged_failure(self.export)
        self.promote()
        with (self.root / ".release.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.unchanged_failure(self.export)

    def test_existing_generation_tamper_is_not_reused(self):
        self.promote()
        self.export()
        path = self.endpoint / "current/release/repo" / self.archive.name
        path.chmod(0o644)
        path.write_bytes(b"corrupt existing endpoint")
        self.unchanged_failure(self.export)

    def test_cli_defaults_to_plan_and_reports_real_gate_refusal(self):
        self.promote()
        command = [sys.executable, "-B", str(HERE / "export_repository.py"), "--root", str(self.root),
                   "--endpoint", str(self.endpoint), "--gpg-home", str(self.home), "--key", self.key]
        result = subprocess.run(command, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"gate identity mismatch", result.stderr)
        self.assertEqual(list(self.endpoint.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
