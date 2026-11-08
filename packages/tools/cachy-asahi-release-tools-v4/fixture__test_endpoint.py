#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Real TEST-GPG/filesystem recipient tests; positive hardware admission is modeled."""
import argparse
import hashlib
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


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p = module("endpoint_recipient", HERE / "endpoint.py")
fixture = module("endpoint_export_fixture", HERE.parent / "release/test_export_repository.py")


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.ExportTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixture.ExportTests.tearDownClass.__func__(cls)

    def setUp(self):
        fixture.ExportTests.setUp(self)
        self.keyring = self.inputs / "public.gpg"
        fixture.e.r.run(["gpg", "--batch", "--export", "--output", self.keyring, self.key], env=self.env)

    put = fixture.ExportTests.put
    ref = fixture.ExportTests.ref
    save_spec = fixture.ExportTests.save_spec
    stage = fixture.ExportTests.stage
    promote = fixture.ExportTests.promote
    export = fixture.ExportTests.export
    snapshot = fixture.ExportTests.snapshot
    add_sources = fixture.ExportTests.add_sources

    def generation(self, sources=False):
        if sources:
            self.add_sources()
        self.promote()
        record = self.export()
        self.ident = record["generation"]
        self.gen = self.endpoint / "generations" / self.ident
        return self.gen

    def verify(self, modeled=True, **kw):
        args = dict(generation=self.gen, expected_generation=self.ident, public_keyring=self.keyring, signer=self.key)
        args.update(kw)
        if not modeled:
            return p.verify(**args)
        # Only promotion/hardware gate admission is modeled. All signed release,
        # dependency, database and source-sidecar checks use real implementations.
        with mock.patch.object(p.e.r, "gates_check", side_effect=lambda *a: p.e.r.load(a[-1])):
            return p.verify(**args)

    def rehash(self):
        plan = p.c.decode((self.gen / "export.json").read_bytes())
        files, links = p.e.tree(self.gen)
        files.pop("export.json")
        plan.update(files=files, symlinks=links)
        raw = p.e.encoded(plan)
        self.edit(self.gen / "export.json", raw)
        self.ident = hashlib.sha256(raw).hexdigest()
        return plan

    def edit(self, path, raw):
        # The fixture exporter makes files 0444. Model an owner changing bytes
        # explicitly; owner writes remain allowed by the storage contract.
        if path.exists():
            path.chmod(0o644)
        path.write_bytes(raw)

    def resign(self, path):
        Path(str(path) + ".sig").unlink()
        fixture.e.r.sign(path, self.key, self.env)
        self.rehash()

    def refused(self, **kw):
        before = self.snapshot(self.endpoint)
        key = self.keyring.read_bytes()
        with self.assertRaises((p.c.Error, p.e.r.Error, OSError, ValueError)):
            self.verify(**kw)
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assertEqual(self.keyring.read_bytes(), key)

    def withdraw(self):
        reason = self.inputs / "incident.txt"
        reason.write_text("Synthetic retained withdrawal; no real release.\n")
        fixture.e.r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(reason)), self.root, self.key, self.env)
        record = self.export()
        self.ident = record["generation"]
        self.gen = self.endpoint / "generations" / self.ident

    def test_exported_complete_source_generation_and_copied_location(self):
        self.generation(sources=True)
        before = self.snapshot(self.endpoint)
        key = self.keyring.read_bytes()
        copied = self.base / "downloaded-generation"
        shutil.copytree(self.gen, copied, symlinks=True)
        result = self.verify(generation=copied)
        self.assertEqual(result["selected_release"], "fixture-1")
        self.assertEqual(result["repository_relative_path"], "release/repo/fixture.db")
        self.assertTrue(result["stable_contract_checked"])
        for flag in ("freshness_established", "installation_authorized", "production_accepted", "trust_changed", "state_changed", "network_used"):
            self.assertFalse(result[flag])
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assertEqual(self.keyring.read_bytes(), key)

    def test_real_gate_refuses_synthetic_stable(self):
        self.generation()
        self.refused(modeled=False)

    def test_signed_withdrawal_only_generation_and_cli(self):
        self.generation()
        self.withdraw()
        result = self.verify(modeled=False)
        self.assertEqual(result["withdrawn_releases"], ["fixture-1"])
        self.assertIsNone(result["selected_release"])
        self.assertIsNone(result["repository_relative_path"])
        self.assertFalse(result["stable_contract_checked"])
        before = self.snapshot(self.endpoint)
        completed = subprocess.run([sys.executable, "-B", HERE / "endpoint.py", "--generation", self.gen,
            "--expected-generation", self.ident, "--public-keyring", self.keyring, "--signer", self.key],
            capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(p.c.decode(completed.stdout), result)
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_cli_real_stable_refusal_has_no_success_result(self):
        self.generation()
        completed = subprocess.run([sys.executable, "-B", HERE / "endpoint.py", "--generation", self.gen,
            "--expected-generation", self.ident, "--public-keyring", self.keyring, "--signer", self.key],
            capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(b"endpoint verification error", completed.stderr)

    def test_digest_is_required_and_is_not_a_signer_pin(self):
        self.generation()
        for value in ("f" * 64, "a" * 63, "A" * 64):
            with self.subTest(pin=value):
                self.refused(expected_generation=value)
        plan = p.c.decode((self.gen / "export.json").read_bytes())
        plan["signer"] = "F" * 40
        raw = p.e.encoded(plan)
        self.edit(self.gen / "export.json", raw)
        self.ident = p.c.digest(raw)
        self.refused(signer="F" * 40)

    def test_package_tamper_even_with_rehashed_unsigned_inventory(self):
        self.generation()
        path = self.gen / "release/repo" / self.archive.name
        self.edit(path, path.read_bytes() + b"tampered")
        self.rehash()
        self.refused()

    def test_missing_or_wrong_promotion_signature(self):
        self.generation()
        path = self.gen / "promotion.json.sig"
        original = path.read_bytes()
        path.unlink()
        self.rehash()
        self.refused()
        path.write_bytes(original + b"tampered")
        # Appended signature bytes may parse, so replace with an invalid signature.
        path.write_bytes(b"not a signature\n")
        self.rehash()
        self.refused()

    def test_crossrelease_signed_promotion_refused(self):
        self.generation()
        path = self.gen / "promotion.json"
        value = p.e.r.load(path)
        value["release_id"] = "foreign-release"
        self.edit(path, p.e.encoded(value))
        self.resign(path)
        self.refused()

    def test_source_material_tamper_is_not_hidden_by_inventory(self):
        self.generation(sources=True)
        path = self.gen / "release/evidence/source.tar"
        self.edit(path, b"foreign source bytes\n")
        self.rehash()
        self.refused()

    def test_selected_release_with_signed_withdrawal_refused(self):
        old = self.generation()
        self.withdraw()
        shutil.copytree(old / "release", self.gen / "release", symlinks=True)
        for name in ("promotion.json", "promotion.json.sig"):
            shutil.copyfile(old / name, self.gen / name)
        plan = self.rehash()
        plan["selected_release"] = "fixture-1"
        raw = p.e.encoded(plan)
        self.edit(self.gen / "export.json", raw)
        self.ident = p.c.digest(raw)
        self.refused()

    def test_signed_withdrawal_identity_bound_to_filename(self):
        self.generation()
        self.withdraw()
        path = self.gen / "withdrawals/fixture-1.json"
        value = p.e.r.load(path)
        value["release_id"] = "foreign-release"
        self.edit(path, p.e.encoded(value))
        self.resign(path)
        self.refused()

    def test_unsigned_partial_and_altered_withdrawals_refused(self):
        self.generation()
        self.withdraw()
        path = self.gen / "withdrawals/fixture-1.json.sig"
        raw = path.read_bytes()
        path.unlink()
        self.rehash()
        self.refused(modeled=False)
        path.write_bytes(raw)
        value = self.gen / "withdrawals/fixture-1.json"
        self.edit(value, value.read_bytes() + b" ")
        self.rehash()
        self.refused(modeled=False)

    def test_extra_foreign_member_and_escaping_alias_refused(self):
        self.generation()
        extra = self.gen / "foreign"
        extra.write_text("unrecorded\n")
        self.refused()
        self.rehash()
        self.refused()
        extra.unlink()
        alias = self.gen / "release/repo/fixture.db"
        alias.unlink()
        alias.symlink_to("../../foreign")
        self.refused()

    def test_symlink_paths_traversal_double_slash_and_hardlinks_refused(self):
        self.generation()
        alias = self.base / "alias"
        alias.symlink_to(self.gen, target_is_directory=True)
        for value in (alias, "/" + str(self.gen), str(self.gen) + "/../" + self.gen.name):
            with self.subTest(path=str(value)):
                self.refused(generation=value)
        os.link(self.gen / "export.json", self.base / "linked")
        self.refused()

    def test_writable_generation_and_descendant_refused_before_crypto(self):
        self.generation()
        for path in (self.gen, self.gen / "release", self.gen / "release/repo"):
            mode = path.stat().st_mode & 0o777
            path.chmod(0o777)
            try:
                with mock.patch.object(p.e.r, "verify_signature", side_effect=AssertionError("unexpected crypto")):
                    self.refused()
            finally:
                path.chmod(mode)

    def test_keyring_symlink_hardlink_and_bounds_refused(self):
        self.generation()
        alias = self.inputs / "keyring-alias"
        alias.symlink_to(self.keyring)
        self.refused(public_keyring=alias)
        alias.unlink()
        os.link(self.keyring, alias)
        self.refused()
        alias.unlink()
        with mock.patch.object(p.c, "MAX_KEYRING", 1):
            self.refused()

    def test_private_gpg_environment_cannot_consume_ambient_configuration(self):
        self.generation()
        key = self.keyring.read_bytes()
        calls = []
        original = p.e.r.run
        def observed(argv, *, env=None):
            if argv[0] == "gpg":
                calls.append(env)
                home = Path(env["GNUPGHOME"])
                self.assertEqual(home.joinpath("pubring.gpg").read_bytes(), key)
                self.assertNotEqual(home, self.home)
                self.assertEqual(set(env), {"PATH", "HOME", "GNUPGHOME", "LC_ALL"})
                config = home.joinpath("gpg.conf").read_text()
                self.assertIn("disable-dirmngr", config)
                self.assertIn("no-autostart", config)
                self.assertIn("no-auto-key-import", config)
            return original(argv, env=env)
        with mock.patch.dict(os.environ, {"GNUPGHOME": "/untrusted-home", "GPG_TTY": "foreign", "HOME": "/foreign"}), \
                mock.patch.object(p.e.r, "run", side_effect=observed):
            self.verify()
        self.assertGreaterEqual(len(calls), 5)
        self.assertTrue(all(not Path(env["GNUPGHOME"]).exists() for env in calls))
        self.assertEqual(self.keyring.read_bytes(), key)

    def test_final_recheck_detects_drift_after_signed_checks(self):
        self.generation()
        original = p.e.stable
        def mutate(*args):
            value = original(*args)
            path = self.gen / "promotion.json.sig"
            self.edit(path, path.read_bytes() + b"changed after verification")
            return value
        with mock.patch.object(p.e, "stable", side_effect=mutate):
            with self.assertRaises((p.c.Error, p.e.r.Error)):
                self.verify()

    def test_busy_generation_lock_refused(self):
        self.generation()
        import fcntl
        fd = os.open(self.gen, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.refused()
        finally:
            os.close(fd)

    def test_strict_inventory_unknown_duplicate_boolean_and_float_refused(self):
        self.generation()
        original = (self.gen / "export.json").read_bytes()
        changed = [original.replace(b'"schema_version": 1', b'"schema_version": true'),
                   original.replace(b'"schema_version": 1', b'"schema_version": 1.0'),
                   b'{"unknown":1,\n' + original[1:],
                   b'{"schema_version":1,\n' + original[1:]]
        for raw in changed:
            with self.subTest(raw=raw[:40]):
                self.edit(self.gen / "export.json", raw)
                self.ident = p.c.digest(raw)
                self.refused()


if __name__ == "__main__":
    unittest.main(verbosity=2)
