#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify recovery-producer/recipient interoperability with disposable TEST keys."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p = module("recovery_recipient", HERE / "endpoint_v2.py")
fixture = module("recovery_producer_fixture", HERE.parent / "release/test_recover_repository.py")


class RecoveryEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.Recovery.setUpClass()
        cls.addClassCleanup(fixture.Recovery.tearDownClass)
        producer = cls.producer = fixture.Recovery()
        cls.addClassCleanup(producer.doCleanups)
        producer.setUp()
        producer.pair()
        producer.withdraw("successor")
        producer.sign()
        cls.produced = producer.recover()
        cls.original = producer.endpoint / cls.produced["selection"]
        cls.keyring = producer.inputs / "public.gpg"
        fixture.H.R.run(["gpg", "--batch", "--export", "--output", cls.keyring, producer.key], env=producer.env)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-recovery-recipient-")
        self.addCleanup(temporary.cleanup)
        self.generation = Path(temporary.name) / "offline-copy"
        shutil.copytree(self.original, self.generation, symlinks=True)
        self.ident = self.produced["generation"]
        self.plan = self.generation / p.PLAN
        self.signature = self.generation / p.SIGNATURE

    def verify(self, **kwargs):
        args = dict(generation=self.generation, expected_generation=self.ident,
                    public_keyring=self.keyring, signer=self.producer.key)
        args.update(kwargs)
        # Only the factual gate is modeled. Producer and recipient run real signature,
        # archive, dependency, promotion-binding and withdrawal validation.
        with mock.patch.object(p.v2.R, "gates_check", side_effect=lambda *a: p.v2.R.load(a[-1])):
            return p.verify(**args)

    def replace(self, path, raw):
        path.unlink(missing_ok=True)
        path.write_bytes(raw)

    def rehash(self, **fields):
        manifest = self.generation / "export.json"
        plan = p.c.decode(manifest.read_bytes())
        files, links = p.e.tree(self.generation)
        files.pop("export.json")
        plan.update(files=files, symlinks=links, **fields)
        raw = p.e.encoded(plan)
        self.replace(manifest, raw)
        self.ident = p.e.digest(raw)

    def sign(self, raw):
        self.replace(self.plan, raw)
        self.producer.resign(self.plan)
        self.rehash()

    def refused(self, message, **kwargs):
        snapshot = self.producer.snapshot
        before = snapshot(self.generation), self.keyring.read_bytes()
        with self.assertRaisesRegex((p.c.Error, p.e.r.Error, p.v2.R.Error, p.v2.C.r.Error), message):
            self.verify(**kwargs)
        self.assertEqual((snapshot(self.generation), self.keyring.read_bytes()), before)

    def test_consumes_exact_producer_output_read_only(self):
        snapshot = self.producer.snapshot
        before = snapshot(self.generation), snapshot(self.producer.endpoint), self.keyring.read_bytes()
        with self.assertRaisesRegex(p.c.Error, "unrecognized endpoint member"):
            p.v1.verify(self.generation, self.ident, self.keyring, self.producer.key)
        result = self.verify()
        for field in ("generation", "selected_release", "previous_selection", "authorization_sha256"):
            self.assertEqual(result[field], self.produced[field])
        self.assertEqual(result["withdrawn_releases"], ["successor"])
        self.assertEqual(result["repository_relative_path"], "release/repo/fixture.db")
        self.assertTrue(result["stable_contract_checked"])
        for field in ("freshness_established", "installation_authorized", "production_accepted", "network_used",
                      "trust_changed", "state_changed"):
            self.assertFalse(result[field])
        self.assertEqual((snapshot(self.generation), snapshot(self.producer.endpoint), self.keyring.read_bytes()), before)

    def test_cli_reaches_real_stable_gate_and_refuses_synthetic_target(self):
        before = self.producer.snapshot(self.generation)
        result = subprocess.run([sys.executable, "-I", "-B", HERE / "endpoint_v2.py", "--generation", self.generation,
            "--expected-generation", self.ident, "--public-keyring", self.keyring, "--signer", self.producer.key],
            capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"synthetic fixtures cannot enter stable", result.stderr)
        self.assertEqual(self.producer.snapshot(self.generation), before)

    def test_generation_and_signer_pins_are_independent(self):
        self.refused("independently supplied identity", expected_generation="0" * 64)
        other = "F" * 40
        self.rehash(signer=other)
        self.refused("pinned primary", signer=other)

    def test_partial_and_absent_plan_refused_with_rehashed_inventory(self):
        signature = self.signature.read_bytes()
        self.signature.unlink()
        self.rehash()
        self.refused("complete signed plan")
        self.signature.write_bytes(signature)
        self.plan.unlink()
        self.rehash()
        self.refused("complete signed plan")
        self.signature.unlink()
        self.rehash()
        self.refused("complete signed plan")

    def test_signature_must_verify_exact_bytes_once(self):
        original = self.plan.read_bytes()
        signature = self.signature.read_bytes()
        self.replace(self.plan, original + b"\n")
        self.rehash()
        self.refused("GPG rejected detached signature")
        self.replace(self.plan, original)
        self.replace(self.signature, signature + signature)
        self.rehash()
        self.refused("one complete detached signature")

    def test_valid_signature_does_not_excuse_incomplete_or_noncanonical_plan(self):
        original = p.c.decode(self.plan.read_bytes())
        self.sign(p.e.encoded(original) + b"\n")
        self.refused("invalid canonical recovery authorization")
        del original["current_release_sha256"]
        self.sign(p.e.encoded(original))
        self.refused("invalid canonical recovery authorization")

    def test_signed_plan_must_match_every_selected_binding(self):
        original = p.c.decode(self.plan.read_bytes())
        for name, value in {"target_release_id": "foreign", "target_release_sha256": "0" * 64,
                            "target_promotion_sha256": "0" * 64, "base_sha256": "0" * 64,
                            "withdrawal_files": {}}.items():
            with self.subTest(field=name):
                self.sign(p.e.encoded(dict(original, **{name: value})))
                self.refused("differs from selected release, promotion, base or withdrawals")

    def test_signed_plan_requires_a_distinct_canonical_previous_selection(self):
        original = p.c.decode(self.plan.read_bytes())
        for name, value in {"expected_current": "../current", "current_release_id": original["target_release_id"],
                            "current_release_sha256": original["target_release_sha256"]}.items():
            with self.subTest(field=name):
                self.sign(p.e.encoded(dict(original, **{name: value})))
                self.refused("invalid expected-current recovery lineage")

    def test_final_inventory_check_refuses_drift_after_plan_verification(self):
        def drift(*args):
            self.replace(self.plan, self.plan.read_bytes() + b"\n")
            return p.v2.R.load(args[-1])

        with mock.patch.object(p.v2.R, "gates_check", side_effect=drift):
            with self.assertRaisesRegex(p.e.r.Error, "generation differs from its complete export plan"):
                p.verify(self.generation, self.ident, self.keyring, self.producer.key)

    def test_lineage_must_reach_the_actual_archive_bytes(self):
        # The producer fixture can make a signed, old-verifier-valid release whose
        # archive bytes differ from the digest in the package record and index.
        root = self.generation.parent / "lineage-fixture"
        release = root / "stable/previous"
        shutil.copytree(self.generation / "release", release, symlinks=True)
        promotion = root / "promotions/previous.json"
        promotion.parent.mkdir()
        for suffix in ("", ".sig"):
            shutil.copyfile(self.generation / ("promotion.json" + suffix), promotion.with_name(promotion.name + suffix))
        for path in release.rglob("*"):
            if path.is_file() and not path.is_symlink():
                path.chmod(0o644)
        with mock.patch.object(self.producer, "root", root):
            release_pin, promotion_pin = self.producer.mismatched_lineage("previous")
        shutil.rmtree(self.generation / "release")
        shutil.copytree(release, self.generation / "release", symlinks=True)
        for suffix in ("", ".sig"):
            self.replace(self.generation / ("promotion.json" + suffix), promotion.with_name(promotion.name + suffix).read_bytes())
        plan = dict(p.c.decode(self.plan.read_bytes()), target_release_sha256=release_pin, target_promotion_sha256=promotion_pin)
        self.sign(p.e.encoded(plan))
        self.refused("artifact digest differs from signed file map")


if __name__ == "__main__":
    unittest.main(verbosity=2)
