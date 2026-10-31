#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact finite profile; unchanged legacy helper bytes and source-only receipts."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve()
ROOT = next(p for p in HERE.parents if (p / 'scripts/release/recipe_source_delivery.py').is_file())
PROPOSED = next((p for p in HERE.parents if (p / 'packages/tools/cachy-asahi-support/PKGBUILD').is_file()), ROOT)
SPEC = importlib.util.spec_from_file_location('support_delivery_v1_test', HERE.with_name('support_source_delivery_v1.py'))
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
REVISION = 'a0bbaee4da1c588f33375b6d4cda372d89a85f77'


class Delivery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='support-delivery-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.recipe = PROPOSED / 'packages/tools/cachy-asahi-support'
        self.d = A.transport()

    def test_exact_sources_repeat_relocation_and_unbound_status(self):
        one, two = self.work / 'one', self.work / 'two'
        first = self.d.pack(self.recipe, A.NAME, REVISION, one)
        self.assertEqual(first, self.d.pack(self.recipe, A.NAME, REVISION, two))
        self.assertEqual((one / 'source.tar').read_bytes(), (two / 'source.tar').read_bytes())
        saved, bodies = self.d.unpacked((one / 'source.tar').read_bytes(), first['bundle_sha256'])
        self.assertEqual(saved['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
        self.assertIsNone(saved['archive_binding'])
        self.assertEqual(saved['native_build'], 'NOT_RUN')
        self.assertFalse((one / 'source-delivery.json').exists())
        target = self.work / 'relocated'
        self.d.write_fresh(target, bodies)
        check = subprocess.run([sys.executable, '-I', '-B', str(target / 'check_package.py'), '--recipe-root', str(target)], capture_output=True, timeout=15)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, bodies)

    def test_exact_recipe_pair_and_every_source_tamper_refused(self):
        bodies, _ = self.d.source_set(A.NAME, lambda key: self.d.s.local_read(self.recipe, key, self.d.MAX_FILE))
        target = self.work / 'recipe'
        self.d.write_fresh(target, bodies)
        for name, raw in bodies.items():
            (target / name).write_bytes(raw + b'\nchanged\n')
            with self.assertRaises(self.d.s.Error): self.d.pack(target, A.NAME, REVISION, self.work / 'refused')
            self.assertFalse((self.work / 'refused').exists())
            (target / name).write_bytes(raw)

    def test_old_profiles_and_helper_bytes_unchanged(self):
        for name, checksum in A.HELPERS.items():
            self.assertEqual(self.d.s.digest((ROOT / 'scripts/release' / name).read_bytes()), checksum)
        original = self.d.module('original_delivery_control', ROOT / 'scripts/release/recipe_source_delivery.py')
        self.assertNotIn(A.NAME, original.PROFILES)
        self.assertEqual(len(original.PROFILES), 11)
        with self.assertRaises(original.s.Error): original.profile(A.NAME)

    def test_cli_pack_unpack_and_wrong_hash_refusal(self):
        output = self.work / 'packed'
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(A.main(['pack', '--recipe', str(self.recipe), '--source-revision', REVISION, '--output', str(output)]), 0)
        result = json.loads(out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(A.main(['unpack', '--bundle', str(output / 'source.tar'), '--sha256', result['bundle_sha256'], '--output', str(self.work / 'unpacked')]), 0)
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(A.main(['unpack', '--bundle', str(output / 'source.tar'), '--sha256', '0' * 64, '--output', str(self.work / 'refused')]), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertFalse((self.work / 'refused').exists())


if __name__ == '__main__':
    unittest.main()
