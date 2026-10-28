#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New finite v2 export/relocation controls with the unchanged v1 caller held."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve()
ROOT = next(p for p in HERE.parents if (p / 'scripts/release/recipe_source_delivery.py').is_file())
PROPOSED = next((p for p in HERE.parents if (p / 'packages/tools/cachy-asahi-support2/PKGBUILD').is_file()), ROOT)
V1 = ROOT if (ROOT / 'scripts/release/support_source_delivery_v1.py').is_file() else ROOT / 'artifacts/development/package-tools-and-capacity-root-integration-20261028-v3/canonical-ready'
REVISION = 'e7d2a0bb1f3fddd8637fb1c478de462efdccc686'
V1_ADAPTER_SHA256 = '40bc85e419325325af8fabeccef64e4a6937f010976653fcde33b0cb29a8c9c1'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


A = module('support_delivery_v2_test', HERE.with_name('support_source_delivery_v2.py'))


class Delivery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='support2-delivery-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.recipe = PROPOSED / 'packages/tools/cachy-asahi-support2'
        self.d = A.transport()

    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE.with_name('support_source_delivery_v2.py')), *map(str, args)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, (result.stdout, result.stderr))
        return json.loads(result.stdout) if result.stdout else None

    def test_real_cli_repeat_unpack_relocate_check_and_source_only_status(self):
        first = self.cli('pack', '--recipe', self.recipe, '--source-revision', REVISION, '--output', self.work / 'one')
        second = self.cli('pack', '--recipe', self.recipe, '--source-revision', REVISION, '--output', self.work / 'two')
        self.assertEqual(first, second)
        raw = (self.work / 'one/source.tar').read_bytes()
        self.assertEqual(raw, (self.work / 'two/source.tar').read_bytes())
        saved, bodies = self.d.unpacked(raw, first['bundle_sha256'])
        self.assertEqual(saved['package']['version'], '0.2.0-1')
        self.assertEqual(saved['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
        self.assertIsNone(saved['archive_binding'])
        self.assertTrue(saved['stage_is_not_installation'])
        for field in ('native_build', 'alpm_installation', 'physical_m2'):
            self.assertEqual(saved[field], 'NOT_RUN')
        self.assertEqual(saved['release'], 'NOT_ADMITTED')
        self.assertFalse((self.work / 'one/source-delivery.json').exists())
        target = self.work / 'relocated-sources'
        result = self.cli('unpack', '--bundle', self.work / 'one/source.tar', '--sha256', first['bundle_sha256'], '--output', target)
        self.assertEqual(result['status'], 'UNPACKED_SOURCE_ONLY')
        self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, bodies)
        checked = subprocess.run([sys.executable, '-I', '-B', str(target / 'check_package.py'), '--recipe-root', str(target)],
                                 cwd=self.work, capture_output=True, timeout=15)
        self.assertEqual(checked.returncode, 0, (checked.stdout, checked.stderr))
        self.assertFalse(list(target.rglob('__pycache__')))

    def test_every_recipe_and_source_byte_tamper_refuses_export(self):
        bodies, _ = self.d.source_set(A.NAME, lambda key: self.d.s.local_read(self.recipe, key, self.d.MAX_FILE))
        target = self.work / 'changed-recipe'
        self.d.write_fresh(target, bodies)
        for name, raw in bodies.items():
            with self.subTest(source=name):
                (target / name).write_bytes(raw + b'\nchanged\n')
                with self.assertRaises(self.d.s.Error):
                    self.d.pack(target, A.NAME, REVISION, self.work / 'refused')
                self.assertFalse((self.work / 'refused').exists())
                (target / name).write_bytes(raw)

    def test_real_cli_wrong_external_digest_refuses_without_output(self):
        first = self.cli('pack', '--recipe', self.recipe, '--source-revision', REVISION, '--output', self.work / 'packed')
        self.assertNotEqual(first['bundle_sha256'], '0' * 64)
        self.assertIsNone(self.cli('unpack', '--bundle', self.work / 'packed/source.tar', '--sha256', '0' * 64,
                                  '--output', self.work / 'refused', expected=2))
        self.assertFalse((self.work / 'refused').exists())

    def test_v1_caller_still_exports_exact_v1_and_reciprocal_version_refusal(self):
        adapter = V1 / 'scripts/release/support_source_delivery_v1.py'
        self.assertEqual(hashlib.sha256(adapter.read_bytes()).hexdigest(), V1_ADAPTER_SHA256)
        old = module('support_v1_held_caller', adapter)
        previous = old.transport()
        called = subprocess.run([sys.executable, '-I', '-B', str(adapter), 'pack', '--recipe',
            str(V1 / 'packages/tools/cachy-asahi-support'), '--source-revision', REVISION,
            '--output', str(self.work / 'v1')], capture_output=True, timeout=15)
        self.assertEqual(called.returncode, 0, (called.stdout, called.stderr))
        result = json.loads(called.stdout)
        saved, _ = previous.unpacked((self.work / 'v1/source.tar').read_bytes(), result['bundle_sha256'])
        self.assertEqual(saved['package']['version'], '0.1.0-1')
        self.assertEqual(saved['recipe_sha256'], old.RECIPE_SHA256)
        self.assertEqual(saved['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
        with self.assertRaises(previous.s.Error):
            previous.pack(self.recipe, A.NAME, REVISION, self.work / 'v1-refuses-v2')
        with self.assertRaises(self.d.s.Error):
            self.d.pack(V1 / 'packages/tools/cachy-asahi-support', A.NAME, REVISION, self.work / 'v2-refuses-v1')
        for name, checksum in A.HELPERS.items():
            self.assertEqual(hashlib.sha256((ROOT / 'scripts/release' / name).read_bytes()).hexdigest(), checksum)
        original = self.d.module('original_v2_isolation_control', ROOT / 'scripts/release/recipe_source_delivery.py')
        self.assertNotIn(A.NAME, original.PROFILES)
        self.assertEqual(len(original.PROFILES), 11)


if __name__ == '__main__':
    unittest.main(verbosity=2)
