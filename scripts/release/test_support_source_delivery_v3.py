#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise exact support3 source export and the retained support2 route."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parents[1] / 'packages/tools'
V3 = HERE / 'support_source_delivery_v3.py'
RECIPE = TOOLS / 'cachy-asahi-support3'
PRIOR_RECIPE = TOOLS / 'cachy-asahi-support2'
FIXTURE_REVISION = 'a' * 40


class Delivery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='support3-delivery-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)

    def cli(self, adapter, *args, expected=0):
        result = subprocess.run([sys.executable, '-I', '-B', str(adapter), *map(str, args)], cwd=self.work,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, (result.stdout, result.stderr))
        if expected:
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'Traceback', result.stderr)
            return None
        return json.loads(result.stdout)

    def pack(self, adapter, recipe, output, expected=0):
        return self.cli(adapter, 'pack', '--recipe', recipe, '--source-revision', FIXTURE_REVISION,
                        '--output', output, expected=expected)

    def unpack(self, adapter, packed, digest, output, expected=0):
        return self.cli(adapter, 'unpack', '--bundle', packed / 'source.tar', '--sha256', digest,
                        '--output', output, expected=expected)

    def test_reproducible_export_and_relocated_check(self):
        first, second = self.work / 'first', self.work / 'second'
        result = self.pack(V3, RECIPE, first)
        self.assertEqual(result, self.pack(V3, RECIPE, second))
        self.assertEqual((first / 'source.tar').read_bytes(), (second / 'source.tar').read_bytes())
        saved = json.loads((first / 'bundle.json').read_bytes())
        self.assertEqual(saved['package']['version'], '0.2.0-2')
        self.assertEqual(saved['archive_status'], 'UNBOUND_NO_ARCHIVE_SUPPLIED')
        self.assertIsNone(saved['archive_binding'])
        self.assertFalse((first / 'source-delivery.json').exists())
        self.assertEqual(saved['native_build'], 'NOT_RUN')
        self.assertEqual(saved['alpm_installation'], 'NOT_RUN')
        self.assertEqual(saved['release'], 'NOT_ADMITTED')
        relocated = self.work / 'relocated'
        self.assertEqual(self.unpack(V3, first, result['bundle_sha256'], relocated)['status'], 'UNPACKED_SOURCE_ONLY')
        self.assertEqual({p.name: p.read_bytes() for p in relocated.iterdir()},
                         {name: (RECIPE / name).read_bytes() for name in saved['files']})
        checked = subprocess.run([sys.executable, '-I', '-B', str(relocated / 'check_package.py')],
                                 cwd=self.work, capture_output=True, timeout=15)
        self.assertEqual(checked.returncode, 0, (checked.stdout, checked.stderr))

    def test_retained_v2_export_and_reciprocal_refusals(self):
        release = self.work / 'historical/scripts/release'
        release.mkdir(parents=True)
        v2 = release / 'support_source_delivery_v2.py'
        shutil.copyfile(HERE / v2.name, v2)
        for name in ('recipe_source_delivery.py', 'source_delivery.py'):
            shutil.copyfile(TOOLS / 'cachy-asahi-release-tools' / name, release / name)
        old, new = self.work / 'old', self.work / 'new'
        old_result = self.pack(v2, PRIOR_RECIPE, old)
        new_result = self.pack(V3, RECIPE, new)
        self.assertEqual(old_result['package']['version'], '0.2.0-1')
        self.assertEqual(self.unpack(v2, old, old_result['bundle_sha256'], self.work / 'old-sources')['status'],
                         'UNPACKED_SOURCE_ONLY')
        rejected = self.work / 'rejected'
        self.pack(v2, RECIPE, rejected, expected=2)
        self.pack(V3, PRIOR_RECIPE, rejected, expected=2)
        self.unpack(v2, new, new_result['bundle_sha256'], rejected, expected=2)
        self.unpack(V3, old, old_result['bundle_sha256'], rejected, expected=2)
        self.assertFalse(rejected.exists())

    def test_source_and_external_digest_refusals(self):
        packed = self.work / 'packed'
        result = self.pack(V3, RECIPE, packed)
        changed = self.work / 'changed'
        self.unpack(V3, packed, result['bundle_sha256'], changed)
        path = changed / 'collect_support.py'
        path.write_bytes(path.read_bytes() + b'\n# changed fixture\n')
        rejected = self.work / 'rejected'
        self.pack(V3, changed, rejected, expected=2)
        self.assertFalse(rejected.exists())
        self.unpack(V3, packed, '0' * 64, rejected, expected=2)
        self.assertFalse(rejected.exists())

    def test_helper_pin_refuses_before_export(self):
        adapter = self.work / V3.name
        shutil.copyfile(V3, adapter)
        for name in ('recipe_source_delivery.py', 'source_delivery.py'):
            shutil.copyfile(HERE / name, self.work / name)
        changed = self.work / 'source_delivery.py'
        changed.write_bytes(changed.read_bytes() + b'\n# changed fixture\n')
        rejected = self.work / 'rejected'
        self.pack(adapter, RECIPE, rejected, expected=2)
        self.assertFalse(rejected.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
