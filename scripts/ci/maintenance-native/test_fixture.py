#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Host controls: stage the exact recipe and run fresh real signed TEST controls."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).absolute().parent
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--package-root', type=Path)
options, unittest_args = parser.parse_known_args()
DEFAULT = next((p / 'packages/tools/cachy-asahi-maintenance' for p in HERE.parents
                if (p / 'packages/tools/cachy-asahi-maintenance/PKGBUILD').is_file()), None)
PACKAGE = options.package_root or DEFAULT
spec = importlib.util.spec_from_file_location('maintenance_fixture_test_subject', HERE / 'cli_fixture.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class FixtureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if PACKAGE is None:
            raise ValueError('--package-root is required outside an emitted source context')
        cls.temp = tempfile.TemporaryDirectory(prefix='maintenance-fresh-signed-fixture-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.stage = cls.root / 'stage'
        subprocess.run(['/bin/bash', '-c',
            'set -eu; source "$1/PKGBUILD"; srcdir="$1"; pkgdir="$2"; package',
            'stage-maintenance-fixture', str(PACKAGE.absolute()), str(cls.stage)],
            check=True, capture_output=True, timeout=20)
        cls.cli = cls.stage / 'usr/bin/cachy-asahi-maintenance'

    def test_actual_signed_staged_cli_all_observations_and_controls(self):
        work = self.root / 'actual-signed-work'
        work.mkdir(mode=0o700)
        report = self.root / 'actual-signed-proof.json'
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'cli_fixture.py'),
            '--cli', str(self.cli), '--work', str(work), '--report', str(report)], cwd='/tmp',
            capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        value = json.loads(result.stdout)
        self.assertEqual(value, json.loads(report.read_bytes()))
        self.assertEqual(value['status'], 'PASS_MAINTENANCE_INSTALLED_SIGNED_TEST_CONTROLS')
        self.assertEqual(tuple(row['case'] for row in value['controls']), f.LABELS)
        self.assertEqual([row['returncode'] for row in value['controls']], [0] * 6 + [2] * 6)
        self.assertEqual(value['signature_verification']['fingerprint'], value['signer'])
        self.assertFalse(value['fake_signature_time_used'])
        self.assertLessEqual(value['started_epoch'], value['key_created_epoch'])
        self.assertLessEqual(value['key_created_epoch'], value['evaluation_epoch'])
        self.assertLessEqual(value['evaluation_epoch'], value['finished_epoch'])
        for field in ('all_five_observations_replayed', 'input_data_preserved', 'public_home_preserved',
                      'installed_payload_preserved', 'signing_secret_removed'):
            self.assertIs(value[field], True)
        self.assertEqual(value['uid'], os.getuid())
        self.assertEqual(value['architecture'], os.uname().machine)
        self.assertEqual(value['page_size'], os.sysconf('SC_PAGE_SIZE'))
        self.assertLessEqual(len(result.stdout), 128 * 1024)
        self.assertGreater(len(value['public_evidence']), 40)
        self.assertLessEqual(sum(row['bytes'] for row in value['public_evidence'].values()), 16 * 1024**2)
        for name, row in value['public_evidence'].items():
            path = work / name
            self.assertFalse(path.is_symlink())
            self.assertNotIn('TEST-signing-secret', path.parts)
            self.assertEqual(f.pin(path.read_bytes()), row)
        self.assertFalse((work / 'TEST-signing-secret').exists())
        self.assertFalse(list(self.stage.rglob('__pycache__')))

    def test_nonempty_work_refused_before_any_signing(self):
        work = self.root / 'nonempty'
        work.mkdir(mode=0o700)
        (work / 'sentinel').write_bytes(b'unchanged')
        with self.assertRaisesRegex(ValueError, 'owned empty 0700'):
            f.run(self.cli, work)
        self.assertEqual(list(work.iterdir()), [work / 'sentinel'])
        self.assertEqual((work / 'sentinel').read_bytes(), b'unchanged')

    def test_public_work_permissions_refused(self):
        work = self.root / 'public-work'
        work.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'owned empty 0700'):
            f.run(self.cli, work)
        self.assertEqual(list(work.iterdir()), [])

    def test_symlink_and_relative_paths_refused(self):
        alias = self.root / 'cli-alias'
        alias.symlink_to(self.cli)
        with self.assertRaisesRegex(ValueError, 'ordinary absolute'):
            f.packaged(alias)
        with self.assertRaisesRegex(ValueError, 'ordinary absolute'):
            f.packaged(Path('usr/bin/cachy-asahi-maintenance'))

    def test_mutated_private_source_refused_before_import(self):
        path = self.stage / 'usr/lib/cachy-asahi/maintenance/scripts/maintenance/health.py'
        raw = path.read_bytes()
        try:
            path.write_bytes(raw + b'\nraise AssertionError("unreviewed health executed")\n')
            with self.assertRaisesRegex(ValueError, 'provenance differs'):
                f.packaged(self.cli)
        finally:
            path.write_bytes(raw)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *unittest_args], verbosity=2)
