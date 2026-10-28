#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused v2 package staging/installed collect journeys; no host installation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('support2_check', ROOT / 'check_package.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def stage(source, target):
    target.mkdir(mode=0o700)
    command = ['/usr/bin/bash', '--noprofile', '--norc', '-c',
               'set -euo pipefail\numask 022\nsource "$1/PKGBUILD"\nsrcdir=$1\npkgdir=$2\npackage',
               'support2-private-stage', str(source), str(target)]
    result = subprocess.run(command, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr.decode())
    C.check_stage(source, target)


def runtime_mounts():
    mounts = ['--ro-bind', '/usr', '/usr']
    for name in ('lib', 'lib64'):
        path = Path('/') / name
        if path.is_symlink():
            mounts += ['--symlink', os.readlink(path), '/' + name]
        elif path.is_dir():
            mounts += ['--ro-bind', str(path), '/' + name]
        elif path.exists():
            raise ValueError('unsupported host library layout')
    return mounts


def sandbox(pkgdir, work, prefix='/stage'):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', *runtime_mounts(),
            '--proc', '/proc', '--dev', '/dev', '--ro-bind', str(pkgdir), prefix,
            '--bind', str(work), '/work', '--chdir', '/work', '--clearenv',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C', '--']


class InstalledCollection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='support2-package-')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.recipe = self.work / 'recipe'
        self.recipe.mkdir()
        for name in ('PKGBUILD', '.SRCINFO', *C.SOURCES):
            shutil.copyfile(ROOT / name, self.recipe / name)
        self.pkgdir = self.work / 'pkgdir'
        stage(self.recipe, self.pkgdir)
        self.inputs = self.work / 'inputs'
        self.inputs.mkdir()
        self.fixtures = json.loads((self.recipe / 'fixtures.json').read_bytes())
        for name in ('doctor', 'session', 'health'):
            (self.inputs / (name + '.json')).write_text(json.dumps(self.fixtures[name], sort_keys=True, indent=2) + '\n')
        self.assertIsNotNone(shutil.which('bwrap'), 'bubblewrap is an explicit check dependency; headless isolation must run')

    def run_cli(self, *args, expected=0, pkgdir=None, prefix='/stage'):
        command = sandbox(pkgdir or self.pkgdir, self.inputs, prefix)
        result = subprocess.run([*command, prefix + '/usr/bin/cachy-asahi-support', *map(str, args)],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, expected, (args, result.stdout, result.stderr))
        return result

    def identity(self, output):
        return ['--release-id', 'synthetic-support-demo', '--release-sha256', 'a' * 64,
                '--source-commit', 'b' * 40, '--output-dir', output]

    def contents(self, path):
        with tarfile.open(path) as archive:
            members = {m.name: archive.extractfile(m).read() for m in archive}
        for marker in (b'PRIVATE', b'/home/', b'192.0.2.19', b'--token=', b'SSID-SECRET'):
            self.assertNotIn(marker, b'\n'.join(members.values()))
        return members

    def test_exact_payload_metadata_and_new_command(self):
        info = C.check_source(self.recipe)
        self.assertEqual(info['pkgver'], ['0.2.0'])
        self.assertEqual(info['checkdepends'], ['bubblewrap'])
        self.assertEqual(len(C.PAYLOAD), 12)
        self.assertEqual(self.run_cli('--version').stdout, b'cachy-asahi-support 0.2.0-1\n')
        self.assertIn(b'output-dir', self.run_cli('collect', '--help').stdout)
        self.assertIn(b'reviewed', self.run_cli('create', '--help').stdout)
        self.assertFalse(list(self.pkgdir.rglob('__pycache__')))

    def test_real_headless_collect_verify_relocation_without_checkout(self):
        snapshot = {str(p.relative_to(self.pkgdir)): p.read_bytes() for p in self.pkgdir.rglob('*') if p.is_file()}
        shutil.rmtree(self.recipe)
        probe = subprocess.run([*sandbox(self.pkgdir, self.inputs), '/usr/bin/python3', '-I', '-B', '-c',
            'import os; assert not os.path.exists("/home"); assert not os.path.exists("/run"); assert not os.path.exists("/stage/PKGBUILD"); print("HEADLESS_CHECKOUT_HIDDEN")'],
            capture_output=True, timeout=10)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.run_cli('collect', *self.identity('/work/case'))
        receipt = json.loads((self.inputs / 'case/collection.json').read_bytes())
        self.assertEqual(receipt['status'], 'CREATED')
        members = self.contents(self.inputs / 'case/share/support-bundle.tar')
        session = json.loads(members['reports/session.json'])
        self.assertGreater(session['coverage'].get('unknown', 0), 0)
        self.assertEqual(set(session['physical_checks'].values()), {'NOT RUN'})
        self.assertFalse(session['session_hints']['wayland_environment_present'])
        self.assertFalse(session['session_hints']['hyprland_environment_present'])
        self.assertNotIn('doctor.private.json', members)
        self.run_cli('verify', '--archive', '/work/case/share/support-bundle.tar', '--sha256', receipt['archive']['sha256'],
                     '--extract-to', '/work/extracted')
        moved = self.work / 'relocated'
        self.pkgdir.rename(moved)
        self.run_cli('collect', *self.identity('/work/relocated-case'), pkgdir=moved, prefix='/relocated')
        other = json.loads((self.inputs / 'relocated-case/collection.json').read_bytes())
        self.run_cli('verify', '--archive', '/work/relocated-case/share/support-bundle.tar', '--sha256', other['archive']['sha256'],
                     '--extract-to', '/work/relocated-extracted', pkgdir=moved, prefix='/relocated')
        self.assertEqual(snapshot, {str(p.relative_to(moved)): p.read_bytes() for p in moved.rglob('*') if p.is_file()})
        self.assertEqual((self.inputs / 'case').stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in (self.inputs / 'case').rglob('*') if p.is_file()))

    def test_unchanged_create_verify_preserves_fixture_failures_and_unknowns(self):
        args = ['create', *self.identity('/work/offline')]
        for name in ('doctor', 'session'):
            args += ['--reviewed-' + name, '/work/' + name + '.json', C.sha(self.inputs / (name + '.json'))]
        result = json.loads(self.run_cli(*args).stdout)
        members = self.contents(self.inputs / 'offline/support-bundle.tar')
        self.assertIn(b'failed', b'\n'.join(members.values()))
        self.assertIn(b'unknown', b'\n'.join(members.values()))
        self.assertIn(b'NOT RUN', b'\n'.join(members.values()))
        self.run_cli('verify', '--archive', '/work/offline/support-bundle.tar', '--sha256', result['sha256'], '--extract-to', '/work/offline-extracted')

    def test_installed_collect_explicit_health_selection(self):
        digest = C.sha(self.inputs / 'health.json')
        self.run_cli('collect', *self.identity('/work/refused'), '--reviewed-health', '/work/health.json', '0' * 64, expected=2)
        self.assertFalse((self.inputs / 'refused').exists())
        self.run_cli('collect', *self.identity('/work/health-case'), '--reviewed-health', '/work/health.json', digest)
        members = self.contents(self.inputs / 'health-case/share/support-bundle.tar')
        self.assertEqual(json.loads(members['reports/health.json'])['arm_security_status'], 'UNKNOWN')

    def test_collector_tamper_refused_before_launch(self):
        path = self.pkgdir / 'usr/lib/cachy-asahi/support/scripts/support/collect_support.py'
        path.write_bytes(path.read_bytes() + b'\n# changed\n')
        self.run_cli('collect', *self.identity('/work/refused'), expected=2)
        self.assertFalse((self.inputs / 'refused').exists())

    def test_new_source_pin_and_payload_refusal(self):
        path = self.recipe / 'collect_support.py'
        path.write_bytes(path.read_bytes() + b'\n# changed\n')
        with self.assertRaises(ValueError):
            C.check_source(self.recipe)
        extra = self.pkgdir / 'usr/bin/foreign'
        extra.write_text('foreign')
        with self.assertRaises(ValueError):
            C.check_stage(self.recipe, self.pkgdir)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--recipe-root', type=Path)
    args, remainder = parser.parse_known_args()
    if args.recipe_root:
        ROOT = args.recipe_root.resolve()
    unittest.main(argv=[sys.argv[0], *remainder], verbosity=2)
