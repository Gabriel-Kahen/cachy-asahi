#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real private package() staging and offline installed-prefix CLI checks."""
import argparse
import copy
import hashlib
import importlib.util
import io
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
SPEC = importlib.util.spec_from_file_location('support_package_check', ROOT / 'check_package.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def stage(source, target):
    target.mkdir(mode=0o700)
    command = ['/usr/bin/bash', '--noprofile', '--norc', '-c',
               'set -euo pipefail\numask 022\nsource "$1/PKGBUILD"\nsrcdir=$1\npkgdir=$2\npackage',
               'support-private-stage', str(source), str(target)]
    result = subprocess.run(command, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr.decode())
    C.check_stage(source, target)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def runtime_mounts(host=Path('/')):
    """Preserve the host's usr/lib layout; never invent loader aliases."""
    if not (host / 'usr/bin/python3').is_file():
        raise ValueError('the launcher requires an available /usr/bin/python3')
    mounts = ['--ro-bind', str(host / 'usr'), '/usr']
    for name in ('lib', 'lib64'):
        path = host / name
        if path.is_symlink():
            mounts += ['--symlink', os.readlink(path), '/' + name]
        elif path.is_dir():
            mounts += ['--ro-bind', str(path), '/' + name]
        elif path.exists():
            raise ValueError('unsupported host library path')
    return mounts


def sandbox_command(pkgdir, work, prefix='/stage'):
    return ['bwrap', '--unshare-all', '--die-with-parent', *runtime_mounts(),
            '--proc', '/proc', '--dev', '/dev', '--ro-bind', str(pkgdir), prefix,
            '--bind', str(work), '/work', '--chdir', '/work',
            '--setenv', 'PYTHONPATH', '/home/poison', '--']


class Package(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='support-package-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / 'recipe'
        self.source.mkdir()
        # Finite declared inputs only; makepkg's root may contain FIFO/log/src/pkg entries.
        for name in ('PKGBUILD', '.SRCINFO', *C.SOURCES):
            shutil.copyfile(ROOT / name, self.source / name)
        self.pkgdir = self.work / 'pkgdir'
        stage(self.source, self.pkgdir)
        self.command = self.pkgdir / 'usr/bin/cachy-asahi-support'
        self.fixtures = json.loads((self.source / 'fixtures.json').read_bytes())
        self.inputs = self.work / 'inputs'
        self.inputs.mkdir()
        for name, value in self.fixtures.items():
            (self.inputs / (name + '.json')).write_bytes(encoded(value))

    def run_cli(self, *args, expected=0, command=None, cwd=None):
        result = subprocess.run([str(command or self.command), *map(str, args)], cwd=cwd or self.work,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONPATH': '/nonexistent/poison', 'PYTHONSTARTUP': '/nonexistent/poison'}, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, (args, result.stdout, result.stderr))
        return json.loads(result.stdout) if result.stdout.startswith(b'{') else result.stdout

    def create_args(self, output, inputs=None):
        args = ['create', '--release-id', 'synthetic-support-demo', '--release-sha256', 'a' * 64, '--source-commit', 'b' * 40, '--output-dir', output]
        for name in ('session', 'doctor', 'doctor-before', 'doctor-after', 'doctor-comparison', 'health'):
            path = (inputs or self.inputs) / (name + '.json')
            args += ['--reviewed-' + name, path, C.sha(self.inputs / path.name)]
        return args

    def test_source_recipe_and_exact_staged_payload(self):
        info = C.check_source(self.source)
        self.assertEqual(info['depends'], ['python>=3.11'])
        self.assertEqual(len(C.PAYLOAD), 10)
        self.assertEqual(self.run_cli('--version'), b'cachy-asahi-support 0.1.0-1\n')
        self.assertIn(b'reviewed', self.run_cli('create', '--help'))
        self.assertFalse(list(self.pkgdir.rglob('__pycache__')))

    def test_create_repeat_verify_extract_relocate_without_recipe(self):
        before = {str(p.relative_to(self.pkgdir)): p.read_bytes() for p in self.pkgdir.rglob('*') if p.is_file()}
        shutil.rmtree(self.source)  # installed command cannot fall back to its recipe source.
        first = self.run_cli(*self.create_args(self.work / 'first'))
        second = self.run_cli(*self.create_args(self.work / 'second'))
        self.assertEqual(first, second)
        archive = self.work / 'first/support-bundle.tar'
        self.assertEqual(archive.read_bytes(), (self.work / 'second/support-bundle.tar').read_bytes())
        self.run_cli('verify', '--archive', archive, '--sha256', first['sha256'], '--extract-to', self.work / 'extracted')
        moved = self.work / 'relocated-prefix'
        self.pkgdir.rename(moved)
        self.run_cli('verify', '--archive', archive, '--sha256', first['sha256'], '--extract-to', self.work / 'relocated-extraction', command=moved / 'usr/bin/cachy-asahi-support')
        self.assertEqual(before, {str(p.relative_to(moved)): p.read_bytes() for p in moved.rglob('*') if p.is_file()})
        with tarfile.open(archive) as source:
            members = {m.name: source.extractfile(m).read() for m in source}
        self.assertEqual(members, {str(p.relative_to(self.work / 'extracted')): p.read_bytes() for p in (self.work / 'extracted').rglob('*') if p.is_file()})
        for marker in (b'PRIVATE', b'/home/', b'192.0.2.19', b'--token=', b'SSID-SECRET'):
            self.assertNotIn(marker, b'\n'.join(members.values()))
        self.assertEqual(json.loads(members['reports/session.json'])['checks']['user/pipewire.service']['value']['ActiveState'], 'failed')

    def test_runtime_tamper_missing_and_symlink_refused(self):
        for name in ('support_bundle.py', 'doctor.py', 'session_probe.py'):
            relative = next(path for path, row in C.PAYLOAD.items() if row['source'] == name)
            path = self.pkgdir / relative
            raw = path.read_bytes()
            for kind in ('tamper', 'missing', 'symlink'):
                path.unlink()
                if kind == 'tamper': path.write_bytes(raw + b'\n')
                elif kind == 'symlink': path.symlink_to(self.source / name)
                self.run_cli('--version', expected=2)
                if path.is_symlink() or path.exists(): path.unlink()
                path.write_bytes(raw)

    def test_pins_metadata_and_source_tamper_refused(self):
        for name in ('PKGBUILD', '.SRCINFO', *C.SOURCES):
            path = self.source / name
            raw = path.read_bytes()
            path.write_bytes(raw + b'\nchanged\n')
            with self.assertRaises((ValueError, SyntaxError)): C.check_source(self.source)
            path.write_bytes(raw)
        # Extra build-context special files are ignored, never traversed or copied.
        os.mkfifo(self.source / 'makepkg.logpipe')
        (self.source / 'src').mkdir()
        C.check_source(self.source)

    def test_stage_foreign_file_mode_and_symlink_refused(self):
        foreign = self.pkgdir / 'usr/bin/foreign'
        foreign.write_bytes(b'foreign')
        with self.assertRaises(ValueError): C.check_stage(self.source, self.pkgdir)
        foreign.unlink()
        self.command.chmod(0o644)
        with self.assertRaises(ValueError): C.check_stage(self.source, self.pkgdir)
        self.command.chmod(0o755)
        target = self.pkgdir / 'usr/share/doc/cachy-asahi-support/README.md'
        target.unlink()
        target.symlink_to(self.source / 'README.md')
        with self.assertRaises(ValueError): C.check_stage(self.source, self.pkgdir)

    def test_offline_refusals_create_no_output(self):
        path = self.inputs / 'health.json'
        path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        self.run_cli(*self.create_args(self.work / 'invalid'), expected=2)
        self.assertFalse((self.work / 'invalid').exists())
        other = self.work / 'archive.tar'
        other.write_bytes(b'not a tar')
        self.run_cli('verify', '--archive', other, '--sha256', C.sha(other), '--extract-to', self.work / 'invalid-extract', expected=2)
        self.assertFalse((self.work / 'invalid-extract').exists())

    def test_removal_of_owned_payload_preserves_reports_and_other_files(self):
        result = self.run_cli(*self.create_args(self.work / 'user-report'))
        foreign = self.pkgdir / 'usr/bin/user-owned'
        foreign.write_bytes(b'preserve')
        for name in C.PAYLOAD: (self.pkgdir / name).unlink()
        self.assertEqual(foreign.read_bytes(), b'preserve')
        self.assertEqual(C.sha(self.work / 'user-report/support-bundle.tar'), result['sha256'])

    def test_real_staged_cli_with_source_checkout_hidden_and_network_unshared(self):
        self.assertIsNotNone(shutil.which('bwrap'), 'bubblewrap is required; hidden-source isolation must execute')
        # Data-only path controls represent Arch and Noble, not a Noble execution.
        layouts = [('arch-merged', 'usr/lib', 'usr/lib'),
                   ('noble-merged', 'usr/lib', 'usr/lib64'),
                   ('noble-absolute-links', '/usr/lib', '/usr/lib64'),
                   ('noble-unmerged-multiarch', None, None),
                   ('optional-lib64-absent', 'usr/lib', False)]
        for label, lib, lib64 in layouts:
            with self.subTest(layout=label):
                host = self.work / label
                (host / 'usr/bin').mkdir(parents=True)
                (host / 'usr/lib/x86_64-linux-gnu').mkdir(parents=True)
                (host / 'usr/lib64').mkdir()
                (host / 'usr/bin/python3.12').write_bytes(b'PATH FIXTURE; not executable Python')
                (host / 'usr/bin/python3').symlink_to('python3.12')
                expected = ['--ro-bind', str(host / 'usr'), '/usr']
                for name, target in (('lib', lib), ('lib64', lib64)):
                    if target is False: continue
                    if target is None:
                        (host / name).mkdir()
                        expected += ['--ro-bind', str(host / name), '/' + name]
                    else:
                        (host / name).symlink_to(target)
                        expected += ['--symlink', target, '/' + name]
                # Noble's loader target lives in a multiarch directory, not usr/lib's root.
                if label.startswith('noble'):
                    library = host / ('lib' if lib is None else 'usr/lib') / 'x86_64-linux-gnu'
                    library.mkdir(exist_ok=True)
                    (library / 'ld-linux-x86-64.so.2').write_bytes(b'PATH FIXTURE; not an ELF loader')
                    loader = host / ('lib64' if lib64 is None else 'usr/lib64') / 'ld-linux-x86-64.so.2'
                    loader.symlink_to('/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')
                self.assertFalse((host / 'usr/bin/python').exists())
                self.assertEqual(runtime_mounts(host), expected)
        command = sandbox_command(self.pkgdir, self.inputs)
        probe = subprocess.run([*command, '/usr/bin/python3', '-I', '-B', '-c',
            'import os; assert not os.path.exists("/home"); assert not os.path.exists("/stage/PKGBUILD"); print("CHECKOUT_HIDDEN")'], capture_output=True, timeout=10)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        args = self.create_args('/work/hidden-output', Path('/work'))
        result = subprocess.run([*command, '/stage/usr/bin/cachy-asahi-support', *map(str, args)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        checksum = json.loads(result.stdout)['sha256']
        verified = subprocess.run([*command, '/stage/usr/bin/cachy-asahi-support', 'verify', '--archive', '/work/hidden-output/support-bundle.tar',
            '--sha256', checksum, '--extract-to', '/work/hidden-extraction'], capture_output=True, timeout=15)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertTrue((self.inputs / 'hidden-extraction/inventory.json').is_file())
        moved = self.work / 'hidden-relocated-prefix'
        self.pkgdir.rename(moved)
        command = sandbox_command(moved, self.inputs, '/relocated')
        relocated = subprocess.run([*command, '/relocated/usr/bin/cachy-asahi-support', 'verify',
            '--archive', '/work/hidden-output/support-bundle.tar', '--sha256', checksum,
            '--extract-to', '/work/hidden-relocated-extraction'], capture_output=True, timeout=15)
        self.assertEqual(relocated.returncode, 0, relocated.stderr)
        self.assertEqual((self.inputs / 'hidden-extraction/inventory.json').read_bytes(),
                         (self.inputs / 'hidden-relocated-extraction/inventory.json').read_bytes())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--recipe-root', type=Path)
    known, remainder = parser.parse_known_args()
    if known.recipe_root: ROOT = known.recipe_root.resolve()
    unittest.main(argv=[sys.argv[0], *remainder])
