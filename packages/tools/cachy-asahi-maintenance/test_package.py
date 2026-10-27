#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Real unprivileged package staging and isolated CLI controls, without a checkout."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--recipe-root', type=Path, default=Path(__file__).absolute().parent)
options, unittest_args = parser.parse_known_args()
HERE = options.recipe_root.absolute()
spec = importlib.util.spec_from_file_location('maintenance_package_checks', HERE / 'check_source.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def copy_recipe(source, target):
    """Copy only the checked recipe; makepkg's live build outputs are not inputs."""
    c.check(source)
    target.mkdir()
    for name in sorted(c.recipe_files()):
        (target / name).write_bytes(c.recipe_bytes(source / name))
    c.check(target)


def stage(recipe, target):
    subprocess.run(['/bin/bash', '-c',
                    'set -eu; source "$1/PKGBUILD"; srcdir="$1"; pkgdir="$2"; package',
                    'stage-maintenance', str(recipe), str(target)], check=True, capture_output=True)


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob('*') if p.is_file()}


class PackageControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='maintenance-package-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.stage = cls.root / 'stage'
        cls.cwd = cls.root / 'unrelated-working-directory'
        cls.cwd.mkdir()
        cls.recipe = cls.root / 'source'
        copy_recipe(HERE, cls.recipe)
        stage(cls.recipe, cls.stage)
        cls.cli = cls.stage / 'usr/bin/cachy-asahi-maintenance'
        cls.baseline = snapshot(cls.stage)

    def run_cli(self, *args, environment=None):
        result = subprocess.run([str(self.cli), *args], cwd=self.cwd, capture_output=True,
                                timeout=15, env=dict(os.environ, **(environment or {})))
        self.assertEqual(snapshot(self.stage), self.baseline)
        return result

    def arguments(self):
        return ['--release', str(self.cwd), '--release-sha256', '0' * 64, '--key', 'A' * 40,
                '--gpg-home', str(self.cwd), '--as-of', '2026-10-27T05:00:00Z']

    def test_recipe_checksums_provenance_and_srcinfo(self):
        value = c.check(self.recipe)
        self.assertEqual(value['module_files'], 9)

    def test_exact_stage_files_modes_and_bytes(self):
        self.assertEqual(c.check(self.recipe, self.stage)['installed_files'], 16)

    def test_fixture_ignores_makepkg_fifo_and_dynamic_outputs(self):
        work = self.root / 'makepkg-work'
        copy_recipe(self.recipe, work)
        fifo = work / 'logpipe.qnO8Pi3J'
        os.mkfifo(fifo, 0o600)
        (work / 'src').mkdir()
        (work / 'src/unreviewed.py').write_text('raise AssertionError("not a recipe input")\n')
        (work / 'build.log').write_text('live makepkg output\n')
        (work / 'candidate.pkg.tar.zst').write_bytes(b'not a recipe input')
        target = self.root / 'copied-makepkg-recipe'
        copy_recipe(work, target)
        self.assertEqual({p.name for p in target.iterdir()}, c.recipe_files())
        self.assertTrue(fifo.exists())
        staged = self.root / 'fifo-regression-stage'
        stage(target, staged)
        self.assertEqual(c.check(target, staged)['installed_files'], 16)
        self.assertEqual(snapshot(staged), self.baseline)

    def test_fixture_refuses_unsafe_declared_recipe_inputs(self):
        for name in ('PKGBUILD', '.SRCINFO', 'health.py'):
            for kind in ('fifo', 'symlink', 'directory', 'hardlink'):
                with self.subTest(name=name, kind=kind):
                    work = self.root / ('unsafe-' + name + '-' + kind)
                    copy_recipe(self.recipe, work)
                    leaf = work / name
                    leaf.unlink()
                    if kind == 'fifo': os.mkfifo(leaf, 0o600)
                    elif kind == 'symlink': leaf.symlink_to(self.recipe / name)
                    elif kind == 'directory': leaf.mkdir()
                    else: os.link(self.recipe / name, leaf)
                    with self.assertRaisesRegex(ValueError, 'ordinary'):
                        copy_recipe(work, self.root / ('refused-' + name + '-' + kind))
                    if kind == 'hardlink': leaf.unlink()

    def test_fixture_revalidates_declared_checksums_before_copy(self):
        work = self.root / 'bad-fixture-input'
        copy_recipe(self.recipe, work)
        (work / 'health.py').write_bytes((work / 'health.py').read_bytes() + b'\n# changed\n')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch: health.py'):
            copy_recipe(work, self.root / 'refused-changed-recipe')

    def test_help_outside_checkout(self):
        result = self.run_cli('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--release-sha256', result.stdout)
        self.assertIn(b'--observations-sha256', result.stdout)
        self.assertEqual(result.stderr, b'')

    def test_version_outside_checkout(self):
        result = self.run_cli('--version')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'cachy-asahi-maintenance 0.1.0-2\n')

    def test_required_explicit_inputs(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'required', result.stderr)

    def test_bad_release_digest_clean_refusal(self):
        args = self.arguments()
        args[args.index('--release-sha256') + 1] = 'wrong'
        result = self.run_cli(*args)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'SHA-256', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)

    def test_bad_time_clean_refusal(self):
        args = self.arguments()
        args[args.index('--as-of') + 1] = '2026-10-27'
        result = self.run_cli(*args)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'UTC', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)

    def test_missing_release_clean_refusal(self):
        args = self.arguments()
        args[args.index('--release') + 1] = str(self.cwd / 'missing')
        result = self.run_cli(*args)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'release directory missing', result.stderr)

    def test_private_layout_resolves_without_repository(self):
        # A second relocation contains only the 16 installed files.
        target = self.root / 'other-prefix'
        shutil.copytree(self.stage, target)
        result = subprocess.run([str(target / 'usr/bin/cachy-asahi-maintenance'), '--help'],
                                cwd=self.cwd, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(snapshot(target), self.baseline)

    def test_pythonpath_and_startup_injection_ignored(self):
        marker = self.cwd / 'injection-ran'
        (self.cwd / 'sitecustomize.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
        result = self.run_cli('--help', environment={'PYTHONPATH': str(self.cwd),
                                                   'PYTHONSTARTUP': str(self.cwd / 'sitecustomize.py')})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_modified_frozen_rebuild_refused_before_import(self):
        target = self.root / 'tampered-prefix'
        shutil.copytree(self.stage, target)
        path = target / c.PRIVATE / 'scripts/maintenance/rebuild_plan.py'
        path.write_bytes(path.read_bytes() + b'\nraise AssertionError("unreviewed planner ran")\n')
        result = subprocess.run([str(target / 'usr/bin/cachy-asahi-maintenance'), '--help'],
                                cwd=self.cwd, capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'rebuild planner changed', result.stderr)
        self.assertNotIn(b'unreviewed planner ran', result.stderr)

    def test_source_pin_tamper_refused(self):
        target = self.root / 'tampered-source'
        shutil.copytree(self.recipe, target)
        (target / 'health.py').write_bytes((target / 'health.py').read_bytes() + b'\n# changed\n')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch: health.py'):
            c.check(target)

    def test_extra_installed_file_refused(self):
        target = self.root / 'extra-file-prefix'
        shutil.copytree(self.stage, target)
        (target / 'usr/extra').write_text('not package owned\n')
        with self.assertRaisesRegex(ValueError, 'unexpected or missing'):
            c.check(self.recipe, target)

    def test_symlink_installed_file_refused(self):
        target = self.root / 'alias-prefix'
        shutil.copytree(self.stage, target)
        (target / 'usr/alias').symlink_to('bin/cachy-asahi-maintenance')
        with self.assertRaisesRegex(ValueError, 'symlinks refused'):
            c.check(self.recipe, target)

    def test_no_bytecode_or_hooks_or_automatic_system_activation(self):
        self.assertFalse(list(self.stage.rglob('__pycache__')))
        self.assertFalse((self.stage / 'etc').exists())
        self.assertFalse((self.stage / 'usr/lib/systemd').exists())
        self.assertFalse(list(self.recipe.glob('*.install')))


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *unittest_args])
