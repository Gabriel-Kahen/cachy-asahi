#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Real private package() staging and isolated launcher controls; no signing keys."""
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

sys.dont_write_bytecode = True
PARSER = argparse.ArgumentParser()
PARSER.add_argument('--recipe-root', type=Path, required=True)
ARGS, REST = PARSER.parse_known_args()
SPEC = importlib.util.spec_from_file_location('recovery_package_checker', Path(__file__).with_name('check_package.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
ROOT = ARGS.recipe_root.absolute()


class PackageTests(unittest.TestCase):
    def setUp(self):
        C.check(ROOT)
        self.temporary = tempfile.TemporaryDirectory(prefix='recovery-package-original-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.recipe = self.root / 'recipe'
        self.recipe.mkdir()
        # Copy only finite recipe inputs; never mirror makepkg pipes or work dirs.
        for name in (*C.SOURCES, 'PKGBUILD', '.SRCINFO'):
            shutil.copyfile(ROOT / name, self.recipe / name)
        self.source = self.root / 'source'
        self.source.mkdir()
        for name in C.SOURCES:
            shutil.copyfile(self.recipe / name, self.source / name)
        with tarfile.open(self.source / 'private-source.tar.gz', 'r:gz') as archive:
            for member in archive:
                C.need(member.isfile() and '..' not in Path(member.name).parts
                       and not member.name.startswith('/'), 'unsafe fixture member')
                target = self.source / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as stream:
                    target.write_bytes(stream.read())
                target.chmod(member.mode)
        self.prefix = self.root / 'prefix'
        self.prefix.mkdir()
        self.env = dict(PATH='/usr/bin:/bin', HOME=str(self.root), LC_ALL='C', LANG='C')
        self.stage()
        self.launcher = self.prefix / 'usr/bin' / C.NAME
        self.runtime = self.prefix / 'usr/lib/cachy-asahi/recovery-tools'

    def stage(self):
        result = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c',
            'source "$1"; srcdir="$2"; pkgdir="$3"; package', 'package-fixture',
            str(self.recipe / 'PKGBUILD'), str(self.source), str(self.prefix)],
            env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_cli(self, *argv, expected=0, env=None, cwd=None):
        result = subprocess.run([str(self.launcher), *map(str, argv)], env=env or self.env,
            cwd=cwd or self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def test_exact_source_and_staged_payload(self):
        observed = C.check(self.recipe, self.prefix)
        self.assertEqual(observed['runtime_files'], 15)
        self.assertEqual(observed['payload_files'], 22)
        self.assertEqual(self.run_cli('--version').stdout.strip(), C.NAME + ' 0.1.0')

    def test_isolation_from_cwd_and_pythonpath(self):
        poison = self.root / 'poison'
        poison.mkdir()
        marker = self.root / 'POISON_EXECUTED'
        code = f'from pathlib import Path\nPath({str(marker)!r}).write_text("BAD")\nraise RuntimeError("untrusted import")\n'
        for name in ('sitecustomize', 'usercustomize', 'native_arm', 'preview', 'package_checks', 'offline_kit', 'recovery_bundle'):
            (poison / (name + '.py')).write_text(code)
        environment = dict(self.env, PYTHONPATH=str(poison), PYTHONHOME=str(poison))
        for command in ('materialize', 'verify'):
            self.assertIn('--selection-sha256', self.run_cli(command, '--help', env=environment, cwd=poison).stdout)
        self.run_cli('apply', expected=2, env=environment, cwd=poison)
        self.assertFalse(marker.exists())
        self.assertFalse(list(self.prefix.rglob('__pycache__')))

    def test_moved_prefix_without_recipe_or_extracted_sources(self):
        moved = self.root / 'moved-prefix'
        self.prefix.rename(moved)
        self.prefix = moved
        self.launcher = moved / 'usr/bin' / C.NAME
        shutil.rmtree(self.source)
        shutil.rmtree(self.recipe)
        self.assertIn('materialize', self.run_cli('--help').stdout)
        self.assertIn('--workspace', self.run_cli('verify', '--help').stdout)

    def test_missing_mutated_and_foreign_runtime_refuse(self):
        target = self.runtime / 'scripts/release/recovery_bundle.py'
        original = target.read_bytes()
        for case in ('missing', 'mutated', 'foreign-bytecode'):
            with self.subTest(case=case):
                if case == 'missing':
                    target.unlink()
                elif case == 'mutated':
                    target.write_bytes(original + b'\n# mutation\n')
                else:
                    (self.runtime / 'foreign.pyc').write_bytes(b'foreign bytecode')
                self.assertIn('private runtime', self.run_cli('--help', expected=1).stderr)
                if case == 'foreign-bytecode':
                    (self.runtime / 'foreign.pyc').unlink()
                else:
                    target.write_bytes(original)
        self.run_cli('--help')

    def test_runtime_links_and_writable_member_refuse(self):
        target = self.runtime / 'scripts/release/source_delivery.py'
        original = target.read_bytes()
        for case in ('symlink', 'hardlink', 'writable'):
            with self.subTest(case=case):
                other = self.root / 'untrusted-source'
                other.write_bytes(original)
                if case == 'writable':
                    target.chmod(0o666)
                else:
                    target.unlink()
                    if case == 'symlink':
                        target.symlink_to(other)
                    else:
                        os.link(other, target)
                self.assertIn('private runtime', self.run_cli('--help', expected=1).stderr)
                target.unlink()
                target.write_bytes(original)
                target.chmod(0o644)
                other.unlink()
        self.run_cli('--help')

    def test_recipe_mutation_missing_and_metadata_refuse(self):
        for name in ('private-source.tar.gz', '.SRCINFO', 'NOTICE'):
            with self.subTest(name=name):
                path = self.recipe / name
                original = path.read_bytes()
                path.write_bytes(original + b'\nchanged\n')
                with self.assertRaises((ValueError, OSError)):
                    C.check(self.recipe)
                path.unlink()
                with self.assertRaises((ValueError, OSError)):
                    C.check(self.recipe)
                path.write_bytes(original)
        C.check(self.recipe)

    def test_removal_and_reinstall_preserve_external_user_data(self):
        workspace = self.root / 'operator-workspace'
        state = self.root / 'receiver-state'
        workspace.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        for path in (workspace / 'recovery-data', state / 'checkpoint.json'):
            path.write_bytes(b'original external operator bytes\n')
        before = {str(path): path.read_bytes() for directory in (workspace, state) for path in directory.iterdir()}
        payload = json.loads((self.recipe / 'payload-map.json').read_bytes())
        for rel in payload:
            (self.prefix / rel).unlink()
        self.assertFalse(self.launcher.exists())
        self.assertEqual(before, {name: Path(name).read_bytes() for name in before})
        self.stage()
        C.check(self.recipe, self.prefix)
        self.run_cli('--help')
        self.assertEqual(before, {name: Path(name).read_bytes() for name in before})

    def test_external_selection_pin_refuses_without_output_or_state_change(self):
        selection = self.root / 'selection.json'
        selection.write_bytes(b'{}\n')
        state = self.root / 'state'
        state.mkdir(mode=0o700)
        output = self.root / 'never-created'
        result = self.run_cli('materialize', '--selection', selection, '--selection-sha256', '0' * 64,
            '--kit', self.root / 'absent-kit', '--signer', 'A' * 40, '--namespace', 'dev.original',
            '--minimum-sequence', '1', '--state-dir', state, '--output', output, expected=1)
        self.assertIn('external input SHA-256 differs', result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(list(state.iterdir()), [])


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
