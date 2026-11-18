#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the actual package() layout and relocated ordinary-user CLI."""
import argparse
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RECIPE = HERE / 'PKGBUILD'


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='first-login-delivery-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / 'relocated prefix'
        self.stage.mkdir()
        staged = subprocess.run(['bash', '-euc', 'source "$1"; srcdir="$2"; pkgdir="$3"; package',
                                 'stage', str(RECIPE), str(HERE), str(self.stage)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.launcher = self.stage / 'usr/bin/cachy-asahi-first-login'
        self.helper = self.root / 'setup'
        shutil.copyfile(HERE / 'setup8-fixture.py', self.helper)
        self.helper.chmod(0o700)
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        self.templates = self.root / 'templates'
        self.templates.mkdir(mode=0o700)
        template = self.templates / 'fish/config.fish'
        template.parent.mkdir(mode=0o700)
        template.write_text('# fixture fish\n')

    def cli(self, *args, env=None):
        return subprocess.run([str(self.launcher), *args, '--setup-helper', str(self.helper),
                               '--home', str(self.home), '--template-root', str(self.templates)],
                              cwd='/', env=env, capture_output=True, text=True, check=False)

    def test_actual_package_function_installs_only_six_opt_in_files(self):
        files = {str(path.relative_to(self.stage)): path.stat().st_mode & 0o777
                 for path in self.stage.rglob('*') if path.is_file()}
        self.assertEqual(files, {
            'usr/bin/cachy-asahi-first-login': 0o755,
            'usr/lib/cachy-asahi/first-login/first_login.py': 0o644,
            'usr/share/doc/cachy-asahi-first-login/README.md': 0o644,
            'usr/share/doc/cachy-asahi-first-login/source-provenance.json': 0o644,
            'usr/share/licenses/cachy-asahi-first-login/LICENSE': 0o644,
            'usr/share/licenses/cachy-asahi-first-login/NOTICE': 0o644})
        self.assertEqual((self.stage / 'usr/lib/cachy-asahi/first-login/first_login.py').read_bytes(),
                         (HERE / 'first_login.py').read_bytes())
        self.assertEqual(list(self.home.iterdir()), [])

    def test_relocated_launcher_runs_without_checkout_or_cwd_python_imports(self):
        poison = self.root / 'poison'
        poison.mkdir()
        for name in ('pathlib.py', 'runpy.py', 'argparse.py', 'json.py'):
            (poison / name).write_text("raise RuntimeError('ambient import executed')\n")
        env = dict(os.environ, PYTHONPATH=str(poison), PYTHONHOME=str(poison))
        process = subprocess.run([str(self.launcher), '--help'], cwd=poison, env=env,
                                 capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn('inspect,activate,recover', process.stdout)

    def poisoned_context(self):
        poison = self.root / 'unsafe working directory'; poison.mkdir()
        for folder in (poison, self.root):
            (folder / 'argparse.py').write_text("raise RuntimeError('AMBIENT_FIRST_LOGIN_IMPORT')\n")
        fake = poison / 'python3'; fake.write_text('#!/bin/sh\nexit 97\n'); fake.chmod(0o700)
        return poison, dict(os.environ, PYTHONPATH=str(poison), PYTHONHOME=str(poison), PATH=str(poison))

    def zsh_template(self):
        (self.templates / 'fish/config.fish').unlink()
        zsh = self.templates / 'zsh/config.zsh'; zsh.parent.mkdir(); zsh.write_text('# fixture zsh\n')

    def test_installed_inspect_isolated_through_actual_setup_helper(self):
        poison, env = self.poisoned_context()
        command = [str(self.launcher), 'inspect', '--setup-helper', str(self.helper),
                   '--home', str(self.home), '--template-root', str(self.templates)]
        process = subprocess.run(command, cwd=poison, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)['operation'], 'inspect')
        self.assertEqual(list(self.home.iterdir()), [])

    def test_installed_printed_preview_and_apply_followups_keep_isolation_and_roots(self):
        self.zsh_template(); poison, env = self.poisoned_context()
        target = self.home / 'custom zsh/.zshrc'; target.parent.mkdir(); target.write_text('# keep user line\n')
        options = ['--config-home', str(self.home / 'custom config'), '--zdotdir', str(target.parent),
                   '--state-dir', str(self.home / 'custom state')]
        inspect = subprocess.run([str(self.launcher), 'inspect', '--setup-helper', str(self.helper),
                     '--home', str(self.home), '--template-root', str(self.templates), *options],
                     cwd=poison, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        command = shlex.split(json.loads(inspect.stdout)['next'][0])
        self.assertEqual(command[1:3], ['-I', '-B']); self.assertEqual(Path(command[3]), self.stage / 'usr/lib/cachy-asahi/first-login/first_login.py')
        for path in [str(self.home), str(self.templates), *options]: self.assertIn(path, command)
        self.assertNotIn('--apply', command)
        preview = subprocess.run(command, cwd=poison, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(target.read_text(), '# keep user line\n')
        apply = shlex.split(json.loads(preview.stdout)['next'][0]); self.assertEqual(apply[1:3], ['-I', '-B']); self.assertIn('--apply', apply)
        applied = subprocess.run(apply, cwd=poison, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(json.loads(applied.stdout)['status'], 'activation-applied')
        self.assertTrue(target.read_text().startswith('# keep user line\n'))
        self.assertFalse((self.home / '.zshrc').exists()); self.assertTrue((self.home / 'custom state/state.json').is_file())

    def test_candidate_payload_uninstall_preserves_user_configuration(self):
        self.zsh_template()
        applied = self.cli('activate', '--components', 'zsh', '--apply')
        self.assertEqual(applied.returncode, 0, applied.stderr)
        before = {str(p): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        owned = [p for p in self.stage.rglob('*') if p.is_file()]; self.assertEqual(len(owned), 6)
        for path in owned: path.unlink()
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.home.rglob('*') if p.is_file()})
        self.assertTrue((self.home / '.zshrc').is_file()); self.assertFalse(self.launcher.exists())

    def test_relocated_inspect_and_preview_preserve_fresh_home(self):
        process = self.cli('inspect')
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report['operation'], 'inspect')
        self.assertEqual(list(self.home.iterdir()), [])
        process = self.cli('activate', '--components', 'fish')
        # Availability is checked against the host's /usr/bin/fish; never install it here.
        expected = 0 if os.access('/usr/bin/fish', os.X_OK) else 1
        self.assertEqual(process.returncode, expected, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report['status'], 'activation-preview' if expected == 0 else 'blocked')
        self.assertEqual(list(self.home.iterdir()), [])
        applied = self.cli('activate', '--components', 'fish', '--apply')
        self.assertEqual(applied.returncode, expected, applied.stderr)
        if expected == 0:
            target = self.home / '.config/fish/config.fish'
            self.assertIn(str(self.templates).encode(), target.read_bytes())
            before = target.read_bytes()
            repeated = self.cli('activate', '--components', 'fish', '--apply')
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertEqual(target.read_bytes(), before)
        else:
            self.assertEqual(list(self.home.iterdir()), [])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--recipe', type=Path, default=RECIPE)
    args, remaining = parser.parse_known_args()
    RECIPE = args.recipe.resolve()
    unittest.main(argv=[__file__, *remaining])
