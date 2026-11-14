#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the actual package() layout and relocated ordinary-user CLI."""
import argparse
import json
import os
from pathlib import Path
import shutil
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
