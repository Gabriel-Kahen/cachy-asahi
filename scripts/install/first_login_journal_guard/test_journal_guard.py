# SPDX-License-Identifier: MIT
"""Exercise the successor First Login and Setup entry points in temporary homes."""
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
FIRST = Path('scripts/install/first_login.py')
SETUP = Path('scripts/setup8/setup.py')
PATCH = Path(__file__).with_name('journal-guard.patch').resolve()


def stage_sources(destination):
    # Keep the accepted source snapshots usable for their frozen package recipes.
    for relative in (FIRST, SETUP):
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, path)
    subprocess.run(['git', 'apply', str(PATCH)], cwd=destination, check=True)
    (destination / SETUP).chmod(0o700)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class JournalGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = tempfile.TemporaryDirectory(prefix='first-login-source-')
        cls.addClassCleanup(source.cleanup)
        destination = Path(source.name)
        stage_sources(destination)
        cls.first = load_module('guarded_first_login', destination / FIRST)
        cls.setup = load_module('guarded_setup', destination / SETUP)
        cls.helper = destination / SETUP

    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix='first-login-guard-')
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name)
        self.home = self.root / 'home with spaces'
        self.home.mkdir(mode=0o700)
        self.templates = self.root / 'templates'
        for component in self.first.COMPONENTS:
            path = self.templates / self.setup.TEMPLATES[component]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# fixture\n')
        self.engine = self.setup.Setup(self.home, self.templates)
        self.addCleanup(self.engine.close)
        self.journal = self.home / self.engine.journal_path
        self.state = self.home / self.engine.state_path
        self.fish = self.home / self.engine.targets['fish']
        self.zsh = self.home / self.engine.targets['zsh']

    def interrupt(self, component, engine=None):
        engine = engine or self.engine
        with mock.patch.object(engine, 'replay', side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):
                engine.run('activate', (component,), True)
        return engine.load(engine.journal_path)['id']

    def run_first(self, *arguments, helper=None, run=None):
        args = self.first.parser().parse_args([
            *arguments, '--setup-helper', str(helper or self.helper),
            '--home', str(self.home), '--template-root', str(self.templates),
        ])
        return self.first.execute(args, run=run or self.first.invoke, executable=lambda *_: True)

    def test_fish_activation_refuses_zsh_journal_arriving_after_preview(self):
        def invoke(command):
            if command[1] == 'activate' and '--apply' in command:
                self.interrupt('zsh')
                before = self.journal.read_bytes()
                result = self.first.invoke(command)
                self.assertEqual(self.journal.read_bytes(), before)
                return result
            return self.first.invoke(command)

        report, code = self.run_first('activate', '--components', 'fish', '--apply', run=invoke)
        self.assertEqual((report['status'], report['mode'], code), ('attention-required', 'read-only', 2))
        self.assertFalse(self.fish.exists())
        self.assertFalse(self.zsh.exists())
        self.assertFalse(self.state.exists())

    def test_setup_checks_for_a_journal_after_lock_acquisition(self):
        other = self.setup.Setup(self.home, self.templates)
        self.addCleanup(other.close)
        lock = self.engine.fs.lock

        def acquire(path):
            self.interrupt('zsh', other)
            return lock(path)

        with mock.patch.object(self.engine.fs, 'lock', side_effect=acquire):
            report = self.engine.run('activate', ('fish',), True, expected_journal='none')
        self.assertTrue(report['journal_changed'])
        self.assertFalse(self.fish.exists())
        self.assertFalse(self.zsh.exists())
        self.assertFalse(self.state.exists())
        self.assertTrue(self.journal.exists())

    def test_fish_recovery_ignores_unrelated_symlink_but_preserves_it(self):
        self.interrupt('fish')
        dotfile = self.home / 'dotfiles' / 'zshrc'
        dotfile.parent.mkdir()
        dotfile.write_bytes(b'# user zsh config without final newline')
        link = Path('dotfiles/zshrc')
        self.zsh.symlink_to(link)
        before = self.journal.read_bytes()

        report, code = self.run_first('recover')
        self.assertEqual((report['status'], code), ('recovery-preview', 2))
        self.assertEqual(report['setup_status']['exit_code'], 1)
        self.assertEqual([row['component'] for row in report['setup_result']['actions']], ['fish'])
        self.assertEqual(self.journal.read_bytes(), before)
        self.assertFalse(self.fish.exists())
        self.assertFalse(self.state.exists())

        command = shlex.split(report['next'][1])
        process = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn(self.setup.markers('fish')[0], self.fish.read_text())
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.zsh.readlink(), link)
        self.assertEqual(dotfile.read_bytes(), b'# user zsh config without final newline')

    def test_recovery_refuses_a_replacement_after_status(self):
        self.interrupt('fish')

        def invoke(command):
            if command[1] == 'recover' and '--apply' in command:
                self.journal.unlink()
                self.interrupt('zsh')
                before = self.journal.read_bytes()
                result = self.first.invoke(command)
                self.assertEqual(self.journal.read_bytes(), before)
                return result
            return self.first.invoke(command)

        report, code = self.run_first('recover', '--apply', run=invoke)
        self.assertEqual((report['status'], report['mode'], code), ('attention-required', 'read-only', 2))
        self.assertFalse(self.fish.exists())
        self.assertFalse(self.zsh.exists())
        self.assertFalse(self.state.exists())

    def test_printed_recovery_refuses_a_replacement_before_invocation(self):
        original = self.interrupt('fish')
        report, code = self.run_first('inspect')
        self.assertEqual((report['status'], code), ('recovery-required', 2))
        command = shlex.split(report['next'][1])
        self.assertEqual(command[command.index('--expected-journal') + 1], original)
        self.journal.unlink()
        self.interrupt('zsh')
        before = self.journal.read_bytes()

        process = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(self.journal.read_bytes(), before)
        self.assertFalse(self.fish.exists())
        self.assertFalse(self.zsh.exists())

    def test_fish_activation_works_with_no_journal_and_preserves_zsh(self):
        self.zsh.write_bytes(b'# existing zsh config\n')
        report, code = self.run_first('activate', '--components', 'fish', '--apply')
        self.assertEqual((report['status'], code), ('activation-applied', 0))
        self.assertEqual([row['component'] for row in report['setup_result']['actions']], ['fish'])
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.zsh.read_bytes(), b'# existing zsh config\n')

    def test_older_setup_refuses_guarded_apply(self):
        legacy = ROOT / 'packages/tools/cachy-asahi-setup8/cachy-asahi-setup'
        with self.assertRaises(self.first.Error):
            self.run_first('activate', '--components', 'fish', '--apply', helper=legacy)
        self.assertEqual(list(self.home.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
