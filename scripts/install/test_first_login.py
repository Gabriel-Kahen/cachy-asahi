# SPDX-License-Identifier: MIT
"""Real Setup8 helper in temporary homes; no package/session/system operations."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


first = module('first_login', Path(__file__).with_name('first_login.py'))
setup = module('first_login_setup8', ROOT / 'packages/tools/cachy-asahi-setup8/setup.py')


class Interrupted(Exception):
    pass


class FirstLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='first-login-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'user with spaces'
        self.home.mkdir(mode=0o700)
        self.templates = self.root / 'templates'
        self.templates.mkdir(mode=0o700)
        for component in first.COMPONENTS:
            path = self.templates / setup.TEMPLATES[component]
            path.parent.mkdir(mode=0o700)
            path.write_text('# fixture ' + component + '\n')
        self.helper = self.root / 'setup helper'
        shutil.copyfile(ROOT / 'packages/tools/cachy-asahi-setup8/cachy-asahi-setup', self.helper)
        self.helper.chmod(0o700)
        self.paths = ['--setup-helper', str(self.helper), '--home', str(self.home),
                      '--template-root', str(self.templates)]
        self.commands = []

    def run_helper(self, command):
        self.commands.append(command)
        return first.invoke(command)

    def run_first(self, *argv, executable=lambda *_: True):
        args = first.parser().parse_args([*argv, *self.paths])
        return first.execute(args, run=self.run_helper, executable=executable)

    def snapshot(self):
        return {str(p.relative_to(self.home)): (p.read_bytes(), p.stat().st_mode)
                for p in self.home.rglob('*') if p.is_file()}

    def test_inspect_and_preview_have_no_writes_and_explicit_selection(self):
        report, code = self.run_first()
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'ready-to-select')
        self.assertTrue(all(row['available'] for row in report['components']))
        report, code = self.run_first('activate', '--components', 'fish', 'zsh')
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'activation-preview')
        self.assertIn('--apply', shlex.split(report['next'][0]))
        self.assertEqual(list(self.home.iterdir()), [])
        with self.assertRaises(first.Error):
            self.run_first('activate', '--apply')

    def test_apply_repeat_and_real_helper_deactivation_preserve_existing_bytes(self):
        fish = self.home / '.config/fish/config.fish'
        fish.parent.mkdir(mode=0o700, parents=True)
        fish.write_text('# existing user fish without final newline')
        original = fish.read_bytes()
        report, code = self.run_first('activate', '--components', 'fish', 'zsh', '--apply')
        self.assertEqual((report['status'], code), ('activation-applied', 0))
        self.assertIn(original, fish.read_bytes())
        before = self.snapshot()
        self.run_first('activate', '--components', 'fish', 'zsh', '--apply')
        self.assertEqual(self.snapshot(), before)
        args = first.parser().parse_args(self.paths)
        data, code = first.invoke(first.helper_command(args, 'remove', ('fish', 'zsh'), True))
        self.assertEqual(code, 0)
        self.assertFalse(data['preserved_conflicts'])
        self.assertEqual(fish.read_bytes(), original)
        self.assertFalse((self.home / '.zshrc').exists())

    def test_unavailable_program_or_template_blocks_entire_selection(self):
        (self.templates / 'zsh/config.zsh').unlink()
        report, code = self.run_first('activate', '--components', 'fish', 'zsh', '--apply')
        self.assertEqual((report['status'], code), ('blocked', 1))
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(list(self.home.iterdir()), [])
        report, code = self.run_first('activate', '--components', 'fish', '--apply', executable=lambda *_: False)
        self.assertEqual((report['status'], code), ('blocked', 1))
        self.assertEqual(list(self.home.iterdir()), [])

    def test_config_conflict_blocks_other_selected_components_before_apply(self):
        target = self.home / '.config/cachy-asahi/hyprland.lua'
        target.parent.mkdir(mode=0o700, parents=True)
        target.write_text('-- existing user content\n')
        before = self.snapshot()
        report, code = self.run_first('activate', '--components', 'fish', 'hyprland', '--apply')
        self.assertEqual((report['status'], code), ('blocked', 2))
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(any('--apply' in command for command in self.commands))

    def interrupted_setup(self, **paths):
        engine = setup.Setup(self.home, self.templates, **paths)
        self.addCleanup(engine.close)
        original = engine.fs.atomic
        def interrupt(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == engine.targets['fish']:
                raise Interrupted()
            return result
        with mock.patch.object(engine.fs, 'atomic', side_effect=interrupt):
            with self.assertRaises(Interrupted):
                engine.run('activate', ('fish', 'zsh'), True)
        return engine

    def test_interruption_is_routed_to_explicit_preview_then_recovery(self):
        engine = self.interrupted_setup()
        before = self.snapshot()
        report, code = self.run_first('activate', '--components', 'hyprland', '--apply')
        self.assertEqual((report['status'], code), ('recovery-required', 2))
        self.assertEqual(report['mode'], 'read-only')
        self.assertEqual(self.snapshot(), before)
        report, code = self.run_first('recover')
        self.assertEqual((report['status'], code), ('recovery-preview', 2))
        self.assertEqual(self.snapshot(), before)
        report, code = self.run_first('recover', '--apply')
        self.assertEqual((report['status'], code), ('recovery-applied', 0))
        self.assertTrue(report['setup_result']['recovered_transaction'])
        self.assertFalse((self.home / engine.journal_path).exists())
        self.assertTrue((self.home / '.zshrc').is_file())
        self.assertFalse((self.home / '.config/cachy-asahi/hyprland.lua').exists())

    def test_recovery_preserves_custom_path_options_and_edits(self):
        options = ['--config-home', str(self.home / 'config space'), '--zdotdir', str(self.home / 'zsh space'),
                   '--state-dir', str(self.home / 'state space')]
        engine = self.interrupted_setup(config='config space', zsh='zsh space', state='state space')
        report, code = self.run_first('inspect', *options)
        self.assertEqual(code, 2)
        command = shlex.split(report['next'][0])
        for value in options + self.paths:
            self.assertIn(value, command)
        target = self.home / engine.targets['fish']
        target.write_bytes(target.read_bytes() + b'# user edit after interruption\n')
        before = self.snapshot()
        report, code = self.run_first('recover', '--apply', *options)
        self.assertEqual((report['status'], code), ('recovery-required', 1))
        self.assertEqual(self.snapshot(), before)
        self.assertTrue((self.home / engine.journal_path).exists())

    def test_migration_journal_is_redirected_to_its_owner_without_replay(self):
        state = self.home / '.local/state/cachy-asahi/setup'
        state.mkdir(mode=0o700, parents=True)
        journal = state / 'journal.json'
        journal.write_text(json.dumps({'schema_version': 1, 'roots': {'config': '.config', 'zsh': '.'},
                                      'kind': 'config-migration-v1', 'id': 'migration-' + 'a' * 32,
                                      'manifest_sha256': 'b' * 64}))
        journal.chmod(0o600)
        before = self.snapshot()
        report, code = self.run_first('recover', '--apply')
        self.assertEqual((report['status'], code), ('recovery-required', 2))
        self.assertIn('cachy-asahi-config-migrate', report['next'][0])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.commands), 1)

    def test_environment_roots_are_frozen_for_recovery_from_another_shell(self):
        engine = self.interrupted_setup(config='env config', zsh='env zsh', state='env state/cachy-asahi/setup')
        args = first.parser().parse_args(['inspect', '--setup-helper', str(self.helper),
                                         '--template-root', str(self.templates)])
        inherited = {'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.home / 'env config'),
                     'ZDOTDIR': str(self.home / 'env zsh'), 'XDG_STATE_HOME': str(self.home / 'env state')}
        with mock.patch.dict(os.environ, inherited):
            report, code = first.execute(args, run=self.run_helper)
        self.assertEqual(code, 2)
        command = shlex.split(report['next'][1])
        recovery_args = first.parser().parse_args(command[2:])
        with mock.patch.dict(os.environ, {'HOME': str(self.root), 'XDG_CONFIG_HOME': '/unrelated',
                                         'ZDOTDIR': '/unrelated', 'XDG_STATE_HOME': '/unrelated'}):
            report, code = first.execute(recovery_args, run=self.run_helper)
        self.assertEqual((report['status'], code), ('recovery-applied', 0))
        self.assertTrue((self.home / engine.targets['zsh']).is_file())
        self.assertFalse((self.home / '.zshrc').exists())

    def test_unknown_state_and_symlinked_targets_fail_without_apply(self):
        target = self.home / '.zshrc'
        outside = self.root / 'outside'
        outside.write_text('untouched\n')
        target.symlink_to(outside)
        report, code = self.run_first('activate', '--components', 'zsh', '--apply')
        self.assertEqual((report['status'], code), ('blocked', 1))
        self.assertEqual(outside.read_text(), 'untouched\n')
        self.assertEqual(len(self.commands), 1)

    def test_incompatible_helper_status_refuses_operation(self):
        args = first.parser().parse_args(['activate', '--components', 'fish', '--apply', *self.paths])
        for bad in ({}, {'schema_version': 1, 'operation': 'status', 'mode': 'read-only', 'exit_code': 0, 'state': None}):
            with self.assertRaises(first.Error):
                first.execute(args, run=lambda _: (bad, 0))

    def test_cli_returns_json_and_root_refusal(self):
        process = subprocess.run([sys.executable, '-B', str(Path(first.__file__)), *self.paths],
                                 capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)['operation'], 'inspect')
        with mock.patch.object(sys, 'argv', ['first-login']), mock.patch.object(os, 'geteuid', return_value=0), \
                mock.patch('sys.stderr') as stderr:
            self.assertEqual(first.main(), 1)
            self.assertIn('without sudo', ''.join(call.args[0] for call in stderr.write.call_args_list))


if __name__ == '__main__':
    unittest.main()
