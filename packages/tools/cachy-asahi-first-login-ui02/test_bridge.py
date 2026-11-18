# SPDX-License-Identifier: MIT
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('support', HERE / 'test_support.py')
support = importlib.util.module_from_spec(spec); spec.loader.exec_module(support)
bridge = support.bridge


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.f = support.Fixture(); self.addCleanup(self.f.close)
        self.client = self.f.client

    def test_real_inspect_preview_apply_private_home(self):
        self.assertEqual(self.client.run('inspect')[0]['status'], 'ready-to-select')
        self.assertEqual(self.client.run('preview', ('fish', 'zsh'))[0]['status'], 'activation-preview')
        self.assertEqual(self.f.files(), {})
        self.assertEqual(self.client.run('apply')[0]['status'], 'activation-applied')
        self.assertIn('.zshrc', self.f.files())
        self.assertIn('.config/fish/config.fish', self.f.files())

    def test_apply_requires_preview_and_ticket_is_single_use(self):
        with self.assertRaises(bridge.Error): self.client.run('apply')
        self.client.run('preview', ('fish',)); self.client.run('apply')
        before = self.f.files()
        with self.assertRaises(bridge.Error): self.client.run('apply')
        self.assertEqual(self.f.files(), before)

    def test_expired_preview_refused_without_writes(self):
        self.client.run('preview', ('fish',))
        ticket = self.client.ticket
        self.client.ticket = (*ticket[:4], time.monotonic() - 121)
        with self.assertRaisesRegex(bridge.Error, 'expired'): self.client.run('apply')
        self.assertEqual(self.f.files(), {})

    def test_new_unmanaged_user_edit_invalidates_same_cli_actions(self):
        self.client.run('preview', ('zsh',))
        (self.f.home / '.zshrc').write_text('# my new edit\n')
        before = self.f.files()
        with self.assertRaisesRegex(bridge.Error, 'changed'): self.client.run('apply')
        self.assertEqual(self.f.files(), before)
        self.assertIsNone(self.client.ticket)

    def test_changed_template_refused(self):
        self.client.run('preview', ('fish',))
        (self.f.templates / 'fish/config.fish').write_text('# updated template\n')
        with self.assertRaisesRegex(bridge.Error, 'changed'): self.client.run('apply')
        self.assertEqual(self.f.files(), {})

    def test_conflict_blocks_entire_selection(self):
        target = self.f.home / '.zshrc'
        begin, end = support.setup.markers('zsh')
        target.write_text(begin + '\n' + end + '\n')
        before = self.f.files()
        result, code = self.client.run('preview', ('fish', 'zsh'))
        self.assertEqual((result['status'], code), ('blocked', 2))
        self.assertIsNone(self.client.ticket)
        self.assertEqual(self.f.files(), before)

    def test_optional_hyprland_unavailable_is_not_a_configuration_conflict(self):
        first = support.module('unavailable_hyprland', HERE / 'first-login-fixture.py')
        args = first.parser().parse_args(['activate', '--components', 'hyprland', '--apply',
            '--home', str(self.f.home), '--template-root', str(self.f.templates),
            '--setup-helper', str(self.f.usr / 'bin/cachy-asahi-setup')])
        commands = []
        def run(command):
            commands.append(command); return first.invoke(command)
        report, code = first.execute(args, run=run, executable=lambda *_: False)
        self.assertEqual((report['status'], code), ('blocked', 1))
        self.assertFalse(report['components'][0]['available'])
        self.assertFalse(any('--apply' in command for command in commands))
        self.assertEqual(self.f.files(), {})

    def test_missing_template_blocks(self):
        (self.f.templates / 'zsh/config.zsh').unlink()
        report, code = self.client.run('preview', ('fish', 'zsh'))
        self.assertEqual((report['status'], code), ('blocked', 1))
        self.assertEqual(self.f.files(), {})

    def test_real_pending_recovery_is_explicit(self):
        self.f.interrupted(); before = self.f.files()
        self.assertEqual(self.client.run('inspect')[0]['status'], 'recovery-required')
        self.assertEqual(self.client.run('recover-preview')[0]['status'], 'recovery-preview')
        self.assertEqual(self.f.files(), before)
        self.assertEqual(self.client.run('apply')[0]['status'], 'recovery-applied')
        self.assertIn('.zshrc', self.f.files())
        self.assertFalse((self.client.paths['state_dir'] / 'journal.json').exists())

    def test_pending_user_edit_prevents_recovery(self):
        self.f.interrupted()
        self.client.run('recover-preview')
        (self.f.home / '.config/fish/config.fish').write_text('# keep this edit\n')
        before = self.f.files()
        with self.assertRaisesRegex(bridge.Error, 'changed'): self.client.run('apply')
        self.assertEqual(self.f.files(), before)

    def test_symlink_refused_and_target_preserved(self):
        other = self.f.root / 'other'; other.write_text('keep')
        (self.f.home / '.zshrc').symlink_to(other)
        with self.assertRaises(bridge.Error): self.client.run('preview', ('zsh',))
        self.assertEqual(other.read_text(), 'keep')

    def test_inflight_input_edit_refuses_preview(self):
        original = self.client.invoke
        def changed(*args):
            result = original(*args); (self.f.home / '.zshrc').write_text('new edit'); return result
        with patch.object(self.client, 'invoke', changed), self.assertRaisesRegex(bridge.Error, 'during preview'):
            self.client.run('preview', ('zsh',))
        self.assertIsNone(self.client.ticket)

    def test_invalid_operations_never_spawn(self):
        with patch('subprocess.Popen') as spawn:
            for op, components in (('shell', ()), ('inspect', ('fish',)), ('activate', ('fish;sh',))):
                with self.assertRaises(bridge.Error): self.client.invoke(op, components)
            spawn.assert_not_called()

    def test_multiple_actions_refused(self):
        self.client.lock.acquire()
        try:
            with self.assertRaisesRegex(bridge.Error, 'still running'): self.client.run('inspect')
        finally:
            self.client.lock.release()

    def test_inspect_invalidates_preview(self):
        self.client.run('preview', ('fish',)); self.client.run('inspect')
        self.assertIsNone(self.client.ticket)

    def test_real_helper_cancellation_reaps_worker(self):
        entry = self.f.usr / 'bin/cachy-asahi-first-login'
        entry.write_text('#!/usr/bin/python3 -I\nimport time\ntime.sleep(60)\n')
        errors = []
        def work():
            try: self.client.run('inspect')
            except bridge.Error as error: errors.append(str(error))
        worker = threading.Thread(target=work); worker.start()
        time.sleep(0.1); self.client.cancel.set(); worker.join(3)
        self.assertFalse(worker.is_alive()); self.assertEqual(len(errors), 1)
        self.assertIn('stopped', errors[0])

    def test_duplicate_invalid_and_oversized_reports_refused(self):
        entry = self.f.usr / 'bin/cachy-asahi-first-login'
        for value in ('{"schema_version":1,"schema_version":1}', 'not JSON', 'x' * (bridge.MAX_BYTES + 1)):
            entry.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.stdout.write(' + repr(value) + ')\n')
            with self.assertRaises(bridge.Error): self.client.run('inspect')

    def test_malformed_component_rows_fail_closed(self):
        report = self.client.run('inspect')[0]
        report['components'] = ['untrusted row']
        entry = self.f.usr / 'bin/cachy-asahi-first-login'
        entry.write_text('#!/usr/bin/python3 -I\nprint(' + repr(json.dumps(report)) + ')\n')
        with self.assertRaises(bridge.Error): self.client.run('inspect')

    def test_unrequested_applied_mode_refused(self):
        report = self.client.run('inspect')[0]; report['mode'] = 'applied'
        entry = self.f.usr / 'bin/cachy-asahi-first-login'
        entry.write_text('#!/usr/bin/python3 -I\nprint(' + repr(json.dumps(report)) + ')\n')
        with self.assertRaises(bridge.Error): self.client.run('inspect')

    def test_relative_prefix_refused(self):
        with self.assertRaises(bridge.Error): bridge.Bridge(Path('relative'), home=self.f.home)

    def test_original_recorded_template_root_is_bound(self):
        self.client.run('preview', ('fish',)); self.client.run('apply')
        alternate = self.f.root / 'other templates'
        import shutil
        shutil.copytree(self.f.templates, alternate)
        other = bridge.Bridge(self.f.usr, home=self.f.home, template_root=alternate)
        other.run('preview', ('fish',))
        (self.f.templates / 'fish/config.fish').write_text('# changed original root\n')
        before = self.f.files()
        with self.assertRaisesRegex(bridge.Error, 'changed'): other.run('apply')
        self.assertEqual(self.f.files(), before)

    def test_migration_owned_journal_cannot_enable_apply(self):
        directory = self.client.paths['state_dir']; directory.mkdir(parents=True, mode=0o700)
        journal = directory / 'journal.json'
        journal.write_text(json.dumps({'schema_version': 1, 'roots': {'config': '.config', 'zsh': '.'},
                                      'kind': 'config-migration-v1', 'id': 'migration-' + 'a' * 32,
                                      'manifest_sha256': 'b' * 64})); journal.chmod(0o600)
        before = self.f.files()
        self.assertEqual(self.client.run('inspect')[0]['setup_status']['pending']['status'], 'migration-owned')
        self.client.run('recover-preview')
        self.assertIsNone(self.client.ticket)
        self.assertEqual(self.f.files(), before)

    def test_unknown_ownership_cannot_enable_apply_from_preview_report(self):
        report, code = self.client.run('preview', ('fish',))
        report['setup_status']['state']['status'] = 'unknown'
        with patch.object(self.client, 'invoke', return_value=(report, code)):
            self.client.run('preview', ('fish',))
        self.assertIsNone(self.client.ticket)
        self.assertEqual(self.f.files(), {})



class RemovalTests(unittest.TestCase):
    setUp = BridgeTests.setUp

    def activate(self, components=('fish', 'zsh')):
        self.client.run('preview', components); self.client.run('apply')

    def test_real_removal_preview_apply_preserves_surrounding_user_edits(self):
        zsh = self.f.home / '.zshrc'; zsh.write_text('# original zsh\n')
        self.activate(); zsh.write_text(zsh.read_text() + '# later user edit\n')
        before = self.f.files()
        report, code = self.client.run('remove-preview', ('fish', 'zsh'))
        self.assertEqual((report['status'], code), ('removal-preview', 0))
        self.assertEqual(self.f.files(), before)
        self.assertEqual([r['status'] for r in report['setup_result']['actions']], ['would-remove', 'would-remove'])
        report, code = self.client.run('apply')
        self.assertEqual((report['status'], code), ('removal-applied', 0))
        self.assertEqual(zsh.read_text(), '# original zsh\n# later user edit\n')
        self.assertFalse((self.f.home / '.config/fish/config.fish').exists())
        self.assertEqual(json.loads((self.client.paths['state_dir'] / 'state.json').read_bytes())['components'], {})

    def test_remove_apply_requires_fresh_single_use_preview(self):
        self.activate(('fish',)); self.client.run('remove-preview', ('fish',))
        ticket = self.client.ticket; self.client.ticket = (*ticket[:4], time.monotonic() - 121)
        before = self.f.files()
        with self.assertRaisesRegex(bridge.Error, 'expired'): self.client.run('apply')
        self.assertEqual(self.f.files(), before)
        self.client.run('remove-preview', ('fish',)); self.client.run('apply')
        with self.assertRaises(bridge.Error): self.client.run('apply')

    def test_stale_removal_preserves_new_edit_and_ownership(self):
        self.activate(('fish',)); self.client.run('remove-preview', ('fish',))
        target = self.f.home / '.config/fish/config.fish'; target.write_text(target.read_text() + '# new user line\n')
        before = self.f.files()
        with self.assertRaisesRegex(bridge.Error, 'changed'): self.client.run('apply')
        self.assertEqual(self.f.files(), before)

    def test_owned_block_conflict_blocks_entire_removal(self):
        self.activate(); target = self.f.home / '.zshrc'; target.write_text(target.read_text().replace('source ', '# user changed source ', 1))
        before = self.f.files(); report, code = self.client.run('remove-preview', ('fish', 'zsh'))
        self.assertEqual((report['status'], code), ('blocked', 2)); self.assertIsNone(self.client.ticket)
        with self.assertRaises(bridge.Error): self.client.run('apply')
        self.assertEqual(self.f.files(), before)

    def test_remove_managed_settings_after_template_is_uninstalled(self):
        self.activate(('fish',)); (self.f.templates / 'fish/config.fish').unlink()
        self.assertFalse(next(r for r in self.client.run('inspect')[0]['components'] if r['component'] == 'fish')['available'])
        self.assertEqual(self.client.run('remove-preview', ('fish',))[0]['status'], 'removal-preview')
        self.assertEqual(self.client.run('apply')[0]['status'], 'removal-applied')
        self.assertFalse((self.f.home / '.config/fish/config.fish').exists())

    def test_pending_activation_is_not_implicitly_recovered_by_remove(self):
        self.f.interrupted(); before = self.f.files()
        with patch.object(bridge.subprocess, 'Popen', wraps=bridge.subprocess.Popen) as calls:
            report, code = self.client.run('remove-preview', ('fish',))
        self.assertEqual((report['status'], code), ('blocked', 2)); self.assertIsNone(self.client.ticket)
        self.assertFalse(any(c.args[0][0].endswith('/cachy-asahi-setup') and c.args[0][1] == 'remove' for c in calls.call_args_list))
        self.assertEqual(self.f.files(), before)

    def test_migration_owned_journal_blocks_removal(self):
        state = self.client.paths['state_dir']; state.mkdir(parents=True, mode=0o700)
        journal = state / 'journal.json'; journal.write_text(json.dumps({'schema_version': 1, 'roots': {'config': '.config', 'zsh': '.'}, 'kind': 'config-migration-v1', 'id': 'migration-' + 'a' * 32, 'manifest_sha256': 'b' * 64})); journal.chmod(0o600)
        before = self.f.files(); report, code = self.client.run('remove-preview', ('zsh',))
        self.assertEqual((report['status'], code), ('blocked', 2)); self.assertIsNone(self.client.ticket); self.assertEqual(self.f.files(), before)

    def test_exact_unedited_hyprland_copy_can_be_removed_without_launch(self):
        engine = support.setup.Setup(self.f.home, self.f.templates)
        try: engine.run('activate', ('hyprland',), True)
        finally: engine.close()
        self.client.run('remove-preview', ('hyprland',)); self.client.run('apply')
        self.assertFalse((self.f.home / '.config/cachy-asahi/hyprland.lua').exists())

    def test_unselected_managed_module_is_preserved(self):
        path = self.f.templates / support.setup.TEMPLATES['fish-bang-bang']; path.parent.mkdir(); path.write_text('# private module\n')
        engine = support.setup.Setup(self.f.home, self.f.templates)
        try: engine.run('activate', ('fish', 'fish-bang-bang'), True)
        finally: engine.close()
        statefile = self.client.paths['state_dir'] / 'state.json'; block = json.loads(statefile.read_bytes())['components']['fish-bang-bang']['block']
        self.client.run('remove-preview', ('fish',)); self.client.run('apply')
        self.assertEqual((self.f.home / '.config/fish/config.fish').read_text(), block)
        self.assertEqual(set(json.loads(statefile.read_bytes())['components']), {'fish-bang-bang'})

    def test_unmanaged_user_file_has_no_removal_ticket(self):
        (self.f.home / '.zshrc').write_text('# only user settings\n'); before = self.f.files()
        report, code = self.client.run('remove-preview', ('zsh',))
        self.assertEqual((report['status'], code), ('removal-preview', 0)); self.assertIsNone(self.client.ticket); self.assertEqual(self.f.files(), before)

    def test_interrupted_removal_resumes_original_transaction(self):
        (self.f.home / '.zshrc').write_text('# keep zsh\n'); fish = self.f.home / '.config/fish/config.fish'; fish.parent.mkdir(parents=True); fish.write_text('# keep fish\n')
        self.activate(); engine = support.setup.Setup(self.f.home, self.f.templates); atomic = engine.fs.atomic
        def interrupt(path, *args, **kwargs):
            result = atomic(path, *args, **kwargs)
            if path == engine.targets['fish']: raise support.Interrupted()
            return result
        engine.fs.atomic = interrupt
        try:
            with self.assertRaises(support.Interrupted): engine.run('remove', ('fish', 'zsh'), True)
        finally: engine.close()
        self.assertEqual(self.client.run('inspect')[0]['status'], 'recovery-required')
        self.assertEqual(self.client.run('recover-preview')[0]['status'], 'recovery-preview')
        self.assertEqual(self.client.run('apply')[0]['status'], 'recovery-applied')
        self.assertEqual(fish.read_text(), '# keep fish\n'); self.assertEqual((self.f.home / '.zshrc').read_text(), '# keep zsh\n')

    def test_remove_argv_is_fixed_and_cannot_expand_to_all_components(self):
        argv = self.client.argv('remove', ('fish', 'zsh'), True)
        self.assertEqual(argv[:4], [str(self.f.usr / 'bin/cachy-asahi-setup'), 'remove', '--components', 'fish'])
        self.assertEqual(argv[-1], '--apply'); self.assertNotIn('--setup-helper', argv)
        for components in ((), ('fish', 'fish'), ('fish;touch',)):
            with self.subTest(components=components), self.assertRaises(bridge.Error): self.client.argv('remove', components)

    def test_malformed_or_pending_remove_reports_cannot_enable_apply(self):
        self.activate(('fish',)); observed = self.client.run('inspect')[0]
        result = {'operation': 'remove', 'mode': 'preview', 'recovered_transaction': False, 'preserved_conflicts': False, 'actions': [{'component': 'fish', 'status': 'would-remove', 'path': '.config/fish/config.fish'}]}
        import copy
        for mode in ('mode', 'component', 'status', 'pending', 'duplicate', 'exit'):
            bad = copy.deepcopy(result); code = 0
            if mode == 'mode': bad['mode'] = 'applied'
            elif mode == 'component': bad['actions'][0]['component'] = []
            elif mode == 'status': bad['actions'][0]['status'] = {}
            elif mode == 'pending': bad['pending_transaction'] = 'foreign'
            elif mode == 'duplicate': bad['actions'] *= 2
            else: code = 2
            with self.subTest(mode=mode), self.assertRaises(bridge.Error): self.client.removal_report(observed, bad, ('fish',), False, code)

    def test_remove_mode_and_action_must_agree(self):
        observed = self.client.run('inspect')[0]
        for apply, mode, action in ((False, 'preview', 'remove'), (True, 'applied', 'would-remove')):
            result = {'operation': 'remove', 'mode': mode, 'recovered_transaction': False, 'preserved_conflicts': False,
                      'actions': [{'component': 'fish', 'status': action, 'path': '.config/fish/config.fish'}]}
            with self.subTest(apply=apply), self.assertRaises(bridge.Error):
                self.client.removal_report(observed, result, ('fish',), apply, 0)

    def test_unexpected_concurrent_recovery_is_attention_not_success(self):
        observed = self.client.run('inspect')[0]
        raw = {'operation': 'remove', 'mode': 'applied', 'recovered_transaction': True, 'preserved_conflicts': False, 'actions': [{'component': 'fish', 'status': 'remove', 'path': '.config/fish/config.fish'}]}
        report, code = self.client.removal_report(observed, raw, ('fish',), True, 0)
        self.assertEqual((report['status'], code), ('removal-attention', 2)); self.assertEqual(report['setup_exit_code'], 0)

if __name__ == '__main__':
    unittest.main()
