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
        target = self.f.home / '.config/cachy-asahi/hyprland.lua'
        target.parent.mkdir(parents=True); target.write_text('-- my desktop\n')
        before = self.f.files()
        result, code = self.client.run('preview', ('fish', 'hyprland'))
        self.assertEqual((result['status'], code), ('blocked', 2))
        self.assertIsNone(self.client.ticket)
        self.assertEqual(self.f.files(), before)

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


if __name__ == '__main__':
    unittest.main()
