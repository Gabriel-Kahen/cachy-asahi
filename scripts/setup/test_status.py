# SPDX-License-Identifier: MIT
"""Read-only observations of real private files and genuinely interrupted transactions."""
import json
import os
from pathlib import Path
import stat
import unittest
from unittest import mock

import test_setup
import test_shell_modules
import test_recovery_preview

setup = test_setup.setup


class StatusTests(unittest.TestCase):
    setUp = test_setup.SetupTests.setUp
    target = test_setup.SetupTests.target
    put = test_setup.SetupTests.put
    state = test_setup.SetupTests.state
    env = test_shell_modules.ShellModuleTests.env
    cli = test_shell_modules.ShellModuleTests.cli
    crash = test_recovery_preview.RecoveryPreviewTests.crash

    def snapshot(self):
        result = {}
        for root in (self.home, self.templates):
            for path in (root, *sorted(root.rglob('*'))):
                item = path.lstat()
                content = (os.readlink(path) if stat.S_ISLNK(item.st_mode) else
                           path.read_bytes() if stat.S_ISREG(item.st_mode) and item.st_mode & 0o400 else None)
                result[str(path)] = (item.st_mode, item.st_uid, item.st_gid, item.st_ino,
                                     item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
                                     content, {key: os.getxattr(path, key, follow_symlinks=False)
                                               for key in os.listxattr(path, follow_symlinks=False)})
        return result

    def observe(self, components=(), expected=0, script=None):
        before = self.snapshot()
        result = self.cli('status', components, script=script)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['exit_code'], expected)
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['operation'], 'status')
        self.assertEqual(report['mode'], 'read-only')
        return report

    def actions(self, report):
        return {action['component']: action for action in report['actions']}

    def test_missing_state_all_components_and_no_directories_created(self):
        report = self.observe()
        self.assertEqual(report['state'], {'status': 'missing'})
        self.assertEqual(report['pending'], {'status': 'none', 'can_resume': False, 'actions': []})
        self.assertEqual([a['component'] for a in report['actions']], list(setup.ORDER))
        self.assertTrue(all(a['status'] == 'unmanaged' for a in report['actions']))
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual(report, self.observe())

    def test_selection_order_clean_records_and_unrelated_edits(self):
        self.put('fish', b'# private existing user code\n')
        self.engine.run('activate', setup.ALL_COMPONENTS, True)
        path = self.target('fish')
        path.write_bytes(b'# private added before\n' + path.read_bytes() + b'# private added after\n')
        os.setxattr(path, 'user.status-fixture', b'private metadata')
        report = self.observe(('zsh', 'fish', 'fish'))
        self.assertEqual([a['component'] for a in report['actions']], ['fish', 'zsh'])
        self.assertTrue(all(a['status'] == 'clean' and a['ownership'] == 'managed' for a in report['actions']))
        self.assertNotIn('private', json.dumps(report))
        self.assertTrue(all(a['status'] == 'clean' for a in self.observe()['actions']))

    def test_owned_file_and_block_drift_missing_and_duplicate_conflict(self):
        self.engine.run('activate', setup.ALL_COMPONENTS, True)
        self.target('hyprland').write_text('-- private changed config\n')
        self.target('zsh').unlink()
        text = self.target('fish').read_text()
        self.target('fish').write_text(text.replace('    source ', '    # private changed source ', 1))
        actions = self.actions(self.observe(expected=2))
        self.assertEqual(actions['hyprland']['status'], 'drifted')
        self.assertEqual(actions['fish']['status'], 'drifted')
        self.assertEqual(actions['zsh']['status'], 'missing')
        self.assertEqual(actions['fish-autopair']['status'], 'clean')
        self.target('fish').write_text(text + self.state()['components']['fish']['block'])
        self.assertEqual(self.actions(self.observe(('fish',), 2))['fish']['status'], 'conflicting')
        self.target('fish').write_text('# wholly replaced private content\n')
        self.assertEqual(self.actions(self.observe(('fish',), 2))['fish']['status'], 'missing')

    def test_unmanaged_content_never_adopted_even_if_template_matches(self):
        self.put('hyprland', (self.templates / setup.TEMPLATES['hyprland']).read_bytes())
        self.put('fish', setup.block('fish', self.templates / setup.TEMPLATES['fish']).encode())
        self.put('zsh', b'# ordinary private user config\n')
        actions = self.actions(self.observe(setup.COMPONENTS, 2))
        self.assertEqual(actions['fish']['status'], 'conflicting')
        self.assertEqual(actions['hyprland']['status'], 'conflicting')
        self.assertEqual(actions['zsh']['status'], 'unmanaged')
        self.assertTrue(all(a['ownership'] == 'unmanaged' for a in actions.values()))

    def test_reordered_managed_sources_conflict_without_repair(self):
        self.engine.run('activate', ('fish', 'fish-autopair'), True)
        records = self.state()['components']
        self.target('fish').write_text(records['fish-autopair']['block'] + records['fish']['block'])
        actions = self.observe(('fish-autopair', 'fish'), 2)['actions']
        self.assertTrue(all(a['reason'] == 'owned-block-order-changed' for a in actions))

    def test_missing_and_changed_templates_are_separate_from_ownership(self):
        self.engine.run('activate', setup.COMPONENTS, True)
        (self.templates / setup.TEMPLATES['fish']).unlink()
        (self.templates / setup.TEMPLATES['hyprland']).write_text('-- upgraded template\n')
        actions = self.actions(self.observe(setup.COMPONENTS, 2))
        self.assertTrue(all(a['status'] == 'clean' for a in actions.values()))
        self.assertEqual(actions['fish']['template'], 'missing')
        self.assertEqual(actions['hyprland']['template'], 'changed')

    def test_historical_shell_source_root_checked_instead_of_new_cli_root(self):
        self.engine.run('activate', ('fish',), True)
        other = self.root / 'new-templates'
        other.mkdir(mode=0o700)
        newer = setup.Setup(self.home, other)
        self.addCleanup(newer.close)
        self.assertEqual(newer.run('status', ('fish',))['actions'][0]['template'], 'available')
        (self.templates / setup.TEMPLATES['fish']).unlink()
        self.assertEqual(newer.run('status', ('fish',))['actions'][0]['template'], 'missing')

    def test_invalid_and_nonprivate_state_are_unknown_never_unmanaged(self):
        self.engine.run('activate', ('fish',), True)
        path = self.home / self.engine.state_path
        original = path.read_bytes()
        for raw in (b'{private-invalid', b'{}', b'[]',
                    original.replace(b'"schema_version": 1', b'"schema_version": 1.0'),
                    original.replace(b'"components": {', b'"components": {"unknown-component": {},')):
            path.write_bytes(raw)
            report = self.observe(('fish',), 1)
            self.assertEqual(report['state']['status'], 'unknown')
            self.assertEqual(report['actions'][0]['ownership'], 'unknown')
            self.assertEqual(report['actions'][0]['status'], 'unknown')
            self.assertNotIn('private-invalid', json.dumps(report))
        path.write_bytes(original)
        path.chmod(0o644)
        self.assertEqual(self.observe(('fish',), 1)['state']['status'], 'unknown')

    def test_unsafe_targets_and_unreadable_state_remain_unknown(self):
        self.engine.run('activate', ('fish',), True)
        state = self.home / self.engine.state_path
        state.chmod(0)
        self.assertEqual(self.observe(('fish',), 1)['state']['status'], 'unknown')
        state.chmod(0o600)
        target = self.target('fish')
        target.unlink()
        target.symlink_to(self.templates / setup.TEMPLATES['fish'])
        self.assertEqual(self.observe(('fish',), 1)['actions'][0]['status'], 'unknown')
        target.unlink()
        os.mkfifo(target, 0o600)
        self.assertEqual(self.observe(('fish',), 1)['actions'][0]['status'], 'unknown')

    def test_real_interrupted_activate_and_remove_readiness_matches_recover(self):
        for operation in ('activate', 'remove'):
            self.crash(operation, 'fish')
            report = self.observe(expected=2)
            self.assertEqual(report['pending']['status'], 'resumable')
            self.assertTrue(report['pending']['can_resume'])
            recovery = self.cli('recover')
            self.assertEqual(recovery.returncode, 2, recovery.stderr)
            self.assertEqual(report['pending']['actions'], json.loads(recovery.stdout)['actions'])
            self.assertEqual(self.cli('recover', apply=True).returncode, 0)
        self.assertEqual(self.observe()['state']['status'], 'valid')

    def test_real_interrupted_state_commit_is_resumable_without_rewriting(self):
        self.crash('activate', 'state')
        report = self.observe(expected=2)
        self.assertEqual(report['pending']['status'], 'resumable')
        self.assertTrue(all(a['status'] == 'already-applied' for a in report['pending']['actions']))
        self.assertTrue(all(a['status'] == 'clean' for a in report['actions']))

    def test_conflicting_interrupted_user_edit_blocks_recovery_without_leak(self):
        self.crash('activate', 'fish')
        self.target('fish').write_text('# private interruption edit\n')
        report = self.observe(expected=1)
        self.assertEqual(report['pending']['status'], 'blocked')
        self.assertFalse(report['pending']['can_resume'])
        self.assertNotIn('private interruption edit', json.dumps(report))
        self.assertEqual(self.cli('recover').returncode, 1)

    def test_changed_required_template_blocks_real_pending_transaction(self):
        self.crash('activate', 'journal')
        (self.templates / setup.TEMPLATES['hyprland']).write_text('-- changed required template\n')
        self.assertEqual(self.observe(expected=1)['pending']['status'], 'blocked')
        self.assertEqual(self.observe(('fish',), 1)['pending']['status'], 'blocked')
        self.assertEqual(self.cli('recover').returncode, 1)

    def test_status_apply_on_missing_state_is_refused_without_creating_storage(self):
        before = self.snapshot()
        result = self.cli('status', ('fish',), apply=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_missing_template_directory_creates_nothing(self):
        absent = self.root / 'absent-templates'
        engine = setup.Setup(self.home, absent)
        self.addCleanup(engine.close)
        before = self.snapshot()
        report = engine.run('status')
        self.assertTrue(all(a['template'] == 'missing' for a in report['actions']))
        self.assertFalse(absent.exists())
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(self.snapshot(), before)

    def test_unsafe_state_parent_and_duplicate_state_keys_are_explicit(self):
        self.engine.run('activate', ('fish',), True)
        path = self.home / self.engine.state_path
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'))
        self.assertEqual(self.observe(('fish',), 1)['state']['status'], 'unknown')
        path.write_bytes(original)
        path.parent.chmod(0o777)
        self.assertEqual(self.observe(('fish',), 1)['state']['status'], 'unknown')
        path.parent.chmod(0o700)

    def test_malformed_forged_and_unreadable_journals_are_unknown(self):
        self.crash('activate', 'journal')
        path = self.home / self.engine.journal_path
        original = path.read_bytes()
        forged = json.loads(original)
        forged['entries'][0]['path'] = '../private-escape'
        for raw in (b'{}', b'null', b'{"private-invalid":', json.dumps(forged).encode()):
            path.write_bytes(raw)
            report = self.observe(expected=1)
            self.assertEqual(report['pending']['status'], 'unknown')
            self.assertIsNone(report['pending']['can_resume'])
            self.assertNotIn('private-escape', json.dumps(report))
        path.write_bytes(original)
        path.chmod(0)
        self.assertEqual(self.observe(expected=1)['pending']['status'], 'unknown')
        path.chmod(0o600)

    def test_no_lock_write_or_replay_even_with_existing_writer_lock(self):
        self.engine.run('activate', ('fish',), True)
        lock = self.engine.fs.lock(self.engine.lock_path)
        self.addCleanup(os.close, lock)
        self.observe(('fish',))
        with (mock.patch.object(self.engine.fs, 'lock', side_effect=AssertionError('lock')),
              mock.patch.object(self.engine.fs, 'atomic', side_effect=AssertionError('write')),
              mock.patch.object(self.engine, 'save', side_effect=AssertionError('save')),
              mock.patch.object(self.engine, 'replay', side_effect=AssertionError('replay'))):
            self.assertEqual(self.engine.run('status', ('fish',))['exit_code'], 0)
        before = self.snapshot()
        result = self.cli('status', ('fish',), apply=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Status is read-only', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_packaged_and_canonical_cli_are_byte_identical_and_reports_equal(self):
        packaged = Path(setup.__file__).parents[2] / 'packages/settings/cachy-asahi-setup/cachy-asahi-setup'
        self.assertEqual(packaged.read_bytes(), Path(setup.__file__).read_bytes())
        self.engine.run('activate', ('fish',), True)
        self.assertEqual(self.observe(('fish',)), self.observe(('fish',), script=packaged))


if __name__ == '__main__':
    unittest.main(verbosity=2)
