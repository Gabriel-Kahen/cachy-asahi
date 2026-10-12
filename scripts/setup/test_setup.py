# SPDX-License-Identifier: MIT
"""Temporary-user lifecycle fixtures only. No package installation or real HOME writes."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('cachy_asahi_setup', Path(__file__).with_name('setup.py'))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class Interrupted(Exception):
    pass


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cachy-asahi-setup-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'user'
        self.home.mkdir(mode=0o700)
        self.templates = self.root / 'templates'
        self.templates.mkdir(mode=0o700)
        for component, name in setup.TEMPLATES.items():
            path = self.templates / name
            path.parent.mkdir(mode=0o700)
            path.write_text(f'# fixture {component}\n')
        self.engine = setup.Setup(self.home, self.templates)
        self.addCleanup(self.engine.close)

    def target(self, component):
        return self.home / self.engine.targets[component]

    def put(self, component, content, mode=0o600):
        path = self.target(component)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def state(self):
        return json.loads((self.home / self.engine.state_path).read_text())

    def snapshot(self):
        return {str(p.relative_to(self.home)): (p.read_bytes(), p.stat().st_mode)
                for p in self.home.rglob('*') if p.is_file() and not p.is_symlink()}

    def interrupt(self, operation, component, after_write=True):
        original = self.engine.fs.atomic
        path = self.engine.targets[component]
        def injected(target, data, expected, private=False):
            if target == path and not after_write:
                raise Interrupted()
            result = original(target, data, expected, private)
            if target == path and after_write:
                raise Interrupted()
            return result
        with mock.patch.object(self.engine.fs, 'atomic', side_effect=injected):
            with self.assertRaises(Interrupted):
                self.engine.run(operation, setup.COMPONENTS, apply=True)
        self.assertTrue((self.home / self.engine.journal_path).is_file())

    def test_preview_has_no_writes_or_state_directories(self):
        before = list(self.home.iterdir())
        report = self.engine.run('activate', setup.COMPONENTS)
        self.assertEqual(report['mode'], 'preview')
        self.assertEqual(len(report['actions']), 3)
        self.assertEqual(list(self.home.iterdir()), before)
        self.assertFalse((self.home / '.local').exists())

    def test_fresh_activation_repeated_setup_remove_and_reinstall(self):
        self.engine.run('activate', setup.COMPONENTS, apply=True)
        first = self.snapshot()
        report = self.engine.run('activate', setup.COMPONENTS, apply=True)
        self.assertTrue(all(a['status'] == 'unchanged' for a in report['actions']))
        self.assertEqual(self.snapshot(), first)
        self.engine.run('remove', apply=True)
        self.assertTrue(all(not self.target(c).exists() for c in setup.COMPONENTS))
        self.assertEqual(self.state()['components'], {})
        self.engine.run('remove', apply=True)
        self.engine.run('activate', setup.COMPONENTS, apply=True)
        self.assertTrue(all(self.target(c).exists() for c in setup.COMPONENTS))

    def test_existing_shell_bytes_and_permissions_preserved_after_removal(self):
        originals = {'fish': b'# old fish without trailing newline', 'zsh': b'# old zsh\n'}
        for component, content in originals.items():
            self.put(component, content, 0o640)
        self.engine.run('activate', ('fish', 'zsh'), apply=True)
        for component, content in originals.items():
            self.assertTrue(self.target(component).read_bytes().startswith(content))
            self.assertEqual(self.target(component).stat().st_mode & 0o777, 0o640)
        self.engine.run('remove', apply=True)
        for component, content in originals.items():
            self.assertEqual(self.target(component).read_bytes(), content)

    def test_existing_empty_shell_files_are_not_removed(self):
        for component in ('fish', 'zsh'):
            self.put(component, b'')
        self.engine.run('activate', ('fish', 'zsh'), apply=True)
        self.engine.run('remove', apply=True)
        for component in ('fish', 'zsh'):
            self.assertEqual(self.target(component).read_bytes(), b'')

    def test_existing_hyprland_file_is_never_adopted_or_overwritten(self):
        content = (self.templates / setup.TEMPLATES['hyprland']).read_bytes()
        self.put('hyprland', content)
        report = self.engine.run('activate', ('hyprland',), apply=True)
        self.assertEqual(report['actions'][0]['status'], 'preserved-existing')
        self.engine.run('remove', ('hyprland',), apply=True)
        self.assertEqual(self.target('hyprland').read_bytes(), content)

    def test_base_hyprland_rc_is_untouched_and_not_launched(self):
        path = self.home / '.config/hypr/hyprland.conf'
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_text('base-launcher-config\n')
        with mock.patch.object(subprocess, 'run', side_effect=AssertionError('No child process allowed')):
            report = self.engine.run('activate', ('hyprland',), apply=True)
        self.assertEqual(path.read_text(), 'base-launcher-config\n')
        self.assertTrue(any('UWSM' in line for line in report['guidance']))
        self.assertNotEqual(self.target('hyprland'), path)

    def test_unrelated_user_edits_survive_block_removal_and_repeat(self):
        self.put('zsh', b'# user before\n')
        self.engine.run('activate', ('zsh',), apply=True)
        path = self.target('zsh')
        path.write_bytes(b'# newly added before\n' + path.read_bytes() + b'# new user after\n')
        before = path.read_bytes()
        self.engine.run('activate', ('zsh',), apply=True)
        self.assertEqual(path.read_bytes(), before)
        self.engine.run('remove', apply=True)
        self.assertEqual(path.read_bytes(), b'# newly added before\n# user before\n# new user after\n')

    def test_missing_newline_separator_keeps_later_user_code_separate(self):
        self.put('fish', b'# user original')
        self.engine.run('activate', ('fish',), apply=True)
        path = self.target('fish')
        path.write_bytes(path.read_bytes() + b'echo user-added\n')
        self.engine.run('remove', apply=True)
        self.assertEqual(path.read_bytes(), b'# user original\necho user-added\n')

    def test_edited_owned_blocks_and_hyprland_are_preserved(self):
        self.engine.run('activate', setup.COMPONENTS, apply=True)
        self.target('fish').write_text(self.target('fish').read_text().replace('source ', '# edited source '))
        self.target('hyprland').write_text('-- user edited\n')
        expected = {c: self.target(c).read_bytes() for c in ('fish', 'hyprland')}
        report = self.engine.run('remove', apply=True)
        self.assertTrue(report['preserved_conflicts'])
        self.assertFalse(self.target('zsh').exists())
        for component, content in expected.items():
            self.assertEqual(self.target(component).read_bytes(), content)
            self.assertIn(component, self.state()['components'])
        self.engine.run('activate', ('fish', 'hyprland'), apply=True)
        for component, content in expected.items():
            self.assertEqual(self.target(component).read_bytes(), content)

    def test_template_upgrade_updates_only_unchanged_owned_file(self):
        self.engine.run('activate', ('hyprland',), apply=True)
        source = self.templates / setup.TEMPLATES['hyprland']
        source.write_text('-- updated template\n')
        report = self.engine.run('activate', ('hyprland',), apply=True)
        self.assertEqual(report['actions'][0]['status'], 'update')
        self.assertEqual(self.target('hyprland').read_bytes(), source.read_bytes())
        self.target('hyprland').write_text('-- user edited\n')
        source.write_text('-- second template update\n')
        self.engine.run('activate', ('hyprland',), apply=True)
        self.assertEqual(self.target('hyprland').read_text(), '-- user edited\n')

    def test_interrupted_activation_resumes_after_first_atomic_write(self):
        self.interrupt('activate', 'fish')
        self.assertTrue(self.target('fish').exists())
        preview = self.engine.run('activate', setup.COMPONENTS)
        self.assertIn('pending_transaction', preview)
        report = self.engine.run('activate', setup.COMPONENTS, apply=True)
        self.assertTrue(report['recovered_transaction'])
        self.assertFalse((self.home / self.engine.journal_path).exists())
        self.assertTrue(all(self.target(c).exists() for c in setup.COMPONENTS))

    def test_interrupted_before_first_write_resumes(self):
        self.interrupt('activate', 'fish', after_write=False)
        self.assertFalse(self.target('fish').exists())
        self.engine.run('recover', apply=True)
        self.assertTrue(all(self.target(c).exists() for c in setup.COMPONENTS))

    def test_interrupted_removal_resumes_and_reinstall_works(self):
        self.engine.run('activate', setup.COMPONENTS, apply=True)
        self.interrupt('remove', 'fish')
        self.assertFalse(self.target('fish').exists())
        self.engine.run('recover', apply=True)
        self.assertTrue(all(not self.target(c).exists() for c in setup.COMPONENTS))
        self.engine.run('activate', setup.COMPONENTS, apply=True)
        self.assertTrue(self.target('hyprland').is_file())

    def test_edit_after_interruption_stops_recovery_without_clobber(self):
        self.interrupt('activate', 'fish')
        self.target('fish').write_text('# edit after interruption\n')
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'user edits preserved'):
            self.engine.run('recover', apply=True)
        self.assertEqual(self.snapshot(), before)

    def test_removal_works_after_packages_disappear(self):
        self.engine.run('activate', setup.COMPONENTS, apply=True)
        shutil.rmtree(self.templates)
        self.engine.run('remove', apply=True)
        self.assertTrue(all(not self.target(c).exists() for c in setup.COMPONENTS))

    def test_preexisting_untracked_marker_is_not_duplicated(self):
        original = setup.block('zsh', self.templates / setup.TEMPLATES['zsh']).encode()
        self.put('zsh', original)
        report = self.engine.run('activate', ('zsh',), apply=True)
        self.assertEqual(report['actions'][0]['status'], 'preserved-existing')
        self.engine.run('remove', ('zsh',), apply=True)
        self.assertEqual(self.target('zsh').read_bytes(), original)

    def test_symlink_file_parent_template_and_state_are_rejected(self):
        external = self.root / 'private'
        external.write_text('credentials must not be read or changed')
        path = self.target('zsh')
        path.symlink_to(external)
        with self.assertRaises(OSError):
            self.engine.run('activate', ('zsh',))
        path.unlink()
        (self.home / '.config').symlink_to(self.templates, target_is_directory=True)
        with self.assertRaises(OSError):
            self.engine.run('activate', ('fish',), apply=True)
        (self.home / '.config').unlink()
        source = self.templates / setup.TEMPLATES['zsh']
        source.unlink()
        source.symlink_to(external)
        with self.assertRaises(OSError):
            self.engine.run('activate', ('zsh',))
        source.unlink()
        source.write_text('# restored')
        state = self.home / self.engine.state_path
        state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        state.symlink_to(external)
        with self.assertRaises(OSError):
            self.engine.run('remove')
        self.assertEqual(external.read_text(), 'credentials must not be read or changed')

    def test_hardlinks_fifo_and_writable_permissions_rejected(self):
        path = self.put('zsh', b'config')
        os.link(path, self.home / 'also-config')
        with self.assertRaisesRegex(setup.Error, 'singly linked'):
            self.engine.run('activate', ('zsh',))
        (self.home / 'also-config').unlink()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(setup.Error, 'regular'):
            self.engine.run('activate', ('zsh',))
        path.unlink()
        self.put('zsh', b'config', 0o666)
        with self.assertRaisesRegex(setup.Error, 'permissions'):
            self.engine.run('activate', ('zsh',))

    def test_path_escape_invalid_root_and_metadata_target_tampering(self):
        for config in ('../outside', '/outside', 'bad\npath'):
            with self.assertRaises(setup.Error):
                setup.Setup(self.home, self.templates, config=config)
        self.engine.run('activate', ('zsh',), apply=True)
        state_path = self.home / self.engine.state_path
        state = self.state()
        state['components']['zsh']['path'] = '.ssh/authorized_keys'
        state_path.write_text(json.dumps(state))
        with self.assertRaisesRegex(setup.Error, 'Unrecognized'):
            self.engine.run('remove', apply=True)
        self.assertFalse((self.home / '.ssh').exists())

    def test_no_user_configuration_content_in_journal_state_or_reports(self):
        credential = 'USER_SECRET_never_persist_as_evidence'
        self.put('zsh', ('# ' + credential + '\n').encode())
        self.interrupt('activate', 'fish')
        journal = (self.home / self.engine.journal_path).read_text()
        report = json.dumps(self.engine.run('recover'))
        self.assertNotIn(credential, journal + report)
        self.engine.run('recover', apply=True)
        self.assertNotIn(credential, (self.home / self.engine.state_path).read_text())

    def test_config_roots_and_template_path_with_quotes_spaces(self):
        templates = self.root / "template user's files"
        self.templates.rename(templates)
        engine = setup.Setup(self.home, templates, config='config space', zsh='zsh place')
        try:
            engine.run('activate', ('fish', 'zsh'), apply=True)
            for component in ('fish', 'zsh'):
                data = (self.home / engine.targets[component]).read_text()
                self.assertIn(setup.shlex.quote(str(templates / setup.TEMPLATES[component])), data)
                self.assertNotIn('\n' + str(templates), data)
            engine.run('remove', apply=True)
        finally:
            engine.close()

    @unittest.skipUnless(os.getuid() != 0, 'CLI intentionally refuses root; filesystem engine fixtures remain valid')
    def test_cli_preview_and_error_output_does_not_leak_config(self):
        secret = 'PRIVATE_CONFIG_SENTINEL'
        self.put('zsh', secret.encode())
        out, err = io.StringIO(), io.StringIO()
        argv = ['setup.py', 'activate', '--components', 'zsh', '--home', str(self.home), '--template-root', str(self.templates)]
        with mock.patch.object(setup.sys, 'argv', argv), mock.patch.object(setup.os, 'geteuid', return_value=os.getuid()), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = setup.main()
        self.assertEqual(result, 0)
        self.assertNotIn(secret, out.getvalue() + err.getvalue())
        self.assertEqual(self.target('zsh').read_bytes(), secret.encode())

    def test_interruption_after_state_commit_replays_without_duplicate_blocks(self):
        original = self.engine.fs.atomic
        def injected(target, data, expected, private=False):
            result = original(target, data, expected, private)
            if target == self.engine.state_path:
                raise Interrupted()
            return result
        with mock.patch.object(self.engine.fs, 'atomic', side_effect=injected):
            with self.assertRaises(Interrupted):
                self.engine.run('activate', setup.COMPONENTS, apply=True)
        expected = {c: self.target(c).read_bytes() for c in setup.COMPONENTS}
        self.engine.run('recover', apply=True)
        for c, content in expected.items():
            self.assertEqual(self.target(c).read_bytes(), content)
        self.assertFalse((self.home / self.engine.journal_path).exists())

    def test_parallel_apply_is_rejected_with_no_config_change(self):
        lock = self.engine.fs.lock(self.engine.lock_path)
        try:
            with self.assertRaisesRegex(setup.Error, 'Another setup command'):
                self.engine.run('activate', ('zsh',), apply=True)
            self.assertFalse(self.target('zsh').exists())
        finally:
            os.close(lock)

    def test_pending_template_change_refuses_to_guess(self):
        self.interrupt('activate', 'fish')
        (self.templates / setup.TEMPLATES['hyprland']).write_text('-- template upgraded while interrupted\n')
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'Pending template changed'):
            self.engine.run('recover', apply=True)
        self.assertEqual(self.snapshot(), before)

    def test_tampered_pending_block_and_target_never_get_applied(self):
        self.interrupt('activate', 'fish', after_write=False)
        journal_path = self.home / self.engine.journal_path
        original = json.loads(journal_path.read_text())
        for key, value in (('path', '.ssh/authorized_keys'), ('change', {'type': 'append', 'new': 'untrusted executable text'})):
            journal = json.loads(json.dumps(original))
            journal['entries'][0][key] = value
            journal_path.write_text(json.dumps(journal))
            with self.assertRaises(setup.Error):
                self.engine.run('recover', apply=True)
        self.assertFalse(self.target('fish').exists())
        self.assertFalse((self.home / '.ssh').exists())

    def test_group_writable_home_and_private_state_mode_are_rejected(self):
        self.home.chmod(0o770)
        with self.assertRaisesRegex(setup.Error, 'Directory ownership'):
            setup.Setup(self.home, self.templates)
        self.home.chmod(0o700)
        self.engine.run('activate', ('zsh',), apply=True)
        state = self.home / self.engine.state_path
        state.chmod(0o644)
        with self.assertRaisesRegex(setup.Error, 'must be private'):
            self.engine.run('remove', apply=True)

    @unittest.skipUnless(shutil.which('fish') and shutil.which('zsh'), 'Actual shell interpreters not installed')
    def test_real_shell_guards_with_quoted_paths_and_disappeared_templates(self):
        templates = self.root / "template user's files"
        self.templates.rename(templates)
        engine = setup.Setup(self.home, templates)
        self.addCleanup(engine.close)
        for component in ('fish', 'zsh'):
            (templates / setup.TEMPLATES[component]).write_text("printf '%s\\n' loaded\n")
            self.put(component, b'')
        engine.run('activate', ('fish', 'zsh'), apply=True)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'TERM': 'dumb',
               'XDG_CONFIG_HOME': str(self.home / '.config'), 'XDG_DATA_HOME': str(self.home / '.local/share'),
               'XDG_STATE_HOME': str(self.home / '.local/state'), 'ZDOTDIR': str(self.home)}
        for component in ('fish', 'zsh'):
            path = self.home / engine.targets[component]
            syntax = ['fish', '--no-config', '--no-execute', str(path)] if component == 'fish' else ['zsh', '-dfn', str(path)]
            result = subprocess.run(syntax, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            command = 'source ' + setup.shlex.quote(str(path))
            run = ['fish', '--no-config', '--private', '--interactive', '--command', command] if component == 'fish' else ['zsh', '-dfi', '-c', command]
            result = subprocess.run(run, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'loaded\n')
        shutil.rmtree(templates)
        for component in ('fish', 'zsh'):
            command = 'source ' + setup.shlex.quote(str(self.home / engine.targets[component]))
            run = ['fish', '--no-config', '--private', '--interactive', '--command', command] if component == 'fish' else ['zsh', '-dfi', '-c', command]
            result = subprocess.run(run, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
        engine.run('remove', apply=True)

    def test_pending_changed_template_fails_before_any_new_config_write(self):
        self.interrupt('activate', 'fish', after_write=False)
        (self.templates / setup.TEMPLATES['hyprland']).write_text('-- changed template\n')
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'Pending template changed'):
            self.engine.run('recover', apply=True)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.target('fish').exists())

    def test_preserves_existing_extended_attributes(self):
        path = self.put('zsh', b'# config\n')
        try:
            os.setxattr(path, 'user.fixture', b'original metadata')
        except OSError:
            self.skipTest('Filesystem lacks user extended attributes')
        self.engine.run('activate', ('zsh',), apply=True)
        self.assertEqual(os.getxattr(path, 'user.fixture'), b'original metadata')
        self.engine.run('remove', apply=True)
        self.assertEqual(os.getxattr(path, 'user.fixture'), b'original metadata')

    def test_cli_root_refusal_without_any_filesystem_operation(self):
        argv = ['setup.py', 'activate', '--components', 'zsh', '--home', str(self.home), '--apply']
        output = io.StringIO()
        with mock.patch.object(setup.sys, 'argv', argv), mock.patch.object(setup.os, 'geteuid', return_value=0), \
             mock.patch.object(setup, 'Setup') as initialized, contextlib.redirect_stderr(output):
            self.assertEqual(setup.main(), 1)
            initialized.assert_not_called()
        self.assertIn('non-root', output.getvalue())

    def test_coherent_pending_shell_root_retargeting_refused_before_any_write(self):
        self.interrupt('activate', 'fish', after_write=False)
        journal_path = self.home / self.engine.journal_path
        original = json.loads(journal_path.read_text())
        unapproved = self.root / 'unapproved-templates'
        for component in ('fish', 'zsh'):
            journal = json.loads(json.dumps(original))
            entry = next(e for e in journal['entries'] if e['component'] == component)
            retargeted = setup.block(component, unapproved / setup.TEMPLATES[component])
            entry['new_record']['source_root'] = str(unapproved)
            entry['new_record']['block'] = retargeted
            entry['change']['new'] = retargeted
            entry['after'] = setup.checksum(retargeted.encode())
            journal['new_state']['components'][component] = dict(entry['new_record'])
            journal_path.write_text(json.dumps(journal))
            before = self.snapshot()
            with self.assertRaisesRegex(setup.Error, 'approved template root'):
                self.engine.run('recover', apply=True)
            self.assertEqual(self.snapshot(), before)
            self.assertTrue(all(not self.target(c).exists() for c in setup.COMPONENTS))

    def test_pending_unapproved_record_without_entry_is_not_adopted(self):
        self.interrupt('activate', 'fish', after_write=False)
        journal_path = self.home / self.engine.journal_path
        journal = json.loads(journal_path.read_text())
        journal['entries'] = [e for e in journal['entries'] if e['component'] != 'zsh']
        root = self.root / 'unapproved-root'
        record = journal['new_state']['components']['zsh']
        record['source_root'] = str(root)
        record['block'] = setup.block('zsh', root / setup.TEMPLATES['zsh'])
        journal_path.write_text(json.dumps(journal))
        with self.assertRaisesRegex(setup.Error, 'approved template root'):
            self.engine.run('recover', apply=True)
        self.assertTrue(all(not self.target(c).exists() for c in setup.COMPONENTS))

    def test_template_root_switch_updates_only_selected_owned_shell_block(self):
        self.engine.run('activate', ('fish', 'zsh'), apply=True)
        fish = self.target('fish').read_bytes()
        approved = self.root / 'new-approved-root'
        shutil.copytree(self.templates, approved)
        engine = setup.Setup(self.home, approved)
        self.addCleanup(engine.close)
        engine.run('activate', ('zsh',), apply=True)
        self.assertEqual(self.target('fish').read_bytes(), fish)
        self.assertIn(setup.shlex.quote(str(approved / setup.TEMPLATES['zsh'])), self.target('zsh').read_text())
        engine.run('remove', apply=True)
        self.assertFalse(self.target('fish').exists())
        self.assertFalse(self.target('zsh').exists())

    def test_shell_post_delta_exact_limit_stays_removable(self):
        block_size = len(setup.block('fish', self.templates / setup.TEMPLATES['fish']).encode())
        original = b'#' + b'x' * (setup.MAX_BYTES - block_size - 2) + b'\n'
        self.put('fish', original)
        self.engine.run('activate', ('fish',), apply=True)
        self.assertEqual(len(self.target('fish').read_bytes()), setup.MAX_BYTES)
        self.engine.run('remove', apply=True)
        self.assertEqual(self.target('fish').read_bytes(), original)

    def test_shell_post_delta_over_limit_rejected_without_journal_or_config_write(self):
        block_size = len(setup.block('fish', self.templates / setup.TEMPLATES['fish']).encode())
        for before_size in (setup.MAX_BYTES - block_size + 1, setup.MAX_BYTES):
            original = b'#' + b'x' * (before_size - 2) + b'\n'
            self.put('fish', original)
            for apply in (False, True):
                with self.assertRaisesRegex(setup.Error, 'Proposed configuration exceeds size limit'):
                    self.engine.run('activate', setup.COMPONENTS, apply=apply)
                self.assertEqual(self.target('fish').read_bytes(), original)
                self.assertFalse(self.target('hyprland').exists())
                self.assertFalse(self.target('zsh').exists())
                self.assertFalse((self.home / self.engine.journal_path).exists())

    def test_pending_oversized_later_delta_fails_before_earlier_writes(self):
        self.put('zsh', b'# original\n')
        self.interrupt('activate', 'fish', after_write=False)
        original = b'#' + b'x' * (setup.MAX_BYTES - 2) + b'\n'
        self.put('zsh', original)
        journal_path = self.home / self.engine.journal_path
        journal = json.loads(journal_path.read_text())
        entry = next(e for e in journal['entries'] if e['component'] == 'zsh')
        entry['before'] = setup.checksum(original)
        entry['after'] = setup.checksum(original + entry['change']['new'].encode())
        journal_path.write_text(json.dumps(journal))
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'Proposed configuration exceeds size limit'):
            self.engine.run('recover', apply=True)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.target('fish').exists())
        self.assertFalse(self.target('hyprland').exists())

    def test_atomic_writer_checks_size_before_directory_creation(self):
        path = 'must-not-create/config'
        with self.assertRaisesRegex(setup.Error, 'Proposed configuration exceeds size limit'):
            self.engine.fs.atomic(path, b'x' * (setup.MAX_BYTES + 1), None)
        self.assertFalse((self.home / 'must-not-create').exists())

    def test_copied_file_at_size_limit_removable_and_over_limit_refused(self):
        source = self.templates / setup.TEMPLATES['hyprland']
        source.write_bytes(b'-' * (setup.MAX_BYTES - 1) + b'\n')
        self.engine.run('activate', ('hyprland',), apply=True)
        self.assertEqual(len(self.target('hyprland').read_bytes()), setup.MAX_BYTES)
        self.engine.run('remove', apply=True)
        self.assertFalse(self.target('hyprland').exists())
        source.write_bytes(b'-' * setup.MAX_BYTES + b'\n')
        with self.assertRaisesRegex(setup.Error, 'size'):
            self.engine.run('activate', ('hyprland',), apply=True)
        self.assertFalse(self.target('hyprland').exists())

    def test_pending_changed_record_must_use_current_root_even_if_old_root_was_approved(self):
        self.engine.run('activate', ('fish', 'zsh'), apply=True)
        prior_record = dict(self.state()['components']['zsh'])
        approved = self.root / 'new-approved-root'
        shutil.copytree(self.templates, approved)
        engine = setup.Setup(self.home, approved)
        self.addCleanup(engine.close)
        original_atomic = engine.fs.atomic
        def injected(path, data, expected, private=False):
            if path == engine.targets['zsh']:
                raise Interrupted()
            return original_atomic(path, data, expected, private)
        with mock.patch.object(engine.fs, 'atomic', side_effect=injected):
            with self.assertRaises(Interrupted):
                engine.run('activate', ('zsh',), apply=True)
        journal_path = self.home / engine.journal_path
        journal = json.loads(journal_path.read_text())
        entry = journal['entries'][0]
        entry['new_record'] = prior_record
        entry['change']['new'] = prior_record['block']
        entry['after'] = entry['before']
        journal['new_state']['components']['zsh'] = prior_record
        journal_path.write_text(json.dumps(journal))
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'approved template root'):
            engine.run('recover', apply=True)
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
