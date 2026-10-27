# SPDX-License-Identifier: MIT
"""Real temporary-home migrations against the existing setup ownership contract."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

# Works both in the proposal tree and after the two scripts are integrated.
HERE = Path(__file__).resolve().parent
CONTRACT_DIR = next(p / 'scripts/setup' for p in HERE.parents
                    if (p / 'scripts/setup/setup.py').is_file())
spec = importlib.util.spec_from_file_location('setup', CONTRACT_DIR / 'setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
spec = importlib.util.spec_from_file_location('config_migrate', HERE / 'config_migrate.py')
migrate = importlib.util.module_from_spec(spec)
with mock.patch.dict(sys.modules, {'setup': setup}):
    spec.loader.exec_module(migrate)


class Interrupted(BaseException):
    pass


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cachy-migration-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'user'
        self.home.mkdir(mode=0o700)
        self.old, self.new = self.root / 'v1', self.root / 'v2'
        for root in (self.old, self.new):
            root.mkdir(mode=0o700)
            for name, relative in setup.TEMPLATES.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_text(f'# {name} {root.name}\n')
        self.owner = setup.Setup(self.home, self.old)
        self.addCleanup(self.owner.close)
        self.put('fish', b'# user fish\n')
        self.put('zsh', b'# user zsh without newline')
        self.owner.run('activate', setup.ALL_COMPONENTS, apply=True)
        self.manifest = {'schema_version': 1, 'id': 'release-1-to-2',
                         'package': 'cachy-asahi-fixture', 'from_version': '1.0-1',
                         'to_version': '2.0-1', 'entries': []}
        for name in setup.ALL_COMPONENTS:
            self.manifest['entries'].append({'component': name,
                'old': {'root': str(self.old), 'sha256': setup.checksum((self.old / setup.TEMPLATES[name]).read_bytes())},
                'new': {'root': str(self.new), 'sha256': setup.checksum((self.new / setup.TEMPLATES[name]).read_bytes())}})
        self.manifest_path = self.root / 'migration.json'
        self.engine = self.make_engine()

    def make_engine(self, manifest=None):
        self.manifest_path.write_bytes(migrate.encode(manifest or self.manifest))
        digest = setup.checksum(self.manifest_path.read_bytes())
        engine = migrate.Migration(self.home, self.manifest_path, digest)
        self.addCleanup(engine.close)
        return engine

    def put(self, component, data):
        path = self.home / self.owner.targets[component]
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        return path

    def target(self, component):
        return self.home / self.owner.targets[component]

    def snapshot(self):
        return {str(p.relative_to(self.home)): (p.read_bytes(), p.stat().st_mode)
                for p in self.home.rglob('*') if p.is_file() and not p.is_symlink()}

    def interrupt(self, path, after=True):
        atomic = self.engine.fs.atomic
        def injected(target, data, expected, private=False):
            if target == path and not after:
                raise Interrupted()
            result = atomic(target, data, expected, private)
            if target == path and after:
                raise Interrupted()
            return result
        with mock.patch.object(self.engine.fs, 'atomic', side_effect=injected):
            with self.assertRaises(Interrupted):
                self.engine.run('apply')
        self.assertTrue((self.home / self.owner.journal_path).exists())

    def test_preview_and_status_are_read_only(self):
        before = self.snapshot()
        for operation in ('preview', 'status'):
            self.assertEqual(self.engine.run(operation)['status'], 'ready')
            self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.home / self.engine.ledger_path).exists())

    def test_apply_shared_shell_files_preserves_outside_edits_and_removal(self):
        for name in ('fish', 'zsh'):
            with self.target(name).open('ab') as stream:
                stream.write(b'# later user code\n')
        self.assertEqual(self.engine.run('apply')['status'], 'applied')
        for name in ('fish', 'zsh'):
            data = self.target(name).read_text()
            self.assertIn('# later user code\n', data)
            self.assertIn(str(self.new), data)
            self.assertNotIn(str(self.old), data)
            for component in (name,) + tuple(c for c in setup.MODULES if c.startswith(name + '-')):
                self.assertEqual(data.count(setup.markers(component)[0]), 1)
        self.assertEqual(self.target('hyprland').read_bytes(), (self.new / setup.TEMPLATES['hyprland']).read_bytes())
        before = self.snapshot()
        self.assertEqual(self.engine.run('apply')['status'], 'already-applied')
        self.assertEqual(self.snapshot(), before)
        new_owner = setup.Setup(self.home, self.new)
        self.addCleanup(new_owner.close)
        new_owner.run('remove', apply=True)
        self.assertEqual(self.target('fish').read_bytes(), b'# user fish\n# later user code\n')
        self.assertEqual(self.target('zsh').read_bytes(), b'# user zsh without newline\n# later user code\n')
        self.assertFalse(self.target('hyprland').exists())
        with self.assertRaisesRegex(setup.Error, 'was removed'):
            self.engine.run('apply')
        new_owner.run('activate', setup.ALL_COMPONENTS, apply=True)
        self.assertEqual(self.engine.run('apply')['status'], 'already-applied')

    def test_managed_user_edits_and_duplicate_markers_refuse_all_changes(self):
        original = self.target('zsh').read_bytes()
        for data in (original.replace(b'source ', b'# user changed source ', 1),
                     original + setup.markers('zsh')[0].encode()):
            self.target('zsh').write_bytes(data)
            before = self.snapshot()
            for operation in ('preview', 'apply', 'status'):
                with self.assertRaisesRegex(setup.Error, 'edited|duplicated'):
                    self.engine.run(operation)
                self.assertEqual(self.snapshot(), before)
            self.assertFalse((self.home / self.owner.journal_path).exists())

    def test_edited_owned_file_refuses_without_touching_other_files(self):
        self.target('hyprland').write_bytes(b'# user customized\n')
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'file edited'):
            self.engine.run('apply')
        self.assertEqual(self.snapshot(), before)

    def test_missing_new_or_changed_old_input_refuses_preflight(self):
        for path in (self.new / setup.TEMPLATES['zsh'], self.old / setup.TEMPLATES['fish']):
            original = path.read_bytes()
            path.write_bytes(b'# unexpected content\n')
            before = self.snapshot()
            with self.assertRaisesRegex(setup.Error, 'hash differs'):
                self.engine.run('apply')
            self.assertEqual(self.snapshot(), before)
            path.write_bytes(original)

    def test_wrong_manifest_hash_and_duplicate_keys(self):
        with self.assertRaisesRegex(setup.Error, 'hash differs'):
            migrate.Migration(self.home, self.manifest_path, '0' * 64)
        self.manifest_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(setup.Error, 'Invalid migration manifest'):
            migrate.Migration(self.home, self.manifest_path, setup.checksum(self.manifest_path.read_bytes()))

    def test_finite_manifest_rejects_unknown_duplicate_and_paths(self):
        variants = []
        for change in ('unknown', 'duplicate', 'extra', 'traversal', 'bool', 'empty'):
            value = copy.deepcopy(self.manifest)
            if change == 'unknown':value['entries'][0]['component'] = 'ssh'
            if change == 'duplicate':value['entries'][1] = value['entries'][0]
            if change == 'extra':value['entries'][0]['target'] = '.ssh/authorized_keys'
            if change == 'traversal':value['entries'][0]['new']['root'] = str(self.root) + '/../v2'
            if change == 'bool':value['schema_version'] = True
            if change == 'empty':value['entries'] = []
            variants.append(value)
        for value in variants:
            with self.subTest(value=value):
                with self.assertRaises(setup.Error):self.make_engine(value)

    def test_recovery_at_each_durable_boundary(self):
        # A separate fixture is needed for each boundary because recovery completes it.
        for path in (self.owner.journal_path, self.owner.targets['fish'],
                     self.owner.targets['hyprland'], self.owner.targets['zsh'],
                     self.owner.state_path, self.engine.ledger_path):
            for after in (False, True):
                if path == self.owner.journal_path and not after:
                    continue
                with self.subTest(path=path, after=after):
                    with tempfile.TemporaryDirectory(dir=self.root) as directory:
                        home = Path(directory)
                        shutil.copytree(self.home, home, dirs_exist_ok=True)
                        engine = migrate.Migration(home, self.manifest_path, self.engine.manifest_sha256)
                        self.addCleanup(engine.close)
                        atomic = engine.fs.atomic
                        def injected(target, data, expected, private=False):
                            if target == path and not after:raise Interrupted()
                            result = atomic(target, data, expected, private)
                            if target == path and after:raise Interrupted()
                            return result
                        with mock.patch.object(engine.fs, 'atomic', side_effect=injected):
                            with self.assertRaises(Interrupted):engine.run('apply')
                        self.assertEqual(engine.run('status')['status'], 'pending')
                        with self.assertRaisesRegex(setup.Error, 'explicit recover'):engine.run('apply')
                        self.assertEqual(engine.run('recover')['status'], 'recovered')
                        self.assertFalse((home / engine.setup.journal_path).exists())
                        self.assertEqual(engine.run('apply')['status'], 'already-applied')
                        self.assertEqual(engine.run('recover')['status'], 'no-pending-transaction')

    def test_edit_after_interruption_refuses_all_remaining_writes(self):
        self.interrupt(self.owner.targets['fish'])
        with self.target('zsh').open('ab') as stream:stream.write(b'# edit while interrupted\n')
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'interrupted migration'):
            self.engine.run('recover')
        self.assertEqual(self.snapshot(), before)

    def test_pending_migration_blocks_legacy_remove_and_activate(self):
        self.interrupt(self.owner.targets['fish'])
        before = self.snapshot()
        for operation in ('remove', 'activate', 'recover'):
            with self.assertRaisesRegex(setup.Error, 'transaction identity'):
                self.owner.run(operation, ('fish',), apply=True)
            self.assertEqual(self.snapshot(), before)
        self.engine.run('recover')
        self.owner.run('remove', apply=True)
        self.assertEqual(self.target('fish').read_bytes(), b'# user fish\n')

    def test_existing_setup_journal_is_not_adopted(self):
        journal = {'schema_version': 1, 'roots': self.owner.roots, 'kind': 'setup'}
        self.owner.save(self.owner.journal_path, journal)
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'setup.py first'):
            self.engine.run('recover')
        self.assertEqual(self.snapshot(), before)

    def test_lock_shared_with_setup_and_released_after_failure(self):
        lock = self.owner.fs.lock(self.owner.lock_path)
        try:
            for operation in ('apply', 'recover'):
                with self.assertRaisesRegex(setup.Error, 'Another setup command'):
                    self.engine.run(operation)
            self.assertEqual(self.engine.run('preview')['status'], 'ready')
        finally:os.close(lock)
        self.assertEqual(self.engine.run('apply')['status'], 'applied')

    def test_process_lock_is_released_on_actual_process_death(self):
        script = ('import fcntl,sys; f=open(sys.argv[1],"r+"); '
                  'fcntl.flock(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.read()')
        process = subprocess.Popen([sys.executable, '-B', '-c', script, str(self.home / self.owner.lock_path)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'locked')
            with self.assertRaisesRegex(setup.Error, 'Another setup command'):self.engine.run('apply')
        finally:
            process.kill(); process.wait(timeout=5)
            process.stdin.close(); process.stdout.close()
        self.assertEqual(self.engine.run('apply')['status'], 'applied')

    def test_tampered_pending_delta_target_and_state_refuse(self):
        self.interrupt(self.owner.targets['fish'], after=False)
        path = self.home / self.owner.journal_path
        original = json.loads(path.read_text())
        variants = []
        for change in ('target', 'after', 'manifest', 'record', 'ledger', 'extra'):
            journal = copy.deepcopy(original)
            if change == 'target':journal['files'][0]['path'] = '.ssh/authorized_keys'
            if change == 'after':journal['files'][0]['after'] = '0' * 64
            if change == 'manifest':journal['manifest_sha256'] = '0' * 64
            if change == 'record':journal['old_state']['components']['fish']['source_root'] = str(self.new)
            if change == 'ledger':journal['old_ledger']['components']['fish'] = self.engine.version(self.manifest['entries'][0], 'new')
            if change == 'extra':journal['secret'] = 'PRIVATE_CANARY'
            variants.append(journal)
        for journal in variants:
            path.write_bytes(migrate.encode(journal))
            before = self.snapshot()
            with self.assertRaises(setup.Error) as caught:self.engine.run('recover')
            self.assertNotIn('PRIVATE_CANARY', str(caught.exception))
            self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.home / '.ssh').exists())

    def test_metadata_changes_and_permissions_refuse_recovery(self):
        self.interrupt(self.owner.targets['fish'])
        state = self.home / self.owner.state_path
        original = state.read_bytes()
        state.write_bytes(original + b' ')
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'Metadata changed'):self.engine.run('recover')
        self.assertEqual(self.snapshot(), before)
        state.write_bytes(original);state.chmod(0o644)
        with self.assertRaisesRegex(setup.Error, 'private'):self.engine.run('recover')

    def test_symlink_hardlink_fifo_and_directory_targets_refuse(self):
        path = self.target('hyprland')
        original = path.read_bytes()
        outside = self.root / 'outside';outside.write_bytes(original)
        for kind in ('symlink', 'hardlink', 'fifo', 'directory'):
            path.unlink()
            if kind == 'symlink':path.symlink_to(outside)
            if kind == 'hardlink':os.link(outside, path)
            if kind == 'fifo':os.mkfifo(path, 0o600)
            if kind == 'directory':path.mkdir(mode=0o700)
            before_fish = self.target('fish').read_bytes()
            with self.assertRaises((setup.Error, OSError)):self.engine.run('apply')
            self.assertEqual(self.target('fish').read_bytes(), before_fish)
            self.assertEqual(outside.read_bytes(), original)
            if kind == 'directory':path.rmdir()
            else:path.unlink()
            path.write_bytes(original)

    def test_permissions_xattrs_and_contents_not_in_journal(self):
        self.target('fish').chmod(0o640)
        try:os.setxattr(self.target('fish'), 'user.fixture', b'preserved')
        except OSError:self.skipTest('Filesystem lacks user extended attributes')
        with self.target('fish').open('ab') as stream:stream.write(b'# PRIVATE_USER_CANARY\n')
        self.interrupt(self.owner.targets['fish'])
        journal = (self.home / self.owner.journal_path).read_bytes()
        self.assertNotIn(b'PRIVATE_USER_CANARY', journal)
        self.engine.run('recover')
        self.assertEqual(self.target('fish').stat().st_mode & 0o777, 0o640)
        self.assertEqual(os.getxattr(self.target('fish'), 'user.fixture'), b'preserved')
        self.assertIn(b'PRIVATE_USER_CANARY', self.target('fish').read_bytes())

    def test_conflicting_recorded_version_refuses_and_next_version_works(self):
        self.engine.run('apply')
        third = self.root / 'v3';shutil.copytree(self.new, third)
        manifest = copy.deepcopy(self.manifest)
        manifest.update(id='release-2-to-3', from_version='2.0-1', to_version='3.0-1')
        for entry in manifest['entries']:
            entry['old'] = dict(entry['new'])
            entry['new']['root'] = str(third)
        next_engine = self.make_engine(manifest)
        self.assertEqual(next_engine.run('apply')['status'], 'applied')
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'Recorded version differs'):self.engine.run('apply')
        self.assertEqual(self.snapshot(), before)

    def test_no_ownership_means_no_migration_or_target_creation(self):
        self.owner.run('remove', apply=True)
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'not owned'):self.engine.run('apply')
        self.assertEqual(self.snapshot(), before)


    def test_real_process_death_after_durable_target_write_recovers(self):
        script = """import importlib.util,os,signal,sys
sys.path.insert(0,sys.argv[1])
spec=importlib.util.spec_from_file_location('config_migrate',sys.argv[2])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
e=m.Migration(sys.argv[3],sys.argv[4],sys.argv[5])
original=e.fs.atomic
def killed(path,data,expected,private=False):
    result=original(path,data,expected,private)
    if path==e.setup.targets['fish']:
        os.kill(os.getpid(),signal.SIGKILL)
    return result
e.fs.atomic=killed
e.run('apply')
"""
        process = subprocess.run([sys.executable, '-B', '-c', script, str(CONTRACT_DIR),
                                  str(HERE / 'config_migrate.py'), str(self.home),
                                  str(self.manifest_path), self.engine.manifest_sha256],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, -9, process.stderr)
        self.assertTrue((self.home / self.owner.journal_path).is_file())
        self.assertIn(str(self.new), self.target('fish').read_text())
        self.assertIn(str(self.old), self.target('zsh').read_text())
        self.assertEqual(self.engine.run('recover')['status'], 'recovered')
        self.assertEqual(self.engine.run('apply')['status'], 'already-applied')

    def test_write_failure_retains_intent_and_recovery_completes(self):
        atomic = self.engine.fs.atomic
        def failed(path, data, expected, private=False):
            if path == self.owner.targets['hyprland']:
                raise OSError('simulated ENOSPC')
            return atomic(path, data, expected, private)
        with mock.patch.object(self.engine.fs, 'atomic', side_effect=failed):
            with self.assertRaises(OSError):self.engine.run('apply')
        self.assertTrue((self.home / self.owner.journal_path).exists())
        self.assertEqual(self.engine.run('recover')['status'], 'recovered')
        self.assertEqual(self.engine.run('apply')['status'], 'already-applied')

    def test_target_edit_after_its_write_is_detected_before_metadata_commit(self):
        atomic = self.engine.fs.atomic
        original_state = (self.home / self.owner.state_path).read_bytes()
        def injected(path, data, expected, private=False):
            result = atomic(path, data, expected, private)
            if path == self.owner.targets['hyprland']:
                with self.target('fish').open('ab') as stream:stream.write(b'# concurrent user edit\n')
            return result
        with mock.patch.object(self.engine.fs, 'atomic', side_effect=injected):
            with self.assertRaisesRegex(setup.Error, 'before metadata commit'):
                self.engine.run('apply')
        self.assertEqual((self.home / self.owner.state_path).read_bytes(), original_state)
        self.assertIn(b'# concurrent user edit', self.target('fish').read_bytes())
        self.assertTrue((self.home / self.owner.journal_path).exists())

    def test_metadata_edit_after_preflight_is_not_overwritten(self):
        atomic = self.engine.fs.atomic
        state = self.home / self.owner.state_path
        edited = state.read_bytes() + b' '
        def injected(path, data, expected, private=False):
            result = atomic(path, data, expected, private)
            if path == self.owner.targets['zsh']:
                state.write_bytes(edited)
            return result
        with mock.patch.object(self.engine.fs, 'atomic', side_effect=injected):
            with self.assertRaisesRegex(setup.Error, 'changed during operation'):
                self.engine.run('apply')
        self.assertEqual(state.read_bytes(), edited)
        self.assertTrue((self.home / self.owner.journal_path).exists())

    def test_template_target_alias_refused(self):
        manifest = copy.deepcopy(self.manifest)
        entry = manifest['entries'][0]
        entry['old'] = {'root': str(self.home / '.config'),
                        'sha256': setup.checksum(self.target('fish').read_bytes())}
        manifest['entries'] = [entry]
        engine = self.make_engine(manifest)
        before = self.snapshot()
        with self.assertRaisesRegex(setup.Error, 'managed target'):engine.run('apply')
        self.assertEqual(self.snapshot(), before)

    def test_symlink_parent_refused(self):
        config = self.home / '.config'
        renamed = self.home / 'config-real';config.rename(renamed);config.symlink_to(renamed)
        before = (renamed / 'fish/config.fish').read_bytes()
        with self.assertRaises(OSError):self.engine.run('apply')
        self.assertEqual((renamed / 'fish/config.fish').read_bytes(), before)

    def test_final_journal_removal_failure_is_recoverable(self):
        atomic = self.engine.fs.atomic
        def injected(path, data, expected, private=False):
            if path == self.owner.journal_path and data is None:
                raise OSError('simulated directory fsync/unlink failure')
            return atomic(path, data, expected, private)
        with mock.patch.object(self.engine.fs, 'atomic', side_effect=injected):
            with self.assertRaises(OSError):self.engine.run('apply')
        self.assertEqual(self.engine.run('status')['status'], 'pending')
        result = self.engine.run('recover')
        self.assertEqual(result['status'], 'recovered')
        self.assertTrue(all(item['status'] == 'recovered' for item in result['actions']))
        self.assertEqual(self.engine.run('apply')['status'], 'already-applied')

    def test_size_preflight_fails_without_new_intent(self):
        path = self.target('fish')
        original = path.read_bytes()
        path.write_bytes(original + b'#' * setup.MAX_BYTES)
        before = self.target('zsh').read_bytes()
        with self.assertRaises(setup.Error):self.engine.run('apply')
        self.assertEqual(self.target('zsh').read_bytes(), before)
        self.assertFalse((self.home / self.owner.journal_path).exists())

    @unittest.skipIf(os.geteuid() == 0, 'CLI intentionally refuses root')
    def test_subprocess_cli_with_custom_roots_and_quoted_sources(self):
        home = self.root / 'custom-user';home.mkdir(mode=0o700)
        old = self.root / "old user's templates";shutil.copytree(self.old, old)
        new = self.root / "new user's templates";shutil.copytree(self.new, new)
        owner = setup.Setup(home, old, config='settings', zsh='shell', state='state')
        self.addCleanup(owner.close)
        owner.run('activate', setup.ALL_COMPONENTS, apply=True)
        manifest = copy.deepcopy(self.manifest)
        for entry in manifest['entries']:
            entry['old']['root'] = str(old)
            entry['new']['root'] = str(new)
        path = self.root / 'custom-manifest.json';path.write_bytes(migrate.encode(manifest))
        arguments = ['--home', str(home), '--config-home', str(home / 'settings'),
                     '--zdotdir', str(home / 'shell'), '--state-dir', str(home / 'state'),
                     '--manifest', str(path), '--sha256', setup.checksum(path.read_bytes())]
        environment = dict(os.environ, PYTHONPATH=str(CONTRACT_DIR),
                           XDG_CONFIG_HOME='/invalid/unrelated-config', ZDOTDIR='/invalid/unrelated-zsh',
                           XDG_STATE_HOME='/invalid/unrelated-state')
        for operation, status in (('preview', 'ready'), ('apply', 'applied'),
                                  ('status', 'already-applied'), ('recover', 'no-pending-transaction')):
            result = subprocess.run([sys.executable, '-B', str(HERE / 'config_migrate.py'), operation, *arguments],
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], status)
            self.assertEqual(result.stderr, '')
        self.assertTrue((home / 'state/migrations.json').is_file())
        self.assertFalse((home / '.config').exists())
        new_owner = setup.Setup(home, new, config='settings', zsh='shell', state='state')
        self.addCleanup(new_owner.close)
        new_owner.run('remove', apply=True)
        self.assertFalse((home / 'shell/.zshrc').exists())
        self.assertFalse((home / 'settings/fish/config.fish').exists())

    def test_cli_root_refusal_and_sanitized_json(self):
        arguments = ['preview', '--home', str(self.home), '--manifest', str(self.manifest_path),
                     '--sha256', self.engine.manifest_sha256]
        output = io.StringIO()
        with mock.patch.object(migrate.os, 'geteuid', return_value=0), mock.patch.object(migrate, 'Migration') as constructor, contextlib.redirect_stderr(output):
            self.assertEqual(migrate.main(arguments), 1)
            constructor.assert_not_called()
        self.assertIn('non-root', json.loads(output.getvalue())['error'])
        output = io.StringIO();errors = io.StringIO()
        with mock.patch.object(migrate.os, 'geteuid', return_value=os.getuid()), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = migrate.main(arguments)
        if os.getuid() == 0:
            self.assertEqual(result, 1)
        else:
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())['status'], 'ready')
            self.assertEqual(errors.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
