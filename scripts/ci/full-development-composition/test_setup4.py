#!/usr/bin/env python3
"""Inert setup4 policy/control-flow regressions; no system actors are executed."""
import hashlib
import importlib.util
import importlib.machinery
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('composition_setup4', Path(__file__).with_name('setup4.py'))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


def need(ok, message):
    if not ok:
        raise ValueError(message)


class Setup4Checks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.work = self.root / 'inputs', self.root / 'work'
        self.source.mkdir(); self.work.mkdir()
        self.checkpoint = {'base-' + str(i): '1-1' for i in range(586)} | {trial.NAME: '0.1.0-3'}
        expected = self.checkpoint | {trial.NAME: '0.1.0-4'}
        lock = ''.join(k + ' ' + v + '\n' for k, v in sorted(expected.items())).encode()
        (self.source / 'expected-setup4.lock').write_bytes(lock)
        hashes = {'/usr/bin/cachy-asahi-setup': '3e652bff75f6202cd3c13c327e50a298f7b25149b3c5cb55cdf4912d35af5919',
                  trial.CLI: '38db2d45955b569a4c74c3f31d6b6c79611126238e1bbe1e5cf819f81d0fb54f'}
        row = {'name': trial.NAME, 'version': '0.1.0-4', 'filename': 'setup.pkg.tar.xz',
               'sha256': trial.PACKAGE_SHA, 'size': 22632, 'signature_sha256': 'a' * 64, 'signature_size': 64,
               'depends': ['python>=3.11', 'gnupg', 'pacman'], 'provides': [], 'conflicts': [],
               'payload': [{'path': p, 'type': 'file', 'mode': 0o644, 'sha256': hashes.get(p, 'b' * 64)} for p in sorted(trial.PATHS)]}
        self.plan = {'setup4': {'package': row, 'expected_inventory_sha256': hashlib.sha256(lock).hexdigest()},
                     'test_signer_fingerprint': 'A' * 40, 'signer_fingerprint': 'B' * 40}
        self.commands = []
        def command(argv):
            self.commands.append(argv)
            return '\n'.join(sorted(trial.PATHS)) + '\n'
        self.composition = SimpleNamespace(need=need, lock=lambda text: dict(line.split() for line in text.splitlines()),
            pin=Mock(), archive_metadata=lambda row, source: {'depend': list(row['depends'])}, run=command)

    def test_unrelated_inventory_change_is_rejected_before_package_actors(self):
        path = self.source / 'expected-setup4.lock'
        path.write_text(path.read_text().replace('base-0 1-1', 'base-0 2-1'))
        self.plan['setup4']['expected_inventory_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'expected inventory differs'):
            trial.inputs(self.plan, self.checkpoint, self.source, self.composition)
        self.composition.pin.assert_not_called()
        self.assertFalse(self.commands)

    def test_install_script_or_hook_is_refused_before_transaction(self):
        for member in ('.INSTALL', './.INSTALL', 'usr/share/libalpm/hooks/unexpected.hook'):
            with self.subTest(member=member):
                self.composition.run = lambda argv: member + '\n'
                with self.assertRaisesRegex(ValueError, 'install script or hook'):
                    trial.inputs(self.plan, self.checkpoint, self.source, self.composition)

    def test_actual_dependency_drift_is_rejected(self):
        self.composition.archive_metadata = lambda row, source: {'depend': [*row['depends'], 'unexpected']}
        with self.assertRaisesRegex(ValueError, 'actual metadata differs'):
            trial.inputs(self.plan, self.checkpoint, self.source, self.composition)
        self.assertFalse(self.commands)

    def repository(self, drift=None):
        main, include = self.root / 'pacman.conf', self.root / 'cachy-asahi.conf'
        original = b'[options]\n# unrelated operator bytes\nArchitecture = aarch64\n'
        main.write_bytes(original)
        (self.source / 'TEST-public.asc').write_bytes(b'inert public fixture')
        calls = []
        enrolls = 0
        def command(argv):
            nonlocal enrolls
            calls.append(argv)
            if argv[0] == 'gpg':
                return 'pub:f:::::::::\nfpr:::::::::' + argv[-1] + ':\n'
            if argv[0] == 'pacman-conf':
                return ('PackageRequired DatabaseRequired PackageTrustedOnly DatabaseTrustedOnly '
                        'https://repository.test.invalid/generations/' + 'a' * 64 + '/release/repo')
            self.assertEqual(argv[0], trial.CLI)
            if '--apply' not in argv:
                if drift == 'preview': main.write_bytes(b'changed')
                return json.dumps({'status': 'preview'})
            self.assertEqual(argv[1], '--apply')
            if argv[2] == 'enroll':
                enrolls += 1
                main.write_bytes(original + trial.BLOCK)
                include.write_text('inert signed include\n')
                if drift == 'repeat' and enrolls == 2: main.write_bytes(main.read_bytes() + b'unrelated drift')
                return json.dumps({'status': 'enabled', 'config_changed': enrolls == 1,
                                   'managed_include': include.read_text()})
            self.assertEqual(argv[2], 'disable')
            changed = include.exists()
            include.unlink(missing_ok=True); main.write_bytes(original)
            return json.dumps({'status': 'disabled', 'config_changed': changed})
        api = SimpleNamespace(run=command, need=need)
        temporary_directory = tempfile.TemporaryDirectory
        def private_directory(**kwargs):
            self.assertEqual(kwargs, {'dir': '/root', 'prefix': 'setup4-TEST-'})
            return temporary_directory(dir=self.work, prefix=kwargs['prefix'])
        with patch.object(trial.os, 'chown'), patch.object(trial.tempfile, 'TemporaryDirectory', side_effect=private_directory) as private:
            result = trial.repository_trial(self.plan, self.source, self.work, api, main, include)
        private.assert_called_once_with(dir='/root', prefix='setup4-TEST-')
        for argv in calls:
            if '--public-key' in argv:
                public = Path(argv[argv.index('--public-key') + 1])
                self.assertFalse(public.exists())
                self.assertFalse(public.parent.exists())
        return result, calls, main, include, original

    def test_repository_repeat_and_disable_preserve_unrelated_bytes_and_trust(self):
        result, calls, main, include, original = self.repository()
        self.assertEqual(result['status'], 'PASS-disposable-TEST-only')
        self.assertEqual(main.read_bytes(), original)
        self.assertFalse(include.exists())
        cli = [argv for argv in calls if argv[0] == trial.CLI]
        self.assertEqual(len(cli), 5)
        self.assertEqual([argv[2] for argv in cli if '--apply' in argv], ['enroll', 'enroll', 'disable', 'disable'])
        self.assertTrue(all(argv[0] not in ('pacman-key', 'curl', 'wget') for argv in calls))
        self.assertEqual(result['public_trust_after_disable'], 'INTENTIONALLY RETAINED')

    def test_repository_preview_and_repeat_detect_configuration_drift(self):
        for drift, message in (('preview', 'preview changed'), ('repeat', 'repeated enrollment changed')):
            with self.subTest(drift=drift):
                with self.assertRaisesRegex(ValueError, message):
                    self.repository(drift)
                self.assertFalse(list(self.work.glob('setup4-TEST-*')))

    def test_wrong_initial_checkpoint_stops_before_any_actor(self):
        actor = Mock()
        api = SimpleNamespace(guard=Mock(), inventory=lambda: {'unrelated': '1'}, need=need, run=actor)
        with self.assertRaisesRegex(RuntimeError, 'failed at checkpoint'):
            trial.run(['pacman'], self.plan, self.checkpoint, self.source, self.work, api, None, None)
        actor.assert_not_called()


    def test_actual_retained_cli_rejects_tmp_but_accepts_private_root_chain(self):
        repo = next(root for root in Path(__file__).resolve().parents if (root / 'AGENTS.md').is_file()
                    and (root / 'packages/settings/cachy-asahi-setup/cachy-asahi-repository').is_file())
        path = repo / 'packages/settings/cachy-asahi-setup/cachy-asahi-repository'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         '38db2d45955b569a4c74c3f31d6b6c79611126238e1bbe1e5cf819f81d0fb54f')
        loader = importlib.machinery.SourceFileLoader('retained_repository_cli', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        # Simulate only directory stat observations; call the actual unmodified path guard.
        def directory_stat(path):
            mode = 0o1777 if str(path) == '/tmp' else 0o700 if str(path).startswith('/root') else 0o755
            return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=0)
        with patch.object(Path, 'lstat', directory_stat):
            with self.assertRaisesRegex(cli.Error, 'unsafe directory ownership/mode: /tmp'):
                cli.parents(Path('/tmp/composition-fixture/TEST-public.asc'), Path('/'), 0)
            cli.parents(Path('/root/setup4-TEST-fixture/TEST-public.asc'), Path('/'), 0)


    def transaction(self, updater, failure=None):
        # Exercise run() itself; all absolute installed paths map into this synthetic root.
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            sandbox = Path(temporary)
            work = sandbox / 'work'; work.mkdir()
            real_path = Path
            mapping = {p: sandbox / 'system' / p.lstrip('/') for p in trial.PATHS}
            mapping['/etc/pacman.conf'] = sandbox / 'system/etc/pacman.conf'
            mapping['/etc/pacman.d/cachy-asahi.conf'] = sandbox / 'system/etc/pacman.d/cachy-asahi.conf'
            for path in mapping.values(): path.parent.mkdir(parents=True, exist_ok=True)
            mapping['/etc/pacman.conf'].write_bytes(b'[options]\n# preserve operator bytes\n')
            names = {'cachy-asahi-' + name for name in ('hyprland-settings', 'fish-config', 'zsh-config',
                'setup', 'ksmctl', 'update', 'fdk-aac', 'zsh-autosuggestions', 'topmem', 'fish-bang-bang')}
            checkpoint = {'base-' + str(i): '1-1' for i in range(573)}
            checkpoint.update({name: '1-1' for name in names | {'htmlq', 'pacman-contrib', 'archlinux-contrib', 'pyalpm'}})
            checkpoint.update({trial.NAME: '0.1.0-3', 'cachy-asahi-update': updater})
            self.assertEqual(len(checkpoint), 587)
            current, stages, commands, checked_payload_counts = dict(checkpoint), [], [], []
            row = self.plan['setup4']['package']
            plan = dict(self.plan, projects=[{'name': name, 'version': checkpoint[name], 'depends': [], 'payload': []}
                                           for name in sorted(names)], packages=[
                {'name': trial.NAME, 'version': '0.1.0-3', 'filename': 'setup3.pkg.tar.xz',
                 'sha256': 'a' * 64, 'size': 1, 'signature_sha256': 'b' * 64, 'signature_size': 1}])
            expected = checkpoint | {trial.NAME: '0.1.0-4'}
            def command(argv):
                commands.append(argv)
                if '-U' in argv:
                    old = str(argv[-1]).endswith('setup3.pkg.tar.xz')
                    stages.append('rollback' if old else 'upgrade' if len(stages) == 0 else 'reinstall')
                    current[trial.NAME] = '0.1.0-3' if old else '0.1.0-4'
                    for name in trial.PATHS:
                        path = mapping[name]
                        if old and name in trial.NEW_PATHS: path.unlink(missing_ok=True)
                        else: path.write_text(current[trial.NAME])
                elif '-R' in argv:
                    self.assertEqual(argv[-1], trial.NAME)
                    stages.append('remove'); del current[trial.NAME]
                    for name in trial.PATHS: mapping[name].unlink()
                    if failure == 'removal-drift': current['base-0'] = '2-1'
                return ''
            api = SimpleNamespace(guard=Mock(), need=need, inventory=lambda: dict(current), run=command,
                                  pin=Mock(), archive_metadata=Mock())
            def make_fixtures(root, composition, core):
                users = [{'home': root / label} for label in ('fresh', 'existing')]
                for user in users: user['home'].mkdir()
                adapter = SimpleNamespace(checks=[])
                adapter.paths = lambda user: {'fish': user['home'] / 'fish', 'zsh': user['home'] / '.zshrc',
                                              'hyprland': user['home'] / 'hyprland'}
                adapter.snapshot = lambda user: {str(p.relative_to(user['home'])): p.read_bytes()
                                                for p in user['home'].rglob('*') if p.is_file()}
                def fixture(user, relative, data):
                    path = user['home'] / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
                adapter.fixture = fixture
                def helper(user, operation, components=(), apply=True, allowed=(0,)):
                    if not apply: return
                    if failure == 'fixture-failure': raise ValueError('injected setup fixture failure')
                    for path in adapter.paths(user).values():
                        if not path.exists(): path.write_bytes(b'# activated fixture\n')
                adapter.helper = helper
                def check(label, ok):
                    need(ok, label); adapter.checks.append(label)
                adapter.check = check
                return adapter, users
            def payloads(pacman, projects, composition):
                actual_names = {p['name'] for p in projects}
                self.assertEqual(actual_names, names if trial.NAME in current else names - {trial.NAME})
                self.assertTrue(all(p['version'] == current[p['name']] for p in projects))
                self.assertEqual(current['cachy-asahi-update'], updater)
                checked_payload_counts.append(len(projects))
            payload = SimpleNamespace(fixtures=make_fixtures, payloads=payloads)
            def mapped_path(value):
                return mapping.get(str(value), real_path(value))
            with patch.object(trial, 'Path', side_effect=mapped_path), \
                 patch.object(trial, 'inputs', return_value=(row, expected)), \
                 patch.object(trial, 'repository_trial', return_value={'status': 'PASS-mocked-CLI'}):
                if failure:
                    with self.assertRaisesRegex(RuntimeError, 'normal-setup4-removal' if failure == 'removal-drift'
                                                else 'installed-per-user-setup'):
                        trial.run(['pacman'], plan, checkpoint, self.source, work, api, None, payload)
                    self.assertEqual(stages, ['upgrade', 'remove'] if failure == 'removal-drift' else ['upgrade'])
                    return
                result = trial.run(['pacman'], plan, checkpoint, self.source, work, api, None, payload)
            self.assertEqual(stages, ['upgrade', 'remove', 'reinstall', 'rollback'])
            self.assertEqual(checked_payload_counts, [10, 9, 10, 10])
            self.assertEqual(current, checkpoint)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['removed_package_count'], 586)
            self.assertEqual(result['final_package_count'], 587)
            self.assertEqual(result['final_inventory_sha256'], trial.inventory_sha(checkpoint))
            self.assertTrue(all('--noscriptlet' in argv and not set(argv) & {'--nodeps', '--overwrite', '--assume-installed'}
                                for argv in commands if '-U' in argv or '-R' in argv))

    def test_full_transaction_returns_exact_updater1_and_updater2_checkpoints(self):
        for updater in ('4.4.2-1', '4.4.2-2'):
            with self.subTest(updater=updater): self.transaction(updater)

    def test_removal_drift_or_fixture_failure_cannot_finish_transaction(self):
        for failure in ('removal-drift', 'fixture-failure'):
            with self.subTest(failure=failure): self.transaction('4.4.2-1', failure)


if __name__ == '__main__':
    unittest.main()
