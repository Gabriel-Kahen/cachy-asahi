#!/usr/bin/env python3
"""Causal fixture checks; never run pacman, Docker, GPG, network, or a build."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
REPO = next(root for root in HERE.parents if (root / 'AGENTS.md').is_file()
            and (root / 'packages/settings/cachy-asahi-setup/cachy-asahi-setup').is_file())
trial = load('proposed_lifecycle', HERE / 'lifecycle.py')
SETUP_PATH = REPO / 'packages/settings/cachy-asahi-setup/cachy-asahi-setup'
setup = load('real_setup', SETUP_PATH)


def snapshot(home):
    return {str(p.relative_to(home)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
            for p in home.rglob('*') if p.is_file()}


class LifecycleChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home, self.templates = self.root / 'home', self.root / 'templates'
        self.home.mkdir(mode=0o700); self.templates.mkdir(mode=0o700)
        for relative in setup.TEMPLATES.values():
            path = self.templates / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(b'# version one\n')
        self.engine = setup.Setup(self.home, self.templates)
        self.addCleanup(self.engine.close)

    def apply(self, operation, components=trial.COMPONENTS):
        return self.engine.run(operation, components, apply=True)

    def test_preview_and_repeat_do_not_write(self):
        before = snapshot(self.home)
        self.engine.run('activate', trial.COMPONENTS, apply=False)
        self.assertEqual(snapshot(self.home), before)
        self.apply('activate')
        before = snapshot(self.home)
        self.apply('activate')
        self.assertEqual(snapshot(self.home), before)

    def test_changed_template_refreshes_only_unmodified_copy(self):
        self.apply('activate')
        desktop = self.home / '.config/cachy-asahi/hyprland.lua'
        original = desktop.read_bytes()
        installed = self.templates / setup.TEMPLATES['hyprland']
        installed.write_bytes(b'# version two\n')
        self.apply('activate')
        self.assertEqual(desktop.read_bytes(), installed.read_bytes())
        self.assertNotEqual(desktop.read_bytes(), original)
        desktop.write_bytes(desktop.read_bytes() + b'# user edit\n')
        edited = desktop.read_bytes()
        installed.write_bytes(b'# version three\n')
        report = self.apply('activate')
        self.assertTrue(report['preserved_conflicts'])
        self.assertEqual(desktop.read_bytes(), edited)

    def test_deactivation_removes_only_owned_shell_blocks(self):
        shell = self.home / '.zshrc'
        shell.write_bytes(b'# original\n'); shell.chmod(0o640)
        self.apply('activate')
        shell.write_bytes(b'# prefix\n' + shell.read_bytes() + b'# suffix\n')
        desktop = self.home / '.config/cachy-asahi/hyprland.lua'
        desktop.write_bytes(desktop.read_bytes() + b'# edited\n')
        edited = desktop.read_bytes()
        self.assertTrue(self.apply('remove')['preserved_conflicts'])
        self.assertEqual(shell.read_bytes(), b'# prefix\n# original\n# suffix\n')
        self.assertEqual(stat.S_IMODE(shell.stat().st_mode), 0o640)
        self.assertEqual(desktop.read_bytes(), edited)

    def test_real_helper_fault_recovers_activate_and_remove(self):
        code = '''import importlib.machinery, importlib.util, os, sys
loader=importlib.machinery.SourceFileLoader('setup_fault',sys.argv[1])
spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec); loader.exec_module(m)
original=m.Files.atomic
def atomic(self,path,data,expected,private=False):
    result=original(self,path,data,expected,private)
    if path=='.config/fish/config.fish': os._exit(75)
    return result
m.Files.atomic=atomic
m.Setup(sys.argv[2],sys.argv[3]).run(sys.argv[4],('fish','zsh','hyprland'),apply=True)
'''
        for operation in ('activate', 'remove'):
            with self.subTest(operation=operation):
                proc = subprocess.run([sys.executable, '-B', '-c', code, str(SETUP_PATH),
                    str(self.home), str(self.templates), operation], capture_output=True, timeout=10)
                self.assertEqual(proc.returncode, 75, proc.stderr.decode())
                journal = self.home / '.local/state/cachy-asahi/setup/journal.json'
                self.assertTrue(journal.is_file())
                before = snapshot(self.home)
                report = self.engine.run('recover', apply=False)
                self.assertIn('pending_transaction', report)
                self.assertEqual(snapshot(self.home), before)
                self.engine.run('recover', apply=True)
                self.assertFalse(journal.exists())
                paths = [self.home / p for p in self.engine.targets.values()]
                self.assertEqual([p.exists() for p in paths], [operation == 'activate'] * 3)

    def test_restoration_inventory_drift_stops_before_provider_mutation(self):
        def need(ok, message):
            if not ok:
                raise ValueError(message)
        command = Mock(return_value='')
        composition = SimpleNamespace(PROJECTS={'project', trial.FDK}, EXTRAS={'extra'},
                                      run=command, inventory=lambda: {'unexpected': '2'}, need=need)
        with self.assertRaisesRegex(ValueError, 'unrelated inventory'):
            trial.restore(['pacman'], {}, {'base': '1'}, {'base': '1', 'project': '1', trial.FDK: '1'},
                          self.root, composition, None, {}, [])
        self.assertEqual(command.call_count, 1)
        self.assertIn('-R', command.call_args.args[0])
        self.assertNotIn('-U', command.call_args.args[0])


    def test_payload_content_symlink_and_package_owner_drift_are_rejected(self):
        def need(ok, message):
            if not ok:
                raise ValueError(message)
        package = 'fixture-project'
        regular = self.root / 'owned-file'
        regular.write_bytes(b'verified bytes'); regular.chmod(0o644)
        link = self.root / 'owned-link'
        link.symlink_to(regular.name)
        projects = [{'name': package, 'payload': [
            {'path': str(regular), 'type': 'file', 'mode': 0o644,
             'sha256': trial.hashlib.sha256(regular.read_bytes()).hexdigest()},
            {'path': str(link), 'type': 'symlink', 'target': regular.name}]}]
        composition = SimpleNamespace(need=need, run=lambda argv: package if '-Qqo' in argv else '')
        actual_lstat = Path.lstat
        def root_owned(path, *args, **kwargs):
            return SimpleNamespace(st_uid=0, st_gid=0,
                st_mode=actual_lstat(path, *args, **kwargs).st_mode)
        with patch.object(Path, 'lstat', root_owned):
            trial.payloads(['pacman'], projects, composition)
            with self.subTest(drift='content'):
                regular.write_bytes(b'modified bytes')
                with self.assertRaisesRegex(ValueError, 'payload differs'):
                    trial.payloads(['pacman'], projects, composition)
                regular.write_bytes(b'verified bytes')
            with self.subTest(drift='symlink'):
                link.unlink(); link.symlink_to('unexpected-target')
                with self.assertRaisesRegex(ValueError, 'payload differs'):
                    trial.payloads(['pacman'], projects, composition)
                link.unlink(); link.symlink_to(regular.name)
            with self.subTest(drift='package-owner'):
                composition.run = lambda argv: 'unrelated-package' if '-Qqo' in argv else ''
                with self.assertRaisesRegex(ValueError, 'package owner differs'):
                    trial.payloads(['pacman'], projects, composition)
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=1, st_gid=1, st_mode=0o100644)):
            with self.assertRaisesRegex(ValueError, 'uid/gid differs'):
                trial.payloads(['pacman'], projects, composition)

    def test_signed_upgrade_cannot_change_dependency_policy(self):
        def need(ok, message):
            if not ok:
                raise ValueError(message)
        names = {'desktop', 'fish', 'zsh', 'setup'}
        rows = [{'name': name, 'version': '0.1.1-1', 'filename': name + '.pkg.tar.xz',
                 'sha256': 'a' * 64, 'size': 1, 'signature_sha256': 'b' * 64,
                 'signature_size': 1, 'payload': []} for name in sorted(names)]
        plan = {'lifecycle': {'upgrades': rows}, 'projects': [
            {'name': name, 'depends': ['glibc'], 'provides': [], 'conflicts': []} for name in names]}
        command = Mock()
        composition = SimpleNamespace(need=need, pin=Mock(), run=command,
            archive_metadata=lambda row, source: {'depend': ['unreviewed-dependency']})
        with self.assertRaisesRegex(ValueError, 'dependency/provider policy'):
            trial.upgrade_inputs(plan, self.root, composition, SimpleNamespace(PACKAGES=names))
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
