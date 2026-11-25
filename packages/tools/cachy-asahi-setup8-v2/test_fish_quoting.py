# SPDX-License-Identifier: MIT
"""Exercise legacy state and the staged Setup8 successor with real Fish."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

FISH_COMPONENTS = ('fish', 'fish-bang-bang', 'fish-autopair', 'fish-done')
STATE = Path('.local/state/cachy-asahi/setup')
PROFILE = Path('.config/fish/config.fish')


class Interrupted(Exception):
    pass


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_engines(root):
    setup = load('setup', root / 'setup.py')
    with patch.dict(sys.modules, {'setup': setup}):
        migrate = load('config_migrate', root / 'config_migrate.py')
    return setup, migrate


class FishQuotingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='setup8-fish-')))
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        self.target = self.home / PROFILE
        self.state = self.home / STATE / 'state.json'
        self.journal = self.home / STATE / 'journal.json'
        self.ledger = self.home / STATE / 'migrations.json'

    def templates(self, name, label):
        root = self.root / name
        for component in FISH_COMPONENTS:
            source = root / LEGACY_SETUP.TEMPLATES[component]
            source.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source.write_text(f'echo {label}-{component}\n')
        return root

    def command(self, argv, code=0):
        env = {'PATH': os.environ['PATH'], 'HOME': str(self.home), 'TERM': 'dumb'}
        result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def setup(self, templates, operation, *options, legacy=False, code=0):
        entry = [sys.executable, '-I', '-B', LEGACY_ROOT / 'setup.py'] if legacy else [STAGE / 'bin/cachy-asahi-setup']
        result = self.command([*entry, operation, '--home', self.home,
                               '--template-root', templates, *options], code)
        return json.loads(result.stderr if code == 1 else result.stdout)

    def fish(self, *, interactive=True):
        args = ['fish', '--no-config', '--private']
        if interactive:
            args.append('--interactive')
        result = self.command([*args, '-c', 'source "$argv[1]"', self.target])
        self.assertEqual(result.stderr, '')
        return result.stdout.splitlines()

    def activate(self, templates, *options, legacy=False):
        return self.setup(templates, 'activate', '--components', *FISH_COMPONENTS,
                          *options, legacy=legacy)

    def manifest(self, old, new):
        entries = []
        for name in FISH_COMPONENTS:
            relative = LEGACY_SETUP.TEMPLATES[name]
            entries.append({'component': name,
                            'old': {'root': str(old), 'sha256': LEGACY_SETUP.checksum((old / relative).read_bytes())},
                            'new': {'root': str(new), 'sha256': LEGACY_SETUP.checksum((new / relative).read_bytes())}})
        raw = LEGACY_MIGRATE.encode({'schema_version': 1, 'id': 'fixture-upgrade', 'package': 'fish-fixture',
                                     'from_version': '1-1', 'to_version': '2-1', 'entries': entries})
        path = self.root / 'manifest.json'
        path.write_bytes(raw)
        return path, LEGACY_SETUP.checksum(raw)

    def migrate(self, operation, path, digest, code=0):
        result = self.command([STAGE / 'bin/cachy-asahi-config-migrate', operation, '--home', self.home,
                               '--manifest', path, '--sha256', digest], code)
        return json.loads(result.stderr if code == 1 else result.stdout)

    def interrupt_migration(self, module, path, digest, after):
        engine = module.Migration(self.home, path, digest)
        self.addCleanup(engine.close)
        observed_atomic = engine.fs.atomic

        def interrupt(target, data, expected, private=False):
            observed_atomic(target, data, expected, private)
            if target == str(after):
                raise Interrupted

        with patch.object(engine.fs, 'atomic', side_effect=interrupt):
            with self.assertRaises(Interrupted):
                engine.run('apply')
        self.assertTrue(self.journal.is_file())

    def test_fresh_activation_sources_literal_paths_and_is_interactive_only(self):
        templates = self.templates(r"double\\slash user's $templates [test]", 'fresh')
        self.activate(templates, '--apply')
        self.assertEqual(self.fish(), [f'fresh-{name}' for name in FISH_COMPONENTS])
        self.assertEqual(self.fish(interactive=False), [])
        self.assertEqual([item['status'] for item in self.activate(templates, '--apply')['actions']],
                         ['unchanged'] * len(FISH_COMPONENTS))

    def test_legacy_blocks_can_be_updated_and_removed_with_user_bytes_intact(self):
        templates = self.templates(r'two\\backslashes', 'updated')
        self.target.parent.mkdir(parents=True, mode=0o700)
        self.target.write_bytes(b'# user prefix without newline')
        self.activate(templates, '--apply', legacy=True)
        with self.target.open('ab') as stream:
            stream.write(b'echo user-suffix\n')
        before, ownership = self.target.read_bytes(), self.state.read_bytes()
        self.assertEqual(self.fish(), ['user-suffix'])
        self.assertTrue(all(item['status'] == 'clean' for item in
                            self.setup(templates, 'status', '--components', *FISH_COMPONENTS)['actions']))
        self.assertTrue(all(item['status'] == 'would-update' for item in self.activate(templates)['actions']))
        self.assertEqual((self.target.read_bytes(), self.state.read_bytes()), (before, ownership))
        self.activate(templates, '--apply')
        self.assertEqual(self.fish(), [*(f'updated-{name}' for name in FISH_COMPONENTS), 'user-suffix'])
        self.setup(templates, 'remove', '--apply')
        self.assertEqual(self.target.read_bytes(), b'# user prefix without newline\necho user-suffix\n')

    def test_ordinary_legacy_blocks_keep_their_bytes_and_can_be_removed(self):
        templates = self.templates("user's normal templates", 'normal')
        self.activate(templates, '--apply', legacy=True)
        before, ownership = self.target.read_bytes(), self.state.read_bytes()
        self.assertEqual(self.fish(), [f'normal-{name}' for name in FISH_COMPONENTS])
        self.activate(templates, '--apply')
        self.assertEqual((self.target.read_bytes(), self.state.read_bytes()), (before, ownership))
        self.setup(templates, 'remove', '--apply')
        self.assertFalse(self.target.exists())

    def test_setup_can_finish_a_legacy_journal_and_remove_its_blocks(self):
        templates = self.templates(r'pending\\setup', 'pending')
        owner = LEGACY_SETUP.Setup(self.home, templates)
        self.addCleanup(owner.close)
        with patch.object(owner, 'replay', side_effect=Interrupted):
            with self.assertRaises(Interrupted):
                owner.run('activate', FISH_COMPONENTS, apply=True)
        self.assertTrue(self.setup(templates, 'status', '--components', 'fish', code=2)['pending']['can_resume'])
        self.assertTrue(self.setup(templates, 'recover', '--apply')['recovered_transaction'])
        self.assertFalse(self.journal.exists())
        self.setup(templates, 'remove', '--apply')
        self.assertFalse(self.target.exists())

    def test_legacy_migration_recovers_original_hashes_and_can_be_requoted(self):
        old = self.templates('old', 'old')
        new = self.templates(r'new\\root', 'migrated')
        self.activate(old, '--apply', legacy=True)
        path, digest = self.manifest(old, new)
        self.interrupt_migration(LEGACY_MIGRATE, path, digest, STATE / 'state.json')
        self.assertNotIn('fish_quoting', json.loads(self.journal.read_bytes()))
        self.assertEqual(self.migrate('status', path, digest, code=2)['status'], 'pending')
        self.assertEqual(self.migrate('recover', path, digest)['status'], 'recovered')
        self.assertEqual(self.migrate('status', path, digest)['status'], 'already-applied')
        ledger = self.ledger.read_bytes()
        self.activate(new, '--apply')
        self.assertEqual(self.fish(), [f'migrated-{name}' for name in FISH_COMPONENTS])
        self.assertEqual(self.migrate('status', path, digest)['status'], 'already-applied')
        self.assertEqual(self.ledger.read_bytes(), ledger)

    def test_new_migration_binds_its_quoting_and_resumes_with_real_fish(self):
        old = self.templates('old', 'old')
        new = self.templates(r'new\\root', 'new')
        self.activate(old, '--apply', legacy=True)
        path, digest = self.manifest(old, new)
        self.interrupt_migration(CURRENT_MIGRATE, path, digest, STATE / 'journal.json')
        raw = self.journal.read_bytes()
        journal = json.loads(raw)
        self.assertEqual(journal['fish_quoting'], 'literal-v1')
        self.journal.write_bytes(CURRENT_MIGRATE.encode(dict(journal, fish_quoting='unknown')))
        self.assertIn('Unsupported pending Fish quoting rule', self.migrate('recover', path, digest, code=1)['error'])
        self.assertEqual(self.fish(), [f'old-{name}' for name in FISH_COMPONENTS])
        self.journal.write_bytes(raw)
        self.assertEqual(self.migrate('recover', path, digest)['status'], 'recovered')
        self.assertEqual(self.fish(), [f'new-{name}' for name in FISH_COMPONENTS])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', type=Path, required=True, help='staged package usr directory')
    parser.add_argument('--legacy-root', type=Path, required=True, help='pinned unpatched Setup8 sources')
    args, remaining = parser.parse_known_args()
    STAGE, LEGACY_ROOT = args.stage.resolve(strict=True), args.legacy_root.resolve(strict=True)
    LEGACY_SETUP, LEGACY_MIGRATE = load_engines(LEGACY_ROOT)
    _, CURRENT_MIGRATE = load_engines(STAGE / 'lib/cachy-asahi/setup8')
    unittest.main(argv=[sys.argv[0], *remaining])
