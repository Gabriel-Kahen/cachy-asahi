"""Source-only checkout and refusal-custody tests for the v3 launcher."""

from pathlib import Path
import runpy
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


FILES = Path(__file__).resolve().parent
LAUNCHER = runpy.run_path(str(FILES / 'development-launcher-v3.py'))


class RefusalCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.support = runpy.run_path(str(FILES / 'test_development_bootstrap_v3.py'))
        cls.support['BootstrapV3Tests'].setUpClass()

    def setUp(self):
        self.fixture = self.support['BootstrapV3Tests']()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def refuse_checkout(self, *, replace_grant=False):
        primary = ValueError('forced-checkout-refusal')
        fixture = self.fixture
        legacy = SimpleNamespace(**runpy.run_path(str(FILES / 'development-launcher.py')))
        legacy.clock = lambda *args: (fixture.deadline, fixture.deadline + 10)
        runner = Mock()
        paths = []

        def refuse(_legacy, _bootstrap, prepared, _plan, _deadline, _runner):
            private = prepared['paths']['bootstrap']
            self.assertEqual(sum(p.is_file() for p in private.rglob('*')), 163)
            paths.append(prepared['paths'])
            if replace_grant:
                foreign = fixture.temporary / 'foreign-grant'
                foreign.write_bytes(b'foreign replacement')
                foreign.replace(private / 'grant.json')
            raise primary

        with patch.object(self.support['legacy'], 'observe_runtime', return_value=self.support['OBSERVED']), \
                patch.dict(LAUNCHER['_launch'].__globals__, {'checkout': refuse}), \
                patch.object(LAUNCHER['signal'], 'setitimer'):
            with self.assertRaises(ValueError) as refused:
                LAUNCHER['_launch'](legacy, (self.support['legacy'], self.support['bootstrap'],
                    SimpleNamespace(issue=lambda *args: {})),
                    (fixture.selection_raw, self.support['PEER'], fixture.history_raw),
                    {'root_pins': fixture.pins}, fixture.environment, fixture.deadline, runner, SimpleNamespace())
        self.assertIs(refused.exception, primary)
        runner.assert_not_called()
        return paths[0], primary

    def test_checkout_refusal_retires_actual_private_tree_and_allows_bootstrap_retry(self):
        unrelated = self.fixture.temporary / 'unrelated'
        unrelated.write_bytes(b'untouched')
        for _ in range(2):
            paths, failure = self.refuse_checkout()
            self.assertFalse(paths['bootstrap'].exists())
            self.assertFalse(paths['tools'].exists())
            self.assertEqual(list(self.fixture.temporary.iterdir()), [unrelated])
            self.assertEqual(unrelated.read_bytes(), b'untouched')
            self.assertFalse(getattr(failure, '__notes__', ()))

    def test_uncertain_retirement_preserves_foreign_bytes_and_primary_refusal(self):
        paths, failure = self.refuse_checkout(replace_grant=True)
        self.assertEqual((paths['bootstrap'] / 'grant.json').read_bytes(), b'foreign replacement')
        self.assertFalse((paths['bootstrap'] / 'runtime.json').exists())
        self.assertFalse(paths['tools'].exists())
        self.assertTrue(any(note.startswith('bootstrap-disposal-uncertain') for note in failure.__notes__))


class GitDataCustodyTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='v3-checkout-source-')
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        self.repo = root / 'source'
        workspace = root / 'workspace'
        temporary = root / 'temporary'
        self.tools = temporary / 'tools'
        for path in (self.repo, workspace, self.tools / 'home', self.tools / 'tmp'):
            path.mkdir(parents=True)
        self.legacy = SimpleNamespace(**runpy.run_path(str(FILES / 'development-launcher.py')))
        self.bootstrap = SimpleNamespace(**runpy.run_path(str(FILES / 'development-bootstrap.py')))
        self.deadline = time.monotonic() + 45
        environment = {'GITHUB_WORKSPACE': str(workspace), 'RUNNER_TEMP': str(temporary),
                       'GITHUB_RUN_ID': '3', 'GITHUB_RUN_ATTEMPT': '1'}
        self.owner = self.legacy.select_workspace(environment, self.deadline)
        self.addCleanup(self.owner.close)
        self.prepared = {'paths': {'workspace': self.owner.path, 'tools': self.tools},
                         'workspace_owner': self.owner}
        self.git('init', '-q')
        self.git('config', 'core.filemode', 'true')
        self.git('commit', '-qm', 'source', '--allow-empty')
        self.source = self.git('rev-parse', 'HEAD').decode()
        self.commands = []

    def git(self, *arguments):
        config = ('-c', 'user.name=Source fixture', '-c', 'user.email=source-fixture@example.invalid',
                  '-c', 'commit.gpgsign=false')
        return subprocess.check_output(['/usr/bin/git', *config, '-C', str(self.repo), *arguments],
                                       env=self.legacy.git_environment(self.prepared), timeout=10).strip()

    def checkout(self, *, executable_peer=False, different_peer=False, large=False):
        bodies = {key: key.encode() for key in LAUNCHER['DATA_PATHS']}
        if large:
            # The legacy runner's 4 MiB buffer cannot transfer this selected blob.
            bodies['original_source_sha256'] = b'!' * (4 * 1024**2 + 1)
        for key, path in LAUNCHER['DATA_PATHS'].items():
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            is_peer = key == 'peer_receipt_sha256'
            target.write_bytes(b'different committed bytes' if is_peer and different_peer else bodies[key])
            target.chmod(0o755 if is_peer and executable_peer else 0o644)
        self.git('add', '.')
        self.git('commit', '-qm', 'data')
        plan = {'root_pins': {**{key: LAUNCHER['digest'](body) for key, body in bodies.items()},
                              'source_commit': self.source},
                'data_commit': self.git('rev-parse', 'HEAD').decode(),
                'git_sha256': LAUNCHER['digest'](Path('/usr/bin/git').read_bytes())}

        def run(command, environment, cwd, end, **options):
            self.commands.append(command)
            # Restrict exercise to a local synthetic Git repository with no network.
            if LAUNCHER['REMOTE'] in command:
                command = [str(self.repo) if arg == LAUNCHER['REMOTE'] else
                           'protocol.file.allow=always' if arg == 'protocol.file.allow=never' else arg
                           for arg in command]
            return LAUNCHER['run'](command, environment, cwd, end, **options)

        LAUNCHER['checkout'](self.legacy, self.bootstrap, self.prepared, plan, self.deadline, run)

    def test_exact_mode_and_bytes_are_joined_to_fetched_commit(self):
        self.checkout(large=True)
        self.assertEqual(sum(cmd[-3:-1] == ['cat-file', '-t'] for cmd in self.commands), 3)
        self.assertEqual(sum(cmd[-3:-1] == ['cat-file', 'blob'] for cmd in self.commands), 3)
        self.assertTrue(any('--detach' in cmd for cmd in self.commands))

    def test_executable_peer_blob_refuses_under_real_git_diff(self):
        with self.assertRaisesRegex(LAUNCHER['Refused'], '^data-only-tree-required$'):
            self.checkout(executable_peer=True)
        self.assertFalse(any('--detach' in cmd for cmd in self.commands))

    def test_different_peer_blob_refuses_with_exact_names_and_modes(self):
        with self.assertRaisesRegex(LAUNCHER['Refused'], '^data-blob-pin$'):
            self.checkout(different_peer=True)
        self.assertFalse(any('--detach' in cmd for cmd in self.commands))


if __name__ == '__main__':
    unittest.main()
