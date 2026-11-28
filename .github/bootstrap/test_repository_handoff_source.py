# SPDX-License-Identifier: MIT
"""Source workflow coverage and check-only replay against committed Git objects."""

from fnmatch import fnmatchcase
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time
import unittest

from test_development_bootstrap_v3 import HERE, PACKET, ROOT, bootstrap, legacy, load


def path_matches(path, pattern):
    """Match the workflow's literal, single-component and recursive filters."""
    if pattern.endswith('/**'):
        return path.startswith(pattern[:-2])
    parts = path.split('/')
    globs = pattern.split('/')
    return len(parts) == len(globs) and all(fnmatchcase(part, glob) for part, glob in zip(parts, globs))


class WorkflowPathsTests(unittest.TestCase):
    def test_pull_request_filters_cover_the_committed_packet_and_replay(self):
        workflow = '.github/workflows/repository-handoff-source.yml'
        workflow_text = (ROOT / workflow).read_text()
        filters = re.search(r'(?m)^  pull_request:\n    paths:\n((?:      - [^\n]+\n)+)', workflow_text)
        self.assertIsNotNone(filters)
        patterns = [line.removeprefix('      - ') for line in filters[1].splitlines()]
        rows = legacy.decode((ROOT / PACKET).read_bytes())['source_files']
        targets = {*rows, PACKET, workflow, Path(__file__).relative_to(ROOT).as_posix()}
        uncovered = sorted(path for path in targets if not any(path_matches(path, pattern) for pattern in patterns))
        self.assertEqual(uncovered, [])


class RealGitReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.checkout = Path(temporary.name) / 'checkout'
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                   GIT_LFS_SKIP_SMUDGE='1', GIT_TERMINAL_PROMPT='0')
        git = ['git', '--no-replace-objects', '-C', str(ROOT), '-c', 'core.hooksPath=/dev/null',
               '-c', 'submodule.recurse=false']
        head = subprocess.check_output([*git, 'rev-parse', '--verify', 'HEAD^{commit}'],
                                       env=env, text=True, timeout=15).strip()
        # Replay the committed tree without inheriting the caller's ignored files.
        subprocess.run([*git, 'worktree', 'add', '--quiet', '--detach', str(cls.checkout), head],
                       env=env, check=True, timeout=30)
        cls.addClassCleanup(subprocess.run, [*git, 'worktree', 'remove', str(cls.checkout)],
                            env=env, check=True, timeout=30)
        cls.packet_raw = (cls.checkout / PACKET).read_bytes()
        cls.packet = legacy.decode(cls.packet_raw)
        cls.issuer = load('source_replay_clock_issuer', 'development-clock-issuer.py')
        cls.issuer_pin = legacy.digest((HERE / 'development-clock-issuer.py').read_bytes())
        fixture = runpy.run_path(str(ROOT / 'scripts/ci/development/repository_graph_fixture.py'))
        lock_raw, _ = fixture['historical_input'](ROOT, legacy.INITIAL)
        cls.lock, rows, cls.invocation = bootstrap.historical_specs(legacy, lock_raw)
        captures = {name: fixture['historical_input'](ROOT, name) for name in rows}
        cls.original = Path(temporary.name) / 'historical'
        owned = legacy.Owned()
        cls.addClassCleanup(owned.dispose)
        bootstrap.stage_historical(legacy, owned, cls.original, captures, time.monotonic() + 20)

    def replay(self, source_commit):
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            layout = {'workspace': self.checkout, 'original': self.original, 'output': scratch / 'evidence',
                      'cache': scratch / 'cache'}
            env_file = scratch / 'fixture.env'
            env_file.touch(mode=0o600)
            environment = {
                'PATH': os.defpath, 'LC_ALL': 'C', 'TMPDIR': str(scratch), 'RUNNER_TEMP': str(scratch),
                'GITHUB_WORKSPACE': str(self.checkout), 'GITHUB_ENV': str(env_file), 'GITHUB_SHA': source_commit,
                'GITHUB_WORKFLOW_SHA': source_commit, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
            }
            selection = {
                'source_commit': source_commit, 'source_files': self.packet['source_files'],
                'original_source': self.packet['original_source'], 'callbacks': legacy.CALLBACKS,
                'maps': {role: {'path': prefix + '/source-map.json',
                               'sha256': self.packet['metadata_pins'][prefix + '/source-map.json']}
                         for role, prefix in legacy.PREFIXES.items()},
            }
            # These private contracts are only test inputs for the check-only controller.
            runtime = legacy.encoded({'cli_sha256': '0' * 64, 'endpoint_identity': [], 'env': {}})
            grant = legacy.encoded(bootstrap.grant_contract(
                legacy, selection, self.lock, layout, self.invocation, environment, runtime,
            ))
            references = []
            for name, raw in (('grant', grant), ('runtime', runtime)):
                path = scratch / (name + '.json')
                path.touch(mode=0o600)
                path.write_bytes(raw)
                references.append((str(path), legacy.digest(raw)))
            bindings = self.issuer.issue(environment, self.issuer_pin, *references)
            argv = [
                sys.executable, '-E', '-s', '-B', str(self.checkout / 'scripts/ci/development/controller.py'),
                '--composition', 'repository-svg', '--check-only',
                '--development-sha256', legacy.digest(self.packet_raw), '--packet', str(self.checkout / PACKET),
                '--original-source-root', str(self.original),
                '--cache', str(layout['cache']), '--output', str(layout['output']),
            ]
            for name in ('inputs', 'recipes', 'integration'):
                argv.extend(('--' + name + '-sha256', self.invocation[f'scripts/ci/{name}.lock.json']))
            for name in ('clock', 'execution-grant', 'runtime-contract'):
                key = 'DEVELOPMENT_' + name.upper().replace('-', '_')
                argv.extend(('--' + name, bindings[key + '_PATH'], '--' + name + '-sha256', bindings[key + '_SHA256']))
            result = subprocess.run(argv, cwd=self.checkout, env={**environment, **bindings}, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=30)
            for name in ('output', 'cache'):
                self.assertFalse(os.path.lexists(layout[name]), f'{name} allocated during check-only')
            return result

    def test_check_only_verifies_both_roots_without_creating_actor_paths(self):
        result = self.replay(os.environ['GITHUB_SHA'])
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stdout, 'dual-source development inputs verified; execution NOT RUN\n')
        self.assertEqual(result.stderr, '')

    def test_check_only_refuses_a_real_commit_that_is_not_the_checkout(self):
        result = self.replay(bootstrap.ORIGINAL_SOURCE['source_commit'])
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        report = legacy.decode(result.stdout.encode())
        self.assertEqual((report['status'], report['execution']), ('FAIL', 'NOT RUN'))
        self.assertEqual(result.stderr, 'FAIL: development boundary/source refusal\n')

    def test_check_only_still_refuses_cache_in_the_selected_checkout(self):
        cache = self.checkout / 'scripts/benchmarks/__pycache__'
        cache.mkdir()
        try:
            result = self.replay(os.environ['GITHUB_SHA'])
        finally:
            cache.rmdir()
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        report = legacy.decode(result.stdout.encode())
        self.assertEqual((report['status'], report['execution']), ('FAIL', 'NOT RUN'))


if __name__ == '__main__':
    unittest.main()
