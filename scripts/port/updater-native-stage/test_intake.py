# SPDX-License-Identifier: MIT
"""Credential-free controls for the pinned updater builder-carrier intake."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import intake
import seed_archives


class RetainedIntake(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='updater-intake-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_source_closure_matches_builder_plan(self):
        profiles = intake.manifest()
        expected = seed_archives.planned_files()
        selected = {path.rsplit('/', 1)[1]: (row['bytes'], row['sha256'])
                    for p in profiles.values() for path, row in p['selected'].items()}
        self.assertEqual(len(selected), 224)
        self.assertTrue(all(expected[name] == pin for name, pin in selected.items()))

    def test_key_only_used_by_verified_ssh_fetch(self):
        secret = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + 'inert fixture\n' * 6
        secret += '-----END OPENSSH PRIVATE KEY-----'
        env = intake.clean_environment(self.root)
        profiles = intake.manifest()
        seen = []

        def execute(argv, process_env, **kwargs):
            if argv[0] == '/usr/bin/ssh-keygen':
                seen.append(Path(argv[2]))
                self.assertTrue(seen[0].is_file())
                self.assertEqual(process_env, env)
                return b' '.join(intake.DEPLOY_KEY)
            self.assertEqual(argv[:2], ['git', 'fetch'])
            self.assertIn(intake.REMOTE, argv)
            self.assertEqual(len(argv[-4:]), len(profiles))
            self.assertIn('StrictHostKeyChecking=yes', process_env['GIT_SSH_COMMAND'])
            self.assertNotIn(secret, process_env.values())
            self.assertEqual(kwargs['seconds'], 185)

        with mock.patch.object(intake, 'command', side_effect=execute) as execute:
            intake.fetch(['git'], env, profiles, secret, self.root)
            self.assertEqual(execute.call_count, 2)
        self.assertFalse(seen[0].exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_deploy_key_cannot_fetch(self):
        secret = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + 'inert fixture\n' * 6
        secret += '-----END OPENSSH PRIVATE KEY-----'
        with mock.patch.object(intake, 'command', return_value=b'wrong identity') as execute:
            with self.assertRaisesRegex(ValueError, 'deploy-key-fingerprint'):
                intake.fetch(['git'], intake.clean_environment(self.root),
                             intake.manifest(), secret, self.root)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_real_git_reads_immutable_tree_and_verifies_selected_blob(self):
        env = dict(intake.clean_environment(self.root),
                   GIT_AUTHOR_NAME='test', GIT_AUTHOR_EMAIL='test@invalid',
                   GIT_COMMITTER_NAME='test', GIT_COMMITTER_EMAIL='test@invalid')
        git = ['/usr/bin/git', '--git-dir=' + str(self.root / 'test.git')]

        def run(*args, data=None):
            return subprocess.check_output(git + list(args), input=data, env=env, timeout=5).strip()

        run('init', '--bare', '--quiet')
        body = b'inert archived bytes\n'
        blob = run('hash-object', '-w', '--stdin', data=body)
        archive = 'test.pkg.tar.xz'
        sub = run('mktree', data=b'100644 blob ' + blob + b'\t' + archive.encode() + b'\n')
        tree = run('mktree', data=b'040000 tree ' + sub + b'\tpackages\n')
        commit = run('commit-tree', tree.decode(), data=b'test carrier\n')
        run('update-ref', 'refs/heads/test', commit.decode())
        target = self.root / 'out'
        target.mkdir()
        profile = {'commit': commit.decode(), 'tree': tree.decode(), 'tree_files': 1,
                   'selected': {'packages/' + archive: {'bytes': len(body),
                                                         'sha256': hashlib.sha256(body).hexdigest()}}}
        intake.materialize(git, env, {'test': profile}, target)
        self.assertEqual((target / archive).read_bytes(), body)
        profile['tree'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'carrier-parentless-tree'):
            intake.materialize(git, env, {'test': profile}, target)

    def test_retirement_is_idempotent_and_refuses_symlink(self):
        for name in ('retained-cache', 'retained-fetch'):
            (self.root / name).mkdir(mode=0o700)
            (self.root / name / 'inert').touch()
        intake.retire(self.root)
        intake.retire(self.root)
        self.assertEqual(list(self.root.iterdir()), [])
        victim = self.root / 'unowned'
        victim.mkdir(mode=0o700)
        (self.root / 'retained-cache').symlink_to(victim, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'private-directory'):
            intake.retire(self.root)
        self.assertTrue(victim.is_dir())
