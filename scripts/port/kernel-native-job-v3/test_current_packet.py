# SPDX-License-Identifier: MIT
"""Exact-commit kernel packet checks with local Git and an inert daemon boundary."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/port/kernel-native-job'))
import job
import packet
import packet_v2
import packet_v3
from test_public import bootstrap


class ManifestCustodyTests(unittest.TestCase):
    def test_v3_refuses_manifest_drift_after_its_first_capture(self):
        commit = 'a' * 40
        body = b'{"schema_version": 1, "files": {}}\n'
        cases = (('show', 'mode'), ('rev-parse', 'mode'), ('rev-parse', 'bytes'))
        for phase, change in cases:
            with (self.subTest(phase=phase, change=change),
                  TemporaryDirectory(prefix='kernel-v3-manifest-') as temporary,
                  patch.dict(os.environ, {'GITHUB_SHA': commit, 'GITHUB_WORKFLOW_SHA': commit})):
                root = Path(temporary)
                manifest = root / packet_v3.MANIFEST
                manifest.parent.mkdir(parents=True)
                manifest.write_bytes(body)
                manifest.chmod(0o644)
                output = root / 'artifacts/kernel-native-job/source'
                output.parent.mkdir(parents=True)

                policy = packet_v3._policy()
                # Use the inherited verifier and real file capture with no
                # package rows or subprocesses in this custody fixture.
                policy.closure = lambda root: (set(), {}, {})
                policy.frozen = lambda *args: None
                mutations = []

                def run(argv, *, timeout, limit):
                    verb = argv[argv.index('-C') + 2]
                    if verb == phase:
                        if change == 'mode':
                            manifest.chmod(0o755)
                        else:
                            manifest.write_bytes(body + b'\n')
                        mutations.append(verb)
                    stdout = {'show': body, 'ls-tree': b'100644\n',
                              'rev-parse': (commit + '\n').encode()}[verb]
                    return SimpleNamespace(returncode=0, stdout=stdout)

                with (patch.object(packet_v3, '_policy', return_value=policy),
                      self.assertRaisesRegex(ValueError, '^packet-v3-manifest-race$')):
                    packet_v3.verify(root, manifest, packet.sha(body), commit, SimpleNamespace(run=run), output)
                self.assertEqual(mutations, [phase])
                if phase == 'show':
                    self.assertFalse(output.exists())


class CurrentPacketTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix='kernel-packet-v3-')
        self.addCleanup(temporary.cleanup)
        self.private = Path(temporary.name)
        self.inline = bootstrap()
        self.manifest = ROOT / packet_v3.MANIFEST
        self.git_env = {'PATH': '/usr/bin:/bin', 'HOME': temporary.name, 'GIT_CONFIG_NOSYSTEM': '1',
                        'GIT_CONFIG_GLOBAL': '/dev/null', 'LANG': 'C.UTF-8'}
        env = patch.dict(os.environ, {'RUNNER_TEMP': temporary.name})
        env.start()
        self.addCleanup(env.stop)
        self.commit = self.inline['git'](ROOT, 'rev-parse', 'HEAD').decode().strip()
        env = patch.dict(os.environ, {'GITHUB_SHA': self.commit, 'GITHUB_WORKFLOW_SHA': self.commit})
        env.start()
        self.addCleanup(env.stop)
        self.lock = self.inline['git'](ROOT, 'show', f'{self.commit}:{packet_v3.MANIFEST}')
        self.pin = packet.sha(self.lock)
        self.rows = packet.decode(self.lock)['files']
        self.runner = SimpleNamespace(run=self.run_git)

    def run_git(self, argv, *, timeout, limit):
        self.assertEqual(argv[0], '/usr/bin/git')
        result = subprocess.run(argv, env=self.git_env, capture_output=True, timeout=timeout)
        self.assertLessEqual(len(result.stdout), limit)
        return result

    def private_checkout(self):
        root = self.private / 'fixture'
        self.run_git(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', 'clone', '--quiet', '--shared',
                      '--no-checkout', '--single-branch', '--', str(ROOT), str(root)],
                     timeout=10, limit=4096).check_returncode()
        self.assertEqual(self.inline['git'](root, 'rev-parse', 'HEAD'), (self.commit + '\n').encode())
        for name in (*self.rows, packet_v3.MANIFEST):
            body, mode = packet.capture(ROOT / name)
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            target.chmod(mode)
        return root

    def test_preview_matches_committed_current_lock_and_inherits_setup_policy(self):
        self.assertEqual(self.inline['PACKET'], packet_v3.MANIFEST)
        self.assertEqual(packet.read(self.manifest), self.lock)
        self.assertEqual(packet_v3.preview(ROOT), packet.decode(self.lock))
        self.assertEqual(set(packet_v3.BUILD_HELPERS), {'scripts/build/build.py', 'scripts/build/compare.py'})

        policy = packet_v3._policy()
        old_policy = packet_v2._policy()
        parents = {packet.PREFIX + 'packet.py': (packet_v2.PARENT_SHA, 0o644),
                   packet.PREFIX + 'packet_v2.py': (packet_v3.PARENT_SHA, 0o644)}
        self.assertEqual(policy.HELPERS, {**old_policy.HELPERS, **packet_v3.BUILD_HELPERS, **parents})
        _, kernel, recipes = policy.closure(ROOT)
        self.assertEqual((kernel, recipes), old_policy.closure(ROOT)[1:])
        self.assertNotIn(packet_v2.ENROLL, self.rows)
        self.assertEqual(self.rows[packet_v2.HELD_SETUP]['sha256'], packet_v2.HELD_SETUP_SHA)
        for leaf, digest in packet_v2.SETUP_PINS.items():
            self.assertEqual(self.rows[f'{packet_v2.SETUP}/{leaf}']['sha256'], digest)
        for name, (digest, mode) in packet_v3.BUILD_HELPERS.items():
            self.assertEqual((self.rows[name]['sha256'], self.rows[name]['mode']), (digest, mode))
            old_digest, old_mode = old_policy.HELPERS[name]
            altered = {**self.rows, name: {**self.rows[name], 'sha256': old_digest, 'mode': old_mode}}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, '^frozen-producer-drift$'):
                policy.frozen(altered, kernel, recipes)

    def test_both_git_verifiers_capture_current_commit_and_reject_v2_pin(self):
        out = self.private / 'verified'
        old_pin = packet.sha(packet.read(ROOT / packet_v2.MANIFEST))
        self.assertNotEqual(self.pin, old_pin)
        with self.assertRaises(ValueError):
            self.inline['source'](ROOT, self.commit, old_pin)
        with self.assertRaisesRegex(ValueError, '^packet-pin$'):
            packet_v3.verify(ROOT, self.manifest, old_pin, self.commit, self.runner, out)
        self.assertFalse(out.exists())

        modes = {}
        captured = self.inline['source'](ROOT, self.commit, self.pin, modes)
        evidence = packet_v3.verify(ROOT, self.manifest, self.pin, self.commit, self.runner, out)
        self.assertEqual((evidence['status'], evidence['source_commit'], evidence['packet_sha256']),
                         ('PASS', self.commit, self.pin))
        self.assertEqual(evidence['files_map'], self.rows)
        self.assertEqual({name: packet.row(body, modes[name]) for name, body in captured.items()}, self.rows)
        self.assertEqual({name: packet.capture(out / name) for name in self.rows},
                         {name: (body, modes[name]) for name, body in captured.items()})

    def test_both_git_verifiers_refuse_changed_worktree_bytes(self):
        root = self.private_checkout()
        name = next(iter(sorted(packet_v3.BUILD_HELPERS)))
        changed = root / name
        changed.write_bytes(packet.read(changed) + b'\n')

        with self.assertRaises(ValueError):
            self.inline['source'](root, self.commit, self.pin)
        out = self.private / 'refused'
        with self.assertRaisesRegex(ValueError, '^packet-byte-mode-pin$'):
            packet_v3.verify(root, root / packet_v3.MANIFEST, self.pin, self.commit, self.runner, out)
        self.assertFalse((out / name).exists())

    def test_both_git_verifiers_refuse_repinning_an_uncommitted_lock(self):
        root = self.private_checkout()
        manifest = root / packet_v3.MANIFEST
        manifest.write_bytes(self.lock + b'\n')
        self.assertEqual(packet.load(manifest), packet.decode(self.lock))
        self.assert_repin_refused(root, manifest, 'uncommitted-formatting')

        name = packet.PREFIX + 'job.py'
        changed = root / name
        changed.write_bytes(packet.read(changed) + b'\n')
        altered = {'schema_version': 1, 'files': {**self.rows, name: packet.row(*packet.capture(changed))}}
        manifest.write_bytes((json.dumps(altered, sort_keys=True, indent=2) + '\n').encode())
        self.assert_repin_refused(root, manifest, 'uncommitted-job-row')

    def assert_repin_refused(self, root, manifest, output_name):
        pin = packet.sha(packet.read(manifest))
        self.assertNotEqual(pin, self.pin)

        with self.assertRaises(ValueError):
            self.inline['source'](root, self.commit, pin)
        out = self.private / output_name
        with self.assertRaisesRegex(ValueError, '^packet-v3-manifest-Git-binding$'):
            packet_v3.verify(root, manifest, pin, self.commit, self.runner, out)
        self.assertFalse(out.exists())

    def test_job_dispatch_projects_frozen_setup_and_current_helpers_before_daemon(self):
        root = self.private_checkout()
        output = root / 'artifacts/kernel-native-job/job-1-1'
        output.parent.mkdir(parents=True)
        args = SimpleNamespace(source_root=root, source_commit=self.commit, packet_sha256=self.pin,
                               packet=root / packet_v3.MANIFEST, output=output,
                               docker_endpoint='unix:///modeled-no-daemon')
        terminal = []
        with (patch.dict(os.environ, {'GITHUB_WORKSPACE': str(root)}),
              patch.object(job, 'ordinary'),
              patch.object(job.runtime, 'Runner', return_value=self.runner),
              patch.object(job, 'Docker', side_effect=ValueError('modeled daemon boundary')) as daemon,
              patch.object(packet, 'verify', side_effect=AssertionError('legacy verifier selected')) as legacy,
              patch.object(packet_v2, 'verify', side_effect=AssertionError('v2 verifier selected')) as v2,
              patch.object(packet_v3, 'verify', wraps=packet_v3.verify) as v3):
            self.assertEqual(job.work(args, terminal, monotonic()), 1)

        legacy.assert_not_called()
        v2.assert_not_called()
        v3.assert_called_once_with(root, args.packet, self.pin, self.commit, self.runner, output / 'private/source')
        daemon.assert_called_once_with(args)
        self.assertEqual(terminal, [])
        receipt = packet.load(output / 'private/result.json')
        self.assertEqual(receipt['source']['status'], 'PASS')
        self.assertEqual(receipt['source']['files_map'], self.rows)
        status = receipt['status']
        self.assertEqual((status['status'], status['producer'], status['native_compilation']),
                         ('FAIL', 'NOT RUN', 'NOT RUN'))

        source, producer = output / 'private/source', output / 'private/producer-source'
        self.assertFalse((source / packet_v2.ENROLL).exists())
        enrollment = packet.capture(producer / packet_v2.ENROLL)
        self.assertEqual((packet.sha(enrollment[0]), enrollment[1]), packet.HELPERS[packet_v2.ENROLL])
        self.assertEqual(enrollment, packet.capture(source / packet_v2.SETUP / 'cachy-asahi-repository'))
        recipes = packet.load(producer / packet.RECIPES_LOCK, packet.RECIPES_SHA)
        for recipe, expected in recipes.items():
            self.assertEqual({name: packet.sha(packet.read(producer / recipe / name))
                              for name in packet.walk(producer / recipe)}, expected)
        for name in packet_v3.BUILD_HELPERS:
            self.assertEqual(packet.row(*packet.capture(producer / name)), self.rows[name])
        self.assertEqual(packet.walk(producer), self.rows.keys() | {packet_v2.ENROLL})


if __name__ == '__main__':
    unittest.main()
