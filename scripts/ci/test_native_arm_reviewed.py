# SPDX-License-Identifier: MIT
"""Source-only checks for the maintained producer's reviewed-map handoff."""
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from textwrap import dedent
import unittest
from unittest.mock import patch

import native_arm_reviewed as reviewed


class ReviewedBuildTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory(prefix='standalone-native-review-')
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.recipe = 'packages/shells/fixture'
        self.hashes = {'PKGBUILD': '1' * 64, 'payload': '2' * 64}
        self.lock = self.root / 'approved.json'
        self.lock.write_text(json.dumps({self.recipe: self.hashes}))
        self.pin = hashlib.sha256(self.lock.read_bytes()).hexdigest()
        self.output = self.root / 'out'
        self.log = self.root / 'build.log'
        self.builder = [sys.executable, str(reviewed.native_arm.ROOT / 'scripts/build/build.py')]
        self.command = [*self.builder, str(reviewed.native_arm.ROOT / self.recipe),
                        '--reviewed-inputs', str(self.root / 'producer-review.json'),
                        '--output', str(self.output)]

    def arguments(self, pin=None):
        return ['build', '--recipes', str(self.lock), '--recipes-sha256', pin or self.pin,
                '--output', str(self.output), '--cache', str(self.root / 'cache')]

    def test_only_exact_build_driver_receives_a_sealed_map(self):
        args = self.arguments()
        compare = [sys.executable, str(reviewed.native_arm.ROOT / 'scripts/build/compare.py')]
        calls = []
        transferred = []

        def previous(command, log, timeout):
            calls.append((command, log, timeout))
            return 'unchanged command'

        def producer(argv):
            self.assertEqual(argv, args)
            self.assertEqual(reviewed.native_arm.run(compare, self.log, 10), 'unchanged command')
            reviewed.native_arm.run(self.command, self.log, 7)
            return 0

        def child(command, *, stdout, stderr, timeout, pass_fds):
            self.assertEqual(command[:3], self.command[:3])
            self.assertEqual(command[-2], '--reviewed-inputs')
            self.assertNotIn(self.command[4], command)
            self.assertEqual(timeout, 7)
            self.assertEqual(stderr, subprocess.STDOUT)
            self.assertEqual(Path(stdout.name), self.log)
            descriptor, = pass_fds
            transferred.append(descriptor)
            self.assertEqual(command[-1], f'/proc/self/fd/{descriptor}')
            get_seals = getattr(fcntl, 'F_GET_SEALS', 1034)
            self.assertEqual(fcntl.fcntl(descriptor, get_seals) & reviewed.SEALS, reviewed.SEALS)
            self.assertEqual(json.loads(Path(command[-1]).read_bytes()), self.hashes)
            return subprocess.CompletedProcess(command, 0)

        with (patch.object(reviewed.native_arm, 'run', previous),
              patch.object(reviewed.native_arm, 'main', side_effect=producer),
              patch.object(reviewed.subprocess, 'run', side_effect=child) as launch):
            self.assertEqual(reviewed.main(args), 0)
            self.assertIs(reviewed.native_arm.run, previous)
        self.assertEqual(calls, [(compare, self.log, 10)])
        launch.assert_called_once()
        with self.assertRaises(OSError):
            os.fstat(transferred[0])

    def test_mismatched_pin_refuses_before_producer_or_child(self):
        with (patch.object(reviewed.native_arm, 'main') as producer,
              patch.object(reviewed.subprocess, 'run') as launch,
              contextlib.redirect_stderr(io.StringIO()) as stderr):
            self.assertEqual(reviewed.main(self.arguments('0' * 64)), 1)
        self.assertIn('reviewed input file changed', stderr.getvalue())
        producer.assert_not_called()
        launch.assert_not_called()

    def test_missing_review_or_unapproved_recipe_refuses_before_launch(self):
        runner = reviewed.bound_runner(lambda *args: self.fail('unexpected fallback'),
                                       {self.recipe: self.hashes})
        for command in (self.command[:3], [*self.command[:3], '--reviewed-inputs'],
                        [*self.command[:2], str(self.root / 'unknown'), *self.command[3:]]):
            with self.subTest(command=command):
                with (patch.object(reviewed.subprocess, 'run') as launch,
                      self.assertRaisesRegex(ValueError, 'unbound build recipe review')):
                    runner(command, self.log)
                launch.assert_not_called()

    def test_frozen_child_exit_and_review_descriptor_lifetime(self):
        runner = reviewed.bound_runner(None, {self.recipe: self.hashes})
        with patch.object(reviewed.subprocess, 'run', return_value=subprocess.CompletedProcess([], 17)) as launch:
            with self.assertRaisesRegex(ValueError, r'command failed \(17\)'):
                runner(self.command, self.log)
        descriptor, = launch.call_args.kwargs['pass_fds']
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_both_recipe_lock_versions_can_be_loaded_without_source_edits(self):
        for name in ('recipes.lock.json', 'setup-0.1.0-4-recipes.lock.json'):
            with self.subTest(name=name):
                path = reviewed.native_arm.ROOT / 'scripts/ci' / name
                args = ['build', '--recipes', str(path), '--recipes-sha256', reviewed.native_arm.sha(path)]
                with patch.object(reviewed.native_arm, 'main', return_value=0) as producer:
                    self.assertEqual(reviewed.main(args), 0)
                producer.assert_called_once_with(args)


class WorkflowRoutingTests(unittest.TestCase):
    def test_only_maintained_build_selects_the_reviewed_driver(self):
        path = reviewed.native_arm.ROOT / '.github/workflows/native-arm-build.yml'
        text = path.read_text()
        start = text.index('      - name: Authenticate inputs or build in isolated native containers')
        step = text[start:text.index('      - name: Retain bounded evidence', start)]
        body = dedent(step.split('        run: |\n', 1)[1])
        fixture = 'env() { printf "%s\\n" "$@"; }\n'
        for mode, driver in (('build', 'native_arm_reviewed.py'), ('audit', 'native_arm.py'),
                             ('integration', 'native_arm.py')):
            with self.subTest(mode=mode):
                recipe_lock = ('scripts/ci/setup-0.1.0-4-recipes.lock.json' if mode == 'build'
                               else 'scripts/ci/recipes.lock.json')
                settings = {key: 'fixture' for key in ('RUNNER_TEMP', 'RUNNER_ARCH', 'RUNNER_OS', 'GITHUB_SHA',
                            'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'NATIVE_INPUTS_PATH',
                            'INPUTS_SHA256', 'RECIPES_SHA256', 'INTEGRATION_SHA256')}
                settings.update(BUILD_MODE=mode, NATIVE_RECIPES_PATH=recipe_lock)
                result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', fixture + body],
                                        env=settings, check=True, capture_output=True, text=True, timeout=5)
                call = result.stdout.splitlines()
                at = call.index('python3')
                self.assertEqual(call[at:at + 4], ['python3', '-B', f'scripts/ci/{driver}', mode])
                self.assertEqual(call[call.index('--recipes') + 1], recipe_lock)
                self.assertEqual(call[call.index('--recipes-sha256') + 1], settings['RECIPES_SHA256'])


if __name__ == '__main__':
    unittest.main()
