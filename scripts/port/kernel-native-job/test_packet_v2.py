# SPDX-License-Identifier: MIT
"""Focused checks for the current packet and its frozen producer inputs."""
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import packet
import packet_v2
from test_public import bootstrap

ROOT = Path(__file__).resolve().parents[3]
LEGACY = ROOT / packet.PREFIX / 'packet.lock.json'
LEGACY_SHA = '3676a36626bf55a925e395128fb32ab6a876642259f2eac2c4221a920db65e18'


class CurrentPacketTests(unittest.TestCase):
    def test_successor_previews_exactly_and_preserves_historical_policy(self):
        legacy = packet.load(LEGACY, LEGACY_SHA)
        successor = packet.load(ROOT / packet_v2.MANIFEST)
        self.assertEqual(packet_v2.preview(ROOT), successor)
        self.assertEqual(legacy['files'][packet.PREFIX + 'packet.py']['sha256'], packet_v2.PARENT_SHA)
        historical_pin = packet.HELPERS[packet_v2.CHECKER]
        self.assertEqual(historical_pin[0], legacy['files'][packet_v2.CHECKER]['sha256'])
        self.assertNotEqual(historical_pin[0], packet_v2.CHECKER_SHA)
        self.assertEqual(successor['files'][packet_v2.CHECKER]['sha256'], packet_v2.CHECKER_SHA)
        with self.assertRaisesRegex(ValueError, 'frozen-producer-drift'):
            packet.preview(ROOT)

    def test_successor_checks_current_sources_and_rejects_historical_or_changed_bytes(self):
        policy = packet_v2._policy()
        helpers = dict(packet.HELPERS)
        helpers.pop(packet_v2.ENROLL)
        helpers.update({packet_v2.CHECKER: (packet_v2.CHECKER_SHA, 0o644),
                        packet_v2.HELD_SETUP: (packet_v2.HELD_SETUP_SHA, 0o644)})
        self.assertEqual(policy.HELPERS, helpers)
        _, kernel, recipes = policy.closure(ROOT)
        rows = policy.preview(ROOT)['files']
        self.assertNotIn(packet_v2.ENROLL, rows)
        historical = packet.load(LEGACY, LEGACY_SHA)['files'][packet_v2.CHECKER]
        for bad_checker in (historical, {**rows[packet_v2.CHECKER], 'sha256': '0' * 64}):
            with self.subTest(checker=bad_checker), self.assertRaisesRegex(ValueError, 'frozen-producer-drift'):
                policy.frozen({**rows, packet_v2.CHECKER: bad_checker}, kernel, recipes)
        legacy_recipes = packet.load(ROOT / packet.RECIPES_LOCK, packet.RECIPES_SHA)
        for leaf, digest in packet_v2.SETUP_PINS.items():
            name = f'{packet_v2.SETUP}/{leaf}'
            self.assertEqual(rows[name]['sha256'], digest)
            historical_row = {**rows[name], 'sha256': legacy_recipes[packet_v2.SETUP][leaf]}
            with self.subTest(recipe=name), self.assertRaisesRegex(ValueError, 'original-recipe-drift'):
                policy.frozen({**rows, name: historical_row}, kernel, recipes)

    def test_successor_refuses_the_historical_manifest_path(self):
        runner = Mock()
        with self.assertRaisesRegex(ValueError, 'packet-v2-path'):
            packet_v2.verify(ROOT, LEGACY, LEGACY_SHA, 'a' * 40, runner, ROOT / 'unused')
        runner.run.assert_not_called()

    def test_successor_requires_an_explicit_well_formed_pin_before_reading(self):
        runner = Mock()
        with patch.object(packet_v2, '_policy', side_effect=AssertionError('opened policy before pin check')):
            for pin in (None, b'a' * 64, '', 'a' * 63, 'A' * 64):
                with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, 'packet-pin'):
                    packet_v2.verify(ROOT, ROOT / packet_v2.MANIFEST, pin, 'a' * 40, runner, ROOT / 'unused')
        runner.run.assert_not_called()

    def test_both_verifiers_accept_the_committed_successor_lock(self):
        inline = bootstrap()
        self.assertEqual(inline['PACKET'], packet_v2.MANIFEST)
        manifest = ROOT / packet_v2.MANIFEST
        with TemporaryDirectory(prefix='kernel-packet-v2-') as temporary, patch.dict(
                os.environ, {'RUNNER_TEMP': temporary}):
            env = {'PATH': '/usr/bin:/bin', 'HOME': temporary, 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'LANG': 'C.UTF-8'}

            def run_git(argv, *, timeout, limit):
                self.assertEqual(argv[0], '/usr/bin/git')
                result = subprocess.run(argv, env=env, capture_output=True, timeout=timeout)
                self.assertLessEqual(len(result.stdout), limit)
                return result

            commit = inline['git'](ROOT, 'rev-parse', 'HEAD').decode().strip()
            committed = inline['git'](ROOT, 'show', f'{commit}:{packet_v2.MANIFEST}')
            pin = packet.sha(committed)
            output = Path(temporary) / 'source'
            runner = SimpleNamespace(run=run_git)
            with patch.dict(os.environ, {'GITHUB_SHA': commit, 'GITHUB_WORKFLOW_SHA': commit}):
                with self.assertRaises(ValueError):
                    inline['source'](ROOT, commit, LEGACY_SHA)
                with self.assertRaisesRegex(ValueError, 'packet-pin'):
                    packet_v2.verify(ROOT, manifest, LEGACY_SHA, commit, runner, output)
                self.assertFalse(output.exists())
                modes = {}
                captured = inline['source'](ROOT, commit, pin, modes)
                result = packet_v2.verify(ROOT, manifest, pin, commit, runner, output)

            self.assertEqual((result['status'], result['source_commit'], result['packet_sha256']), ('PASS', commit, pin))
            self.assertEqual(result['files_map'], packet.decode(committed)['files'])
            self.assertEqual({name: packet.row(body, modes[name]) for name, body in captured.items()}, result['files_map'])
            self.assertEqual(packet.capture(output / packet_v2.CHECKER),
                             (captured[packet_v2.CHECKER], modes[packet_v2.CHECKER]))

            producer = Path(temporary) / 'producer-source'
            self.assertEqual(packet_v2.producer_snapshot(output, producer, result['files_map']), producer)
            self.assertFalse((output / packet_v2.ENROLL).exists())
            raw, mode = packet.capture(producer / packet_v2.ENROLL)
            self.assertEqual((packet.sha(raw), mode), packet.HELPERS[packet_v2.ENROLL])
            recipes = packet.load(producer / packet.RECIPES_LOCK, packet.RECIPES_SHA)
            for recipe, expected in recipes.items():
                self.assertEqual({name: packet.sha(packet.read(producer / recipe / name))
                                  for name in packet.walk(producer / recipe)}, expected)
            for leaf in packet_v2.SETUP_PINS:
                name = f'{packet_v2.SETUP}/{leaf}'
                self.assertEqual(packet.row(*packet.capture(output / name)), result['files_map'][name])

            recipe = producer / packet_v2.SETUP
            prepared = subprocess.run(
                ['/usr/bin/bash', '-ec', 'startdir=$1; srcdir=$1; source "$1/PKGBUILD"; prepare', 'bash', recipe],
                env=env, capture_output=True, timeout=10,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr.decode())
