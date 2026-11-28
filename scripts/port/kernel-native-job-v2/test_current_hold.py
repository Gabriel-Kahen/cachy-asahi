# SPDX-License-Identifier: MIT
"""Current packet refusal and Setup source checks. Static replays the seal separately."""
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/port/kernel-native-job'))
import packet
import packet_v2
import packet_v3
from test_public import bootstrap

LEGACY = ROOT / packet.PREFIX / 'packet.lock.json'
LEGACY_SHA = '3676a36626bf55a925e395128fb32ab6a876642259f2eac2c4221a920db65e18'
MANIFEST = ROOT / packet_v2.MANIFEST
SUCCESSOR_POLICY = packet.PREFIX + 'packet_v3.py'
SUCCESSOR_CHANGES = {*packet_v3.BUILD_HELPERS, packet.WORKFLOW, packet.DOCUMENT,
                     packet.PREFIX + 'job.py', packet.PREFIX + 'test_public.py'}


class CurrentPacketTests(unittest.TestCase):
    def test_current_lock_preserves_historical_policy_and_preview_holds(self):
        legacy = packet.load(LEGACY, LEGACY_SHA)
        successor = packet.load(MANIFEST)
        policy = packet_v2._policy()
        names, kernel, recipes = policy.closure(ROOT)
        self.assertEqual(names - set(successor['files']), {SUCCESSOR_POLICY})
        self.assertFalse(set(successor['files']) - names)
        policy.frozen(successor['files'], kernel, recipes)
        self.assertEqual(legacy['files'][packet.PREFIX + 'packet.py']['sha256'], packet_v2.PARENT_SHA)
        historical_pin = packet.HELPERS[packet_v2.CHECKER]
        self.assertEqual(historical_pin[0], legacy['files'][packet_v2.CHECKER]['sha256'])
        self.assertNotEqual(historical_pin[0], packet_v2.CHECKER_SHA)
        self.assertEqual(successor['files'][packet_v2.CHECKER]['sha256'], packet_v2.CHECKER_SHA)
        with self.assertRaisesRegex(ValueError, '^frozen-producer-drift$'):
            packet_v2.preview(ROOT)
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
        rows = packet.load(MANIFEST)['files']
        policy.frozen(rows, kernel, recipes)
        self.assertNotIn(packet_v2.ENROLL, rows)
        historical = packet.load(LEGACY, LEGACY_SHA)['files'][packet_v2.CHECKER]
        for bad_checker in (historical, {**rows[packet_v2.CHECKER], 'sha256': '0' * 64}):
            with self.subTest(checker=bad_checker), self.assertRaisesRegex(ValueError, 'frozen-producer-drift'):
                policy.frozen({**rows, packet_v2.CHECKER: bad_checker}, kernel, recipes)
        legacy_recipes = packet.load(ROOT / packet.RECIPES_LOCK, packet.RECIPES_SHA)
        for leaf, digest in packet_v2.SETUP_PINS.items():
            name = f'{packet_v2.SETUP}/{leaf}'
            self.assertEqual(rows[name]['sha256'], digest)
            self.assertEqual(packet.row(*packet.capture(ROOT / name)), rows[name])
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

    def test_current_verifiers_refuse_the_v2_seal(self):
        inline = bootstrap()
        self.assertEqual(inline['PACKET'], packet_v3.MANIFEST)
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
            self.assertEqual(packet.read(MANIFEST), committed)
            rows = packet.decode(committed)['files']
            live = {name: packet.row(*packet.capture(ROOT / name)) for name in rows}
            changed = {name for name, row in rows.items() if live[name] != row}
            self.assertEqual(changed, SUCCESSOR_CHANGES)
            for name in changed:
                self.assertEqual(live[name]['mode'], rows[name]['mode'])
            output = Path(temporary) / 'source'
            runner = SimpleNamespace(run=run_git)
            with patch.dict(os.environ, {'GITHUB_SHA': commit, 'GITHUB_WORKFLOW_SHA': commit}):
                with self.assertRaisesRegex(ValueError, '^boundary$'):
                    inline['source'](ROOT, commit, LEGACY_SHA)
                with self.assertRaisesRegex(ValueError, '^packet-pin$'):
                    packet_v2.verify(ROOT, MANIFEST, LEGACY_SHA, commit, runner, output)
                self.assertFalse(output.exists())
                with patch.dict(inline, read=Mock(wraps=inline['read']),
                                committed=Mock(wraps=inline['committed'])):
                    with self.assertRaisesRegex(ValueError, '^boundary$'):
                        inline['source'](ROOT, commit, pin)
                    self.assertEqual(inline['read'].call_args.args[0], ROOT / packet_v3.MANIFEST)
                    inline['committed'].assert_not_called()
                with self.assertRaisesRegex(ValueError, '^packet-complete-set$'):
                    packet_v2.verify(ROOT, MANIFEST, pin, commit, runner, output)
            for name in changed:
                self.assertFalse((output / name).exists())

    def test_current_setup_sources_reconstruct_the_frozen_producer_recipes(self):
        rows = packet.load(MANIFEST)['files']
        recipes = packet.load(ROOT / packet.RECIPES_LOCK, packet.RECIPES_SHA)
        # Exercise the reconstruction on a recipe fixture during the packet HOLD.
        names = {f'{recipe}/{leaf}' for recipe, leaves in recipes.items() for leaf in leaves}
        names.update((packet.RECIPES_LOCK, packet_v2.HELD_SETUP))
        fixture_rows = {name: rows[name] for name in sorted(names)}
        with TemporaryDirectory(prefix='kernel-setup-producer-') as temporary:
            producer = Path(temporary) / 'producer-source'
            self.assertEqual(packet_v2.producer_snapshot(ROOT, producer, fixture_rows), producer)
            self.assertNotIn(packet_v2.ENROLL, fixture_rows)
            raw, mode = packet.capture(producer / packet_v2.ENROLL)
            self.assertEqual((packet.sha(raw), mode), packet.HELPERS[packet_v2.ENROLL])
            self.assertEqual((raw, mode), packet.capture(ROOT / packet_v2.SETUP / 'cachy-asahi-repository'))
            self.assertEqual(packet.load(producer / packet.RECIPES_LOCK, packet.RECIPES_SHA), recipes)
            for recipe, expected in recipes.items():
                self.assertEqual({name: packet.sha(packet.read(producer / recipe / name))
                                  for name in packet.walk(producer / recipe)}, expected)
