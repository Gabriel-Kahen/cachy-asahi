# SPDX-License-Identifier: MIT
"""Focused checks for the separately sealed current-checker packet."""
from pathlib import Path
import unittest
from unittest.mock import Mock

import packet
import packet_v2

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

    def test_successor_changes_only_checker_and_keeps_independent_frozen_checks(self):
        policy = packet_v2._policy()
        self.assertEqual(policy.HELPERS, {**packet.HELPERS, packet_v2.CHECKER: (packet_v2.CHECKER_SHA, 0o644)})
        _, kernel, recipes = policy.closure(ROOT)
        rows = policy.preview(ROOT)['files']
        historical = packet.load(LEGACY, LEGACY_SHA)['files'][packet_v2.CHECKER]
        for bad_checker in (historical, {**rows[packet_v2.CHECKER], 'sha256': '0' * 64}):
            with self.subTest(checker=bad_checker), self.assertRaisesRegex(ValueError, 'frozen-producer-drift'):
                policy.frozen({**rows, packet_v2.CHECKER: bad_checker}, kernel, recipes)

    def test_successor_refuses_the_historical_manifest_path(self):
        runner = Mock()
        with self.assertRaisesRegex(ValueError, 'packet-v2-path'):
            packet_v2.verify(ROOT, LEGACY, LEGACY_SHA, 'a' * 40, runner, ROOT / 'unused')
        runner.run.assert_not_called()
