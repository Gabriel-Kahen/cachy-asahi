#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in actual-package integration checks; require real local Fish/Zsh tools.

Run this file explicitly with a reviewed four-archive selection and its SHA-256.
Its name keeps package execution out of ordinary test_*.py source discovery.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('first_login_journey', HERE / 'first_login.py')
journey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journey)
INPUTS = None
INPUTS_PATH = None
INPUTS_SHA256 = None


class ActualFirstLoginTests(unittest.TestCase):
    def test_actual_four_package_developer_shell_journey(self):
        self.assertIsNotNone(INPUTS, 'Run explicitly with --inputs and --inputs-sha256; no fake inputs or skips')
        with tempfile.TemporaryDirectory(prefix='actual-first-login-test-') as temporary:
            output = Path(temporary) / 'evidence'
            report = journey.execute(INPUTS, output)
            self.assertEqual(report['status'], 'PASS')
            self.assertTrue(report['temporary_state_removed'])
            self.assertFalse(list(output.glob('private-journey-*')))
            self.assertEqual(report['journey']['actual_shell_startups'], 10)
            canonical = {
                'first_login': ('usr/lib/cachy-asahi/first-login/first_login.py', 'scripts/install/first_login.py'),
                'setup': ('usr/bin/cachy-asahi-setup', 'packages/tools/cachy-asahi-setup8/cachy-asahi-setup'),
                'fish': ('usr/share/cachy-asahi/fish/config.fish', 'packages/shells/cachy-asahi-fish-config/config.fish'),
                'zsh': ('usr/share/cachy-asahi/zsh/config.zsh', 'packages/shells/cachy-asahi-zsh-config/config.zsh')}
            for name, (member, source) in canonical.items():
                self.assertEqual(report['packages'][name]['members'][member], journey.sha(journey.ROOT / source))
            records = json.loads((output / 'first-login-commands.json').read_text())
            self.assertTrue(all(row['success'] and row['returncode'] == row['expected_returncode'] for row in records))
            exits = {row['step']: row['returncode'] for row in records}
            self.assertEqual(exits['interrupted-setup'], 75)
            self.assertEqual(exits['pending-new-selection-refused'], 2)
            self.assertEqual(exits['recover'], 0)

    def test_substituted_package_identity_fails_before_user_configuration_and_cleans(self):
        self.assertIsNotNone(INPUTS)
        altered = copy.deepcopy(INPUTS)
        altered['fish'] = copy.deepcopy(altered['zsh'])
        with tempfile.TemporaryDirectory(prefix='first-login-wrong-package-') as temporary:
            output = Path(temporary) / 'evidence'
            with self.assertRaises(journey.Failure):
                journey.execute(altered, output)
            self.assertFalse(list(output.glob('private-journey-*')))
            self.assertEqual(json.loads((output / 'result.json').read_text())['status'], 'FAIL')

    def test_cli_requires_explicit_temporary_execution_flag(self):
        with tempfile.TemporaryDirectory(prefix='first-login-opt-in-') as temporary:
            output = Path(temporary) / 'unused'
            result = subprocess.run([sys.executable, '-B', str(HERE / 'first_login.py'), '--inputs', str(INPUTS_PATH),
                                     '--inputs-sha256', INPUTS_SHA256, '--output', str(output)],
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn('--run-temporary-journey', result.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    args, remaining = parser.parse_known_args()
    INPUTS_PATH, INPUTS_SHA256 = args.inputs, args.inputs_sha256
    INPUTS = journey.selection(INPUTS_PATH, INPUTS_SHA256)
    unittest.main(argv=[__file__, *remaining])
