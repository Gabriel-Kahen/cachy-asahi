#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit real makepkg plus Fish/Zsh test; reports remain at --output."""
import argparse
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('first_login_rehearsal', HERE / 'first_login_rehearsal.py')
rehearsal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rehearsal)
ROOT = None
OUTPUT = None


class BuildAndRehearseTests(unittest.TestCase):
    def test_actual_four_recipe_assembly_and_real_shell_recovery(self):
        self.assertIsNotNone(ROOT, 'Run explicitly with --build-and-rehearse-test and --output')
        report = rehearsal.execute(ROOT, OUTPUT)
        self.assertEqual(report['status'], 'PASS')
        self.assertTrue(report['temporary_build_state_removed'])
        self.assertFalse(list(OUTPUT.glob('private-build-*')))
        self.assertEqual(set(report['builds']), set(rehearsal.RECIPES))
        self.assertEqual(report['recipe_check_functions'], 'NOT RUN (--nocheck)')
        self.assertEqual(report['dependency_resolution'], 'NOT RUN (--nodeps)')
        self.assertEqual(report['journey']['commands'], 41)
        self.assertEqual(report['journey']['journey']['actual_shell_startups'], 10)
        self.assertTrue(report['journey']['temporary_state_removed'])
        records = json.loads((OUTPUT / 'host-build-commands.json').read_text())
        self.assertTrue(all(row['success'] for row in records))
        for name in rehearsal.RECIPES:
            source = next(row for row in records if row['step'] == name + '-verify-local-source')
            build = next(row for row in records if row['step'] == name + '-assemble')
            self.assertLess(records.index(source), records.index(build))
            self.assertIn('--verifysource', source['argv'])
            for option in ('--nodeps', '--nocheck', '--nosign'):
                self.assertIn(option, build['argv'])
            self.assertEqual(build['environment']['SOURCE_DATE_EPOCH'], str(rehearsal.SOURCE_DATE_EPOCH))
        for name, member, relative in (
                ('first_login', 'usr/lib/cachy-asahi/first-login/first_login.py', 'packages/tools/cachy-asahi-first-login/first_login.py'),
                ('setup', 'usr/bin/cachy-asahi-setup', 'packages/tools/cachy-asahi-setup8/cachy-asahi-setup'),
                ('fish', 'usr/share/cachy-asahi/fish/config.fish', 'packages/shells/cachy-asahi-fish-config/config.fish'),
                ('zsh', 'usr/share/cachy-asahi/zsh/config.zsh', 'packages/shells/cachy-asahi-zsh-config/config.zsh')):
            self.assertEqual(report['journey']['packages'][name]['members'][member], rehearsal.journey.sha(ROOT / relative))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--root', type=Path, default=rehearsal.ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-and-rehearse-test', action='store_true')
    args, remaining = parser.parse_known_args()
    if not args.build_and_rehearse_test:
        parser.error('Execution requires --build-and-rehearse-test')
    ROOT, OUTPUT = args.root, args.output
    unittest.main(argv=[__file__, *remaining])
