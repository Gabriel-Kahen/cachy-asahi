#!/usr/bin/env python3
"""Causal inventory gates and retained boundaries; no system actors are executed."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('composed_real_check', Path(__file__).with_name('updater-v2-real-check.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def inventory(count):
    return {'cachy-asahi-update': '4.4.2-2'} | {'base-' + str(i): '1-1' for i in range(count - 1)}


def encoded(rows):
    return ''.join(name + ' ' + version + '\n' for name, version in sorted(rows.items())).encode('ascii')


class InventoryGates(unittest.TestCase):
    def test_default_requires_original_standalone_count(self):
        rows = inventory(360)
        self.assertEqual(fixture.validate_inventory(encoded(rows)), rows)
        with self.assertRaisesRegex(ValueError, 'standalone runtime'):
            fixture.validate_inventory(encoded(inventory(587)))

    def test_composed_inventory_requires_full_equality(self):
        expected = inventory(587)
        self.assertEqual(fixture.validate_inventory(encoded(expected), expected), expected)
        actual = dict(expected, **{'base-0': '2-1'})
        with self.assertRaisesRegex(ValueError, 'composed runtime'):
            fixture.validate_inventory(encoded(actual), expected)

    def test_composed_count_and_new_updater_identity_are_required(self):
        expected = inventory(587)
        for actual, wanted in ((inventory(586), expected), (expected, inventory(586)),
                               (dict(expected, **{'cachy-asahi-update': '4.4.2-1'}),
                                dict(expected, **{'cachy-asahi-update': '4.4.2-1'}))):
            with self.subTest(actual=len(actual), wanted=len(wanted)), self.assertRaisesRegex(ValueError, 'composed runtime'):
                fixture.validate_inventory(encoded(actual), wanted)

    def test_duplicate_or_malformed_rows_cannot_hide_missing_base_package(self):
        expected = inventory(587)
        actual = encoded(expected).splitlines()
        actual[-1] = actual[0]
        malformed = (b'\n'.join(actual) + b'\n', encoded(expected).replace(b' 1-1', b'  1-1', 1),
                     encoded(expected).replace(b' 1-1', b' \x001-1', 1))
        for data in malformed:
            with self.subTest(data_length=len(data)), self.assertRaisesRegex(ValueError, 'invalid or duplicate'):
                fixture.validate_inventory(data, expected)

    def test_inert_fixture_preexistence_is_rejected_even_if_expected(self):
        expected = inventory(587)
        del expected['base-0']
        expected[fixture.NAME] = '0.1.0-1'
        with self.assertRaisesRegex(ValueError, 'fixture already installed'):
            fixture.validate_inventory(encoded(expected), expected)

    def test_default_host_guard_still_precedes_all_actors(self):
        for expected in (None, inventory(587)):
            with self.subTest(composed=expected is not None), \
                 patch.object(fixture.platform, 'machine', return_value='x86_64'), \
                 patch.object(fixture.subprocess, 'run', side_effect=AssertionError('must not execute')) as actor:
                result = fixture.exercise(Path('/missing'), Path('/missing/key'), 'A' * 40,
                                          expected_inventory=expected)
                actor.assert_not_called()
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['phase'], 'container-guard')
            self.assertEqual(result['error_type'], 'ValueError')
            self.assertEqual(result['cases'], {})

    def test_updater_payload_query_retains_one_mib_bound(self):
        argv = ['/usr/bin/pacman', '-Qlq', 'cachy-asahi-update']
        for length, accepted in ((88073, True), (1024**2 + 1, False)):
            process = subprocess.CompletedProcess(argv, 0, stdout=b'x' * length, stderr=b'')
            with self.subTest(length=length), patch.object(fixture.subprocess, 'run', return_value=process):
                if accepted:
                    self.assertEqual(len(fixture.capture(argv).stdout), length)
                else:
                    with self.assertRaisesRegex(ValueError, 'diagnostic exceeds bound'):
                        fixture.capture(argv)

    def test_other_commands_keep_original_output_bound(self):
        argv = ['/usr/bin/pacman', '-Q']
        process = subprocess.CompletedProcess(argv, 0, stdout=b'x' * 65537, stderr=b'')
        with patch.object(fixture.subprocess, 'run', return_value=process), \
             self.assertRaisesRegex(ValueError, 'diagnostic exceeds bound'):
            fixture.capture(argv)


if __name__ == '__main__':
    unittest.main()
