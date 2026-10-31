# SPDX-License-Identifier: MIT
"""Failure controls only; positive semantic comparisons always use real binaries."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prerequisites', HERE / 'platform_transition_prerequisites.py')
p = importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
ROOT = next(parent for parent in HERE.parents if (parent / 'scripts/platform/tuple_audit.py').is_file())
spec = importlib.util.spec_from_file_location('tuple_versions', ROOT / 'scripts/platform/tuple_audit.py')
audit = importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)


class PrerequisiteTests(unittest.TestCase):
    def test_missing_library_refuses_checker(self):
        with patch.object(p.ctypes.util, 'find_library', return_value=None):
            with self.assertRaisesRegex(ValueError, 'real preinstalled libalpm'):
                p.run()

    def test_original_missing_library_refuses_without_fallback(self):
        with patch.object(audit.ctypes.util, 'find_library', return_value=None):
            with self.assertRaisesRegex(ValueError, 'preinstalled libalpm is required'):
                audit.Versions()

    def test_wrong_expected_library_version_refuses(self):
        with self.assertRaisesRegex(ValueError, 'unexpected loaded libalpm version'):
            p.run('deliberately-incorrect-version')

    def test_missing_vercmp_refuses_checker(self):
        with patch.object(p.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'real preinstalled vercmp'):
                p.run()

    def test_real_preinstalled_version_semantics(self):
        result = p.run()
        self.assertEqual(len(result['observations']), 10)
        self.assertEqual(result['status'], 'PASS-real-version-prerequisites')
        self.assertFalse(result['hardware_accepted'])


if __name__ == '__main__':
    unittest.main()
