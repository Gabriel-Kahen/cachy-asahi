#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the active component signatures in a complete checkout."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('component_selector', HERE / 'select.py')
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)
POLICY = selector.policy_check(selector.decode((HERE / 'dependencies.json').read_bytes()))


class CheckoutSignatures(unittest.TestCase):
    def test_paths_eligible_for_narrow_selection_match_reviewed_signatures(self):
        for path, expected in POLICY['dependency_signatures'].items():
            if selector.protected_path(POLICY, path):
                continue
            with self.subTest(path=path):
                self.assertEqual(selector.dependency_signature((ROOT / path).read_bytes()), expected)


if __name__ == '__main__':
    unittest.main()
