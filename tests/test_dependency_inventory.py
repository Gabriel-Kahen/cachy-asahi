import unittest
import sys
from pathlib import Path

# Import the checked-in resolver and its sibling helpers.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "checks"))
from dependencies import resolve

class TestDependencyInventory(unittest.TestCase):
    def setUp(self):
        self.valid_reports = []
        self.overlay_provider = {'metadata': {
            'pkgname': ['project-provider'],
            'pkgver': ['1'],
            'pkgrel': ['1'],
            'provides': ['virtual-provider'],
            'conflicts': ['virtual-provider'],
        }}

    def test_phantom_provides(self):
        # Test that a string in 'provides' instead of a list causes error
        inventory = [{
            "name": "provider",
            "version": "1",
            "arch": "aarch64",
            "provides": "foo"
        }]
        with self.assertRaisesRegex(ValueError, "provides must be a list"):
            resolve(self.valid_reports, inventory)

    def test_malformed_rows(self):
        # Test non-dict row
        with self.assertRaisesRegex(ValueError, "invalid inventory item"):
            resolve(self.valid_reports, ["not a dict"])
        # Test missing name
        with self.assertRaisesRegex(ValueError, "invalid inventory item"):
            resolve(self.valid_reports, [{"version": "1", "arch": "any"}])
        # Test invalid version type
        with self.assertRaisesRegex(ValueError, "invalid aarch64 inventory item"):
            resolve(self.valid_reports, [{"name": "x", "version": 123, "arch": "any"}])

    def test_malformed_top_level(self):
        # Test non-list top level
        with self.assertRaisesRegex(ValueError, "inventory must be a list"):
            resolve(self.valid_reports, {})

    def test_malformed_fields(self):
        # Test empty name/version
        with self.assertRaisesRegex(ValueError, "invalid inventory item"):
            resolve(self.valid_reports, [{"name": "", "version": "1", "arch": "any"}])
        # Test invalid arch
        with self.assertRaisesRegex(ValueError, "invalid aarch64 inventory item"):
            resolve(self.valid_reports, [{"name": "x", "version": "1", "arch": "arm64"}])

    def test_valid_scenarios(self):
        # Test successful real provider
        inventory = [{
            "name": "foo",
            "version": "1.0",
            "arch": "any",
            "provides": ["bar=1.0"]
        }]
        resolve(self.valid_reports, inventory)

        # Test omitted provides
        inventory_no_provides = [{
            "name": "foo",
            "version": "1.0",
            "arch": "any"
        }]
        resolve(self.valid_reports, inventory_no_provides)

    def test_dependency_resolution(self):
        # Test consumer depends on f, provider provides f
        reports = [{
            'metadata': {
                'pkgname': ['consumer'],
                'pkgver': ['1'],
                'pkgrel': ['1'],
                'depends': ['f']
            },
            'errors': []
        }]
        # Case 1: Provider provides 'f' via name match
        inventory_direct = [{
            "name": "f",
            "version": "1",
            "arch": "any"
        }]
        res = resolve(reports, inventory_direct)
        self.assertEqual(len(res['errors']), 0)

        # Case 2: Provider provides 'f' via 'provides' list
        inventory_provides = [{
            "name": "provider",
            "version": "1",
            "arch": "any",
            "provides": ["f"]
        }]
        res = resolve(reports, inventory_provides)
        self.assertEqual(len(res['errors']), 0)

    def test_conflict_ignores_own_virtual_provision(self):
        result = resolve([self.overlay_provider], [])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['build_order'], ['project-provider'])

    def test_conflict_detects_competing_virtual_providers(self):
        selected = {'metadata': {
            'pkgname': ['other-provider'],
            'pkgver': ['1'],
            'pkgrel': ['1'],
            'provides': ['virtual-provider'],
        }}
        inventory = {
            'name': 'other-provider',
            'version': '1-1',
            'arch': 'aarch64',
            'provides': ['virtual-provider'],
        }
        cases = (
            ('selected', [self.overlay_provider, selected], []),
            ('inventory', [self.overlay_provider], [inventory]),
        )
        for origin, reports, inventory_rows in cases:
            with self.subTest(origin=origin):
                self.assertEqual(resolve(reports, inventory_rows)['errors'], [
                    'project-provider: conflicts intersects inventory/overlay: virtual-provider',
                ])

    def test_unresolved_provides(self):
        # Test malformed provide string (empty string in list)
        inventory = [{
            "name": "provider",
            "version": "1",
            "arch": "any",
            "provides": [""]
        }]
        with self.assertRaisesRegex(ValueError, "invalid provide string"):
            resolve(self.valid_reports, inventory)

if __name__ == '__main__':
    unittest.main()
