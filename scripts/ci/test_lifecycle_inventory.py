"""Pure inventory projection regressions; no package/native/Docker operations."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


inventory = module('lifecycle_inventory')
exporter = module('integration_export')


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = self.root / 'raw'; (self.raw / 'lifecycle').mkdir(parents=True)
        # This name/version is the real signed-base entry that triggered the
        # generic credential pattern. The rest of this fixture is synthetic.
        self.base = {'glibc': '2.43-2', 'libsecret': '0.21.8.2-1', 'pacman': '7.1.0.r7-1'}
        self.baseline = [{'name': name, 'version': '0.1.0-2'} for name in sorted(inventory.PACKAGES)]
        self.upgrade = [{'name': name, 'version': '0.1.0-3'} for name in sorted(inventory.PACKAGES)]

    def expected(self, kind):
        rows = self.baseline if kind == 'baseline' else self.upgrade
        return dict(self.base) if kind == 'base' else {**self.base, **{r['name']: r['version'] for r in rows}}

    def put(self, stage, value=None, data=None):
        path = self.raw / 'lifecycle' / (stage + '-inventory.json')
        if data is None:
            value = self.expected(inventory.STAGES[stage]) if value is None else value
            data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
        path.write_bytes(data)
        return path

    def project(self):
        return inventory.projections(self.raw, self.base, self.baseline, self.upgrade)

    def assert_refused_before_hash(self, value):
        self.put('before', value=value)
        with patch.object(inventory.hashlib, 'sha256', side_effect=AssertionError('invalid evidence hashed')), self.assertRaises((ValueError, UnicodeError)):
            self.project()

    def test_legitimate_libsecret_false_positive_projects_all_rows_for_generic_export(self):
        source = self.put('before'); original = source.read_bytes()
        match = exporter.PRIVATE_CONTENT.search(original.decode())
        self.assertEqual(match.group(0), 'secret": "0.21.8.2-1",')
        result = self.project()
        self.assertEqual(set(result), {'lifecycle/before-inventory.json'})
        record = json.loads(result['lifecycle/before-inventory.json'])
        self.assertEqual(record['original_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(record['original_bytes'], len(original))
        self.assertEqual({r['name']: r['version'] for r in record['packages']}, self.base)
        self.assertTrue(record['complete_inventory_matches_authority'])
        self.assertFalse(record['raw_bytes_exported'])
        self.assertIsNone(exporter.PRIVATE_CONTENT.search(result['lifecycle/before-inventory.json'].decode()))
        selected = self.root / 'selected'; (selected / 'lifecycle').mkdir(parents=True)
        for name, data in result.items():
            (selected / name).write_bytes(data)
        self.assertEqual(exporter.export_evidence(selected, self.root / 'public')['evidence_export'], 'PASS')
        self.assertEqual(source.read_bytes(), original)

    def test_all_eight_exact_stage_authorities_include_reinstalled_upgrade(self):
        originals = {}
        for stage in inventory.STAGES:
            path = self.put(stage); originals[str(path)] = path.read_bytes()
        result = self.project()
        self.assertEqual(len(result), 8)
        for path, data in result.items():
            record = json.loads(data)
            self.assertEqual({r['name']: r['version'] for r in record['packages']}, self.expected(record['authority']))
            self.assertEqual(record['package_count'], len(self.expected(record['authority'])))
        self.assertEqual(json.loads(result['lifecycle/reinstalled-inventory.json'])['authority'], 'upgrade')
        self.assertEqual({path: Path(path).read_bytes() for path in originals}, originals)

    def test_reinstalled_baseline_versions_refused_against_real_producer(self):
        self.put('reinstalled', value=self.expected('baseline'))
        with self.assertRaisesRegex(ValueError, 'complete accepted stage authority'):
            self.project()

    def test_empty_missing_extra_or_changed_complete_inventory_refused(self):
        missing = dict(self.base); del missing['libsecret']
        extra = {**self.base, 'unreviewed': '1-1'}
        changed = {**self.base, 'libsecret': '0.21.8.2-2'}
        for value in ({}, missing, extra, changed):
            with self.subTest(value=value):
                self.assert_refused_before_hash(value)

    def test_credentials_nested_values_controls_and_nonscalar_types_refused(self):
        values = ({**self.base, 'password': 'DO-NOT-PUBLISH'},
                  {**self.base, 'libsecret': 'password=DO-NOT-PUBLISH'},
                  {**self.base, 'libsecret': {'secret': 'DO-NOT-PUBLISH'}},
                  {**self.base, 'libsecret': ['DO-NOT-PUBLISH']},
                  {**self.base, 'libsecret': True}, {**self.base, 'libsecret': None},
                  {**self.base, 'libsecret': 1}, {**self.base, 'libsecret': '1\x00-1'},
                  {**self.base, 'libsecret': '1\n-1'}, {**self.base, 'libsecret': '1\x1b[31m-1'},
                  {**self.base, 'libsecret': '-----BEGIN PGP PRIVATE KEY BLOCK-----'},
                  {'packages': [{'name': 'secret', 'version': 'DO-NOT-PUBLISH'}]})
        for value in values:
            with self.subTest(value=value):
                self.assert_refused_before_hash(value)

    def test_invalid_utf8_duplicate_keys_nonfinite_or_nonobject_json_refused(self):
        for data in (b'\xff', b'{"libsecret":"1-1","libsecret":"2-1"}',
                     b'{"libsecret":NaN}', b'[]', b'"DO-NOT-PUBLISH"', b'123', b'null'):
            self.put('before', data=data)
            with self.subTest(data=data), patch.object(inventory.hashlib, 'sha256', side_effect=AssertionError('invalid input hashed')), self.assertRaises(ValueError):
                self.project()

    def test_all_present_inputs_validate_before_any_hash(self):
        self.put('before')
        self.put('upgraded', value={**self.expected('upgrade'), 'password': 'DO-NOT-PUBLISH'})
        with patch.object(inventory.hashlib, 'sha256', side_effect=AssertionError('earlier input hashed')), self.assertRaises(ValueError):
            self.project()

    def test_unknown_paths_omitted_and_private_content_still_rejected_generically(self):
        self.put('before')
        unknown = self.raw / 'lifecycle/unknown-inventory.json'
        unknown.write_bytes(b'{"password":"DO-NOT-PUBLISH"}')
        result = self.project()
        self.assertNotIn('lifecycle/unknown-inventory.json', result)
        receipt = exporter.export_evidence(self.raw, self.root / 'public')
        self.assertEqual(receipt['evidence_export'], 'FAIL')
        self.assertTrue(any(r['path'] == 'lifecycle/unknown-inventory.json' for r in receipt['rejected']))

    def test_absent_known_paths_are_omitted_for_partial_failure_evidence(self):
        self.assertEqual(self.project(), {})
        self.put('before')
        self.assertEqual(len(self.project()), 1)

    def test_relative_raw_root_refused_before_reads_or_hashing(self):
        with patch.object(inventory, 'real_directories', side_effect=AssertionError('relative root inspected')), \
                patch.object(inventory.hashlib, 'sha256', side_effect=AssertionError('relative input hashed')), \
                self.assertRaisesRegex(ValueError, 'absolute raw inventory directory'):
            inventory.projections(Path('raw'), self.base, self.baseline, self.upgrade)

    def test_symlink_hardlink_nonregular_and_symlink_ancestor_refused(self):
        source = self.put('before'); outside = self.root / 'outside.json'
        outside.write_bytes(source.read_bytes())
        source.unlink(); source.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.project()
        source.unlink(); os.link(outside, source)
        with self.assertRaises(ValueError):
            self.project()
        source.unlink(); os.mkfifo(source)
        with self.assertRaises(ValueError):
            self.project()
        source.unlink()
        folder = self.raw / 'lifecycle'; folder.rmdir(); folder.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.project()

    def test_raw_and_projected_bounds_refused_without_truncation(self):
        self.put('before', data=b' ' * 129)
        with patch.object(inventory, 'LIMIT', 128), self.assertRaises(ValueError):
            self.project()
        self.put('before')
        with patch.object(inventory, 'LIMIT', 512), self.assertRaisesRegex(ValueError, 'projection exceeds'):
            self.project()

    def test_unaccepted_base_or_overlay_authority_refused(self):
        for base in ({}, {**self.base, 'password': 'a b'}, {**self.base, self.baseline[0]['name']: '1-1'}):
            with self.subTest(base=base), self.assertRaises(ValueError):
                inventory.projections(self.raw, base, self.baseline, self.upgrade)
        for stage in ('baseline', 'upgrade'):
            invalid = copy.deepcopy(self.baseline if stage == 'baseline' else self.upgrade)
            invalid[1]['name'] = invalid[0]['name']
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                inventory.projections(self.raw, self.base, invalid if stage == 'baseline' else self.baseline,
                                      invalid if stage == 'upgrade' else self.upgrade)
