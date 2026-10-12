#!/usr/bin/env python3
"""Synthetic Cargo output validation only; never execute Cargo or compiled code."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('worker_build', Path(__file__).with_name('worker-build.py'))
worker_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker_build)


def fixture():
    packages = [{'id': name, 'name': name, 'targets': [{'kind': ['bin'] if name == 'arch-update-tray' else ['custom-build']}]} for name in ('arch-update-tray', 'gettext-sys', 'system-deps')]
    metadata = {'packages': packages, 'resolve': {'nodes': [
        {'id': p['id'], 'features': ['gettext-system'] if p['name'] == 'gettext-sys' else ['default']} for p in packages]}}
    events = [{'reason': 'compiler-artifact', 'package_id': p['id'], 'features': list(node['features']),
               'target': p['targets'][0], 'executable': '/tmp/target/tray' if p['name'] == 'arch-update-tray' else None} for p, node in zip(packages, metadata['resolve']['nodes'])]
    events += [{'reason': 'build-script-executed', 'package_id': 'gettext-sys', 'cfgs': [], 'env': [], 'linked_libs': [], 'linked_paths': []}, {'reason': 'build-finished', 'success': True}]
    return metadata, events


def parse(metadata, events):
    return worker_build.unit_evidence(json.dumps(metadata).encode(),
                                      b'\n'.join(json.dumps(e).encode() for e in events), Path('/tmp/target/tray'))


class UnitTests(unittest.TestCase):
    def test_actual_records_remain_distinct_from_metadata_union(self):
        metadata, events = fixture()
        metadata['resolve']['nodes'][0]['features'].append('uncompiled-union-feature')
        result = parse(metadata, events)
        self.assertEqual(len(result['compiler_artifacts']), 3)
        self.assertNotIn('uncompiled-union-feature', result['compiler_artifacts'][0]['features'])

    def test_extra_source_or_actual_feature_refused(self):
        for key, value in [('package_id', 'unreviewed-source'), ('features', ['unreviewed-feature'])]:
            metadata, events = fixture();events[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): parse(metadata, events)

    def test_gettext_system_and_system_deps_binary_conditions_enforced(self):
        metadata, events = fixture();events[1]['features'] = []
        with self.assertRaisesRegex(ValueError, 'gettext'): parse(metadata, events)
        metadata, events = fixture();metadata['resolve']['nodes'][2]['features'].append('binary');events[2]['features'].append('binary')
        with self.assertRaisesRegex(ValueError, 'system-deps'): parse(metadata, events)

    def test_build_script_run_requires_compiled_script_feature_record(self):
        metadata, events = fixture();events.pop(1)
        with self.assertRaisesRegex(ValueError, 'retained compiled unit'): parse(metadata, events)

    def test_failed_incomplete_or_wrong_binary_cannot_pass(self):
        for failure in ('failed', 'missing-end', 'wrong-binary'):
            metadata, events = fixture()
            if failure == 'failed': events[-1]['success'] = False
            if failure == 'missing-end': events.pop()
            if failure == 'wrong-binary': events[0]['executable'] = '/tmp/another-tray'
            with self.subTest(failure=failure), self.assertRaises(ValueError): parse(metadata, events)


if __name__ == '__main__':
    unittest.main()
