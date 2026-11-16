#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite constructor DATA controls; no actor, source execution or Root authority."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


P = module('v12_constructor_DATA', HERE / 'prepare.py')
V11 = module('v11_test_support_DATA', HERE.parent / 'successor_v11/test_data.py')


def parent_model():
    before = V11.parent_model()
    with patch.object(V11.P, 'PARENT', V11.P.identity(before)):
        return V11.P.render(before)


def write(files, root):
    root.mkdir()
    for name, (raw, mode) in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)


class SourceControls(unittest.TestCase):
    def test_complete340_inverse_and_every_outside_leaf_mode_unchanged(self):
        before = parent_model()
        with patch.object(P, 'PARENT', P.identity(before)):
            after = P.render(before)
            self.assertEqual(P.undo(after), before)
            self.assertEqual(set(after) - set(before), {P.MARKER} |
                {P.ARCHIVE + name for name in P.REPLACED | {'source-map.json'}})
            for name, row in before.items():
                if name not in P.REPLACED | {'source-map.json'}:
                    self.assertEqual(after[name], row, name)
            marker = json.loads(after[P.MARKER][0])
            self.assertTrue(marker['holds_preserved'])
            self.assertTrue(marker['unadmitted'])
            self.assertIsNone(marker['Root_grants'])
            self.assertIsNone(marker['dispatch'])
            self.assertEqual(marker['actual'], P.ACTUAL)
            self.assertTrue(all(marker[k] is False for k in ('resources_changed', 'recipe_changed',
                'workflows_changed', 'metadata_headers_changed', 'carrier_transport_changed',
                'metadata_normalization_changed', 'request_bounds_changed')))

    def test_constructor_changes_only_two_reviewed_module_function_sets(self):
        before = parent_model()
        P.check_delta(before, P.fs.snapshot(HERE / 'payload'))
        bad = P.fs.snapshot(HERE / 'payload')
        name = 'hosted/producer.py'
        bad[name] = (bad[name][0].replace(b"'--memory=8g'", b"'--memory=9g'"), 0o644)
        with self.assertRaises(ValueError):
            P.check_delta(before, bad)

    def test_inverse_refuses_changed_markers_payload_old_body_modes_and_namespace(self):
        before = parent_model()
        with patch.object(P, 'PARENT', P.identity(before)):
            after = P.render(before)
            for name in ('hosted/producer.py', 'hosted/qualification.py',
                         P.ARCHIVE + 'hosted/producer.py', 'source-map.json', P.MARKER):
                bad = dict(after)
                bad[name] = (bad[name][0] + b'FENCED tamper', 0o644)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    P.undo(bad)
            bad = dict(after, extra=(b'FENCED extra', 0o644))
            with self.assertRaises(ValueError):
                P.undo(bad)
            bad = dict(after)
            raw, _ = bad['hosted/producer.py']
            bad['hosted/producer.py'] = (raw, 0o755)
            with self.assertRaises(ValueError):
                P.undo(bad)

    def test_external_whole_profile_fresh_output_and_current_map_are_required(self):
        before = parent_model()
        parent = P.identity(before)
        with tempfile.TemporaryDirectory(prefix='FENCED-v12-constructor-') as directory:
            root = Path(directory)
            write(before, root / 'parent')
            constructor = root / 'constructor'
            constructor.mkdir()
            shutil.copytree(HERE / 'payload', constructor / 'payload')
            with patch.object(P, 'PARENT', parent), patch.object(P, 'HERE', constructor):
                files = P.render(before)
                profile = dict(schema=12, scope=P.SCOPE, parent=parent, actual=P.ACTUAL,
                    Root_review=None, accepted=None, unadmitted=True, constructor_files=P.inputs(),
                    **P.identity(files))
                raw = P.encode(profile)
                (constructor / 'constructor-profile.json').write_bytes(raw)
                pin = P.fs.pin(raw)['sha256']
                with self.assertRaises(ValueError):
                    P.construct(root / 'parent', root / 'bad', '0' * 64)
                self.assertFalse((root / 'bad').exists())
                result = P.construct(root / 'parent', root / 'output', pin)
                self.assertTrue(result['unadmitted'])
                self.assertEqual(result['actual'], P.ACTUAL)
                self.assertEqual(P.fs.snapshot(root / 'output'), files)
                with self.assertRaises((OSError, ValueError)):
                    P.construct(root / 'parent', root / 'output', pin)

    def test_committed_profile_matches_complete_constructor_inputs_and_null_template(self):
        profile = json.loads((HERE / 'constructor-profile.json').read_bytes())
        self.assertEqual(profile['schema'], 12)
        self.assertEqual(profile['parent'], P.PARENT)
        self.assertEqual(profile['actual'], P.ACTUAL)
        self.assertIsNone(profile['Root_review'])
        self.assertIsNone(profile['accepted'])
        self.assertTrue(profile['unadmitted'])
        self.assertEqual(profile['constructor_files'], P.inputs())
        self.assertEqual((HERE / 'Root-admission.TEMPLATE.json').read_bytes(),
                         (HERE.parent / 'successor_v11/Root-admission.TEMPLATE.json').read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
