#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fenced constructor MODEL: only frozen external membership is substituted.

The exact eight-file adapter closure is not assumed present in the checkout.
Copying, whole-reference checks, namespace/mode rules and failure retirement
are the real constructor. No copied Source body is imported or executed.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {
            'os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'fcntl.flock'}:
        raise AssertionError('Constructor MODEL forbids operational event: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bankstown_prepare_model', HERE / 'prepare.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class PrepareControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bankstown-prepare-MODEL-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.carriers = self.root / 'carriers'
        self.carriers.mkdir()
        self.output = self.root / 'source'
        self.rows = {}
        for index, name in enumerate(sorted(P.REQUIRED)):
            path = self.carriers / ('%03d.DATA' % index)
            # Deliberately invalid Python proves construction never executes it.
            raw = ('MODEL inert body %03d: this is not executable Python\n' % index).encode()
            path.write_bytes(raw)
            self.rows[name] = dict(path=str(path), **P.H.pin(raw), mode=0o755 if index == 0 else 0o644)
        self.membership = patch.object(P, 'required_members', return_value=set(P.REQUIRED))
        self.membership.start()
        self.addCleanup(self.membership.stop)

    def prepare(self, rows=None, expected=None):
        rows = self.rows if rows is None else rows
        return P.prepare_source(file_rows=rows,
            file_rows_sha256=P.H.pin(P.H.encoded(rows))['sha256'] if expected is None else expected,
            output=self.output)

    def refuse_without_source(self, rows, errors=(ValueError, OSError)):
        with self.assertRaises(errors):
            self.prepare(rows)
        self.assertFalse(self.output.exists())

    def test_closed_byte_mode_map_aliases_and_all_authority_null(self):
        result = self.prepare()
        raw = (self.output / 'source-map.json').read_bytes()
        self.assertEqual(raw, (self.output / 'source.lock.json').read_bytes())
        value = json.loads(raw)
        self.assertEqual(value['kind'], 'BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1')
        self.assertEqual(value['operation'], 'bankstown-qt3-native-private-test-v1')
        self.assertTrue(value['actual'])
        self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertEqual(set(value['files']), set(self.rows))
        actual = {str(p.relative_to(self.output)) for p in self.output.rglob('*') if p.is_file()}
        self.assertEqual(actual, set(self.rows) | {'source-map.json', 'source.lock.json'})
        self.assertFalse(any(p.name == '.git' for p in self.output.rglob('*')))
        for name, row in self.rows.items():
            target = self.output / name
            self.assertEqual(P.H.pin(target.read_bytes()), {k: row[k] for k in ('bytes', 'sha256')})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), row['mode'])
            self.assertEqual(value['files'][name], {k: row[k] for k in ('bytes', 'sha256', 'mode')})
        self.assertEqual(result['source_lock'], P.H.pin(raw))
        self.assertEqual(result['files'], len(self.rows))
        self.assertIsNone(result['actual_selectors'])
        self.assertIsNone(result['Root_final_acceptance'])
        self.assertFalse(result['native_credit'])

    def test_external_selection_pin_and_missing_member_refuse(self):
        with self.assertRaisesRegex(ValueError, 'EXTERNAL_SOURCE_ROWS_PIN'):
            self.prepare(expected='0' * 64)
        self.assertFalse(self.output.exists())
        rows = copy.deepcopy(self.rows)
        del rows[next(iter(rows))]
        self.refuse_without_source(rows)

    def test_traversal_aliases_private_names_and_reserved_maps_refuse(self):
        for name in ('../escape', '/absolute', 'a//b', 'a/../b', 'a/./b', 'a/.git/b',
                     'work/input', '__pycache__/cached', 'a\\b', 'a/\u2603', 'source-map.json', 'source.lock.json'):
            with self.subTest(name=name):
                rows = copy.deepcopy(self.rows)
                rows[name] = copy.deepcopy(next(iter(rows.values())))
                self.refuse_without_source(rows)

    def test_invalid_mode_and_open_row_schema_refuse(self):
        for mode in (True, 0o600, 0o4755, 0o777):
            with self.subTest(mode=mode):
                rows = copy.deepcopy(self.rows)
                rows[next(iter(rows))]['mode'] = mode
                self.refuse_without_source(rows)
        rows = copy.deepcopy(self.rows)
        rows[next(iter(rows))]['Root_approved'] = True
        self.refuse_without_source(rows)

    def test_missing_drifted_oversized_or_boolean_reference_refuse(self):
        for change in ('missing', 'hash', 'size', 'boolean'):
            with self.subTest(change=change):
                rows = copy.deepcopy(self.rows)
                row = rows[next(iter(rows))]
                if change == 'missing':
                    row['path'] = str(self.root / 'absent')
                elif change == 'hash':
                    row['sha256'] = '0' * 64
                elif change == 'size':
                    row['bytes'] = 64 * 1024**2 + 1
                else:
                    row['bytes'] = True
                self.refuse_without_source(rows)

    def test_symlink_and_hardlink_source_operands_refuse(self):
        row = next(iter(self.rows.values()))
        alias = self.root / 'alias'
        alias.symlink_to(row['path'])
        rows = copy.deepcopy(self.rows)
        rows[next(iter(rows))]['path'] = str(alias)
        self.refuse_without_source(rows)
        alias.unlink()
        os.link(row['path'], alias)
        self.refuse_without_source(self.rows)

    def test_finite_membership_bound_refuses_before_body_reads(self):
        rows = copy.deepcopy(self.rows)
        for index in range(256):
            rows['MODEL/extra-%03d' % index] = copy.deepcopy(next(iter(rows.values())))
        self.refuse_without_source(rows)

    def test_existing_output_preserved(self):
        self.output.mkdir()
        marker = self.output / 'foreign.DATA'
        marker.write_bytes(b'preserve existing output')
        with self.assertRaisesRegex(ValueError, 'FRESH_AUDIO_SOURCE_OUTPUT'):
            self.prepare()
        self.assertEqual(marker.read_bytes(), b'preserve existing output')

    def test_file_directory_collision_refuses_before_publication(self):
        rows = copy.deepcopy(self.rows)
        row = copy.deepcopy(next(iter(rows.values())))
        rows.update({'MODEL/collision': row, 'MODEL/collision/child': copy.deepcopy(row)})
        with self.assertRaisesRegex(ValueError, 'SOURCE_FILE_DIRECTORY_COLLISION'):
            self.prepare(rows)
        self.assertFalse(self.output.exists())

    def test_late_io_failure_retires_only_owned_partial_source(self):
        actual_open = Path.open
        before = set(self.root.iterdir())
        def fail(path, *args, **kwargs):
            if path == self.output / 'source.lock.json':
                raise OSError('MODEL late map write fault')
            return actual_open(path, *args, **kwargs)
        with patch.object(Path, 'open', fail):
            with self.assertRaisesRegex(OSError, 'MODEL late map write fault'):
                self.prepare()
        self.assertFalse(self.output.exists())
        self.assertEqual(set(self.root.iterdir()), before)

    def test_foreign_entry_holds_cleanup_and_preserves_original_io_error(self):
        actual_open = Path.open
        foreign = self.output / 'foreign.DATA'
        def fail(path, *args, **kwargs):
            if path == self.output / 'source.lock.json':
                with actual_open(foreign, 'xb') as stream:
                    stream.write(b'MODEL foreign bytes never deleted')
                raise OSError('MODEL original writer failure')
            return actual_open(path, *args, **kwargs)
        with patch.object(Path, 'open', fail):
            with self.assertRaisesRegex(OSError, 'MODEL original writer failure') as error:
                self.prepare()
        self.assertEqual(foreign.read_bytes(), b'MODEL foreign bytes never deleted')
        self.assertTrue(any('Source cleanup held' in note for note in error.exception.__notes__))
        self.assertTrue((self.output / 'source-map.json').is_file())

    def test_frozen_admission_pin_refusal_is_not_mocked(self):
        self.membership.stop()
        key = 'scripts/port/bankstown-qt3-native-v1/admission.py'
        with self.assertRaisesRegex(ValueError, 'FROZEN_ADMISSION_SOURCE_REQUIRED'):
            P.required_members({})
        rows = {key: dict(next(iter(self.rows.values())), bytes=8276, sha256='0' * 64)}
        with self.assertRaisesRegex(ValueError, 'FROZEN_ADMISSION_SOURCE_PIN'):
            P.required_members(rows)


if __name__ == '__main__':
    unittest.main()
