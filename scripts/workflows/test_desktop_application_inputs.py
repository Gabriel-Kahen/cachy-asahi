#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit input parsing, exact argv launch and local byte-custody controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import unittest
from unittest import mock

import desktop_application_inputs as inputs
import desktop_application_runtime as runtime
import test_desktop_application_runtime as base_tests


class InputTests(unittest.TestCase):
    def setUp(self):
        self.fixture = base_tests.RuntimeTests('test_natural_close')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.first = self.fixture.base / 'first "quoted";$(literal) %f ü.txt'
        self.first.write_text('first data\n')
        self.second = self.fixture.base / 'second file.txt'
        self.second.write_text('second data\n')

    def records(self, *paths):
        return inputs.prepare([dict(kind='file', value=str(path)) for path in paths])

    def uri_records(self, *values, allowed=('file', 'http', 'https')):
        return inputs.prepare([dict(kind='uri', value=value) for value in values], allowed)

    def execute(self, field, items, allowed=()):
        f = self.fixture
        f.entry.write_text('[Desktop Entry]\nType=Application\nName=Fixture Name\nExec=fixture ' + field + '\n')
        f.script('import json,sys\nprint("READY",json.dumps(sys.argv[1:]),flush=True)\n')
        f.args.inputs, f.args.allow_uri_scheme = items, allowed
        return f.run_case()

    def test_single_file_exact_boundaries(self):
        row = self.execute('%f', [dict(kind='file', value=str(self.first))])
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(json.loads(row['output'].split('READY ', 1)[1]), [str(self.first)])
        self.assertEqual(row['inputs'][0]['state'], 'UNCHANGED')
        self.assertEqual(row['inputs'][0]['before']['sha256'], hashlib.sha256(self.first.read_bytes()).hexdigest())

    def test_many_files_exact_order(self):
        row = self.execute('%F', [dict(kind='file', value=str(x)) for x in (self.second, self.first, self.second)])
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(json.loads(row['output'].split('READY ', 1)[1]), [str(self.second), str(self.first), str(self.second)])

    def test_single_uri_exact(self):
        value = 'https://example.invalid/a%20b?q=%25f&literal=%22quoted%22#section'
        row = self.execute('%u', [dict(kind='uri', value=value)], ['https'])
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(json.loads(row['output'].split('READY ', 1)[1]), [value])
        self.assertEqual(row['inputs'][0]['state'], 'URI_PASSED_WITHOUT_FETCH')

    def test_mixed_uri_list_order(self):
        values = [dict(kind='file', value=str(self.first)), dict(kind='uri', value='https://example.invalid/a?b=c&d=e'),
                  dict(kind='uri', value=self.second.as_uri())]
        row = self.execute('%U', values, ['https', 'file'])
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(json.loads(row['output'].split('READY ', 1)[1]),
                         [self.first.as_uri(), values[1]['value'], self.second.as_uri()])

    def test_embedded_single_field(self):
        argv = inputs.expand('fixture --input=%f', records=self.records(self.first))
        self.assertEqual(argv, ['fixture', '--input=' + str(self.first)])

    def test_no_input_behavior_held(self):
        for field in ('%f', '%F', '%u', '%U'):
            self.assertEqual(inputs.expand('fixture ' + field), ['fixture'])

    def test_literal_percent_not_expanded(self):
        self.assertEqual(inputs.expand('fixture %%f %f', records=self.records(self.first)),
                         ['fixture', '%f', str(self.first)])

    def test_other_fields_are_not_reexpanded(self):
        argv = inputs.expand('fixture %c %k %% %f', name='Name %u', location='/entry %F.desktop', records=self.records(self.first))
        self.assertEqual(argv, ['fixture', 'Name %u', '/entry %F.desktop', '%', str(self.first)])

    def test_placeholder_collision_is_bounded(self):
        with mock.patch.object(inputs.secrets, 'token_hex', return_value='fixed'):
            with self.assertRaisesRegex(ValueError, 'collision budget'):
                inputs.expand('fixture %c %f', name='CAA_INPUT_fixed', records=self.records(self.first))

    def test_single_fields_refuse_multiple(self):
        for field in ('%f', '%u'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'at most one'):
                inputs.expand('fixture ' + field, records=self.records(self.first, self.second))

    def test_repeated_or_mixed_fields_refused(self):
        for text in ('%f %f', '%F %U', '%u %f'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                inputs.expand('fixture ' + text, records=self.records(self.first))

    def test_multifields_must_stand_alone(self):
        for text in ('--file=%F', 'prefix%U'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'stand alone'):
                inputs.expand('fixture ' + text, records=self.records(self.first))

    def test_quoted_fields_refused(self):
        for field in ('%f', '%F', '%u', '%U'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'quoted'):
                inputs.expand('fixture "' + field + '"', records=self.records(self.first))

    def test_unknown_field_refused(self):
        with self.assertRaisesRegex(ValueError, 'unknown'):
            inputs.expand('fixture %z', records=self.records(self.first))

    def test_inputs_without_field_refused_before_launch(self):
        with mock.patch.object(runtime, 'launch') as launch:
            with self.assertRaisesRegex(ValueError, 'no file/URI field'):
                self.execute('--help', [dict(kind='file', value=str(self.first))])
            launch.assert_not_called()

    def test_remote_uri_cannot_enter_file_field(self):
        for field in ('%f', '%F'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'remote download unsupported'):
                inputs.expand('fixture ' + field, records=self.uri_records('https://example.invalid/a'))

    def test_file_uri_converts_to_local_path(self):
        self.assertEqual(inputs.expand('fixture %f', records=self.uri_records(self.first.as_uri())), ['fixture', str(self.first)])

    def test_file_option_converts_to_uri(self):
        self.assertEqual(inputs.expand('fixture %u', records=self.records(self.first)), ['fixture', self.first.as_uri()])

    def test_uri_schemes_are_opt_in(self):
        for value in (self.first.as_uri(), 'http://example.invalid/', 'https://example.invalid/'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'not explicitly allowed'):
                self.uri_records(value, allowed=())

    def test_unsafe_uri_policies_refused(self):
        for scheme in ('javascript', 'data', 'ssh', 'ftp'):
            with self.subTest(scheme=scheme), self.assertRaisesRegex(ValueError, 'only file, http, https'):
                inputs.prepare([], [scheme])

    def test_malformed_remote_uris_refused(self):
        values = ['https:///no-host', 'https://user:pass@example.invalid/a', 'https://example.invalid/%zz',
                  'https://example.invalid/a b', 'https://example.invalid/\n', 'https://example.invalid/\\x',
                  'https://example.invalid:99999/', 'https://example.invalid:abc/', 'https://%65xample.invalid/a',
                  'https://example.invalid:/', 'https://[::1]trailing/', 'https://example.invalid|junk/',
                  'https://example.invalid/"literal"']
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.uri_records(value)

    def test_nonlocal_or_ambiguous_file_uris_refused(self):
        for value in ('file://host.invalid/a', 'file://localhost/a', self.first.as_uri() + '?q=x',
                      self.first.as_uri() + '#frag', 'file:/tmp/a', 'file:///tmp/%00', 'file:///tmp/%2fetc'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.uri_records(value)

    def test_relative_or_noncanonical_files_refused(self):
        for value in ('relative', str(self.first.parent / '..' / self.first.name), '//tmp/file', str(self.first) + '/..'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                inputs.prepare([dict(kind='file', value=value)])

    def test_file_symlink_and_directory_symlink_refused(self):
        alias = self.fixture.base / 'alias'
        alias.symlink_to(self.first)
        folder = self.fixture.base / 'folder-alias'
        folder.symlink_to(self.first.parent)
        for path in (alias, folder / self.first.name):
            with self.subTest(path=path), self.assertRaises(OSError):
                self.records(path)

    def test_fifo_and_directory_refused(self):
        fifo = self.fixture.base / 'input-fifo'
        os.mkfifo(fifo)
        for path in (fifo, self.first.parent):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'regular file'):
                self.records(path)

    def test_missing_local_input_refused(self):
        with self.assertRaises(FileNotFoundError):
            self.records(self.fixture.base / 'absent')

    def test_per_file_size_cap(self):
        with mock.patch.object(inputs, 'MAX_FILE', 3):
            with self.assertRaisesRegex(ValueError, 'byte budget'):
                self.records(self.first)

    def test_aggregate_size_cap(self):
        with mock.patch.object(inputs, 'MAX_TOTAL', self.first.stat().st_size):
            with self.assertRaisesRegex(ValueError, 'byte budget'):
                self.records(self.first, self.second)

    def test_input_count_cap(self):
        with self.assertRaisesRegex(ValueError, 'count cap'):
            inputs.prepare([dict(kind='file', value=str(self.first))] * 65)

    def test_changed_input_retains_application_result(self):
        f = self.fixture
        f.entry.write_text('[Desktop Entry]\nType=Application\nName=Fixture\nExec=fixture %f\n')
        f.script('import sys\nfrom pathlib import Path\nPath(sys.argv[1]).write_text("edited")\nprint("READY",flush=True)\n')
        f.args.inputs = [dict(kind='file', value=str(self.first))]
        row = f.run_case()
        self.assertEqual(row['status'], 'INPUT_CHANGED')
        self.assertEqual(row['application_status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(row['exit'], 0)
        self.assertEqual(row['inputs'][0]['state'], 'CHANGED')

    def test_removed_input_retains_application_result(self):
        records = self.records(self.first)
        self.first.unlink()
        checked = inputs.verify(records)
        self.assertEqual(checked[0]['state'], 'UNVERIFIED')
        self.assertEqual(checked[0]['before'], records[0]['before'])

    def test_replacement_during_hashing_refused(self):
        original_read = inputs.os.read
        replaced = False
        def read(fd, count):
            nonlocal replaced
            block = original_read(fd, count)
            if block and not replaced:
                replacement = self.fixture.base / 'replacement'
                replacement.write_bytes(b'replacement')
                replacement.replace(self.first)
                replaced = True
            return block
        with mock.patch.object(inputs.os, 'read', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'changed while reading'):
                self.records(self.first)

    def test_ordered_argument_action(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--file', dest='inputs', action=inputs.InputAction)
        parser.add_argument('--uri', dest='inputs', action=inputs.InputAction)
        parsed = parser.parse_args(['--file', str(self.first), '--uri', 'https://example.invalid/', '--file', str(self.second)])
        self.assertEqual([item['kind'] for item in parsed.inputs], ['file', 'uri', 'file'])

    def test_failed_identity_checks_still_charge_shared_read_budget(self):
        records = self.records(self.first, self.first)
        cap = self.first.stat().st_size + 1
        original_read = inputs.os.read
        read_bytes = 0
        generation = 0
        def read(fd, count):
            nonlocal read_bytes
            block = original_read(fd, count)
            read_bytes += len(block)
            return block
        def unstable(info):
            nonlocal generation
            generation += 1
            return {'generation': generation}
        with mock.patch.object(inputs, 'MAX_TOTAL', cap), \
             mock.patch.object(inputs.os, 'read', side_effect=read), \
             mock.patch.object(inputs, 'metadata', side_effect=unstable):
            rows = inputs.verify(records)
        self.assertEqual([row['state'] for row in rows], ['UNVERIFIED', 'UNVERIFIED'])
        self.assertEqual(read_bytes, cap - 1)
        self.assertLessEqual(read_bytes, cap)
        self.assertIn('byte budget', rows[1]['error'])

    def test_pseudo_regular_unknown_size_refused(self):
        with self.assertRaisesRegex(ValueError, 'size differs from metadata'):
            inputs.bind_file('/proc/' + str(os.getpid()) + '/cmdline')

    def test_remote_scheme_case_preserves_uri(self):
        value = 'HTTPS://Example.Invalid/a?q=one'
        records = self.uri_records(value, allowed=('https',))
        self.assertEqual(inputs.expand('fixture %u', records=records), ['fixture', value])

    def test_embedded_single_uri(self):
        records = self.uri_records('https://example.invalid/a;literal=$x?q=(one)&quote=%22')
        self.assertEqual(inputs.expand('fixture --uri=%u', records=records), ['fixture', '--uri=' + records[0]['value']])

    def test_prelaunch_local_change_refused(self):
        original_prepare = inputs.prepare
        def prepare(*args, **kwargs):
            selected = original_prepare(*args, **kwargs)
            self.first.write_text('changed before launch')
            return selected
        with mock.patch.object(inputs, 'prepare', side_effect=prepare), mock.patch.object(runtime, 'launch') as launch:
            with self.assertRaisesRegex(ValueError, 'changed before launch'):
                self.execute('%f', [dict(kind='file', value=str(self.first))])
            launch.assert_not_called()

    def test_terminal_wrapper_preserves_file_arguments(self):
        f = self.fixture
        f.write('usr/bin/input-terminal', '#!' + f.interpreter + '\nimport os,sys\nassert sys.argv[1]=="--"\nos.execv(sys.argv[2],sys.argv[2:])\n', 0o755)
        f.env['terminal_argv'] = ['input-terminal', '--']
        f.entry.write_text('[Desktop Entry]\nType=Application\nName=Fixture\nExec=fixture %F\nTerminal=true\n')
        f.script('import json,sys\nprint("READY",json.dumps(sys.argv[1:]),flush=True)\n')
        f.args.inputs = [dict(kind='file', value=str(x)) for x in (self.first, self.second)]
        row = f.run_case()
        self.assertEqual(row['status'], 'PASS_EXEC_WORKFLOW')
        self.assertEqual(json.loads(row['output'].split('READY ', 1)[1]), [str(self.first), str(self.second)])

    def test_remote_uri_validation_never_connects(self):
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('network call')):
            records = self.uri_records('https://example.invalid/a?q=b&c=d')
            self.assertEqual(inputs.expand('fixture %U', records=records), ['fixture', records[0]['value']])


if __name__ == '__main__':
    unittest.main()
