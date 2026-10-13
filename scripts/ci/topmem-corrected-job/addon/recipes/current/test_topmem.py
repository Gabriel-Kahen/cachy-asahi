#!/usr/bin/python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors.
"""Finite synthetic procfs/CLI controls; no host proc, actors or system mutation."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parent
app = types.ModuleType('topmem');app.__file__=str(PACKAGE/'cachy-asahi-topmem')
exec(compile(Path(app.__file__).read_bytes(),app.__file__,'exec'),app.__dict__)


def status(pid,uid=1000,kib=32,name='editor'):
    return f'Name:\t{name}\nPid:\t{pid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nVmRSS:\t{kib} kB\n'.encode()


class FunctionalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.proc=Path(self.temp.name)
    def add(self,pid,raw):
        directory=self.proc/str(pid);directory.mkdir();(directory/'status').write_bytes(raw)
    def test_largest_current_uid_processes_and_pid_ties_have_deterministic_order(self):
        for pid,uid,kib in ((8,1000,64),(3,1000,64),(10,1000,0),(2,1001,1000),(11,1000,128)):
            self.add(pid,status(pid,uid,kib))
        value=app.snapshot(self.proc,uid=1000,limit=3)
        self.assertEqual([r['pid'] for r in value['processes']],[11,3,8]);self.assertEqual(value['matching_processes'],4)
        self.assertEqual(value['skipped']['other_users'],1);self.assertEqual(value['scope'],'current-real-uid')
    def test_kernel_KiB_conversion_requires_no_page_size_and_preserves_zero(self):
        with patch.object(os,'sysconf',side_effect=AssertionError('no page-size assumption')):
            self.assertEqual(app.process_status(status(3,kib=17),3,1000)['rss_bytes'],17408)
            self.assertEqual(app.process_status(status(3,kib=0),3,1000)['rss_bytes'],0)
    def test_names_with_spaces_are_retained_without_reading_command_arguments(self):
        self.add(3,status(3,name='editor work'));(self.proc/'3/cmdline').write_bytes(b'PRIVATE_TOKEN_DO_NOT_READ')
        value=app.snapshot(self.proc,uid=1000);self.assertEqual(value['processes'][0]['name'],'editor work')
        self.assertNotIn('PRIVATE_TOKEN',json.dumps(value))
    def test_bad_identity_duplicates_units_missing_values_and_huge_numbers_are_visible_skips(self):
        cases=(status(9),status(3)+b'VmRSS:\t1 kB\n',status(3).replace(b'32 kB',b'32 MB'),
            status(3).replace(b'32 kB',b'-1 kB'),status(3).replace(b'32 kB',b'nan kB'),status(3,kib=1<<64),
            status(3).replace(b'Uid:\t1000\t1000\t1000\t1000',b'Uid:\t1000'),status(3).replace(b'VmRSS:\t32 kB\n',b''))
        for raw in cases:
            with self.assertRaises(ValueError):app.process_status(raw,3,1000)
        self.add(3,cases[0]);value=app.snapshot(self.proc,uid=1000)
        self.assertEqual(value['skipped']['unavailable'],1);self.assertEqual(value['processes'],[])
    def test_status_read_is_capped_and_oversize_is_rejected(self):
        stream=io.BytesIO(b'x'*(app.MAX_STATUS+100));stream.close=lambda:None
        with patch.object(Path,'open',return_value=stream):raw=app.read_status(self.proc/'unread')
        self.assertEqual(len(raw),app.MAX_STATUS+1)
        with self.assertRaises(ValueError):app.process_status(raw,3,1000)
    def test_exit_permission_and_ordinary_read_failures_keep_useful_rows_and_counts(self):
        for pid in (3,4,5,6):self.add(pid,status(pid))
        actual=app.read_status
        def read(path):
            failures={'3':FileNotFoundError(),'4':PermissionError(),'5':OSError()}
            if path.parent.name in failures:raise failures[path.parent.name]
            return actual(path)
        with patch.object(app,'read_status',side_effect=read):value=app.snapshot(self.proc,uid=1000)
        self.assertEqual([r['pid'] for r in value['processes']],[6])
        self.assertEqual(value['skipped'],dict(other_users=0,raced=1,permission_denied=1,unavailable=0,read_errors=1))
    def test_cancellation_and_fatal_control_are_not_disguised_as_empty_snapshot(self):
        self.add(3,status(3))
        for first in (KeyboardInterrupt(),SystemExit(7)):
            with patch.object(app,'read_status',side_effect=first),self.assertRaises(type(first)) as caught:
                app.snapshot(self.proc,uid=1000)
            self.assertIs(caught.exception,first)
    def test_directory_scan_limit_marks_incomplete_snapshot(self):
        self.add(3,status(3));self.add(4,status(4));self.add(5,status(5))
        with patch.object(app,'MAX_ENTRIES',2):value=app.snapshot(self.proc,uid=1000)
        self.assertTrue(value['scan_truncated']);self.assertEqual(value['status_reads'],2)
    def test_non_PID_entries_and_other_user_kernel_thread_do_not_add_memory_rows(self):
        (self.proc/'self').mkdir();(self.proc/'0').mkdir();(self.proc/'01').mkdir();(self.proc/'１２').mkdir()
        self.add(3,status(3,uid=0).replace(b'VmRSS:\t32 kB\n',b''))
        value=app.snapshot(self.proc,uid=1000);self.assertEqual(value['processes'],[])
        self.assertEqual(value['status_reads'],1);self.assertEqual(value['skipped']['other_users'],1)
    def test_terminal_output_quotes_control_characters_and_JSON_keeps_exact_data(self):
        self.add(3,status(3,name='\x1b[31meditor'));value=app.snapshot(self.proc,uid=1000)
        out=io.StringIO()
        with patch.object(app,'snapshot',return_value=value),contextlib.redirect_stdout(out):self.assertEqual(app.main([]),0)
        self.assertNotIn('\x1b',out.getvalue());self.assertIn('\\u001b',out.getvalue());self.assertTrue(out.getvalue().isascii())
        out=io.StringIO()
        with patch.object(app,'snapshot',return_value=value),contextlib.redirect_stdout(out):self.assertEqual(app.main(['--json']),0)
        self.assertEqual(json.loads(out.getvalue()),value)
    def test_help_and_invalid_limits_never_scan_any_processes(self):
        for argv,code in ((['--help'],0),(['--limit','0'],2),(['--limit','51'],2),(['--limit','true'],2)):
            with patch.object(app,'snapshot',side_effect=AssertionError('scan forbidden')),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:app.main(argv)
                self.assertEqual(caught.exception.code,code)
    def test_unreadable_proc_root_and_invalid_programmatic_selections_refuse(self):
        with self.assertRaises(FileNotFoundError):app.snapshot(self.proc/'absent',uid=1000)
        for uid,limit in ((True,10),(-1,10),(1000,True),(1000,0),(1000,51)):
            with self.assertRaises(ValueError):app.snapshot(self.proc,uid=uid,limit=limit)
        out=io.StringIO()
        with patch.object(app,'snapshot',side_effect=PermissionError()),contextlib.redirect_stderr(out):self.assertEqual(app.main([]),1)
        self.assertIn('PermissionError',out.getvalue())
    def test_input_files_and_user_state_are_unchanged(self):
        self.add(3,status(3));before={str(p.relative_to(self.proc)):p.read_bytes() for p in self.proc.rglob('*') if p.is_file()}
        app.snapshot(self.proc,uid=1000)
        self.assertEqual(before,{str(p.relative_to(self.proc)):p.read_bytes() for p in self.proc.rglob('*') if p.is_file()})


if __name__=='__main__':unittest.main()
