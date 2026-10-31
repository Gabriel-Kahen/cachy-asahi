# SPDX-License-Identifier: MIT
"""Disposable sources only: never query the host journal or pstore."""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
TOOL = HERE / 'cachy-asahi-boot-report'
loader = importlib.machinery.SourceFileLoader('boot_report', str(TOOL))
spec = importlib.util.spec_from_loader(loader.name, loader)
M = importlib.util.module_from_spec(spec)
loader.exec_module(M)
B1, B2 = '1' * 32, '2' * 32
ROWS = [{'index': -1, 'boot_id': B1, 'first_entry': 1, 'last_entry': 2},
        {'index': 0, 'boot_id': B2, 'first_entry': 3, 'last_entry': 4}]
RECORD = {'_BOOT_ID': B1, '_TRANSPORT': 'kernel', '__CURSOR': 'disposable-cursor',
          '__REALTIME_TIMESTAMP': '1', '__MONOTONIC_TIMESTAMP': '2', 'MESSAGE': 'sensitive fixture'}
GOOD = {'state': 'complete', 'exit_code': 0}


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.journal = self.root / 'journal'
        self.journal.mkdir()
        self.pstore = self.root / 'pstore'
        self.pstore.mkdir()
        self.script = self.root / 'fake-journalctl'
        self.script.write_text('#!/usr/bin/python3 -I\nimport json,os,sys\n'
                               f'rows={ROWS!r}\nrecord={RECORD!r}\n'
                               'if "--list-boots" in sys.argv: print(json.dumps(rows))\n'
                               'else: print(json.dumps(record))\n')
        self.script.chmod(0o700)

    def run_main(self, extra=(), *, output='result', boot=B1):
        argv = ['export', '--journal-directory', str(self.journal), '--boot-id', boot,
                '--output', str(self.root / output), *extra]
        with patch.object(M, 'JOURNALCTL', str(self.script)), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return M.main(argv)

    def test_explicit_boot_and_raw_provenance(self):
        self.assertEqual(self.run_main(), 0)
        out = self.root / 'result'
        report = json.loads((out / 'report.json').read_bytes())
        raw = (out / 'kernel.jsonl').read_bytes()
        self.assertEqual(report['kernel_journal']['raw'], M.digest(raw))
        self.assertEqual(json.loads(raw), RECORD)
        self.assertEqual(report['selected_boot_id'], B1)
        self.assertEqual(report['history_completeness'], 'UNKNOWN')
        self.assertEqual(report['kernel_crash_diagnosis'], 'NOT_ESTABLISHED')
        self.assertEqual(report['pstore']['state'], 'not-requested')
        self.assertEqual(report['kernel_journal']['validated_records'], 1)
        self.assertEqual(report['kernel_journal']['argv'][-2:], ['--boot=' + B1, '_TRANSPORT=kernel'])
        self.assertTrue(report['kernel_journal']['child_reaped'])
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in out.iterdir()))

    def test_list_does_not_create_export(self):
        with patch.object(M, 'JOURNALCTL', str(self.script)), contextlib.redirect_stdout(io.StringIO()) as result:
            self.assertEqual(M.main(['list', '--journal-directory', str(self.journal)]), 0)
        report = json.loads(result.getvalue())
        self.assertEqual(report['boots'], ROWS)
        self.assertEqual(report['state'], 'listed')
        self.assertFalse((self.root / 'result').exists())

    def test_relative_boot_and_extra_options_refused_before_query(self):
        for boot in ('-1', '0', 'A' * 32, B1 + '+1', '--since=now'):
            with patch.object(M, 'query', side_effect=AssertionError('must not query')), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.run_main(boot=boot)
        with patch.object(M, 'query', side_effect=AssertionError('must not query')), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                M.main(['list', '--file=/etc/shadow'])

    def test_missing_boot_refuses_without_kernel_query(self):
        self.assertEqual(self.run_main(boot='3' * 32), 1)
        report = json.loads((self.root / 'result/report.json').read_bytes())
        self.assertNotIn('kernel_journal', report)
        self.assertIn('not visible', report['reason'])

    def test_wrong_boot_or_transport_or_duplicate_field_refused(self):
        for row in ({**RECORD, '_BOOT_ID': B2}, {**RECORD, '_TRANSPORT': 'stdout'},
                    {**RECORD, '__CURSOR': ['duplicate']}, {**RECORD, '__REALTIME_TIMESTAMP': 'bad'}):
            with self.assertRaises(ValueError): M.records(json.dumps(row).encode(), B1)
        with self.assertRaises(ValueError): M.records(b'{"_BOOT_ID":"a","_BOOT_ID":"b"}', B1)

    def test_boot_listing_unsupported_incomplete_and_duplicates(self):
        for raw in (b'not json', b'{}', json.dumps(ROWS * 2).encode(),
                    json.dumps([{**ROWS[0], 'first_entry': True}]).encode(),
                    json.dumps([{**ROWS[0], 'extra': 1}]).encode()):
            with self.assertRaises(ValueError): M.boots(GOOD, raw)
        for state in ('timeout', 'output-limit', 'unavailable'):
            with self.assertRaises(ValueError): M.boots({'state': state, 'exit_code': 0}, b'[]')

    def test_no_environment_remote_pager_or_loader_inheritance(self):
        script = self.root / 'environment'
        script.write_text('#!/usr/bin/python3 -I\nimport os,json\nprint(json.dumps(dict(os.environ)))\n')
        script.chmod(0o700)
        hostile = {'SYSTEMD_JOURNAL_PATH': '/host/secret', 'SYSTEMD_HOST': 'remote',
                   'SYSTEMD_PAGER': '/host/run-me', 'LD_PRELOAD': '/host/bad.so',
                   'PYTHONPATH': '/host/modules', 'JOURNAL_STREAM': '1:2'}
        with patch.dict(os.environ, hostile):
            result, raw, err = M.query([str(script)], 65536, 1)
        self.assertEqual(result['state'], 'complete')
        seen = json.loads(raw)
        for key in hostile:
            self.assertEqual(seen.get(key), M.ENV.get(key))
        self.assertEqual(err, b'')

    def test_existing_symlink_and_unsafe_parent_refused_before_query(self):
        (self.root / 'existing').mkdir()
        (self.root / 'link').symlink_to(self.journal, target_is_directory=True)
        for name in ('existing', 'link', 'link/new', 'journal/new'):
            with patch.object(M, 'query', side_effect=AssertionError('must not query')):
                self.assertEqual(self.run_main(output=name), 1)
        unsafe = self.root / 'unsafe'; unsafe.mkdir(); unsafe.chmod(0o777)
        with patch.object(M, 'query', side_effect=AssertionError('must not query')):
            self.assertEqual(self.run_main(output='unsafe/new'), 1)

    def test_output_does_not_overwrite_or_follow_file_links(self):
        fd = M.fresh_output(str(self.root / 'out'))
        try:
            M.write_file(fd, 'raw', b'original')
            with self.assertRaises(FileExistsError): M.write_file(fd, 'raw', b'replacement')
            (self.root / 'out/link').symlink_to(self.root / 'marker')
            with self.assertRaises(FileExistsError): M.write_file(fd, 'link', b'no')
        finally: os.close(fd)
        self.assertEqual((self.root / 'out/raw').read_bytes(), b'original')
        self.assertFalse((self.root / 'marker').exists())

    def test_pstore_preserved_and_not_attributed_to_boot(self):
        raw = b'private crash\x00\xffbytes\n'
        source = self.pstore / 'dmesg-ramoops-0'; source.write_bytes(raw)
        before = M.metadata(source.stat())
        self.assertEqual(self.run_main(['--include-pstore', '--pstore-directory', str(self.pstore)]), 0)
        report = json.loads((self.root / 'result/report.json').read_bytes())
        self.assertEqual(report['pstore']['boot_attribution'], 'UNKNOWN')
        self.assertEqual(report['pstore']['files'][0]['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual((self.root / 'result/pstore-0000.bin').read_bytes(), raw)
        self.assertEqual(M.metadata(source.stat()), before)
        self.assertEqual(source.read_bytes(), raw)

    def test_pstore_symlink_hardlink_fifo_and_missing_refused(self):
        target = self.root / 'secret'; target.write_text('must not copy')
        (self.pstore / 'symlink').symlink_to(target)
        os.link(target, self.pstore / 'hardlink')
        os.mkfifo(self.pstore / 'fifo')
        self.assertEqual(self.run_main(['--include-pstore', '--pstore-directory', str(self.pstore)]), 1)
        rows = json.loads((self.root / 'result/report.json').read_bytes())['pstore']['files']
        self.assertEqual({r['state'] for r in rows}, {'refused-node'})
        self.assertFalse(list((self.root / 'result').glob('pstore-*.bin')))
        self.assertEqual(self.run_main(['--include-pstore', '--pstore-directory', str(self.root / 'missing')], output='missing-result'), 1)

    def test_pstore_exact_cap_and_oversize_prefix_are_distinguished(self):
        (self.pstore / 'record').write_bytes(b'x' * 8)
        with patch.dict(M.LIMITS, pstore_file_bytes=8):
            self.assertEqual(self.run_main(['--include-pstore', '--pstore-directory', str(self.pstore)]), 0)
        (self.pstore / 'record').write_bytes(b'x' * 9)
        with patch.dict(M.LIMITS, pstore_file_bytes=8):
            self.assertEqual(self.run_main(['--include-pstore', '--pstore-directory', str(self.pstore)], output='large'), 1)
        self.assertEqual((self.root / 'large/pstore-0000.bin').read_bytes(), b'x' * 8)
        report = json.loads((self.root / 'large/report.json').read_bytes())
        self.assertEqual(report['pstore']['files'][0]['state'], 'limit')

    def test_pstore_file_count_limit_and_changed_inode(self):
        for i in range(3): (self.pstore / str(i)).write_text(str(i))
        with patch.dict(M.LIMITS, pstore_files=2):
            self.assertEqual(self.run_main(['--include-pstore', '--pstore-directory', str(self.pstore)]), 1)
        report = json.loads((self.root / 'result/report.json').read_bytes())
        self.assertEqual(report['pstore']['state'], 'limit')
        self.assertEqual(len(report['pstore']['files']), 2)
        original = M.os.read
        changed = False
        def change(fd, count):
            nonlocal changed
            data = original(fd, count)
            if not changed:
                changed = True
                for p in self.pstore.iterdir(): p.write_text('changed')
            return data
        outfd = M.fresh_output(str(self.root / 'changed'))
        try:
            with patch.object(M.os, 'read', change): result = M.pstore(str(self.pstore), outfd)
        finally: os.close(outfd)
        self.assertTrue(any(row['state'] == 'changed' for row in result['files']))

    def test_query_output_bound_and_timeout_reap(self):
        for body, cap, expected in (("import os\nos.write(1,b'x'*100000)\n", 64, 'output-limit'),
                                    ('import time\ntime.sleep(10)\n', 64, 'timeout')):
            self.script.write_text('#!/usr/bin/python3 -I\n' + body)
            started = time.monotonic()
            result, raw, err = M.query([str(self.script)], cap, .15)
            self.assertEqual(result['state'], expected)
            self.assertLessEqual(len(raw), cap)
            self.assertTrue(result['child_reaped'])
            self.assertLess(time.monotonic() - started, 3)

    def test_query_closes_inherited_descriptors_and_kills_same_group_pipe_holder(self):
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        prior = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(prior), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        self.addCleanup(lambda: libc.prctl(36, prior.value, 0, 0, 0))
        fd = os.open(self.root / 'unrelated', os.O_CREAT | os.O_RDWR, 0o600)
        os.set_inheritable(fd, True)
        self.addCleanup(os.close, fd)
        pidfile = self.root / 'owned-child-pid'
        self.script.write_text('#!/usr/bin/python3 -I\nimport os,sys,time,json\n'
                               'print(json.dumps([os.readlink("/proc/self/fd/"+n) for n in os.listdir("/proc/self/fd") if n.isdigit() and int(n)>2 and os.path.exists("/proc/self/fd/"+n)]),flush=True)\n'
                               'pid=os.fork()\n'
                               'if pid==0: time.sleep(10)\n'
                               'else: open('+repr(str(pidfile))+',"w").write(str(pid))\n')
        result, raw, _ = M.query([str(self.script)], 65536, .15)
        self.assertEqual(json.loads(raw), [])
        self.assertEqual(result['state'], 'timeout')
        self.assertTrue(result['child_reaped'])
        pid = int(pidfile.read_text())
        got, status = os.waitpid(pid, 0)
        self.assertEqual(got, pid)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)

    def test_selector_failure_reaps_and_repeated_queries_do_not_leak_fds(self):
        self.script.write_text('#!/usr/bin/python3 -I\nimport time\ntime.sleep(10)\n')
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(M.selectors, 'DefaultSelector', side_effect=OSError(24, 'fixture fd exhaustion')):
            result, _, _ = M.query([str(self.script)], 64, 1)
        self.assertEqual(result['state'], 'error')
        self.assertTrue(result['child_reaped'])
        self.script.write_text('#!/usr/bin/python3 -I\nprint("fixture")\n')
        for _ in range(5):
            result, raw, _ = M.query([str(self.script)], 64, 1)
            self.assertTrue(result['child_reaped'])
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_stderr_output_cap_and_missing_executable(self):
        self.script.write_text('#!/usr/bin/python3 -I\nimport os\nos.write(2,b"x"*100000)\n')
        with patch.dict(M.LIMITS, stderr_bytes=64):
            result, _, err = M.query([str(self.script)], 64, 1)
        self.assertEqual(result['state'], 'output-limit')
        self.assertEqual(len(err), 64)
        result, _, _ = M.query([str(self.root / 'not-installed')], 64, 1)
        self.assertEqual(result['state'], 'unavailable')

    def test_incomplete_command_cannot_be_captured(self):
        def reply(argv, cap, seconds):
            return (GOOD, json.dumps(ROWS).encode(), b'') if '--list-boots' in argv else ({**GOOD, 'state': 'output-limit'}, json.dumps(RECORD).encode(), b'')
        with patch.object(M, 'query', reply): self.assertEqual(self.run_main(), 1)
        self.assertEqual(json.loads((self.root / 'result/report.json').read_bytes())['state'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
