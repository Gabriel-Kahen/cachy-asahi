# SPDX-License-Identifier: MIT
"""Bounded real Linux children; wrappers audit actual proc/wait/signal calls."""
import ast
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = load('owned_rss', ROOT / 'scripts/virtual/owned_process.py')
REFERENCE = load('group_rss_reference', ROOT / 'tests/fixtures/process_group_memory.py')
WAITID, WAITPID, KILLPG = os.waitid, os.waitpid, os.killpg
STAT, OPEN, SCANDIR = R._stat, os.open, os.scandir
LIMIT = 'import os,resource,signal,time\nresource.setrlimit(resource.RLIMIT_AS,(64*1024**2,64*1024**2))\n'


def terminal(pid):
    end = time.monotonic() + 2
    while time.monotonic() < end:
        row = WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        if row is not None:
            return row
        time.sleep(.002)
    raise AssertionError('fresh child did not terminate')


class Audit:
    def __init__(self, pid):
        self.pid, self.released, self.lost = pid, False, False
        self.events = []

    def numeric(self):
        if self.released or self.lost:
            raise AssertionError('numeric proc/signal access after reap/ECHILD')

    def waitid(self, *args):
        self.numeric()
        try:
            return WAITID(*args)
        except ChildProcessError:
            self.lost = True
            self.events.append('ECHILD')
            raise

    def waitpid(self, pid, flags):
        self.numeric()
        if pid != self.pid:
            raise AssertionError('foreign wait')
        row = WAITPID(pid, flags)
        if row[0] == pid:
            self.released = True
            self.events.append('raw_reap')
        return row

    def stat(self, pid, **kwargs):
        self.numeric()
        return STAT(pid, **kwargs)

    def open(self, path, *args, **kwargs):
        if str(path).startswith('/proc/'):
            self.numeric()
        return OPEN(path, *args, **kwargs)

    def scandir(self, path):
        if str(path) == '/proc':
            self.numeric()
        return SCANDIR(path)

    def killpg(self, pid, sig):
        self.numeric()
        if pid != self.pid:
            raise AssertionError('foreign group signal')
        WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        self.events.append(signal.Signals(sig).name)
        return KILLPG(pid, sig)

    def __enter__(self):
        self.stack = contextlib.ExitStack()
        for owner, name, replacement in ((R.os, 'waitid', self.waitid), (R.os, 'waitpid', self.waitpid),
                (R.os, 'open', self.open), (R.os, 'scandir', self.scandir),
                (R.os, 'killpg', self.killpg), (R, '_stat', self.stat)):
            self.stack.enter_context(patch.object(owner, name, replacement))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


class OwnedMemory(unittest.TestCase):
    def setUp(self):
        R.prepare()
        self.children = []

    def tearDown(self):
        for child in self.children:
            try:
                WAITID(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            except ChildProcessError:
                continue
            R.supervise(child, cap=.9, retirement=.5, grace=.05)

    def launch(self, source, pass_fds=()):
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', LIMIT + source],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True, pass_fds=pass_fds)
        self.children.append(child)
        return child

    def launch_ready(self, setup, hold=3):
        read, write = os.pipe()
        try:
            child = self.launch(setup + f'\nos.write({write},b"R"); os.close({write})\ntime.sleep({hold})', (write,))
            os.close(write)
            write = None
            self.assertTrue(select.select([read], [], [], 2)[0])
            self.assertEqual(os.read(read, 1), b'R')
            return child
        finally:
            os.close(read)
            if write is not None:
                os.close(write)

    def record(self, result, audit):
        target = os.environ.get('OWNED_RSS_RECEIPTS')
        if target:
            data = dict(result)
            data['output'] = data['output'].hex()
            data['audit_events'] = audit.events
            (Path(target) / (self._testMethodName + '.json')).write_text(json.dumps(data, indent=2) + '\n')

    def legacy_summary_equal(self, rss):
        expected = REFERENCE.summarize(rss['samples'])
        self.assertEqual({key: rss[key] for key in expected}, expected)
        self.assertEqual(rss['scope'], REFERENCE.SCOPE)

    def test_real_allocation_clocks_and_peak_observed(self):
        command, send = os.pipe()
        ack, acknowledge = os.pipe()
        try:
            child = self.launch(f'''os.write({acknowledge},b'R')
os.read({command},1)
data=bytearray(8*1024**2)
data[::4096]=b'x'*(len(data)//4096)
os.write({acknowledge},b'A')
os.read({command},1)
''', (command, acknowledge))
            os.close(command)
            command = None
            os.close(acknowledge)
            acknowledge = None
            self.assertTrue(select.select([ack], [], [], 2)[0])
            self.assertEqual(os.read(ack, 1), b'R')
            sample = R._rss_sample
            complete = 0

            def allocate_then_exit(*args):
                nonlocal complete
                row = sample(*args)  # Always the actual bounded kernel sample.
                if row['status'] == 'complete':
                    complete += 1
                    os.write(send, b'A' if complete == 1 else b'E')
                    if complete == 1:
                        self.assertTrue(select.select([ack], [], [], 2)[0])
                        self.assertEqual(os.read(ack, 1), b'A')
                    else:
                        terminal(child.pid)  # WNOWAIT; core still owns raw reap.
                return row

            with Audit(child.pid) as audit, patch.object(R, '_rss_sample', allocate_then_exit):
                result = R.supervise(child, cap=1.5, retirement=.4, rss_interval=.15)
        finally:
            for fd in (command, send, ack, acknowledge):
                if fd is not None:
                    os.close(fd)
        self.record(result, audit)
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['group_census'], 'RESERVED_LEADER_ONLY')
        rss = result['rss']
        self.assertEqual(rss['status'], 'complete')
        self.assertGreaterEqual(rss['leader_sampled_rss_kib'], 8192)
        values = [row['rss_sum_kib'] for row in rss['samples'] if row['status'] == 'complete']
        self.assertGreaterEqual(values[-1] - values[0], 7 * 1024)
        self.assertEqual(rss['process_group_sampled_rss_kib'], max(
            row['rss_sum_kib'] for row in rss['samples'] if row['status'] == 'complete'))
        last = 0
        for row in rss['samples']:
            self.assertLessEqual(last, row['monotonic_start_ns'])
            self.assertLessEqual(row['monotonic_start_ns'], row['monotonic_end_ns'])
            last = row['monotonic_end_ns']
            if row['status'] == 'complete':
                self.assertEqual(row['rss_sum_kib'], sum(m['rss_kib'] for m in row['members']))
        self.legacy_summary_equal(rss)
        self.assertEqual(audit.events, ['raw_reap'])

    def test_real_descendant_group_sum_is_distinct_from_leader_rss(self):
        read, write = os.pipe()
        try:
            child = self.launch(f'''data=bytearray(8*1024**2)
data[::4096]=b'x'*(len(data)//4096)
pid=os.fork()
if pid==0:
 extra=bytearray(12*1024**2)
 extra[::4096]=b'y'*(len(extra)//4096)
 os.write({write},b'R'); os.close({write})
 time.sleep(.2); os._exit(0)
os.close({write})
os.waitpid(pid,0)
''', (write,))
            os.close(write)
            write = None
            self.assertTrue(select.select([read], [], [], 2)[0])
            self.assertEqual(os.read(read, 1), b'R')
        finally:
            os.close(read)
            if write is not None:
                os.close(write)
        with Audit(child.pid) as audit:
            result = R.supervise(child, cap=1.6, retirement=.4, rss_interval=.5)
        self.record(result, audit)
        self.assertTrue(result['passed'], result)
        rss = result['rss']
        self.assertTrue(any(row['status'] == 'complete' and len(row['members']) == 2 for row in rss['samples']))
        self.assertGreater(rss['process_group_sampled_rss_kib'], rss['leader_sampled_rss_kib'] + 8192)
        pair = next(row for row in rss['samples'] if row['status'] == 'complete' and len(row['members']) == 2)
        root = next(m['rss_kib'] for m in pair['members'] if m['pid'] == child.pid)
        descendant = next(m['rss_kib'] for m in pair['members'] if m['pid'] != child.pid)
        self.assertGreaterEqual(descendant - root, 6 * 1024)
        self.legacy_summary_equal(rss)

    def test_real_timeout_last_signal_precedes_reap(self):
        child = self.launch_ready('data=bytearray(8*1024**2)\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)')
        with Audit(child.pid) as audit:
            result = R.supervise(child, cap=.8, retirement=.35, grace=.04, rss_interval=.03)
        self.record(result, audit)
        self.assertTrue(result['timeout'] and result['reaped'], result)
        self.assertEqual(result['exit'], -signal.SIGKILL)
        self.assertEqual(audit.events, ['SIGTERM', 'SIGKILL', 'raw_reap'])
        self.assertIn(result['rss']['status'], ('complete', 'partial'))
        self.assertGreaterEqual(result['rss']['process_group_observed_rss_kib'], 8192)
        if result['rss']['status'] == 'partial':
            self.assertIsNone(result['rss']['process_group_sampled_rss_kib'])
        self.assertFalse(result['passed'])

    def test_real_stolen_wait_before_observation_is_unknown(self):
        child = self.launch('os._exit(23)')
        terminal(child.pid)
        self.assertEqual(os.waitstatus_to_exitcode(WAITPID(child.pid, 0)[1]), 23)
        with Audit(child.pid) as audit:
            result = R.supervise(child, cap=.8, retirement=.35, rss_interval=.03)
        self.record(result, audit)
        self.assertEqual(audit.events, ['ECHILD'])
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertIsNone(result['exit'])
        self.assertIsNone(result['rss']['process_group_sampled_rss_kib'])
        self.assertIsNone(child.returncode)
        self.assertFalse(result['passed'])
        self.legacy_summary_equal(result['rss'])

    def test_real_stolen_wait_during_observation_stops_all_numeric_access(self):
        child = self.launch('time.sleep(.025)')
        sample = R._rss_sample
        inside = False
        stolen = False
        audited_stat = None

        def observe(*args):
            nonlocal inside
            inside = True
            try:
                return sample(*args)
            finally:
                inside = False

        def steal(pid, **kwargs):
            nonlocal stolen
            row = audited_stat(pid, **kwargs)
            if inside and not stolen:
                terminal(child.pid)
                WAITPID(child.pid, 0)  # Real theft of ONLY this fresh child.
                stolen = True
            return row

        with Audit(child.pid) as audit:
            audited_stat = R._stat
            with patch.object(R, '_rss_sample', observe), patch.object(R, '_stat', steal):
                result = R.supervise(child, cap=1, retirement=.35, rss_interval=.03)
        self.record(result, audit)
        self.assertTrue(stolen)
        self.assertEqual(audit.events, ['ECHILD'])
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertFalse(result['reaped'] or result['passed'])
        self.assertIsNone(result['rss']['process_group_sampled_rss_kib'])
        self.assertTrue(any(row['status'] == 'incomplete' for row in result['rss']['samples']))

    def test_real_membership_change_invalidates_observation_and_retires(self):
        command, send = os.pipe()
        ack, acknowledge = os.pipe()
        try:
            child = self.launch(f'''os.read({command},1)
pid=os.fork()
if pid==0:
 time.sleep(3); os._exit(0)
def stop(sig,frame):
 os.waitpid(pid,0); os._exit(0)
signal.signal(signal.SIGTERM,stop)
os.write({acknowledge},b'R')
while True: time.sleep(1)
''', (command, acknowledge))
            os.close(command)
            command = None
            os.close(acknowledge)
            acknowledge = None
            members = R._rss_members
            changed = False

            def change(*args, **kwargs):
                nonlocal changed
                rows = members(*args, **kwargs)
                if not changed:
                    changed = True
                    os.write(send, b'F')
                    self.assertTrue(select.select([ack], [], [], 2)[0])
                    self.assertEqual(os.read(ack, 1), b'R')
                return rows

            with Audit(child.pid) as audit, patch.object(R, '_rss_members', change):
                result = R.supervise(child, cap=1.3, retirement=.5, rss_interval=.03)
            self.record(result, audit)
            self.assertTrue(result['reaped'], result)
            self.assertFalse(result['passed'])
            self.assertIn('membership changed', result['rss']['error'])
            self.assertIsNone(result['rss']['process_group_sampled_rss_kib'])
            self.assertIn('SIGTERM', audit.events)
            self.legacy_summary_equal(result['rss'])
        finally:
            for fd in (command, send, ack, acknowledge):
                if fd is not None:
                    os.close(fd)

    def test_real_stolen_wait_during_retirement_scan_stops_probes(self):
        child = self.launch_ready('data=bytearray(8*1024**2)', hold=.2)
        members = R._rss_members
        retiring = False
        stolen = False
        audited_stat = None

        def scan(*args, **kwargs):
            nonlocal retiring
            retiring = sys._getframe(1).f_code.co_name == 'live'
            try:
                return members(*args, **kwargs)
            finally:
                retiring = False

        def steal(pid, **kwargs):
            nonlocal stolen
            row = audited_stat(pid, **kwargs)
            if retiring and not stolen:
                self.assertIsNotNone(WAITID(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG))
                WAITPID(child.pid, 0)
                stolen = True
            return row

        with Audit(child.pid) as audit:
            audited_stat = R._stat
            with patch.object(R, '_rss_members', scan), patch.object(R, '_stat', steal):
                result = R.supervise(child, cap=1.4, retirement=.4, rss_interval=.5)
        self.record(result, audit)
        self.assertTrue(stolen)
        self.assertEqual(audit.events, ['ECHILD'])
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertFalse(result['passed'] or result['reaped'])
        self.assertEqual(result['rss']['status'], 'partial')
        self.assertIsNone(result['rss']['process_group_sampled_rss_kib'])
        self.legacy_summary_equal(result['rss'])

    def test_retention_bound_invalidates_prior_peak(self):
        child = self.launch_ready('data=bytearray(8*1024**2)')
        with Audit(child.pid) as audit, patch.object(R, 'RSS_MAX_SAMPLES', 2):
            result = R.supervise(child, cap=1, retirement=.4, rss_interval=.02)
        self.record(result, audit)
        self.assertEqual(len(result['rss']['samples']), 2)
        self.assertEqual(result['rss']['status'], 'partial')
        self.assertIsNotNone(result['rss']['process_group_observed_rss_kib'])
        self.assertIsNone(result['rss']['process_group_sampled_rss_kib'])
        self.assertFalse(result['passed'])
        self.legacy_summary_equal(result['rss'])

    def test_default_helpers_and_result_contract_stay_compatible(self):
        before = (ROOT / 'tests/fixtures/owned_process.py').read_text()
        after = Path(R.__file__).read_text()
        for name in ('prepare', '_stat', '_members'):
            old = next(n for n in ast.parse(before).body if isinstance(n, ast.FunctionDef) and n.name == name)
            new = next(n for n in ast.parse(after).body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(ast.get_source_segment(before, old), ast.get_source_segment(after, new))
        child = self.launch('os._exit(0)')
        for value in (True, float('nan'), 0, .001, 61):
            with self.assertRaises(ValueError):
                R.supervise(child, cap=1, retirement=.4, rss_interval=value)
        with patch.object(R, '_rss_sample', side_effect=AssertionError('default must never observe')):
            result = R.supervise(child, cap=1, retirement=.4)
        self.assertTrue(result['passed'], result)
        self.assertEqual(set(result), {'exit','reaped','ownership','timeout','signals','output',
                                      'output_complete','group_census','error','seconds','passed'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
