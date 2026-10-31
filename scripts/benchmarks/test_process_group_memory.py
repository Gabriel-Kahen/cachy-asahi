# SPDX-License-Identifier: MIT
"""Structural/race controls plus actual child allocation; no ARM/M2 acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('group_memory', HERE / 'process_group_memory.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
spec = importlib.util.spec_from_file_location('benchmark_memory', HERE / 'benchmark.py')
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


def stat(pid, group=100, session=100, started=500, state='S'):
    fields = [state, '1', str(group), str(session)] + ['0'] * 15 + [str(started), '0', '0']
    return str(pid) + ' (name ) with ( parens) ' + ' '.join(fields) + '\n'


class ProcessGroupMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc(100, 12); self.proc(101, 200)
        self.proc(200, 999, group=200, session=200)
        # Unrelated kernel tasks may have group/session zero, and must not invalidate our group.
        self.proc(2, 0, group=0, session=0)

    def proc(self, pid, rss, group=100, session=100, started=500, state='S'):
        path = self.root / str(pid); path.mkdir(exist_ok=True)
        (path/'stat').write_text(stat(pid, group, session, started, state))
        (path/'status').write_text(f'Tgid:\t{pid}\nVmRSS:\t{rss} kB\n')

    def test_adds_only_original_group_once_per_thread_group(self):
        row = m.sample(100, self.root)
        self.assertEqual(row['status'], 'complete', row)
        self.assertEqual(row['rss_sum_kib'], 212)
        self.assertEqual([r['pid'] for r in row['members']], [100, 101])
        self.assertEqual(row['members'][0]['start_ticks'], 500)
        self.assertIn('double-counts', row['scope']); self.assertIn('not true peak', row['scope'])

    def test_missing_live_rss_and_malformed_units_are_not_zero(self):
        for text in ('Tgid: 101\n', 'Tgid: 101\nVmRSS: 200 MB\n', 'Tgid: 999\nVmRSS: 200 kB\n'):
            with self.subTest(text=text):
                (self.root/'101/status').write_text(text)
                row = m.sample(100, self.root)
                self.assertEqual(row['status'], 'incomplete'); self.assertIsNone(row['rss_sum_kib'])

    def test_zombie_members_are_explicitly_not_live_rss(self):
        self.proc(101, 200, state='Z')
        (self.root/'101/status').write_text('Tgid: 101\n')
        row = m.sample(100, self.root)
        self.assertEqual(row['status'], 'complete', row); self.assertEqual(row['rss_sum_kib'], 12)
        self.assertEqual(row['members'][1]['rss_kib'], 0)
        self.proc(100, 12, state='Z')
        row = m.sample(100, self.root)
        self.assertEqual(row['status'], 'exited'); self.assertIsNone(row['rss_sum_kib'])

    def test_member_fork_exit_reuse_or_group_change_invalidates_snapshot(self):
        for mutation in ('fork', 'exit', 'reuse', 'group'):
            with self.subTest(mutation=mutation):
                self.proc(101, 200)
                original = m.members
                calls = []
                def changed(*args):
                    calls.append(1)
                    if len(calls) == 2:
                        if mutation == 'fork': self.proc(102, 300)
                        elif mutation == 'exit': (self.root/'101/stat').unlink()
                        elif mutation == 'reuse': self.proc(101, 200, started=900)
                        else: self.proc(101, 200, group=200, session=200)
                    return original(*args)
                with patch.object(m, 'members', side_effect=changed): row = m.sample(100, self.root)
                self.assertEqual(row['status'], 'incomplete', row); self.assertIsNone(row['rss_sum_kib'])
                if (self.root/'102').exists():
                    (self.root/'102/stat').unlink(); (self.root/'102/status').unlink(); (self.root/'102').rmdir()

    def test_member_pid_reuse_during_rss_read_invalidates_snapshot(self):
        original = m.read
        def changed(path, deadline):
            data = original(path, deadline)
            if path == self.root/'101/status': self.proc(101, 200, started=900)
            return data
        with patch.object(m, 'read', side_effect=changed): row = m.sample(100, self.root)
        self.assertEqual(row['status'], 'incomplete'); self.assertIsNone(row['rss_sum_kib'])

    def test_no_root_identity_and_escaping_session_refused(self):
        (self.root/'100/stat').unlink()
        row = m.sample(100, self.root)
        self.assertEqual(row['status'], 'incomplete'); self.assertIsNone(row['rss_sum_kib'])
        self.proc(100, 12)
        self.proc(101, 200, session=300)
        self.assertEqual(m.sample(100, self.root)['status'], 'incomplete')

    def test_live_leader_outside_original_group_is_missing_not_exited(self):
        self.proc(100, 12, group=200, session=200)
        self.proc(101, 200, group=200, session=200)
        row = m.sample(100, self.root)
        self.assertEqual(row['status'], 'incomplete'); self.assertIsNone(row['rss_sum_kib'])
        for pid in (100,101):
            (self.root/str(pid)/'stat').unlink(); (self.root/str(pid)/'status').unlink()
        row = m.sample(100, self.root)
        self.assertEqual(row['status'], 'exited'); self.assertIsNone(row['rss_sum_kib'])

    def test_process_and_member_caps_and_deadline_return_unavailable_metric(self):
        for name, value in (('MAX_TASKS', 1), ('MAX_MEMBERS', 1), ('SAMPLE_SECONDS', -1)):
            with self.subTest(name=name), patch.object(m, name, value):
                row = m.sample(100, self.root)
                self.assertEqual(row['status'], 'incomplete'); self.assertIsNone(row['rss_sum_kib'])

    def test_partial_samples_missing_legacy_and_leader_reuse_have_no_complete_peak(self):
        row = m.sample(100, self.root)
        self.assertEqual(m.summarize([row])['process_group_sampled_rss_kib'], 212)
        for missing in (None, {'status':'incomplete'}, {'status':'unavailable'}):
            summary = m.summarize([row, missing])
            self.assertIsNone(summary['process_group_sampled_rss_kib'])
            self.assertEqual(summary['process_group_observed_rss_kib'], 212)
            self.assertEqual(summary['process_group_rss_coverage']['missing_or_incomplete_samples'], 1)
        self.proc(100, 12, started=999)
        summary = m.summarize([row, m.sample(100, self.root)])
        self.assertIsNone(summary['process_group_sampled_rss_kib'])
        self.assertFalse(summary['process_group_leader_identity_stable'])
        summary = m.summarize([row, {'status':'exited'}])
        self.assertEqual(summary['process_group_sampled_rss_kib'], 212)
        self.assertEqual(summary['process_group_rss_coverage']['exited_samples'], 1)

    def test_harness_additive_fields_preserve_root_rss_and_no_acceptance_guard(self):
        (self.root/'100/status').write_text('Tgid: 100\nState: S (sleeping)\nVmRSS: 12 kB\n')
        row = b.telemetry(100, self.root/'nosys', self.root)
        result = b.metrics([row])
        self.assertEqual(result['root_rss_kib'], 12)
        self.assertEqual(result['process_group_sampled_rss_kib'], 212)
        self.assertIn('rss_coverage', result)
        self.assertEqual(row['missing'], ['thermal','power','battery'])

    def test_new_plan_pins_harness_and_sampler_and_refuses_sampler_drift(self):
        # Reuse the original valid synthetic plan fixture. Only trusted local
        # source copies execute; mutation stays in this disposable directory.
        spec = importlib.util.spec_from_file_location('original_harness_controls', HERE/'test_benchmark.py')
        controls = importlib.util.module_from_spec(spec); spec.loader.exec_module(controls)
        fixture = controls.BenchmarkTests('test_workload_drift_and_overwrite_refused')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        fixture.config_path.write_text(json.dumps(fixture.config))
        copied = self.root/'measurement-source'; copied.mkdir()
        for name in ('benchmark.py','process_group_memory.py'):
            (copied/name).write_bytes((HERE/name).read_bytes())
        spec = importlib.util.spec_from_file_location('copied_harness', copied/'benchmark.py')
        harness = importlib.util.module_from_spec(spec); spec.loader.exec_module(harness)
        harness.freeze(fixture.config_path, fixture.state, fixture.state, fixture.plan)
        plan = harness.load_plan(fixture.plan)
        self.assertTrue({str(copied/'benchmark.py'),str(copied/'process_group_memory.py')} <= {row['path'] for row in plan['inputs']})
        sampler = copied/'process_group_memory.py'; sampler.write_bytes(sampler.read_bytes()+b'\n')
        with self.assertRaisesRegex(harness.Invalid, 'input changed'):harness.load_plan(fixture.plan)

    def test_real_child_allocation_is_measured_while_launcher_remains_small(self):
        # No shell, package/system actor, host tuning, or benchmark acceptance.
        child = "import os,sys,time;data=bytearray(24*1024*1024);print(os.getpid(),flush=True);sys.stdin.read(1)"
        parent = "import subprocess,sys;child=subprocess.Popen([sys.executable,'-I','-B','-c',sys.argv[1]],stdin=subprocess.PIPE,stdout=subprocess.PIPE);print(child.stdout.readline().decode().strip(),flush=True);sys.stdin.read(1);child.communicate(b'x',timeout=3)"
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', parent, child],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, text=True)
        try:
            import select
            ready, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(ready, 'child allocation readiness timed out')
            child_pid = int(process.stdout.readline())
            row = m.sample(process.pid)
            self.assertEqual(row['status'], 'complete', row)
            indexed = {r['pid']: r for r in row['members']}
            self.assertEqual(set(indexed), {process.pid, child_pid})
            self.assertGreater(indexed[child_pid]['rss_kib'], 24*1024)
            self.assertGreater(row['rss_sum_kib'] - indexed[process.pid]['rss_kib'], 24*1024)
            output, errors = process.communicate('x', timeout=5)
            self.assertEqual(process.returncode, 0, errors)
        finally:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed: stream.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
