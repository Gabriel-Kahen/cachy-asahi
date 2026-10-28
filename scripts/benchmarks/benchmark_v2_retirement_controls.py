# SPDX-License-Identifier: MIT
"""Controlled real-child tests; run only in the receipt runner's private namespace."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('benchmark_v2_test', HERE / 'benchmark_v2.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
POPEN, WAITID, WAITPID, KILL, KILLPG = subprocess.Popen, os.waitid, os.waitpid, os.kill, os.killpg
LIMIT = 'import os,sys,time,signal,resource\nresource.setrlimit(resource.RLIMIT_AS,(64*1024**2,64*1024**2))\n'


def terminal(pid):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        if WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
            return
        time.sleep(.002)
    raise AssertionError('fresh owned child did not become terminal')


class Lifecycle:
    def __init__(self, owner, *, steal=False, ready=None, delay=0, after_reap=None):
        self.owner, self.steal, self.ready, self.delay = owner, steal, ready, delay
        self.after_reap = after_reap
        self.child = None
        self.reaped = self.lost = self.stolen = False
        self.events = []

    def numeric(self):
        if self.reaped or self.lost or self.stolen:
            raise AssertionError('numeric action after raw reap/lost custody')

    def __enter__(self):
        lifecycle = self

        class Child(POPEN):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                lifecycle.child = self
                if lifecycle.ready:
                    until = time.monotonic() + 2
                    while not lifecycle.ready.exists() and time.monotonic() < until:
                        time.sleep(.002)
                    if not lifecycle.ready.exists():
                        raise AssertionError('fresh child did not become ready')
                if lifecycle.delay:
                    time.sleep(lifecycle.delay)
                if lifecycle.steal:
                    terminal(self.pid)
                    WAITPID(self.pid, 0)
                    lifecycle.stolen = True

            def poll(self):
                raise AssertionError('Popen.poll forbidden after transfer')

            def wait(self, *args, **kwargs):
                raise AssertionError('Popen.wait forbidden after transfer')

            def communicate(self, *args, **kwargs):
                raise AssertionError('Popen.communicate forbidden after transfer')

        stat = self.owner._stat

        def peek(*args):
            if self.reaped or self.lost:
                raise AssertionError('numeric wait probe after raw reap/ECHILD')
            try:
                return WAITID(*args)
            except ChildProcessError:
                self.lost = True
                self.events.append('ECHILD')
                raise

        def reap(pid, flags):
            self.numeric()
            if self.child is None or pid != self.child.pid:
                raise AssertionError('foreign raw wait')
            row = WAITPID(pid, flags)
            if row[0] == pid:
                self.reaped = True
                self.events.append('raw_reap')
                if self.after_reap:
                    self.after_reap()
            return row

        def read_stat(pid):
            self.numeric()
            return stat(pid)

        def send(pid, sig, group):
            self.numeric()
            if self.child is None or pid != self.child.pid:
                raise AssertionError('foreign numeric signal')
            WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            self.events.append(signal.Signals(sig).name)
            return (KILLPG if group else KILL)(pid, sig)

        self.stack = contextlib.ExitStack()
        for obj, name, value in ((subprocess, 'Popen', Child), (os, 'waitid', peek),
                (os, 'waitpid', reap), (self.owner, '_stat', read_stat),
                (os, 'killpg', lambda p, s: send(p, s, True)),
                (os, 'kill', lambda p, s: send(p, s, False))):
            self.stack.enter_context(patch.object(obj, name, value))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


class OwnedLegacy(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.stat('/proc/self/ns/pid').st_ino, int(os.environ['OUTER_PID_NS']))
        self.assertFalse(any(Path('/sys').iterdir()))
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TEST_WRITABLE'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        B._retirement_adapter = None
        self.adapter = B.retirement_adapter()
        self.owner = self.adapter.owner_module()
        self.case = self.root / 'trial'
        self.case.mkdir()

    def invoke(self, source, timeout=1, interval=.5, **trace):
        with Lifecycle(self.owner, **trace) as audit, patch.object(self.adapter, 'owner_module', return_value=self.owner):
            result = B.execute([sys.executable, '-I', '-B', '-c', LIMIT + source], self.root,
                               os.environ.copy(), self.case, timeout, interval)
        self.receipt(result, audit)
        return result, audit

    def receipt(self, result, audit):
        target = Path(os.environ['CASE_RECEIPTS']) / self._testMethodName
        target.mkdir()
        for path in self.case.iterdir():
            if path.is_file():
                (target / path.name).write_bytes(path.read_bytes())
        (target / 'result.json').write_text(json.dumps(dict(result=result, events=audit.events), indent=2) + '\n')

    def test_natural_literal_raw_wait_once_and_offline_replay(self):
        result, audit = self.invoke("print('literal;$(touch SHOULD_NOT_EXIST)',flush=True)\nprint('stderr',file=sys.stderr)\ntime.sleep(.12)")
        self.assertIsNone(result['error'], result)
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(audit.events, ['raw_reap'])
        self.assertIn(b'$(touch SHOULD_NOT_EXIST)', (self.case/'stdout.txt').read_bytes())
        self.assertEqual((self.case/'stderr.txt').read_bytes(), b'')
        self.assertFalse((self.root/'SHOULD_NOT_EXIST').exists())
        samples = [json.loads(line) for line in (self.case/'telemetry.jsonl').read_bytes().splitlines()]
        trial = result | dict(valid=True)
        self.assertEqual(self.adapter.verify(self.case, trial, .5, samples, B.metrics, B.owned_rss_metrics), result['metrics'])
        forged = copy.deepcopy(trial)
        forged['returncode'] = 7
        with self.assertRaisesRegex(ValueError, 'wait truth'):
            self.adapter.verify(self.case, forged, .5, samples, B.metrics, B.owned_rss_metrics)

    def test_timeout_descendants_retired_before_reap(self):
        ready = self.root/'ready'
        source = f'''pid=os.fork()
if pid==0:
 time.sleep(3); os._exit(0)
def stop(sig,frame):
 os.waitpid(pid,0); os._exit(0)
signal.signal(signal.SIGTERM,stop)
open({str(ready)!r},'x').close()
while True: time.sleep(1)
'''
        result, audit = self.invoke(source, timeout=.3, interval=.5, ready=ready)
        self.assertEqual(result['error'], 'timeout')
        self.assertTrue(result['sampling_status']['workload_reaped'])
        self.assertIn('SIGTERM', audit.events)
        self.assertEqual(audit.events[-1], 'raw_reap')
        self.assertEqual(audit.events.count('raw_reap'), 1)

    def test_nonzero_exit_is_real_failure_not_unknown_or_zero(self):
        result, audit = self.invoke('time.sleep(.02)\nos._exit(7)')
        self.assertEqual(result['returncode'], 7)
        self.assertTrue(result['sampling_status']['workload_reaped'])
        self.assertIsNotNone(result['error'])
        self.assertEqual(audit.events, ['raw_reap'])

    def test_cancel_uses_owned_cleanup_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        timer = threading.Timer(.07, lambda: signal.raise_signal(signal.SIGTERM))
        timer.start()
        try:
            result, audit = self.invoke('time.sleep(3)')
        finally:
            timer.join(1)
        self.assertEqual(result['error'], 'interrupted by SIGTERM')
        self.assertTrue(result['sampling_status']['workload_reaped'])
        self.assertEqual(audit.events[-1], 'raw_reap')
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_stolen_wait_is_unknown_without_numeric_cleanup(self):
        result, audit = self.invoke('time.sleep(.01)\nos._exit(23)', steal=True)
        self.assertEqual(audit.events, ['ECHILD'])
        self.assertIsNone(result['returncode'])
        self.assertIsNone(audit.child.returncode)
        self.assertFalse(result['sampling_status']['workload_reaped'])
        self.assertIsNone(result['metrics']['root_rss_kib'])
        self.assertIsNotNone(self.adapter._unresolved)
        with self.assertRaisesRegex(ValueError, 'custody unresolved'):
            B.execute([sys.executable,'-c','pass'], self.root, {}, self.case, 1, .5)

    def test_sensor_failure_after_raw_reap_never_signals(self):
        released = threading.Event()

        def late_failure():
            released.wait(2)
            raise OSError('controlled late sensor/log failure')

        with patch.object(B, 'legacy_sensor_snapshot', late_failure):
            result, audit = self.invoke('time.sleep(.12)', after_reap=released.set)
        self.assertEqual(audit.events, ['raw_reap'])
        self.assertIn('late sensor/log', result['sampling_status']['error'])
        self.assertIsNotNone(result['error'])

    def test_blocked_sensor_refuses_new_workload_without_pid_access(self):
        release = threading.Event()

        def blocked():
            release.wait(2)
            return dict(monotonic_ns=time.monotonic_ns(), memory=dict(root_rss_kib=None,lifecycle='unknown'),
                        thermal=[],power=[],battery=[])

        try:
            with patch.object(B, 'legacy_sensor_snapshot', blocked):
                result, audit = self.invoke('time.sleep(.12)')
            self.assertEqual(audit.events, ['raw_reap'])
            self.assertFalse(result['sampling_status']['worker_stopped'])
            with self.assertRaisesRegex(ValueError, 'worker blocked'):
                B.execute([sys.executable,'-c','pass'], self.root, {}, self.case, 1, .5)
        finally:
            release.set()
            self.adapter._worker.join(1)

    def test_output_and_offline_raw_bounds_fail_closed(self):
        result, audit = self.invoke("os.write(1,b'x'*(600*1024))\ntime.sleep(1)")
        self.assertIsNotNone(result['error'])
        self.assertLessEqual((self.case/'stdout.txt').stat().st_size, 512*1024)
        self.assertEqual(audit.events[-1], 'raw_reap')
        path = self.case/'telemetry.jsonl'
        path.unlink()
        path.symlink_to(self.case/'stdout.txt')
        with self.assertRaises(OSError):
            self.adapter.raw_files(self.case)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, 'ordinary'):
            self.adapter.raw_files(self.case)

    def test_spawn_budget_is_not_granted_twice(self):
        supervise = self.owner.supervise
        caps = []

        def bounded(*args, **kwargs):
            caps.append(kwargs['cap'])
            return supervise(*args, **kwargs)

        with patch.object(self.owner, 'supervise', bounded):
            result, audit = self.invoke('time.sleep(3)', timeout=.04, interval=.5, delay=.06)
        self.assertEqual(result['error'], 'timeout')
        self.assertLessEqual(caps[0], .502)
        self.assertEqual(audit.events[-1], 'raw_reap')

    def test_unknown_custody_retained_before_final_log_failure(self):
        original = Path.open

        class Broken:
            def __init__(self, stream):
                self.stream = stream
            def write(self, raw):
                raise OSError('controlled final fallback log failure')
            def close(self):
                self.stream.close()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()

        def open_file(path, *args, **kwargs):
            stream = original(path, *args, **kwargs)
            return Broken(stream) if path.name == 'telemetry.jsonl' and args in (('xb',), ('ab',)) else stream

        with patch.object(B, 'legacy_sensor_snapshot', side_effect=OSError('no sensor row')):
            with Lifecycle(self.owner, steal=True) as audit, patch.object(self.adapter, 'owner_module', return_value=self.owner):
                with patch.object(Path, 'open', open_file), self.assertRaisesRegex(OSError, 'fallback log'):
                    B.execute([sys.executable,'-I','-B','-c',LIMIT+'os._exit(0)'], self.root, {}, self.case, 1, .5)
        self.assertEqual(audit.events, ['ECHILD'])
        self.assertIsNotNone(self.adapter._unresolved)
        self.assertIs(self.adapter._unresolved[0], audit.child)

    def test_decision_arithmetic_and_guardrail_semantics_are_held(self):
        before = (HERE/'benchmark.py').read_text()
        after = (HERE/'benchmark_v2.py').read_text()
        for name in ('metrics','describe','sensor_identity','owned_rss_metrics','validate_conditions'):
            x = next(n for n in ast.parse(before).body if isinstance(n,ast.FunctionDef) and n.name==name)
            y = next(n for n in ast.parse(after).body if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertEqual(ast.get_source_segment(before,x), ast.get_source_segment(after,y))
        start = '    trials.sort(key=lambda t: t["slot"])'
        end = '\n\ndef main():'
        self.assertEqual(before[before.index(start):before.index(end)],after[after.index(start):after.index(end)])
        data = dict(memory=dict(root_rss_kib=None,lifecycle='unknown'),thermal=[],power=[])
        self.assertIsNone(B.metrics([data])['root_rss_kib'])

    def test_new_plan_real_run_replay_and_historical_binding_refusal(self):
        driver = self.root/'workload.py'
        driver.write_text('import time\ntime.sleep(.12)\n')
        state = self.root/'state.json'
        record = dict(architecture='x86_64',execution_context='unknown',kernel='CONTROL_ONLY',
                      page_size_bytes=4096,packages={'returncode':1},repositories={'sync_databases':[]})
        state.write_text(json.dumps(record))
        controls = dict(power_source='AC',display_config='CONTROL_ONLY',brightness='CONTROL_ONLY',
                        cache_mode='warm',background_load='CONTROL_ONLY',warmup='CONTROL_ONLY',
                        ambient_C=[0,1],thermal_start_C=[0,1],battery_soc_percent=[0,1])
        config = dict(experiment_id='ownership-fixture',machine_id='CONTROL_ONLY',base_id='CONTROL_ONLY',
            workload_id='sleep',execution_context='unknown',
            change=dict(variable='fixture',baseline='A',candidate='B',rationale='CONTROL_ONLY'),
            argv=[sys.executable,'-I','-B',str(driver)],inputs=[sys.executable,str(driver)],
            order=['baseline','candidate','candidate','baseline']*3,minimum_trials=5,
            timeout_seconds=1,sample_seconds=.5,controls=controls,
            thresholds=dict(minimum_elapsed_improvement_pct=1,maximum_elapsed_range_pct=100))
        cfg = self.root/'config.json'
        cfg.write_text(json.dumps(config))
        plan_path = self.root/'plan.json'
        B.freeze(cfg,state,state,plan_path)
        plan = B.load_plan(plan_path)
        self.assertEqual(plan['execution_layer']['schema'],'benchmark-owned-retirement-v2')
        paths = {pin['path'] for pin in plan['inputs']}
        self.assertIn(str(Path(self.adapter.__file__).resolve()),paths)
        self.assertIn(str(self.adapter.owner_path()),paths)
        historical = self.root/'historical.json'
        old = copy.deepcopy(plan)
        old.pop('execution_layer')
        old.update(schema_version=1,record_type='frozen-experiment-plan')
        historical.write_text(json.dumps(old))
        with self.assertRaisesRegex(ValueError,'historical plans'):
            B.load_plan(historical)
        legacy_spec = importlib.util.spec_from_file_location('historical_benchmark_offline',HERE/'benchmark.py')
        legacy = importlib.util.module_from_spec(legacy_spec)
        legacy_spec.loader.exec_module(legacy)
        with self.assertRaisesRegex(ValueError,'not a supported frozen plan'):
            legacy.load_plan(plan_path)
        conditions = self.root/'conditions.json'
        conditions.write_text(json.dumps(controls|dict(ambient_C=.5,thermal_start_C=.5,battery_soc_percent=.5,
                                                       operator='CONTROL_ONLY',notes='no physical controls measured')))
        trial = self.root/'actual-trial'
        with patch.object(B,'live_identity',return_value=plan['states']['baseline']), \
                patch.object(self.adapter,'owner_module',return_value=self.owner), Lifecycle(self.owner) as audit:
            status = B.run(plan_path,0,state,conditions,self.root,trial)
        self.assertEqual(status,0)
        result = B.read_json(trial/'trial.json')
        self.assertTrue(result['valid'])
        self.assertEqual(result['optimization_acceptance'],'NOT RUN')
        self.assertEqual(audit.events,['raw_reap'])
        self.assertIn('owned-retirement.json',result['raw_sha256'])
        forged = copy.deepcopy(result)
        forged['metrics']['root_rss_kib']=0
        (trial/'trial.json').write_text(json.dumps(forged))
        with self.assertRaisesRegex(ValueError,'summary differs'):
            B.compare(plan_path,[trial],self.root/'bad-compare.json')
        (trial/'trial.json').write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError,'complete predeclared order'):
            B.compare(plan_path,[trial],self.root/'incomplete-compare.json')


if __name__ == '__main__':
    unittest.main(verbosity=2)
