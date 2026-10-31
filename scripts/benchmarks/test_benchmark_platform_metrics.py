# SPDX-License-Identifier: MIT
"""Optional integration controls. Host work is real; frozen state/conditions are fixture-only."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('benchmark_with_metrics', HERE / 'benchmark.py')
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
a = b.platform_adapter()
m, owner = a.load_dependencies()


def files(root, metrics=True, program=None):
    root.mkdir(exist_ok=True)
    driver = root / 'workload.py'
    driver.write_text(program or "import hashlib,time\npayload=b'host component demonstration'*1024\nfor _ in range(4000): payload=hashlib.sha256(payload).digest()\ntime.sleep(.36)\nprint(payload.hex(),flush=True)\n")
    state = {'architecture': os.uname().machine, 'kernel': os.uname().release,
             'execution_context': 'unknown', 'page_size_bytes': os.sysconf('SC_PAGE_SIZE'),
             'packages': {'returncode': 1}, 'repositories': {'sync_databases': []}}
    controls = {'power_source': 'uncontrolled fixture declaration', 'display_config': 'unchanged, unmeasured',
                'brightness': 'unchanged, unmeasured', 'cache_mode': 'uncontrolled', 'background_load': 'uncontrolled',
                'warmup': 'not performed; component control', 'ambient_C': [0, 0], 'thermal_start_C': [0, 0],
                'battery_soc_percent': [0, 0]}
    config = {'experiment_id': 'host-optional-platform-component', 'machine_id': 'host-fixture-plan-no-M2',
              'base_id': 'fixture-state-package-inventory-unavailable', 'workload_id': 'hash-and-short-sleep',
              'execution_context': 'unknown', 'change': {'variable': 'fixture-only', 'baseline': 'A',
              'candidate': 'B', 'rationale': 'component control; no comparison or tuning claim'},
              'argv': [sys.executable, str(driver)], 'inputs': [sys.executable, str(driver)],
              'order': ['baseline', 'candidate', 'candidate', 'baseline'] * 3, 'minimum_trials': 5,
              'timeout_seconds': 1, 'sample_seconds': .02, 'controls': controls,
              'thresholds': {'minimum_elapsed_improvement_pct': 1, 'maximum_elapsed_range_pct': 100}}
    if metrics:
        config['platform_metrics'] = {'interval_seconds': .1}
    conditions = controls | {'ambient_C': 0, 'thermal_start_C': 0, 'battery_soc_percent': 0,
                             'operator': 'source control', 'notes': 'Zeros are fixture placeholders, never measured physical conditions.'}
    for name, value in (('state.json', state), ('config.json', config), ('conditions.json', conditions)):
        (root / name).write_text(json.dumps(value))
    b.freeze(root / 'config.json', root / 'state.json', root / 'state.json', root / 'plan.json')
    identity = b.state_identity(state)
    return config, identity


def genuine_trial(root, program=None, timeout=None):
    config, identity = files(root, program=program)
    if timeout is not None:
        config['timeout_seconds'] = timeout
        (root / 'config.json').write_text(json.dumps(config)); (root / 'plan.json').unlink()
        b.freeze(root / 'config.json', root / 'state.json', root / 'state.json', root / 'plan.json')
    # Avoid package queries. The capture independently observes real boot/kernel/arch.
    # These replacements are explicit fixture state validation, not hardware admission.
    with patch.object(b, 'live_identity', return_value=identity):
        code = b.run(root / 'plan.json', 0, root / 'state.json', root / 'conditions.json', root,
                     root / 'trial', platform_metrics=True)
    return code, b.read_json(root / 'trial/trial.json')


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.shared.cleanup)
        cls.reference = Path(cls.shared.name)
        # Sensor paths are generated fixture files; only owned workloads/clocks
        # are real. Host sysfs reads can outlive the bounded sampler drain.
        cls.sysfs = cls.reference / 'fixture-sysfs'
        device = cls.sysfs / 'class/hwmon/hwmon0'
        device.mkdir(parents=True)
        for name, value in {'name': 'integration-fixture', 'temp1_input': '42000',
                            'temp1_label': 'fixture', 'temp1_type': '1',
                            'temp1_enable': '1', 'temp1_fault': '0'}.items():
            (device / name).write_text(value + '\n')
        discover = m.discover
        cls.enterClassContext(patch.object(m, 'discover', side_effect=lambda: discover(cls.sysfs)))
        cls.enterClassContext(patch.object(a, 'load_dependencies', return_value=(m, owner)))
        code, trial = genuine_trial(cls.reference)
        if code != 0:
            raise AssertionError(trial)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'trial'
        shutil.copytree(self.reference / 'trial', self.directory)
        self.trial = b.read_json(self.directory / 'trial.json')
        self.capture = b.read_json(self.directory / 'platform-metrics/capture.json')
        self.samples = [json.loads(line) for line in (self.directory / 'platform-metrics/samples.jsonl').read_text().splitlines()]

    def verify(self):
        return a.verify_trial(self.directory, self.trial, {'interval_seconds':.1})

    def test_real_harness_run_has_bound_capture_genuine_raw_and_unknown_legacy_rss(self):
        summary = self.verify()
        self.assertTrue(self.trial['valid']); self.assertEqual(self.trial['returncode'], 0)
        self.assertTrue(self.capture['supervision']['reaped'])
        self.assertEqual(self.capture['supervision']['ownership'], 'REAPED')
        self.assertEqual(self.capture['supervision']['signals'], [])
        self.assertEqual(self.trial['optimization_acceptance'], 'NOT RUN')
        self.assertIsNone(self.trial['metrics']['root_rss_kib'])
        self.assertGreaterEqual(len(self.samples), 3)
        self.assertEqual(summary['window_monotonic_start_ns'], self.trial['monotonic_start_ns'])
        self.assertTrue((self.directory / 'stdout.txt').read_text().strip())
        self.assertIn('no with/without logging estimate', self.trial['platform_metrics']['overhead_scope'])
        for name, want in self.trial['raw_sha256'].items():
            self.assertEqual(b.digest(self.directory / name), want)
        self.assertIn('platform-metrics/samples.jsonl', self.trial['raw_sha256'])

    def test_integration_sensors_are_explicit_readable_fixture_files(self):
        inventory = b.read_json(self.directory / 'platform-metrics/inventory.json')
        self.assertEqual(inventory['sysfs_root'], str(self.sysfs))
        self.assertEqual([row['id'] for row in inventory['sensors']],
                         [str(self.sysfs / 'class/hwmon/hwmon0/temp1_input')])
        for sample in self.samples:
            self.assertEqual([row['value'] for row in sample['readings']], [42000])
        self.assertTrue(self.capture['completed'])
        self.assertTrue(self.capture['worker_stopped'])

    def test_frozen_plan_pins_adapter_collector_and_owner(self):
        plan = b.read_json(self.reference / 'plan.json')
        pinned = {Path(row['path']).name for row in plan['inputs']}
        self.assertTrue({'benchmark_platform_metrics.py', 'platform_metrics.py', 'owned_process.py'} <= pinned)

    def test_default_run_api_dispatch_and_signature_unchanged_without_opt_in(self):
        run = self.root / 'default'; _, identity = files(run, metrics=False)
        result = {'error': None, 'returncode': 0, 'elapsed_ns': 1, 'monotonic_start_ns': 1,
                  'monotonic_end_ns': 2, 'sample_count': 0, 'metrics': {}, 'sampling_status': {}}
        with patch.object(b, 'live_identity', return_value=identity), patch.object(b, 'execute', return_value=result) as legacy, patch.object(b, 'platform_adapter', side_effect=AssertionError('default imported optional adapter')):
            self.assertEqual(b.run(run/'plan.json',0,run/'state.json',run/'conditions.json',run,run/'trial'),0)
        self.assertEqual(len(legacy.call_args.args),6)
        self.assertFalse('platform_metrics' in b.read_json(run/'trial/trial.json'))

    def test_opt_in_flag_must_match_frozen_instrumentation_before_workload(self):
        for declared, selected in ((True, False), (False, True)):
            run = self.root / str(declared); files(run, metrics=declared)
            with patch.object(b, 'execute', side_effect=AssertionError('launched')), self.assertRaisesRegex(b.Invalid, 'flag must match'):
                b.run(run/'plan.json',0,run/'state.json',run/'conditions.json',run,run/'trial',platform_metrics=selected)
            self.assertFalse((run/'trial').exists())

    def test_dependency_pin_mismatch_refused(self):
        with patch.object(a,'COLLECTOR_SHA256','0'*64), self.assertRaisesRegex(a.Invalid,'source pin'):
            a.dependencies()

    def test_config_and_sample_bounds_refused(self):
        for config in ({}, {'interval_seconds':True}, {'interval_seconds':float('nan')},
                       {'interval_seconds':.01}, {'interval_seconds':11}, {'interval_seconds':1,'extra':0}):
            with self.subTest(config=config), self.assertRaises(a.Invalid): a.validate_config(config,1)
        with self.assertRaises(a.Invalid): a.validate_config({'interval_seconds':.1},3600)

    def test_capture_machine_boot_mismatch_refused(self):
        self.capture['machine_before']['boot_id'] = 'different-boot'
        (self.directory/'platform-metrics/capture.json').write_text(json.dumps(self.capture))
        with self.assertRaisesRegex(a.Invalid,'machine or boot mismatch'): self.verify()

    def test_trial_machine_boot_mismatch_refused(self):
        self.trial['platform_metrics']['binding']['machine_before']['boot_id'] = 'different-boot'
        with self.assertRaisesRegex(a.Invalid,'machine or boot mismatch'): self.verify()

    def test_trial_boundary_mismatch_refused(self):
        self.trial['monotonic_end_ns'] -= 1
        with self.assertRaisesRegex(a.Invalid,'clock mismatch'): self.verify()

    def test_trial_argv_and_cwd_mismatch_refused(self):
        for key in ('argv', 'cwd'):
            original = copy.deepcopy(self.trial)
            self.trial[key] = ['wrong-program'] if key == 'argv' else '/wrong-cwd'
            with self.subTest(key=key), self.assertRaisesRegex(a.Invalid,'workload mismatch'): self.verify()
            self.trial = original

    def test_clock_reversal_and_suspend_discontinuity_refused(self):
        for key in ('monotonic_ns','boottime_ns','realtime_ns'):
            capture, binding = copy.deepcopy(self.capture), copy.deepcopy(self.capture['workload'])
            binding['end'][key] = binding['start'][key] - 1
            capture['workload'] = binding
            with self.subTest(key=key), self.assertRaisesRegex(a.Invalid,'clock reversal'):
                a.binding_check(capture,self.samples,binding)
        capture, binding = copy.deepcopy(self.capture), copy.deepcopy(self.capture['workload'])
        binding['end']['boottime_ns'] += 1_000_000_000; capture['workload'] = binding
        with self.assertRaisesRegex(a.Invalid,'discontinuity'): a.binding_check(capture,self.samples,binding)

    def test_constant_capture_clock_origin_mismatch_refused(self):
        for clock in ('boottime_ns','realtime_ns'):
            samples=copy.deepcopy(self.samples)
            for row in samples:
                for phase in ('start','end'): row[phase][clock]+=1_000_000_000
            with self.subTest(clock=clock), self.assertRaisesRegex(a.Invalid,'clock origin mismatch'):
                a.binding_check(self.capture,samples,self.capture['workload'])

    def test_sampler_failure_preserves_incomplete_capture_after_owned_retirement(self):
        run=self.root/'sampler-error'; run.mkdir()
        original=m.snapshot
        def failed(inventory,sequence):
            if threading.current_thread() is not threading.main_thread(): raise OSError('fixture sensor read failure')
            return original(inventory,sequence)
        with patch.object(a,'load_dependencies',return_value=(m,owner)), patch.object(m,'snapshot',side_effect=failed), self.assertRaisesRegex(a.Invalid,'binding/summarization failed'):
            a.execute([sys.executable,'-c','import time; time.sleep(.2)'],run,os.environ.copy(),run,1,.02,{'interval_seconds':.1},b.metrics)
        receipt=b.read_json(run/'platform-metrics/capture.json')
        self.assertFalse(receipt['completed']); self.assertTrue(receipt['supervision']['reaped'])
        self.assertIn('fixture sensor read failure',receipt['sampling']['error'])
        self.assertTrue((run/'platform-metrics/samples.jsonl').exists())
        self.assertFalse((run/'platform-metrics/summary.json').exists())

    def test_blocked_sensor_preserves_unknown_capture_and_blocks_next_workload(self):
        run=self.root/'blocked-sensor'; run.mkdir()
        entered,release,exited=threading.Event(),threading.Event(),threading.Event()
        original=m.snapshot
        initial,workers,streams=[],[],[]
        fdopen=os.fdopen
        def opened(fd,*args,**kwargs):
            stream=fdopen(fd,*args,**kwargs)
            if os.readlink('/proc/self/fd/'+str(fd))==str(run/'platform-metrics/samples.jsonl'):
                streams.append(stream)
            return stream
        def delayed(inventory,sequence):
            if threading.current_thread() is not threading.main_thread():
                workers.append(threading.current_thread()); entered.set()
                try:
                    release.wait()
                    # The stopped worker discards this fixture row. Do not start
                    # another real sensor read while retiring a test-owned block.
                    return initial[0]
                finally:
                    exited.set()
            row=original(inventory,sequence); initial.append(row); return row
        with patch.object(a,'load_dependencies',return_value=(m,owner)), patch.object(m,'snapshot',side_effect=delayed), patch.object(os,'fdopen',side_effect=opened):
            try:
                with self.assertRaisesRegex(a.Invalid,'incomplete workload/platform worker'):
                    a.execute([sys.executable,'-c','import time; time.sleep(.2)'],run,os.environ.copy(),run,1,.02,{'interval_seconds':.1},b.metrics)
                self.assertTrue(entered.is_set()); self.assertEqual(len(workers),1)
                self.assertTrue(workers[0].is_alive())
                receipt=b.read_json(run/'platform-metrics/capture.json')
                self.assertFalse(receipt['completed']); self.assertFalse(receipt['worker_stopped'])
                self.assertTrue(receipt['supervision']['reaped']); self.assertNotIn('files',receipt)
                with patch.object(a.subprocess,'Popen',side_effect=AssertionError('blocked sampler launched workload')), self.assertRaisesRegex(a.Invalid,'sampler still blocked'):
                    a.execute([sys.executable,'-c','pass'],run,os.environ.copy(),run,1,.02,{'interval_seconds':.1},b.metrics)
            finally:
                release.set()
                if workers:
                    self.assertTrue(exited.wait(2),'fixture snapshot did not exit')
                    workers[0].join(timeout=2)
                    self.assertFalse(workers[0].is_alive(),'fixture sampler did not retire')
                # Preserve the incomplete capture, then close only the test-owned
                # stream after its sole writer has stopped.
                for stream in streams: stream.close()

    def test_unresolved_owned_wait_blocks_next_launch_without_numeric_access(self):
        run=self.root/'blocked-owned'; run.mkdir()
        with patch.object(a,'_unresolved',(object(),{'ownership':'OWNED'})), patch.object(a.subprocess,'Popen',side_effect=AssertionError('launched')), self.assertRaisesRegex(a.Invalid,'wait remains unresolved'):
            a.execute([sys.executable,'-c','pass'],run,os.environ.copy(),run,1,.02,{'interval_seconds':.1},b.metrics)

    def test_capture_that_does_not_bracket_workload_refused(self):
        samples = self.samples[1:]
        with self.assertRaisesRegex(a.Invalid,'does not bracket'):
            a.binding_check(self.capture,samples,self.capture['workload'])

    def test_capture_file_pin_and_derived_summary_tampering_refused(self):
        raw = self.directory/'platform-metrics/samples.jsonl'
        original = raw.read_bytes(); raw.write_bytes(original+b'\n')
        with self.assertRaisesRegex(a.Invalid,'pin mismatch'): self.verify()
        raw.write_bytes(original)
        (self.directory/'platform-metrics/summary.json').write_text('{}')
        with self.assertRaisesRegex(a.Invalid,'summary mismatch'): self.verify()

    def test_capture_sampling_and_adapter_source_mismatch_refused(self):
        for key,value in (('interval_seconds_requested',.2),('max_gap_seconds',100),('adapter_sha256','0'*64)):
            original = copy.deepcopy(self.capture); self.capture[key] = value
            (self.directory/'platform-metrics/capture.json').write_text(json.dumps(self.capture))
            with self.subTest(key=key), self.assertRaises(a.Invalid): self.verify()
            self.capture = original

    def test_capture_wait_result_and_worker_mismatch_refused(self):
        for mutation in ('exit','ownership','worker'):
            original = copy.deepcopy(self.capture)
            if mutation == 'exit': self.capture['supervision']['exit'] = 1
            elif mutation == 'ownership': self.capture['supervision']['ownership'] = 'UNKNOWN'
            else: self.capture['worker_stopped'] = False
            (self.directory/'platform-metrics/capture.json').write_text(json.dumps(self.capture))
            with self.subTest(mutation=mutation), self.assertRaises(a.Invalid): self.verify()
            self.capture = original

    def test_real_complete_block_reaches_existing_comparator_and_missing_rss_guardrail(self):
        run = self.root/'block'
        config,identity=files(run, program='import time\ntime.sleep(.12)\nprint("owned block component")\n')
        config['thresholds']['minimum_elapsed_improvement_pct']=0
        config['thresholds']['maximum_regression']={'root_rss_kib_pct':5}
        (run/'plan.json').unlink(); (run/'config.json').write_text(json.dumps(config))
        b.freeze(run/'config.json',run/'state.json',run/'state.json',run/'plan.json')
        directories=[]
        with patch.object(b,'live_identity',return_value=identity):
            for slot in range(len(config['order'])):
                directory=run/('trial-'+str(slot))
                self.assertEqual(b.run(run/'plan.json',slot,run/'state.json',run/'conditions.json',run,directory,platform_metrics=True),0)
                directories.append(directory)
        self.assertEqual(b.compare(run/'plan.json',directories,run/'comparison.json'),2)
        comparison=b.read_json(run/'comparison.json')
        self.assertIn(comparison['preliminary_result'],('INCOMPLETE','FAIL'))
        self.assertTrue(comparison['missing_guardrail_telemetry'])
        self.assertEqual(comparison['optimization_acceptance'],'NOT RUN')
        self.assertEqual(len(comparison['trial_bindings']),12)

    def test_incomplete_capture_and_source_mismatch_refused(self):
        for key,value in (('completed',False),('collector_sha256','0'*64)):
            original = copy.deepcopy(self.capture); self.capture[key]=value
            (self.directory/'platform-metrics/capture.json').write_text(json.dumps(self.capture))
            with self.subTest(key=key), self.assertRaises(a.Invalid): self.verify()
            self.capture = original

    def test_timeout_is_owned_reaped_and_never_valid(self):
        run=self.root/'timeout'
        code, trial=genuine_trial(run,program='import time\ntime.sleep(10)\n',timeout=.15)
        self.assertEqual(code,2); self.assertFalse(trial['valid'])
        capture=b.read_json(run/'trial/platform-metrics/capture.json')
        self.assertTrue(capture['supervision']['timeout']); self.assertTrue(capture['supervision']['reaped'])
        self.assertTrue(capture['supervision']['signals'])
        a.verify_trial(run/'trial',trial)

    def test_genuinely_stolen_wait_is_unknown_with_no_later_numeric_probe_or_signal(self):
        run=self.root/'stolen'; run.mkdir()
        real=owner.supervise
        def stolen(child,**kwargs):
            os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT)
            got,status=os.waitpid(child.pid,0)
            self.assertEqual(got,child.pid); self.assertEqual(os.waitstatus_to_exitcode(status),0)
            with patch.object(owner,'_stat',side_effect=AssertionError('numeric probe after stolen wait')), patch.object(owner.os,'killpg',side_effect=AssertionError('signal after stolen wait')), patch.object(owner.os,'waitpid',side_effect=AssertionError('waitpid after ECHILD')):
                return real(child,**kwargs)
        with patch.object(a,'load_dependencies',return_value=(m,owner)), patch.object(owner,'supervise',side_effect=stolen), self.assertRaisesRegex(a.Invalid,'binding/summarization failed'):
            a.execute([sys.executable,'-c','pass'],run,os.environ.copy(),run,1,.02,{'interval_seconds':.1},b.metrics)
        receipt=b.read_json(run/'platform-metrics/capture.json')
        self.assertFalse(receipt['completed'])
        self.assertEqual(receipt['supervision']['ownership'],'UNKNOWN')
        self.assertIsNone(receipt['supervision']['exit'])
        self.assertFalse(receipt['supervision']['reaped'])


if __name__ == '__main__': unittest.main()
