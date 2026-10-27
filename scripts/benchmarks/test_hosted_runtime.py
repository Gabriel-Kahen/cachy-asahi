# SPDX-License-Identifier: MIT
"""Bounded host-Python and source controls; no ARM package binary or external action."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
import benchmark as B
import paired_zlib as P


def config():
    return dict(experiment_id='HOST-SOURCE-CONTROL', machine_id='synthetic-host', base_id='synthetic-base',
        workload_id='synthetic-no-ARM-execution', execution_context='virtual', measurement_scope=B.HOSTED_SCOPE,
        change=dict(variable='artifact', environment_key='ZLIB_MINIGZIP', baseline='/baseline', candidate='/candidate',
                    rationale='source-only contract control'), argv=[str(Path(sys.executable).resolve()), '-B', '-c', 'print(1)'],
        inputs=[str(Path(sys.executable).resolve())], order=P.ORDER, minimum_trials=6, timeout_seconds=45,
        sample_seconds=.1, controls=dict(power_source='hosted supply unknown', display_config='headless container',
        brightness='unavailable headless', cache_mode='warm declared public workload', background_load='hosted unisolated',
        warmup='one excluded ABBA block', ambient_C=None, thermal_start_C=None, battery_soc_percent=None),
        thresholds=dict(minimum_elapsed_improvement_pct=1, maximum_elapsed_range_pct=100), allowed_state_changes=[])


def conditions(c):
    return c['controls'] | dict(operator='source-only fixture', notes='no physical sensor or target measurement',
        unavailable={k: 'not exposed to this hosted control fixture' for k in B.UNAVAILABLE_CONTROLS})


def sample(pid):
    return dict(monotonic_ns=time.monotonic_ns(), thermal=[], power=[], battery=[],
                memory=dict(root_rss_kib=32, lifecycle='live'), missing=['thermal', 'power', 'battery'])


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def execute(self, code, timeout=2):
        output = self.root / ('raw-' + str(len(list(self.root.iterdir())))); output.mkdir()
        self.assertLessEqual(timeout, 2)
        with patch.object(B, 'telemetry', side_effect=sample):
            result = B.execute([sys.executable, '-B', '-c', code], self.root, os.environ.copy(), output, timeout, .1)
        return result, output

    def test_unavailable_is_exact_null_with_reasons_only_in_strict_virtual_scope(self):
        c = config(); B.validate_config(c); B.validate_conditions(c, conditions(c))
        for key in B.UNAVAILABLE_CONTROLS:
            altered = conditions(c); altered[key] = 0
            with self.subTest(key=key), self.assertRaises(B.Invalid): B.validate_conditions(c, altered)
        for reasons in ({}, {'ambient_C': 'only one'}, {k: '' for k in B.UNAVAILABLE_CONTROLS}):
            with self.subTest(reasons=reasons), self.assertRaises(B.Invalid):
                B.validate_conditions(c, conditions(c) | {'unavailable': reasons})
        for context, scope in (('physical', B.HOSTED_SCOPE), ('emulated', B.HOSTED_SCOPE), ('virtual', 'other')):
            altered = copy.deepcopy(c); altered.update(execution_context=context, measurement_scope=scope)
            with self.subTest(context=context, scope=scope), self.assertRaises(B.Invalid): B.validate_config(altered)

    def test_physical_numeric_and_reviewed_hardware_gate_requirements_remain(self):
        c = config(); c.pop('measurement_scope'); c['execution_context'] = 'physical'
        for key in B.UNAVAILABLE_CONTROLS: c['controls'][key] = [10, 40]
        with self.assertRaisesRegex(B.Invalid, 'recovery evidence'): B.validate_config(c)
        c['hardware_gate_evidence'] = '/operator-reviewed-gates.json'; B.validate_config(c)
        observed = conditions(c)
        for key in B.UNAVAILABLE_CONTROLS: observed[key] = 20
        B.validate_conditions(c, observed)
        for value in (None, True, float('nan')):
            altered = dict(observed, ambient_C=value)
            with self.subTest(value=value), self.assertRaises(B.Invalid): B.validate_conditions(c, altered)

    def test_hosted_runtime_requires_actual_native_aarch64_elf_and_no_override(self):
        c = config()
        arm = b'\x7fELF\x02\x01' + bytes(12) + b'\xb7\x00'
        with patch.dict(os.environ, {}, clear=True), patch.object(B.platform, 'system', return_value='Linux'), \
                patch.object(B.platform, 'machine', return_value='aarch64'), patch('builtins.open', return_value=io.BytesIO(arm)):
            B.hosted_runtime(c)
        for key in ('QEMU_CPU', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            with self.subTest(key=key), patch.dict(os.environ, {key: 'refused'}, clear=True), \
                    patch.object(B.platform, 'system', return_value='Linux'), patch.object(B.platform, 'machine', return_value='aarch64'), \
                    self.assertRaisesRegex(B.Invalid, 'overrides'):
                B.hosted_runtime(c)
        with patch.object(B.platform, 'machine', return_value='x86_64'), self.assertRaises(B.Invalid): B.hosted_runtime(c)
        with patch.dict(os.environ, {}, clear=True), patch.object(B.platform, 'system', return_value='Linux'), \
                patch.object(B.platform, 'machine', return_value='aarch64'), \
                patch('builtins.open', return_value=io.BytesIO(b'not a native ARM ELF')), self.assertRaises(B.Invalid):
            B.hosted_runtime(c)

    def test_paired_hosted_branch_calls_installed_plan_guard_and_keeps18_step_schedule(self):
        c = config()
        paths = []
        for variant in ('baseline', 'candidate'):
            p = self.root / variant; p.write_bytes(b'not executed'); p.chmod(0o755)
            c['change'][variant] = str(p); paths.append(str(p))
        c['variant_env'] = {v: {'ZLIB_MINIGZIP': c['change'][v]} for v in ('baseline', 'candidate')}
        c['variant_inputs'] = {v: [c['change'][v]] for v in ('baseline', 'candidate')}
        c['inputs'] += [str(Path(P.__file__).resolve())]
        frozen = set(c['inputs']) | set(paths) | {str(Path(B.__file__).resolve()), str(Path(B.process_group_memory.__file__).resolve())}
        plan = dict(config=c, inputs=[dict(path=p) for p in frozen])
        seen = []
        driver = NS(SCOPE=B.HOSTED_SCOPE, validate_plan=lambda p: seen.append(p))
        with patch.object(B, 'hosted_runtime') as runtime, patch.object(P, 'workload_driver', return_value=driver):
            P.validate(plan, False)
            with self.assertRaisesRegex(ValueError, 'control-only bypass'): P.validate(plan, True)
        self.assertEqual(seen, [plan]); runtime.assert_called_once_with(c)
        steps = P.schedule(c, 1)
        self.assertEqual(len(steps), 18)
        self.assertEqual([s['variant'] for s in steps if s['phase'] == 'measured'], P.ORDER)
        self.assertEqual(sum(s['phase'] == 'correctness' for s in steps), 2)
        self.assertEqual(sum(s['phase'] == 'warmup' for s in steps), 4)

    def test_real_host_python_natural_exit_has_held_leader_and_observed_live_absence(self):
        result, output = self.execute('import time; time.sleep(.08); print("HOST CONTROL ONLY")')
        self.assertEqual(result['returncode'], 0); self.assertIsNone(result['error'])
        self.assertLess(result['elapsed_ns'], 2_000_000_000)
        cleanup = result['sampling_status']
        self.assertTrue(cleanup['leader_held_until_group_inspection'])
        self.assertTrue(cleanup['leader_natural_exit_observed'])
        self.assertTrue(cleanup['live_group_absence_verified'])
        self.assertEqual(cleanup['group_liveness']['live_pids'], [])
        self.assertIn('zombies ignored', cleanup['group_liveness']['scope'])
        self.assertEqual((output / 'stdout.txt').read_text().strip(), 'HOST CONTROL ONLY')

    def test_real_host_python_timeout_retires_original_live_group_and_preserves_failure(self):
        result, _ = self.execute('import time; time.sleep(1)', timeout=.08)
        self.assertEqual(result['error'], 'timeout')
        self.assertFalse(result['sampling_status']['leader_natural_exit_observed'])
        self.assertTrue(result['sampling_status']['workload_reaped'])
        self.assertTrue(result['sampling_status']['live_group_absence_verified'])
        self.assertLess(result['elapsed_ns'], 2_000_000_000)

    def test_real_natural_leader_live_descendant_is_killed_before_reap(self):
        code = ('import subprocess,sys,time; child=subprocess.Popen([sys.executable,"-B","-c",'
                '"import time;time.sleep(1)"]); print(child.pid,flush=True); time.sleep(.08)')
        result, _ = self.execute(code)
        self.assertIsNone(result['error'])
        self.assertTrue(result['sampling_status']['group_liveness_before']['live_pids'])
        self.assertTrue(result['sampling_status']['leader_held_until_group_inspection'])
        self.assertTrue(result['sampling_status']['live_group_absence_verified'])

    def test_unavailable_group_observation_is_not_absence_or_valid_cleanup(self):
        with patch.object(B, 'live_group', return_value={'status': 'UNAVAILABLE', 'live_pids': None, 'reason': 'control'}):
            result, _ = self.execute('print("bounded host control")')
        self.assertIsNotNone(result['error'])
        self.assertFalse(result['sampling_status']['live_group_absence_verified'])
        self.assertEqual(result['sampling_status']['group_liveness']['status'], 'UNAVAILABLE')

    def test_sampler_error_still_invalidates_otherwise_successful_workload(self):
        output = self.root / 'telemetry-failure'; output.mkdir()
        with patch.object(B, 'telemetry', side_effect=ValueError('explicit synthetic sampler failure')):
            result = B.execute([sys.executable, '-B', '-c', 'import time;time.sleep(.05)'], self.root,
                               os.environ.copy(), output, 2, .1)
        self.assertIsNotNone(result['error'])
        self.assertIn('sampler failure', result['sampling_status']['error'])
        self.assertTrue(result['sampling_status']['live_group_absence_verified'])


if __name__ == '__main__':
    unittest.main()
