# SPDX-License-Identifier: MIT
"""Small process fixtures and offline replay for the benchmark wait owner."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import benchmark_owned_retirement as adapter
from benchmark_v2_retirement_controls import B, LIMIT, Lifecycle
import test_benchmark_v2_plan as plan_controls

SHARED_SHA = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
PREVIOUS_ADAPTER_SHA = '0d682260c424abf4207b90cc92607528ae1b17656ebd3093d4e9d3919463748c'

WORKLOAD = '''from pathlib import Path
def wait_for(name):
    end = time.monotonic() + 2
    while not Path(name).exists():
        if time.monotonic() >= end:
            raise TimeoutError(name)
        time.sleep(.002)
pid = os.fork()
if pid == 0:
    wait_for('drop')
    os._exit(0)
Path('ready').touch()
os.waitpid(pid, 0)
Path('gone').touch()
wait_for('finish')
print('finished')
'''


def sensor():
    return dict(monotonic_ns=time.monotonic_ns(), thermal=[], power=[],
                memory=dict(root_rss_kib=None, lifecycle='unknown'))


class BenchmarkOwner(unittest.TestCase):
    def test_sources_bind_to_versioned_owner_and_preserve_shared_pin(self):
        shared = HERE.parent / 'virtual/owned_process.py'
        self.assertEqual(hashlib.sha256(shared.read_bytes()).hexdigest(), SHARED_SHA)
        source = adapter.owner_path()
        self.assertEqual(source, HERE / 'benchmark_owned_process_v2.py')
        self.assertEqual(B.digest(source), adapter.declaration(.2)['owner_sha256'])
        self.assertEqual(Path(adapter.owner_module().__file__), source)
        with patch.object(adapter, 'OWNER_SHA256', SHARED_SHA):
            with self.assertRaisesRegex(ValueError, 'source differs from reviewed pin'):
                adapter.owner_module()

    def test_v2_caller_pin_binds_and_replays_complete_evidence(self):
        adapter_sha = B.digest(adapter.__file__)
        interval = .5
        with (tempfile.TemporaryDirectory() as directory,
              patch.object(B, 'OWNED_RETIREMENT_ADAPTER_SHA256', adapter_sha),
              patch.object(B, '_retirement_adapter', None),
              patch.object(B, 'legacy_sensor_snapshot', sensor)):
            root = Path(directory)
            binding = B.execution_binding()
            self.assertEqual(binding['owner']['sha256'], adapter.OWNER_SHA256)
            self.assertEqual(binding['adapter']['sha256'], adapter_sha)
            result = B.execute([sys.executable, '-I', '-B', '-c', LIMIT + 'time.sleep(.1)'],
                               root, os.environ.copy(), root, 1, interval)
            self.assertIsNone(result['error'], result)
            self.assertGreater(result['metrics']['root_rss_kib'], 0)
            samples = [json.loads(line) for line in (root / 'telemetry.jsonl').read_bytes().splitlines()]
            self.assertEqual(adapter.verify(root, result | dict(valid=True), interval, samples,
                                            B.metrics, B.owned_rss_metrics), result['metrics'])

    def test_adapter_retains_churn_without_signaling_and_refuses_guardrails(self):
        owner = adapter.owner_module()
        members, sample = owner._rss_members, owner._rss_sample
        scans = 0

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def census(pid, deadline, owned):
                nonlocal scans
                scans += 1
                if scans == 4:  # End census of the second observation.
                    (root / 'drop').touch()
                    while not (root / 'gone').exists():
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(.002)
                return members(pid, deadline, owned)

            def observe(*args):
                row = sample(*args)
                if scans == 6:
                    (root / 'finish').touch()
                return row

            interval = .08
            with (Lifecycle(owner, ready=root / 'ready') as audit,
                  patch.object(owner, '_rss_members', census), patch.object(owner, '_rss_sample', observe),
                  patch.object(adapter, 'owner_module', return_value=owner)):
                result = adapter.execute([sys.executable, '-I', '-B', '-c', LIMIT + WORKLOAD],
                                         root, os.environ.copy(), root, 1, interval, sensor,
                                         B.metrics, B.owned_rss_metrics)

            self.assertEqual(audit.events, ['raw_reap'])
            self.assertEqual(result['returncode'], 0)
            self.assertIsNone(result['error'], result)
            self.assertEqual((root / 'stdout.txt').read_bytes(), b'finished\n')
            receipt = root / 'owned-retirement.json'
            raw = json.loads(receipt.read_bytes())
            self.assertEqual(raw['owner_sha256'], adapter.OWNER_SHA256)
            self.assertTrue(raw['supervision']['passed'])
            self.assertEqual(raw['supervision']['group_census'], 'RESERVED_LEADER_ONLY')
            rss = raw['supervision']['rss']
            self.assertEqual([row['status'] for row in rss['samples'][:3]],
                             ['complete', 'incomplete', 'complete'])
            self.assertEqual(rss['samples'][1]['kind'], 'membership_churn')
            self.assertGreater(result['metrics']['process_group_observed_rss_kib'], 0)
            self.assertIsNone(result['metrics']['root_rss_kib'])
            self.assertIsNone(result['metrics']['process_group_sampled_rss_kib'])

            samples = [json.loads(line) for line in (root / 'telemetry.jsonl').read_bytes().splitlines()]
            valid = result | dict(valid=True)
            self.assertEqual(adapter.verify(root, valid, interval, samples,
                                            B.metrics, B.owned_rss_metrics), result['metrics'])

            nonchurn = deepcopy(raw['supervision'])
            nonchurn['rss']['samples'][1]['kind'] = 'observation_error'
            for case, changes, trial_changes in (
                ('non-churn observation', dict(supervision=nonchurn), {}),
                ('incomplete output', dict(supervision=raw['supervision'] | dict(output_complete=False)), {}),
                ('scheduler failure', dict(sampling_status=raw['sampling_status'] | dict(error='worker failed')),
                 dict(sampling_status=raw['sampling_status'] | dict(error='worker failed'))),
            ):
                with self.subTest(case=case):
                    receipt.write_bytes(adapter.encoded(raw | changes))
                    with self.assertRaisesRegex(ValueError, 'valid trial contradicts'):
                        adapter.verify(root, valid | trial_changes, interval, samples,
                                       B.metrics, B.owned_rss_metrics)

            prior = dict(owner_sha256=SHARED_SHA, adapter_sha256=PREVIOUS_ADAPTER_SHA)
            receipt.write_bytes(adapter.encoded(raw | prior))
            historical = result | dict(owned_retirement=result['owned_retirement'] | prior, valid=False)
            with self.assertRaisesRegex(ValueError, 'trial binding differs'):
                adapter.verify(root, historical, interval, samples, B.metrics, B.owned_rss_metrics)

    def test_modeled_block_admits_churn_and_reports_required_guardrails_as_incomplete(self):
        fixture = plan_controls.PlanTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        owner = adapter.owner_module()
        conditions = fixture.root / 'conditions.json'
        fixture.write(conditions, fixture.config['controls'] | dict(ambient_C=0, thermal_start_C=0,
                      battery_soc_percent=0, operator='fixture', notes='modeled RSS and timing'))
        budgets = dict(root_rss_kib_pct=5, process_group_sampled_rss_kib_pct=5)

        def modeled_execute(_argv, _cwd, _env, output, _timeout, interval):
            slot = int(output.name)
            elapsed = 200_000_000 if fixture.config['order'][slot] == 'baseline' else 100_000_000
            start = slot * 1_000_000_000
            end = start + elapsed
            member = dict(pid=11, state='S', group=11, session=11, start_ticks=17, rss_kib=100)
            snapshots = [dict(status='complete', group_id=11, rss_sum_kib=100, members=[member],
                              scope=owner.RSS_SCOPE, monotonic_start_ns=start, monotonic_end_ns=start + 1)]
            problem = 'RSS group membership changed during sample' if slot == 0 else None
            if problem:
                snapshots.append(owner._rss_failure(11, problem) | dict(kind='membership_churn',
                                 monotonic_start_ns=start + 2, monotonic_end_ns=start + 3))
            rss = owner._rss_summary(snapshots, interval, problem)
            supervision = dict(reaped=True, ownership='REAPED', exit=0, passed=True, timeout=False,
                               signals=[], error=None, output_complete=True, group_census='RESERVED_LEADER_ONLY', rss=rss)
            sampling = dict(error=None, dropped_samples=0, worker_stopped=True, workload_reaped=True)
            times = dict(monotonic_start_ns=start, monotonic_end_ns=end)
            observations = [sensor() | dict(monotonic_ns=start)]
            declaration = adapter.declaration(interval)
            stdout = b'finished\n'
            (output / 'stdout.txt').write_bytes(stdout)
            (output / 'stderr.txt').write_bytes(b'')
            (output / 'telemetry.jsonl').write_bytes(adapter.encoded(observations[0]))
            B.write_json(output / 'owned-retirement.json', declaration | times | dict(supervision=supervision,
                         sampling_status=sampling, output_sha256=hashlib.sha256(stdout).hexdigest()))
            measured = B.metrics(observations) | B.owned_rss_metrics(rss, start, end, interval)
            return times | dict(elapsed_ns=elapsed, returncode=0, error=None, sampling_status=sampling,
                                sample_count=1, metrics=measured, owned_retirement=declaration)

        with (patch.object(plan_controls, 'runner', B), patch.object(B, '_retirement_adapter', None),
              patch.object(B, 'OWNED_RETIREMENT_ADAPTER_SHA256', B.digest(adapter.__file__)),
              patch.object(B, 'execute', modeled_execute), patch.object(os, 'geteuid', return_value=1000)):
            for label, required in (('timing', {}), ('rss', budgets)):
                with self.subTest(label=label):
                    directory = fixture.root / label
                    directory.mkdir()
                    fixture.plan_path = directory / 'plan.json'
                    fixture.config['thresholds']['maximum_regression'] = required
                    fixture.freeze()
                    identity = B.load_plan(fixture.plan_path)['states']['baseline']
                    trials = []
                    with patch.object(B, 'live_identity', return_value=identity):
                        for slot, variant in enumerate(fixture.config['order']):
                            output = directory / str(slot)
                            self.assertEqual(B.run(fixture.plan_path, slot, getattr(fixture, variant),
                                                   conditions, fixture.root, output), 0)
                            trials.append(output)
                    report = directory / 'comparison.json'
                    self.assertEqual(B.compare(fixture.plan_path, trials, report), 2 if required else 0)
                    comparison = B.read_json(report)
                    self.assertEqual(comparison['preliminary_result'],
                                     'INCOMPLETE' if required else 'MEETS_TIMING_RULE_ONLY')
                    self.assertEqual(comparison['missing_guardrail_telemetry'], [
                        'root_rss_kib_pct:root_rss_kib',
                        'process_group_sampled_rss_kib_pct:process_group_sampled_rss_kib',
                    ] if required else [])

    def test_wait_ownership_lost_after_gap_refuses_further_numeric_operations(self):
        owner = adapter.owner_module()

        def observe(pid, *_args):
            gap = owner._rss_failure(pid, 'RSS group membership changed during sample')
            return dict(gap, kind='membership_churn')

        with (patch.object(owner, '_rss_sample', observe),
              patch.object(owner, '_stat', return_value=(11, b'S', 11, 11, 11)) as stat,
              patch.object(os, 'waitid', side_effect=[None, None, None, ChildProcessError()]),
              patch.object(os, 'waitpid') as reap, patch.object(os, 'killpg') as kill):
            result = owner.supervise(11, cap=.5, retirement=.25, rss_interval=.06)

        self.assertEqual(stat.call_count, 2)
        reap.assert_not_called()
        kill.assert_not_called()
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertFalse(result['passed'])
        self.assertIn('ECHILD', result['error'])
        self.assertEqual([row['kind'] for row in result['rss']['samples']],
                         ['membership_churn', 'observation_error'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
