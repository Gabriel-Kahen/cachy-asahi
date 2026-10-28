#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disposable fake-builder process exercises, explicitly NOT OCI/ARM builds."""
import fcntl
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
from test_build_batch import Fixture, PACKET, artifact, m

FAKE = r'''
import fcntl, hashlib, json, os, pathlib, sys, time
name, output, events, fail, delay = sys.argv[1:]
p = pathlib.Path(output)
p.mkdir()
def event(kind):
    with open(events, 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(dict(package=name, event=kind, monotonic=time.monotonic(), pid=os.getpid())) + '\n')
        f.flush()
event('start')
time.sleep(float(delay))
(p / 'artifact.fake').write_text('HOST FAKE ARTIFACT: ' + name + '\n')
(p / 'fake.json').write_text(json.dumps(dict(package=name, status='FAILED' if fail == '1' else 'FAKE_PASS')))
event('finish')
sys.exit(7 if fail == '1' else 0)
'''


class FakeBuilder:
    kind = 'HOST_FAKE_PROCESSES_NOT_OCI_NOT_ARM'

    def __init__(self, path, fail=(), delay=0.15):
        self.events = path / 'events.jsonl'
        self.fail = set(fail)
        self.delay = delay
        self.cleaned = []

    def start(self, task, output, log, lock_fd):
        return subprocess.Popen([sys.executable, '-B', '-c', FAKE, task['package'], str(output), str(self.events),
            '1' if task['package'] in self.fail else '0', str(self.delay)], stdout=log,
            stderr=subprocess.STDOUT, start_new_session=True, pass_fds=(lock_fd,))

    def verify(self, task, output):
        record = m.decode(m.read(output / 'fake.json'))
        m.need(record == dict(package=task['package'], status='FAKE_PASS'), 'fake result failed identity/status')
        m.need((output / 'artifact.fake').read_bytes() == artifact(task['package']), 'fake artifact mismatch')
        return m.digest(output / 'artifact.fake')

    def cleanup(self, task, output):
        self.cleaned.append(str(output))

    def observations(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='batch-e2e-', dir=PACKET / 'evidence' if PACKET else None)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.fixture = Fixture(self.path)
        self.admit = self.fixture.admit()
        self.output = self.path / 'batch'
        self.builder = FakeBuilder(self.path)

    def run_batch(self, **kwargs):
        return m.run(self.admit, self.output, builder=self.builder, **kwargs)

    def test_dependency_order_and_bounded_concurrency(self):
        state = self.run_batch()
        self.assertEqual(state['status'], 'COMPLETE')
        times = {(p['package'], p['event']): p['monotonic'] for p in self.builder.observations()}
        self.assertGreater(times['beta', 'start'], times['alpha', 'finish'])
        self.assertGreater(times['gamma', 'start'], times['beta', 'finish'])
        self.assertLess(times['independent', 'start'], times['alpha', 'finish'])
        active, peak = 0, 0
        for event in self.builder.observations():
            active += 1 if event['event'] == 'start' else -1
            peak = max(peak, active)
        self.assertEqual((active, peak), (0, 2))
        self.assertTrue(all(p['status'] == 'SUCCESS' for p in state['packages'].values()))

    def test_failure_blocks_descendants_preserves_independent_and_resumes(self):
        self.builder.fail = {'alpha'}
        state = self.run_batch()
        self.assertEqual({n: p['status'] for n, p in state['packages'].items()},
            dict(alpha='FAILED', beta='BLOCKED', gamma='BLOCKED', independent='SUCCESS'))
        independent = state['packages']['independent']['attempts'][0]
        self.builder.fail.clear()
        state = self.run_batch(resume=True, retry=['alpha'])
        self.assertEqual(state['status'], 'COMPLETE')
        self.assertEqual(len(state['packages']['alpha']['attempts']), 2)
        self.assertEqual(state['packages']['independent']['attempts'], [independent])

    def test_failure_does_not_retry_without_explicit_named_retry(self):
        self.builder.fail = {'beta'}
        first = self.run_batch()
        second = self.run_batch(resume=True)
        self.assertEqual(second['status'], 'INCOMPLETE')
        self.assertEqual(first['packages']['beta']['attempts'], second['packages']['beta']['attempts'])

    def test_changed_success_tree_refuses_resume(self):
        state = self.run_batch()
        attempt = state['packages']['alpha']['attempts'][-1]
        (self.output / attempt['output'] / 'extra').write_text('stale\n')
        with self.assertRaisesRegex(ValueError, 'success tree changed'):
            self.run_batch(resume=True)

    def test_output_exclusive_reuse_and_nesting(self):
        self.run_batch()
        with self.assertRaises(FileExistsError):
            self.run_batch()
        with self.assertRaisesRegex(ValueError, 'nested batch'):
            m.run(self.admit, self.output / 'nested', builder=self.builder)

    def test_live_output_lock_refuses_other_runner(self):
        self.run_batch()
        with (self.output / '.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, 'already owned'):
                self.run_batch(resume=True)

    def test_recipe_and_review_joint_drift_cannot_launch(self):
        task = self.admit['tasks']['alpha']
        recipe = Path(task['recipe']) / 'PKGBUILD'
        recipe.write_text(recipe.read_text() + '# changed together\n')
        reviewed = dict(task['recipe_inputs'], PKGBUILD=m.digest(recipe))
        Path(task['reviewed_inputs']).write_bytes(m.encoded(reviewed))
        state = self.run_batch()
        self.assertEqual(state['packages']['alpha']['status'], 'FAILED')
        self.assertEqual(state['packages']['independent']['status'], 'SUCCESS')
        self.assertNotIn('alpha', [e['package'] for e in self.builder.observations()])

    def test_implementation_drift_cannot_launch(self):
        self.admit['implementation'][str(m.ROOT / 'scripts/build/build.py')] = '0' * 64
        state = self.run_batch()
        self.assertEqual(state['status'], 'INCOMPLETE')
        self.assertFalse(self.builder.events.exists())

    def test_preexisting_image_artifact_mismatch_blocks_consumer(self):
        self.admit['tasks']['beta']['prerequisite_artifacts']['alpha'] = '0' * 64
        state = self.run_batch()
        self.assertEqual(state['packages']['alpha']['status'], 'SUCCESS')
        self.assertEqual(state['packages']['beta']['status'], 'BLOCKED')
        self.assertEqual(state['packages']['gamma']['status'], 'BLOCKED')

    def test_stop_is_checkpointed_and_named_retry_resumes(self):
        state = self.run_batch(stop=lambda: self.builder.events.exists())
        self.assertEqual(state['status'], 'INTERRUPTED')
        interrupted = [n for n, p in state['packages'].items() if p['status'] == 'INTERRUPTED']
        self.assertTrue(interrupted)
        state = self.run_batch(resume=True, retry=interrupted)
        self.assertEqual(state['status'], 'COMPLETE')
        self.assertTrue(self.builder.cleaned)

    def test_attempt_bound_is_total_across_resumes(self):
        self.admit['max_attempts'] = 1
        self.builder.fail = {'alpha'}
        self.run_batch()
        with self.assertRaisesRegex(ValueError, 'attempt bound'):
            self.run_batch(resume=True, retry=['alpha'])

    def test_resume_kind_and_admission_are_bound(self):
        self.run_batch()
        self.builder.kind = 'OTHER_KIND'
        with self.assertRaisesRegex(ValueError, 'evidence kind mismatch'):
            self.run_batch(resume=True)

    def test_output_cannot_contain_admitted_inputs(self):
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            m.run(self.admit, self.path, builder=self.builder)

    def test_held_unknown_owner_can_be_omitted_without_hiding_hold(self):
        self.fixture.source['build_dependencies'][0]['owner'] = None
        self.fixture.config['tasks'] = [t for t in self.fixture.config['tasks'] if t['package'] == 'independent']
        self.admit = self.fixture.admit()
        state = self.run_batch()
        self.assertEqual(state['status'], 'INCOMPLETE')
        self.assertEqual(state['packages']['independent']['status'], 'SUCCESS')
        self.assertEqual(state['packages']['alpha']['status'], 'HELD')

    def test_external_only_hold_is_not_complete(self):
        for row in self.fixture.source['build_dependencies']:
            row['disposition'] = 'external'
        self.fixture.config['tasks'] = []
        self.admit = self.fixture.admit()
        state = self.run_batch()
        self.assertEqual(state['status'], 'INCOMPLETE')
        self.assertTrue(all(p['status'] == 'HELD' for p in state['packages'].values()))

    def test_scc_hold_does_not_stop_independent(self):
        graph = dict(alpha=['beta'], beta=['alpha'], independent=[])
        path = self.path / 'cycle'
        path.mkdir()
        fixture = Fixture(path, graph)
        fixture.config['tasks'] = [t for t in fixture.config['tasks'] if t['package'] == 'independent']
        self.admit = fixture.admit()
        state = self.run_batch()
        self.assertEqual(state['status'], 'INCOMPLETE')
        self.assertEqual(state['packages']['independent']['status'], 'SUCCESS')
        self.assertEqual(state['packages']['alpha']['status'], 'HELD')

    def test_sigkill_child_holds_lock_then_explicit_recovery(self):
        # Real parent death: no invented checkpoint or fake signal handler result.
        launch = "from test_build_batch_e2e import *; p=Path(sys.argv[1]); f=Fixture(p); m.run(f.admit(),p/'batch',builder=FakeBuilder(p,delay=0.8))"
        child_root = self.path / 'hard-kill'
        child_root.mkdir()
        process = subprocess.Popen([sys.executable, '-B', '-c', launch, str(child_root)], cwd=Path(__file__).parent)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        events = child_root / 'events.jsonl'
        deadline = time.monotonic() + 5
        while not events.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(events.exists())
        process.kill()
        process.wait(timeout=3)
        # Reuse exact admission retained before death; no regeneration of inputs.
        admit = m.decode(m.read(child_root / 'batch/admission.json'))
        builder = FakeBuilder(child_root)
        with self.assertRaisesRegex(ValueError, 'already owned'):
            m.run(admit, child_root / 'batch', resume=True, builder=builder)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            with (child_root / 'batch/.lock').open('rb') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.03)
        state = m.run(admit, child_root / 'batch', resume=True, builder=builder)
        interrupted = [n for n, p in state['packages'].items() if p['status'] == 'INTERRUPTED']
        self.assertTrue(interrupted)
        self.assertFalse(any(p['status'] == 'SUCCESS' for p in state['packages'].values()))
        final = m.run(admit, child_root / 'batch', resume=True, retry=interrupted, builder=builder)
        self.assertEqual(final['status'], 'COMPLETE')

    def test_wall_deadline_stops_active_workers(self):
        self.admit['max_wall_seconds'] = 1
        self.builder.delay = 5
        state = self.run_batch()
        self.assertEqual(state['status'], 'INTERRUPTED')
        self.assertFalse(any(p['status'] == 'SUCCESS' for p in state['packages'].values()))
        self.assertTrue(self.builder.cleaned)

    def test_serial_budget_is_observed_by_real_processes(self):
        self.admit['max_parallel'] = 1
        state = self.run_batch()
        active, peak = 0, 0
        for event in self.builder.observations():
            active += 1 if event['event'] == 'start' else -1
            peak = max(peak, active)
        self.assertEqual((state['status'], active, peak), ('COMPLETE', 0, 1))

    def test_exception_cleanup_continues_and_checkpoint_retains_failure(self):
        original_cleanup = self.builder.cleanup
        def bad_cleanup(task, output):
            original_cleanup(task, output)
            if task['package'] == 'alpha':
                raise ValueError('synthetic daemon unavailable')
        self.builder.cleanup = bad_cleanup
        self.builder.delay = 5
        def crash():
            if len(self.builder.observations()) >= 2:
                raise RuntimeError('synthetic runner exception')
            return False
        with self.assertRaisesRegex(RuntimeError, 'runner exception'):
            self.run_batch(stop=crash)
        state = m.decode(m.read(self.output / 'state.json'))
        self.assertEqual(state['status'], 'INTERRUPTED')
        self.assertEqual(state['cleanup_errors'][0]['package'], 'alpha')
        self.assertEqual(len(self.builder.cleaned), 2)
        self.assertEqual(state['packages']['alpha']['attempts'][-1]['status'], 'RUNNING')
        self.builder.cleanup = original_cleanup
        self.builder.delay = 0.1
        state = self.run_batch(resume=True, retry=['alpha', 'independent'])
        self.assertEqual(state['status'], 'COMPLETE')

    def test_no_roots_is_explicit_no_work(self):
        self.fixture.source['changed']['sources'] = []
        self.fixture.config['tasks'] = []
        self.admit = self.fixture.admit()
        state = self.run_batch()
        self.assertEqual(state['status'], 'NO_WORK')
        self.assertEqual(state['packages'], {})

    def test_grouped_outputs_are_held_without_breaking_independent_work(self):
        # Shared source build units cannot be split into separate build.py calls.
        self.fixture.source['build_dependencies'][1]['source_id'] = 'alpha'
        self.fixture.source['packages'][1]['depend'] = []
        self.fixture.source['sources'] = [r for r in self.fixture.source['sources'] if r['id'] != 'beta']
        self.fixture.source['changed']['sources'].remove('beta')
        self.fixture.config['tasks'] = [t for t in self.fixture.config['tasks'] if t['package'] == 'independent']
        self.admit = self.fixture.admit()
        state = self.run_batch()
        self.assertEqual(state['packages']['alpha']['status'], 'HELD')
        self.assertEqual(state['packages']['gamma']['status'], 'HELD')
        self.assertEqual(state['packages']['independent']['status'], 'SUCCESS')


def exercise(path):
    path.mkdir()
    fixture = Fixture(path)
    admit = fixture.admit()
    builder = FakeBuilder(path, fail=['alpha'])
    first = m.run(admit, path / 'batch', builder=builder)
    (path / 'first-failure-state.json').write_bytes(m.encoded(first))
    builder.fail.clear()
    second = m.run(admit, path / 'batch', resume=True, retry=['alpha'], builder=builder)
    (path / 'final-state.json').write_bytes(m.encoded(second))
    m.need(first['packages']['beta']['status'] == 'BLOCKED' and second['status'] == 'COMPLETE', 'exercise expectations failed')
    print(json.dumps(dict(kind=builder.kind, first=first['status'], final=second['status'], output=str(path))))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--exercise':
        exercise(Path(sys.argv[2]).resolve())
    else:
        unittest.main()
