#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Temporary controller fixtures; every native/tool/source-stage call is mocked."""
import sys
sys.dont_write_bytecode = True

from contextlib import contextmanager
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fdk_job_controller_fixture', HERE / 'job.py')
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)
ROOT = HERE.parents[2]
IMAGE = 'sha256:' + '1' * 64
COMMIT = 'a' * 40


def fdk_receipt():
    return {'schema_version': 1, 'stage': 'fdk-native-development', 'status': 'PASS',
            'phase': 'complete', 'error_code': None, 'cancelled': False,
            'owned_container_absence': True, 'native_build': 'PASS', 'hardware': 'NOT RUN',
            'installation': 'NOT RUN', 'selected_for_release': False, 'binary_publication': 'NOT RUN'}


def passing_report():
    return {'status': 'PASS', 'phase': 'complete', 'cancelled': False,
            'source': {'status': 'PASS'}, 'producer': {'status': 'PASS'}, 'fdk': {'status': 'PASS'},
            'cleanup': {'status': 'PASS', 'owned_image_absence': True}}


def worker_boundary(receipt):
    boundary = job.evidence.new_boundary(worker=True)
    boundary.update(last_recipe='cachy-asahi-setup', last_command='compare', last_command_zero=True,
                    comparisons_completed=4, native_delegate_zero=True,
                    worker_status=receipt['status'], worker_cancelled=receipt['cancelled'],
                    worker_cleanup_status=receipt['cleanup']['status'],
                    worker_cleanup_absence=receipt['cleanup']['absence_verified'], worker_cleanup_cancelled=False)
    return boundary


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'repo'
        self.here = self.root / job.packet.PREFIX
        self.here.mkdir(parents=True)
        self.out = self.base / 'job'
        self.private = self.out / 'private'
        self.args = SimpleNamespace(source_root=self.root, output=self.out,
            execute_native=True, producer_timeout=1800, fdk_timeout=1800, deadline=5400,
            docker_endpoint='unix:///run/docker.sock', docker_binary='/mock/docker',
            docker_sha256='b' * 64, source_commit=COMMIT, packet=self.base / 'packet.lock.json',
            packet_sha256='c' * 64)
        self.env = {'GITHUB_SHA': COMMIT, 'RUNNER_ARCH': 'ARM64', 'RUNNER_OS': 'Linux'}
        self.original = b'{"native_build":"PASS","status":"native-builds-and-byte-comparison-pass"}\n'
        self.events, self.commands = [], []
        self.boundary_change = None
        self.mode = 'pass'
        self.broker = mock.Mock()
        self.broker.initialize.return_value = {'id': 'fixture-daemon', 'architecture': 'aarch64'}
        self.broker.cleanup.side_effect = self.cleanup
        self.runtime = SimpleNamespace(Runner=mock.Mock(), Cancelled=job.jr.Cancelled)
        self.cls = mock.Mock(return_value=self.broker)
        self.cls.runtime = self.runtime
        self.runner = SimpleNamespace(deadline=time.monotonic() + 9000, run=self.run_command)
        self.original_execute = job.execute
        self.patches = [mock.patch.object(job, 'HERE', self.here),
                mock.patch.object(job, 'ordinary'),
                mock.patch.dict(os.environ, self.env, clear=True),
                mock.patch.object(job.shutil, 'disk_usage', return_value=SimpleNamespace(free=16 * 1024**3)),
                mock.patch.object(job.jr, 'Runner', return_value=self.runner),
                mock.patch.object(job.packet, 'verify', side_effect=self.snapshot),
                mock.patch.object(job, 'broker_class', return_value=self.cls),
                mock.patch.object(job.evidence, 'validate_producer', return_value={'status': 'PASS', 'native_build': 'PASS'}),
                mock.patch.object(job.evidence, 'publish', side_effect=self.publish)]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def snapshot(self, root, manifest, pin, commit, runner, output):
        self.events.append('source')
        if self.mode == 'source-fail':
            raise ValueError('fixture incomplete packet')
        for name, data in {'scripts/ci/native_arm.py': b'fixture immutable native source',
                           'scripts/ci/recipes.lock.json': b'{}\n'}.items():
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return {'status': 'PASS', 'source_commit': commit, 'packet_sha256': pin}

    def run_command(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[0] == '/usr/bin/git':
            return subprocess.CompletedProcess(argv, 0, (COMMIT + '\n').encode())
        if argv[3].endswith('/producer.py'):
            self.events.append('producer')
            if self.mode == 'producer-cancel':
                raise job.jr.Cancelled(signal.SIGTERM)
            producer = self.private / 'producer'
            producer.mkdir()
            for name, data in {'result.json': self.original, 'bootstrap.json': b'{}\n',
                               'packages.lock': b'fixture 1-1\n', 'inputs.lock.json': b'{}\n'}.items():
                (producer / name).write_bytes(data)
            receipt = {'status': 'PASS', 'cancelled': False, 'image_id': IMAGE,
                       'cleanup': {'status': 'PASS', 'absence_verified': True, 'cancelled': False}}
            if self.mode == 'producer-receipt-fail':
                receipt['status'] = 'FAIL'
            if self.mode == 'producer-cancel-receipt':
                receipt['cancelled'] = True
            if self.mode == 'producer-absence-fail':
                receipt['cleanup']['absence_verified'] = False
            if self.mode == 'producer-cleanup-fail':
                receipt['cleanup']['status'] = 'FAIL'
            if self.mode in ('producer-diagnostic-fail', 'producer-outer-fail', 'producer-diagnostic-poison'):
                receipt['status'] = 'FAIL'
                receipt['diagnostic'] = {'phase': 'gpg-verify', 'outcome': 'runner-failed'}
                if self.mode == 'producer-outer-fail':
                    receipt['diagnostic'] = {'phase': 'bootstrap', 'outcome': 'started'}
                if self.mode == 'producer-diagnostic-poison':
                    receipt['diagnostic']['raw_private_response'] = 'PRIVATE-DIAGNOSTIC-SECRET'
            if self.mode == 'producer-probe-detail-fail':
                receipt.update(status='FAIL', diagnostic={'phase': 'base-probe', 'outcome': 'runner-failed',
                               'call': 'image-inspect', 'refusal_code': 'docker-image-drift'})
            receipt['boundary'] = worker_boundary(receipt)
            if self.boundary_change is not None:
                self.boundary_change(receipt)
            job.packet.save(self.private / 'producer-worker.json', receipt)
            if self.mode == 'producer-outer-fail':
                raise ValueError('PRIVATE-OUTER-EXCEPTION')
            return subprocess.CompletedProcess(argv, int(self.mode == 'producer-exit-fail'), b'')
        self.assertEqual(argv[3], str(self.root / (job.packet.ADAPTER + 'stage.py')))
        self.events.append('fdk')
        self.assertEqual(argv[argv.index('--accepted-result') + 1], str(self.private / 'original-result.json'))
        self.assertEqual(argv[argv.index('--accepted-result-sha256') + 1], job.packet.sha(self.original))
        self.assertEqual(argv[argv.index('--image') + 1], IMAGE)
        record = fdk_receipt()
        if self.mode == 'fdk-fail':
            record.update(status='FAIL', native_build='NOT ACCEPTED')
        elif self.mode == 'fdk-malformed':
            record = {'status': 'PASS', 'cancelled': False}
        elif self.mode == 'fdk-inconsistent':
            record['native_build'] = 'NOT ACCEPTED'
        elif self.mode == 'fdk-cancel':
            raise job.jr.Cancelled(signal.SIGTERM)
        path = self.private / 'fdk/public/status.json'
        path.parent.mkdir(parents=True)
        job.packet.save(path, record)
        return subprocess.CompletedProcess(argv, int(self.mode == 'fdk-fail'), b'')

    def cleanup(self, **kwargs):
        self.events.append('cleanup')
        return {'status': 'FAIL' if self.mode == 'cleanup-fail' else 'PASS',
                'owned_image_absence': self.mode != 'cleanup-fail', 'cancelled': False}

    def publish(self, directory, public, image, native_sha, recipes, report):
        self.events.append('publish')
        public.mkdir()
        status = job.evidence.public_status(report)['status']
        job.packet.save(public / 'producer-summary.json', {'status': status,
                'authoritative_job_status': status, 'native_build': 'PASS' if status == 'PASS' else 'NOT ACCEPTED'})
        return {'status': status, 'files': {}, 'binary_publication': 'NOT RUN'}

    def execute(self):
        state = {}
        result = self.original_execute(self.args, state)
        return result, state

    def records(self):
        return {name: job.packet.load(self.out / name) for name in
                ('private/job-result.json', 'public/status.json', 'public/fdk/status.json',
                 'public/producer/producer-summary.json')}

    def assert_failed_public(self):
        for name, record in self.records().items():
            self.assertEqual(record['status'], 'FAIL', name)
        self.assertEqual(self.records()['public/producer/producer-summary.json']['native_build'], 'NOT ACCEPTED')
        self.assertEqual(self.records()['public/fdk/status.json']['native_build'], 'NOT ACCEPTED')

    def test_success_uses_same_job_image_and_preserves_original_result(self):
        result, state = self.execute()
        self.assertEqual(result, 0)
        self.assertEqual(self.events, ['source', 'producer', 'fdk', 'cleanup', 'publish'])
        self.assertEqual((self.private / 'producer/result.json').read_bytes(), self.original)
        self.assertEqual((self.private / 'original-result.json').read_bytes(), self.original)
        self.assertEqual(state['report']['original_result_sha256'], job.packet.sha(self.original))
        self.assertTrue(all(record['status'] == 'PASS' for record in self.records().values()))
        public = self.records()['public/status.json']
        self.assertEqual(public['hardware'], public['installation'])
        self.assertEqual(public['hardware'], 'NOT RUN')
        self.assertEqual(public['binary_publication'], 'NOT RUN')
        boundary = public['producer_boundary']
        self.assertEqual(boundary['outer_gate'], 'accepted')
        self.assertEqual(boundary['outer_outcome'], 'PASS')
        self.assertEqual(boundary['comparisons_completed'], 4)
        self.assertIs(boundary['worker_return_zero'], True)
        self.assertIsNotNone(job.evidence.producer_boundary(boundary))

    def next_fixture(self, label):
        self.out = self.base / label
        self.private = self.out / 'private'
        self.args.output = self.out
        self.events.clear()
        self.commands.clear()

    def test_worker_acceptance_failures_record_exact_ordered_gate(self):
        cases = [('producer-exit-fail', 'worker-exit', 'worker-exit-nonzero'),
                 ('producer-receipt-fail', 'worker-status', 'worker-status-not-pass'),
                 ('producer-cancel-receipt', 'worker-cancelled', 'worker-cancelled'),
                 ('producer-cleanup-fail', 'worker-cleanup-status', 'worker-cleanup-not-pass'),
                 ('producer-absence-fail', 'worker-cleanup-absence', 'worker-cleanup-absence-unverified')]
        for mode, gate, reason in cases:
            with self.subTest(mode=mode):
                self.next_fixture(mode); self.mode = mode
                result, state = self.execute()
                self.assertEqual(result, 1)
                self.assertNotIn('fdk', self.events)
                self.assertNotIn('image', state)
                boundary = self.records()['public/status.json']['producer_boundary']
                self.assertEqual((boundary['outer_gate'], boundary['outer_outcome'], boundary['outer_reason']),
                                 (gate, 'FAIL', reason))
                self.assertEqual(boundary['worker_return_zero'], mode != 'producer-exit-fail')
                self.assertEqual(boundary['comparisons_completed'], 4)
                self.assert_failed_public()

    def test_before_and_after_each_gate_are_durable_before_fdk(self):
        original = job.packet.save
        seen = []
        def save(path, value):
            original(path, value)
            if path == self.private / 'job-result.json' and 'producer_boundary' in value:
                boundary = value['producer_boundary']
                seen.append((boundary['outer_gate'], boundary['outer_outcome']))
        with mock.patch.object(job.packet, 'save', side_effect=save):
            result, _ = self.execute()
        self.assertEqual(result, 0)
        gates = ['worker-exit','worker-receipt','worker-status','worker-cancelled',
                 'worker-cleanup-status','worker-cleanup-absence','producer-receipts','original-result-retention']
        expected = [(gate, outcome) for gate in gates for outcome in ['STARTED','PASS']] + [('accepted','PASS')]
        self.assertEqual(seen[:len(expected)], expected)

    def test_gate_start_pass_and_acceptance_save_failures_record_finite_fail(self):
        original = job.packet.save
        for gate, outcome in [('worker-exit','STARTED'),('worker-exit','PASS'),('accepted','PASS')]:
            with self.subTest(gate=gate,outcome=outcome):
                self.next_fixture('save-' + gate + '-' + outcome)
                failed = False
                def save(path, value):
                    nonlocal failed
                    boundary = value.get('producer_boundary', {})
                    if path == self.private / 'job-result.json' and not failed and (
                            boundary.get('outer_gate'), boundary.get('outer_outcome')) == (gate,outcome):
                        failed = True
                        raise OSError('PRIVATE-BOUNDARY-SAVE')
                    return original(path, value)
                with mock.patch.object(job.packet, 'save', side_effect=save):
                    result, state = self.execute()
                self.assertTrue(failed)
                self.assertEqual(result, 1)
                self.assertNotIn('fdk', self.events)
                self.assert_failed_public()
                public = self.records()['public/status.json']
                boundary = public['producer_boundary']
                self.assertEqual((boundary['outer_gate'], boundary['outer_outcome'], boundary['outer_reason']),
                                 ('original-result-retention' if gate == 'accepted' else gate,'FAIL','os-error'))
                self.assertEqual(boundary['worker_return_zero'], 'UNOBSERVED' if outcome == 'STARTED' else True)
                self.assertEqual(boundary['comparisons_completed'], 0 if outcome == 'STARTED' else 4)
                self.assertEqual(state['report']['producer_boundary'], boundary)
                self.assertNotIn('PRIVATE-BOUNDARY-SAVE', str(public))

    def test_failed_failure_save_keeps_original_error_and_final_typed_receipt(self):
        original = job.packet.save
        failures = 0
        def save(path, value):
            nonlocal failures
            boundary = value.get('producer_boundary', {})
            if path == self.private / 'job-result.json' and boundary.get('outer_gate') == 'worker-status':
                if boundary.get('outer_outcome') == 'PASS' and failures == 0:
                    failures += 1
                    raise OSError('PRIVATE-FIRST-SAVE-ERROR')
                if boundary.get('outer_outcome') == 'FAIL' and failures == 1:
                    failures += 1
                    raise ValueError('PRIVATE-SECOND-SAVE-ERROR')
            return original(path, value)
        with mock.patch.object(job.packet, 'save', side_effect=save):
            result, state = self.execute()
        self.assertEqual(failures, 2)
        self.assertEqual(result, 1)
        self.assertNotIn('fdk', self.events)
        self.assert_failed_public()
        public = self.records()['public/status.json']
        boundary = public['producer_boundary']
        self.assertEqual((boundary['outer_gate'], boundary['outer_outcome'], boundary['outer_reason']),
                         ('worker-status','FAIL','os-error'))
        self.assertEqual(boundary['comparisons_completed'], 4)
        self.assertIs(boundary['worker_return_zero'], True)
        self.assertEqual(state['report']['producer_boundary'], boundary)
        self.assertNotIn('PRIVATE-FIRST-SAVE-ERROR', str(public))
        self.assertNotIn('PRIVATE-SECOND-SAVE-ERROR', str(public))

    def test_failed_failure_persistence_does_not_mask_original_exception(self):
        self.private.mkdir(parents=True)
        report = {'producer_boundary':job.evidence.new_boundary(), 'cancelled':False}
        first = OSError('PRIVATE-FIRST-PERSISTENCE-ERROR')
        second = ValueError('PRIVATE-SECOND-PERSISTENCE-ERROR')
        with mock.patch.object(job.packet, 'save', side_effect=[first,second]) as save:
            with self.assertRaises(OSError) as raised:
                with job.producer_gate(self.private, report, 'worker-exit'):
                    self.fail('failed STARTED persistence must prevent launch')
        self.assertIs(raised.exception, first)
        self.assertEqual(save.call_count, 2)
        boundary = report['producer_boundary']
        self.assertEqual((boundary['outer_gate'], boundary['outer_outcome'], boundary['outer_reason']),
                         ('worker-exit','FAIL','os-error'))
        self.assertIsNotNone(job.evidence.producer_boundary(boundary))

    def test_invalid_worker_boundary_never_trusts_private_parent_fields(self):
        changes = [lambda receipt: receipt.pop('boundary'),
                   lambda receipt: receipt.update(boundary=None),
                   lambda receipt: receipt['boundary'].update(comparisons_completed=True),
                   lambda receipt: receipt['boundary'].update(raw_private_response='PRIVATE-BOUNDARY-SECRET'),
                   lambda receipt: receipt['boundary'].update(worker_return_zero=True, outer_gate='accepted',
                                                             outer_outcome='PASS', outer_reason='none')]
        for number, change in enumerate(changes):
            with self.subTest(number=number):
                self.next_fixture('invalid-boundary-' + str(number)); self.boundary_change = change
                result, state = self.execute()
                self.assertEqual(result, 1)
                self.assertNotIn('image', state)
                self.assertNotIn('fdk', self.events)
                public = self.records()['public/status.json']
                boundary = public['producer_boundary']
                self.assertEqual((boundary['outer_gate'], boundary['outer_reason']), ('worker-receipt','boundary-invalid'))
                self.assertEqual(boundary['worker_status'], 'UNOBSERVED')
                self.assertIs(boundary['worker_return_zero'], True)
                self.assertNotIn('PRIVATE-BOUNDARY-SECRET', str(public))

    def test_missing_or_oversized_worker_receipt_fails_bounded_read(self):
        original = self.run_command
        for mode in ['missing', 'oversized', 'symlink', 'hardlink']:
            with self.subTest(mode=mode):
                self.next_fixture('receipt-' + mode)
                def run(argv, **kwargs):
                    result = original(argv, **kwargs)
                    if argv[0] != '/usr/bin/git' and argv[3].endswith('/producer.py'):
                        path = self.private / 'producer-worker.json'
                        if mode == 'missing': path.unlink()
                        elif mode == 'oversized': path.write_bytes(b' ' * 65537)
                        else:
                            held = path.with_name('held-worker.json'); path.rename(held)
                            if mode == 'symlink': path.symlink_to(held)
                            else: os.link(held, path)
                    return result
                self.runner.run = run
                result, state = self.execute()
                self.assertEqual(result, 1)
                self.assertNotIn('image', state)
                boundary = self.records()['public/status.json']['producer_boundary']
                self.assertEqual((boundary['outer_gate'], boundary['outer_reason']), ('worker-receipt','boundary-invalid'))

    def test_noninteger_return_code_is_not_observed_zero_or_nonzero(self):
        original = self.run_command
        for number, code in enumerate([False, True, 0.0, '0', None]):
            with self.subTest(code=code):
                self.next_fixture('invalid-return-' + str(number))
                def run(argv, **kwargs):
                    result = original(argv, **kwargs)
                    if argv[0] != '/usr/bin/git' and argv[3].endswith('/producer.py'):
                        result.returncode = code
                    return result
                self.runner.run = run
                result, state = self.execute()
                self.assertEqual(result, 1)
                self.assertNotIn('image', state)
                boundary = self.records()['public/status.json']['producer_boundary']
                self.assertEqual(boundary['worker_return_zero'], 'UNOBSERVED')
                self.assertEqual((boundary['outer_gate'], boundary['outer_reason']), ('worker-exit','worker-return-invalid'))

    def test_runner_exception_preserves_worker_progress_without_inventing_return_code(self):
        self.mode = 'producer-outer-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        boundary = self.records()['public/status.json']['producer_boundary']
        self.assertEqual(boundary['worker_return_zero'], 'UNOBSERVED')
        self.assertEqual(boundary['worker_status'], 'FAIL')
        self.assertEqual(boundary['comparisons_completed'], 4)
        self.assertEqual((boundary['outer_gate'], boundary['outer_reason']), ('worker-exit','value-error'))

    def test_invalid_child_receipt_preserves_first_outer_failure(self):
        original = self.run_command
        for mode, missing in [('nonzero',False),('nonzero',True),('runner-error',False),('runner-error',True)]:
            with self.subTest(mode=mode,missing=missing):
                self.next_fixture(mode + '-missing-' + str(missing))
                def run(argv, **kwargs):
                    result = original(argv, **kwargs)
                    if argv[0] != '/usr/bin/git' and argv[3].endswith('/producer.py'):
                        path = self.private / 'producer-worker.json'
                        if missing: path.unlink()
                        else: job.packet.save(path, {'boundary':None})
                        if mode == 'runner-error': raise OSError('PRIVATE-RUNNER-ERROR')
                        result.returncode = 7
                    return result
                self.runner.run = run
                result, _ = self.execute()
                self.assertEqual(result, 1)
                public = self.records()['public/status.json']
                boundary = public['producer_boundary']
                self.assertEqual((boundary['outer_gate'], boundary['outer_outcome']), ('worker-exit','FAIL'))
                self.assertEqual(boundary['outer_reason'], 'os-error' if mode == 'runner-error' else 'worker-exit-nonzero')
                self.assertEqual(boundary['worker_return_zero'], 'UNOBSERVED' if mode == 'runner-error' else False)
                self.assertEqual(boundary['comparisons_completed'], 0)
                self.assertEqual(boundary['worker_status'], 'UNOBSERVED')
                self.assertNotIn('PRIVATE-RUNNER-ERROR', str(public))

    def test_known_child_observations_must_match_same_raw_receipt(self):
        changes = [lambda receipt: receipt['boundary'].update(worker_status='FAIL'),
                   lambda receipt: receipt['boundary'].update(worker_cancelled=True),
                   lambda receipt: receipt['boundary'].update(worker_cleanup_status='FAIL'),
                   lambda receipt: receipt['boundary'].update(worker_cleanup_absence=False),
                   lambda receipt: receipt['boundary'].update(worker_cleanup_cancelled=True),
                   lambda receipt: receipt.update(cancelled=0),
                   lambda receipt: receipt['cleanup'].update(absence_verified=1),
                   lambda receipt: receipt['cleanup'].pop('cancelled')]
        for number, change in enumerate(changes):
            with self.subTest(number=number):
                self.next_fixture('contradiction-' + str(number)); self.boundary_change = change
                result, state = self.execute()
                self.assertEqual(result, 1)
                self.assertNotIn('image', state)
                boundary = self.records()['public/status.json']['producer_boundary']
                self.assertEqual((boundary['outer_gate'], boundary['outer_reason']), ('worker-receipt','boundary-invalid'))
                self.assertEqual(boundary['worker_status'], 'UNOBSERVED')
                self.assertEqual(boundary['comparisons_completed'], 0)

    def test_unobserved_cleanup_cancel_is_not_derived_from_missing_raw_key(self):
        def change(receipt):
            receipt['cleanup'].pop('cancelled')
            receipt['boundary']['worker_cleanup_cancelled'] = 'UNOBSERVED'
        self.boundary_change = change
        result, _ = self.execute()
        self.assertEqual(result, 0)
        boundary = self.records()['public/status.json']['producer_boundary']
        self.assertEqual(boundary['outer_gate'], 'accepted')
        self.assertEqual(boundary['worker_cleanup_cancelled'], 'UNOBSERVED')

    def test_matching_cleanup_cancellation_observation_still_refuses_acceptance(self):
        def change(receipt):
            receipt['cleanup']['cancelled'] = True
            receipt['boundary']['worker_cleanup_cancelled'] = True
        self.boundary_change = change
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assertNotIn('fdk', self.events)
        boundary = self.records()['public/status.json']['producer_boundary']
        self.assertIs(boundary['worker_cleanup_cancelled'], True)
        self.assertEqual((boundary['outer_gate'], boundary['outer_reason']), ('original-result-retention','boundary-invalid'))

    def test_unobserved_inflight_worker_fields_allow_conservative_exception_fallback(self):
        self.mode = 'producer-outer-fail'
        def change(receipt):
            receipt['boundary'].update(worker_status='UNOBSERVED', worker_cancelled='UNOBSERVED',
                worker_cleanup_status='UNOBSERVED', worker_cleanup_absence='UNOBSERVED',
                worker_cleanup_cancelled='UNOBSERVED', comparisons_completed=2, native_delegate_zero='UNOBSERVED')
            receipt['cleanup'] = {'status':'FAIL','absence_verified':False}
        self.boundary_change = change
        result, _ = self.execute()
        self.assertEqual(result, 1)
        boundary = self.records()['public/status.json']['producer_boundary']
        self.assertEqual(boundary['outer_gate'], 'worker-exit')
        self.assertEqual(boundary['comparisons_completed'], 2)
        self.assertEqual(boundary['worker_cleanup_status'], 'UNOBSERVED')
        self.assertEqual(boundary['worker_cleanup_absence'], 'UNOBSERVED')

    def test_invalid_child_drops_stale_worker_metadata_without_replacing_parent_failure(self):
        self.private.mkdir(parents=True)
        receipt = {'status':'PASS','cancelled':False,'cleanup':{'status':'PASS','absence_verified':True,'cancelled':False}}
        boundary = job.evidence.new_boundary()
        boundary.update(worker_boundary(receipt), worker_return_zero=False, outer_gate='worker-exit',
                        outer_outcome='FAIL', outer_reason='worker-exit-nonzero')
        report = {'producer_boundary':boundary}
        parent = {key:boundary[key] for key in job.evidence.OUTER_BOUNDARY_FIELDS}
        job.packet.save(self.private / 'producer-worker.json', {'boundary':None})
        self.assertIsNone(job.retain_producer_boundary(self.private, report))
        self.assertEqual({key:boundary[key] for key in job.evidence.OUTER_BOUNDARY_FIELDS}, parent)
        self.assertEqual({key:boundary[key] for key in job.evidence.WORKER_BOUNDARY_FIELDS},
                         job.evidence.new_boundary(worker=True))

    def test_incomplete_observed_progress_refuses_late_acceptance(self):
        changes = [('comparisons_completed',3),('last_command_zero',False),('native_delegate_zero',False)]
        for number, (key, value) in enumerate(changes):
            with self.subTest(key=key):
                self.next_fixture('late-boundary-' + str(number))
                self.boundary_change = lambda receipt: receipt['boundary'].update({key:value})
                result, _ = self.execute()
                self.assertEqual(result, 1)
                self.assertNotIn('fdk', self.events)
                self.assertEqual((self.private / 'original-result.json').read_bytes(), self.original)
                boundary = self.records()['public/status.json']['producer_boundary']
                self.assertEqual((boundary['outer_gate'], boundary['outer_reason']),
                                 ('original-result-retention','boundary-invalid'))

    def test_receipt_validation_failure_is_closed_and_preserves_original_bytes(self):
        for number, (error, reason) in enumerate([(ValueError('producer-original-comparison'), 'producer-original-comparison'),
                                                (ValueError('PRIVATE-VALIDATION-SECRET'), 'value-error')]):
            with self.subTest(reason=reason):
                self.next_fixture('validation-' + str(number))
                with mock.patch.object(job.evidence, 'validate_producer', side_effect=error):
                    result, _ = self.execute()
                self.assertEqual(result, 1)
                public = self.records()['public/status.json']
                self.assertEqual((public['producer_boundary']['outer_gate'], public['producer_boundary']['outer_reason']),
                                 ('producer-receipts',reason))
                self.assertNotIn('PRIVATE-VALIDATION-SECRET', str(public))
                self.assertEqual((self.private / 'producer/result.json').read_bytes(), self.original)
                self.assertFalse((self.private / 'original-result.json').exists())

    def test_original_result_retention_failure_is_recorded_before_fdk(self):
        original = job.packet.read
        def read(path, *args, **kwargs):
            if Path(path) == self.private / 'producer/result.json':
                raise OSError('PRIVATE-READ-SECRET')
            return original(path, *args, **kwargs)
        with mock.patch.object(job.packet, 'read', side_effect=read):
            result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assertNotIn('fdk', self.events)
        public = self.records()['public/status.json']
        self.assertEqual((public['producer_boundary']['outer_gate'], public['producer_boundary']['outer_reason']),
                         ('original-result-retention','os-error'))
        self.assertNotIn('PRIVATE-READ-SECRET', str(public))

    def test_incomplete_source_prevents_broker_or_native_stage(self):
        self.mode = 'source-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.cls.assert_not_called()
        self.assertEqual(self.events, ['source', 'publish'])

    def test_producer_exit_failure_does_not_enter_fdk(self):
        self.mode = 'producer-exit-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.assertNotIn('fdk', self.events)
        self.assertLess(self.events.index('cleanup'), self.events.index('publish'))

    def test_probe_substep_predicate_survives_owned_cleanup_without_raw_data(self):
        self.mode = 'producer-probe-detail-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assertNotIn('fdk', self.events)
        public = self.records()['public/status.json']
        self.assertEqual(public['error_code'], 'producer-base-probe-image-inspect-docker-image-drift')
        self.assertTrue(public['owned_image_absence'])
        self.assertEqual(public['fdk_status'], 'NOT RUN')

    def test_failed_producer_retains_only_fixed_diagnostic_after_cleanup(self):
        self.mode = 'producer-diagnostic-fail'
        result, state = self.execute()
        self.assertEqual(result, 1)
        self.assertNotIn('fdk', self.events)
        public = self.records()['public/status.json']
        self.assertEqual(public['error_code'], 'producer-gpg-verify-runner-failed')
        self.assertEqual(state['report']['producer_diagnostic'], {'phase': 'gpg-verify', 'outcome': 'runner-failed'})
        self.assertTrue(public['owned_image_absence'])
        self.assertEqual(public['fdk_status'], 'NOT RUN')

    def test_outer_worker_failure_recovers_durable_started_state(self):
        self.mode = 'producer-outer-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assertNotIn('fdk', self.events)
        self.assertEqual(self.records()['public/status.json']['error_code'], 'producer-during-bootstrap-failed')
        self.assertNotIn('PRIVATE-OUTER-EXCEPTION', str(self.records()['public/status.json']))

    def test_unknown_diagnostic_fields_never_reach_public_error_code(self):
        self.mode = 'producer-diagnostic-poison'
        result, state = self.execute()
        self.assertEqual(result, 1)
        self.assertNotIn('producer_diagnostic', state['report'])
        public = self.records()['public/status.json']
        self.assertEqual(public['error_code'], 'fdk-native-job-failed')
        self.assertNotIn('PRIVATE-DIAGNOSTIC-SECRET', str(public))

    def test_producer_failed_receipt_does_not_enter_fdk(self):
        self.mode = 'producer-receipt-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.assertNotIn('fdk', self.events)

    def test_cancelled_producer_receipt_does_not_enter_fdk(self):
        self.mode = 'producer-cancel-receipt'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.assertNotIn('fdk', self.events)

    def test_unverified_producer_container_absence_does_not_enter_fdk(self):
        self.mode = 'producer-absence-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.assertNotIn('fdk', self.events)

    def test_active_producer_cancellation_still_cleans_before_publication(self):
        self.mode = 'producer-cancel'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.assertTrue(self.records()['public/status.json']['cancelled'])
        self.assertLess(self.events.index('cleanup'), self.events.index('publish'))

    def test_failed_fdk_keeps_original_result_and_refuses_job_acceptance(self):
        self.mode = 'fdk-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.assertEqual((self.private / 'producer/result.json').read_bytes(), self.original)
        self.assertEqual((self.private / 'original-result.json').read_bytes(), self.original)

    def test_cancelled_fdk_refuses_both_public_candidates(self):
        self.mode = 'fdk-cancel'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()
        self.assertTrue(self.records()['public/status.json']['cancelled'])

    def test_image_cleanup_failure_blocks_all_public_pass_receipts(self):
        self.mode = 'cleanup-fail'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()

    def test_malformed_fdk_pass_cannot_publish_job_or_producer_pass(self):
        self.mode = 'fdk-malformed'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()

    def test_inconsistent_fdk_pass_cannot_publish_job_or_producer_pass(self):
        self.mode = 'fdk-inconsistent'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()

    def main(self, execute, **patches):
        argv = ['job.py', '--source-root', str(self.root), '--output', str(self.out),
                '--packet', str(self.args.packet), '--source-commit', COMMIT,
                '--packet-sha256', 'c' * 64, '--docker-endpoint', self.args.docker_endpoint,
                '--docker-binary', self.args.docker_binary, '--docker-sha256', 'b' * 64]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(job, 'execute', execute), \
                mock.patch('sys.stderr', new=io.StringIO()):
            if patches:
                with mock.patch.multiple(job.jr, **patches):
                    return job.main()
            return job.main()

    def prepare_finish(self, state):
        job.output(self.out, self.root)
        path = self.private / 'fdk/public/status.json'
        path.parent.mkdir(parents=True)
        job.packet.save(path, fdk_receipt())
        state.update(out=self.out, report=passing_report(), recipes=self.root / 'recipes.json',
                     native_sha='d' * 64, image=IMAGE)

    def test_actual_sigterm_during_candidate_publication_rewrites_all_fail(self):
        original = job.packet.save
        fired = False
        def save(path, value):
            nonlocal fired
            original(path, value)
            if path == self.out / 'public/status.json' and value['status'] == 'PASS' and not fired:
                fired = True
                os.kill(os.getpid(), signal.SIGTERM)
        def execute(args, state):
            self.prepare_finish(state)
            job.finish(self.out, state['report'], state)
            return 0
        with mock.patch.object(job.packet, 'save', save):
            self.assertEqual(self.main(execute), 1)
        self.assertTrue(fired)
        self.assert_failed_public()
        self.assertTrue(self.records()['public/status.json']['cancelled'])

    def test_late_main_cancellation_retires_candidate_pass_exports(self):
        def execute(args, state):
            self.prepare_finish(state)
            job.finish(self.out, state['report'], state)
            raise job.jr.Cancelled(signal.SIGTERM)
        self.assertEqual(self.main(execute), 1)
        self.assert_failed_public()
        self.assertTrue(self.records()['public/status.json']['cancelled'])

    def test_late_malformed_boundary_refuses_all_candidate_pass_exports(self):
        state = {}
        self.prepare_finish(state)
        boundary = job.evidence.new_boundary()
        boundary.update(outer_gate='accepted', outer_outcome='PASS', comparisons_completed=True,
                        raw_private_response='PRIVATE-LATE-BOUNDARY')
        state['report']['producer_boundary'] = boundary
        job.finish(self.out, state['report'], state)
        self.assert_failed_public()
        public = self.records()['public/status.json']
        self.assertNotIn('producer_boundary', public)
        self.assertNotIn('PRIVATE-LATE-BOUNDARY', str(public))

    def test_repeated_sigterm_finalization_is_bounded_to_two_write_attempts(self):
        state = {}
        self.prepare_finish(state)
        original = job.packet.save
        writes = 0
        def save(path, value):
            nonlocal writes
            original(path, value)
            if path == self.out / 'public/status.json':
                writes += 1
                os.kill(os.getpid(), signal.SIGTERM)
        with mock.patch.object(job.packet, 'save', save), job.jr.cancellation_handlers():
            with self.assertRaises(job.jr.Cancelled):
                job.finish(self.out, state['report'], state)
        self.assertEqual(writes, 2)
        self.assert_failed_public()
        self.assertTrue(self.records()['public/status.json']['cancelled'])

    def test_failed_late_rewrite_removes_stale_public_candidates(self):
        original = job.finish
        def execute(args, state):
            self.prepare_finish(state)
            original(self.out, state['report'], state)
            raise job.jr.Cancelled(signal.SIGTERM)
        def finish(out, report, state):
            if report['status'] == 'FAIL':
                raise OSError('fixture final rewrite failure')
            original(out, report, state)
        with mock.patch.object(job, 'finish', finish):
            self.assertEqual(self.main(execute), 1)
        for name in ('public/status.json', 'public/fdk/status.json', 'private/job-result.json',
                     'public/producer/producer-summary.json'):
            self.assertFalse((self.out / name).exists(), name)

    def test_handler_restoration_cancellation_invalidates_candidate_pass(self):
        def execute(args, state):
            self.prepare_finish(state)
            job.finish(self.out, state['report'], state)
            return 0
        @contextmanager
        def late_cancel():
            yield
            raise job.jr.Cancelled(signal.SIGTERM)
        self.assertEqual(self.main(execute, cancellation_handlers=late_cancel), 1)
        self.assert_failed_public()

    def test_public_source_gate_requires_complete_source_receipt(self):
        for change in ('missing', 'failed'):
            report = passing_report()
            if change == 'missing':
                del report['source']
            else:
                report['source']['status'] = 'FAIL'
            with self.subTest(change=change):
                self.assertEqual(job.evidence.public_status(report)['status'], 'FAIL')

    def test_current_frozen_source_closure_is_116_plus_only_job_inputs(self):
        names, adapter, recipes = job.packet.closure(ROOT)
        base = names - {n for n in names if n.startswith(job.packet.PREFIX)}
        self.assertEqual(len(adapter['files']), 39)
        self.assertEqual(sum(len(rows) for rows in recipes.values()), 71)
        self.assertEqual(len(base), 116)
        self.assertIn('scripts/setup/setup.py', base)
        self.assertEqual(job.packet.sha(job.packet.read(ROOT / 'scripts/ci/inputs.lock.json')), job.packet.INPUTS_SHA)
        self.assertEqual(job.packet.sha(job.packet.read(ROOT / 'scripts/ci/recipes.lock.json')), job.packet.RECIPES_SHA)
        self.assertFalse(any(name.endswith(('.tar.gz', '.pkg.tar.xz', '.pkg.tar.zst')) for name in names))


if __name__ == '__main__':
    unittest.main()
