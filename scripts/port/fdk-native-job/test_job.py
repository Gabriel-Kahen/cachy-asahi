#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Temporary controller fixtures; every native/tool/source-stage call is mocked."""
import sys
sys.dont_write_bytecode = True

from contextlib import contextmanager, nullcontext
import importlib.util
import io
import json
import ast
import hashlib
import re
import textwrap
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


def stage_validator():
    return job.validator_from_bytes({name: (ROOT / (job.packet.ADAPTER + name)).read_bytes()
                                    for name in ('evidence.py', 'worker_evidence.py')})


def sampled_inner():
    # Explicit synthetic data for the pure public validator; no compiler actor.
    event = {'kind': 'COMPILE', 'index': 0, 'natural': False, 'returncode': None}
    return {'availability': 'BOUND', 'reason': 'OBSERVED', 'raw_sha256': 'a' * 64,
        'observation': {'schema_version': 1, 'binding_sha256': 'b' * 64, 'phase': 'PACKAGE',
            'first_failure': None, 'cancelled': False, 'write_failed': False,
            'compiler_attempted': True, 'compiler_attempt_count': 1, 'compiler_natural_count': 1,
            'first_compiler_attempt': event, 'first_compiler_natural': dict(event, natural=True, returncode=0),
            'publication': 'NOT ACCEPTED'}}


def worker_rows():
    validator = stage_validator(); rows = {}
    for action in validator.ACTIONS:
        config = {'source_commit': COMMIT, 'stage_lock_sha256': 'b' * 64, 'run_id': '1',
                  'run_attempt': '2', 'action': action, 'nonce': '3' * 32}
        row = validator.initial(config, 'd' * 64); row['current_predicate'] = 'COMPLETE'
        if action != 'compare':
            row['inner'] = sampled_inner()
            row['builder'].update(status='STATIC_PASS', exit=validator.exit_record(0),
                provenance={'sha256': 'e' * 64, 'bytes': 1}, log={'sha256': 'f' * 64, 'bytes': 1})
            row['commands'].update(create=validator.exit_record(0), attach=validator.exit_record(0),
                                   container=validator.no_exit('UNOBSERVED'))
            row['cleanup'] = {'status': 'PASS', 'absence': 'PASS', 'reason': 'NONE'}
        rows[action] = {'availability': 'VERIFIED', 'exit': validator.exit_record(0), 'observation': validator.project(row)}
    return rows


def fdk_receipt():
    return {'schema_version': 2, 'stage': 'fdk-native-development', 'status': 'PASS',
            'phase': 'complete', 'error_code': None, 'cancelled': False,
            'owned_container_absence': True, 'native_build': 'PASS', 'hardware': 'NOT RUN',
            'installation': 'NOT RUN', 'selected_for_release': False, 'binary_publication': 'NOT RUN',
            'worker_diagnostics': worker_rows()}


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
        self.env = {'GITHUB_SHA': COMMIT, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '2', 'RUNNER_ARCH': 'ARM64', 'RUNNER_OS': 'Linux'}
        self.validator = stage_validator()
        self.source_bytes = {job.packet.ADAPTER + name: (ROOT / (job.packet.ADAPTER + name)).read_bytes()
                             for name in ('evidence.py', 'worker_evidence.py')}
        adapter = {'schema_version': 1, 'files': {n: {'sha256': job.packet.sha(data), 'mode': 0o644}
                                                for n, data in self.source_bytes.items()}}
        self.source_bytes[job.packet.ADAPTER + 'stage.lock.json'] = (json.dumps(adapter) + '\n').encode()
        rows = {n: {'sha256': job.packet.sha(data), 'mode': 0o644, 'bytes': len(data)} for n, data in self.source_bytes.items()}
        job.packet.save(self.args.packet, {'schema_version': 1, 'files': rows})
        self.args.packet_sha256 = job.packet.sha(job.packet.read(self.args.packet))
        self.real_adapter_pin = job.packet.ADAPTER_SHA
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
                mock.patch.object(job.packet, 'ADAPTER_SHA', job.packet.sha(self.source_bytes[job.packet.ADAPTER + 'stage.lock.json'])),
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
                           'scripts/ci/recipes.lock.json': b'{}\n', **self.source_bytes}.items():
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
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
            record.update(status='FAIL', native_build='NOT ACCEPTED', error_code='fdk-stage-failed')
        elif self.mode == 'fdk-malformed':
            record = {'status': 'PASS', 'cancelled': False}
        elif self.mode == 'fdk-inconsistent':
            record['native_build'] = 'NOT ACCEPTED'
        elif self.mode == 'fdk-cancel':
            raise job.jr.Cancelled(signal.SIGTERM)
        path = self.private / 'fdk/public/status.json'
        path.parent.mkdir(parents=True)
        job.packet.save(path, record)
        return subprocess.CompletedProcess(argv, False if self.mode == 'fdk-untyped-exit' else int(self.mode == 'fdk-fail'), b'')

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

    def test_boolean_child_exit_cannot_accept_valid_fdk_receipt(self):
        self.mode = 'fdk-untyped-exit'
        result, _ = self.execute()
        self.assertEqual(result, 1)
        self.assert_failed_public()

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
                     native_sha='d' * 64, image=IMAGE, worker_validator=self.validator, fdk_attempted=True)

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

    def test_current_frozen_source_closure_is_121_plus_only_job_inputs(self):
        with mock.patch.object(job.packet, 'ADAPTER_SHA', self.real_adapter_pin):
            names, adapter, recipes = job.packet.closure(ROOT)
        base = names - {n for n in names if n.startswith(job.packet.PREFIX)}
        self.assertEqual(len(adapter['files']), 44)
        self.assertEqual(sum(len(rows) for rows in recipes.values()), 71)
        self.assertEqual(len(base), 121)
        self.assertIn('scripts/setup/setup.py', base)
        self.assertEqual(job.packet.sha(job.packet.read(ROOT / 'scripts/ci/inputs.lock.json')), job.packet.INPUTS_SHA)
        self.assertEqual(job.packet.sha(job.packet.read(ROOT / 'scripts/ci/recipes.lock.json')), job.packet.RECIPES_SHA)
        self.assertFalse(any(name.endswith(('.tar.gz', '.pkg.tar.xz', '.pkg.tar.zst')) for name in names))


class ValidatorLoaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.manifest = self.root / 'packet.lock.json'
        self.source = {job.packet.ADAPTER + name: (ROOT / (job.packet.ADAPTER + name)).read_bytes()
                       for name in ('evidence.py', 'worker_evidence.py')}
        adapter = {'schema_version': 1, 'files': {n: {'sha256': job.packet.sha(data), 'mode': 0o644}
                                               for n, data in self.source.items()}}
        self.stage_bytes = (json.dumps(adapter) + '\n').encode()
        self.source[job.packet.ADAPTER + 'stage.lock.json'] = self.stage_bytes
        for name, data in self.source.items():
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(0o644)
        self.rows = {n: {'sha256': job.packet.sha(data), 'mode': 0o644, 'bytes': len(data)} for n, data in self.source.items()}
        job.packet.save(self.manifest, {'schema_version': 1, 'files': self.rows})
        self.pin = job.packet.sha(job.packet.read(self.manifest))
        patch = mock.patch.object(job.packet, 'ADAPTER_SHA', job.packet.sha(self.stage_bytes)); patch.start(); self.addCleanup(patch.stop)

    def load(self):
        return job.authenticated_worker_validator(self.root, self.manifest, self.pin)

    def test_explicit_dependency_ignores_wrong_global_evidence_without_global_import_mutation(self):
        original_job = job.evidence
        trap = SimpleNamespace(INPUTS_SHA='private poison')
        before_worker = sys.modules.get('worker_evidence')
        with mock.patch.dict(sys.modules, {'evidence': trap}):
            validator = self.load()
            validator.validate_workers(worker_rows(), require_complete=True)
            self.assertIs(sys.modules['evidence'], trap)
            self.assertIs(sys.modules.get('worker_evidence'), before_worker)
        self.assertIs(job.evidence, original_job)

    def test_unauthenticated_helper_and_dependency_refused_before_execute(self):
        for name in ('evidence.py', 'worker_evidence.py'):
            path = self.root / (job.packet.ADAPTER + name); original = path.read_bytes()
            path.write_bytes(b'raise AssertionError("unauthenticated executed")\n')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'FDK-validator-binding'): self.load()
            path.write_bytes(original)
        with self.assertRaises(ValueError): job.authenticated_worker_validator(self.root, self.manifest, 'f' * 64)

    def test_stage_pair_pin_modes_and_declared_bytes_are_not_trusted_blindly(self):
        path = self.root / (job.packet.ADAPTER + 'worker_evidence.py')
        path.chmod(0o600)
        with self.assertRaises(ValueError): self.load()
        path.chmod(0o644)
        with mock.patch.object(job.packet, 'ADAPTER_SHA', 'f' * 64), self.assertRaises(ValueError): self.load()
        row = self.rows[job.packet.ADAPTER + 'worker_evidence.py']; row['bytes'] += 1
        job.packet.save(self.manifest, {'schema_version': 1, 'files': self.rows})
        self.pin = job.packet.sha(job.packet.read(self.manifest))
        with self.assertRaises(ValueError): self.load()

    def test_one_valid_capture_does_not_re_read_live_helper_bytes(self):
        validator = self.load()
        path = self.root / (job.packet.ADAPTER + 'worker_evidence.py')
        path.write_bytes(b'raise AssertionError("late mutable helper")\n')
        validator.validate_workers(worker_rows(), require_complete=True)
        with self.assertRaises(ValueError): self.load()

    def test_record_success_requires_current_complete_vector_no_legacy_fallback(self):
        validator = self.load(); good = fdk_receipt()
        self.assertEqual(job.validate_fdk_record(good, validator), good)
        for change in (lambda r: r.update(schema_version=1), lambda r: r.pop('worker_diagnostics'),
            lambda r: r['worker_diagnostics']['build-2'].update(availability='UNVERIFIED', observation=None),
            lambda r: r['worker_diagnostics']['compare']['exit'].update(kind='EXIT_NONZERO', code=1),
            lambda r: r['worker_diagnostics']['build-1']['observation'].update(raw='SECRET')):
            row = json.loads(json.dumps(good)); change(row)
            with self.subTest(change=change), self.assertRaises(ValueError): job.validate_fdk_record(row, validator)

    def test_capture_retains_same_valid_snapshot_and_does_not_late_promote_missing(self):
        path = self.root / 'fdk/public/status.json'; path.parent.mkdir(parents=True)
        state = {'worker_validator': self.load(), 'fdk_attempted': True}
        self.assertIsNone(job.capture_fdk(self.root, state))
        job.packet.save(path, fdk_receipt())
        self.assertIsNone(job.capture_fdk(self.root, state))
        state = {'worker_validator': self.load(), 'fdk_attempted': True}
        good = job.capture_fdk(self.root, state)
        job.packet.save(path, {'raw': 'SECRET late poison'})
        self.assertEqual(job.capture_fdk(self.root, state), good)
        projected = job.fdk_public(self.root, passing_report(), state)
        self.assertEqual(projected['status'], 'PASS'); self.assertNotIn('SECRET', json.dumps(projected))
        failed = passing_report(); failed.update(status='FAIL', cancelled=True)
        downgraded = job.fdk_public(self.root, failed, state)
        self.assertEqual((downgraded['status'], downgraded['native_build']), ('FAIL', 'NOT ACCEPTED'))
        self.assertTrue(downgraded['cancelled'])
        self.assertEqual(downgraded['worker_diagnostics'], good['worker_diagnostics'])

    def test_run_and_attempt_fields_forwarded_and_fallback_is_finite_fail(self):
        self.assertIn('GITHUB_RUN_ATTEMPT', job.ENV_FIELDS)
        for attempted, availability in ((False, 'NOT_RUN'), (True, 'UNAVAILABLE')):
            state = {'fdk_attempted': attempted}
            record = job.fdk_public(self.root, passing_report(), state)
            self.assertEqual((record['schema_version'], record['status']), (2, 'FAIL'))
            self.assertEqual({r['availability'] for r in record['worker_diagnostics'].values()}, {availability})
            self.load().validate_workers(record['worker_diagnostics'])


class FrozenVimCarrierTests(unittest.TestCase):
    """Actual filesystem helper with four tiny, explicitly derived lock fixtures."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.private = self.base / 'job/private'; self.private.mkdir(parents=True, mode=0o700)
        self.snapshot = self.private / 'source'
        self.carrier = self.base / 'carrier'; self.carrier.mkdir(mode=0o700)
        self.production_files = job.FROZEN_VIM_FILES; self.production_pin = job.packet.INPUTS_SHA
        self.files = tuple((name, len((name + '\n').encode()), job.packet.sha((name + '\n').encode()))
                           for name, _, _ in self.production_files)
        self.data = {name:(name + '\n').encode() for name, _, _ in self.files}
        rows = []
        for package in ('vim', 'vim-runtime'):
            name = package + '-9.2.1164-2-aarch64.pkg.tar.xz'
            rows.append({'name':package, 'version':'9.2.1164-2', 'arch':'aarch64', 'filename':name,
                'size':len(self.data[name]), 'sha256':job.packet.sha(self.data[name]),
                'signature_size':len(self.data[name + '.sig']), 'signature_sha256':job.packet.sha(self.data[name + '.sig'])})
        self.lock = {'packages':rows}; self.lock_path = self.snapshot / 'scripts/ci/inputs.lock.json'
        self.lock_path.parent.mkdir(parents=True); self.write_lock()
        for name, data in self.data.items():(self.carrier / name).write_bytes(data)
        self.J = time.monotonic() + 100
        patches = (mock.patch.object(job, 'HERE', self.base / 'repo' / job.packet.PREFIX),
            mock.patch.object(job, 'FROZEN_VIM_FILES', self.files),
            mock.patch.object(job.packet, 'INPUTS_SHA', job.packet.sha(self.lock_path.read_bytes())))
        for patch in patches:patch.start(); self.addCleanup(patch.stop)

    def write_lock(self):
        self.lock_path.write_text(json.dumps(self.lock, sort_keys=True) + '\n')
        self.lock_path.chmod(0o644)

    def seed(self, pin=None):
        return job.seed_frozen_vim(self.snapshot, self.private, self.carrier, self.J, pin)

    def test_exact_four_tiny_files_copy_to_fresh_owned_cache_and_immutable_manifest(self):
        contract = job.frozen_vim_inputs(self.snapshot, self.J)
        self.assertEqual(self.seed(contract.manifest_sha256()), contract)
        with self.assertRaises(Exception):contract.files = ()
        cache = self.private / 'cache'
        self.assertEqual(cache.stat().st_mode & 0o777, 0o700)
        self.assertEqual(set(p.name for p in cache.iterdir()), set(self.data))
        for name, data in self.data.items():
            path = cache / name
            self.assertEqual(path.read_bytes(), data); self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_actual_frozen_source_lock_matches_four_production_pins_and_total(self):
        raw = (ROOT / 'scripts/ci/inputs.lock.json').read_bytes(); self.lock_path.write_bytes(raw)
        with mock.patch.object(job, 'FROZEN_VIM_FILES', self.production_files), \
             mock.patch.object(job.packet, 'INPUTS_SHA', self.production_pin):
            contract = job.frozen_vim_inputs(self.snapshot, self.J)
        self.assertEqual(contract.files, tuple(sorted(self.production_files)))
        self.assertEqual(sum(size for _, size, _ in contract.files), 9790183)
        self.assertFalse((self.private / 'cache').exists())

    def test_rehashed_arbitrary_lock_cannot_replace_fixed_production_contract(self):
        with mock.patch.object(job, 'FROZEN_VIM_FILES', self.production_files):
            with self.assertRaisesRegex(ValueError, 'frozen-vim-carrier-contract'):self.seed()
        self.assertFalse((self.private / 'cache').exists())

    def test_bad_input_pin_and_bad_manifest_refuse_before_carrier_files(self):
        original = job.frozen_read; names = []
        def read(directory, name, *args, **kwargs):
            names.append(name);return original(directory, name, *args, **kwargs)
        with mock.patch.object(job, 'frozen_read', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'manifest-pin'):self.seed('0' * 64)
            self.lock_path.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'pin-drift'):self.seed()
        self.assertEqual(names, ['inputs.lock.json', 'inputs.lock.json'])
        self.assertFalse((self.private / 'cache').exists())

    def test_lock_duplicate_wrong_version_arch_and_boolean_size_refuse(self):
        import copy
        original = copy.deepcopy(self.lock)
        changes = (lambda rows:rows.append(copy.deepcopy(rows[0])),
                   lambda rows:rows[0].update(version='new'), lambda rows:rows[0].update(arch='x86_64'),
                   lambda rows:rows[0].update(size=True))
        for change in changes:
            self.lock = copy.deepcopy(original);change(self.lock['packages']);self.write_lock()
            with mock.patch.object(job.packet, 'INPUTS_SHA', job.packet.sha(self.lock_path.read_bytes())):
                with self.assertRaises(ValueError):self.seed()
            self.assertFalse((self.private / 'cache').exists())

    def test_missing_and_unselected_extra_members_refuse_without_reading_extra(self):
        name = next(iter(self.data)); path = self.carrier / name; path.unlink()
        with self.assertRaisesRegex(ValueError, 'membership'):self.seed()
        path.write_bytes(self.data[name]);(self.carrier / 'unselected').write_bytes(b'unselected')
        with mock.patch.object(job, 'frozen_read', wraps=job.frozen_read) as read:
            with self.assertRaisesRegex(ValueError, 'membership'):self.seed()
        self.assertEqual([call.args[1] for call in read.call_args_list], ['inputs.lock.json'])
        self.assertFalse((self.private / 'cache').exists())

    def test_last_file_size_hash_modes_links_and_fifo_refuse_before_cache(self):
        name = sorted(self.data)[-1];path = self.carrier / name
        for kind in ('size', 'hash', 'mode', 'hardlink', 'symlink', 'fifo'):
            path.unlink();other = self.base / 'other';other.unlink(missing_ok=True)
            if kind == 'symlink':other.write_bytes(self.data[name]);path.symlink_to(other)
            elif kind == 'fifo':os.mkfifo(path)
            else:
                path.write_bytes(b'x' if kind == 'size' else b'x' * len(self.data[name]) if kind == 'hash' else self.data[name])
                if kind == 'mode':path.chmod(0o755)
                if kind == 'hardlink':os.link(path, other)
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):self.seed()
                self.assertFalse((self.private / 'cache').exists())

    def test_parent_symlink_and_foreign_owner_and_carrier_mode_refuse(self):
        alias = self.base / 'alias';alias.symlink_to(self.carrier, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'parent'):
            job.seed_frozen_vim(self.snapshot, self.private, alias, self.J)
        with mock.patch.object(job.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):self.seed()
        self.carrier.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'directory'):self.seed()
        self.assertFalse((self.private / 'cache').exists())

    def test_carrier_and_parent_replacement_during_source_capture_refuse(self):
        read = os.read; changed = []
        def replace(fd, count):
            data = read(fd, count)
            if data and not changed and os.fstat(fd).st_size != self.lock_path.stat().st_size:
                changed.append(True);self.carrier.rename(self.base / 'held-original')
                self.carrier.mkdir(mode=0o700)
            return data
        with mock.patch.object(job.os, 'read', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'parent-drift'):self.seed()
        self.assertTrue(changed);self.assertFalse((self.private / 'cache').exists())

    def test_existing_foreign_cache_is_never_modified_or_removed(self):
        cache = self.private / 'cache';cache.mkdir();(cache / 'foreign').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):self.seed()
        self.assertEqual((cache / 'foreign').read_bytes(), b'keep')

    def test_partial_copy_disposes_only_created_files_and_preserves_first_cause(self):
        write = os.write; calls = []
        def failure(fd, data):
            calls.append(data)
            if len(calls) == 2:raise OSError('first-copy-cause')
            return write(fd, data)
        with mock.patch.object(job.os, 'write', side_effect=failure):
            with self.assertRaisesRegex(OSError, 'first-copy-cause'):self.seed()
        self.assertEqual(len(calls), 2);self.assertFalse((self.private / 'cache').exists())
        for name, data in self.data.items():self.assertEqual((self.carrier / name).read_bytes(), data)

    def test_short_write_and_partial_copy_cancel_dispose_cache(self):
        for kind in ('short', 'cancel'):
            def failure(fd, data):
                if kind == 'cancel':raise job.jr.Cancelled(signal.SIGTERM)
                return len(data) - 1
            with mock.patch.object(job.os, 'write', side_effect=failure):
                with self.assertRaises(job.jr.Cancelled if kind == 'cancel' else ValueError):self.seed()
            self.assertFalse((self.private / 'cache').exists())

    def test_expired_and_nonfinite_deadline_refuse_before_any_source_read(self):
        for deadline in (time.monotonic() - 1, True, float('inf'), 10**1000):
            with mock.patch.object(job.os, 'read') as read:
                with self.assertRaisesRegex(ValueError, 'deadline'):
                    job.seed_frozen_vim(self.snapshot, self.private, self.carrier, deadline)
            read.assert_not_called();self.assertFalse((self.private / 'cache').exists())

    def test_copy_expiry_uses_same_J_and_disposes_partial_cache(self):
        write = os.write;now = [100.0];J = 200.0
        def expired(fd, data):
            result = write(fd, data);now[0] = J;return result
        with mock.patch.object(job.time, 'monotonic', side_effect=lambda:now[0]), \
             mock.patch.object(job.os, 'write', side_effect=expired):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                job.seed_frozen_vim(self.snapshot, self.private, self.carrier, J)
        self.assertEqual(J, 200.0);self.assertFalse((self.private / 'cache').exists())

    def test_source_drift_during_copy_disposes_partial_cache(self):
        write = os.write;changed = []
        def drift(fd, data):
            result = write(fd, data)
            if not changed:
                changed.append(True);(self.carrier / sorted(self.data)[-1]).write_bytes(b'drift')
            return result
        with mock.patch.object(job.os, 'write', side_effect=drift):
            with self.assertRaisesRegex(ValueError, 'file-drift'):self.seed()
        self.assertFalse((self.private / 'cache').exists())

    def test_foreign_replacement_cache_is_not_cleaned_and_does_not_mask_first_error(self):
        write = os.write;changed = [];cache = self.private / 'cache'
        def replace(fd, data):
            result = write(fd, data)
            if not changed:
                changed.append(True);cache.rename(self.private / 'owned-displaced')
                cache.mkdir();(cache / 'foreign').write_bytes(b'keep')
            return result
        with mock.patch.object(job.os, 'write', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'cache-drift') as raised:self.seed()
        self.assertIn('frozen-vim-owned-cache-disposal-failed', raised.exception.__notes__)
        self.assertEqual((cache / 'foreign').read_bytes(), b'keep')

    def test_foreign_cache_member_refuses_disposal_without_deleting_foreign_bytes(self):
        write = os.write;changed = [];cache = self.private / 'cache'
        def extra(fd, data):
            result = write(fd, data)
            if not changed:changed.append(True);(cache / 'foreign').write_bytes(b'keep')
            return result
        with mock.patch.object(job.os, 'write', side_effect=extra):
            with self.assertRaisesRegex(ValueError, 'membership') as raised:self.seed()
        self.assertIn('frozen-vim-owned-cache-disposal-failed', raised.exception.__notes__)
        self.assertEqual((cache / 'foreign').read_bytes(), b'keep')

    def test_disposal_failure_and_pending_cancel_preserve_original_exception(self):
        @contextmanager
        def deferred():yield [signal.SIGTERM]
        original = job.jr.defer_signals;calls = []
        def defer():
            calls.append(True)
            return deferred() if len(calls) > 2 else original()
        with mock.patch.object(job.os, 'write', side_effect=OSError('first-cause')), \
             mock.patch.object(job.os, 'unlink', side_effect=PermissionError()), \
             mock.patch.object(job.jr, 'defer_signals', side_effect=defer):
            with self.assertRaisesRegex(OSError, 'first-cause') as raised:self.seed()
        self.assertIn('frozen-vim-owned-cache-disposal-failed', raised.exception.__notes__)
        self.assertTrue(raised.exception.frozen_vim_cancelled)

    def test_same_bytes_foreign_inode_replacement_after_write_refuses_acceptance(self):
        fsync = os.fsync; changed = [];cache = self.private / 'cache'
        def replace(fd):
            fsync(fd)
            if job.stat.S_ISREG(os.fstat(fd).st_mode) and not changed:
                changed.append(True);name = sorted(self.data)[0];path = cache / name
                path.unlink();path.write_bytes(self.data[name]);path.chmod(0o600)
        with mock.patch.object(job.os, 'fsync', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'copy-pin') as raised:self.seed()
        self.assertIn('frozen-vim-owned-cache-disposal-failed', raised.exception.__notes__)
        self.assertEqual((cache / sorted(self.data)[0]).read_bytes(), self.data[sorted(self.data)[0]])

    def test_completed_cache_file_drift_during_later_copy_refuses_and_disposes(self):
        write = os.write;calls = []
        def drift(fd, data):
            result = write(fd, data);calls.append(True)
            if len(calls) == 2:(self.private / 'cache' / sorted(self.data)[0]).write_bytes(b'drift')
            return result
        with mock.patch.object(job.os, 'write', side_effect=drift):
            with self.assertRaisesRegex(ValueError, 'copy-drift'):self.seed()
        self.assertFalse((self.private / 'cache').exists())

    def test_actual_original_fetch_existing_branch_uses_seed_without_transport(self):
        contract = self.seed();raw = (ROOT / 'scripts/ci/native_arm.py').read_bytes()
        tree = ast.parse(raw)
        definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
                       node.name in ('sha', 'check_pin', 'input_name', 'fetch')]
        self.assertEqual(len(definitions), 4)
        network = mock.Mock(side_effect=AssertionError('transport forbidden in fixture'))
        scope = {'hashlib':hashlib, 're':re, 'urllib':SimpleNamespace(request=SimpleNamespace(urlopen=network))}
        exec(compile(ast.Module(body=definitions, type_ignores=[]), 'captured-original-fetch', 'exec'), scope)
        for name, size, pin in contract.files:
            path = self.private / 'cache' / name; before = job.frozen_stamp(path.stat())
            self.assertEqual(scope['fetch']({'filename':name, 'size':size, 'sha256':pin,
                'url':'https://fixture.invalid/' + name}, path.parent), path)
            self.assertEqual(job.frozen_stamp(path.stat()), before)
        network.assert_not_called()


    def _fault_errors(self):
        return (ValueError('private first ordinary'), job.jr.Cancelled(signal.SIGTERM),
                KeyboardInterrupt('private first control'), SystemExit(7))

    def _fd_after_fault(self, records):
        # Fixture retirement only: an ambiguous close is never blindly retried.
        for fd, before in records:
            try:current = os.fstat(fd)
            except OSError:continue
            if (current.st_dev, current.st_ino, current.st_mode) == before:
                os.close(fd)

    def test_directory_close_fault_preserves_all_first_types_and_attempts_every_fd(self):
        real_open, real_close = os.open, os.close
        for first in self._fault_errors():
            with self.subTest(first=type(first).__name__):
                records = []; attempts = []
                def opening(*args, **kwargs):
                    fd = real_open(*args, **kwargs);s = os.fstat(fd)
                    records.append((fd, (s.st_dev, s.st_ino, s.st_mode)));return fd
                def closing(fd):
                    attempts.append(fd);real_close(fd);raise OSError('private close-after-close fault')
                with mock.patch.object(job.os, 'open', side_effect=opening), \
                     mock.patch.object(job.os, 'close', side_effect=closing):
                    with self.assertRaises(type(first)) as raised:
                        with job.frozen_directory(self.carrier, self.J):raise first
                self.assertIs(raised.exception, first)
                self.assertEqual(attempts, [fd for fd, _ in reversed(records)])
                self.assertIn('frozen-vim-owned-fd-cleanup-outcome-unknown', first.__notes__)
                self._fd_after_fault(records)

    def test_source_read_close_fault_preserves_all_first_types(self):
        parent = os.open(self.carrier, os.O_RDONLY | os.O_DIRECTORY)
        real_close = os.close
        try:
            for first in self._fault_errors():
                with self.subTest(first=type(first).__name__):
                    attempts = []
                    def closing(fd):attempts.append(fd);real_close(fd);raise OSError('private read-close fault')
                    with mock.patch.object(job.os, 'read', side_effect=first), \
                         mock.patch.object(job.os, 'close', side_effect=closing):
                        with self.assertRaises(type(first)) as raised:
                            job.frozen_read(parent, self.files[0][0], self.J)
                    self.assertIs(raised.exception, first);self.assertEqual(len(attempts), 1)
        finally:real_close(parent)

    def test_enumeration_close_fault_preserves_all_first_types(self):
        parent = os.open(self.carrier, os.O_RDONLY | os.O_DIRECTORY)
        real_close = os.close
        try:
            for first in self._fault_errors():
                with self.subTest(first=type(first).__name__):
                    attempts = []
                    def closing(fd):attempts.append(fd);real_close(fd);raise OSError('private names-close fault')
                    with mock.patch.object(job.os, 'scandir', side_effect=first), \
                         mock.patch.object(job.os, 'close', side_effect=closing):
                        with self.assertRaises(type(first)) as raised:job.frozen_names(parent, self.J)
                    self.assertIs(raised.exception, first);self.assertEqual(len(attempts), 1)
        finally:real_close(parent)

    def test_copy_and_cache_close_fault_preserve_all_first_types(self):
        real_open, real_close = os.open, os.close
        for role in ('copy', 'cache'):
            for first in self._fault_errors():
                with self.subTest(role=role, first=type(first).__name__):
                    selected = []; attempts = []
                    def opening(name, flags, *args, **kwargs):
                        fd = real_open(name, flags, *args, **kwargs)
                        if (role == 'cache' and name == 'cache' and flags & os.O_DIRECTORY or
                            role == 'copy' and flags & os.O_CREAT):
                            s = os.fstat(fd);selected.append((fd, (s.st_dev, s.st_ino, s.st_mode)))
                        return fd
                    def closing(fd):
                        s = os.fstat(fd);owned = selected and fd == selected[0][0] and \
                            (s.st_dev, s.st_ino, s.st_mode) == selected[0][1]
                        real_close(fd)
                        if owned:attempts.append(fd);raise OSError('private retained close fault')
                    with mock.patch.object(job.os, 'open', side_effect=opening), \
                         mock.patch.object(job.os, 'write', side_effect=first), \
                         mock.patch.object(job.os, 'close', side_effect=closing):
                        with self.assertRaises(type(first)) as raised:self.seed()
                    self.assertIs(raised.exception, first);self.assertEqual(len(attempts), 1)
                    self.assertFalse((self.private / 'cache').exists())

    def test_cleanup_alone_close_fault_refuses_healthy_completion_and_never_retries(self):
        real_close = os.close;attempts = [];exact = OSError('private healthy close fault')
        def closing(fd):attempts.append(fd);real_close(fd);raise exact
        with mock.patch.object(job.os, 'close', side_effect=closing):
            with self.assertRaises(OSError) as raised:
                with job.frozen_directory(self.carrier, self.J):pass
        self.assertIs(raised.exception, exact)
        self.assertEqual(len(attempts), len(set(attempts)))
        self.assertGreater(len(attempts), 1)

    def test_directory_close_before_effect_remains_unknown_without_retry(self):
        real_open, real_close = os.open, os.close;records = [];attempts = []
        first = job.jr.Cancelled(signal.SIGTERM)
        def opening(*args, **kwargs):
            fd = real_open(*args, **kwargs);info = os.fstat(fd)
            records.append((fd, (info.st_dev, info.st_ino, info.st_mode)));return fd
        def closing(fd):
            attempts.append(fd)
            if fd == records[-1][0]:raise OSError('private close-before-effect fault')
            real_close(fd)
        try:
            with mock.patch.object(job.os, 'open', side_effect=opening), mock.patch.object(job.os, 'close', side_effect=closing):
                with self.assertRaises(job.jr.Cancelled) as raised:
                    with job.frozen_directory(self.carrier, self.J):raise first
            self.assertIs(raised.exception, first)
            self.assertEqual(attempts, [fd for fd, _ in reversed(records)])
            os.fstat(records[-1][0])  # Retained open fixture fd; no absence claim.
            self.assertIn('frozen-vim-owned-fd-cleanup-outcome-unknown', first.__notes__)
        finally:self._fd_after_fault(records)

    def _pending_source_signal(self, kind, where):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        parent = real_open(self.carrier, os.O_RDONLY | os.O_DIRECTORY)
        allocated = [];closed = [];sent = []
        def opening(*args, **kwargs):
            fd = real_open(*args, **kwargs);allocated.append(fd)
            if where == 'open' and not sent:
                sent.append(True);os.kill(os.getpid(), signal.SIGTERM)
            return fd
        def fstat(fd):
            if where == 'fstat' and fd in allocated and not sent:
                sent.append(True);os.kill(os.getpid(), signal.SIGTERM)
            return real_fstat(fd)
        def closing(fd):closed.append(fd);return real_close(fd)
        try:
            with job.jr.cancellation_handlers(), mock.patch.object(job.os, 'open', side_effect=opening), \
                 mock.patch.object(job.os, 'fstat', side_effect=fstat), mock.patch.object(job.os, 'close', side_effect=closing):
                with self.assertRaises(job.jr.Cancelled) as raised:
                    if kind == 'directory':
                        with job.frozen_directory(self.carrier, self.J):self.fail('pending control entered body')
                    elif kind == 'read':job.frozen_read(parent, self.files[0][0], self.J)
                    else:job.frozen_names(parent, self.J)
            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            self.assertEqual(len(allocated), 1);self.assertEqual(closed, allocated)
            with self.assertRaises(OSError):real_fstat(allocated[0])
        finally:
            for fd in allocated:
                if fd not in closed:real_close(fd)
            real_close(parent)

    def test_pending_directory_signal_after_returned_open_and_fstat_is_registered(self):
        for where in ('open', 'fstat'):
            with self.subTest(where=where):self._pending_source_signal('directory', where)

    def test_pending_read_signal_after_returned_open_and_fstat_is_registered(self):
        for where in ('open', 'fstat'):
            with self.subTest(where=where):self._pending_source_signal('read', where)

    def test_pending_names_signal_after_returned_open_and_fstat_is_registered(self):
        for where in ('open', 'fstat'):
            with self.subTest(where=where):self._pending_source_signal('names', where)

    def test_pending_copy_and_cache_signal_after_returned_open_is_registered(self):
        real_open, real_close = os.open, os.close
        for role in ('cache', 'copy'):
            with self.subTest(role=role):
                selected = [];closed = []
                def opening(name, flags, *args, **kwargs):
                    fd = real_open(name, flags, *args, **kwargs)
                    if not selected and (role == 'cache' and name == 'cache' and flags & os.O_DIRECTORY or
                                         role == 'copy' and flags & os.O_CREAT):
                        selected.append(fd);os.kill(os.getpid(), signal.SIGTERM)
                    return fd
                def closing(fd):closed.append(fd);return real_close(fd)
                with job.jr.cancellation_handlers(), mock.patch.object(job.os, 'open', side_effect=opening), \
                     mock.patch.object(job.os, 'close', side_effect=closing):
                    with self.assertRaises(job.jr.Cancelled):self.seed()
                self.assertEqual(len(selected), 1);self.assertIn(selected[0], closed)
                with self.assertRaises(OSError):os.fstat(selected[0])
                self.assertFalse((self.private / 'cache').exists())

    def test_postopen_fstat_fault_closes_every_registered_source_fd(self):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        parent = real_open(self.carrier, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for kind in ('directory', 'read', 'names'):
                with self.subTest(kind=kind):
                    allocated = [];closed = [];first = ValueError('private postopen fstat cause')
                    def opening(*args, **kwargs):
                        fd = real_open(*args, **kwargs);allocated.append(fd);return fd
                    def fstat(fd):
                        if allocated and fd == allocated[-1]:raise first
                        return real_fstat(fd)
                    def closing(fd):closed.append(fd);return real_close(fd)
                    with mock.patch.object(job.os, 'open', side_effect=opening), \
                         mock.patch.object(job.os, 'fstat', side_effect=fstat), mock.patch.object(job.os, 'close', side_effect=closing):
                        with self.assertRaises(ValueError) as raised:
                            if kind == 'directory':
                                with job.frozen_directory(self.carrier, self.J):self.fail('fstat fault entered body')
                            elif kind == 'read':job.frozen_read(parent, self.files[0][0], self.J)
                            else:job.frozen_names(parent, self.J)
                    self.assertIs(raised.exception, first);self.assertEqual(allocated, closed)
        finally:real_close(parent)

    def test_mask_restoration_fault_preserves_postopen_cause_and_closes_owned_fd(self):
        real_mask, real_open, real_close, real_fstat = signal.pthread_sigmask, os.open, os.close, os.fstat
        first = job.jr.Cancelled(signal.SIGTERM);secondary = OSError('private restored-mask fault')
        allocated = [];closed = [];faulted = []
        def opening(*args, **kwargs):
            fd = real_open(*args, **kwargs);allocated.append(fd);return fd
        def fstat(fd):
            if allocated and fd == allocated[-1]:raise first
            return real_fstat(fd)
        def mask(how, values):
            result = real_mask(how, values)
            if how == signal.SIG_SETMASK and not faulted:faulted.append(True);raise secondary
            return result
        def closing(fd):closed.append(fd);return real_close(fd)
        with mock.patch.object(job.os, 'open', side_effect=opening), mock.patch.object(job.os, 'fstat', side_effect=fstat), \
             mock.patch.object(job.os, 'close', side_effect=closing), mock.patch.object(job.signal, 'pthread_sigmask', side_effect=mask):
            with self.assertRaises(job.jr.Cancelled) as raised:
                with job.frozen_directory(self.carrier, self.J):self.fail('must not enter')
        self.assertIs(raised.exception, first);self.assertEqual(allocated, closed)
        self.assertIn('frozen-vim-signal-restoration-outcome-unknown', first.__notes__)

    def test_handler_restoration_fault_preserves_body_and_copy_first_causes(self):
        @contextmanager
        def faulty_defer():
            try:yield []
            finally:raise OSError('private handler-restoration fault')
        first = ValueError('private first fstat');real_fstat = os.fstat
        def fstat(fd):
            info = real_fstat(fd)
            if job.stat.S_ISREG(info.st_mode) and info.st_mode & 0o777 == 0o600:raise first
            return info
        original = job.jr.defer_signals;calls = []
        def defer():
            calls.append(True);return faulty_defer() if len(calls) == 2 else original()
        with mock.patch.object(job.jr, 'defer_signals', side_effect=defer), \
             mock.patch.object(job.os, 'fstat', side_effect=fstat):
            with self.assertRaises(ValueError) as raised:self.seed()
        self.assertIs(raised.exception, first)
        for first in self._fault_errors():
            with mock.patch.object(job.jr, 'defer_signals', side_effect=faulty_defer):
                with self.assertRaises(type(first)) as raised:
                    with job.frozen_defer():raise first
            self.assertIs(raised.exception, first)

    def test_unreturned_descriptor_from_arbitrary_replacement_open_is_unclaimed(self):
        real_open, real_close = os.open, os.close
        allocated = [];first = job.jr.Cancelled(signal.SIGTERM)
        def unreturned(*args, **kwargs):
            fd = real_open(*args, **kwargs);allocated.append(fd);raise first
        try:
            with mock.patch.object(job.os, 'open', side_effect=unreturned):
                with self.assertRaises(job.jr.Cancelled) as raised:
                    with job.frozen_directory(self.carrier, self.J):self.fail('must not enter')
            self.assertIs(raised.exception, first);self.assertEqual(len(allocated), 1)
            # This artificial wrapper hid its allocated fd. The source cannot
            # own it; only the fixture, which retained that fd, may retire it.
            os.fstat(allocated[0])
        finally:
            for fd in allocated:real_close(fd)

    def test_postopen_cache_and_copy_fstat_fault_retains_fd_ownership(self):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        for role in ('cache', 'copy'):
            with self.subTest(role=role):
                selected = [];closed = [];faulted = [];first = ValueError('private created-fd fstat cause')
                def opening(name, flags, *args, **kwargs):
                    fd = real_open(name, flags, *args, **kwargs)
                    if not selected and (role == 'cache' and name == 'cache' and flags & os.O_DIRECTORY or
                                         role == 'copy' and flags & os.O_CREAT):selected.append(fd)
                    return fd
                def fstat(fd):
                    if selected and fd == selected[0] and not faulted:
                        faulted.append(True);raise first
                    return real_fstat(fd)
                def closing(fd):closed.append(fd);return real_close(fd)
                with mock.patch.object(job.os, 'open', side_effect=opening), mock.patch.object(job.os, 'fstat', side_effect=fstat), \
                     mock.patch.object(job.os, 'close', side_effect=closing):
                    with self.assertRaises(ValueError) as raised:self.seed()
                self.assertIs(raised.exception, first);self.assertIn(selected[0], closed)
                with self.assertRaises(OSError):real_fstat(selected[0])
                if role == 'cache':self.assertFalse((self.private / 'cache').exists())
                else:
                    # No file inode was captured after its failed fstat. The
                    # cache conservatively remains; fd close is a separate fact.
                    self.assertTrue((self.private / 'cache').exists())
                    self.assertIn('frozen-vim-owned-cache-disposal-failed', first.__notes__)


class JobCarrierRouteTests(unittest.TestCase):
    setUp = JobTests.setUp
    snapshot = JobTests.snapshot
    run_command = JobTests.run_command
    cleanup = JobTests.cleanup
    publish = JobTests.publish
    execute = JobTests.execute
    records = JobTests.records
    assert_failed_public = JobTests.assert_failed_public

    def carrier_args(self):
        self.args.frozen_vim_carrier = self.base / 'carrier'
        self.args.frozen_vim_manifest_sha256 = None

    def test_legacy_route_never_calls_carrier_and_preserves_existing_commands(self):
        with mock.patch.object(job, 'seed_frozen_vim') as seed:result, _ = self.execute()
        seed.assert_not_called();self.assertEqual(result, 0)
        self.assertEqual(self.events, ['source', 'producer', 'fdk', 'cleanup', 'publish'])
        self.assertFalse((self.private / 'frozen-vim-carrier.json').exists())

    def test_hook_after_complete_source_capture_before_broker_and_producer_same_J(self):
        self.carrier_args();calls = []
        def seed(snapshot, private, carrier, J, pin):
            self.assertEqual(self.events, ['source']);self.assertEqual(J, self.runner.deadline)
            self.assertTrue((private / 'source-receipt.json').is_file())
            self.assertTrue((snapshot / 'scripts/ci/native_arm.py').is_file())
            self.cls.assert_not_called();calls.append((carrier, pin));self.events.append('carrier')
            return job.FrozenVimInputs(job.packet.INPUTS_SHA, job.FROZEN_VIM_FILES)
        with mock.patch.object(job, 'seed_frozen_vim', side_effect=seed):result, _ = self.execute()
        self.assertEqual(result, 0);self.assertEqual(calls, [(self.args.frozen_vim_carrier, None)])
        self.assertEqual(self.events, ['source', 'carrier', 'producer', 'fdk', 'cleanup', 'publish'])
        receipt = job.packet.load(self.private / 'frozen-vim-carrier.json')
        self.assertEqual((receipt['source_commit'], receipt['run_id'], receipt['run_attempt']), (COMMIT, '1', '2'))

    def test_failed_source_prevents_all_carrier_reads_and_broker_calls(self):
        self.carrier_args();self.mode = 'source-fail'
        with mock.patch.object(job, 'seed_frozen_vim') as seed:result, _ = self.execute()
        self.assertEqual(result, 1);seed.assert_not_called();self.cls.assert_not_called()
        self.assertEqual(self.events, ['source', 'publish'])

    def test_preexisting_output_and_invalid_carrier_arguments_refuse_before_source(self):
        self.carrier_args();self.out.mkdir()
        with mock.patch.object(job, 'seed_frozen_vim') as seed:
            with self.assertRaisesRegex(ValueError, 'new-external-job-output'):self.execute()
        seed.assert_not_called();self.assertEqual(self.events, []);self.out.rmdir()
        for carrier, pin in ((None, 'a' * 64), (str(self.base / 'carrier'), None),
                             (self.out / 'carrier', None), (self.root / 'carrier', None),
                             (self.base / 'carrier', True)):
            self.args.frozen_vim_carrier = carrier;self.args.frozen_vim_manifest_sha256 = pin
            with self.assertRaises(ValueError):self.execute()
            self.assertFalse(self.out.exists());self.assertEqual(self.events, [])

    def test_wrong_run_identity_refuses_before_carrier_and_producer(self):
        self.carrier_args()
        with mock.patch.dict(os.environ, {'GITHUB_RUN_ATTEMPT':'0'}), mock.patch.object(job, 'seed_frozen_vim') as seed:
            result, _ = self.execute()
        self.assertEqual(result, 1);seed.assert_not_called();self.cls.assert_not_called();self.assert_failed_public()

    def test_carrier_cancel_or_failure_retains_fixed_fail_and_never_starts_producer(self):
        self.carrier_args()
        with mock.patch.object(job, 'seed_frozen_vim', side_effect=job.jr.Cancelled(signal.SIGTERM)):
            result, state = self.execute()
        self.assertEqual(result, 1);self.assertTrue(state['report']['cancelled'])
        self.cls.assert_not_called();self.assert_failed_public()

    def test_disposal_cancel_preserves_outer_first_failure_and_cancelled_status(self):
        self.carrier_args();error = OSError('first-cause');error.frozen_vim_cancelled = True
        with mock.patch.object(job, 'seed_frozen_vim', side_effect=error):result, state = self.execute()
        self.assertEqual(result, 1);self.assertTrue(state['report']['cancelled'])
        self.assertEqual(state['report']['error_code'], 'fdk-native-job-failed')
        self.cls.assert_not_called();self.assert_failed_public()

    def test_actual_inline_helper_copies_tiny_four_after_snapshot_before_broker(self):
        self.carrier_args();self.args.frozen_vim_carrier.mkdir(mode=0o700)
        data = {name:(name + '\n').encode() for name, _, _ in job.FROZEN_VIM_FILES}
        files = tuple((name, len(raw), job.packet.sha(raw)) for name, raw in data.items())
        rows = []
        for package in ('vim', 'vim-runtime'):
            name = package + '-9.2.1164-2-aarch64.pkg.tar.xz'
            rows.append({'name':package, 'version':'9.2.1164-2', 'arch':'aarch64', 'filename':name,
                'size':len(data[name]), 'sha256':job.packet.sha(data[name]),
                'signature_size':len(data[name + '.sig']), 'signature_sha256':job.packet.sha(data[name + '.sig'])})
        raw = json.dumps({'packages':rows}, sort_keys=True).encode()
        self.source_bytes['scripts/ci/inputs.lock.json'] = raw
        for name, content in data.items():(self.args.frozen_vim_carrier / name).write_bytes(content)
        def broker(*args, **kwargs):
            self.assertEqual(self.events, ['source'])
            for name, content in data.items():self.assertEqual((self.private / 'cache' / name).read_bytes(), content)
            return self.broker
        self.cls.side_effect = broker
        with mock.patch.object(job, 'FROZEN_VIM_FILES', files), mock.patch.object(job.packet, 'INPUTS_SHA', job.packet.sha(raw)), \
             mock.patch.object(job, 'seed_frozen_vim', wraps=job.seed_frozen_vim) as seed:
            result, _ = self.execute()
        self.assertEqual(result, 0);self.assertEqual(seed.call_args.args[3], self.runner.deadline)
        self.assertEqual(self.events, ['source', 'producer', 'fdk', 'cleanup', 'publish'])


class CleanupProjectionTests(unittest.TestCase):
    # Reuse inert controller fixtures without inheriting or duplicating old tests.
    setUp = JobTests.setUp
    snapshot = JobTests.snapshot
    run_command = JobTests.run_command
    cleanup = JobTests.cleanup
    publish = JobTests.publish
    execute = JobTests.execute
    records = JobTests.records
    assert_failed_public = JobTests.assert_failed_public
    main = JobTests.main
    prepare_finish = JobTests.prepare_finish

    def observation(self, **changes):
        return {'schema_version': 1, 'scope': 'producer-containers', 'phase': 'acquisition',
                'call': 'returned', 'journal': 'ABSENT', 'reason': 'unknown-error',
                'boundary_error': 'none', 'observation_error': 'none', 'status': 'FAIL',
                'absence_verified': False, 'cancelled': False, **changes}

    def worker(self, observation=None, raw=None):
        self.private.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.private / 'producer-worker.json'
        if raw is None:
            job.packet.save(path, {'cleanup_diagnostic': observation})
        else:
            path.write_bytes(raw)
            path.chmod(0o600)
        return path

    def capture(self, state=None):
        return job.capture_producer_cleanup(self.private,
            {'producer_cleanup_allowed': True} if state is None else state)

    def project(self, observation):
        return job.cleanup_observation(observation, job.evidence.PRODUCER_PHASES,
            job.evidence.BASE_PROBE_POLICY_CODES, job.evidence.BASE_PROBE_REFUSALS)

    def test_finite_return_raised_and_partial_snapshots_roundtrip_without_absence_inference(self):
        for observation in [self.observation(),
                self.observation(call='raised', status='UNOBSERVED', absence_verified='UNOBSERVED',
                                 cancelled='UNOBSERVED', reason='os-error'),
                self.observation(call='not-run', status='UNOBSERVED', absence_verified='UNOBSERVED',
                                 cancelled='UNOBSERVED', reason='none'),
                self.observation(call='started', journal='REGULAR', status='UNOBSERVED',
                                 absence_verified='UNOBSERVED', cancelled='UNOBSERVED', reason='none')]:
            with self.subTest(call=observation['call']):
                self.worker(observation)
                value = self.capture()
                self.assertEqual(value, {'availability': 'OBSERVED', 'observation': observation})
                self.assertTrue({'pid', 'process_launch', 'process_reap', 'container_id'}.isdisjoint(value['observation']))
                self.assertEqual(value['observation']['absence_verified'], observation['absence_verified'])

    def test_missing_capture_never_late_promotes_and_success_is_detached_from_caller_mutation(self):
        state = {'producer_cleanup_allowed': True}
        self.assertEqual(self.capture(state), {'availability': 'UNOBSERVED', 'observation': None})
        self.worker(self.observation())
        self.assertEqual(self.capture(state), {'availability': 'UNOBSERVED', 'observation': None})
        fresh = {'producer_cleanup_allowed': True}
        captured = self.capture(fresh)
        expected = self.observation()
        captured['observation']['reason'] = 'PRIVATE-SECRET'
        self.worker(self.observation(reason='none', journal='REGULAR'))
        with mock.patch.object(job.packet, 'read', side_effect=AssertionError('no second read')):
            self.assertEqual(self.capture(fresh), {'availability': 'OBSERVED', 'observation': expected})

    def test_capture_ownership_mode_symlink_and_hardlink_refuse_before_open(self):
        path = self.worker(self.observation())
        target = self.private / 'unrelated.json'
        target.write_text('PRIVATE-SECRET')
        target.chmod(0o600)
        for kind in ('mode', 'owner', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                path.unlink(missing_ok=True)
                self.worker(self.observation())
                patch = mock.patch.object(job.os, 'getuid', return_value=os.getuid() + 1) if kind == 'owner' else nullcontext()
                if kind == 'mode': path.chmod(0o644)
                if kind == 'symlink':
                    path.unlink(); path.symlink_to(target)
                if kind == 'hardlink':
                    path.unlink(); os.link(target, path)
                with patch, mock.patch.object(job.packet, 'read', side_effect=AssertionError('must refuse before open')) as read:
                    self.assertEqual(self.capture(), {'availability': 'UNOBSERVED', 'observation': None})
                    read.assert_not_called()
        self.assertEqual(target.read_text(), 'PRIVATE-SECRET')

    def test_same_bytes_inode_replacement_during_read_refuses_capture(self):
        path = self.worker(self.observation())
        original = job.packet.read
        def replace(source, *args, **kwargs):
            raw = original(source, *args, **kwargs)
            replacement = path.with_name('replacement.json')
            replacement.write_bytes(raw); replacement.chmod(0o600); replacement.replace(path)
            return raw
        with mock.patch.object(job.packet, 'read', side_effect=replace):
            self.assertEqual(self.capture(), {'availability': 'UNOBSERVED', 'observation': None})

    def test_duplicate_nonfinite_oversized_and_extra_private_diagnostics_are_unobserved(self):
        valid = json.dumps({'cleanup_diagnostic': self.observation()}).encode()
        samples = [valid.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'),
                   valid.replace(b'"schema_version": 1', b'"schema_version": NaN'),
                   valid.replace(b'"schema_version": 1', b'"schema_version": Infinity'),
                   valid.replace(b'"schema_version": 1', b'"schema_version": 1e999'),
                   b'{' + b' ' * 65536 + b'}',
                   json.dumps({'cleanup_diagnostic': self.observation(credentialData='PRIVATE-SECRET')}).encode()]
        for raw in samples:
            with self.subTest(bytes=len(raw)):
                self.worker(raw=raw)
                self.assertEqual(self.capture(), {'availability': 'UNOBSERVED', 'observation': None})

    def test_every_observation_field_refuses_nonplain_scalar_or_unregistered_enum(self):
        class Text(str): pass
        mutations = {'schema_version': [True, 1.0, None], 'scope': [Text('producer-containers'), 'PRIVATE-SECRET'],
            'phase': [None, [], 'PRIVATE-SECRET'], 'call': [False, 'PRIVATE-SECRET'], 'journal': [True, '/PRIVATE/path'],
            'reason': ['[Errno 2] PRIVATE-SECRET', {'message': 'PRIVATE-SECRET'}],
            'boundary_error': ['returned-failure', 'PRIVATE-SECRET'], 'observation_error': [float('nan'), 'PRIVATE-SECRET'],
            'status': [True, 'NOT RUN'], 'absence_verified': [0, 1, None], 'cancelled': [0, 1, None]}
        for name, values in mutations.items():
            for value in values:
                with self.subTest(field=name, type=type(value).__name__):
                    self.assertIsNone(self.project(self.observation(**{name: value})))
        self.assertIsNone(self.project(dict(list(self.observation().items())[1:])))
        self.assertIsNone(self.project(self.observation(raw_error='PRIVATE-SECRET')))

    def test_envelope_requires_exact_availability_and_observation_pair(self):
        def project(value):
            return job.producer_cleanup(value, job.evidence.PRODUCER_PHASES,
                job.evidence.BASE_PROBE_POLICY_CODES, job.evidence.BASE_PROBE_REFUSALS)
        self.assertEqual(project({'availability': 'UNOBSERVED', 'observation': None}),
                         {'availability': 'UNOBSERVED', 'observation': None})
        for value in [None, {'availability': True, 'observation': None},
                {'availability': 'UNOBSERVED', 'observation': self.observation()},
                {'availability': 'OBSERVED', 'observation': None},
                {'availability': 'OBSERVED', 'observation': self.observation(), 'credentialData': 'PRIVATE-SECRET'}]:
            with self.subTest(value=value): self.assertIsNone(project(value))

    def test_source_failure_does_not_read_or_accept_a_preexisting_optional_receipt(self):
        first_bytes = b'PRIVATE-FIRST-SOURCE-CAUSE'
        class SourceFailure(ValueError): pass
        error = SourceFailure(first_bytes)
        def source(*args, **kwargs):
            self.events.append('source')
            self.worker(self.observation(status='PASS', absence_verified=True, reason='none'))
            raise error
        with mock.patch.object(job.packet, 'verify', side_effect=source), \
                mock.patch.object(job.packet, 'read', wraps=job.packet.read) as read:
            result, state = self.execute()
        self.assertEqual(result, 1)
        self.cls.assert_not_called()
        self.assertNotIn('producer', self.events)
        self.assertEqual(error.args, (first_bytes,))
        self.assertFalse(state.get('producer_cleanup_allowed', False))
        self.assertFalse(any(call.args[0] == self.private / 'producer-worker.json' for call in read.call_args_list))
        public = self.records()['public/status.json']
        self.assertEqual(public.pop('producer_cleanup'), {'availability': 'UNOBSERVED', 'observation': None})
        self.assertEqual(public, job.evidence.public_status(state['report']))

    def test_optional_pass_claim_cannot_promote_failed_worker_or_unverified_absence(self):
        observed = self.observation(status='PASS', absence_verified=True, reason='none', phase='complete', journal='REGULAR')
        for mode in ('producer-exit-fail', 'producer-receipt-fail', 'producer-absence-fail'):
            with self.subTest(mode=mode):
                self.mode = mode
                self.boundary_change = lambda receipt: receipt.update(cleanup_diagnostic=observed)
                result, state = self.execute()
                self.assertEqual(result, 1)
                self.assert_failed_public()
                self.assertNotIn('fdk', self.events)
                public = self.records()['public/status.json']
                self.assertEqual(public.pop('producer_cleanup'), {'availability': 'OBSERVED', 'observation': observed})
                self.assertEqual(public, job.evidence.public_status(state['report']))
                # Each modeled run gets a fresh owned output, preserving earlier evidence.
                self.out = self.base / ('job-' + mode); self.private = self.out / 'private'
                self.args.output = self.out; self.events.clear()

    def test_optional_failed_or_unknown_snapshot_cannot_veto_otherwise_accepted_worker(self):
        for observation in (self.observation(), self.observation(credentialData='PRIVATE-SECRET')):
            with self.subTest(invalid='credentialData' in observation):
                self.boundary_change = lambda receipt: receipt.update(cleanup_diagnostic=observation)
                result, state = self.execute()
                self.assertEqual(result, 0)
                public = self.records()['public/status.json']
                self.assertEqual(public['status'], 'PASS')
                self.assertEqual(public.pop('producer_cleanup')['availability'],
                                 'UNOBSERVED' if 'credentialData' in observation else 'OBSERVED')
                self.assertEqual(public, job.evidence.public_status(state['report']))
                self.out = self.base / 'job-second'; self.private = self.out / 'private'; self.args.output = self.out

    def test_optional_reader_fault_preserves_original_business_failure_without_raw_error(self):
        self.mode = 'producer-diagnostic-fail'
        original, injected = job.packet.read, []
        def read(path, *args, **kwargs):
            if path == self.private / 'producer-worker.json' and kwargs == {} and args == (65536,):
                # Existing admission reads happen first; inject only within the optional observer.
                if state_holder and state_holder[0].get('producer_cleanup_capture_attempted'):
                    injected.append(True)
                    raise RuntimeError('PRIVATE-OBSERVER-ERROR')
            return original(path, *args, **kwargs)
        state_holder = []
        def execute(args, state):
            state_holder.append(state)
            return self.original_execute(self.args, state)
        with mock.patch.object(job.packet, 'read', side_effect=read):
            self.assertEqual(self.main(execute), 1)
        self.assertEqual(len(injected), 1)
        self.assert_failed_public()
        public = self.records()['public/status.json']
        self.assertEqual(public.pop('producer_cleanup'), {'availability': 'UNOBSERVED', 'observation': None})
        self.assertEqual(public, job.evidence.public_status(state_holder[0]['report']))
        self.assertEqual(public['error_code'], 'producer-gpg-verify-runner-failed')
        self.assertNotIn('PRIVATE', json.dumps(public))

    def test_observer_cancellation_uses_existing_late_failure_rewrite_and_never_rereads(self):
        original, injected, state_holder = job.packet.read, [], []
        def read(path, *args, **kwargs):
            if (state_holder and state_holder[0].get('producer_cleanup_capture_attempted') and
                    path == self.private / 'producer-worker.json'):
                injected.append(True)
                raise job.jr.Cancelled(signal.SIGTERM)
            return original(path, *args, **kwargs)
        def execute(args, state):
            state_holder.append(state)
            return self.original_execute(self.args, state)
        with mock.patch.object(job.packet, 'read', side_effect=read):
            self.assertEqual(self.main(execute), 1)
        self.assertEqual(len(injected), 1)
        self.assert_failed_public()
        self.assertIs(self.records()['public/status.json']['cancelled'], True)
        self.assertEqual(self.records()['public/status.json']['producer_cleanup'],
                         {'availability': 'UNOBSERVED', 'observation': None})



def workflow_functions(text, index=-1):
    blocks = re.findall(r"/usr/bin/python3 -I -B - <<'PY'\n(.*?)\n          PY", text, re.S)
    tree = ast.parse(textwrap.dedent(blocks[index]))
    scope = {'__name__': 'fdk_consumer_fixture'}
    nodes = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'captured-workflow-fixture', 'exec'), scope)
    return scope


class WorkflowBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.text = (ROOT / '.github/workflows/native-arm-fdk.yml').read_text()
        self.scope = workflow_functions(self.text)
        self.bootstrap = workflow_functions(self.text, 0)
        prefix, adapter = job.packet.PREFIX, job.packet.ADAPTER
        self.source = {adapter + n: (ROOT / (adapter + n)).read_bytes() for n in ('evidence.py', 'worker_evidence.py')}
        stage = {'schema_version': 1, 'files': {n: {'sha256': job.packet.sha(raw), 'mode': 0o644}
                                               for n, raw in self.source.items()}}
        stage_raw = (json.dumps(stage) + '\n').encode()
        self.source.update({adapter + 'stage.lock.json': stage_raw,
            prefix + 'job.py': (ROOT / (prefix + 'job.py')).read_bytes(),
            prefix + 'packet.py': ('ADAPTER_SHA = ' + repr(job.packet.sha(stage_raw)) + '\n').encode()})
        for number in range(128): self.source['fixture/' + str(number) + '.txt'] = b'data-only fixture\n'
        self.rows = {n: {'sha256': job.packet.sha(raw), 'bytes': len(raw), 'mode': 0o644} for n, raw in self.source.items()}
        self.source[prefix + 'packet.lock.json'] = (json.dumps({'schema_version': 1, 'files': self.rows}) + '\n').encode()
        self.pin = job.packet.sha(self.source[prefix + 'packet.lock.json'])
        self.source['scripts/ci/log_evidence.py'] = (ROOT / 'scripts/ci/log_evidence.py').read_bytes()
        self.source['.github/workflows/native-arm-fdk.yml'] = self.text.encode()
        self.write()
        self.blobs = {hashlib.sha1(raw).hexdigest(): raw for raw in self.source.values()}
        self.env = mock.patch.dict(os.environ, {'GITHUB_WORKFLOW_SHA': COMMIT, 'RUNNER_TEMP': str(self.root)})
        self.env.start(); self.addCleanup(self.env.stop)

    def write(self):
        for name, raw in self.source.items():
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); path.chmod(0o644)

    def git(self, argv, **kwargs):
        index = argv.index('-C') + 2; args = argv[index:]
        if args == ['rev-parse', 'HEAD']: raw = (COMMIT + '\n').encode()
        elif args[:1] == ['show']: raw = self.source[args[1].split(':', 1)[1]]
        elif args[:2] == ['ls-tree', '--format=%(objectmode)']: raw = b'100644\n'
        elif args[:2] == ['ls-tree', '-z']:
            name = args[-1]; raw = ('100644 blob ' + hashlib.sha1(self.source[name]).hexdigest() + '\t' + name).encode() + b'\0'
        elif args[:2] == ['cat-file', '-s']: raw = (str(len(self.blobs[args[2]])) + '\n').encode()
        elif args[:2] == ['cat-file', 'blob']: raw = self.blobs[args[2]]
        else: raise AssertionError(args)
        return subprocess.CompletedProcess(argv, 0, raw, b'')

    def verify(self):
        with mock.patch.object(self.scope['subprocess'], 'run', side_effect=self.git):
            return self.scope['verify_consumers'](self.root, COMMIT, self.pin, {})

    def test_bootstrap_133_and_exact_loader_dependency_pair_accept_source_fixture(self):
        with mock.patch.object(self.bootstrap['subprocess'], 'run', side_effect=self.git):
            self.bootstrap['source'](self.root, COMMIT, self.pin)
        validator = self.verify(); validator.validate_workers(worker_rows(), require_complete=True)

    def test_coherently_rehashed_unbound_helper_refused_before_execution(self):
        name = job.packet.ADAPTER + 'worker_evidence.py'
        raw = b'raise AssertionError("unbound helper executed")\n'
        self.source[name] = raw
        self.rows[name].update(sha256=job.packet.sha(raw), bytes=len(raw))
        self.source[job.packet.PREFIX + 'packet.lock.json'] = (json.dumps({'schema_version': 1, 'files': self.rows}) + '\n').encode()
        self.pin = job.packet.sha(self.source[job.packet.PREFIX + 'packet.lock.json']); self.write()
        with self.assertRaises(ValueError): self.verify()

    def test_current_packet_count_wrong_mode_workflow_identity_and_missing_row_refuse(self):
        manifest = self.root / (job.packet.PREFIX + 'packet.lock.json')
        helper = self.root / (job.packet.ADAPTER + 'worker_evidence.py')
        helper.chmod(0o600)
        with self.assertRaises(ValueError): self.verify()
        helper.chmod(0o644)
        with mock.patch.dict(os.environ, {'GITHUB_WORKFLOW_SHA': 'f' * 40}), self.assertRaises(ValueError): self.verify()
        rows = dict(self.rows); rows.pop('fixture/0.txt')
        raw = (json.dumps({'schema_version': 1, 'files': rows}) + '\n').encode()
        self.source[job.packet.PREFIX + 'packet.lock.json'] = raw; manifest.write_bytes(raw); self.pin = job.packet.sha(raw)
        with self.assertRaises(ValueError): self.verify()


class WorkflowConsumerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.scope = workflow_functions((ROOT / '.github/workflows/native-arm-fdk.yml').read_text())
        self.validator = stage_validator()
        self.historical = ROOT / 'artifacts/ci/38277573107/decoded/public'

    def fixture(self, passed=True):
        public = self.root / ('pass' if passed else 'fail'); public.mkdir(mode=0o700)
        for path in self.historical.rglob('*.json'):
            dest = public / path.relative_to(self.historical); dest.parent.mkdir(mode=0o700, exist_ok=True)
            dest.write_bytes(path.read_bytes())
        status = job.packet.load(public / 'status.json')
        if passed:
            status.update(status='PASS', fdk_status='PASS', error_code=None)
            summary = job.packet.load(public / 'producer/producer-summary.json')
            summary.update(status='PASS', authoritative_job_status='PASS', native_build='PASS')
            summary.pop('recorded_native_build', None)
            job.packet.save(public / 'producer/producer-summary.json', summary)
        fdk = fdk_receipt()
        if not passed: fdk.update(status='FAIL', native_build='NOT ACCEPTED', error_code='fdk-stage-failed')
        job.packet.save(public / 'fdk/status.json', fdk); job.packet.save(public / 'status.json', status)
        producer = public / 'producer'
        manifest = job.packet.load(producer / 'export-manifest.json')
        manifest.update(status='PASS' if passed else 'FAIL', files={p.name: job.packet.sha(p.read_bytes())
                        for p in producer.iterdir() if p.name != 'export-manifest.json'})
        job.packet.save(producer / 'export-manifest.json', manifest)
        return public, status

    def validate(self, public, status):
        return self.scope['validate_public'](public, status['source_commit'], status['source_packet_sha256'], self.validator)

    def test_current_success_and_outer_failure_preserve_completed_inner_vectors(self):
        with mock.patch.dict(os.environ, {'FDK_NATIVE_OUTCOME': 'success'}):
            public, status = self.fixture(); self.assertEqual(len(self.validate(public, status)), 8)
        with mock.patch.dict(os.environ, {'FDK_NATIVE_OUTCOME': 'failure'}):
            public, status = self.fixture(False)
            raw = self.validate(public, status)
            rows = job.packet.decode(raw['fdk/status.json'])['worker_diagnostics']
            self.assertTrue(all(r['observation']['first_failed_predicate'] == 'NONE' for r in rows.values()))

    def test_current_workflow_refuses_missing_malformed_and_contradictory_worker_claims(self):
        public, status = self.fixture()
        good = job.packet.load(public / 'fdk/status.json')
        changes = (lambda r: r.update(schema_version=1), lambda r: r.pop('worker_diagnostics'),
            lambda r: r['worker_diagnostics']['build-2'].update(availability='UNAVAILABLE', observation=None),
            lambda r: r['worker_diagnostics']['compare']['exit'].update(kind='EXIT_NONZERO', code=1),
            lambda r: r['worker_diagnostics']['build-1']['observation'].update(raw='SECRET'),
            lambda r: r['worker_diagnostics']['build-2']['observation'].update(
                binding_sha256=r['worker_diagnostics']['build-1']['observation']['binding_sha256']))
        with mock.patch.dict(os.environ, {'FDK_NATIVE_OUTCOME': 'success'}):
            for change in changes:
                row = json.loads(json.dumps(good)); change(row); job.packet.save(public / 'fdk/status.json', row)
                with self.subTest(change=change), self.assertRaises(ValueError): self.validate(public, status)

    def test_finite_fallback_and_unknown_path_outcome_producer_checks_remain(self):
        public, status = self.fixture(False)
        fdk = job.packet.load(public / 'fdk/status.json')
        fdk['worker_diagnostics'] = {name: self.validator.worker_row() for name in self.validator.ACTIONS}
        job.packet.save(public / 'fdk/status.json', fdk)
        with mock.patch.dict(os.environ, {'FDK_NATIVE_OUTCOME': 'failure'}):
            self.validate(public, status)
            (public / 'unknown.json').write_text('{}')
            with self.assertRaises(ValueError): self.validate(public, status)
            (public / 'unknown.json').unlink()
            job.packet.save(public / 'producer/export-manifest.json', {'unknown': 'SECRET'})
            with self.assertRaises(ValueError): self.validate(public, status)

    def test_exact_old_failure_replays_only_with_historical_committed_consumer(self):
        old = ROOT / 'artifacts/reviews/fdk-diagnostics-consumer-20261012/fixtures/historical-workflow-6df.yml'
        raw = old.read_bytes()
        self.assertEqual(job.packet.sha(raw), '6df06b24cba7d55f26a8941b515f234a9ad4a24e11b164b8615cf3357dd9faa9')
        historical = workflow_functions(raw.decode())
        status = job.packet.load(self.historical / 'status.json')
        with mock.patch.dict(os.environ, {'FDK_NATIVE_OUTCOME': 'failure'}):
            result = historical['validate_public'](self.historical, status['source_commit'], status['source_packet_sha256'])
            self.assertEqual(len(result), 8)
            self.assertEqual(job.packet.sha(result['fdk/status.json']),
                             'df953517781c0811b604946099d9c57a4ad0af4366f34c14f7d37452e7e02404')
            with self.assertRaises(ValueError): self.validate(self.historical, status)


if __name__ == '__main__':
    unittest.main()
