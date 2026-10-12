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
                       'cleanup': {'status': 'PASS', 'absence_verified': True}}
            if self.mode == 'producer-receipt-fail':
                receipt['status'] = 'FAIL'
            if self.mode == 'producer-cancel-receipt':
                receipt['cancelled'] = True
            if self.mode == 'producer-absence-fail':
                receipt['cleanup']['absence_verified'] = False
            job.packet.save(self.private / 'producer-worker.json', receipt)
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
