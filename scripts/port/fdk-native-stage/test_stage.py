#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Temporary-fixture stage regressions; no Git, Docker or native build runs."""
import sys
sys.dont_write_bytecode = True

from contextlib import contextmanager, nullcontext
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from test_worker import passing_workers, config_fixture

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fdk_stage_fixture', HERE / 'stage.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def passing_report():
    clean = {'status': 'PASS', 'absence_verified': True}
    return {'status': 'PASS', 'phase': 'complete', 'cancelled': False,
            'worker_diagnostics': passing_workers(),
            'cleanup': clean, 'comparison': {'status': 'PASS'},
            **{key: {'status': 'PASS'} for key in ('accepted_base', 'live_base', 'source')},
            **{key: {'status': 'PASS', 'cleanup': clean.copy()} for key in ('build-1', 'build-2')}}


class WorkerReceiverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.config = config_fixture(self.root)
        self.report = {'worker_diagnostics': {name: stage.worker_diagnostic.worker_row()
            for name in stage.worker_diagnostic.ACTIONS}}

    def runner(self, code=1, malformed=False, late=False):
        def run(command, **kwargs):
            path = Path(command[command.index('--config') + 1])
            config = stage.load(path); pin = command[command.index('--config-sha256') + 1]
            row = stage.worker_diagnostic.initial(config, pin)
            stage.worker_diagnostic.failure(row, 'IO', 'BROKER_INITIALIZE')
            if malformed: row['binding']['source_commit'] = 'f' * 40
            receipt = {'status': 'FAIL', 'action': 'build-1', 'cancelled': False, 'hardware': 'NOT RUN', 'diagnostics': row}
            stage.save(self.root / 'build-1-receipt.json', receipt)
            return SimpleNamespace(returncode=code)
        return SimpleNamespace(run=run)

    def test_nonzero_actual_worker_return_retains_finite_failed_receipt(self):
        for code in (1, 125, -15):
            with self.subTest(code=code):
                with self.assertRaisesRegex(ValueError, 'worker-failed'):
                    stage.worker(self.runner(code), self.config, 'build-1', self.report)
                row = self.report['worker_diagnostics']['build-1']
                self.assertEqual(row['exit'], stage.worker_diagnostic.exit_record(code))
                self.assertEqual(row['availability'], 'VERIFIED')
                self.assertEqual(row['observation']['first_failed_predicate'], 'BROKER_INITIALIZE')

    def test_zero_return_with_failed_or_wrong_binding_receipt_cannot_accept(self):
        for malformed, reason in ((False, 'worker-receipt-failed'), (True, 'worker-receipt-unverified')):
            with self.subTest(malformed=malformed), self.assertRaisesRegex(ValueError, reason):
                stage.worker(self.runner(0, malformed), self.config, 'build-1', self.report)
            row = self.report['worker_diagnostics']['build-1']
            self.assertEqual(row['exit'], stage.worker_diagnostic.exit_record(0))
            if malformed: self.assertEqual((row['availability'], row['observation']), ('UNVERIFIED', None))

    def test_missing_receipt_and_cancelled_command_are_not_inferred_returns(self):
        runner = SimpleNamespace(run=lambda *a, **k: SimpleNamespace(returncode=1))
        with self.assertRaisesRegex(ValueError, 'worker-failed'):
            stage.worker(runner, self.config, 'build-1', self.report)
        row = self.report['worker_diagnostics']['build-1']
        self.assertEqual(row['availability'], 'UNAVAILABLE')
        def run(*args, **kwargs): raise stage.Cancelled(15)
        with self.assertRaises(stage.Cancelled):
            stage.worker(SimpleNamespace(run=run), self.config, 'build-1', self.report)
        self.assertEqual(self.report['worker_diagnostics']['build-1']['exit'], stage.worker_diagnostic.no_exit('UNOBSERVED'))

    def test_late_file_poison_does_not_change_already_validated_projection(self):
        original = stage.worker_diagnostic.receive
        def receive(*args):
            result = original(*args)
            stage.save(self.root / 'build-1-receipt.json', {'raw': 'SECRET private poison'})
            return result
        with mock.patch.object(stage.worker_diagnostic, 'receive', side_effect=receive), self.assertRaises(ValueError):
            stage.worker(self.runner(), self.config, 'build-1', self.report)
        row = self.report['worker_diagnostics']['build-1']
        self.assertEqual(row['availability'], 'VERIFIED')
        self.assertEqual(row['observation']['first_failed_predicate'], 'BROKER_INITIALIZE')
        self.assertNotIn('SECRET', json.dumps(row))


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'output'
        self.output.mkdir()
        for name in ('private', 'public'):
            (self.output / name).mkdir()

    def records(self):
        return [json.loads((self.output / name).read_bytes())
                for name in ('private/result.json', 'public/status.json')]

    def argv(self):
        paths = ('source-root', 'lock', 'accepted-result', 'bootstrap', 'packages', 'inputs')
        pins = ('source-commit', 'lock-sha256', 'accepted-result-sha256', 'bootstrap-sha256',
                'image', 'docker-endpoint', 'docker-binary', 'docker-sha256')
        return ['stage.py', '--output', str(self.output),
                *[part for name in paths for part in ('--' + name, '/unused/' + name)],
                *[part for name in pins for part in ('--' + name, 'synthetic')]]

    def main(self, execute, **patches):
        with mock.patch.object(stage, 'execute', execute), mock.patch.object(sys, 'argv', self.argv()), \
                mock.patch('sys.stderr', new=io.StringIO()):
            with mock.patch.multiple(stage, **patches) if patches else nullcontext():
                return stage.main()

    def publish(self, args, state):
        report = passing_report()
        state.update(output=self.output, report=report)
        stage.finish(self.output, report)
        return 0

    def test_complete_receipt_has_explicit_unrun_lifecycle_gates(self):
        stage.finish(self.output, passing_report())
        private, public = self.records()
        self.assertEqual(private['status'], public['status'])
        self.assertEqual(public['status'], 'PASS')
        for key in ('hardware', 'installation', 'binary_publication'):
            self.assertEqual(public[key], 'NOT RUN')
        self.assertFalse(public['selected_for_release'])

    def test_missing_prerequisite_or_cleanup_cannot_publish_pass(self):
        for key in ('accepted_base', 'live_base', 'source', 'build-1', 'build-2', 'comparison'):
            report = passing_report()
            del report[key]
            with self.subTest(missing=key):
                stage.finish(self.output, report)
                self.assertEqual(self.records()[1]['status'], 'FAIL')
        for key in ('status', 'absence_verified'):
            report = passing_report()
            report['build-2']['cleanup'][key] = 'FAIL' if key == 'status' else False
            with self.subTest(cleanup=key):
                self.assertEqual(stage.finalstatus_public(report)['status'], 'FAIL')

    def test_actual_sigterm_during_each_final_write_invalidates_both_receipts(self):
        original = stage.save
        for target in ('result.json', 'status.json'):
            fired = False
            def save(path, value):
                nonlocal fired
                original(path, value)
                if path.name == target and not fired:
                    fired = True
                    os.kill(os.getpid(), signal.SIGTERM)
            with self.subTest(target=target), mock.patch.object(stage, 'save', save):
                with stage.cancellation_handlers(), self.assertRaises(stage.Cancelled):
                    stage.finish(self.output, passing_report())
                self.assertTrue(fired)
                for record in self.records():
                    self.assertEqual(record['status'], 'FAIL')
                    self.assertTrue(record['cancelled'])

    def test_late_execute_cancellation_rewrites_published_pass(self):
        def execute(args, state):
            self.publish(args, state)
            raise stage.Cancelled(signal.SIGTERM)
        self.assertEqual(self.main(execute), 1)
        for record in self.records():
            self.assertEqual(record['status'], 'FAIL')
            self.assertTrue(record['cancelled'])

    def test_handler_restoration_cancellation_rewrites_published_pass(self):
        @contextmanager
        def restoration_cancel():
            yield
            raise stage.Cancelled(signal.SIGTERM)
        self.assertEqual(self.main(self.publish, cancellation_handlers=restoration_cancel), 1)
        for record in self.records():
            self.assertEqual(record['status'], 'FAIL')
            self.assertTrue(record['cancelled'])

    def test_final_deferred_context_exit_cancellation_is_invalidated_by_main(self):
        original = stage.defer_signals
        fired = False
        @contextmanager
        def late_cancel():
            nonlocal fired
            with original() as events:
                yield events
            if not fired:
                fired = True
                raise stage.Cancelled(signal.SIGTERM)
        self.assertEqual(self.main(self.publish, defer_signals=late_cancel), 1)
        self.assertTrue(fired)
        for record in self.records():
            self.assertEqual(record['status'], 'FAIL')
            self.assertTrue(record['cancelled'])

    def test_failed_rewrite_removes_both_stale_pass_receipts(self):
        original = stage.finish
        def execute(args, state):
            self.publish(args, state)
            raise stage.Cancelled(signal.SIGTERM)
        def finish(output, report):
            if report['status'] == 'FAIL':
                raise OSError('synthetic write failure')
            original(output, report)
        self.assertEqual(self.main(execute, finish=finish), 1)
        self.assertFalse((self.output / 'public/status.json').exists())
        self.assertFalse((self.output / 'private/result.json').exists())

    def test_cancellation_before_owned_output_has_no_receipt_side_effect(self):
        def execute(args, state):
            raise stage.Cancelled(signal.SIGTERM)
        self.assertEqual(self.main(execute), 1)
        self.assertEqual(list((self.output / 'private').iterdir()), [])
        self.assertEqual(list((self.output / 'public').iterdir()), [])

    def test_preflight_failure_records_fail_without_creating_a_native_runner(self):
        output = Path(self.temp.name) / 'preflight-output'
        root = Path(self.temp.name) / 'repo'
        root.mkdir()
        args = SimpleNamespace(source_root=root, output=output)
        with mock.patch.object(stage, 'ordinary', side_effect=ValueError('synthetic preflight')), \
                mock.patch.object(stage, 'Runner') as runner, mock.patch.object(stage, 'Broker') as broker:
            self.assertEqual(stage.execute(args), 1)
            runner.assert_not_called()
            broker.assert_not_called()
        for name in ('private/result.json', 'public/status.json'):
            self.assertEqual(json.loads((output / name).read_bytes())['status'], 'FAIL')


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.output = self.base / 'repo', self.base / 'output'
        self.root.mkdir()
        self.output.mkdir()
        self.here = self.root / stage.PREFIX
        self.here.mkdir(parents=True)
        self.template = {'PKGBUILD': stage.sha(b'fixture recipe\n')}
        contents = {stage.TEMPLATE + 'PKGBUILD': b'fixture recipe\n',
                    **{name: b'fixture helper\n' for name in stage.HELPERS},
                    stage.PREFIX + 'stage.py': b'fixture stage\n',
                    stage.PREFIX + 'template-inputs.json': (json.dumps(self.template) + '\n').encode(),
                    stage.PREFIX + 'reviewed-inputs.json': b'{"fixture": "synthetic"}\n'}
        self.lock = {'schema_version': 1, 'files': {}}
        for name, data in contents.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            mode = 0o755 if name.endswith('.sh') else 0o644
            path.chmod(mode)
            self.lock['files'][name] = {'sha256': stage.sha(data), 'mode': mode}
        self.contents = contents
        self.commands = []
        self.commit = 'a' * 40
        self.patch = mock.patch.multiple(stage, HERE=self.here,
                TEMPLATE_SHA=stage.sha(contents[stage.PREFIX + 'template-inputs.json']),
                RECIPE_SHA=stage.sha(contents[stage.PREFIX + 'reviewed-inputs.json']))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def run_git(self, argv, **kwargs):
        self.commands.append(argv)
        if 'show' in argv:
            name = argv[-1].removeprefix(self.commit + ':')
            return subprocess.CompletedProcess(argv, 0, self.contents[name])
        self.assertIn('ls-tree', argv)
        name = argv[-1]
        return subprocess.CompletedProcess(argv, 0,
                ('100' + oct(self.lock['files'][name]['mode'])[2:] + '\n').encode())

    def snapshot(self, callback=None):
        runner = mock.Mock()
        runner.run.side_effect = callback or self.run_git
        return stage.snapshot(self.root, self.output, self.lock, runner, self.commit)

    def test_exact_snapshot_preserves_bytes_modes_and_binds_every_git_blob(self):
        target = self.snapshot()
        for name, row in self.lock['files'].items():
            self.assertEqual((target / name).read_bytes(), self.contents[name])
            self.assertEqual((target / name).stat().st_mode & 0o777, row['mode'])
        self.assertEqual(len(self.commands), 2 * len(self.contents))
        self.assertTrue(all('/usr/bin/git' == argv[0] for argv in self.commands))

    def test_worktree_byte_or_mode_drift_fails_before_copy(self):
        name = stage.PREFIX + 'stage.py'
        for change in ('bytes', 'mode'):
            with self.subTest(change=change):
                path = self.root / name
                path.write_bytes(self.contents[name] if change == 'mode' else b'changed\n')
                path.chmod(0o755 if change == 'mode' else 0o644)
                output = self.base / change
                output.mkdir()
                with self.assertRaises(ValueError):
                    stage.snapshot(self.root, output, self.lock, mock.Mock(), self.commit)

    def test_commit_blob_or_executable_mode_mismatch_fails(self):
        for operation in ('show', 'ls-tree'):
            def drift(argv, **kwargs):
                result = self.run_git(argv, **kwargs)
                if operation in argv:
                    result.stdout = b'wrong\n'
                return result
            output = self.base / operation
            output.mkdir()
            runner = mock.Mock()
            runner.run.side_effect = drift
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                stage.snapshot(self.root, output, self.lock, runner, self.commit)

    def test_missing_extra_or_traversal_locked_input_is_rejected(self):
        original = copy.deepcopy(self.lock)
        for change in ('missing', 'extra', 'traversal'):
            self.lock = copy.deepcopy(original)
            if change == 'missing':
                self.lock['files'].pop(stage.PREFIX + 'stage.py')
            else:
                self.lock['files']['../escape' if change == 'traversal' else 'unexpected.py'] = {
                        'mode': 0o644, 'sha256': '0' * 64}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.snapshot()

    def test_source_symlink_or_mid_copy_drift_is_rejected(self):
        name = stage.PREFIX + 'stage.py'
        path = self.root / name
        path.unlink()
        path.symlink_to(self.root / 'scripts/build/build.py')
        with self.assertRaises(ValueError):
            self.snapshot()
        path.unlink()
        path.write_bytes(self.contents[name])
        path.chmod(0o644)
        output = self.base / 'race'
        output.mkdir()
        def drift(argv, **kwargs):
            result = self.run_git(argv, **kwargs)
            if 'ls-tree' in argv and argv[-1] == name:
                path.write_bytes(b'mid-copy drift\n')
            return result
        runner = mock.Mock()
        runner.run.side_effect = drift
        with self.assertRaisesRegex(ValueError, 'snapshot-race'):
            stage.snapshot(self.root, output, self.lock, runner, self.commit)


if __name__ == '__main__':
    unittest.main()
