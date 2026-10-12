#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Mocked producer boundaries; no GPG, Docker, recipes or compilation runs."""
import sys
sys.dont_write_bytecode = True

from contextlib import contextmanager
import hashlib
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

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fdk_job_producer_fixture', HERE / 'producer.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.config = {'snapshot': str(self.root / 'snapshot'), 'jobroot': str(self.root),
                'adapter': str(self.root / 'adapter'), 'producer_timeout': 600,
                'docker_binary': '/mock/docker', 'docker_sha256': 'a' * 64,
                'endpoint': 'unix:///run/docker.sock', 'nonce': 'b' * 32,
                'daemon': {'id': 'fixture-daemon', 'architecture': 'aarch64'}}
        self.env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
                    'HOME': str(self.root), 'DOCKER_CONFIG': str(self.root / 'docker-config')}
        self.cancelled = producer.jr.Cancelled
        self.original_execute = producer.execute

    def commands(self):
        broker, runner = mock.Mock(), mock.Mock()
        return producer.ProducerCommands(self.config, broker, runner), broker, runner

    def fake_native(self, code=0):
        native = SimpleNamespace(main=mock.Mock(return_value=code))
        broker = mock.Mock()
        broker.image = 'sha256:' + '1' * 64
        broker.cleanup.return_value = {'status': 'PASS', 'absence_verified': True, 'cancelled': False}
        runtime = SimpleNamespace(Runner=mock.Mock(), Cancelled=self.cancelled)
        cls = mock.Mock(return_value=broker)
        cls.runtime = runtime
        return native, broker, cls, runtime

    def execute(self, native, cls, state=None):
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(producer, 'broker_class', return_value=cls), \
                mock.patch.object(producer, 'module', return_value=native), \
                mock.patch.object(producer.jr, 'Runner'):
            return self.original_execute(self.config, state if state is not None else {})

    def main(self, execute, **patches):
        path = self.root / 'config.json'
        path.write_text(json.dumps(self.config))
        pin = hashlib.sha256(path.read_bytes()).hexdigest()
        with mock.patch.object(sys, 'argv', ['producer.py', '--config', str(path), '--config-sha256', pin]), \
                mock.patch.object(producer, 'execute', execute), mock.patch('sys.stderr', new=io.StringIO()):
            if patches:
                with mock.patch.multiple(producer.jr, **patches):
                    return producer.main()
            return producer.main()

    def receipt(self):
        return json.loads((self.root / 'producer-worker.json').read_bytes())


class CommandTests(Fixture):
    def gpg(self, verify=True):
        for name in ('public-key.gpg', 'payload.xz', 'payload.xz.sig'):
            (self.cache / name).write_bytes(b'fixture input; never authenticate')
        base = ['gpg', '--batch', '--no-options', '--homedir', str(self.root / 'producer/gpg'),
                '--no-auto-key-retrieve']
        return base + (['--status-fd', '1', '--verify', str(self.cache / 'payload.xz.sig'),
                        str(self.cache / 'payload.xz')] if verify else
                       ['--import', str(self.cache / 'public-key.gpg')])

    def test_gpg_actual_no_autostart_preserves_separate_status_and_diagnostics(self):
        commands, broker, runner = self.commands()
        raw = self.gpg()
        runner.run.return_value = subprocess.CompletedProcess(raw, 0, b'[GNUPG:] FIXTURE\n', b'diagnostic\n')
        result = commands.run(raw, text=True, capture_output=True, timeout=17)
        self.assertEqual(result.stdout, '[GNUPG:] FIXTURE\n')
        self.assertEqual(result.stderr, 'diagnostic\n')
        argv = runner.run.call_args.args[0]
        self.assertEqual(argv, ['/usr/bin/gpg', '--no-autostart', *raw[1:]])
        self.assertTrue(runner.run.call_args.kwargs['separate_stderr'])
        self.assertEqual(runner.run.call_args.kwargs['timeout'], 17)
        self.assertEqual(json.loads((self.root / 'producer-commands.json').read_bytes())['commands'], [argv])
        self.assertEqual(broker.method_calls, [])

    def test_gpg_import_combines_only_bound_log_streams_and_retains_exit(self):
        commands, _, runner = self.commands()
        raw = self.gpg(False)
        runner.run.return_value = subprocess.CompletedProcess(raw, 7, b'stdout\n', b'stderr\n')
        target = io.StringIO()
        result = commands.run(raw, stdout=target, stderr=subprocess.STDOUT, timeout=60)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(target.getvalue(), 'stdout\nstderr\n')
        self.assertTrue(runner.run.call_args.kwargs['separate_stderr'])

    def test_gpg_unapproved_commands_paths_and_symlinks_never_run(self):
        commands, _, runner = self.commands()
        original = self.gpg()
        outside = self.root / 'outside.xz'
        outside.write_bytes(b'fixture')
        alias = self.cache / 'alias.xz'
        alias.symlink_to(self.cache / 'payload.xz')
        for change in ('option', 'outside', 'symlink'):
            argv = original.copy()
            if change == 'option':
                argv[argv.index('--verify')] = '--decrypt'
            else:
                argv[-1] = str(outside if change == 'outside' else alias)
            with self.subTest(change=change), self.assertRaises(ValueError):
                commands.run(argv, text=True, capture_output=True)
        runner.run.assert_not_called()

    def test_inline_builder_patches_only_its_module_and_restores_argv(self):
        commands, broker, _ = self.commands()
        builder = SimpleNamespace(subprocess=subprocess)
        original_run = subprocess.run
        inspector = SimpleNamespace(subprocess=subprocess)
        def main():
            self.assertIsInstance(builder.subprocess, producer.BuilderCommands)
            self.assertIs(builder.subprocess.broker, broker)
            self.assertIs(inspector.subprocess, subprocess)
            self.assertIs(subprocess.run, original_run)
            print('fixture builder output')
            return 0
        builder.main = main
        command = [sys.executable, str(Path(self.config['snapshot']) / 'scripts/build/build.py'),
                   '--output', str(self.root / 'attempt')]
        old = sys.argv
        target = io.StringIO()
        with mock.patch.object(producer, 'module', return_value=builder):
            result = commands.run(command, stdout=target, stderr=subprocess.STDOUT)
        self.assertIs(sys.argv, old)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(target.getvalue(), 'fixture builder output\n')
        self.assertEqual(broker.expected_mounts['/out'], str(self.root / 'attempt/artifacts'))
        self.assertIs(subprocess.run, original_run)

    def test_inline_comparator_error_restores_argv_and_is_not_a_tool_escape(self):
        commands, broker, runner = self.commands()
        comparator = SimpleNamespace(main=mock.Mock(side_effect=ValueError('fixture compare failure')))
        command = [sys.executable, str(Path(self.config['snapshot']) / 'scripts/build/compare.py')]
        old = sys.argv
        with mock.patch.object(producer, 'module', side_effect=[SimpleNamespace(subprocess=subprocess), comparator]):
            with self.assertRaises(ValueError):
                commands.run(command, stdout=io.StringIO(), stderr=subprocess.STDOUT)
        self.assertIs(sys.argv, old)
        runner.run.assert_not_called()
        broker.command.assert_not_called()

    def test_bounded_inline_output_counts_utf8_bytes(self):
        target = io.StringIO()
        with mock.patch.object(producer.jr, 'MAX_OUTPUT', 4):
            stream = producer.BoundedText(target)
            stream.write('éé')
            with self.assertRaises(ValueError):
                stream.write('x')
        self.assertEqual(target.getvalue(), 'éé')


class ReceiptTests(Fixture):
    def test_clean_tool_env_and_fixed_legacy_cli_env_wiring(self):
        native, broker, cls, runtime = self.fake_native()
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(producer, 'broker_class', return_value=cls), \
                mock.patch.object(producer, 'module', return_value=native), \
                mock.patch.object(producer.jr, 'Runner') as tools:
            self.assertEqual(producer.execute(self.config, {}), 0)
        self.assertEqual(tools.call_args.args[1], self.env)
        self.assertEqual(runtime.Runner.call_args_list[0].args[1], {**self.env, 'DOCKER_BUILDKIT': '0'})
        self.assertEqual(runtime.Runner.call_args_list[1].args[1], self.env)
        self.assertEqual(runtime.Runner.call_args_list[1].args[0], 180)
        self.assertIsInstance(native.subprocess, producer.ProducerCommands)
        self.assertEqual(native.main.call_args.args[0][0], 'build')
        broker.initialize.assert_called_once_with(expected_daemon=self.config['daemon'])
        self.assertEqual(self.receipt()['status'], 'PASS')
        self.assertEqual(self.receipt()['hardware'], 'NOT RUN')

    def test_helper_return_one_or_cleanup_failure_records_fail(self):
        for kind in ('helper', 'cleanup'):
            native, broker, cls, _ = self.fake_native(1 if kind == 'helper' else 0)
            if kind == 'cleanup':
                broker.cleanup.return_value = {'status': 'FAIL', 'absence_verified': False}
            with self.subTest(kind=kind):
                if kind == 'helper':
                    with self.assertRaises(ValueError):
                        self.execute(native, cls)
                else:
                    self.assertEqual(self.execute(native, cls), 1)
                self.assertEqual(self.receipt()['status'], 'FAIL')
                broker.cleanup.assert_called_once_with(remove_image=False)

    def test_helper_cancellation_retains_fail_and_owned_cleanup(self):
        native, broker, cls, _ = self.fake_native()
        native.main.side_effect = self.cancelled(signal.SIGTERM)
        with self.assertRaises(self.cancelled):
            self.execute(native, cls)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.receipt()['cancelled'])
        broker.cleanup.assert_called_once_with(remove_image=False)

    def test_actual_sigterm_during_candidate_pass_write_main_rewrites_fail(self):
        native, _, cls, _ = self.fake_native()
        original = producer.save
        fired = False
        def save(path, value):
            nonlocal fired
            original(path, value)
            if path.name == 'producer-worker.json' and value['status'] == 'PASS' and not fired:
                fired = True
                os.kill(os.getpid(), signal.SIGTERM)
        def execute(config, state):
            return self.execute(native, cls, state)
        with mock.patch.object(producer, 'save', save):
            self.assertEqual(self.main(execute), 1)
        self.assertTrue(fired)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.receipt()['cancelled'])

    def test_candidate_receipt_write_failure_main_persists_fail(self):
        native, _, cls, _ = self.fake_native()
        original = producer.save
        def save(path, value):
            if path.name == 'producer-worker.json' and value['status'] == 'PASS':
                raise OSError('fixture candidate receipt write failure')
            original(path, value)
        def execute(config, state):
            return self.execute(native, cls, state)
        with mock.patch.object(producer, 'save', save):
            self.assertEqual(self.main(execute), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertFalse(self.receipt()['cancelled'])

    def publish_then_cancel(self, config, state):
        receipt = {'status': 'PASS', 'cancelled': False, 'hardware': 'NOT RUN'}
        state.update(path=self.root / 'producer-worker.json', receipt=receipt)
        producer.save(state['path'], receipt)
        raise self.cancelled(signal.SIGTERM)

    def test_late_cancellation_rewrites_stale_pass(self):
        self.assertEqual(self.main(self.publish_then_cancel), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.receipt()['cancelled'])

    def test_failed_late_rewrite_removes_candidate_pass(self):
        original = producer.save
        def save(path, value):
            if value['status'] == 'FAIL':
                raise OSError('fixture receipt write failure')
            original(path, value)
        with mock.patch.object(producer, 'save', save):
            self.assertEqual(self.main(self.publish_then_cancel), 1)
        self.assertFalse((self.root / 'producer-worker.json').exists())

    def test_handler_restore_cancellation_rewrites_pass(self):
        def execute(config, state):
            receipt = {'status': 'PASS', 'cancelled': False}
            state.update(path=self.root / 'producer-worker.json', receipt=receipt)
            producer.save(state['path'], receipt)
            return 0
        @contextmanager
        def cancel_after():
            yield
            raise self.cancelled(signal.SIGTERM)
        self.assertEqual(self.main(execute, cancellation_handlers=cancel_after), 1)
        self.assertEqual(self.receipt()['status'], 'FAIL')
        self.assertTrue(self.receipt()['cancelled'])


if __name__ == '__main__':
    unittest.main()
