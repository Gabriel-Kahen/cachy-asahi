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
        native = SimpleNamespace(main=mock.Mock(return_value=code), acquire=mock.Mock(), build=mock.Mock())
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
        self.assertEqual(commands.diagnostic, {'phase': 'gpg-import', 'outcome': 'command-failed'})

    def test_import_preserves_non_utf8_bytes_in_original_text_log_fd(self):
        commands, _, runner = self.commands()
        raw = self.gpg(False)
        data = b'non-UTF8 fixture diagnostic: \xff\xfe\n'
        runner.run.return_value = subprocess.CompletedProcess(raw, 0, b'stdout\n', data)
        path = self.root / 'import.log'
        with path.open('w') as stream:
            commands.run(raw, stdout=stream, stderr=subprocess.STDOUT)
        self.assertEqual(path.read_bytes(), b'stdout\n' + data)
        self.assertEqual(commands.diagnostic, {'phase': 'gpg-import', 'outcome': 'pass'})

    def test_fixture_text_stream_uses_backslash_escape_for_invalid_bytes(self):
        commands, _, runner = self.commands()
        raw = self.gpg(False)
        runner.run.return_value = subprocess.CompletedProcess(raw, 0, b'', b'\xff\n')
        target = io.StringIO()
        commands.run(raw, stdout=target, stderr=subprocess.STDOUT)
        self.assertEqual(target.getvalue(), '\\xff\n')

    def test_gpg_diagnostic_before_runner_has_only_fixed_keys_and_copied_values(self):
        commands, _, runner = self.commands()
        seen = []
        def record(value):
            seen.append(dict(value))
            value['phase'] = 'PRIVATE-SECRET'
        commands.on_diagnostic = record
        raw = self.gpg()
        def run(*args, **kwargs):
            self.assertEqual(seen[-1], {'phase': 'gpg-verify', 'outcome': 'started'})
            self.assertEqual(commands.diagnostic, seen[-1])
            return subprocess.CompletedProcess(raw, 0, b'[GNUPG:] FIXTURE\n', b'private fixture diagnostic\n')
        runner.run.side_effect = run
        commands.run(raw, text=True, capture_output=True)
        self.assertEqual(seen[-1], {'phase': 'gpg-verify', 'outcome': 'pass'})
        self.assertNotIn('private', json.dumps(seen))
        for phase, outcome in (('PRIVATE-SECRET', 'pass'), ('preflight', 'raw exception'), ([], 'pass')):
            with self.assertRaises(ValueError):
                commands.set_diagnostic(phase, outcome)

    def test_gpg_policy_runner_cancel_and_decode_failures_have_distinct_fixed_outcomes(self):
        for kind, outcome in (('policy', 'delegate-refused'), ('streams', 'delegate-refused'),
                              ('runner', 'runner-failed'), ('cancel', 'cancelled'), ('decode', 'delegate-refused')):
            commands, _, runner = self.commands()
            raw = self.gpg()
            runner.run.return_value = subprocess.CompletedProcess(raw, 1, b'\xff', b'private diagnostic')
            if kind == 'policy': raw[raw.index('--verify')] = '--decrypt'
            if kind == 'runner': runner.run.side_effect = ValueError('PRIVATE-SECRET')
            if kind == 'cancel': runner.run.side_effect = self.cancelled(signal.SIGTERM)
            with self.subTest(kind=kind), self.assertRaises((ValueError, self.cancelled, UnicodeError)):
                commands.run(raw, text=kind != 'streams', capture_output=True)
            self.assertEqual(commands.diagnostic, {'phase': 'gpg-verify', 'outcome': outcome})
            if kind in ('policy', 'streams'): runner.run.assert_not_called()
            self.assertNotIn('PRIVATE', json.dumps(commands.diagnostic))

    def test_proxy_records_host_base_and_bootstrap_phases(self):
        commands, broker, runner = self.commands()
        runner.run.return_value = subprocess.CompletedProcess([], 0, b'fixture CPU\n')
        self.assertEqual(commands.check_output(['lscpu'], text=True), 'fixture CPU')
        self.assertEqual(commands.diagnostic, {'phase': 'host-probe', 'outcome': 'pass'})
        broker.capture.return_value = 'fixture daemon'
        commands.check_output(['docker', 'info', '--format', '{{.Architecture}}'], text=True)
        self.assertEqual(commands.diagnostic, {'phase': 'base-probe', 'outcome': 'pass',
                                              'call': 'docker-info', 'refusal_code': 'none'})
        broker.command.return_value = subprocess.CompletedProcess([], 1, b'private fixture output')
        commands.run(['docker', 'build'], stdout=io.StringIO(), stderr=subprocess.STDOUT)
        self.assertEqual(commands.diagnostic, {'phase': 'bootstrap', 'outcome': 'command-failed'})

    def test_exact_base_probe_substeps_persist_before_call_with_no_arguments(self):
        commands, broker, _ = self.commands()
        image = 'sha256:' + '1' * 64
        broker.image = image
        path = self.root / 'private-diagnostic.json'
        commands.on_diagnostic = lambda value: path.write_text(json.dumps(value))
        lock = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat',
                image, '/builder-packages.lock']
        cases = [(['docker', 'info', '--format', '{{.Architecture}}'], 'docker-info'),
                 (['docker', 'version'], 'docker-version'), (['docker', 'context', 'inspect'], 'docker-context'),
                 (['docker', 'image', 'inspect', image], 'image-inspect'), (lock, 'inventory-probe')]
        for argv, call in cases:
            def capture(*args, **kwargs):
                self.assertEqual(json.loads(path.read_bytes()), {'phase': 'base-probe', 'outcome': 'started',
                                 'call': call, 'refusal_code': 'none'})
                return subprocess.CompletedProcess(argv, 0, b'alpha 1\n') if call == 'inventory-probe' else 'fixture'
            broker.capture.side_effect = broker.command.side_effect = capture
            with self.subTest(call=call):
                commands.check_output(argv, text=True)
                value = json.loads(path.read_bytes())
                self.assertEqual(value, {'phase': 'base-probe', 'outcome': 'pass',
                                        'call': call, 'refusal_code': 'none'})
                self.assertNotIn(image, json.dumps(value))
                self.assertNotIn(str(self.root), json.dumps(value))
        for argv in (['docker', 'image', 'inspect', 'PRIVATE-IMAGE'], lock + ['PRIVATE-ARG'],
                     ['docker', 'info', '--format', 'PRIVATE-FORMAT'], ['PRIVATE-TOOL']):
            self.assertEqual(commands.base_probe_call(argv), 'unclassified')

    def test_every_reviewed_base_probe_predicate_is_retained_without_exception_stringification(self):
        class PrivateError(ValueError):
            def __str__(self):
                raise AssertionError('raw exception must never be stringified')
        self.assertEqual(len(producer.BASE_PROBE_POLICY_CODES), 108)
        for code in sorted(producer.BASE_PROBE_POLICY_CODES):
            commands, broker, _ = self.commands()
            broker.image = 'sha256:' + '1' * 64
            broker.capture.side_effect = PrivateError(code, 'PRIVATE-SECRET detail')
            with self.subTest(code=code), self.assertRaises(PrivateError):
                commands.check_output(['docker', 'image', 'inspect', broker.image], text=True)
            self.assertEqual(commands.diagnostic, {'phase': 'base-probe', 'outcome': 'runner-failed',
                                                  'call': 'image-inspect', 'refusal_code': code})
            self.assertNotIn('PRIVATE', json.dumps(commands.diagnostic))

    def test_base_probe_unknown_private_args_and_closed_exception_types_are_sanitized(self):
        errors = [(ValueError('docker-image-drift PRIVATE-SECRET'), 'value-error'),
                  (ValueError('docker-image-drift\n'), 'value-error'),
                  (ValueError(), 'value-error'), (ValueError(Path('/PRIVATE-SECRET')), 'value-error'),
                  (UnicodeError('docker-image-drift'), 'unicode-error'),
                  (OSError('PRIVATE-SECRET'), 'os-error'), (KeyError('docker-image-drift'), 'key-error'),
                  (TypeError('PRIVATE-SECRET'), 'type-error'),
                  (subprocess.SubprocessError('PRIVATE-SECRET'), 'subprocess-error'),
                  (RuntimeError('PRIVATE-SECRET'), 'unknown-error'),
                  (self.cancelled(signal.SIGTERM), 'cancelled')]
        for error, refusal in errors:
            commands, broker, _ = self.commands()
            broker.capture.side_effect = error
            with self.subTest(refusal=refusal, kind=type(error).__name__), self.assertRaises(type(error)):
                commands.check_output(['docker', 'version'], text=True)
            self.assertEqual(commands.diagnostic, {'phase': 'base-probe',
                'outcome': 'cancelled' if refusal == 'cancelled' else 'runner-failed',
                'call': 'docker-version', 'refusal_code': refusal})
            self.assertNotIn('PRIVATE', json.dumps(commands.diagnostic))
        class FalseError(ValueError):
            def __bool__(self): return False
        self.assertEqual(producer.ProducerCommands.refusal(FalseError('docker-image-drift')), 'docker-image-drift')

    def test_base_probe_delegate_refusal_is_unclassified_and_invalid_fields_do_not_change_state(self):
        commands, broker, runner = self.commands()
        with self.assertRaises(ValueError):
            commands.check_output(['PRIVATE-SECRET'], text=True)
        self.assertEqual(commands.diagnostic, {'phase': 'base-probe', 'outcome': 'delegate-refused',
                                              'call': 'unclassified', 'refusal_code': 'value-error'})
        broker.capture.assert_not_called(); runner.run.assert_not_called()
        baseline = dict(commands.diagnostic)
        for call, refusal, outcome in (('PRIVATE-SECRET', 'none', 'started'),
                                       ('image-inspect', 'PRIVATE-SECRET', 'runner-failed'),
                                       ('image-inspect', 'docker-image-drift', 'pass')):
            with self.assertRaises(ValueError):
                commands.set_diagnostic('base-probe', outcome, call=call, refusal_code=refusal)
            self.assertEqual(commands.diagnostic, baseline)
        commands.set_diagnostic('gpg-import', 'pass')
        self.assertEqual(commands.diagnostic, {'phase': 'gpg-import', 'outcome': 'pass'})

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
        self.assertEqual(commands.diagnostic, {'phase': 'original-build', 'outcome': 'pass'})
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
        self.assertEqual(commands.diagnostic, {'phase': 'original-compare', 'outcome': 'delegate-refused'})
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
    def test_private_receipt_records_acquisition_before_unchanged_function_and_preserves_failure(self):
        for failed in (False, True):
            native, broker, cls, _ = self.fake_native()
            def acquired(*args, **kwargs):
                self.assertEqual(self.receipt()['diagnostic'], {'phase': 'acquisition', 'outcome': 'started'})
                if failed:
                    raise ValueError('PRIVATE-SECRET acquisition detail')
                return 'fixture acquisition result'
            native.acquire.side_effect = acquired
            def main(argv):
                self.assertEqual(self.receipt()['diagnostic'], {'phase': 'preflight', 'outcome': 'pass'})
                self.assertEqual(native.acquire('fixture argument'), 'fixture acquisition result')
                return 1
            native.main.side_effect = main
            with self.subTest(failed=failed), self.assertRaises(ValueError):
                self.execute(native, cls)
            self.assertEqual(self.receipt()['status'], 'FAIL')
            self.assertEqual(self.receipt()['diagnostic'], {'phase': 'acquisition',
                             'outcome': 'command-failed' if failed else 'pass'})
            self.assertNotIn('PRIVATE', json.dumps(self.receipt()))
            broker.cleanup.assert_called_once_with(remove_image=False)

    def test_native_build_wrapper_delegates_original_arguments_after_private_started_write(self):
        native, _, cls, _ = self.fake_native()
        def build(*args, **kwargs):
            self.assertEqual(self.receipt()['diagnostic'], {'phase': 'bootstrap', 'outcome': 'started'})
            self.assertEqual((args, kwargs), (('fixture',), {'mode': 'unchanged'}))
            return 'fixture image'
        native.build.side_effect = build
        native.main.side_effect = lambda argv: int(native.build('fixture', mode='unchanged') != 'fixture image')
        self.assertEqual(self.execute(native, cls), 0)
        # No proxy command occurred in this mocked build: do not invent its completion.
        self.assertEqual(self.receipt()['diagnostic'], {'phase': 'bootstrap', 'outcome': 'started'})

    def test_main_retains_last_known_pass_after_upstream_returns_failure(self):
        native, _, cls, _ = self.fake_native()
        def main(argv):
            native.acquire()
            return 1
        native.main.side_effect = main
        def execute(config, state):
            return self.execute(native, cls, state)
        self.assertEqual(self.main(execute), 1)
        self.assertEqual(self.receipt()['diagnostic'], {'phase': 'acquisition', 'outcome': 'pass'})
        self.assertEqual(self.receipt()['status'], 'FAIL')

    def test_private_gpg_started_is_durable_before_runner_and_nonzero_exit_retained(self):
        native, _, cls, _ = self.fake_native()
        key = self.cache / 'archlinuxarm.gpg'
        key.write_bytes(b'fixture public-key bytes; never imported')
        def main(argv):
            commands = native.subprocess
            raw = ['gpg', '--batch', '--no-options', '--homedir', str(self.root / 'producer/gpg'),
                   '--no-auto-key-retrieve', '--import', str(key)]
            def run(*args, **kwargs):
                self.assertEqual(self.receipt()['status'], 'FAIL')
                self.assertEqual(self.receipt()['diagnostic'], {'phase': 'gpg-import', 'outcome': 'started'})
                return subprocess.CompletedProcess(raw, 2, b'', b'PRIVATE-SECRET GPG detail')
            commands.runner.run.side_effect = run
            result = commands.run(raw, stdout=io.StringIO(), stderr=subprocess.STDOUT)
            return int(result.returncode != 0)
        native.main.side_effect = main
        def execute(config, state):
            return self.execute(native, cls, state)
        self.assertEqual(self.main(execute), 1)
        self.assertEqual(self.receipt()['diagnostic'], {'phase': 'gpg-import', 'outcome': 'command-failed'})
        self.assertNotIn('PRIVATE', json.dumps(self.receipt()))

    def test_preflight_failure_diagnostic_survives_main_and_early_constructor_failure_has_not_run(self):
        native, broker, cls, _ = self.fake_native()
        broker.initialize.side_effect = ValueError('PRIVATE-SECRET daemon detail')
        def execute(config, state):
            return self.execute(native, cls, state)
        self.assertEqual(self.main(execute), 1)
        self.assertEqual(self.receipt()['diagnostic'], {'phase': 'preflight', 'outcome': 'runner-failed'})
        self.assertNotIn('PRIVATE', json.dumps(self.receipt()))
        with mock.patch.object(producer, 'broker_class', side_effect=ValueError('PRIVATE-SECRET class detail')):
            self.assertEqual(self.main(self.original_execute), 1)
        self.assertEqual(self.receipt()['diagnostic'], {'phase': 'preflight', 'outcome': 'not-run'})
        self.assertNotIn('PRIVATE', json.dumps(self.receipt()))

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
