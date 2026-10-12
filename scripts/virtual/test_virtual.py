# SPDX-License-Identifier: MIT
"""Guard/output/metadata tests; no Docker, kernel, DRM or ARM execution."""
import copy
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from unittest.mock import Mock

import audit_tooling
import common
import guest
import run


class GuestIPC(unittest.TestCase):
    @contextmanager
    def delayed_fixture(self):
        """Real bound/listening AF_UNIX socket whose loop starts after probe one."""
        with tempfile.TemporaryDirectory(prefix='virtual-ipc-race-') as temporary:
            root = Path(temporary)
            instance = root / 'hypr' / 'fixture'; instance.mkdir(parents=True)
            path = instance / '.socket.sock'
            log = root / 'minimal.log'; log.write_text('startup\n')
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(path)); listener.listen(10); listener.settimeout(.1)
            ready, stop = threading.Event(), threading.Event()
            def serve():
                while not stop.is_set():
                    try: connection, _ = listener.accept()
                    except socket.timeout: continue
                    with connection:
                        connection.recv(1024)
                        ready.wait(2)
                        try: connection.sendall(b'[]\n')
                        except BrokenPipeError: pass
            worker = threading.Thread(target=serve); worker.start()
            results = []
            code = ('import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(.05); '
                    's.connect(sys.argv[1]); s.sendall(b"j/configerrors");\n'
                    'try: data=s.recv(1024)\n'
                    'except socket.timeout:\n'
                    ' print("Hyprland IPC didn\'t respond in time\\n\\nCouldn\'t read (6)"); sys.exit(6)\n'
                    'print(data.decode(),end="")')
            def probe(argv, **options):
                self.assertEqual(argv, guest.IPC_ARGV)
                self.assertEqual(options['env']['HYPRLAND_INSTANCE_SIGNATURE'], 'fixture')
                result = common.bounded([sys.executable, '-I', '-B', '-c', code, str(path)],
                                        timeout=options['timeout'], limit=options['limit'])
                results.append(result); ready.set()
                return result
            try:
                self.assertTrue(path.is_socket())
                yield root, log, {'XDG_RUNTIME_DIR': str(root)}, probe, results
            finally:
                stop.set(); ready.set(); worker.join(timeout=3); listener.close()
                self.assertFalse(worker.is_alive())

    def test_old_socket_exists_gate_causally_fails_on_real_delayed_server(self):
        with self.delayed_fixture() as (root, log, env, probe, results), \
                patch('guest.bounded', side_effect=probe), patch('guest.emit') as events:
            # Historical exact gate: socket discovery immediately followed by command().
            sockets = list(root.glob('hypr/*/.socket.sock'))
            env = dict(env, HYPRLAND_INSTANCE_SIGNATURE=sockets[0].parent.name)
            with self.assertRaisesRegex(ValueError, 'command failed/overflowed'):
                guest.command(guest.IPC_ARGV, env)
            self.assertEqual(results, [{'returncode': 6, 'error': None,
                                        'stdout': guest.IPC_TIMEOUT_REPLY, 'stderr': ''}])
            self.assertEqual(events.call_args.kwargs['returncode'], 6)

    def test_reply_gate_recovers_same_race_and_retains_first_failure(self):
        with self.delayed_fixture() as (root, log, env, probe, results), \
                patch('guest.bounded', side_effect=probe), patch('guest.emit') as events:
            compositor, check = Mock(), Mock(); compositor.poll.return_value = None
            actual = guest.wait_for_ipc('minimal', compositor, env, log, check)
            self.assertEqual(actual['HYPRLAND_INSTANCE_SIGNATURE'], 'fixture')
            self.assertEqual([row['returncode'] for row in results], [6, 0])
            attempts = [call.kwargs for call in events.call_args_list if call.args == ('ipc_probe',)]
            self.assertEqual([row['attempt'] for row in attempts], [1, 2])
            self.assertEqual(attempts[0]['stdout'], guest.IPC_TIMEOUT_REPLY)
            self.assertLessEqual(attempts[0]['elapsed_ms'], attempts[1]['elapsed_ms'])
            self.assertEqual(events.call_args.args, ('command',))
            self.assertEqual(events.call_args.kwargs['returncode'], 0)

    def simple_fixture(self, root):
        instance = root / 'hypr' / 'fixture'; instance.mkdir(parents=True)
        listener = socket.socket(socket.AF_UNIX); listener.bind(str(instance / '.socket.sock'))
        self.addCleanup(listener.close)
        log = root / 'minimal.log'; log.write_text('startup\n')
        compositor = Mock(); compositor.poll.return_value = None
        return compositor, {'XDG_RUNTIME_DIR': str(root)}, log

    def test_only_observed_transient_is_retryable_not_config_or_process_errors(self):
        invalid = [{'returncode': 6, 'error': None, 'stdout': "Couldn't read (6)\n", 'stderr': ''},
                   {'returncode': 4, 'error': None, 'stdout': guest.IPC_TIMEOUT_REPLY, 'stderr': ''},
                   {'returncode': 6, 'error': None, 'stdout': guest.IPC_TIMEOUT_REPLY, 'stderr': 'warning'},
                   {'returncode': -9, 'error': 'timeout', 'stdout': '', 'stderr': ''},
                   {'returncode': -9, 'error': 'output overflow', 'stdout': '', 'stderr': ''},
                   {'returncode': 0, 'error': None, 'stdout': '["bad config"]', 'stderr': ''},
                   {'returncode': 0, 'error': None, 'stdout': '{"not":"list"}', 'stderr': ''},
                   {'returncode': 0, 'error': None, 'stdout': 'not JSON', 'stderr': ''}]
        for result in invalid:
            with self.subTest(result=result), tempfile.TemporaryDirectory() as temporary:
                compositor, env, log = self.simple_fixture(Path(temporary))
                with patch('guest.bounded', return_value=result) as probe, patch('guest.emit') as events, \
                        self.assertRaises(ValueError):
                    guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                self.assertEqual(probe.call_count, 1)
                self.assertEqual(events.call_count, 1)
                self.assertEqual(events.call_args.args, ('ipc_probe',))

    def test_attempt_cap_is_finite_and_holds_each_failed_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            compositor, env, log = self.simple_fixture(Path(temporary))
            result = {'returncode': 6, 'error': None, 'stdout': guest.IPC_TIMEOUT_REPLY, 'stderr': ''}
            with patch('guest.bounded', return_value=result) as probe, patch('guest.emit') as events, \
                    patch('guest.time.sleep'), self.assertRaisesRegex(ValueError, 'attempt limit'):
                guest.wait_for_ipc('overlay', compositor, env, log, Mock())
            self.assertEqual(probe.call_count, guest.IPC_ATTEMPTS)
            self.assertEqual([call.kwargs['attempt'] for call in events.call_args_list],
                             list(range(1, guest.IPC_ATTEMPTS + 1)))
            self.assertTrue(all(0 < call.kwargs['timeout'] <= 30 for call in probe.call_args_list))

    def test_probe_result_types_and_compositor_liveness_stay_strict(self):
        for change in ({'returncode': False}, {'error': False}, {'stdout': False}, {'stderr': None},
                       {'stdout': 'x' * (guest.MAX_LOG + 1)}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                compositor, env, log = self.simple_fixture(Path(temporary))
                result = {'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''} | change
                with patch('guest.bounded', return_value=result), patch('guest.emit') as events, \
                        self.assertRaisesRegex(ValueError, 'invalid bounded IPC'):
                    guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                events.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            compositor, env, log = self.simple_fixture(Path(temporary))
            compositor.poll.side_effect = [None, 1]
            with patch('guest.bounded', return_value={'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''}), \
                    patch('guest.emit') as events, self.assertRaisesRegex(ValueError, 'exited during IPC'):
                guest.wait_for_ipc('minimal', compositor, env, log, Mock())
            self.assertEqual(events.call_count, 1)
            self.assertEqual(events.call_args.args, ('ipc_probe',))

    def test_missing_socket_expires_original_startup_budget_without_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); log = root / 'minimal.log'; log.write_text('startup')
            compositor = Mock(); compositor.poll.return_value = None; clock = [0.0]
            def check(): clock[0] = 180
            with patch('guest.time.monotonic', side_effect=lambda: clock[0]), patch('guest.time.sleep'), \
                    patch('guest.bounded') as probe, self.assertRaisesRegex(ValueError, 'IPC deadline'):
                guest.wait_for_ipc('minimal', compositor, {'XDG_RUNTIME_DIR': str(root)}, log, check)
            probe.assert_not_called()

    def test_same_absolute_deadline_bounds_last_probe_and_cannot_pass_late(self):
        with tempfile.TemporaryDirectory() as temporary:
            compositor, env, log = self.simple_fixture(Path(temporary))
            clock = [0.0]
            def probe(_argv, **options):
                self.assertEqual(options['timeout'], .25)
                clock[0] = 180.1
                return {'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''}
            def check(): clock[0] = 179.75
            with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                    patch('guest.bounded', side_effect=probe), patch('guest.emit') as events, \
                    self.assertRaisesRegex(ValueError, 'IPC deadline'):
                guest.wait_for_ipc('minimal', compositor, env, log, check)
            self.assertEqual(events.call_args.kwargs['elapsed_ms'], 180100)
            self.assertEqual(events.call_count, 1)

    def test_fractional_deadline_reports_floor_milliseconds_and_refuses_late_ready(self):
        for actual_time, milliseconds, ready in ((179.9996, 179999, True), (180.0001, 180000, False)):
            with self.subTest(actual_time=actual_time), tempfile.TemporaryDirectory() as temporary:
                compositor, env, log = self.simple_fixture(Path(temporary)); clock = [0.0]
                def check(): clock[0] = 179.75
                def probe(_argv, **_options):
                    clock[0] = actual_time
                    return {'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''}
                with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                        patch('guest.bounded', side_effect=probe), patch('guest.emit') as events:
                    if ready:
                        self.assertEqual(guest.wait_for_ipc('minimal', compositor, env, log, check)
                                         ['HYPRLAND_INSTANCE_SIGNATURE'], 'fixture')
                    else:
                        with self.assertRaisesRegex(ValueError, 'IPC deadline'):
                            guest.wait_for_ipc('minimal', compositor, env, log, check)
                self.assertEqual(events.call_args_list[0].kwargs['elapsed_ms'], milliseconds)
                self.assertEqual([call.args for call in events.call_args_list],
                                 [('ipc_probe',), ('command',)] if ready else [('ipc_probe',)])

    def test_diagnostic_cap_counts_combined_utf8_bytes_including_replacement_expansion(self):
        # ASCII whitespace is valid JSON padding; Unicode whitespace in stderr still
        # has to count toward the combined cap before any event is published.
        for stdout, stderr, accepted in (('[]' + ' ' * 6, '', True), ('[]' + ' ' * 7, '', False),
                                         ('[]', '\u00e9' * 3, False), ('[]', '\u00e9' * 4, False)):
            with self.subTest(stdout=stdout, stderr=stderr), tempfile.TemporaryDirectory() as temporary:
                compositor, env, log = self.simple_fixture(Path(temporary)); log.write_text('')
                result = {'returncode': 0, 'error': None, 'stdout': stdout, 'stderr': stderr}
                with patch('guest.MAX_LOG', 8), patch('guest.bounded', return_value=result), \
                        patch('guest.emit') as events:
                    if accepted:
                        guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                    else:
                        with self.assertRaises(ValueError):
                            guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                byte_count = len(stdout.encode()) + len(stderr.encode())
                self.assertEqual(events.call_count, 0 if byte_count > 8 else 2 if accepted else 1)
        with tempfile.TemporaryDirectory() as temporary:
            compositor, env, log = self.simple_fixture(Path(temporary)); log.write_text('')
            observed = []
            def probe(_argv, **options):
                result = common.bounded([sys.executable, '-c', 'import os;os.write(1,b"\\xff"*8)'],
                                        timeout=options['timeout'], limit=options['limit'])
                observed.append(result); return result
            with patch('guest.MAX_LOG', 8), patch('guest.bounded', side_effect=probe), \
                    patch('guest.emit') as events, self.assertRaisesRegex(ValueError, 'invalid bounded IPC'):
                guest.wait_for_ipc('minimal', compositor, env, log, Mock())
            self.assertIsNone(observed[0]['error'])
            self.assertEqual(len(observed[0]['stdout']), 8)
            self.assertEqual(len(observed[0]['stdout'].encode()), 24)
            events.assert_not_called()

    def test_compositor_exit_and_non_socket_or_ambiguous_paths_never_probe(self):
        for kind in ('exit', 'file', 'ambiguous', 'overflow'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); compositor, env, log = self.simple_fixture(root)
                path = root / 'hypr' / 'fixture' / '.socket.sock'
                if kind == 'exit': compositor.poll.return_value = 1
                if kind == 'file': path.unlink(); path.write_text('fake')
                if kind == 'ambiguous':
                    extra = root / 'hypr' / 'other'; extra.mkdir(); (extra / '.socket.sock').write_text('fake')
                if kind == 'overflow': log.write_bytes(b'x' * (guest.MAX_LOG + 1))
                with patch('guest.bounded') as probe, self.assertRaises(ValueError):
                    guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                probe.assert_not_called()

    def test_retention_is_bounded_regular_file_only_and_preserves_overflow_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'minimal.log'; path.write_bytes(b'x' * 65)
            with patch('guest.MAX_LOG', 64), patch('guest.emit') as events, \
                    self.assertRaisesRegex(ValueError, 'session log overflow'):
                guest.retained(path, 'minimal')
            row = events.call_args.kwargs
            self.assertEqual(base64.b64decode(row['base64']), b'x' * 64)
            self.assertEqual(row['sha256'], hashlib.sha256(b'x' * 64).hexdigest())
            linked = root / 'linked'; linked.symlink_to(path)
            with self.assertRaises(OSError): guest.log_bytes(linked)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, 'regular session log'): guest.log_bytes(fifo)

    def test_failed_phase_reaps_and_retains_actual_private_log_or_static_failure(self):
        for capture_failure in (False, True):
            with self.subTest(capture_failure=capture_failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); runtime = root / 'runtime'; runtime.mkdir()
                process, collector = Mock(), Mock(); process.poll.return_value = None; collector.process = process
                def launch(_argv, path, **_options):
                    path.write_text('stdout disabled\n')
                    instance = runtime / 'hypr' / 'new'; instance.mkdir(parents=True)
                    private = instance / 'hyprland.log'; private.write_text('actual private startup\n')
                    if capture_failure:
                        private.unlink(); private.symlink_to(root / 'minimal.log')
                    return collector
                failure = ValueError('original IPC failure')
                def terminate(_process): process.poll.return_value = -15
                with patch('guest.LoggedProcess', side_effect=launch), \
                        patch('guest.wait_for_ipc', side_effect=failure), \
                        patch('guest.terminate', side_effect=terminate) as reap, patch('guest.emit') as events, \
                        self.assertRaises(ValueError) as caught:
                    guest.phase('minimal', root / 'config', {'XDG_RUNTIME_DIR': str(runtime)}, root)
                self.assertIs(caught.exception, failure); reap.assert_called_once_with(process)
                collector.finish.assert_called_once()
                rows = [call.kwargs for call in events.call_args_list if call.args == ('session_log',)]
                self.assertEqual([row['filename'] for row in rows], ['minimal.log', 'minimal-compositor.log'])
                expected = b'private compositor log retention failed: ValueError\n' if capture_failure else b'actual private startup\n'
                self.assertEqual(base64.b64decode(rows[-1]['base64']), expected)

    def test_actual_timed_out_probe_is_fatal_and_child_is_reaped(self):
        original, children = subprocess.Popen, []
        def spawn(*args, **kwargs):
            process = original(*args, **kwargs); children.append(process); return process
        def probe(_argv, **options):
            return common.bounded([sys.executable, '-c', 'import time;time.sleep(30)'],
                                  timeout=.05, limit=options['limit'])
        with tempfile.TemporaryDirectory() as temporary:
            compositor, env, log = self.simple_fixture(Path(temporary))
            with patch('common.subprocess.Popen', side_effect=spawn), patch('guest.bounded', side_effect=probe), \
                    patch('guest.emit') as events, self.assertRaisesRegex(ValueError, 'probe failed'):
                guest.wait_for_ipc('minimal', compositor, env, log, Mock())
            self.assertEqual(len(children), 1); self.assertIsNotNone(children[0].poll())
            self.assertEqual(events.call_args.kwargs['error'], 'timeout')


class GuestConfigErrors(unittest.TestCase):
    ACTUAL_READY = '[\n\t""\n]\n\n'
    NEGATIVES = [[' '], ['\t'], ['\n'], ['\u00a0'], ['real error'], ['', 'real error'],
                 ['real error', ''], ['', ''], [['']], [None], [False], [True], [0],
                 {}, None, False, True, '', '[]']

    def test_no_reported_error_text_predicate_has_exact_two_shapes(self):
        for value in ([], ['']):
            with self.subTest(value=value): self.assertTrue(guest.no_reported_config_error_text(value))
        class ListSubclass(list): pass
        class StringSubclass(str): pass
        for value in self.NEGATIVES + [ListSubclass(), [StringSubclass('')], ()]:
            with self.subTest(value=value): self.assertFalse(guest.no_reported_config_error_text(value))

    def test_actual_three_probe_sequence_preserves_stdout_and_ready_command_correlation(self):
        with tempfile.TemporaryDirectory() as temporary:
            compositor, env, log = GuestIPC.simple_fixture(self, Path(temporary)); clock = [0.0]
            results = [{'returncode': 6, 'error': None, 'stdout': guest.IPC_TIMEOUT_REPLY, 'stderr': ''},
                       {'returncode': 6, 'error': None, 'stdout': guest.IPC_TIMEOUT_REPLY, 'stderr': ''},
                       {'returncode': 0, 'error': None, 'stdout': self.ACTUAL_READY, 'stderr': ''}]
            times = iter((9.679, 15.807, 21.315)); remaining = iter(results)
            def probe(argv, **options):
                self.assertEqual(argv, guest.IPC_ARGV)
                self.assertEqual(options['limit'], guest.MAX_LOG)
                self.assertEqual(options['timeout'], 30)
                clock[0] = next(times)
                return next(remaining)
            with patch('guest.bounded', side_effect=probe) as probes, patch('guest.emit') as events, \
                    patch('guest.time.monotonic', side_effect=lambda: clock[0]), patch('guest.time.sleep'):
                ready = guest.wait_for_ipc('minimal', compositor, env, log, Mock())
            self.assertEqual(ready['HYPRLAND_INSTANCE_SIGNATURE'], 'fixture')
            self.assertEqual(probes.call_count, 3)
            rows = [call.kwargs for call in events.call_args_list if call.args == ('ipc_probe',)]
            self.assertEqual(rows, [dict(stage='minimal', attempt=i, elapsed_ms=elapsed, **result)
                                    for i, elapsed, result in zip((1, 2, 3), (9679, 15807, 21315), results)])
            self.assertEqual([call.args for call in events.call_args_list],
                             [('ipc_probe',)] * 3 + [('command',)])
            self.assertEqual(events.call_args.kwargs, dict(argv=guest.IPC_ARGV, **results[-1]))

    def test_nineteen_negative_payloads_and_malformed_json_never_become_ready_commands(self):
        payloads = [json.dumps(value) for value in self.NEGATIVES] + ['not JSON', '[""] trailing']
        self.assertEqual(len(self.NEGATIVES), 19)
        for stdout in payloads:
            with self.subTest(stdout=stdout), tempfile.TemporaryDirectory() as temporary:
                compositor, env, log = GuestIPC.simple_fixture(self, Path(temporary))
                result = {'returncode': 0, 'error': None, 'stdout': stdout, 'stderr': ''}
                with patch('guest.bounded', return_value=result) as probe, patch('guest.emit') as events, \
                        self.assertRaises(ValueError):
                    guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                probe.assert_called_once(); self.assertEqual(events.call_count, 1)
                self.assertEqual(events.call_args.args, ('ipc_probe',))
                self.assertEqual(events.call_args.kwargs['stdout'], stdout)

    def test_new_ready_text_keeps_transport_deadline_liveness_and_byte_guards(self):
        changes = ({'returncode': 6}, {'returncode': False}, {'error': 'timeout'},
                   {'error': 'output overflow'}, {'stderr': 'warning'}, {'stdout': '["" ]' * 100})
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                compositor, env, log = GuestIPC.simple_fixture(self, Path(temporary)); log.write_text('')
                result = {'returncode': 0, 'error': None, 'stdout': self.ACTUAL_READY, 'stderr': ''} | change
                with patch('guest.MAX_LOG', 64), patch('guest.bounded', return_value=result), \
                        patch('guest.emit') as events, self.assertRaises(ValueError):
                    guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                self.assertNotIn(('command',), [call.args for call in events.call_args_list])
                self.assertEqual(events.call_count, 0 if type(result['returncode']) is not int or
                                 len(result['stdout'].encode()) + len(result['stderr'].encode()) > 64 else 1)
        for late, dead in ((True, False), (False, True)):
            with self.subTest(late=late, dead=dead), tempfile.TemporaryDirectory() as temporary:
                compositor, env, log = GuestIPC.simple_fixture(self, Path(temporary)); clock = [0.0]
                def probe(_argv, **_options):
                    clock[0] = 180.0001 if late else 1
                    if dead: compositor.poll.return_value = 1
                    return {'returncode': 0, 'error': None, 'stdout': self.ACTUAL_READY, 'stderr': ''}
                with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                        patch('guest.bounded', side_effect=probe), patch('guest.emit') as events, \
                        self.assertRaisesRegex(ValueError, 'IPC deadline' if late else 'exited during IPC'):
                    guest.wait_for_ipc('minimal', compositor, env, log, Mock())
                self.assertEqual([call.args for call in events.call_args_list], [('ipc_probe',)])


class GuestDiagnostics(unittest.TestCase):
    def diagnostic_phase(self, phase_failure=None, cleanup_failure=None, invalid_capture=False,
                         closed_log=None, closed_summary=False):
        """Exercise phase cleanup with controlled first failures and sink refusal."""
        with tempfile.TemporaryDirectory(prefix='virtual-diagnostic-') as temporary:
            root = Path(temporary); runtime = root / 'runtime'; runtime.mkdir()
            wayland = socket.socket(socket.AF_UNIX); wayland.bind(str(runtime / 'wayland-0'))
            compositor, client = Mock(), Mock(); client.pid = 42
            compositor.poll.return_value = client.poll.return_value = None
            compositor.returncode = 0
            collectors = [Mock(process=compositor), Mock(process=client)]
            collectors[0].finish.side_effect = cleanup_failure
            private = runtime / 'hypr' / 'new' / 'hyprland.log'
            def launch(_argv, path, **_options):
                path.write_text('actual stdout\n')
                if not private.exists():
                    private.parent.mkdir(parents=True); private.write_text('actual private\n')
                return collectors[0] if path.name == 'minimal.log' else collectors[1]
            def reap(process):
                process.poll.return_value = -15
                if process is compositor and invalid_capture:
                    private.unlink(); private.symlink_to(root / 'minimal.log')
            compositor.wait.side_effect = lambda **_options: reap(compositor)
            def command(argv, _env):
                if argv[-1] == 'monitors': return '[{"width":1,"height":1}]'
                if argv[-1] == 'clients': return '[{"pid":42,"mapped":true,"size":[1,1]}]'
                return ''
            delivered, refused = [], []
            channel_failure = BrokenPipeError('log channel closed')
            summary_failure = BrokenPipeError('summary channel closed')
            def emit(event, **row):
                if event == 'session_log' and (closed_log == 'all' and row['filename'] != 'minimal-client.log' or
                        closed_log == 'private' and row['filename'] == 'minimal-compositor.log'):
                    refused.append(row)
                    raise channel_failure if len(refused) == 1 else BrokenPipeError('fallback channel closed')
                delivered.append({'event': event, **row})
            env = {'XDG_RUNTIME_DIR': str(runtime)}
            try:
                with patch('guest.LoggedProcess', side_effect=launch), \
                        patch('guest.wait_for_ipc', side_effect=phase_failure, return_value=env), \
                        patch('guest.command', side_effect=command), patch('guest.terminate', side_effect=reap), \
                        patch('guest.time.monotonic', side_effect=[0, 0, 0, 16]), \
                        patch('guest.emit', side_effect=emit), \
                        patch('guest.print', side_effect=summary_failure if closed_summary else None) as summary:
                    try: guest.phase('minimal', root / 'config', env, root)
                    except Exception as exc: failure = exc
                    else: failure = None
            finally:
                wayland.close()
            return failure, delivered, refused, summary, channel_failure, compositor, collectors

    def test_closed_fallback_and_secondary_summary_preserve_original_phase_failure(self):
        for closed_log, closed_summary in (('private', False), (None, True), ('all', True)):
            with self.subTest(closed_log=closed_log, closed_summary=closed_summary):
                original = ValueError('original IPC refusal')
                failure, delivered, refused, summary, _, process, collectors = self.diagnostic_phase(
                    phase_failure=original, invalid_capture=True,
                    closed_log=closed_log, closed_summary=closed_summary)
                self.assertIs(failure, original)
                self.assertIsNotNone(process.poll()); collectors[0].finish.assert_called_once()
                self.assertEqual([row['filename'] for row in delivered if row['event'] == 'session_log'],
                                 [] if closed_log == 'all' else ['minimal.log'] if closed_log else
                                 ['minimal.log', 'minimal-compositor.log'])
                self.assertEqual(len(refused), 2 if closed_log == 'all' else 1 if closed_log else 0)
                summary.assert_called_once()

    def test_working_channel_retains_capture_failure_without_claiming_private_bytes(self):
        original = ValueError('original IPC refusal')
        failure, delivered, refused, summary, _, _, _ = self.diagnostic_phase(
            phase_failure=original, invalid_capture=True)
        self.assertIs(failure, original); self.assertEqual(refused, [])
        logs = [row for row in delivered if row['event'] == 'session_log']
        expected = b'private compositor log retention failed: ValueError\n'
        self.assertEqual(base64.b64decode(logs[-1]['base64']), expected)
        self.assertEqual(logs[-1]['sha256'], hashlib.sha256(expected).hexdigest())
        self.assertIn('ValueError', summary.call_args.args[0])

    def test_clean_phase_keeps_first_cleanup_failure_when_channels_close(self):
        original = RuntimeError('first collector finish failure')
        failure, delivered, _, _, _, process, _ = self.diagnostic_phase(
            cleanup_failure=original, invalid_capture=True, closed_log='all', closed_summary=True)
        self.assertIs(failure, original); self.assertIsNotNone(process.poll())
        self.assertIn('phase_pass', [row['event'] for row in delivered])

    def test_clean_phase_keeps_first_capture_failure_when_channels_close(self):
        failure, delivered, _, _, _, _, _ = self.diagnostic_phase(
            invalid_capture=True, closed_log='private', closed_summary=True)
        self.assertIs(type(failure), ValueError)
        self.assertEqual(str(failure), 'private compositor log invalid/overflowed')
        self.assertEqual([row['filename'] for row in delivered if row['event'] == 'session_log'],
                         ['minimal-client.log', 'minimal.log'])

    def test_clean_phase_keeps_first_log_channel_failure_without_delivered_log_claim(self):
        failure, delivered, refused, _, channel_failure, _, _ = self.diagnostic_phase(
            closed_log='private', closed_summary=True)
        self.assertIs(failure, channel_failure)
        self.assertEqual([row['filename'] for row in delivered if row['event'] == 'session_log'],
                         ['minimal-client.log', 'minimal.log'])
        self.assertEqual(len(refused), 2)


class Capabilities(unittest.TestCase):
    def results(self):
        return [{'returncode': 0, 'error': None, 'stdout': expected, 'stderr': ''}
                for _, _, expected in run.CAPABILITIES]

    def checks(self, results):
        with tempfile.TemporaryDirectory(prefix='virtual-capability-test-') as temporary:
            root = Path(temporary); report = {}; writes = []
            original = common.save
            def observe(path, value):
                writes.append(copy.deepcopy(value)); original(path, value)
            with patch('run.bounded', side_effect=results) as process, patch('run.save', side_effect=observe):
                try: run.check_capabilities(report, root)
                except BaseException as error: failure = error
                else: failure = None
            self.assertEqual(common.json_load(root / 'capabilities.json'), report['capabilities'])
            for call in process.call_args_list:
                self.assertEqual(call.kwargs, {'timeout': 15, 'limit': 128 * 1024})
            return report, writes, process.call_args_list, failure

    def test_all_four_checks_record_before_and_after_without_raw_help(self):
        report, writes, calls, failure = self.checks(self.results())
        self.assertIsNone(failure)
        self.assertEqual([r['status'] for rows in writes for r in rows[-1:]],
                         ['STARTING', 'PASS'] * 4)
        self.assertEqual([c.args[0] for c in calls],
                         [['/usr/bin/qemu-system-aarch64', *args] for _, args, _ in run.CAPABILITIES])
        self.assertEqual(len(run.capability_projection(report['capabilities'])), 4)
        self.assertNotIn('stdout', report['capabilities'][0])

    def test_each_missing_capability_stops_at_exact_check_and_has_finite_hashes(self):
        for index, (name, _, _) in enumerate(run.CAPABILITIES):
            with self.subTest(check=name):
                rows = self.results(); rows[index]['stdout'] = 'password=PRIVATE_HELP'
                report, writes, calls, failure = self.checks(rows)
                self.assertIsInstance(failure, common.Refused)
                self.assertEqual(len(calls), index + 1)
                self.assertEqual(report['capabilities'][-1]['check'], name)
                self.assertEqual(report['capabilities'][-1]['reason'], 'capability-missing')
                self.assertEqual(writes[-2][-1]['status'], 'STARTING')
                self.assertNotIn('PRIVATE_HELP', json.dumps(report))

    def test_process_bounds_errors_and_cancel_never_publish_exception_text(self):
        for error, reason in [('timeout', 'timeout'), ('output overflow', 'output-limit'),
                              ('password=PRIVATE_HELP', 'launch-failed'), (None, 'process-failed')]:
            report, _, _, failure = self.checks([{'returncode': -9, 'error': error,
                                                 'stdout': '', 'stderr': 'PRIVATE_HELP'}])
            self.assertIsInstance(failure, common.Refused)
            self.assertEqual(report['capabilities'][-1]['reason'], reason)
            self.assertNotIn('PRIVATE_HELP', json.dumps(report))
        for error, reason in [(OSError('PRIVATE_PATH'), 'launch-failed'),
                              (run.ProofInterrupted('PRIVATE_PATH'), 'cancelled'),
                              (KeyboardInterrupt(), 'cancelled')]:
            report, _, _, failure = self.checks([error])
            self.assertIs(failure, error)
            self.assertEqual(report['capabilities'][-1]['reason'], reason)
            self.assertNotIn('PRIVATE_PATH', json.dumps(report))
            self.assertTrue(all(report['capabilities'][-1][key] is None for key in
                                ('returncode', 'stdout_sha256', 'stdout_bytes', 'stderr_sha256', 'stderr_bytes')))
            changed = copy.deepcopy(report['capabilities'])
            changed[-1].update(stdout_bytes=0, stdout_sha256=hashlib.sha256(b'').hexdigest())
            with self.assertRaises(common.Refused): run.capability_projection(changed)

    def test_projection_rejects_secret_types_order_and_partial_records(self):
        report, _, _, _ = self.checks(self.results()); rows = report['capabilities']
        changes = [('check', 'PRIVATE_PATH'), ('status', True), ('returncode', True),
                   ('reason', 'PRIVATE_PATH'), ('stdout_sha256', 'bad'),
                   ('stdout_bytes', False), ('stdout_bytes', 128 * 1024 * 3 + 1),
                   ('stderr_bytes', -1)]
        for key, value in changes:
            changed = copy.deepcopy(rows); changed[0][key] = value
            with self.subTest(field=key), self.assertRaises(common.Refused):
                run.capability_projection(changed)
        for changed in [rows[::-1], rows + [rows[-1]], [dict(rows[0], private='PRIVATE_PATH')],
                        [{key: value for key, value in rows[0].items() if key != 'stdout_bytes'}]]:
            with self.assertRaises(common.Refused): run.capability_projection(changed)

    def test_actual_bounded_process_output_flood_is_refused_and_reaped(self):
        def flood(_argv, **kwargs):
            return common.bounded([sys.executable, '-I', '-B', '-c',
                                   'import os;os.write(1,b"x"*1048576)'], **kwargs)
        with tempfile.TemporaryDirectory(prefix='virtual-capability-flood-') as temporary:
            report = {}
            with patch('run.bounded', side_effect=flood), self.assertRaises(common.Refused):
                run.check_capabilities(report, Path(temporary))
            row = report['capabilities'][0]
            self.assertEqual(row['reason'], 'output-limit')
            self.assertEqual(row['stdout_bytes'], run.CAPABILITY_LIMIT)

    def test_historical_audit_and_corrected_module_shape_stay_distinct(self):
        old = common.json_load(Path(__file__).with_name('tooling.lock.json'))
        old['packages'] = [row for row in old['packages'] if row['name'] not in
                           ('qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci')]
        old['expected_package_count'] = 360
        audit_tooling.validate_lock(old)
        candidate = copy.deepcopy(old)
        candidate['packages'] += [{'name': 'qemu-hw-display-virtio-gpu'},
                                  {'name': 'qemu-hw-display-virtio-gpu-pci'}]
        candidate['expected_package_count'] = 362
        audit_tooling.validate_lock(candidate)
        for change in [dict(expected_package_count=360), dict(base_package_count=345),
                       dict(packages=candidate['packages'][:-1] + [{'name': 'unrelated-module'}])]:
            with self.assertRaises(common.Refused): audit_tooling.validate_lock(candidate | change)

    def test_runtime_requires_corrected_extension_and_exact_inventory(self):
        # Data/interface fixture only: no host pacman, kernel or baseline payload access.
        old = common.json_load(Path(__file__).with_name('tooling.lock.json'))
        old['packages'] = [row for row in old['packages'] if row['name'] not in
                           ('qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci')]
        old['expected_package_count'] = 360
        candidate = copy.deepcopy(old)
        candidate['packages'] += [{'name': name, 'version': '11.1.2-1'} for name in
                                  ('qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci')]
        candidate['expected_package_count'] = 362
        with tempfile.TemporaryDirectory(prefix='virtual-runtime-extension-') as temporary:
            root = Path(temporary); base = {f'base-package-{i:03d}': '1-1' for i in range(341)}
            (root / 'base.lock').write_text(''.join(name + ' ' + version + '\n' for name, version in base.items()))
            contract = {'base_runtime_lock': 'base.lock', 'base_runtime_lock_sha256': common.digest(root / 'base.lock'),
                        'tooling_lock': 'tooling.json', 'tooling_audit': 'audit.json', 'tooling_audit_sha256': 'a' * 64,
                        'baseline': []}
            def attempt(lock, observed=None):
                common.save(root / 'tooling.json', lock)
                contract['tooling_lock_sha256'] = common.digest(root / 'tooling.json')
                common.save(root / 'audit.json', {'status': 'PASS', 'tooling_lock_sha256': contract['tooling_lock_sha256'],
                                                'packages': {row['name']: {} for row in lock['packages']}})
                expected = base | {row['name']: row['version'] for row in lock['packages']}
                text = ''.join(name + ' ' + version + '\n' for name, version in (observed or expected).items())
                with patch('common.pinned', side_effect=lambda _root, name, _sha: root / name), \
                        patch('common.subprocess.check_output', return_value=text) as process, \
                        patch('common.digest', return_value=common.IMAGE_SHA):
                    result = common.check_runtime(contract)
                    process.assert_called_once_with(['/usr/bin/pacman', '-Q'], text=True, timeout=30)
                return result
            self.assertEqual(len(attempt(candidate)), 362)
            with self.assertRaises(common.Refused): attempt(old)
            with self.assertRaises(common.Refused): attempt(candidate | {'expected_package_count': 360})
            expected = base | {row['name']: row['version'] for row in candidate['packages']}
            expected.pop('qemu-hw-display-virtio-gpu-pci'); expected['unrelated-module'] = '11.1.2-1'
            with self.assertRaises(common.Refused): attempt(candidate, expected)


class Guards(unittest.TestCase):
    def fixture(self, prep=False):
        return {'uid': 0 if prep else 1001, 'arch': 'aarch64', 'docker': True,
                'caps': {k: common.SAFE_CAPS if prep else 0 for k in ('CapEff', 'CapPrm', 'CapBnd')},
                'nnp': '1', 'interfaces': ['lo'], 'devices': False, 'docker_socket': False,
                'nonce': 'a' * 32, 'image_id': 'sha256:' + 'b' * 64, 'marker': '1',
                'runner': '/runner/virtual', 'mounts': {
                    '/': {'flags': ['ro'], 'type': 'overlay'}, '/inputs': {'flags': ['ro'], 'type': 'ext4'},
                    '/runner': {'flags': ['ro'], 'type': 'ext4'}, '/out': {'flags': ['rw'], 'type': 'ext4'},
                    '/tmp': {'flags': ['rw'], 'type': 'tmpfs'}}}

    def test_guards_accept_only_reviewed_root_preparation_and_unprivileged_run(self):
        common.validate_environment(self.fixture())
        common.validate_environment(self.fixture(True), preparation=True)
        for prep in (False, True):
            cases = [dict(uid=1001 if prep else 0), dict(arch='x86_64'), dict(docker=False), dict(marker=''),
                     dict(devices=True), dict(interfaces=['lo', 'eth0']), dict(docker_socket=True), dict(nnp='0'),
                     dict(nonce='a'), dict(image_id='latest'), dict(runner='/home/runner')]
            for changes in cases:
                with self.subTest(preparation=prep, changes=changes), self.assertRaises(common.Refused):
                    common.validate_environment(dict(self.fixture(prep), **changes), preparation=prep)

    def test_caps_ro_root_and_nested_mounts(self):
        for prep in (False, True):
            for bit in (12, 16, 21):  # NET_ADMIN/SYS_MODULE/SYS_ADMIN
                f = self.fixture(prep)
                f['caps']['CapBnd'] |= 1 << bit
                with self.assertRaises(common.Refused):
                    common.validate_environment(f, preparation=prep)
        for point in ('/out/secret', '/inputs/socket', '/usr/local', '/home'):
            f = self.fixture()
            f['mounts'][point] = {'flags': ['rw'], 'type': 'ext4'}
            with self.assertRaises(common.Refused):
                common.validate_environment(f)
        f = self.fixture()
        f['mounts']['/']['flags'] = ['rw']
        with self.assertRaises(common.Refused):
            common.validate_environment(f)

    def test_guest_refuses_host_before_cmdline_or_drivers(self):
        with patch.dict(os.environ, {}, clear=True), patch('guest.platform.machine', return_value='x86_64'):
            with self.assertRaises(ValueError):
                guest.guest_guard()

    def test_paths_and_json_data_rejected(self):
        for value in ('/usr/foo', '../x', 'a/../x', 'a//x', 'a\\x', 'a\nx'):
            with self.assertRaises(common.Refused):
                common.relative(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_text('{"a":1,"a":2}')
            with self.assertRaises(common.Refused):
                common.json_load(path)
            path.write_text('{"a":NaN}')
            with self.assertRaises(common.Refused):
                common.json_load(path)
            path.write_bytes(b'fixture')
            linked = Path(directory) / 'link'
            linked.symlink_to(path)
            with self.assertRaises(common.Refused):
                common.pinned(directory, 'link', common.digest(path))
            with self.assertRaises(common.Refused):
                common.pinned(directory, 'input', '0' * 64)


class Bounds(unittest.TestCase):
    def test_cancellation_between_popen_and_registration_reaps_real_child(self):
        original = subprocess.Popen
        for kind in ('bounded', 'logged'):
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
                children = []
                def interrupt(*_):
                    raise KeyboardInterrupt('spawn cancellation')
                def spawn(*args, **kwargs):
                    child = original(*args, **kwargs)
                    children.append(child)
                    os.kill(os.getpid(), sig)
                    return child
                previous = signal.signal(sig, interrupt)
                try:
                    with self.subTest(kind=kind, signal=sig), tempfile.TemporaryDirectory() as directory, \
                            patch('common.subprocess.Popen', side_effect=spawn), self.assertRaises(KeyboardInterrupt):
                        path = Path(directory) / 'cancel.log'
                        argv = [sys.executable, '-c', 'import time; time.sleep(30)']
                        if kind == 'bounded':
                            common.bounded(argv, log=path, timeout=2)
                        else:
                            common.LoggedProcess(argv, path)
                    self.assertEqual(len(children), 1)
                    self.assertIsNotNone(children[0].poll())
                    self.assertIs(signal.getsignal(sig), interrupt)
                    self.assertTrue(children[0].stdout.closed)
                finally:
                    signal.signal(sig, previous)
                    for child in children:
                        if child.poll() is None:
                            run.kill(child)

    def test_spawn_preserves_child_term_and_default_parent_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'term.log'
            item = common.LoggedProcess([sys.executable, '-c', 'import time; print("ready",flush=True); time.sleep(30)'], path)
            deadline = time.monotonic() + 2
            try:
                while not path.read_bytes() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertIn(b'ready', path.read_bytes())
                item.process.send_signal(signal.SIGTERM)
                self.assertEqual(item.process.wait(timeout=2), -signal.SIGTERM)
                item.finish()
            finally:
                if item.process.poll() is None:
                    run.kill(item.process)
            previous = signal.signal(signal.SIGTERM, signal.SIG_DFL)
            original, children = subprocess.Popen, []
            def spawn(*args, **kwargs):
                child = original(*args, **kwargs); children.append(child)
                os.kill(os.getpid(), signal.SIGTERM)
                return child
            try:
                with patch('common.subprocess.Popen', side_effect=spawn), self.assertRaises(InterruptedError):
                    common.bounded([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=2)
                self.assertIsNotNone(children[0].poll())
                self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
            finally:
                signal.signal(signal.SIGTERM, previous)
                for child in children:
                    if child.poll() is None:
                        run.kill(child)

    def test_streaming_combined_output_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bounded.log'
            result = common.bounded([sys.executable, '-c', 'import os; os.write(1,b"x"*100000); os.write(2,b"y"*100000)'], log=path, limit=1024)
            self.assertEqual(result['error'], 'output overflow')
            self.assertEqual(path.stat().st_size, 1024)
            self.assertLessEqual(len(result['stdout']) + len(result['stderr']), 1024)
            self.assertNotEqual(result['returncode'], 0)

    def test_deadline_kills_process_group_and_retains_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'timeout.log'
            result = common.bounded([sys.executable, '-c', 'import os,time; print("before deadline",flush=True); os.fork(); time.sleep(30)'], log=path, timeout=.15)
            self.assertEqual(result['error'], 'timeout')
            self.assertIn('before deadline', path.read_text())
            self.assertNotEqual(result['returncode'], 0)

    def test_long_lived_log_is_capped_while_process_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.log'
            item = common.LoggedProcess([sys.executable, '-c', 'import os,time; os.write(1,b"x"*1000000); time.sleep(30)'], path, limit=2048)
            item.process.wait(timeout=5)
            with self.assertRaises(common.Refused):
                item.finish()
            self.assertEqual(item.error, 'output overflow')
            self.assertEqual(path.stat().st_size, 2048)

    def test_short_log_is_durable_before_process_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'short.log'
            item = common.LoggedProcess([sys.executable, '-c', 'import time; print("retained now",flush=True); time.sleep(30)'], path)
            deadline = time.monotonic() + 2
            while not path.read_bytes() and time.monotonic() < deadline:
                time.sleep(.01)
            try:
                self.assertIn(b'retained now', path.read_bytes())
                self.assertIsNone(item.process.poll())
            finally:
                run.kill(item.process)
                item.finish()

    def test_qmp_dribbling_has_absolute_deadline(self):
        left, right = socket.socketpair()
        qmp = run.QMP.__new__(run.QMP)
        qmp.socket, qmp.buffer = left, b''
        stop = threading.Event()
        def bytes_slowly():
            while not stop.wait(.01):
                try:
                    right.send(b'x')
                except OSError:
                    break
        thread = threading.Thread(target=bytes_slowly)
        thread.start()
        start = time.monotonic()
        try:
            with self.assertRaises(common.Refused):
                qmp.read(start + .12)
            self.assertLess(time.monotonic() - start, .5)
        finally:
            stop.set()
            left.close()
            right.close()
            thread.join()


class Evidence(unittest.TestCase):
    def test_colorful_console_is_never_a_visual_review_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'frame.ppm'
            path.write_bytes(b'P6\n8 1\n255\n' + b''.join(bytes([i, i, i]) for i in range(8)))
            result = run.inspect_ppm(path)
            self.assertEqual(result['visual_review'], 'NOT RUN')
            self.assertNotIn('status', result)
            path.write_bytes(b'P6\n8 1\n255\n' + b'\x00' * 24)
            with self.assertRaises(common.Refused):
                run.inspect_ppm(path)
            path.write_bytes(b'P6\n8 1\n255\n' + b'\x00' * 25)
            with self.assertRaises(common.Refused):
                run.inspect_ppm(path)

    def test_tooling_receipt_exactly_binds_all_resolved_inputs(self):
        root = Path(__file__).parent
        lock = common.json_load(root / 'tooling.lock.json')
        audit = common.json_load(root / 'tooling-audit.json')
        self.assertEqual(audit['status'], 'PASS')
        self.assertEqual(audit['tooling_lock_sha256'], common.digest(root / 'tooling.lock.json'))
        self.assertEqual(lock['resolver']['exit_code'], 0)
        audit_tooling.validate_lock(lock)
        self.assertEqual({p['name'] for p in lock['packages']}, set(audit['packages']))
        for p in lock['packages']:
            with self.subTest(package=p['name']):
                result = audit['packages'][p['name']]
                self.assertEqual(result['archive_sha256'], p['sha256'])
                self.assertFalse(result['hooks'])
                audit_tooling.verify(result['signature_status'], lock['signer_fingerprint'])

    def test_signature_cannot_be_accepted_with_wrong_signer_or_failure(self):
        lock = common.json_load(Path(__file__).parent / 'tooling.lock.json')
        audit = common.json_load(Path(__file__).parent / 'tooling-audit.json')
        status = next(iter(audit['packages'].values()))['signature_status']
        with self.assertRaises(common.Refused):
            audit_tooling.verify(status, 'A' * 40)
        with self.assertRaises(common.Refused):
            audit_tooling.verify(status + '\n[GNUPG:] REVKEYSIG key\n', lock['signer_fingerprint'])


if __name__ == '__main__':
    unittest.main()
