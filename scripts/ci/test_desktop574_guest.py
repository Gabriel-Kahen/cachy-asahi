"""Inert readiness/cleanup controls: no guest tools or child processes."""
import ast
import getopt
import importlib.util
import inspect
import contextlib
import io
import json
import tempfile
from pathlib import Path
import signal
import stat
import subprocess
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('desktop574_guest', Path(__file__).with_name('desktop574_guest.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestTests(unittest.TestCase):
    def test_guard_refusal_never_opens_event_port_or_powers_off(self):
        console = io.StringIO()
        with patch.object(guest.sys, 'argv', ['guest', 'boot']), \
             patch.object(guest, 'guard', side_effect=ValueError('synthetic guest guard refusal')), \
             patch.object(guest.os, 'open') as open_port, \
             patch.object(guest.subprocess, 'run') as run, contextlib.redirect_stderr(console):
            self.assertEqual(guest.main(), 1)
        open_port.assert_not_called()
        run.assert_not_called()
        self.assertIn('synthetic guest guard refusal', console.getvalue())

    def test_missing_event_port_and_failed_emit_still_power_off_guarded_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'missing-port'
            with patch.object(guest, 'guard') as guard, patch.object(guest, 'EVENTS', missing), \
                 patch.object(guest, 'emit', side_effect=OSError('synthetic transport failure')), \
                 patch.object(guest.subprocess, 'run') as run:
                with self.assertRaises(FileNotFoundError) as caught:
                    guest.boot()
            guard.assert_called_once_with(True)
            self.assertEqual(caught.exception.filename, str(missing))
            run.assert_called_once_with(['/usr/bin/systemctl', 'poweroff'],
                env=dict(guest.ENV, CACHY_ASAHI_VIRTUAL_GUEST='1', SEATD_VTBOUND='0'), timeout=10, check=True)

    def test_emit_uses_dedicated_port_without_creating_a_missing_device(self):
        with tempfile.TemporaryDirectory() as directory:
            port = Path(directory) / 'event-port'
            port.touch(mode=0o600)
            console = io.StringIO()
            with patch.object(guest, 'EVENTS', port, create=True), contextlib.redirect_stdout(console):
                guest.emit('process_exit', logs=[dict(tail_base64='A' * 6000)])
            self.assertEqual(console.getvalue(), '')
            line = port.read_text()
            self.assertGreater(len(line), 4096)
            self.assertTrue(line.endswith('\n'))
            self.assertEqual(json.loads(line.removeprefix('DESKTOP574_EVENT ')),
                             dict(event='process_exit', logs=[dict(tail_base64='A' * 6000)]))
            port.unlink()
            with patch.object(guest, 'EVENTS', port, create=True):
                with self.assertRaises(FileNotFoundError):
                    guest.emit('boot')
            self.assertFalse(port.exists())

    def test_seatd_compiled_socket_and_supported_cli(self):
        # Evaluate the actual boot call without starting a child process.
        tree = ast.parse(inspect.getsource(guest.boot))
        call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Name) and node.func.id == 'Logged')
        with patch.object(guest, 'Logged') as logged:
            eval(compile(ast.Expression(call), '<boot-seatd-call>', 'eval'),
                 guest.__dict__, dict(logs=Path('/inert'), env={}))
        argv = logged.call_args.args[0]
        self.assertEqual(argv[0], '/usr/bin/seatd')
        # Exact getopt option string from the pinned 0.9.3 daemon.
        options, rest = getopt.getopt(argv[1:], 'vhn:g:u:l:z')
        self.assertEqual(options, [('-u', 'desktop574'), ('-g', 'desktop574'), ('-l', 'info')])
        self.assertEqual(rest, [])
        self.assertEqual(guest.SEAT, '/run/seatd.sock')
        # Refuse preexisting entries before the production launch call.
        body = next(node for node in tree.body[0].body if isinstance(node, ast.Try)).body
        launch = next(i for i, node in enumerate(body) if isinstance(node, ast.Assign) and
                      any(isinstance(n, ast.Name) and n.id == 'seatd' for n in node.targets))
        check = compile(ast.Module(body=[body[launch - 1]], type_ignores=[]), '<seat-path-guard>', 'exec')
        with patch.object(guest.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(ValueError, 'preexisting seatd socket path'):
                exec(check, guest.__dict__)
        with patch.object(guest.os.path, 'lexists', return_value=False):
            exec(check, guest.__dict__)

    def test_seat_readiness_waits_for_final_socket_attributes(self):
        def entry(mode=stat.S_IFSOCK | 0o770, uid=23001, gid=23001):
            return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)
        states = [FileNotFoundError(), entry(uid=0, gid=0), entry(mode=stat.S_IFSOCK | 0o700),
                  entry(mode=stat.S_IFREG | 0o770), entry(mode=stat.S_IFLNK | 0o770), entry()]
        with patch.object(guest, 'Path') as path:
            path.return_value.lstat.side_effect = states
            self.assertEqual([guest.ready_seat() for _ in states], [False] * 5 + [True])

    def test_configuration_readiness_rejects_reported_errors(self):
        for value in ([], ['']):
            self.assertTrue(guest.ready_config(value))
        for value in ('', None, {}, ['unknown setting'], ['', '']):
            self.assertFalse(guest.ready_config(value))

    def test_monitor_and_actual_client_mapping_required(self):
        self.assertTrue(guest.usable_monitors([dict(width=800, height=600)]))
        for value in ([], [dict(width=0, height=600)], [dict(width=True, height=600)]):
            self.assertFalse(guest.usable_monitors(value))
        good = dict(pid=41, mapped=True, size=[420, 220])
        self.assertTrue(guest.mapped_client([good], 41))
        for delta in (dict(pid=42), dict(mapped=False), dict(size=[0, 220]), dict(size=[True, 220])):
            self.assertFalse(guest.mapped_client([dict(good, **delta)], 41))

    def test_already_exited_process_is_never_signalled(self):
        process = Mock(returncode=0)
        process.poll.return_value = 0
        with patch.object(guest.os, 'killpg') as kill:
            self.assertEqual(guest.terminate(process), 0)
            kill.assert_not_called()
            process.wait.assert_not_called()

    def test_term_timeout_escalates_and_reaps(self):
        process = Mock(pid=41)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('inert', 3), -9]
        with patch.object(guest.os, 'killpg') as kill:
            self.assertEqual(guest.terminate(process), -9)
            self.assertEqual(kill.call_args_list[0].args, (41, signal.SIGTERM))
            self.assertEqual(kill.call_args_list[1].args, (41, signal.SIGKILL))
            self.assertEqual(process.wait.call_count, 2)

    def test_signal_failure_still_waits_and_keeps_first(self):
        process = Mock(pid=41)
        process.poll.return_value = None
        first = OSError('synthetic signal fault')
        process.wait.return_value = 0
        with patch.object(guest.os, 'killpg', side_effect=first):
            with self.assertRaises(OSError) as caught:
                guest.terminate(process)
            self.assertIs(caught.exception, first)
            process.wait.assert_called_once_with(timeout=3)

    def test_command_timeout_cleanup_does_not_replace_primary(self):
        first = subprocess.TimeoutExpired('inert', 1)
        logged = Mock()
        logged.process.wait.side_effect = first
        logged.finish.side_effect = ValueError('synthetic log failure')
        with patch.object(guest, 'Logged', return_value=logged), patch.object(guest, 'terminate') as retire:
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                guest.command(['inert'], {}, Path('/inert'), 'inert', timeout=1)
            self.assertIs(caught.exception, first)
            retire.assert_called_once_with(logged.process)
            logged.finish.assert_called_once()


if __name__ == '__main__':
    unittest.main()
