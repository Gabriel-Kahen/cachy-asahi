"""Inert readiness/cleanup controls: no guest tools or child processes."""
import ast
import base64
import hashlib
import getopt
import importlib.util
import inspect
import contextlib
import io
import json
import shlex
import tempfile
from pathlib import Path
import signal
import stat
import subprocess
import unittest
from unittest.mock import MagicMock, Mock, patch
from types import SimpleNamespace
from contextlib import ExitStack

spec = importlib.util.spec_from_file_location('desktop574_guest', Path(__file__).with_name('desktop574_guest.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestTests(unittest.TestCase):
    def test_event_port_matches_exact_kernel_name_type_and_device_number(self):
        with tempfile.TemporaryDirectory() as directory:
            sysfs, devices = Path(directory) / 'sysfs', Path(directory) / 'dev'
            sysfs.mkdir(); devices.mkdir()
            self.assertIsNone(guest.event_port(sysfs, devices))
            port = sysfs / 'vport0p1'; port.mkdir()
            self.assertIsNone(guest.event_port(sysfs, devices))
            (port / 'name').write_text('desktop574.events\n')
            (port / 'dev').write_text('240:1\n')
            node = devices / port.name
            self.assertIsNone(guest.event_port(sysfs, devices))
            node.touch()
            with self.assertRaisesRegex(ValueError, 'character-device identity'):
                guest.event_port(sysfs, devices)
            value = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=guest.os.makedev(240, 1))
            with patch.object(Path, 'lstat', return_value=value):
                self.assertEqual(guest.event_port(sysfs, devices), node)
                value.st_rdev = guest.os.makedev(240, 2)
                with self.assertRaisesRegex(ValueError, 'character-device identity'):
                    guest.event_port(sysfs, devices)
            node.unlink(); node.symlink_to('/inert')
            with self.assertRaisesRegex(ValueError, 'character-device identity'):
                guest.event_port(sysfs, devices)
            (port / 'name').write_text('wrong-channel\n')
            with self.assertRaisesRegex(ValueError, 'wrong event port name'):
                guest.event_port(sysfs, devices)
            (sysfs / 'vport1p1').mkdir()
            with self.assertRaisesRegex(ValueError, 'ambiguous event ports'):
                guest.event_port(sysfs, devices)

    def test_event_port_wait_keeps_twenty_second_deadline(self):
        with patch.object(guest, 'event_port', side_effect=[None, Path('/inert/vport0p1')]) as probe, \
             patch.object(guest.time, 'monotonic', side_effect=[0, 0, 19.9]), \
             patch.object(guest.time, 'sleep'):
            self.assertEqual(guest.wait_event_port(), Path('/inert/vport0p1'))
            self.assertEqual(probe.call_count, 2)
        with patch.object(guest, 'event_port', return_value=None) as probe, \
             patch.object(guest.time, 'monotonic', side_effect=[0, 0, 20]), \
             patch.object(guest.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'event port readiness deadline'):
                guest.wait_event_port()
            self.assertEqual(probe.call_count, 1)

    def test_user_revalidates_event_identity_and_private_access_after_guard(self):
        body = ast.parse(inspect.getsource(guest.user)).body[0].body[:6]
        code = compile(ast.Module(body=body, type_ignores=[]), '<user-event-boundary>', 'exec')
        node = Mock()
        value = SimpleNamespace(st_uid=23001, st_gid=23001, st_mode=stat.S_IFCHR | 0o600)
        node.lstat.return_value = value
        with patch.object(guest, 'EVENTS', None), patch.object(guest, 'guard') as guard, \
             patch.object(guest, 'event_port', return_value=node) as resolve:
            exec(code, guest.__dict__)
            guard.assert_called_once_with(False)
            resolve.assert_called_once_with()
            for values in (dict(st_uid=0), dict(st_gid=0), dict(st_mode=stat.S_IFCHR | 0o666)):
                with self.subTest(values=values):
                    node.lstat.return_value = SimpleNamespace(**(value.__dict__ | values))
                    with self.assertRaisesRegex(ValueError, 'private user event port'):
                        exec(code, guest.__dict__)
            guard.side_effect = ValueError('synthetic guard refusal')
            resolve.reset_mock()
            with self.assertRaisesRegex(ValueError, 'guard refusal'):
                exec(code, guest.__dict__)
            resolve.assert_not_called()

    def test_drm_kernel_identity_refuses_wrong_type_number_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            sysfs, devices = Path(directory) / 'sysfs', Path(directory) / 'dev'
            sysfs.mkdir(); devices.mkdir()
            self.assertIsNone(guest.drm_card(sysfs, devices))
            card = sysfs / 'card0'; card.mkdir()
            (sysfs / 'card0-Virtual-1').mkdir()  # Connector is not a primary card.
            (card / 'dev').write_text('226:0\n')
            parent = card / 'device'; parent.mkdir()
            (parent / 'vendor').write_text('0x1af4')
            (parent / 'device').write_text('0x1050')
            (parent / 'driver').symlink_to('/inert/virtio-pci')
            child = parent / 'virtio2'; child.mkdir()
            (child / 'driver').symlink_to('/inert/virtio_gpu')
            self.assertIsNone(guest.drm_card(sysfs, devices))
            node = devices / 'card0'; node.touch()
            with self.assertRaisesRegex(ValueError, 'character-device identity'):
                guest.drm_card(sysfs, devices)
            value = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=guest.os.makedev(226, 0))
            with patch.object(Path, 'lstat', return_value=value):
                self.assertEqual(guest.drm_card(sysfs, devices), node)
                for name, wrong in (('vendor', '0xffff'), ('device', '0x1042')):
                    saved = (parent / name).read_text()
                    (parent / name).write_text(wrong)
                    with self.assertRaisesRegex(ValueError, 'wrong DRM PCI'):
                        guest.drm_card(sysfs, devices)
                    (parent / name).write_text(saved)
                (child / 'driver').unlink()
                self.assertIsNone(guest.drm_card(sysfs, devices))
                (child / 'driver').symlink_to('/inert/other')
                with self.assertRaisesRegex(ValueError, 'wrong DRM virtio driver'):
                    guest.drm_card(sysfs, devices)
                (child / 'driver').unlink()
                (child / 'driver').symlink_to('/inert/virtio_gpu')
                (parent / 'virtio3').mkdir()
                with self.assertRaisesRegex(ValueError, 'ambiguous DRM virtio'):
                    guest.drm_card(sysfs, devices)
                (parent / 'virtio3').rmdir()
                value.st_rdev = guest.os.makedev(226, 1)
                with self.assertRaisesRegex(ValueError, 'character-device identity'):
                    guest.drm_card(sysfs, devices)
                value.st_rdev = guest.os.makedev(226, 0)
                for text in ('227:0', '226:1', '226:64'):
                    (card / 'dev').write_text(text)
                    with self.assertRaisesRegex(ValueError, 'character-device identity'):
                        guest.drm_card(sysfs, devices)
            (card / 'dev').write_text('226:0')
            node.unlink(); node.symlink_to('/inert')
            with self.assertRaisesRegex(ValueError, 'character-device identity'):
                guest.drm_card(sysfs, devices)
            (devices / 'card1').touch()
            with self.assertRaisesRegex(ValueError, 'ambiguous DRM'):
                guest.drm_card(sysfs, devices)
            (devices / 'card1').unlink()
            (sysfs / 'card1').mkdir()
            with self.assertRaisesRegex(ValueError, 'ambiguous DRM'):
                guest.drm_card(sysfs, devices)

    def test_drm_wait_keeps_twenty_second_deadline(self):
        card = Path('/inert/card0')
        with patch.object(guest, 'drm_card', side_effect=[None, card]) as probe, \
             patch.object(guest, 'drm_render_node', return_value=Path('/inert/renderD128')), \
             patch.object(guest.time, 'monotonic', side_effect=[0, 0, 19.9]), \
             patch.object(guest.time, 'sleep'):
            self.assertEqual(guest.wait_drm_card(), card)
            self.assertEqual(probe.call_count, 2)
        with patch.object(guest, 'drm_card', return_value=None) as probe, \
             patch.object(guest.time, 'monotonic', side_effect=[0, 0, 20]), \
             patch.object(guest.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'DRM readiness deadline'):
                guest.wait_drm_card()
            self.assertEqual(probe.call_count, 1)

    def test_private_rules_and_kernel_readiness_before_drm_ownership(self):
        fixture = Path(guest.__file__).with_name('desktop574_fixture.sh').read_text()
        pre = [shlex.split(line.removeprefix('ExecStartPre=')) for line in fixture.splitlines()
               if line.startswith('ExecStartPre=')]
        self.assertEqual(pre, [['/usr/bin/modprobe', 'virtio_console']])
        self.assertIn('SUBSYSTEM=="virtio-ports", KERNEL=="vport*", ATTR{name}=="desktop574.events", '
                      'OWNER:="23001", GROUP:="23001", MODE:="0600"', fixture)
        self.assertIn('SUBSYSTEM=="drm", KERNEL=="card[0-9]*", KERNEL!="card*-*", SUBSYSTEMS=="pci", ATTRS{vendor}=="0x1af4", ATTRS{device}=="0x1050", DRIVERS=="virtio-pci", '
                      'OWNER:="23001", GROUP:="23001", MODE:="0600"', fixture)
        tree = ast.parse(inspect.getsource(guest.boot))
        body = next(node.body for node in tree.body[0].body if isinstance(node, ast.Try))
        index = next(i for i, node in enumerate(body) if isinstance(node, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == 'card' for target in node.targets))
        code = compile(ast.Module(body=body[index:index + 3], type_ignores=[]), '<drm-readiness>', 'exec')
        card = Mock()
        with patch.object(guest, 'wait_drm_card', return_value=card) as wait, \
             patch.object(guest.os, 'chown') as chown:
            exec(code, guest.__dict__, {})
            chown.assert_called_once_with(card, 23001, 23001)
            card.chmod.assert_called_once_with(0o600)
            chown.reset_mock(); card.chmod.reset_mock()
            wait.side_effect = ValueError('synthetic DRM readiness failure')
            with self.assertRaisesRegex(ValueError, 'DRM readiness failure'):
                exec(code, guest.__dict__, {})
            chown.assert_not_called(); card.chmod.assert_not_called()
        self.assertNotIn('udevadm', inspect.getsource(guest.boot))

    def test_user_revalidates_private_drm_card_before_gbm(self):
        body = ast.parse(inspect.getsource(guest.user)).body[0].body
        start = next(i for i, node in enumerate(body) if isinstance(node, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == 'card' for target in node.targets))
        code = compile(ast.Module(body=body[start:start + 5], type_ignores=[]), '<user-drm>', 'exec')
        card = Mock()
        value = SimpleNamespace(st_uid=23001, st_gid=23001, st_mode=stat.S_IFCHR | 0o600)
        card.lstat.return_value = value
        with patch.object(guest, 'drm_card', return_value=card) as resolve, \
             patch.object(guest, 'command', return_value='{"status":"PASS"}') as command:
            scope = dict(env={}, logs=Path('/inert'))
            exec(code, guest.__dict__, dict(scope))
            command.assert_called_once()
            command.reset_mock()
            for delta in (dict(st_uid=0), dict(st_gid=0), dict(st_mode=stat.S_IFCHR | 0o660)):
                card.lstat.return_value = SimpleNamespace(**(value.__dict__ | delta))
                with self.assertRaisesRegex(ValueError, 'private user DRM'):
                    exec(code, guest.__dict__, dict(scope))
            resolve.return_value = None
            with self.assertRaisesRegex(ValueError, 'DRM card unavailable'):
                exec(code, guest.__dict__, dict(scope))
            command.assert_not_called()

    def test_only_cleanly_retired_command_timeout_can_retry(self):
        first = subprocess.TimeoutExpired('inert', 3)
        logged = Mock()
        logged.process.wait.side_effect = first
        with patch.object(guest, 'Logged', return_value=logged), patch.object(guest, 'terminate') as retire:
            self.assertIsNone(guest.command(['inert'], {}, Path('/inert'), 'inert', timeout=3, retry_timeout=True))
            retire.assert_called_once_with(logged.process)
            logged.finish.assert_called_once()
            logged.finish.side_effect = ValueError('synthetic incomplete log cleanup')
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                guest.command(['inert'], {}, Path('/inert'), 'inert', timeout=3, retry_timeout=True)
            self.assertIs(caught.exception, first)
            logged.finish.side_effect = None
            retire.side_effect = OSError('synthetic reap failure')
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                guest.command(['inert'], {}, Path('/inert'), 'inert', timeout=3, retry_timeout=True)
            self.assertIs(caught.exception, first)

    def test_client_mapping_probe_timeout_retries_within_existing_bound(self):
        tree = ast.parse(inspect.getsource(guest.phase))
        loop = next(node for node in ast.walk(tree) if isinstance(node, ast.For) and
                    isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name) and
                    node.iter.func.id == 'range' and ast.literal_eval(node.iter.args[0]) == 20)
        code = compile(ast.Module(body=[loop], type_ignores=[]), '<client-readiness-loop>', 'exec')
        client, compositor = Mock(), Mock()
        client.process.pid = 41
        mapped = json.dumps([dict(pid=41, mapped=True, size=[420, 220])])
        logged = Mock()
        logged.process.wait.side_effect = [subprocess.TimeoutExpired('inert-hyprctl', 3), 0]
        logged.process.returncode = 0
        logged.paths = [Mock()]
        logged.paths[0].read_text.return_value = mapped
        with patch.object(guest, 'command', wraps=guest.command) as command, \
             patch.object(guest, 'Logged', return_value=logged), patch.object(guest, 'terminate'), \
             patch.object(guest.time, 'sleep'):
            scope = dict(guest.__dict__, client=client, compositor=compositor,
                         selected={}, logs=Path('/inert'), stage='minimal')
            exec(code, scope)
        self.assertEqual(command.call_count, 2)
        self.assertTrue(all(call.args[0] == ['/usr/bin/hyprctl', '-j', 'clients', '-a']
                            for call in command.call_args_list))
        self.assertEqual(client.healthy.call_count, 2)
        self.assertEqual(compositor.healthy.call_count, 2)
        self.assertTrue(all(call.kwargs == dict(timeout=3, retry_timeout=True) for call in command.call_args_list))
        command = Mock(return_value=None)
        scope['command'] = command
        with self.assertRaisesRegex(ValueError, 'Wofi mapping deadline'):
            exec(code, scope)
        self.assertEqual(command.call_count, 20)
        command.reset_mock(side_effect=True)
        command.return_value = json.dumps([dict(pid=41, mapped=False, size=[420, 220]),
                                          dict(pid=42, mapped=True, size=[420, 220]),
                                          dict(pid=41, mapped=True, size=[0, 220])])
        with self.assertRaisesRegex(ValueError, 'Wofi mapping deadline'), patch.object(guest.time, 'sleep'):
            exec(code, scope)
        self.assertEqual(command.call_count, 20)
        command.reset_mock(side_effect=True)
        command.return_value = '{invalid JSON'
        with self.assertRaises(json.JSONDecodeError):
            exec(code, scope)
        self.assertEqual(command.call_count, 1)

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
            failure = FileNotFoundError(2, 'synthetic missing kernel event port', str(missing))
            with patch.object(guest, 'guard') as guard, patch.object(guest, 'EVENTS', missing), \
                 patch.object(guest, 'wait_event_port', side_effect=failure), \
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
            other = Path(directory) / 'other'
            other.write_text('held')
            port.symlink_to(other)
            with patch.object(guest, 'EVENTS', port):
                with self.assertRaises(OSError):
                    guest.emit('boot')
            self.assertEqual(other.read_text(), 'held')

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


class DiagnosticTests(unittest.TestCase):
    @staticmethod
    def metadata(data, **delta):
        return SimpleNamespace(**(dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
            st_uid=23001, st_gid=23001, st_nlink=1, st_size=len(data),
            st_mtime_ns=3, st_ctime_ns=4) | delta))

    def read_file(self, data, *, before=None, after=None, named=None, named_error=None,
                  read_error=None, short=False):
        before = before or self.metadata(data)
        after = after or before
        named = named or after
        position, lengths = [0], []
        def seek(fd, offset, mode):
            self.assertEqual((fd, mode), (17, guest.os.SEEK_SET))
            position[0] = offset
        def read(fd, size):
            lengths.append(size)
            if read_error is not None:
                raise read_error
            result = data[position[0]:position[0] + size]
            return result[:-1] if short and result else result
        with ExitStack() as stack:
            opened = stack.enter_context(patch.object(guest.os, 'open', return_value=17))
            stack.enter_context(patch.object(guest.os, 'fstat', side_effect=[before, after]))
            stack.enter_context(patch.object(guest.os, 'stat', return_value=named, side_effect=named_error))
            stack.enter_context(patch.object(guest.os, 'lseek', side_effect=seek))
            stack.enter_context(patch.object(guest.os, 'read', side_effect=read))
            closed = stack.enter_context(patch.object(guest.os, 'close'))
            try:
                result = guest.diagnostic_file(11, 'hyprland.log')
            finally:
                closed.assert_called_once_with(17)
            self.assertEqual(opened.call_args.kwargs, {'dir_fd': 11})
            flags = opened.call_args.args[1]
            self.assertTrue(flags & guest.os.O_NOFOLLOW and flags & guest.os.O_NONBLOCK)
            self.assertFalse(flags & guest.os.O_CREAT)
        return result, lengths

    def test_full_and_empty_file_hashes_are_truthful(self):
        for raw in (b'', b'actual synthetic diagnostic\n', b'x' * guest.MAX_LOG):
            with self.subTest(size=len(raw)):
                result, lengths = self.read_file(raw)
                self.assertEqual(result['status'], 'present')
                self.assertEqual(base64.b64decode(result['content_base64']), raw)
                self.assertEqual(result['source_bytes'], len(raw))
                self.assertEqual(result['retained_bytes'], len(raw))
                self.assertFalse(result['truncated'])
                self.assertEqual(result['full_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(result['retained_sha256'], result['full_sha256'])
                self.assertEqual(result['segments'], [dict(offset=0, bytes=len(raw))])
                self.assertLessEqual(sum(lengths), guest.MAX_LOG)

    def test_oversize_retains_only_head_tail_without_full_hash(self):
        half = guest.MAX_LOG // 2
        raw = b'h' * half + b'not retained' * 100 + b't' * half
        result, lengths = self.read_file(raw)
        retained = raw[:half] + raw[-half:]
        self.assertTrue(result['truncated'])
        self.assertEqual(result['source_bytes'], len(raw))
        self.assertEqual(result['retained_bytes'], guest.MAX_LOG)
        self.assertEqual(result['segments'], [dict(offset=0, bytes=half),
                         dict(offset=len(raw) - half, bytes=half)])
        self.assertEqual(base64.b64decode(result['content_base64']), retained)
        self.assertEqual(result['retained_sha256'], hashlib.sha256(retained).hexdigest())
        self.assertNotIn('full_sha256', result)
        self.assertEqual(lengths, [half, half])

    def test_file_shape_drift_and_read_failures_refuse_and_close(self):
        raw = b'diagnostic'
        for delta in (dict(st_uid=0), dict(st_nlink=2), dict(st_mode=stat.S_IFIFO | 0o600),
                      dict(st_mode=stat.S_IFLNK | 0o600)):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                self.read_file(raw, before=self.metadata(raw, **delta))
        for field in ('st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                value = getattr(self.metadata(raw), field)
                self.read_file(raw, after=self.metadata(raw, **{field: value + 1}))
        with self.assertRaises(ValueError):
            self.read_file(raw, named=self.metadata(raw, st_ino=99))
        with self.assertRaises(ValueError):
            self.read_file(raw, short=True)
        with self.assertRaises(ValueError):
            self.read_file(raw, named_error=FileNotFoundError())
        failure = OSError('synthetic read failure')
        with self.assertRaises(OSError) as caught:
            self.read_file(raw, read_error=failure)
        self.assertIs(caught.exception, failure)
        for name in ('', '.', '..', '../other', '/other', 'bad\x00name'):
            with patch.object(guest.os, 'open') as opened, self.assertRaises(ValueError):
                guest.diagnostic_file(11, name)
            opened.assert_not_called()

    def test_directory_walk_is_nofollow_owned_and_retires_current_fd(self):
        with patch.object(guest.os, 'open', side_effect=[10, 11, 12]) as opened, \
             patch.object(guest.os, 'fstat', return_value=SimpleNamespace(st_uid=23001)), \
             patch.object(guest.os, 'close') as closed:
            self.assertEqual(guest.diagnostic_directory(Path('/fixed/leaf')), 12)
            self.assertEqual([call.args[0] for call in closed.call_args_list], [10, 11])
            for call in opened.call_args_list[1:]:
                self.assertTrue(call.args[1] & guest.os.O_NOFOLLOW)
                self.assertTrue(call.args[1] & guest.os.O_DIRECTORY)
        for owner in (0, 23002):
            with patch.object(guest.os, 'open', side_effect=[10, 11]), \
                 patch.object(guest.os, 'fstat', return_value=SimpleNamespace(st_uid=owner)), \
                 patch.object(guest.os, 'close') as closed, self.assertRaises(ValueError):
                guest.diagnostic_directory(Path('/leaf'))
            self.assertEqual([call.args[0] for call in closed.call_args_list], [10, 11])
        with patch.object(guest.os, 'open', side_effect=[10, 11]), \
             patch.object(guest.os, 'close', side_effect=[OSError('synthetic old close'), None]) as closed:
            with self.assertRaises(OSError):
                guest.diagnostic_directory(Path('/leaf'))
            self.assertEqual([call.args[0] for call in closed.call_args_list], [10, 11])
        for path in (Path('relative'), Path('/fixed/../other')):
            with patch.object(guest.os, 'open') as opened, self.assertRaises(ValueError):
                guest.diagnostic_directory(path)
            opened.assert_not_called()

    def test_collector_exact_pid_and_only_one_instance(self):
        records, paths, files = [], [], []
        def directory(path):
            paths.append(path)
            return 11 if len(paths) == 1 else 12
        def file(directory, name):
            files.append((directory, name))
            return dict(status='present', source_bytes=0, retained_bytes=0)
        entries = Mock()
        entries.__enter__ = Mock(return_value=iter([SimpleNamespace(name='sole-instance')]))
        entries.__exit__ = Mock(return_value=False)
        with patch.object(guest, 'diagnostic_directory', side_effect=directory), \
             patch.object(guest, 'diagnostic_file', side_effect=file), \
             patch.object(guest.os, 'scandir', return_value=entries), \
             patch.object(guest.os, 'open', return_value=13) as opened, \
             patch.object(guest.os, 'fstat', return_value=SimpleNamespace(st_uid=23001)), \
             patch.object(guest.os, 'close'), \
             patch.object(guest, 'emit', side_effect=lambda event, **row: records.append((event, row))):
            guest.collect_phase_diagnostics('minimal', 42)
        self.assertEqual(paths, [guest.HOME / 'cache/hyprland', guest.RUNTIME / 'hypr'])
        self.assertEqual(files, [(11, 'hyprlandCrashReport42.txt'), (13, 'hyprland.log')])
        self.assertEqual(opened.call_args.args[0], 'sole-instance')
        self.assertTrue(opened.call_args.args[1] & guest.os.O_NOFOLLOW)
        self.assertEqual([row['name'] for _, row in records], ['crash', 'compositor'])
        self.assertTrue(all(event == 'diagnostic_file' and row['pid'] == 42 for event, row in records))
        self.assertEqual([row['path'] for _, row in records],
                         [str(guest.HOME / 'cache/hyprland/hyprlandCrashReport42.txt'),
                          str(guest.RUNTIME / 'hypr/sole-instance/hyprland.log')])

    def test_collector_absence_errors_and_ambiguous_scan_are_bounded(self):
        records = []
        consumed = []
        def entries():
            for name in ('first', 'second', 'never-inspect-third'):
                consumed.append(name)
                yield SimpleNamespace(name=name)
        scan = MagicMock()
        scan.__enter__.return_value = entries()
        with patch.object(guest, 'diagnostic_directory', return_value=11), \
             patch.object(guest, 'diagnostic_file', side_effect=FileNotFoundError()), \
             patch.object(guest.os, 'scandir', return_value=scan), \
             patch.object(guest.os, 'close'), \
             patch.object(guest, 'emit', side_effect=lambda event, **row: records.append(row)):
            guest.collect_phase_diagnostics('overlay', 42)
        self.assertEqual(consumed, ['first', 'second'])
        self.assertEqual([row['status'] for row in records], ['absent', 'error'])
        self.assertEqual(records[1]['reason'], 'diagnostic collection failed')
        records.clear()
        with patch.object(guest, 'diagnostic_directory', side_effect=OSError('private path must not escape')), \
             patch.object(guest, 'emit', side_effect=lambda event, **row: records.append(row)):
            guest.collect_phase_diagnostics('minimal', 42)
        self.assertEqual([row['status'] for row in records], ['error', 'error'])
        self.assertNotIn('private path', repr(records))

    def test_phase_observes_before_cleanup_and_diagnostics_keep_falsey_primary(self):
        class FalseyError(ValueError):
            def __bool__(self):
                return False
        first = FalseyError('synthetic first')
        for diagnostic_fault in (None, OSError('synthetic collection'), KeyboardInterrupt()):
            with self.subTest(fault=type(diagnostic_fault).__name__):
                order, records = [], []
                compositor = Mock()
                compositor.process.pid = 42
                compositor.process.poll.side_effect = lambda: order.append('poll') or None
                compositor.finish.side_effect = lambda: order.append('finish')
                def retire(process):
                    order.append('terminate')
                    process.returncode = -15
                def collect(stage, pid):
                    order.append('collect')
                    if diagnostic_fault is not None:
                        raise diagnostic_fault
                def emit(event, **row):
                    order.append(event)
                    records.append((event, row))
                runtime = Mock()
                runtime.glob.return_value = []
                with patch.object(guest, 'RUNTIME', runtime), \
                     patch.object(guest, 'Logged', return_value=compositor), \
                     patch.object(guest, 'ipc', side_effect=first), \
                     patch.object(guest, 'terminate', side_effect=retire), \
                     patch.object(guest, 'collect_phase_diagnostics', side_effect=collect), \
                     patch.object(guest, 'emit', side_effect=emit):
                    with self.assertRaises(FalseyError) as caught:
                        guest.phase('minimal', Path('/inert/config'), {}, Path('/inert/logs'))
                self.assertIs(caught.exception, first)
                self.assertEqual(order, ['poll', 'terminate', 'finish', 'phase_diagnostic', 'collect'])
                self.assertIsNone(records[0][1]['returncode_before_cleanup'])
                self.assertFalse(any(event in ('failed', 'failure', 'phase_pass') for event, _ in records))

    def test_phase_poll_and_event_faults_cannot_replace_primary_or_skip_retirement(self):
        first = ValueError('synthetic primary')
        compositor = Mock()
        compositor.process.pid = 42
        compositor.process.poll.side_effect = OSError('synthetic poll fault')
        runtime = Mock()
        runtime.glob.return_value = []
        with patch.object(guest, 'RUNTIME', runtime), \
             patch.object(guest, 'Logged', return_value=compositor), \
             patch.object(guest, 'ipc', side_effect=first), \
             patch.object(guest, 'terminate') as retire, \
             patch.object(guest, 'emit', side_effect=KeyboardInterrupt()), \
             patch.object(guest, 'collect_phase_diagnostics') as collect:
            with self.assertRaises(ValueError) as caught:
                guest.phase('minimal', Path('/inert/config'), {}, Path('/inert/logs'))
        self.assertIs(caught.exception, first)
        retire.assert_called_once_with(compositor.process)
        compositor.finish.assert_called_once()
        collect.assert_not_called()

    def test_successful_phase_keeps_acceptance_and_does_not_collect(self):
        compositor, client = Mock(), Mock()
        compositor.process.returncode = 0
        compositor.process.poll.return_value = 0
        client.process.pid = 43
        socket = Mock(name='private_wayland_socket')
        socket.name = 'wayland-1'
        socket.is_socket.return_value = True
        runtime = Mock()
        runtime.glob.side_effect = [[], [socket]]
        replies = [json.dumps([dict(width=1024, height=768)]),
                   json.dumps([dict(pid=43, mapped=True, size=[420, 220])]), '']
        env = dict(AT_BRIDGE='held', GDK_BACKEND='wayland')
        selected = dict(env)
        with patch.object(guest, 'RUNTIME', runtime), \
             patch.object(guest, 'Logged', side_effect=[compositor, client]) as launch, \
             patch.object(guest, 'ipc', return_value=selected), \
             patch.object(guest, 'command', side_effect=replies) as command, \
             patch.object(guest.time, 'monotonic', side_effect=[0, 0, 9]), \
             patch.object(guest, 'owned_thread_state', return_value=dict(status='unavailable')), \
             patch.object(guest, 'terminate'), patch.object(guest, 'emit') as emit, \
             patch.object(guest, 'collect_phase_diagnostics') as collect:
            guest.phase('minimal', Path('/inert/config'), env, Path('/inert/logs'))
        self.assertIs(launch.call_args_list[0].args[3], env)
        wofi = launch.call_args_list[1]
        self.assertEqual(wofi.args[3], dict(selected, WAYLAND_DEBUG='client'))
        self.assertIsNot(wofi.args[3], selected)
        self.assertNotIn('WAYLAND_DEBUG', selected)
        self.assertEqual(env, dict(AT_BRIDGE='held', GDK_BACKEND='wayland'))
        self.assertEqual(wofi.args[0], ['/usr/bin/wofi', '--normal-window', '--show', 'dmenu',
            '--prompt', 'Generic ARM desktop574', '--width', '420', '--height', '220'])
        self.assertEqual(wofi.kwargs, dict(stdin=subprocess.PIPE))
        client.process.stdin.write.assert_called_once_with(
            b'574 packages: generic ARM software session\nNo Apple hardware claim\n')
        client.process.stdin.close.assert_called_once_with()
        self.assertTrue(all(call.args[1] is selected for call in command.call_args_list))
        self.assertTrue(all('WAYLAND_DEBUG' not in call.args[1] for call in command.call_args_list))
        self.assertEqual([call.args[0] for call in emit.call_args_list], ['frame_ready', 'phase_pass'])
        self.assertEqual(command.call_args_list[-1].args[0], ['/usr/bin/hyprctl', 'dispatch', 'hl.dsp.exit()'])
        self.assertEqual(command.call_args_list[-1].kwargs, dict(timeout=5))
        compositor.process.wait.assert_called_once_with(timeout=10)
        compositor.finish.assert_called_once()
        client.finish.assert_called_once()
        collect.assert_not_called()


class WofiLogTests(unittest.TestCase):
    def captured(self, directory, name, raw, *, fault=False, alive=False):
        logged = guest.Logged.__new__(guest.Logged)
        logged.paths = [Path(directory) / (name + suffix) for suffix in ('.stdout', '.stderr')]
        logged.errors, logged.overflow = [], False
        logged.process = Mock(pid=350, returncode=0)
        logged.process.poll.return_value = 0
        logged.threads = [Mock(), Mock()]
        for thread in logged.threads:
            thread.is_alive.return_value = alive
        for path, data in zip(logged.paths, (b'output', raw)):
            guest.Logged.drain(logged, io.BytesIO(data), path)
        if fault:
            logged.errors.append(OSError('synthetic drain failure'))
        return logged

    def test_full_capped_wofi_stderr_preserves_startup_and_pid(self):
        for name in ('minimal-wofi', 'overlay-wofi'):
            for raw in (b'', b'get_toplevel\n' + b'x' * (guest.MAX_LOG - 13)):
                with self.subTest(name=name, size=len(raw)), tempfile.TemporaryDirectory() as directory:
                    logged = self.captured(directory, name, raw)
                    with patch.object(guest, 'emit') as emit:
                        logged.finish()
                    row = emit.call_args.kwargs
                    self.assertEqual(row['pid'], 350)
                    stderr = row['logs'][1]
                    self.assertTrue(stderr['capture_complete'])
                    self.assertEqual(base64.b64decode(stderr['content_base64']), raw)
                    self.assertEqual(base64.b64decode(stderr['tail_base64']), raw[-4096:])
                    self.assertEqual((stderr['bytes'], stderr['sha256']),
                                     (len(raw), hashlib.sha256(raw).hexdigest()))
                    self.assertNotIn('content_base64', row['logs'][0])
                    for thread in logged.threads:
                        thread.join.assert_called_once_with(timeout=2)

    def test_wofi_overflow_and_drain_fault_never_claim_complete(self):
        for raw, fault in ((b'x' * (guest.MAX_LOG + 1), False), (b'partial', True)):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                logged = self.captured(directory, 'minimal-wofi', raw, fault=fault)
                with patch.object(guest, 'emit') as emit, self.assertRaisesRegex(ValueError, 'log overflow/failure'):
                    logged.finish()
                stderr = emit.call_args.kwargs['logs'][1]
                self.assertFalse(stderr['capture_complete'])
                self.assertEqual(base64.b64decode(stderr['content_base64']), raw[:guest.MAX_LOG])
                self.assertLessEqual(stderr['bytes'], guest.MAX_LOG)
                self.assertEqual(logged.overflow, len(raw) > guest.MAX_LOG)

    def test_incomplete_drain_emits_no_complete_record(self):
        with tempfile.TemporaryDirectory() as directory:
            logged = self.captured(directory, 'minimal-wofi', b'partial', alive=True)
            with patch.object(guest, 'emit') as emit, self.assertRaisesRegex(ValueError, 'log drain incomplete'):
                logged.finish()
            emit.assert_not_called()

    def test_non_wofi_log_records_keep_existing_shape(self):
        for name in ('minimal', 'overlay', 'minimal-clients-0', 'other-wofi'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                logged = self.captured(directory, name, b'x' * 5000)
                with patch.object(guest, 'emit') as emit:
                    logged.finish()
                self.assertEqual(set(emit.call_args.kwargs), {'name', 'returncode', 'logs'})
                for row in emit.call_args.kwargs['logs']:
                    self.assertEqual(set(row), {'path', 'bytes', 'sha256', 'tail_base64'})
                    self.assertLessEqual(len(base64.b64decode(row['tail_base64'])), 4096)


class RenderNodeTests(unittest.TestCase):
    @staticmethod
    def attributes(**delta):
        return SimpleNamespace(**(dict(st_dev=1, st_ino=2, st_mode=stat.S_IFCHR | 0o600,
            st_uid=23001, st_gid=23001, st_rdev=guest.os.makedev(226, 128)) | delta))

    def test_missing_required_node_is_not_ready_and_never_a_primary_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sysfs, devices = root / 'sysfs', root / 'dev'
            sysfs.mkdir(); devices.mkdir()
            card = devices / 'card0'
            self.assertIsNone(guest.drm_render_node(card, sysfs, devices))
            (sysfs / 'renderD128').mkdir()
            self.assertIsNone(guest.drm_render_node(card, sysfs, devices))
            (sysfs / 'renderD128').rmdir()
            (devices / 'renderD128').touch()
            self.assertIsNone(guest.drm_render_node(card, sysfs, devices))
            (devices / 'renderD128').unlink()
            (sysfs / 'renderDwrong').mkdir()
            with self.assertRaises(ValueError):
                guest.drm_render_node(card, sysfs, devices)

    def test_same_gpu_identity_and_all_mismatches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sysfs, devices = root / 'sysfs', root / 'dev'
            sysfs.mkdir(); devices.mkdir()
            primary = sysfs / 'card0'; primary.mkdir()
            parent = primary / 'device'; parent.mkdir()
            entry = sysfs / 'renderD128'; entry.mkdir()
            (entry / 'device').symlink_to(parent, target_is_directory=True)
            (entry / 'dev').write_text('226:128\n')
            node = devices / 'renderD128'; node.touch()
            card = devices / 'card0'
            with self.assertRaises(ValueError):
                guest.drm_render_node(card, sysfs, devices)
            with patch.object(Path, 'lstat', return_value=self.attributes()):
                self.assertEqual(guest.drm_render_node(card, sysfs, devices), node)
                for text in ('227:128', '226:127', '226:192', '226:129'):
                    (entry / 'dev').write_text(text)
                    with self.assertRaises(ValueError):
                        guest.drm_render_node(card, sysfs, devices)
                (entry / 'dev').write_text('226:128')
                other = root / 'other-gpu'; other.mkdir()
                (entry / 'device').unlink()
                (entry / 'device').symlink_to(other, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'another GPU'):
                    guest.drm_render_node(card, sysfs, devices)
                (entry / 'device').unlink()
                (entry / 'device').symlink_to(parent, target_is_directory=True)
                (devices / 'renderD129').touch()
                with self.assertRaises(ValueError):
                    guest.drm_render_node(card, sysfs, devices)
                (devices / 'renderD129').unlink()
                (sysfs / 'renderD129').mkdir()
                with self.assertRaises(ValueError):
                    guest.drm_render_node(card, sysfs, devices)
                (sysfs / 'renderD129').rmdir()
            for mode, number in ((stat.S_IFREG | 0o600, 0), (stat.S_IFLNK | 0o600, 0),
                                 (stat.S_IFCHR | 0o600, guest.os.makedev(226, 129))):
                with patch.object(Path, 'lstat', return_value=self.attributes(st_mode=mode, st_rdev=number)), \
                     self.assertRaises(ValueError):
                    guest.drm_render_node(card, sysfs, devices)

    def test_required_pair_readiness_uses_only_original_twenty_seconds(self):
        card, render = Path('/inert/card0'), Path('/inert/renderD128')
        with patch.object(guest, 'drm_card', return_value=card) as primary, \
             patch.object(guest, 'drm_render_node', side_effect=[None, render]) as rendering, \
             patch.object(guest.time, 'monotonic', side_effect=[0, 0, 19.9]), \
             patch.object(guest.time, 'sleep'):
            self.assertEqual(guest.wait_drm_card(), card)
            self.assertEqual(primary.call_count, 2)
            self.assertEqual(rendering.call_count, 2)
        with patch.object(guest, 'drm_card', return_value=card), \
             patch.object(guest, 'drm_render_node', return_value=None) as rendering, \
             patch.object(guest.time, 'monotonic', side_effect=[0, 0, 20]), \
             patch.object(guest.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'DRM readiness deadline'):
                guest.wait_drm_card()
            rendering.assert_called_once_with(card)

    def test_render_access_opens_only_required_render_fd_and_reports_identity(self):
        card, render = Mock(), Mock()
        render.lstat.return_value = self.attributes()
        with patch.object(guest, 'drm_render_node', return_value=render), \
             patch.object(guest.os, 'open', return_value=17) as opened, \
             patch.object(guest.os, 'fstat', return_value=self.attributes()), \
             patch.object(guest.os, 'close') as closed, patch.object(guest, 'emit') as emit:
            guest.render_access(card)
        self.assertEqual(opened.call_args.args,
            (render, guest.os.O_RDWR | guest.os.O_NOFOLLOW | guest.os.O_CLOEXEC))
        closed.assert_called_once_with(17)
        emit.assert_called_once_with('render_access', status='PASS', errno=0,
            device=str(render), major=226, minor=128, uid=23001, gid=23001, mode=0o600)
        with patch.object(guest, 'drm_render_node', return_value=None), \
             patch.object(guest.os, 'open') as opened, patch.object(guest, 'emit') as emit:
            with self.assertRaisesRegex(ValueError, 'required DRM render node unavailable'):
                guest.render_access(card)
        opened.assert_not_called()
        card.lstat.assert_not_called()
        emit.assert_called_once_with('render_access', status='FAIL', errno=None, device=None)

    def test_render_access_refuses_private_and_opened_identity_changes(self):
        card, render = Mock(), Mock()
        for delta in (dict(st_uid=0), dict(st_gid=0), dict(st_mode=stat.S_IFCHR | 0o666),
                      dict(st_mode=stat.S_IFREG | 0o600)):
            render.lstat.return_value = self.attributes(**delta)
            with patch.object(guest, 'drm_render_node', return_value=render), \
                 patch.object(guest.os, 'open') as opened, self.assertRaises(ValueError):
                guest.render_access(card)
            opened.assert_not_called()
        render.lstat.return_value = self.attributes()
        for delta in (dict(st_dev=2), dict(st_ino=99), dict(st_mode=stat.S_IFREG | 0o600),
                      dict(st_uid=0), dict(st_gid=0), dict(st_rdev=guest.os.makedev(226, 129))):
            with patch.object(guest, 'drm_render_node', return_value=render), \
                 patch.object(guest.os, 'open', return_value=17), \
                 patch.object(guest.os, 'fstat', return_value=self.attributes(**delta)), \
                 patch.object(guest.os, 'close') as closed, patch.object(guest, 'emit') as emit, \
                 self.assertRaises(ValueError):
                guest.render_access(card)
            closed.assert_called_once_with(17)
            self.assertEqual(emit.call_args.kwargs['status'], 'FAIL')
        first = PermissionError(13, 'synthetic inaccessible renderer')
        with patch.object(guest, 'drm_render_node', return_value=render), \
             patch.object(guest.os, 'open', side_effect=first), \
             patch.object(guest.os, 'close') as closed, patch.object(guest, 'emit') as emit:
            with self.assertRaises(PermissionError) as caught:
                guest.render_access(card)
        self.assertIs(caught.exception, first)
        closed.assert_not_called()
        self.assertEqual(emit.call_args.kwargs['status'], 'FAIL')
        self.assertEqual(emit.call_args.kwargs['errno'], 13)
        self.assertNotIn('inaccessible', repr(emit.call_args))
        first = OSError(5, 'synthetic fstat primary')
        with patch.object(guest, 'drm_render_node', return_value=render), \
             patch.object(guest.os, 'open', return_value=17), \
             patch.object(guest.os, 'fstat', side_effect=first), \
             patch.object(guest.os, 'close', side_effect=OSError(9, 'synthetic close secondary')) as closed, \
             patch.object(guest, 'emit') as emit:
            with self.assertRaises(OSError) as caught:
                guest.render_access(card)
        self.assertIs(caught.exception, first)
        closed.assert_called_once_with(17)
        self.assertEqual(emit.call_args.kwargs['errno'], 5)

    def test_root_prepares_only_matched_required_render_node(self):
        tree = ast.parse(inspect.getsource(guest.boot))
        body = next(node.body for node in tree.body[0].body if isinstance(node, ast.Try))
        start = next(i for i, node in enumerate(body) if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == 'render' for target in node.targets))
        code = compile(ast.Module(body=body[start:start + 4], type_ignores=[]), '<prepare-render>', 'exec')
        card, render = Mock(), Mock()
        for result in (None, render):
            with patch.object(guest, 'drm_render_node', return_value=result) as resolve, \
                 patch.object(guest.os, 'chown') as chown:
                if result is None:
                    with self.assertRaises(ValueError):
                        exec(code, guest.__dict__, {'card': card})
                else:
                    exec(code, guest.__dict__, {'card': card})
            resolve.assert_called_once_with(card)
            if result is None:
                chown.assert_not_called()
            else:
                chown.assert_called_once_with(render, 23001, 23001)
                render.chmod.assert_called_once_with(0o600)
        render.chmod.reset_mock()
        with patch.object(guest, 'drm_render_node', side_effect=ValueError('synthetic wrong GPU')), \
             patch.object(guest.os, 'chown') as chown, self.assertRaises(ValueError):
            exec(code, guest.__dict__, {'card': card})
        chown.assert_not_called(); render.chmod.assert_not_called()

    def test_user_preflight_is_after_gbm_pass_and_before_phase(self):
        body = ast.parse(inspect.getsource(guest.user)).body[0].body
        start = next(i for i, node in enumerate(body) if isinstance(node, ast.Expr) and
                     isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                     and node.value.func.id == 'render_access')
        self.assertEqual(body[start - 1].value.args[0].value, 'gbm_pass')
        code = compile(ast.Module(body=body[start:start + 3], type_ignores=[]), '<user-render-boundary>', 'exec')
        card = Mock()
        with patch.object(guest, 'render_access') as access, patch.object(guest, 'phase') as phase, \
             patch.object(guest, 'emit'):
            scope = dict(card=card, env={}, logs=Path('/inert/logs'))
            exec(code, guest.__dict__, dict(scope))
            access.assert_called_once_with(card)
            self.assertEqual(phase.call_count, 2)
            phase.reset_mock()
            failure = PermissionError('synthetic render open')
            access.side_effect = failure
            with self.assertRaises(PermissionError) as caught:
                exec(code, guest.__dict__, dict(scope))
        self.assertIs(caught.exception, failure)
        phase.assert_not_called()

    def test_fixture_three_exact_rules_keep_previous_access_scopes(self):
        fixture = Path(guest.__file__).with_name('desktop574_fixture.sh').read_text()
        rules = [line for line in fixture.splitlines() if line.startswith('printf') and 'OWNER:=' in line]
        self.assertEqual(len(rules), 3)
        render = next(line for line in rules if 'KERNEL=="renderD[0-9]*"' in line)
        for part in ('SUBSYSTEM=="drm"', 'SUBSYSTEMS=="pci"', 'ATTRS{vendor}=="0x1af4"',
                     'ATTRS{device}=="0x1050"', 'DRIVERS=="virtio-pci"',
                     'OWNER:="23001"', 'GROUP:="23001"', 'MODE:="0600"'):
            self.assertIn(part, render)
        self.assertIn('ATTR{name}=="desktop574.events"', rules[0])
        self.assertIn('KERNEL=="card[0-9]*"', rules[1])


if __name__ == '__main__':
    unittest.main()
