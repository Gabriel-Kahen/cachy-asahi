#!/usr/bin/env -S python3 -I -B
"""Synthetic fd/proc/cgroup/socket controls. No actual process or actor probes."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch

P = Path(__file__).with_name('observe.py')
S = importlib.util.spec_from_file_location('hold_metadata_mock_observe', P)
M = importlib.util.module_from_spec(S)
S.loader.exec_module(M)


def proc(pid=234, start=999, state='S', num_threads=2):
    fields = [state, '123', '234', '234'] + ['0'] * 16
    fields[11], fields[12], fields[17], fields[19] = '10', '5', str(num_threads), str(start)
    return (str(pid) + ' (private comm never exported) ' + ' '.join(fields) + '\n').encode()


class Stream:
    def __init__(self, fd):
        self.fd = fd
        self.options = []
    def fileno(self):
        return self.fd
    def getsockopt(self, level, option, size=None):
        self.options.append(option)
        if option == socket.SO_PEERCRED:
            return struct.pack('3i', 234, 1000, 1000)
        if option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            return 65536
        raise AssertionError('unapproved getsockopt')
    def forbidden(self, *args, **kwargs):
        raise AssertionError('consumed or mutated original stream')
    recv = send = read = makefile = close = dup = settimeout = setblocking = forbidden


class Directory:
    def __init__(self, names):
        self.names = names
        self.visited = 0
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def __iter__(self):
        for name in self.names:
            self.visited += 1
            yield types.SimpleNamespace(name=name)


class Fixture:
    def __init__(self):
        self.files = {
            '/proc/self/fdinfo/12': b'pos:\t0\nPid:\t234\nNSpid:\t234\n',
            '/proc/234/stat': proc(), '/proc/234/cgroup': b'0::/user.slice/app.scope\n',
            '/proc/234/task/234/stat': proc(), '/proc/234/task/235/stat': proc(235, 1000),
            '/sys/fs/cgroup/user.slice/app.scope/cpu.stat':
                b'usage_usec 12\nuser_usec 7\nsystem_usec 5\nnr_periods 3\nnr_throttled 1\nthrottled_usec 2\nnr_bursts 0\nburst_usec 0\n',
            '/sys/fs/cgroup/user.slice/app.scope/memory.current': b'4096\n',
            '/sys/fs/cgroup/user.slice/app.scope/memory.events':
                b'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n',
            '/sys/fs/cgroup/user.slice/app.scope/memory.events.local':
                b'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n',
        }
        self.dirs = ('/sys/fs/cgroup', '/sys/fs/cgroup/user.slice', '/sys/fs/cgroup/user.slice/app.scope')
        self.inodes = {p: 100 + n for n, p in enumerate(self.dirs)}
        self.fd_paths = {}
        self.counter, self.closed, self.opened = 1000, [], []
        self.borrowed = {10: (9, 10, stat.S_IFSOCK), 11: (9, 11, stat.S_IFSOCK),
                         12: (9, 12, 0)}
        self.directory = Directory(['234', '235'])
        self.ready = False
        self.clock = 0
        self.qmp, self.serial_socket = Stream(10), Stream(11)
        self.peer = types.SimpleNamespace(stream=self.qmp, fd=10, fds=[12, 13],
                                         credentials=(234, 1000, 1000), actor_pid=123,
                                         qemu=dict(pid=234, start=999))
        self.serial = types.SimpleNamespace(stream=self.serial_socket,
                                            data=bytearray(b'PRIVATE-PAYLOAD'), offset=7)
    def open(self, path, flags, *, dir_fd=None):
        assert flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC and flags & os.O_NONBLOCK
        path = str(path) if dir_fd is None else self.fd_paths[dir_fd] + '/' + str(path)
        self.opened.append(path)
        if path not in self.files and path not in self.dirs:
            raise FileNotFoundError(errno.ENOENT, 'synthetic metadata absent')
        if flags & os.O_DIRECTORY:
            assert path in self.dirs
        self.counter += 1
        self.fd_paths[self.counter] = path
        return self.counter
    def read(self, fd, cap):
        assert fd not in self.borrowed, 'read original descriptor'
        assert cap == 4097
        return self.files[self.fd_paths[fd]][:cap]
    def fstat(self, fd):
        if fd in self.borrowed:
            dev, inode, mode = self.borrowed[fd]
        else:
            path = self.fd_paths[fd]
            dev, inode, mode = 4, self.inodes.get(path, 900), stat.S_IFDIR if path in self.dirs else stat.S_IFREG
        return types.SimpleNamespace(st_dev=dev, st_ino=inode, st_mode=mode)
    def close(self, fd):
        assert fd not in self.borrowed, 'closed an original descriptor'
        self.closed.append(fd)
        del self.fd_paths[fd]
    def ioctl(self, stream, command, data):
        assert command in (0x541B, 0x5411) and data == struct.pack('i', 0)
        return struct.pack('i', 17 if command == 0x541B else 768)
    def poll(self):
        fixture = self
        class Poll:
            def register(self, fd, mask):
                assert fd == 12
            def poll(self, timeout):
                assert timeout == 0
                return [(12, 1)] if fixture.ready else []
        return Poll()
    def stack(self):
        stack = ExitStack()
        for item in (patch.object(os, 'open', self.open), patch.object(os, 'read', self.read),
                     patch.object(os, 'fstat', self.fstat), patch.object(os, 'close', self.close),
                     patch.object(os, 'scandir', lambda path: self.directory if path == '/proc/234/task' else None),
                     patch.object(M.time, 'monotonic', lambda: self.clock),
                     patch.object(M.select, 'poll', self.poll),
                     patch.object(M.select, 'select', lambda r, w, x, t: ([], w, [])),
                     patch.object(M.fcntl, 'ioctl', self.ioctl)):
            stack.enter_context(item)
        for name in ('dup', 'dup2', 'pidfd_open', 'kill', 'killpg', 'waitpid'):
            stack.enter_context(patch.object(os, name, side_effect=AssertionError('forbidden FD/process mutation')))
        stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('reconnect forbidden')))
        return stack


class Controls(unittest.TestCase):
    def test_unbound_refuses_before_any_io(self):
        with patch.object(os, 'open', side_effect=AssertionError('unexpected IO')):
            with self.assertRaisesRegex(M.ObservationError, 'UNBOUND_OR_UNISSUED'):
                M.Binding()
    def test_fixed_metadata_does_not_consume_private_stream(self):
        f = Fixture()
        with f.stack():
            binding = M.Binding(f.peer, f.serial)
            row = binding.sample('HOLD')
        self.assertEqual(row['status'], 'PUBLIC_METADATA_ONLY')
        self.assertEqual(row['process']['start_ticks'], 999)
        self.assertEqual(row['threads']['sampled'], 2)
        self.assertEqual(row['cgroup']['cpu_stat']['usage_usec'], 12)
        self.assertEqual(row['cgroup']['memory_current_bytes'], 4096)
        self.assertEqual(row['serial_buffer'], dict(bytes_retained=15, offset=7, read_ahead_bytes=8))
        self.assertEqual(row['serial']['input_queued_bytes'], 17)
        self.assertEqual(row['qmp']['output_kernel_accounted_bytes'], 768)
        self.assertNotIn(b'PRIVATE', json.dumps(row).encode())
        self.assertNotIn(b'/sys', json.dumps(row).encode())
        self.assertIsNone(row['Root_acceptance'])
        self.assertFalse(f.fd_paths)
        self.assertNotIn(socket.SO_ERROR, f.qmp.options + f.serial_socket.options)
    def test_exact_stage_order_once_and_bounded_journal(self):
        f = Fixture()
        with f.stack():
            binding = M.Binding(f.peer, f.serial)
            with self.assertRaisesRegex(M.ObservationError, 'STAGE_ORDER'):
                binding.sample('DEADLINE')
            for stage in M.STAGES:
                self.assertLessEqual(len((json.dumps(binding.sample(stage), sort_keys=True, indent=2) + '\n').encode()), M.SAMPLE_CAP)
            opened = list(f.opened)
            with self.assertRaisesRegex(M.ObservationError, 'STAGE_ORDER'):
                binding.sample('DEADLINE')
            self.assertEqual(f.opened, opened)
            self.assertLessEqual(binding.bytes_retained, M.JOURNAL_CAP)
    def test_pidfd_ready_refuses_further_process_read(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            f.ready = True
            before = len(f.opened)
            row = b.sample('HOLD')
        self.assertEqual(row['status'], 'IDENTITY_LOST')
        self.assertEqual(row['errors'], ['PIDFD_READY'])
        self.assertEqual(f.opened[before:], [])
        self.assertIs(row['pidfd_live'], False)
    def test_original_socket_fd_change_refuses(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            f.borrowed[11] = (9, 999, stat.S_IFSOCK)
            row = b.sample('HOLD')
        self.assertEqual(row['status'], 'IDENTITY_LOST')
        self.assertEqual(row['errors'], ['BORROWED_FD_IDENTITY'])
    def test_process_start_change_refuses(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            f.files['/proc/234/stat'] = proc(start=1001)
            row = b.sample('HOLD')
        self.assertEqual(row['status'], 'IDENTITY_LOST')
        self.assertIsNone(row['process'])
    def test_cgroup_move_or_replacement_refuses(self):
        for change in ('move', 'replacement'):
            with self.subTest(change=change):
                f = Fixture()
                with f.stack():
                    b = M.Binding(f.peer, f.serial)
                    if change == 'move': f.files['/proc/234/cgroup'] = b'0::/other.scope\n'
                    else: f.inodes['/sys/fs/cgroup/user.slice/app.scope'] += 1
                    row = b.sample('HOLD')
                self.assertEqual(row['status'], 'IDENTITY_LOST')
                self.assertEqual(row['errors'], ['CGROUP_IDENTITY'])
    def test_cgroup_traversal_refuses_before_sysfs_open(self):
        f = Fixture()
        f.files['/proc/234/cgroup'] = b'0::/../private\n'
        with f.stack(), self.assertRaisesRegex(M.ObservationError, 'CGROUP_FORMAT'):
            M.Binding(f.peer, f.serial)
        self.assertFalse(any(p.startswith('/sys') for p in f.opened))
    def test_cgroup_symlink_refuses_and_closes_only_own_metadata_fds(self):
        f = Fixture()
        original = f.open
        def reject_link(path, flags, *, dir_fd=None):
            if path == 'user.slice':
                self.assertTrue(flags & os.O_NOFOLLOW)
                raise OSError(errno.ELOOP, 'synthetic symlink refused')
            return original(path, flags, dir_fd=dir_fd)
        with f.stack(), patch.object(os, 'open', reject_link):
            with self.assertRaises(OSError): M.Binding(f.peer, f.serial)
        self.assertFalse(f.fd_paths)
    def test_pidfd_identity_mismatch_refuses_before_process_read(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            f.files['/proc/self/fdinfo/12'] = b'Pid:\t999\n'
            before = len(f.opened)
            row = b.sample('HOLD')
        self.assertEqual(row['errors'], ['PIDFD_IDENTITY'])
        self.assertEqual(f.opened[before:], ['/proc/self/fdinfo/12'])
    def test_full_thread_schema_and_canonical_three_stage_component_fit_caps(self):
        f = Fixture()
        tids = list(range(234, 266))
        f.directory = Directory([str(tid) for tid in tids])
        for tid in tids:
            f.files['/proc/234/task/' + str(tid) + '/stat'] = proc(tid, 2**64-1)
        f.files['/proc/234/stat'] = proc(num_threads=32)
        for name, keys in (('cpu.stat', M.CPU), ('memory.events', M.MEMORY),
                           ('memory.events.local', M.MEMORY)):
            f.files['/sys/fs/cgroup/user.slice/app.scope/' + name] = ''.join(
                key + ' ' + str(2**64-1) + '\n' for key in keys).encode()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            rows = [b.sample(stage) for stage in M.STAGES]
        self.assertTrue(all(row['threads']['sampled'] == 32 for row in rows))
        self.assertTrue(all(len((json.dumps(row, sort_keys=True, indent=2)+'\n').encode()) <= M.SAMPLE_CAP for row in rows))
        component = (json.dumps({'guest_HOLD_state_observations': rows}, sort_keys=True, indent=2)+'\n').encode()
        self.assertLessEqual(len(component), M.JOURNAL_CAP)
    def test_unrecognized_error_text_is_not_exported(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            with patch.object(M, '_socket_values', side_effect=M.ObservationError('PRIVATE-CREDENTIAL')):
                row = b.sample('HOLD')
        self.assertEqual(row['errors'], ['METADATA_UNAVAILABLE'])
        self.assertNotIn('PRIVATE', json.dumps(row))
    def test_absent_and_missing_counters_are_null_not_zero(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            del f.files['/sys/fs/cgroup/user.slice/app.scope/memory.current']
            f.files['/sys/fs/cgroup/user.slice/app.scope/memory.events'] = b'low 0\n'
            row = b.sample('HOLD')
        self.assertEqual(row['status'], 'PARTIAL_METADATA_ONLY')
        self.assertIsNone(row['cgroup']['memory_current_bytes'])
        self.assertIsNone(row['cgroup']['memory_events']['oom_kill'])
        self.assertEqual(row['cgroup']['memory_events']['low'], 0)
    def test_thread_listing_stops_at_fixed_bound(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            f.directory = Directory([str(n) for n in range(234, 100000)])
            row = b.sample('HOLD')
        self.assertTrue(row['threads']['limited'])
        self.assertEqual(f.directory.visited, 33)
        self.assertLessEqual(row['threads']['sampled'], 32)
        self.assertIn('THREAD_BOUND', row['errors'])
    def test_overlarge_counter_is_not_emitted(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            f.files['/sys/fs/cgroup/user.slice/app.scope/cpu.stat'] = b'PRIVATE' * 1000
            row = b.sample('HOLD')
        self.assertEqual(row['status'], 'PARTIAL_METADATA_ONLY')
        self.assertIsNone(row['cgroup']['cpu_stat']['usage_usec'])
        self.assertNotIn('PRIVATE', json.dumps(row))
    def test_metadata_deadline_is_bounded_and_not_retried(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            with patch.object(M.time, 'monotonic', side_effect=[0, .1, .1]):
                row = b.sample('HOLD')
            self.assertEqual(row['status'], 'DEADLINE')
            with self.assertRaisesRegex(M.ObservationError, 'STAGE_ORDER'):
                b.sample('HOLD')
    def test_private_buffer_count_bound_refuses_without_payload(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            f.serial.offset = len(f.serial.data) + 1
            row = b.sample('HOLD')
        self.assertEqual(row['errors'], ['SERIAL_BUFFER_BOUND'])
        self.assertIsNone(row['serial_buffer'])
    def test_output_bound_returns_fixed_unavailable_record(self):
        f = Fixture()
        with f.stack():
            b = M.Binding(f.peer, f.serial)
            with patch.object(b, '_threads', return_value={'rows': ['x'*20000]}):
                row = b.sample('HOLD')
        self.assertEqual(row['errors'], ['OUTPUT_BOUND'])
        self.assertLess(len(json.dumps(row)), 1024)


if __name__ == '__main__':
    unittest.main(verbosity=2)
