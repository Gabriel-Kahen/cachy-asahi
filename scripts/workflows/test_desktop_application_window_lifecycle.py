#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Protocol/process models only. No compositor, window or ARM success evidence."""
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import desktop_application_window_lifecycle as window


class ModelIPC:
    evidence = 'MODEL_PROTOCOL_ONLY'
    def __init__(self, release, mode='normal'):
        self.release, self.mode = release, mode
        self.pid = None
        self.closed = False
        self.requests = []
    def clients(self, deadline, check):
        if self.mode == 'cancel':
            os.kill(os.getpid(), signal.SIGTERM)
        check()
        self.requests.append('clients')
        if self.closed or self.mode == 'not-mapped':
            return []
        row = dict(pid=self.pid, address='0x123', mapped=True, visible=True, hidden=False,
                   size=[320, 200], xwayland=False, **{'class': 'fixture', 'title': 'Fixture',
                   'initialClass': 'fixture', 'initialTitle': 'Fixture'})
        if self.mode == 'unrelated':
            row['pid'] = self.pid + 100
        if self.mode == 'multiple':
            return [row, dict(row, address='0x456')]
        return [row]
    def evaluate(self, script, deadline, check):
        check()
        self.requests.append(script)
        if b'hl.get_window' in script and self.mode == 'bind-expired':
            raise ValueError('owned window identity changed')
        if b'hl.dispatch' in script:
            if self.mode == 'close-expired':
                raise ValueError('owned window identity changed')
            if self.mode == 'unsupported':
                raise window.runtime.NotRun('required private Lua window IPC unsupported')
            self.closed = True
            self.release.write_text('close-model')
        if self.mode == 'never-unmaps' and self.closed:
            self.closed = False


class LifecycleModels(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='window-model-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.release = self.home / 'release'
        self.env = {'HOME': str(self.home), 'PATH': '/usr/bin', 'LANG': 'C.UTF-8'}
        self.body = 'import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nprint("fixture started",flush=True)\nwhile not p.exists(): time.sleep(.01)\n'
        self.argv = [sys.executable, '-I', '-B', '-c', self.body, str(self.release)]

    def run_model(self, mode='normal'):
        ipc = ModelIPC(self.release, mode)
        original = window.owned._stat
        def observe(pid):
            if ipc.pid is None:
                ipc.pid = pid
            return original(pid)
        with mock.patch.object(window.owned, '_stat', side_effect=observe), \
             mock.patch.object(window, 'admit', return_value=(ipc, self.env, {'evidence': 'MODEL_ONLY'})):
            result = window.launch(self.argv, self.home, self.env, .6, .25, 'unused',
                     contract_path=self.home / 'not-a-real-contract', close_seconds=.2)
        return result, ipc

    def test_modeled_map_atomic_close_and_final_retirement(self):
        row, ipc = self.run_model()
        self.assertEqual(row['status'], 'PASS_MODEL_WINDOW_PROTOCOL')
        self.assertTrue(row['window']['mapped'] and row['window']['close_requested'] and row['window']['unmapped'])
        self.assertEqual(row['exit'], 0)
        self.assertEqual(row['signals'], [])
        self.assertEqual(row['retirement'], 'OBSERVED_EMPTY_GROUP')
        self.assertTrue(row['gui'].startswith('NOT_RUN'))
        self.assertEqual(row['window']['evidence'], 'MODEL_PROTOCOL_ONLY')
        self.assertIn('fixture started', row['output'])
        self.assertEqual(sum(isinstance(x, bytes) and b'hl.dispatch' in x for x in ipc.requests), 1)

    def test_unrelated_window_never_closed(self):
        row, ipc = self.run_model('unrelated')
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertFalse(row['window']['close_requested'])
        self.assertFalse(any(isinstance(x, bytes) and b'hl.dispatch' in x for x in ipc.requests))
        self.assertTrue(row['reaped'])

    def test_multiple_owned_windows_refused(self):
        row, ipc = self.run_model('multiple')
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertFalse(any(isinstance(x, bytes) and b'hl.dispatch' in x for x in ipc.requests))

    def test_mapping_deadline_is_failure_and_retires(self):
        start = time.monotonic()
        row, _ = self.run_model('not-mapped')
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertTrue(row['reaped'])
        self.assertLess(time.monotonic() - start, 1.6)

    def test_expired_binding_prevents_close(self):
        row, ipc = self.run_model('bind-expired')
        self.assertFalse(row['window']['mapped'])
        self.assertFalse(any(isinstance(x, bytes) and b'hl.dispatch' in x for x in ipc.requests))
        self.assertTrue(row['reaped'])

    def test_expired_retained_object_is_not_success(self):
        row, ipc = self.run_model('close-expired')
        self.assertTrue(row['window']['mapped'])
        self.assertFalse(row['window']['close_requested'])
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertTrue(row['reaped'])

    def test_unsupported_protocol_stays_not_run(self):
        row, _ = self.run_model('unsupported')
        self.assertEqual(row['status'], 'NOT_RUN')
        self.assertTrue(row['gui'].startswith('NOT_RUN'))
        self.assertTrue(row['reaped'])

    def test_unmapping_deadline_does_not_claim_window_success(self):
        row, _ = self.run_model('never-unmaps')
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertFalse(row['window']['unmapped'])

    def test_output_overflow_is_bounded(self):
        self.body = 'print("x"*200000,flush=True)\nimport time\ntime.sleep(10)\n'
        self.argv = [sys.executable, '-I', '-B', '-c', self.body]
        row, _ = self.run_model('not-mapped')
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertLessEqual(len(row['output']), window.runtime.CAP)
        self.assertTrue(row['reaped'])

    def test_sigterm_cancellation_stops_window_control_and_retires(self):
        before = signal.getsignal(signal.SIGTERM)
        row, ipc = self.run_model('cancel')
        self.assertEqual(row['status'], 'CANCELLED')
        self.assertTrue(row['reaped'])
        self.assertFalse(row['window']['close_requested'])
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
        self.assertEqual(row['window']['custody_transfer'], 'OWNED_PROCESS_SUPERVISE')

    def test_start_failure_does_not_claim_retirement(self):
        ipc = ModelIPC(self.release)
        with mock.patch.object(window.subprocess, 'Popen', side_effect=OSError('fixture start failure')), \
             mock.patch.object(window, 'admit', return_value=(ipc, self.env, {})):
            row = window.launch(self.argv, self.home, self.env, .6, .25, '', contract_path=self.home)
        self.assertEqual(row['status'], 'START_FAILED')
        self.assertEqual(row['ownership'], 'NOT_LAUNCHED')
        self.assertEqual(row['window']['custody_transfer'], 'NOT_TRANSFERRED')

    def test_natural_early_exit_without_window_is_failure(self):
        self.argv = [sys.executable, '-I', '-B', '-c', 'print("early exit")']
        row, ipc = self.run_model('not-mapped')
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertEqual(row['exit'], 0)
        self.assertFalse(row['window']['mapped'])

    def test_deadline_overrun_still_retires_known_real_child(self):
        ipc = ModelIPC(self.release)
        original_clients = ipc.clients
        original_stat = window.owned._stat
        def observe(pid):
            if ipc.pid is None:
                ipc.pid = pid
            return original_stat(pid)
        def paused(deadline, check):
            time.sleep(1.15)  # Intentionally exhaust .1 run +1 retirement reserve.
            return original_clients(deadline, check)
        ipc.clients = paused
        with mock.patch.object(window, 'admit', return_value=(ipc, self.env, {})), \
             mock.patch.object(window.owned, '_stat', side_effect=observe):
            row = window.launch(self.argv, self.home, self.env, .1, .08, '', contract_path=self.home)
        self.assertTrue(row['window']['deadline_overrun'])
        self.assertTrue(row['reaped'])
        self.assertFalse(row['passed'])
        self.assertEqual(row['status'], 'WINDOW_WORKFLOW_FAILED')
        self.assertIn('SIGTERM', row['signals'])
        self.assertLess(row['seconds_total'], 2.2)

    def test_invalid_deadline_refused_before_process(self):
        for value in (float('nan'), float('inf'), -.1, 0):
            with self.subTest(value=value), mock.patch.object(window.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError):
                    window.launch(self.argv, self.home, self.env, value, .1, '', contract_path=self.home)
                spawn.assert_not_called()

    def test_real_host_admission_refuses_before_bus_or_socket(self):
        with mock.patch.object(window.socket, 'socket') as connect, mock.patch.object(window.subprocess, 'Popen') as spawn:
            with self.assertRaises(window.runtime.NotRun):
                window.admit(self.home / 'missing-contract', self.env)
            connect.assert_not_called()
            spawn.assert_not_called()

    def test_echild_no_further_proc_signal_wait_or_supervision(self):
        pipes = []
        for _ in range(2):
            read, write = os.pipe();os.close(write);pipes.append(os.fdopen(read, 'rb'))
        child = SimpleNamespace(pid=12345, stdout=pipes[0], stderr=pipes[1], _child_created=True)
        ipc = ModelIPC(self.release)
        with mock.patch.object(window.subprocess, 'Popen', return_value=child), \
             mock.patch.object(window.os, 'waitid', side_effect=ChildProcessError), \
             mock.patch.object(window.owned, '_stat') as proc, \
             mock.patch.object(window.owned, 'supervise') as supervise, \
             mock.patch.object(window, 'admit', return_value=(ipc, self.env, {})):
            row = window.launch(self.argv, self.home, self.env, .6, .25, '', contract_path=self.home)
        proc.assert_not_called();supervise.assert_not_called()
        self.assertFalse(child._child_created)
        self.assertEqual(row['ownership'], 'UNKNOWN')
        self.assertEqual(ipc.requests, [])
        self.assertIsNone(row['exit'])

    def test_lua_is_data_encoded_and_close_uses_retained_object(self):
        row = dict(pid=123, address='0x123', mapped=True, visible=True, hidden=False, size=[1, 1],
                   xwayland=False, **{'class': 'x";do_bad()', 'title': 'Title', 'initialClass': 'a', 'initialTitle': 'b'})
        identity = window.window_identity(row, 123)
        bind, close, cleanup = window.scripts(identity, 'CAA_WINDOW_' + 'a' * 32)
        self.assertIn(b'hl.get_window', bind)
        self.assertNotIn(b'do_bad()', bind)
        self.assertIn(b'window=w', close)
        self.assertIn(b'w ~= nil and w.pid == 123', close)
        self.assertNotIn(b'window="address:', close)
        self.assertTrue(cleanup.endswith(b'=nil'))

    def test_bad_or_xwayland_identity_refused(self):
        base = dict(pid=123, address='0x123', mapped=True, visible=True, hidden=False, size=[1, 1],
                    xwayland=False, **{'class': 'x', 'title': 't', 'initialClass': 'x', 'initialTitle': 't'})
        for change in ({'pid': 123.0}, {'address': '0x0'}, {'address': 'evil'}, {'xwayland': True}, {'visible': False}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                window.window_identity(dict(base, **change), 123)


class PrivateTransportModels(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wipc-')
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        self.path = self.runtime / 'hypr/test/.socket.sock'
        self.path.parent.mkdir(parents=True)
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(str(self.path));self.server.listen(1);self.server.settimeout(1)
        self.addCleanup(self.server.close)
        self.env = dict(XDG_RUNTIME_DIR=str(self.runtime), HYPRLAND_INSTANCE_SIGNATURE='test')
        self.contract = dict(compositor_pid=os.getpid(), compositor_start_ticks=window.owned._stat(os.getpid())[4])

    def exchange(self, reply, request=b'j/clients'):
        received = []
        def serve():
            connection, _ = self.server.accept()
            with connection:
                received.append(connection.recv(131072))
                connection.sendall(reply)
        worker = threading.Thread(target=serve);worker.start()
        ipc = window.PrivateIPC(self.contract, self.env)
        try:
            output = ipc.request(request, time.monotonic() + .5, lambda: None)
        finally:
            worker.join(1)
        self.assertFalse(worker.is_alive())
        return output, received

    def test_real_private_socket_transport_is_only_a_model(self):
        output, received = self.exchange(b'[]')
        self.assertEqual(output, b'[]');self.assertEqual(received, [b'j/clients'])

    def test_reply_overflow_refused(self):
        with self.assertRaisesRegex(ValueError, 'reply cap'):
            self.exchange(b'x' * (window.MAX_REPLY + 1))

    def test_peer_identity_mismatch_refused_before_payload(self):
        self.contract['compositor_pid'] = os.getppid()
        self.contract['compositor_start_ticks'] = window.owned._stat(os.getppid())[4]
        ipc = window.PrivateIPC(self.contract, self.env)
        with self.assertRaisesRegex(ValueError, 'peer differs'):
            ipc.request(b'j/clients', time.monotonic() + .2, lambda: None)

    def test_socket_replacement_refused(self):
        ipc = window.PrivateIPC(self.contract, self.env)
        self.path.unlink()
        self.path.write_text('replacement')
        with self.assertRaisesRegex(ValueError, 'socket required'):
            ipc.request(b'j/clients', time.monotonic() + .2, lambda: None)

    def test_symlink_socket_refused(self):
        alias = self.path.with_name('target')
        self.path.rename(alias)
        self.path.symlink_to(alias)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            window.PrivateIPC(self.contract, self.env)

    def test_unknown_request_refused_before_connect(self):
        ipc = window.PrivateIPC(self.contract, self.env)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            ipc.request(b'/dispatch killactive', time.monotonic() + .2, lambda: None)


class ProtectedContractModels(unittest.TestCase):
    def test_root_authority_and_bytes_use_same_descriptor(self):
        with tempfile.TemporaryDirectory(prefix='contract-model-') as folder:
            path = Path(folder) / 'contract.json'
            path.write_text('{"schema":1}')
            original_stat = os.fstat
            def root_stat(fd):
                info = original_stat(fd)
                values = {'st_' + key: getattr(info, 'st_' + key) for key in
                          ('dev', 'ino', 'mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns')}
                values['st_uid'] = 0  # Authority fixture only; no chown/system mutation.
                return SimpleNamespace(**values)
            with mock.patch.object(window.os, 'fstat', side_effect=root_stat), \
                 mock.patch.object(Path, 'lstat', side_effect=AssertionError('separate path authority check')):
                value, identity = window.protected_contract(path)
            self.assertEqual(value, {'schema': 1})
            self.assertEqual(identity, window.runtime.desktop.pin(path.read_bytes()))

    def test_replace_between_check_and_read_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='contract-model-') as folder:
            path = Path(folder) / 'contract.json'
            path.write_text('{"schema":1}')
            original_stat, original_read = os.fstat, os.read
            changed = False
            def root_stat(fd):
                info = original_stat(fd)
                values = {'st_' + key: getattr(info, 'st_' + key) for key in
                          ('dev', 'ino', 'mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns')}
                values['st_uid'] = 0
                return SimpleNamespace(**values)
            def replace(fd, size):
                nonlocal changed
                if not changed:
                    other = Path(folder) / 'replacement'
                    other.write_text('{"schema":999}')
                    other.replace(path)
                    changed = True
                return original_read(fd, size)
            with mock.patch.object(window.os, 'fstat', side_effect=root_stat), \
                 mock.patch.object(window.os, 'read', side_effect=replace):
                with self.assertRaisesRegex(ValueError, 'contract changed|pathname replaced'):
                    window.protected_contract(path)


class LuaObjectModels(unittest.TestCase):
    def run_lua(self, tail):
        executable = shutil.which('lua')
        if not executable:
            self.skipTest('existing Lua interpreter unavailable; no install attempted')
        identity = dict(pid=123, address='0x123', **{'class': 'fixture', 'title': 'Fixture',
                        'initialClass': 'fixture', 'initialTitle': 'Fixture'})
        bind, close, cleanup = window.scripts(identity, 'CAA_WINDOW_' + 'a' * 32)
        setup = r'''local alive=true;local closed=0
local properties={pid=123,address="0x123",class="fixture",title="Fixture",initial_class="fixture",initial_title="Fixture",mapped=true,visible=true,hidden=false,xwayland=false}
local original=setmetatable({}, {__index=function(_,key) if alive then return properties[key] end end})
local lookup=original
hl={get_window=function(_) return lookup end,dispatch=function(fn) return fn() end,dsp={window={close=function(options)
assert(options.window~=nil,"focused fallback forbidden")
assert(options.window==original,"wrong object")
return function() closed=closed+1;return {ok=true} end end}}}
'''
        script = setup + bind.decode() + '\n' + tail.replace('CLOSE_SCRIPT', close.decode()).replace('CLEANUP_SCRIPT', cleanup.decode())
        process = subprocess.run([executable, '-'], input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'}, timeout=2)
        self.assertEqual(process.returncode, 0, process.stderr.decode())

    def test_generated_lua_closes_retained_object(self):
        self.run_lua('CLOSE_SCRIPT;assert(closed==1);assert(_G["CAA_WINDOW_' + 'a'*32 + '"]==nil)')

    def test_recycled_address_does_not_close_another_object(self):
        self.run_lua('alive=false;lookup={pid=999,address="0x123"};local ok=pcall(function() CLOSE_SCRIPT end);assert(not ok);assert(closed==0);CLEANUP_SCRIPT')

    def test_missing_object_never_uses_focused_fallback(self):
        self.run_lua('CLEANUP_SCRIPT;local ok=pcall(function() CLOSE_SCRIPT end);assert(not ok);assert(closed==0)')

    def test_title_change_refuses_close(self):
        self.run_lua('properties.title="changed";local ok=pcall(function() CLOSE_SCRIPT end);assert(not ok);assert(closed==0);CLEANUP_SCRIPT')


if __name__ == '__main__':
    unittest.main()
