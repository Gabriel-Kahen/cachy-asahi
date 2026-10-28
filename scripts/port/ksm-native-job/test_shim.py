# SPDX-License-Identifier: MIT
"""Real private Unix RPC plus fake Docker; subprocess is only the Python shim."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_broker import broker, FakeDocker
spec = importlib.util.spec_from_file_location('ksm_shim_fixture', Path(__file__).with_name('shim.py'))
shim = importlib.util.module_from_spec(spec); spec.loader.exec_module(shim)


class ShimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.private, self.source = root / 'private', root / 'source'
        self.private.mkdir(mode=0o700); self.source.mkdir(mode=0o700)
        self.backend = FakeDocker(self.private)
        self.owner = broker.Broker(self.backend, self.private / 'journal.jsonl', '1' * 32, self.private, self.source,
                                   context_digest=lambda _: 'b' * 64,
                                   binding={'source_commit': 'c' * 40, 'run_id': '123', 'packet_sha256': 'd' * 64,
                                            'uid': os.getuid(), 'gid': os.getgid()})
        self.backend.owner = self.owner; self.addCleanup(self.owner.close)
        self.token, self.path = 'e' * 64, self.private / 'docker.sock'
        self.service = broker.Service(self.path, self.owner, self.token)
        self.addCleanup(self.close_service)

    def close_service(self):
        if self.service is not None: self.service.close()

    def child(self, args, *, token=None):
        env = {'PATH': '/usr/bin:/bin', 'KSM_DOCKER_BROKER_SOCKET': str(self.path),
               'KSM_DOCKER_BROKER_TOKEN': self.token if token is None else token}
        process = subprocess.Popen([sys.executable, '-B', str(Path(shim.__file__)), *args], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env)
        try:
            end = time.monotonic() + 5
            while process.poll() is None:
                self.assertLess(time.monotonic(), end)
                self.service.poll()
                time.sleep(.005)
            out, err = process.communicate(timeout=1)
            return process.returncode, out, err
        finally:
            if process.poll() is None: process.kill(); process.wait()
            process.stdout.close(); process.stderr.close()

    def test_real_shim_subprocess_preserves_original_stdout_and_status(self):
        self.assertEqual(self.child(['info', '--format', '{{.Architecture}}']), (0, b'arm64\n', b''))
        self.assertEqual(self.backend.calls[-1][:2], ['docker', '--host=' + self.backend.endpoint])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_nonzero_backend_exit_is_forwarded(self):
        self.backend.call = lambda argv, timeout: subprocess.CompletedProcess(argv, 17, b'fixture failure\n')
        self.assertEqual(self.child(['version']), (17, b'fixture failure\n', b''))

    def test_unknown_command_never_reaches_backend(self):
        code, out, _ = self.child(['system', 'prune', '-a'])
        self.assertEqual(code, 125); self.assertIn(b'refused', out)
        self.assertEqual(self.backend.calls, [])
        self.assertTrue(self.owner.failed)

    def test_wrong_rpc_token_refused_and_journaled_without_backend(self):
        code, _, _ = self.child(['version'], token='f' * 64)
        self.assertEqual(code, 125)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.owner.events[-1]['event'], 'rpc-failed')

    def test_shim_refuses_invalid_endpoint_token_or_huge_argv_without_connect(self):
        env = {'KSM_DOCKER_BROKER_SOCKET': str(self.path), 'KSM_DOCKER_BROKER_TOKEN': self.token}
        for change, argv in (({'KSM_DOCKER_BROKER_SOCKET': '/tmp/../outside'}, ['version']),
                             ({'KSM_DOCKER_BROKER_TOKEN': 'short'}, ['version']), ({}, ['version', 'x' * 8193])):
            with self.subTest(change=change), patch.object(shim.socket.socket, 'connect') as connect:
                with self.assertRaises(ValueError): shim.exchange(argv, {**env, **change})
                connect.assert_not_called()

    def test_socket_replacement_is_not_removed_by_service_cleanup(self):
        saved = self.private / 'saved.sock'
        self.path.rename(saved)
        self.path.write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError, 'socket-identity'): self.service.poll()
        with self.assertRaisesRegex(ValueError, 'replacement-cleanup'): self.service.close()
        self.service = None
        self.assertEqual(self.path.read_bytes(), b'foreign')
        self.assertTrue(saved.exists())

    def test_rpc_request_length_bound_refuses_body_before_backend(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.connect(str(self.path)); connection.sendall(struct.pack('!I', broker.REQUEST_LIMIT + 1))
        self.service.poll()
        response = json.loads(broker.receive(connection, broker.RESPONSE_LIMIT * 2))
        self.assertEqual(response['code'], 125)
        self.assertEqual(self.backend.calls, [])

    def test_busy_service_does_not_recursively_dispatch(self):
        self.service.busy = True
        try:
            with patch.object(broker.socket.socket, 'accept') as accept:
                self.service.poll(); accept.assert_not_called()
        finally:
            self.service.busy = False

    def test_shim_response_wait_covers_bounded_bootstrap_rpc(self):
        self.assertEqual(shim.CLIENT_TIMEOUT, 2600)
        self.assertGreater(shim.CLIENT_TIMEOUT, 1800 + 4 * 60 + 3 * 60)


if __name__ == '__main__': unittest.main()
