# SPDX-License-Identifier: MIT
"""Real private sockets; no compositor, Docker or ARM execution."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import guest


class ClientsIPC(unittest.TestCase):
    @contextmanager
    def server(self, payload=b'[]', delay=0):
        with tempfile.TemporaryDirectory() as temporary:
            previous = Path.cwd()
            os.chdir(temporary)
            path = Path('r/hypr/fixture/.socket.sock'); path.parent.mkdir(parents=True)
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(path)); listener.listen(1); listener.settimeout(.05)
            stop = threading.Event(); requests = []; errors = []
            def serve():
                try:
                    while not stop.is_set():
                        try: connection, _ = listener.accept()
                        except TimeoutError: continue
                        with connection:
                            connection.settimeout(1)
                            requests.append(connection.recv(1024))
                            stop.wait(delay)
                            try:
                                midpoint = len(payload) // 2
                                connection.sendall(payload[:midpoint])
                                connection.sendall(payload[midpoint:])
                            except BrokenPipeError: pass
                        break
                except BaseException as exc: errors.append(exc)
            worker = threading.Thread(target=serve); worker.start()
            try:
                yield {'XDG_RUNTIME_DIR': 'r', 'HYPRLAND_INSTANCE_SIGNATURE': 'fixture'}, requests
            finally:
                stop.set(); worker.join(timeout=2); listener.close(); os.chdir(previous)
                self.assertFalse(worker.is_alive()); self.assertEqual(errors, [])

    def test_pending_request_survives_cli_five_second_timeout_and_records_real_transport(self):
        payload = b'[{"pid":42,"mapped":true,"size":[420,220]}]'
        with self.server(payload, 5.25) as (env, requests), patch('guest.emit') as events:
            check = Mock()
            actual = guest.query_clients(env, time.monotonic() + 8, check)
            self.assertEqual(actual, json.loads(payload))
            self.assertEqual(requests, [b'j/clients'])
            self.assertGreaterEqual(check.call_count, 20)
            self.assertEqual(events.call_args.args, ('client_ipc',))
            self.assertEqual(events.call_args.kwargs['transport'], 'private-unix-socket')
            self.assertEqual(events.call_args.kwargs['stdout'], payload.decode())

    def test_absolute_deadline_closes_pending_query_without_success(self):
        with self.server(delay=1) as (env, _), patch('guest.emit') as events:
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'Wayland client mapping deadline'):
                guest.query_clients(env, start + .08, Mock())
            self.assertLess(time.monotonic() - start, .5)
            events.assert_not_called()

    def test_invalid_partial_wrong_shape_and_overflow_replies_cannot_pass(self):
        for payload in (b'', b'[', b'{}', b'[1]', b'[]' + b' ' * 63):
            with self.subTest(payload=payload), self.server(payload) as (env, _), \
                    patch('guest.MAX_LOG', 64), patch('guest.emit') as events:
                with self.assertRaises(ValueError):
                    guest.query_clients(env, time.monotonic() + 1, Mock())
                events.assert_not_called()

    def test_log_refusal_and_cancellation_preserve_identity_and_close_socket(self):
        for original in (ValueError('log overflow'), KeyboardInterrupt('cancelled')):
            with self.subTest(original=original), self.server(delay=.5) as (env, _), \
                    patch('guest.emit') as events:
                check = Mock(side_effect=[None, None, original])
                with self.assertRaises(type(original)) as caught:
                    guest.query_clients(env, time.monotonic() + 1, check)
                self.assertIs(caught.exception, original)
                events.assert_not_called()

    def test_symlink_or_ambiguous_private_socket_is_refused_before_connect(self):
        for kind in ('symlink', 'ambiguous'):
            with self.subTest(kind=kind), self.server() as (env, _), patch('guest.emit') as events:
                path = Path('r/hypr/fixture/.socket.sock')
                if kind == 'symlink':
                    path.rename(path.with_name('real')); path.symlink_to('real')
                else:
                    other = Path('r/hypr/other/.socket.sock'); other.parent.mkdir(); other.touch()
                with self.assertRaisesRegex(ValueError, 'private compositor socket'):
                    guest.query_clients(env, time.monotonic() + 1, Mock())
                events.assert_not_called()


class MappedClient(unittest.TestCase):
    def test_two_positive_integer_dimensions_are_accepted(self):
        for size in ([420, 220], [1, 1]):
            with self.subTest(size=size):
                self.assertTrue(guest.mapped_client({'pid': 42, 'mapped': True, 'size': size}, 42))

    def test_empty_wrong_shape_wrong_type_and_nonpositive_dimensions_are_rejected(self):
        for size in (None, [], [1], [1, 2, 3], (420, 220), '420x220',
                     [True, 220], [420, False], [420.0, 220], [420, float('nan')],
                     [float('inf'), 220], [420, '220'], [0, 220], [420, -1]):
            with self.subTest(size=size):
                self.assertFalse(guest.mapped_client({'pid': 42, 'mapped': True, 'size': size}, 42))
        self.assertFalse(guest.mapped_client({'pid': 42, 'mapped': True}, 42))

    def test_own_pid_and_true_mapping_flag_are_still_required(self):
        for pid, mapped in ((41, True), (42, False), (42, 1), (42, None)):
            with self.subTest(pid=pid, mapped=mapped):
                self.assertFalse(guest.mapped_client({'pid': pid, 'mapped': mapped, 'size': [420, 220]}, 42))


if __name__ == '__main__': unittest.main()
