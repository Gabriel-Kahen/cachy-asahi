# SPDX-License-Identifier: MIT
"""Desktop completion controls with local sockets and modeled guest processes."""
import io
import json
from pathlib import Path
import signal
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import controller
import guest
import run


NONCE = 'a' * 32
TERMINAL = {'event': 'desktop_session_exit', 'nonce': NONCE,
            'session_returncode': 0, 'seatd_returncode': -signal.SIGTERM}
FAILED = {'event': 'guest_failed', 'error': 'late cleanup failure', 'hardware_validation': 'NOT RUN'}


def wire(event):
    return run.UART_MARKER + b' ' + json.dumps(event).encode() + b'\n'


class GuestParent(unittest.TestCase):
    def lifecycle(self, *, session_status=0, seatd_status=-signal.SIGTERM, retirement_error=None):
        seatd = Mock(pid=42, returncode=None)
        calls = []

        def child(*args, **kwargs):
            calls.append('session exited')
            return Mock(returncode=session_status)

        def wait_group(process, *, verify_absence):
            self.assertIs(process, seatd)
            self.assertIs(verify_absence, True)
            calls.append('seatd reaped and group absent')
            if retirement_error:
                raise retirement_error
            seatd.returncode = seatd_status

        with patch('guest.Path.is_socket', return_value=True), patch('guest.subprocess.Popen', return_value=seatd), \
                patch('guest.subprocess.run', side_effect=child), patch('guest.terminal', return_value=None), \
                patch('guest.os.killpg') as terminate, patch('guest.await_terminal'), \
                patch('guest.reap', side_effect=wait_group), patch('guest.emit') as emit:
            if session_status or seatd_status == -signal.SIGKILL or retirement_error:
                with self.assertRaises(ValueError):
                    guest.run_desktop_session(NONCE, {})
                emit.assert_not_called()
            else:
                emit.side_effect = lambda *args, **kwargs: calls.append('terminal receipt')
                guest.run_desktop_session(NONCE, {})
                emit.assert_called_once_with('desktop_session_exit', nonce=NONCE,
                                             session_returncode=0, seatd_returncode=-signal.SIGTERM)
            terminate.assert_called_once_with(42, signal.SIGTERM)
        seatd.poll.assert_not_called()
        return calls

    def test_parent_reports_only_after_session_and_seatd_retirement(self):
        self.assertEqual(self.lifecycle(), ['session exited', 'seatd reaped and group absent', 'terminal receipt'])

    def test_failure_or_uncertain_seatd_cleanup_blocks_terminal_receipt(self):
        for case in ({'session_status': 1}, {'seatd_status': -signal.SIGKILL},
                     {'retirement_error': ValueError('seatd group absent was not verified')}):
            with self.subTest(case=case):
                self.assertEqual(self.lifecycle(**case), ['session exited', 'seatd reaped and group absent'])

    def test_stale_socket_cannot_launch_session_after_seatd_exit(self):
        seatd = Mock(pid=42, returncode=None)
        with patch('guest.Path.is_socket', return_value=True), patch('guest.subprocess.Popen', return_value=seatd), \
                patch('guest.terminal', return_value=object()), patch('guest.subprocess.run') as child, \
                patch('guest.os.killpg') as signal_group, patch('guest.reap') as retire, patch('guest.emit') as emit:
            with self.assertRaisesRegex(ValueError, 'seatd exited before session start'):
                guest.run_desktop_session(NONCE, {})
            child.assert_not_called()
            signal_group.assert_not_called()
            retire.assert_called_once_with(seatd, verify_absence=True)
            emit.assert_not_called()


class UART(unittest.TestCase):
    def test_same_read_failure_duplicate_or_event_after_terminal_refused(self):
        for trailing in (FAILED, TERMINAL, {'event': 'session_log'}):
            with self.subTest(trailing=trailing), self.assertRaisesRegex(ValueError, 'late or duplicate'):
                run.desktop_uart_batch((wire(TERMINAL) + wire(trailing)).split(b'\n'), NONCE)
        with self.assertRaisesRegex(ValueError, 'legacy desktop'):
            run.desktop_uart_batch(wire({'event': 'guest_pass', 'nonce': NONCE}).split(b'\n'), NONCE)
        with self.assertRaisesRegex(ValueError, 'late desktop UART marker'):
            run.desktop_uart_batch((wire(TERMINAL) + b'corrupt ' + wire(FAILED)).split(b'\n'), NONCE)

    def test_terminal_shape_types_and_nonce(self):
        for change in ({'nonce': 'b' * 32}, {'session_returncode': 2}, {'session_returncode': False},
                       {'seatd_returncode': 0.0}, {'seatd_returncode': -signal.SIGKILL}, {'extra': True}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'invalid desktop terminal'):
                run.desktop_uart_batch(wire(TERMINAL | change).split(b'\n'), NONCE)

    def finish(self, *, pending=b'', tail=b'', close=True, budget=1, error=None):
        report = {'status': 'FAILED', 'events': [TERMINAL]}
        initial = wire(TERMINAL) + pending
        log = io.BytesIO(initial)
        log.seek(0, io.SEEK_END)
        reader, writer = socket.socketpair()
        with reader, writer:
            reader.setblocking(False)
            writer.sendall(tail)
            if close:
                writer.shutdown(socket.SHUT_WR)
            args = report, reader, log, len(initial), time.monotonic() + budget, pending, NONCE
            if error:
                with self.assertRaisesRegex(ValueError, error):
                    run.finish_desktop_uart(*args)
                self.assertEqual(report['status'], 'FAILED')
                self.assertNotIn('desktop_completion', report)
            else:
                run.finish_desktop_uart(*args)
                self.assertEqual(report['status'], 'CAPTURED_REQUIRES_VISUAL_REVIEW')
                self.assertEqual(report['desktop_completion'], run.desktop_receipt(TERMINAL))
        self.assertEqual(log.getvalue(), initial + tail)

    def test_clean_eof_and_kernel_diagnostics(self):
        self.assertEqual(run.desktop_uart_batch(wire(TERMINAL).split(b'\n'), NONCE), ([TERMINAL], True))
        self.finish(pending=b'systemd', tail=b' stopped the service\n')

    def test_next_read_split_or_partial_tail_cannot_publish(self):
        failure = wire(FAILED)
        for pending, tail in ((b'', failure), (failure[:8], failure[8:]),
                              (failure[:-1], b''), (b'', run.UART_MARKER[:8])):
            with self.subTest(pending=pending, tail=tail):
                self.finish(pending=pending, tail=tail, error='late/duplicate/partial desktop')

    def test_missing_eof_is_bounded(self):
        self.finish(close=False, budget=.02, error='desktop UART EOF deadline')

    def test_tail_overflow_cannot_publish_completion(self):
        report = {'status': 'FAILED', 'events': [TERMINAL]}
        uart = Mock()
        uart.recv.return_value = b'x'
        serial = io.BytesIO()
        with patch('run.MAX_LOG', 16), self.assertRaisesRegex(ValueError, 'UART output overflow'):
            run.finish_desktop_uart(report, uart, serial, 16, time.monotonic() + 1, b'', NONCE)
        uart.recv.assert_called_once_with(1)
        self.assertEqual(serial.getvalue(), b'')
        self.assertNotIn('desktop_completion', report)


class ControllerReplay(unittest.TestCase):
    def test_raw_log_and_retirement_must_agree_before_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            serial = root / 'serial.log'

            def make_result(raw):
                serial.write_bytes(raw)
                return {'nonce': NONCE, 'events': [TERMINAL], 'desktop_completion': run.desktop_receipt(TERMINAL),
                        'owned_group_retirement': 'PASS', 'cleanup_uncertain': False,
                        'logs': {'serial.log': {'size': len(raw), 'sha256': controller.digest(serial)}}}

            raw = b'kernel diagnostic\n' + wire(TERMINAL)
            result = make_result(raw + b'kernel diagnostic\n')
            self.assertEqual(controller.verify_desktop_completion(root, result), run.desktop_receipt(TERMINAL))
            for bad in (result | {'logs': {}}, result | {'cleanup_uncertain': True},
                        result | {'desktop_completion': run.desktop_receipt(TERMINAL) | {'uart_eof': 1}}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    controller.verify_desktop_completion(root, bad)
            for tail in (wire(FAILED), wire(TERMINAL), run.UART_MARKER[:8]):
                with self.subTest(tail=tail), self.assertRaisesRegex(ValueError, 'late or partial'):
                    controller.verify_desktop_completion(root, make_result(raw + tail))


if __name__ == '__main__':
    unittest.main()
