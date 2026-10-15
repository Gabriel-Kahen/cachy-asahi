# SPDX-License-Identifier: MIT
"""Capture ordering and fixed Lua shutdown; no compositor or ARM execution."""
import subprocess
import unittest
from unittest.mock import Mock, patch

import guest
import test_clients_ipc


class CaptureWindow(unittest.TestCase):
    READY = {'pid': 42, 'mapped': True, 'visible': True, 'hidden': False, 'size': [420, 220]}

    def run_window(self, failure_time=None):
        clock, events = [0.0], []
        original = KeyboardInterrupt('capture cancellation')
        def check():
            if failure_time is not None and clock[0] >= failure_time:
                raise original
        def emit(event, **row): events.append((clock[0], event, row))
        with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                patch('guest.time.sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
                patch('guest.emit', side_effect=emit), \
                patch('guest.query_clients', return_value=[self.READY]) as query:
            if failure_time is None:
                guest.capture_window('minimal', ['monitor'], 42, {'instance': 'held'}, check)
            else:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    guest.capture_window('minimal', [], 42, {}, check)
                self.assertIs(caught.exception, original)
        return clock[0], events

    def test_snapshot_is_delayed_inside_original_fifteen_second_live_window(self):
        end, events = self.run_window()
        self.assertEqual(end, 15)
        self.assertEqual(events, [(5, 'frame_ready', {'stage': 'minimal', 'monitors': ['monitor'], 'clients': [self.READY]})])

    def test_cancellation_before_and_after_capture_preserves_identity(self):
        for failure_time in (2, 6):
            with self.subTest(failure_time=failure_time):
                end, events = self.run_window(failure_time)
                self.assertEqual(end, failure_time)
                self.assertEqual(len(events), int(failure_time >= 5))

    def test_slow_health_check_cannot_emit_capture_after_window(self):
        clock = [0]
        def check(): clock[0] = 15
        with patch('guest.time.monotonic', side_effect=lambda: clock[0]), patch('guest.emit') as emit:
            with self.assertRaisesRegex(ValueError, 'capture window expired'):
                guest.capture_window('minimal', [], 42, {}, check)
        emit.assert_not_called()

    def test_fresh_capture_observation_is_required_and_emitted(self):
        for rows in ([], [dict(self.READY, visible=False)], [dict(self.READY, hidden=True)],
                     [dict(self.READY, pid=41)], [dict(self.READY, title='fresh observation')]):
            with self.subTest(rows=rows):
                clock = [0.0]
                check = Mock()
                def query(env, deadline, health, *, deadline_message):
                    self.assertEqual(env, {'instance': 'held'})
                    self.assertEqual(deadline, 15)
                    self.assertIs(health, check)
                    self.assertEqual(deadline_message, 'capture window expired before snapshot')
                    self.assertEqual(clock[0], 5)
                    clock[0] = 7
                    return rows
                with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                        patch('guest.time.sleep', side_effect=lambda n: clock.__setitem__(0, clock[0]+n)), \
                        patch('guest.query_clients', side_effect=query) as request, patch('guest.emit') as emit:
                    if rows and rows[0].get('title'):
                        guest.capture_window('minimal', ['monitor'], 42, {'instance': 'held'}, check)
                        self.assertEqual(clock[0], 15)
                        self.assertIs(emit.call_args.kwargs['clients'], rows)
                    else:
                        with self.assertRaisesRegex(ValueError, 'own client not mapped/visible'):
                            guest.capture_window('minimal', ['monitor'], 42, {'instance': 'held'}, check)
                        emit.assert_not_called()
                    request.assert_called_once()

    def test_capture_query_cannot_reset_or_overrun_existing_deadline(self):
        clock = [0.0]
        def query(env, deadline, check, *, deadline_message):
            self.assertEqual(deadline, 15)
            clock[0] = 15
            return [self.READY]
        with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                patch('guest.time.sleep', side_effect=lambda n: clock.__setitem__(0, clock[0]+n)), \
                patch('guest.query_clients', side_effect=query), patch('guest.emit') as emit:
            with self.assertRaisesRegex(ValueError, 'capture window expired'):
                guest.capture_window('minimal', [], 42, {}, Mock())
            emit.assert_not_called()

    def test_capture_query_failure_retains_identity_without_emitting(self):
        clock = [0.0]
        original = KeyboardInterrupt('fresh observation cancellation')
        with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                patch('guest.time.sleep', side_effect=lambda n: clock.__setitem__(0, clock[0]+n)), \
                patch('guest.query_clients', side_effect=original), patch('guest.emit') as emit:
            with self.assertRaises(KeyboardInterrupt) as caught:
                guest.capture_window('minimal', [], 42, {}, Mock())
            self.assertIs(caught.exception, original)
            emit.assert_not_called()


class Shutdown(unittest.TestCase):
    def test_real_socket_uses_lua_exit_and_waits_for_clean_process(self):
        fixture = test_clients_ipc.ClientsIPC()
        compositor = Mock(returncode=0)
        with fixture.server(b'ok', .03) as (env, requests):
            check = Mock()
            guest.shutdown_compositor(env, compositor, check)
            self.assertEqual(requests, [b'/dispatch hl.dsp.exit()'])
            self.assertGreaterEqual(check.call_count, 4)
            compositor.wait.assert_called_once()
            self.assertTrue(0 < compositor.wait.call_args.kwargs['timeout'] < 15)

    def test_missing_or_wrong_acknowledgement_never_counts_as_shutdown(self):
        for reply in (b'', b'error: wrong syntax', b'ok\n'):
            with self.subTest(reply=reply), patch('guest.private_ipc', return_value=reply):
                compositor = Mock(returncode=0)
                with self.assertRaisesRegex(ValueError, 'acknowledgement differs'):
                    guest.shutdown_compositor({}, compositor, Mock())
                compositor.wait.assert_not_called()

    def test_reply_and_reaping_share_one_deadline_and_require_zero_exit(self):
        for status, end in ((0, 14.5), (3, 14.5), (0, 15.1)):
            with self.subTest(status=status, end=end):
                clock = [0]
                def request(*args): clock[0] = 14; return b'ok'
                def wait(*, timeout):
                    self.assertEqual(timeout, 1); clock[0] = end
                compositor = Mock(returncode=status); compositor.wait.side_effect = wait
                with patch('guest.time.monotonic', side_effect=lambda: clock[0]), \
                        patch('guest.private_ipc', side_effect=request):
                    if status == 0 and end < 15:
                        guest.shutdown_compositor({}, compositor, Mock())
                    else:
                        with self.assertRaisesRegex(ValueError, 'unclean compositor shutdown'):
                            guest.shutdown_compositor({}, compositor, Mock())
        original = subprocess.TimeoutExpired('compositor', 1)
        compositor = Mock(); compositor.wait.side_effect = original
        with patch('guest.private_ipc', return_value=b'ok'):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                guest.shutdown_compositor({}, compositor, Mock())
        self.assertIs(caught.exception, original)


if __name__ == '__main__': unittest.main()
