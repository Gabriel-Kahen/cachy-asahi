"""Inert readiness/cleanup controls: no guest tools or child processes."""
import importlib.util
from pathlib import Path
import signal
import subprocess
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('desktop574_guest', Path(__file__).with_name('desktop574_guest.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestTests(unittest.TestCase):
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
