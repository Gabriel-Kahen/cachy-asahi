"""Finite private Python processes/files; no Docker, compiler or native build."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('stage_runtime', Path(__file__).with_name('runtime.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cachy-stage-runtime-')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(r._REGISTERED.clear)
        self.token = 'a' * 32

    def run_code(self, code, duration=2, on_tick=None):
        return r.run_process([sys.executable, '-c', code], self.root / 'stdout', self.root / 'stderr',
                             time.monotonic() + duration, {'PATH': '/usr/bin:/bin'}, self.root, on_tick)

    def owned(self):
        return r.owned_create(self.root, 'owned', self.token)

    def remove(self, deadline=None):
        return r.owned_remove(self.root, 'owned', self.token, deadline or time.monotonic() + 2)

    def test_process_success_private_logs_and_prior_state_restored(self):
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        prior_handler = signal.getsignal(signal.SIGTERM)
        prior_reaper = r._subreaper()
        result = self.run_code('import sys;print("fixture");print("private",file=sys.stderr)')
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['group_absent'])
        self.assertEqual((self.root / 'stdout').read_bytes(), b'fixture\n')
        self.assertEqual((self.root / 'stderr').read_bytes(), b'private\n')
        self.assertEqual((self.root / 'stderr').stat().st_mode & 0o777, 0o600)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), prior_mask)
        self.assertEqual(signal.getsignal(signal.SIGTERM), prior_handler)
        self.assertEqual(r._subreaper(), prior_reaper)

    def test_child_mask_restored(self):
        result = self.run_code('import signal;print(int(signal.SIGTERM in signal.pthread_sigmask(signal.SIG_BLOCK,set())))')
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual((self.root / 'stdout').read_bytes(), b'0\n')

    def test_pending_signal_consumption_failure_restores_caller_state(self):
        for operation in ('query', 'consume'):
            prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            handlers = {s: signal.getsignal(s) for s in r._signals()}
            scope = r._SignalScope();scope.__enter__()
            with patch.object(r.signal, 'sigpending', side_effect=OSError('private failure')) if operation == 'query' else patch.object(r.signal, 'sigpending', return_value={signal.SIGTERM}):
                with patch.object(r.signal, 'sigtimedwait', side_effect=OSError('private failure')), self.assertRaises(r._Fault):
                    scope.finish()
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), prior_mask)
            self.assertEqual({s: signal.getsignal(s) for s in handlers}, handlers)

    def test_sustained_pending_signals_have_fixed_consumption_bound(self):
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        handlers = {s: signal.getsignal(s) for s in r._signals()}
        scope = r._SignalScope();scope.__enter__()
        with patch.object(r.signal, 'sigpending', return_value={signal.SIGTERM}) as pending, patch.object(r.signal, 'sigtimedwait') as consume, self.assertRaises(r._Fault):
            scope.finish()
        self.assertEqual(consume.call_count, 8)
        self.assertEqual(pending.call_count, 9)
        self.assertIn(signal.SIGTERM, scope.cancelled)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), prior_mask)
        self.assertEqual({s: signal.getsignal(s) for s in handlers}, handlers)

    def test_real_pending_cancellation_consumed_and_prior_mask_restored(self):
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        handler = signal.getsignal(signal.SIGTERM)
        try:
            scope = r._SignalScope();scope.__enter__()
            os.kill(os.getpid(), signal.SIGTERM)
            scope.finish()
            self.assertIn(signal.SIGTERM, scope.cancelled)
            self.assertNotIn(signal.SIGTERM, signal.sigpending())
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), prior_mask | {signal.SIGTERM})
            self.assertEqual(signal.getsignal(signal.SIGTERM), handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)

    def test_signal_consumption_failure_prevents_process_and_cleanup_pass(self):
        self.owned()
        with patch.object(r.signal, 'sigpending', return_value={signal.SIGTERM}), patch.object(r.signal, 'sigtimedwait', side_effect=OSError('private failure')):
            with self.assertRaises(r.RuntimeFailure) as context:
                self.run_code('print("done")')
            self.assertNotIsInstance(context.exception, r.RuntimeCancelled)
            self.assertEqual(context.exception.receipt['status'], 'FAIL')
            self.assertIn('signal-restore-error', context.exception.receipt['teardown_errors'])
            receipt = self.remove()
        self.assertTrue(receipt['removed'])
        self.assertEqual(receipt['status'], 'FAIL')
        self.assertEqual(receipt['reason_code'], 'cleanup-signal-state')
        self.assertIn(signal.SIGTERM, receipt['cancelled_signals'])

    def test_timeout_keeps_partial_stderr_and_kills_group(self):
        with self.assertRaises(r.RuntimeFailure) as context:
            self.run_code('import sys,time;print("partial",file=sys.stderr,flush=True);time.sleep(10)', .3)
        self.assertEqual(context.exception.receipt['reason_code'], 'timeout')
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertEqual((self.root / 'stderr').read_bytes(), b'partial\n')
        self.assertNotIn('partial', str(context.exception))

    def test_term_ignoring_child_requires_kill_and_verified_reap(self):
        code = 'import signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(10)'
        start = time.monotonic()
        with patch.object(r, 'TERM_GRACE', .2), self.assertRaises(r.RuntimeFailure) as context:
            self.run_code(code, .3)
        self.assertEqual(context.exception.receipt['returncode'], -signal.SIGKILL)
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertLess(time.monotonic()-start, 4)

    def test_same_group_grandchild_reaped(self):
        code = 'import subprocess,sys,time;c=subprocess.Popen([sys.executable,"-c","import time;time.sleep(10)"]);print(c.pid,flush=True);time.sleep(10)'
        with self.assertRaises(r.RuntimeFailure) as context:
            self.run_code(code, .4)
        receipt = context.exception.receipt
        self.assertTrue(receipt['group_absent'])
        self.assertGreaterEqual(receipt['group_reaped'], 1)
        descendant = int((self.root / 'stdout').read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(descendant, 0)

    def test_real_cancel_in_spawn_registration_gap(self):
        real_spawn = r.subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            os.kill(os.getpid(), signal.SIGTERM)
            return child
        with patch.object(r.subprocess, 'Popen', side_effect=spawn), self.assertRaises(r.RuntimeCancelled) as context:
            self.run_code('import time;time.sleep(10)')
        self.assertEqual(context.exception.receipt['status'], 'CANCELLED')
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertIsNotNone(children[0].poll())
        self.assertFalse(r._group_exists(children[0].pid))

    def test_cancel_during_successful_teardown_supersedes_pass(self):
        original = r._teardown
        def teardown(*args):
            result = original(*args)
            os.kill(os.getpid(), signal.SIGINT)
            return result
        with patch.object(r, '_teardown', side_effect=teardown), self.assertRaises(r.RuntimeCancelled) as context:
            self.run_code('print("done")')
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertEqual(context.exception.receipt['returncode'], 0)

    def test_tick_failure_and_process_errors_do_not_expose_inputs(self):
        def tick():
            raise ValueError('secret environment and argv')
        with self.assertRaises(r.RuntimeFailure) as context:
            self.run_code('import time;time.sleep(10)', on_tick=tick)
        self.assertEqual(str(context.exception), 'tick-failed')
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertNotIn('secret', json.dumps(context.exception.receipt))

    def test_log_bound_keeps_exact_private_prefix(self):
        with patch.object(r, 'MAX_LOG', 32), self.assertRaises(r.RuntimeFailure) as context:
            self.run_code('import sys;sys.stderr.write("x"*1000);sys.stderr.flush()')
        self.assertEqual(context.exception.receipt['reason_code'], 'log-limit')
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertEqual((self.root / 'stderr').stat().st_size, 32)

    def test_spawn_failure_safe_receipt_and_fresh_logs(self):
        with self.assertRaises(r.RuntimeFailure) as context:
            r.run_process(['/nonexistent/secret'], self.root/'stdout', self.root/'stderr',
                          time.monotonic()+1, {}, self.root)
        self.assertEqual(str(context.exception), 'spawn-failed')
        self.assertNotIn('secret', json.dumps(context.exception.receipt))
        with self.assertRaises(r.RuntimeFailure):
            self.run_code('print("must not overwrite")')

    def test_real_cancel_during_first_handler_installation(self):
        original = r.signal.signal
        fired = []
        def install(number, handler):
            result = original(number, handler)
            if number == signal.SIGTERM and callable(handler) and not fired:
                fired.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with patch.object(r.signal, 'signal', side_effect=install), patch.object(r.subprocess, 'Popen') as spawn, self.assertRaises(r.RuntimeCancelled) as context:
            self.run_code('print("must not spawn")')
        spawn.assert_not_called()
        self.assertTrue(context.exception.receipt['group_absent'])

    def test_handler_install_failure_restores_mask_and_handlers(self):
        original = r.signal.signal
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        prior_term = signal.getsignal(signal.SIGTERM)
        prior_int = signal.getsignal(signal.SIGINT)
        failed = []
        def install(number, handler):
            if number == signal.SIGTERM and callable(handler) and not failed:
                failed.append(True)
                raise OSError('fixture handler install failed')
            return original(number, handler)
        with patch.object(r.signal, 'signal', side_effect=install), self.assertRaises(r.RuntimeFailure):
            self.run_code('print("must not spawn")')
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), prior_mask)
        self.assertEqual(signal.getsignal(signal.SIGTERM), prior_term)
        self.assertEqual(signal.getsignal(signal.SIGINT), prior_int)

    def test_teardown_entry_cancel_is_deferred_until_reaped(self):
        original = r._SignalScope.defer_now
        def defer(scope):
            os.kill(os.getpid(), signal.SIGTERM)
            return original(scope)
        with patch.object(r._SignalScope, 'defer_now', defer), self.assertRaises(r.RuntimeCancelled) as context:
            self.run_code('print("done")')
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertEqual(context.exception.receipt['returncode'], 0)

    def test_active_alarm_cancel_restores_caller_alarm_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, lambda *_: None)
        fired = []
        def tick():
            if not fired:
                fired.append(True)
                os.kill(os.getpid(), signal.SIGALRM)
        try:
            with self.assertRaises(r.RuntimeCancelled) as context:
                self.run_code('import time;time.sleep(10)', on_tick=tick)
            self.assertIn(signal.SIGALRM, context.exception.receipt['cancelled_signals'])
            self.assertTrue(context.exception.receipt['group_absent'])
        finally:
            signal.signal(signal.SIGALRM, previous)

    def test_owned_nested_data_and_external_symlink_target_preserved(self):
        owned = self.owned()
        untouched = self.root / 'untouched';untouched.mkdir()
        (untouched/'keep').write_text('keep')
        (owned/'nested/deep').mkdir(parents=True)
        (owned/'nested/deep/data').write_bytes(b'data')
        (owned/'escape').symlink_to(untouched, target_is_directory=True)
        receipt = self.remove()
        self.assertEqual(receipt['status'], 'PASS')
        self.assertTrue(receipt['removed'])
        self.assertFalse(owned.exists())
        self.assertEqual((untouched/'keep').read_text(), 'keep')

    def test_unregistered_and_foreign_nonce_marker_never_deleted(self):
        outside = self.root / 'unregistered';outside.mkdir()
        (outside/r.MARKER).write_text(json.dumps({'nonce': self.token, 'uid': os.getuid()}))
        result = r.owned_remove(self.root, 'unregistered', self.token, time.monotonic()+1)
        self.assertEqual(result['reason_code'], 'owned-not-registered')
        self.assertTrue(outside.exists())
        owned = self.owned()
        (owned/r.MARKER).write_text(json.dumps({'nonce': 'b'*32, 'uid': os.getuid()}))
        self.assertEqual(self.remove()['status'], 'FAIL')
        self.assertTrue(owned.exists())

    def test_hardlink_and_foreign_uid_refused(self):
        owned = self.owned()
        outside = self.root/'outside';outside.write_text('retained')
        os.link(outside, owned/'linked')
        receipt = self.remove()
        self.assertEqual(receipt['reason_code'], 'cleanup-hardlink-refused')
        self.assertEqual(outside.read_text(), 'retained')
        (owned/'linked').unlink()
        (owned/'foreign').write_text('foreign fixture')
        original = r.os.stat
        def observe(path, *args, **kwargs):
            data = original(path, *args, **kwargs)
            if path == 'foreign':
                return SimpleNamespace(st_uid=os.getuid()+1, st_dev=data.st_dev)
            return data
        with patch.object(r.os, 'stat', side_effect=observe):
            self.assertEqual(self.remove()['reason_code'], 'foreign-cleanup-entry')
        self.assertTrue((owned/'foreign').exists())

    def test_bind_mount_identity_rejected_without_unlink(self):
        owned = self.owned();(owned/'data').write_text('keep')
        with patch.object(r, '_mounts', return_value=[str(owned/'nested')]):
            receipt = self.remove()
        self.assertEqual(receipt['reason_code'], 'owned-mount-refused')
        self.assertEqual((owned/'data').read_text(), 'keep')

    def test_bounds_are_failure_with_retryable_partial_owned_data(self):
        owned = self.owned()
        (owned/'first').write_text('1');(owned/'second').write_text('2')
        with patch.object(r, 'MAX_MEMBERS', 1):
            receipt = self.remove()
        self.assertEqual(receipt['status'], 'FAIL')
        self.assertFalse(receipt['removed'])
        self.assertTrue((owned/r.MARKER).exists())
        self.assertEqual(self.remove()['status'], 'PASS')

    def test_deadline_and_disk_bound(self):
        owned = self.owned();(owned/'large').write_bytes(b'1234')
        self.assertEqual(self.remove(time.monotonic()-1)['reason_code'], 'cleanup-deadline')
        with patch.object(r, 'MAX_DISK', 3):
            self.assertEqual(self.remove()['reason_code'], 'cleanup-disk-bound')
        self.assertTrue((owned/'large').exists())

    def test_creation_failed_marker_write_remains_owned_for_cleanup(self):
        original = r.os.write
        def fail(fd, data):
            raise OSError('private disk failure')
        with patch.object(r.os, 'write', side_effect=fail), self.assertRaises(r.RuntimeFailure) as context:
            self.owned()
        self.assertTrue(context.exception.receipt['registered'])
        owned = self.root/'owned';(owned/'partial').mkdir();(owned/'partial/data').write_text('partial')
        self.assertEqual(self.remove()['status'], 'PASS')

    def test_post_removal_signal_cannot_preserve_pass(self):
        owned = self.owned();(owned/'data').write_text('data')
        original = r.os.rmdir
        def remove(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == 'owned':
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with patch.object(r.os, 'rmdir', side_effect=remove):
            receipt = self.remove()
        self.assertEqual(receipt['status'], 'CANCELLED')
        self.assertTrue(receipt['removed'])
        self.assertFalse(owned.exists())

    def test_creation_cancel_registers_child_before_return(self):
        original = r.os.write
        fired = []
        def write(fd, data):
            result = original(fd, data)
            if not fired:
                fired.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with patch.object(r.os, 'write', side_effect=write), self.assertRaises(r.RuntimeCancelled) as context:
            self.owned()
        self.assertTrue(context.exception.receipt['registered'])
        self.assertEqual(self.remove()['status'], 'PASS')

    def test_named_root_replacement_during_scan_stops_all_unlinks(self):
        owned = self.owned();(owned/'data').write_text('original own data')
        original = r.os.scandir
        moved = self.root/'moved'
        changed = []
        def scan(fd):
            result = original(fd)
            if not changed:
                changed.append(True)
                owned.rename(moved)
                owned.mkdir(mode=0o700)
                (owned/'untouched').write_text('new entry')
            return result
        with patch.object(r.os, 'scandir', side_effect=scan):
            receipt = self.remove()
        self.assertEqual(receipt['reason_code'], 'owned-root-changed')
        self.assertEqual((moved/'data').read_text(), 'original own data')
        self.assertEqual((owned/'untouched').read_text(), 'new entry')

    def test_private_spawn_registration_before_unmask(self):
        captured = []
        def register(identity):
            captured.append(identity)
            self.assertIn(signal.SIGTERM, signal.pthread_sigmask(signal.SIG_BLOCK, set()))
            self.assertEqual(identity['pid'], identity['group'])
            self.assertEqual(identity['start_ticks'], r._pid_start(identity['pid']))
            os.kill(os.getpid(), signal.SIGTERM)
        with self.assertRaises(r.RuntimeCancelled) as context:
            r.run_process([sys.executable, '-c', 'import time;time.sleep(10)'], self.root/'stdout', self.root/'stderr',
                          time.monotonic()+2, {}, self.root, on_spawn=register)
        self.assertTrue(context.exception.receipt['group_absent'])
        self.assertNotIn('pid', context.exception.receipt)
        self.assertEqual(len(captured), 1)

    def test_registration_failure_and_unknown_pid_identity_kill_group(self):
        for failure in ('callback', 'unknown'):
            output = self.root/failure;output.mkdir(mode=0o700)
            def register(_):
                raise ValueError('private owner record failed')
            with patch.object(r, '_pid_start', side_effect=FileNotFoundError()) if failure == 'unknown' else patch.object(r, '_pid_start', wraps=r._pid_start):
                with self.assertRaises(r.RuntimeFailure) as context:
                    r.run_process([sys.executable, '-c', 'import time;time.sleep(10)'], output/'stdout', output/'stderr',
                                  time.monotonic()+2, {}, output, on_spawn=(lambda _: None) if failure=='unknown' else register)
            self.assertEqual(context.exception.receipt['reason_code'], 'registration-failed')
            self.assertTrue(context.exception.receipt['group_absent'])

    def test_authentication_bound_record_can_restore_exact_registration(self):
        owned = self.owned();(owned/'data').write_text('owned')
        record = json.loads(json.dumps(r.owned_record(self.root, 'owned', self.token)))
        r._REGISTERED.clear()
        r.owned_adopt(self.root, 'owned', self.token, record)
        self.assertEqual(self.remove()['status'], 'PASS')

    def test_forged_recovery_record_cannot_grant_other_inode_or_marker(self):
        import copy
        owned = self.owned();(owned/'keep').write_text('owned')
        record = r.owned_record(self.root, 'owned', self.token)
        r._REGISTERED.clear()
        for field in ('child', 'parent', 'uid', 'nonce', 'marker'):
            changed = copy.deepcopy(record)
            if field in ('child', 'parent', 'marker'):
                changed[field][1] += 1
            elif field == 'uid':
                changed[field] += 1
            else:
                changed[field] = 'b'*32
            with self.subTest(field=field), self.assertRaises(r.RuntimeFailure):
                r.owned_adopt(self.root, 'owned', self.token, changed)
        self.assertEqual((owned/'keep').read_text(), 'owned')
        self.assertFalse(r._REGISTERED)

    def test_registered_parent_or_directory_replacement_refused(self):
        owned = self.owned();renamed = self.root/'old';owned.rename(renamed)
        owned.mkdir(mode=0o700)
        (owned/'keep').write_text('untouched replacement')
        receipt = self.remove()
        self.assertEqual(receipt['reason_code'], 'owned-identity-changed')
        self.assertTrue(renamed.exists())
        self.assertEqual((owned/'keep').read_text(), 'untouched replacement')


if __name__ == '__main__':
    unittest.main()
