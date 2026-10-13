#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_nonregular_links_duplicates_and_bounds_refused(self):
        path = self.root / 'data.json'; path.write_text('{"a":1,"a":2}')
        with self.assertRaises(ValueError): common.read_json(path)
        with self.assertRaises(ValueError): common.read_regular(path, 1)
        link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises(ValueError): common.read_regular(link)
        os.link(path, self.root / 'hardlink')
        with self.assertRaises(ValueError): common.read_regular(path)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): common.read_regular(fifo)

    def test_pinned_copy_requires_exact_bytes_and_fresh_destination(self):
        path = self.root / 'source'; path.write_bytes(b'correct')
        target = self.root / 'copy'
        pin = common.digest(path)
        self.assertEqual(common.copy_pinned(path, target, pin)['sha256'], pin)
        with self.assertRaises(FileExistsError): common.copy_pinned(path, target, pin)
        with self.assertRaises(ValueError): common.copy_pinned(path, self.root / 'other', '0' * 64)

    def test_opened_descriptor_rechecks_link_count_before_read_or_hash(self):
        from unittest.mock import patch
        for operation in (common.read_regular, common.digest):
            source = self.root / operation.__name__; source.write_bytes(b'fixture')
            original = os.open
            def changed(path, flags):
                descriptor = original(path, flags)
                os.link(source, self.root / (operation.__name__ + '-link'))
                return descriptor
            with patch.object(common.os, 'open', side_effect=changed):
                with self.assertRaises(ValueError): operation(source)

    def test_interrupted_atomic_status_write_can_retry_without_deleting_unowned_partial(self):
        from unittest.mock import patch
        target = self.root / 'result.json'
        common.save(target, {'status':'PASS'})
        unowned = self.root / 'result.json.partial'; unowned.write_text('unowned')
        def interrupted(value, stream, **kwargs):
            stream.write('{'); raise KeyboardInterrupt()
        with patch.object(common.json, 'dump', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt): common.save(target, {'status':'FAIL'})
        common.save(target, {'status':'FAIL'})
        self.assertEqual(common.read_json(target)['status'], 'FAIL')
        self.assertEqual(unowned.read_text(), 'unowned')
        self.assertEqual(list(self.root.glob('*.partial')), [unowned])

    def test_deadline_allows_owner_term_handler_to_finalize(self):
        helper = self.root / 'worker.py'
        receipt = self.root / 'cleanup.json'
        helper.write_text('import signal,time,sys\nfrom pathlib import Path\n'
                          'def stop(*_):\n Path(sys.argv[1]).write_text("cleaned")\n raise SystemExit(0)\n'
                          'signal.signal(signal.SIGTERM,stop)\nprint("started",flush=True)\ntime.sleep(30)\n')
        with self.assertRaises(ValueError):
            common.command([sys.executable, str(helper), str(receipt)], self.root / 'log', 0.5)
        self.assertEqual(receipt.read_text(), 'cleaned')

    def test_alarm_after_spawn_before_registration_cannot_lose_owned_process(self):
        import signal
        from unittest.mock import patch
        original = common.subprocess.Popen
        owned = []
        def spawning(*args, **kwargs):
            process = original(*args, **kwargs)
            owned.append(process)
            os.kill(os.getpid(), signal.SIGALRM)
            return process
        def interrupted(*_): raise KeyboardInterrupt()
        previous = signal.signal(signal.SIGALRM, interrupted)
        reaped_by_command = False
        try:
            with patch.object(common.subprocess, 'Popen', side_effect=spawning):
                with self.assertRaises(KeyboardInterrupt):
                    common.command([sys.executable, '-c', 'import time; time.sleep(30)'], self.root / 'log', 5)
            reaped_by_command = len(owned) == 1 and owned[0].poll() is not None
        finally:
            signal.signal(signal.SIGALRM, previous)
            for process in owned:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
        self.assertEqual(len(owned), 1)
        self.assertTrue(reaped_by_command)

    def test_output_bound_still_drains_cleanup_output(self):
        helper = self.root / 'worker.py'; receipt = self.root / 'cleaned'
        helper.write_text('import signal,time,sys,os\nfrom pathlib import Path\n'
                          'def stop(*_):\n os.write(1,b"z"*200000)\n'
                          ' Path(sys.argv[1]).write_text("cleaned")\n raise SystemExit(0)\n'
                          'signal.signal(signal.SIGTERM,stop)\n'
                          'while True:\n os.write(1,b"x"*65536);time.sleep(.002)\n')
        with self.assertRaises(ValueError):
            common.command([sys.executable, str(helper), str(receipt)], self.root / 'log', 5)
        self.assertEqual(receipt.read_text(), 'cleaned')
        self.assertLessEqual((self.root / 'log').stat().st_size, common.LOG_LIMIT)

    def test_controlled_environment_omits_credentials_and_python_overrides(self):
        helper = self.root / 'env.py'
        helper.write_text('import os,json\nprint(json.dumps(dict(os.environ)))\n')
        from unittest.mock import patch
        with patch.dict(os.environ, {'AUTHORIZATION': 'hidden', 'PYTHONPATH': '/untrusted', 'DOCKER_HOST': 'tcp://remote'}):
            self.assertEqual(common.command([sys.executable, str(helper)], self.root / 'log', 5), 0)
        value = json.loads((self.root / 'log').read_text())
        self.assertNotIn('AUTHORIZATION', value)
        self.assertNotIn('PYTHONPATH', value)
        self.assertNotIn('DOCKER_HOST', value)

    def test_matching_count_without_authenticated_bootstrap_is_refused(self):
        from types import SimpleNamespace
        controller = SimpleNamespace(native_out=self.root, image='sha256:' + 'a' * 64, commit='b' * 40)
        inputs = {'rootfs_packages': [{'name':[f'package-{i}'],'version':['1']} for i in range(341)], 'packages':[]}
        common.save(self.root / 'inputs.lock.json', inputs)
        lock = ''.join(f'package-{i} 1\n' for i in sorted(range(341), key=lambda i:f'package-{i}'))
        (self.root / 'packages.lock').write_text(lock)
        (self.root / 'image-id').write_text(controller.image)
        common.save(self.root / 'result.json', {'native_build':'PASS','reviewed_inputs_sha256':common.digest(self.root / 'inputs.lock.json')})
        boot = {'status':'image-provisioned','image_id':controller.image,'packages_lock_sha256':common.digest(self.root / 'packages.lock'),
                'inputs_sha256':common.digest(self.root / 'inputs.lock.json')}
        common.save(self.root / 'bootstrap.json', boot)
        self.assertEqual(common.base_prerequisite(controller)['package_count'], 341)
        boot['inputs_sha256'] = '0' * 64; common.save(self.root / 'bootstrap.json', boot)
        with self.assertRaises(ValueError): common.base_prerequisite(controller)


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import Mock
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.clock = [100.0]; self.trace = []
        self.pipe = Mock(); self.pipe.fileno.return_value = 123
        self.process = Mock(pid=4321, stdout=self.pipe)
        self.process.poll.return_value = None
        self.process.wait.side_effect = lambda timeout: self.trace.append(('wait', timeout)) or 0

    def selector(self, *, register_error=None, read=True, close_error=None):
        from types import SimpleNamespace
        trace, process = self.trace, self.process
        class Events:
            def __init__(self): self.mapping = {}
            def register(self, pipe, event):
                if register_error: raise register_error
                self.mapping[123] = SimpleNamespace(fd=123, fileobj=pipe)
            def unregister(self, pipe): self.mapping.clear(); process.poll.return_value = 0
            def get_map(self): return self.mapping
            def select(self, timeout):
                trace.append(('select', timeout))
                return [(next(iter(self.mapping.values())), 1)] if read and self.mapping else []
            def close(self):
                trace.append(('selector-close',))
                if close_error: raise close_error
        return Events()

    def patches(self, selectors):
        from contextlib import ExitStack
        from unittest.mock import patch
        stack = ExitStack()
        stack.enter_context(patch.object(common.time, 'monotonic', side_effect=lambda: self.clock[0]))
        stack.enter_context(patch.object(common.signal, 'pthread_sigmask', return_value=set()))
        stack.enter_context(patch.object(common.signal, 'signal', return_value='previous'))
        stack.enter_context(patch.object(common.selectors, 'DefaultSelector', side_effect=selectors))
        stack.enter_context(patch.object(common.subprocess, 'Popen', return_value=self.process))
        stack.enter_context(patch.object(common.os, 'killpg', side_effect=lambda pid, sig: self.trace.append(('kill', sig))))
        stack.enter_context(patch.object(common.os, 'read', return_value=b''))
        return stack

    def test_malformed_expired_and_insufficient_deadline_refuse_before_log_or_spawn(self):
        from unittest.mock import patch
        for deadline in (True, False, float('inf'), float('nan'), '200', 10**1000, 100, 99, 200):
            with self.subTest(deadline=str(deadline)[:20]), patch.object(common.time, 'monotonic', return_value=100), \
                 patch.object(Path, 'open') as opening, patch.object(common.subprocess, 'Popen') as spawning:
                with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                    common.command(['inert'], self.root / 'log', 30, deadline=deadline)
                opening.assert_not_called(); spawning.assert_not_called()

    def test_setup_latency_cannot_spawn_after_job_or_work_cutoff(self):
        from unittest.mock import patch
        for latency in ('argv', 'environment', 'blocked-mask'):
            self.clock[0] = 100; self.trace.clear(); masks = []
            clock = self.clock
            class Argument:
                def __str__(self):
                    if latency == 'argv': clock[0] = 131
                    return 'inert'
            def environment():
                if latency == 'environment': clock[0] = 131
                return {'PATH':'/usr/bin'}
            def mask(operation, value):
                masks.append(operation)
                if len(masks) == 1 and latency == 'blocked-mask': clock[0] = 230
                return set()
            with self.patches([self.selector()]), \
                 patch.object(common, 'controlled_env', side_effect=environment), \
                 patch.object(common.signal, 'pthread_sigmask', side_effect=mask), \
                 patch.object(common.subprocess, 'Popen') as spawning:
                with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                    common.command([Argument()], self.root / ('log-' + latency), 100, deadline=230)
            spawning.assert_not_called(); self.assertEqual(len(masks), 2)
            self.assertEqual(masks[-1], common.signal.SIG_SETMASK)

    def test_success_uses_original_short_timeout_and_same_deadline(self):
        with self.patches([self.selector()]):
            self.assertEqual(common.command(['inert'], self.root / 'log', 7, deadline=230), 0)
        self.assertEqual(self.trace[1], ('wait', 7.0)); self.pipe.close.assert_called_once()

    def test_work_cutoff_reserved_upfront_and_cleanup_never_renews_J(self):
        from unittest.mock import patch
        selector = self.selector()
        def selecting(timeout): self.clock[0] = 120; return []
        selector.select = selecting
        with self.patches([selector]), patch.object(common, '_stop') as stopping:
            with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                common.command(['inert'], self.root / 'log', 500, deadline=220)
        stopping.assert_called_once_with(self.process, grace=90, deadline=220)

    def test_late_zero_exit_is_refused_and_owned_cleanup_runs(self):
        from unittest.mock import patch
        def wait(timeout): self.clock[0] = 111; return 0
        self.process.wait.side_effect = wait
        with self.patches([self.selector()]), patch.object(common, '_stop') as stopping:
            with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                common.command(['inert'], self.root / 'log', 10, deadline=220)
        stopping.assert_called_once_with(self.process, grace=90, deadline=220)

    def test_TERM_fault_cannot_prevent_KILL_reap_and_handler_restoration(self):
        import signal
        from unittest.mock import patch
        first = OSError('TERM refused'); calls = []
        def kill(pid, sig):
            self.trace.append(('kill', sig))
            if sig == signal.SIGTERM: raise first
        def handlers(sig, disposition): calls.append((sig, disposition)); return 'old'
        with self.patches([self.selector()]), patch.object(common.os, 'killpg', side_effect=kill), \
             patch.object(common.signal, 'signal', side_effect=handlers):
            with self.assertRaises(common.CleanupFailure) as caught: common._stop(self.process, deadline=110)
        self.assertIs(caught.exception.__cause__, first)
        self.assertEqual(self.trace[:2], [('kill', signal.SIGTERM), ('selector-close',)])
        self.assertIn(('kill', signal.SIGKILL), self.trace); self.assertIn(('wait', 10), self.trace)
        self.assertEqual(len(calls), 6)

    def test_pipe_or_selector_fault_still_force_stops_and_reaps(self):
        import signal
        from unittest.mock import patch
        first = OSError('pipe failed'); secondary = OSError('selector disposal failed')
        self.process.poll.return_value = None
        with self.patches([self.selector(close_error=secondary)]), \
             patch.object(common.os, 'read', side_effect=first):
            with self.assertRaises(common.CleanupFailure) as caught: common._stop(self.process, grace=1, deadline=130)
        self.assertIs(caught.exception.__cause__, first)
        self.assertIn(('kill', signal.SIGKILL), self.trace); self.assertIn(('wait', 10), self.trace)

    def test_restore_fault_does_not_skip_other_handlers_or_reap(self):
        import signal
        from unittest.mock import patch
        first = OSError('restore failed'); calls = []
        self.process.poll.return_value = 0
        def handler(sig, value):
            calls.append((sig, value))
            if value == 'old': raise first
            return 'old'
        with self.patches([self.selector()]), patch.object(common.signal, 'signal', side_effect=handler):
            with self.assertRaises(common.CleanupFailure) as caught: common._stop(self.process, deadline=130)
        self.assertIs(caught.exception.__cause__, first); self.assertEqual(len(calls), 6)
        self.assertIn(('wait', 10), self.trace)

    def test_expired_owned_cleanup_KILL_and_zero_wait_cannot_PASS(self):
        import signal, subprocess
        with self.patches([self.selector()]):
            with self.assertRaisesRegex(common.CleanupFailure, 'stage-cleanup-failed') as caught:
                common._stop(self.process, deadline=99)
        self.assertEqual(str(caught.exception.__cause__), 'stage-deadline-exceeded')
        self.assertIn(('kill', signal.SIGKILL), self.trace); self.assertIn(('wait', 0), self.trace)
        self.assertFalse(any(row[0] == 'select' for row in self.trace))

    def test_post_restore_and_post_disposal_expiry_cannot_return_healthy(self):
        from unittest.mock import patch
        self.process.poll.return_value = 0
        def handlers(sig, disposition):
            if disposition == 'old': self.clock[0] = 130
            return 'old'
        with self.patches([self.selector()]), patch.object(common.signal, 'signal', side_effect=handlers):
            with self.assertRaisesRegex(common.CleanupFailure, 'stage-cleanup-failed') as caught:
                common._stop(self.process, deadline=130)
        self.assertIsNone(caught.exception.natural_returncode)
        self.assertEqual(str(caught.exception.__cause__), 'stage-deadline-exceeded')
        self.clock[0] = 100; self.process.wait.side_effect = lambda timeout: 0
        self.pipe.close.side_effect = lambda: self.clock.__setitem__(0, 230)
        with self.patches([self.selector()]):
            with self.assertRaises(common.CleanupFailure) as caught:
                common.command(['inert'], self.root / 'log', 10, deadline=230)
        self.assertEqual(caught.exception.natural_returncode, 0)
        self.assertEqual(str(caught.exception.__cause__), 'stage-deadline-exceeded')

    def test_normal_nonzero_fact_survives_typed_disposal_uncertainty(self):
        from unittest.mock import patch
        first = OSError('pipe disposal failed')
        self.process.wait.side_effect = lambda timeout: 7; self.pipe.close.side_effect = first
        with self.patches([self.selector()]):
            with self.assertRaises(common.CleanupFailure) as caught:
                common.command(['inert'], self.root / 'log', 10, deadline=230)
        self.assertEqual(caught.exception.natural_returncode, 7)
        self.assertEqual(caught.exception.code, 'stage-cleanup-failed'); self.assertIs(caught.exception.__cause__, first)
        for value in (True, '7', 256, -129):
            with self.assertRaisesRegex(ValueError, 'stage-returncode-invalid'):
                common.CleanupFailure(value)

    def test_command_first_business_and_control_survive_cleanup_and_disposal_faults(self):
        import signal
        from unittest.mock import patch
        for first in (ValueError('business'), KeyboardInterrupt('control')):
            self.trace.clear(); self.pipe.close.reset_mock(); self.pipe.close.side_effect = OSError('pipe disposal')
            initial = self.selector(register_error=first, close_error=OSError('selector disposal'))
            cleanup = self.selector(register_error=OSError('cleanup pipe unavailable'))
            def kill(pid, sig):
                self.trace.append(('kill', sig))
                if sig == signal.SIGTERM: raise OSError('TERM failure')
            with self.patches([initial, cleanup]), patch.object(common.os, 'killpg', side_effect=kill):
                with self.assertRaises(type(first)) as caught:
                    common.command(['inert'], self.root / ('log-' + type(first).__name__), 10, deadline=230)
            self.assertIs(caught.exception, first); self.assertIn(('kill', signal.SIGKILL), self.trace)
            self.assertIn(('wait', 10), self.trace); self.pipe.close.assert_called_once()

    def test_partial_log_write_refuses_and_cleans_owned_process(self):
        import signal
        from unittest.mock import Mock, patch
        stream = Mock(); stream.write.return_value = 1
        with self.patches([self.selector(), self.selector()]), patch.object(common.os, 'read', side_effect=[b'bytes', b'']), \
             patch.object(Path, 'open', return_value=stream):
            with self.assertRaisesRegex(ValueError, 'stage-write-failed'):
                common.command(['inert'], self.root / 'log', 10, deadline=230)
        self.assertIn(('kill', signal.SIGTERM), self.trace); self.assertIn(('wait', 10), self.trace)
        stream.close.assert_called_once(); self.pipe.close.assert_called_once()

    def test_read_hash_and_copy_deadline_checks_and_partial_disposal(self):
        from unittest.mock import patch
        source = self.root / 'source'; source.write_bytes(b'original'); target = self.root / 'copy'
        for operation in (common.read_regular, common.digest, common.read_json):
            with patch.object(common.time, 'monotonic', return_value=100), patch.object(common.os, 'open') as opening:
                with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                    operation(source, deadline=99)
                opening.assert_not_called()
        original = common._write
        def late(stream, data, deadline):
            original(stream, data, deadline); self.clock[0] = deadline
        with patch.object(common.time, 'monotonic', side_effect=lambda: self.clock[0]), \
             patch.object(common, '_write', side_effect=late):
            with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                common.copy_regular(source, target, deadline=110)
        self.assertFalse(target.exists()); self.assertEqual(source.read_bytes(), b'original')

    def test_read_and_hash_expiry_after_actual_partial_read_is_refused(self):
        from unittest.mock import patch
        source = self.root / 'source'; source.write_bytes(b'fixture' * 10000)
        original = common.os.fdopen
        for operation in (common.read_regular, common.digest):
            self.clock[0] = 100; closed = []; clock = self.clock
            class Stream:
                def __init__(self, fd, mode): self.stream = original(fd, mode)
                def __enter__(self): return self
                def __exit__(self, *args): self.stream.close(); closed.append(True)
                def fileno(self): return self.stream.fileno()
                def read(self, count):
                    block = self.stream.read(count); clock[0] = 110; return block
            with patch.object(common.time, 'monotonic', side_effect=lambda: self.clock[0]), \
                 patch.object(common.os, 'fdopen', side_effect=Stream):
                with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                    operation(source, deadline=110)
            self.assertEqual(closed, [True]); self.assertEqual(source.stat().st_size, 70000)

    def test_spawn_failure_first_control_survives_signal_mask_restore_fault(self):
        from unittest.mock import patch
        first = KeyboardInterrupt('spawn control'); calls = []
        def mask(operation, value):
            calls.append(operation)
            if len(calls) == 2: raise OSError('mask restore fault')
            return set()
        with self.patches([self.selector()]), patch.object(common.subprocess, 'Popen', side_effect=first), \
             patch.object(common.signal, 'pthread_sigmask', side_effect=mask):
            with self.assertRaises(KeyboardInterrupt) as caught:
                common.command(['inert'], self.root / 'log', 10, deadline=230)
        self.assertIs(caught.exception, first); self.assertEqual(len(calls), 2)

    def test_expired_atomic_save_does_not_publish_or_remove_unowned_partial(self):
        from unittest.mock import patch
        target = self.root / 'result.json'; common.save(target, {'status':'old'})
        unowned = self.root / 'result.json.unowned.partial'; unowned.write_text('unowned')
        original = common._write; writes = []
        def late(stream, data, deadline):
            writes.append(data); original(stream, data, deadline); self.clock[0] = deadline
        with patch.object(common.time, 'monotonic', side_effect=lambda: self.clock[0]), \
             patch.object(common, '_write', side_effect=late):
            with self.assertRaisesRegex(ValueError, 'stage-deadline-exceeded'):
                common.save(target, {'status':'new'}, deadline=110)
        self.assertEqual(common.read_json(target)['status'], 'old'); self.assertEqual(unowned.read_text(), 'unowned')
        self.assertEqual(list(self.root.glob('*.partial')), [unowned])

    def test_explicit_J_forwarded_through_pin_copy_json_and_prerequisite(self):
        from unittest.mock import patch
        source = self.root / 'source'; source.write_bytes(b'fixture')
        pin = common.digest(source); target = self.root / 'copy'
        with patch.object(common.time, 'monotonic', return_value=100), \
             patch.object(common, 'check_deadline', wraps=common.check_deadline) as check:
            self.assertEqual(common.copy_pinned(source, target, pin, deadline=250)['sha256'], pin)
            self.assertTrue(check.call_args_list); self.assertTrue(all(c.args == (250,) for c in check.call_args_list))


if __name__ == '__main__':
    unittest.main()
