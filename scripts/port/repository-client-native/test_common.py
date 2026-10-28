# SPDX-License-Identifier: MIT
"""Real process tests plus explicitly modeled Docker CLI control fixtures."""
import os
import gzip
import lzma
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import common

HERE = Path(__file__).parent
IMAGE = 'sha256:' + 'a' * 64


class Runtime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rcn-common-tests-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_actual_cli_dual_stream_and_nonzero(self):
        cmd = common.Commands(self.root, ('python3',))
        out, err = cmd.run(['python3', '-I', '-c', 'import sys; print("out"); print("err",file=sys.stderr); sys.exit(7)'], expected='nonzero')
        self.assertEqual((out, err), (b'out\n', b'err\n'))
        self.assertEqual(cmd.records[0]['exit_code'], 7)

    def test_actual_output_bound(self):
        cmd = common.Commands(self.root, ('python3',))
        with self.assertRaisesRegex(common.Refused, 'output bound'):
            cmd.run(['python3', '-I', '-c', 'import os; os.write(1,b"x"*(2*1024**2))'])
        self.assertEqual(cmd.records, [])

    def test_actual_deadline_reaps(self):
        cmd = common.Commands(self.root, ('python3',), timeout=.08)
        with self.assertRaisesRegex(common.Refused, 'deadline'):
            cmd.run(['python3', '-I', '-c', 'import time; time.sleep(60)'])
        self.assertEqual(cmd.records, [])

    def test_real_signals_after_spawn_before_assignment_reap(self):
        original = subprocess.Popen
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(sig=sig):
                children = []
                def spawn(*args, **kwargs):
                    child = original(*args, **kwargs)
                    children.append(child)
                    os.kill(os.getpid(), sig)
                    return child
                cmd = common.Commands(self.root, ('python3',))
                with patch.object(common.subprocess, 'Popen', spawn), self.assertRaises(KeyboardInterrupt):
                    cmd.run(['python3', '-I', '-c', 'import time; time.sleep(60)'])
                self.assertIsNotNone(children[0].returncode)
                self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
                self.assertEqual(cmd.records, [])

    def test_nested_signal_finishes_outer_teardown(self):
        done = []
        with self.assertRaises(KeyboardInterrupt):
            with common.defer_cancellation():
                with common.defer_cancellation():
                    os.kill(os.getpid(), signal.SIGTERM)
                done.append(True)
        self.assertEqual(done, [True])
        self.assertEqual(common.PENDING, [])

    def test_source_drift_refused_before_import(self):
        source = self.root / 'source'; source.mkdir()
        (source / 'probe.py').write_text('raise RuntimeError("must not execute")\n')
        with self.assertRaisesRegex(common.Refused, 'source bytes'):
            common.snapshot(source, {'probe.py': {'sha256': '0' * 64, 'mode': 0o644}}, self.root / 'copied')
        self.assertFalse((self.root / 'copied').exists())

    def test_poisoned_pyc_excluded_from_source_execution(self):
        source = self.root / 'source'; source.mkdir()
        raw = b'value=42\n'; (source / 'probe.py').write_bytes(raw)
        cache = source / '__pycache__'; cache.mkdir(); (cache / 'probe.pyc').write_bytes(b'hostile bytecode')
        copied = common.snapshot(source, {'probe.py': {'sha256': common.digest(raw), 'mode': 0o644}}, self.root / 'copied')
        self.assertEqual(common.load_snapshot(copied, ('probe',))['probe'].value, 42)
        self.assertFalse((copied / '__pycache__').exists())

    def test_links_duplicate_json_and_extra_map_refused(self):
        (self.root / 'a').write_bytes(b'x')
        (self.root / 'b').symlink_to('a')
        with self.assertRaises(OSError): common.read(self.root / 'b')
        with self.assertRaises(common.Refused): common.decode(b'{"a":1,"a":2}')
        with self.assertRaises(common.Refused):
            common.mapped(self.root, {'a': {'sha256': common.digest(b'x'), 'bytes': 1}})

    def test_bounded_decompression_before_tar_header_parsing(self):
        for compressor in (gzip.compress, lzma.compress):
            raw = compressor(b'x' * 65537)
            with self.assertRaises(common.Refused): common.bounded_tar_payload(raw, limit=65536)
            with self.assertRaises(common.Refused): common.bounded_tar_payload(raw + b'trailing', limit=100000)

    def test_installed_tool_hash_has_separate_streaming_bound(self):
        tool = self.root / 'docker'
        with tool.open('wb') as stream:
            stream.write(b'x' * (17 * 1024**2))
        with patch.object(common.shutil, 'which', return_value=str(tool)):
            commands = common.Commands(self.root, ('docker',))
        self.assertEqual(commands.pins['docker'], common.digest(tool.read_bytes()))
        with tool.open('wb') as stream:
            stream.truncate(129 * 1024**2)
        with self.assertRaisesRegex(common.Refused, 'installed tool'):
            common.tool_digest(tool)


class SignalTransitions(unittest.TestCase):
    """Real kernel signals at guard cut points; own children always disposed."""
    def setUp(self):
        self.mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        self.handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def tearDown(self):
        signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGINT, signal.SIGTERM))
        for sig in (signal.SIGINT, signal.SIGTERM):
            if sig not in self.mask and sig in signal.sigpending():
                signal.sigwait({sig})
        for sig, handler in self.handlers.items():
            signal.signal(sig, handler)
        common.PENDING.clear()
        signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)

    def assert_restored(self):
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), self.mask)
        self.assertEqual({sig: signal.getsignal(sig) for sig in self.handlers}, self.handlers)
        self.assertEqual(common.PENDING, [])

    def test_actual_TERM_during_cleanup_first_handler_install_reaps(self):
        real_spawn, real_handler = subprocess.Popen, signal.signal
        children, entered, fired = [], [], []
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs); children.append(child); return child
        def install(sig, handler):
            result = real_handler(sig, handler)
            frame, names = sys._getframe(), []
            while frame is not None:
                names.append(frame.f_code.co_name); frame = frame.f_back
            if sig == signal.SIGINT and 'defer_cancellation' in names and getattr(handler, '__name__', '') == 'remember':
                entered.append(True)
                if len(entered) == 2 and not fired:
                    fired.append(True); os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with tempfile.TemporaryDirectory(prefix='rcn-cleanup-entry-signal-') as temporary:
                commands = common.Commands(Path(temporary), ('python3',), timeout=.03, total_seconds=3)
                with common.cancellation_handlers(), patch.object(common.subprocess, 'Popen', spawn), patch.object(common.signal, 'signal', install):
                    with self.assertRaises(KeyboardInterrupt):
                        commands.run(['python3', '-I', '-B', '-c', 'import time;time.sleep(5)'])
                self.assertTrue(fired)
                self.assertEqual(commands.records, [])
                self.assertIsNotNone(children[0].poll(), 'cleanup-entry cancellation left the owned child alive')
                self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
                self.assert_restored()
        finally:
            for child in children:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=2)
                child.stdout.close(); child.stderr.close()

    def test_both_entry_installs_are_transactional_real_signals(self):
        real_handler = signal.signal
        for number in (signal.SIGINT, signal.SIGTERM):
            for position in (1, 2):
                with self.subTest(number=number, position=position):
                    installs, done = [], []
                    def install(sig, handler):
                        old = real_handler(sig, handler)
                        if getattr(handler, '__name__', '') == 'remember':
                            installs.append(sig)
                            if len(installs) == position: os.kill(os.getpid(), number)
                        return old
                    with patch.object(common.signal, 'signal', install), self.assertRaises(KeyboardInterrupt):
                        with common.defer_cancellation(): done.append(True)
                    self.assertEqual(done, [True])
                    self.assert_restored()

    def test_restoration_pair_is_transactional_real_signals(self):
        real_handler = signal.signal
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(number=number):
                fired, done = [], []
                def install(sig, handler):
                    old = real_handler(sig, handler)
                    if sig == signal.SIGINT and handler == self.handlers[signal.SIGINT] and not fired:
                        fired.append(True); os.kill(os.getpid(), number)
                    return old
                with patch.object(common.signal, 'signal', install), self.assertRaises(KeyboardInterrupt):
                    with common.defer_cancellation(): done.append(True)
                self.assertEqual(done, [True]); self.assertTrue(fired)
                self.assert_restored()

    def test_original_blocked_signal_and_pending_state_preserved(self):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        original = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        with common.defer_cancellation(): os.kill(os.getpid(), signal.SIGTERM)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), original)
        self.assertIn(signal.SIGTERM, signal.sigpending())
        signal.sigwait({signal.SIGTERM})
        signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)
        self.assert_restored()

    def test_handler_install_failure_restores_complete_previous_pair(self):
        real_handler = signal.signal
        failed = []
        def install(sig, handler):
            old = real_handler(sig, handler)
            if sig == signal.SIGTERM and getattr(handler, '__name__', '') == 'remember' and not failed:
                failed.append(True); raise OSError('modeled handler installation fault after real installation')
            return old
        with patch.object(common.signal, 'signal', install), self.assertRaises(OSError):
            with common.defer_cancellation(): self.fail('failed guard must not enter body')
        self.assert_restored()

    def test_restoration_fault_after_each_real_set_restores_both(self):
        real_handler = signal.signal
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(number=number):
                failed, done = [], []
                def install(sig, handler):
                    old = real_handler(sig, handler)
                    if sig == number and handler == self.handlers[number] and not failed:
                        failed.append(True); raise OSError('modeled restoration fault after real setter')
                    return old
                with patch.object(common.signal, 'signal', install), self.assertRaises(OSError):
                    with common.defer_cancellation(): done.append(True)
                self.assertEqual(done, [True]); self.assertTrue(failed)
                self.assert_restored()

    def test_restoration_fault_before_real_set_retries_boundedly(self):
        real_handler = signal.signal
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(number=number):
                attempts = []
                def install(sig, handler):
                    if sig == number and handler == self.handlers[number]:
                        attempts.append(True)
                        if len(attempts) == 1: raise OSError('modeled restoration fault before real setter')
                    return real_handler(sig, handler)
                with patch.object(common.signal, 'signal', install), self.assertRaises(OSError):
                    with common.defer_cancellation(): pass
                self.assertEqual(len(attempts), 2)
                self.assert_restored()

    def test_cancel_handler_entry_signal_restores_before_raising(self):
        real_handler = signal.signal
        fired = []
        def install(sig, handler):
            old = real_handler(sig, handler)
            if sig == signal.SIGINT and getattr(handler, '__name__', '') == 'interrupted' and not fired:
                fired.append(True); os.kill(os.getpid(), signal.SIGTERM)
            return old
        with patch.object(common.signal, 'signal', install), self.assertRaises(KeyboardInterrupt):
            with common.cancellation_handlers(): self.fail('entry cancellation must precede work')
        self.assert_restored()

    def test_default_TERM_after_guard_cutoff_keeps_actual_exit(self):
        source = HERE / 'common.py'
        code = ('import os,signal,types;from pathlib import Path;'
                'm=types.ModuleType("owned_common");m.__file__=' + repr(str(source)) + ';'
                'exec(compile(Path(m.__file__).read_bytes(),m.__file__,"exec"),m.__dict__);'
                'signal.signal(signal.SIGINT,signal.SIG_DFL);signal.signal(signal.SIGTERM,signal.SIG_DFL);'
                '\nwith m.defer_cancellation(): pass\n'
                'print("guard-closed",flush=True);os.kill(os.getpid(),signal.SIGTERM)')
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', code], capture_output=True, timeout=3)
        self.assertEqual(result.stdout, b'guard-closed\n')
        self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_actual_child_mask_and_default_TERM_exit_are_preserved(self):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, (signal.SIGINT, signal.SIGTERM))
        expected = sorted(int(value) for value in signal.pthread_sigmask(signal.SIG_BLOCK, ()))
        with tempfile.TemporaryDirectory(prefix='rcn-child-mask-') as temporary:
            commands = common.Commands(Path(temporary), ('python3',), timeout=2)
            raw, _ = commands.run(['python3', '-I', '-B', '-c',
                'import json,signal;print(json.dumps(sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK,()))))'])
            self.assertEqual(json.loads(raw), expected)
            commands.run(['python3', '-I', '-B', '-c', 'import os,signal;os.kill(os.getpid(),signal.SIGTERM)'], expected='nonzero')
            self.assertEqual(commands.records[-1]['exit_code'], -signal.SIGTERM)
        signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)
        self.assert_restored()

    def test_transition_signal_relays_through_nested_disposal(self):
        real_handler, done, fired = signal.signal, [], []
        with self.assertRaises(KeyboardInterrupt):
            with common.defer_cancellation():
                outer = signal.getsignal(signal.SIGINT)
                def install(sig, handler):
                    old = real_handler(sig, handler)
                    if sig == signal.SIGINT and handler is outer and len(common.PENDING) == 1 and not fired:
                        fired.append(True); os.kill(os.getpid(), signal.SIGTERM)
                    return old
                with patch.object(common.signal, 'signal', install):
                    with common.defer_cancellation(): done.append('inner-disposal')
                done.append('outer-disposal')
        self.assertTrue(fired)
        self.assertEqual(done, ['inner-disposal', 'outer-disposal'])
        self.assert_restored()


# This executable is deliberately a fake Docker control plane. It proves actual
# CLI sequencing/CID/cancellation handling, never daemon/container/native execution.
CONTROL = '''#!/usr/bin/python3
import json,os,sys,time
from pathlib import Path
a=sys.argv[1:]; root=Path(os.environ['HOME']); state=root/'state.json'
cid='b'*64
if a[:1]==['info']: print('aarch64')
elif a[:2]==['image','inspect']: print(json.dumps([{'Id':a[2],'Architecture':'arm64','Os':'linux'}]))
elif a[:1]==['create']:
 name=a[a.index('--name')+1]; image=next(x for x in a if x.startswith('sha256:'))
 state.write_text(json.dumps({'Id':cid,'Name':'/'+name,'Image':image,'State':{'Status':'created','ExitCode':0}}))
 Path(a[a.index('--cidfile')+1]).write_text(cid+'\\n'); print(cid)
elif a[:2]==['container','inspect']:
 value=json.loads(state.read_text())
 if (root/'bad-owner').exists(): value['Image']='sha256:'+'c'*64
 print(json.dumps([value]))
elif a[:1]==['start']:
 value=json.loads(state.read_text()); value['State']['Status']='exited'; state.write_text(json.dumps(value))
elif a[:2]==['container','rm']:
 assert a[-1]==cid
 state.unlink(); print(cid)
elif a[:2]==['container','ls']:
 if state.exists():
  value=json.loads(state.read_text()); print(value['Id']+' '+value['Name'][1:])
else: sys.exit(9)
'''


class DockerControl(Runtime):
    def prepare(self):
        source = self.root / 'source'; source.mkdir()
        names = ('common.py', 'base.py', 'worker.py')
        # Source-only controls: no worker is actually launched by fake Docker.
        for name in names: (source / name).write_bytes(b'# control fixture\n')
        pins = {name: {'sha256': common.digest((source / name).read_bytes()), 'mode': 0o644} for name in names}
        copied = common.snapshot(source, pins, self.root / 'copied')
        inputs = self.root / 'inputs'; inputs.mkdir()
        output = self.root / 'output'; output.mkdir()
        tool = self.root / 'docker'; tool.write_text(CONTROL); tool.chmod(0o755)
        return copied, inputs, output, tool

    def test_modeled_cli_full_cid_registration_removal(self):
        source, inputs, output, tool = self.prepare()
        with patch.object(common.shutil, 'which', return_value=str(tool)):
            result = common.run_owned(IMAGE, source, inputs, output, ['/source/base.py', '--worker'])
        self.assertEqual(result['container_id'], 'b' * 64)
        self.assertEqual((result['status'], result['cleanup']), ('PASS', 'PASS'))
        self.assertTrue(result['name_absence_verified'] and result['id_absence_verified'])
        remove = [r for r in result['commands'] if r['argv'][1:3] == ['container', 'rm']]
        self.assertEqual(remove[0]['argv'][-1], 'b' * 64)

    def test_modeled_real_term_after_create_cid_still_removed(self):
        source, inputs, output, tool = self.prepare()
        original = common.Commands.run
        def run(cmd, argv, expected=0):
            result = original(cmd, argv, expected)
            if argv[1:2] == ['create']:
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with patch.object(common.shutil, 'which', return_value=str(tool)), patch.object(common.Commands, 'run', run):
            with self.assertRaises(KeyboardInterrupt) as raised:
                common.run_owned(IMAGE, source, inputs, output, ['/source/base.py', '--worker'])
        receipt = raised.exception.receipt
        self.assertEqual(receipt['status'], 'FAIL')
        self.assertEqual(receipt['cleanup'], 'PASS')
        self.assertTrue(receipt['id_absence_verified'])

    def test_modeled_wrong_image_never_removed(self):
        source, inputs, output, tool = self.prepare()
        tool.write_text(CONTROL.replace("elif a[:2]==['container','inspect']:", "elif a[:2]==['container','inspect']:\n (root/'bad-owner').touch()"))
        with patch.object(common.shutil, 'which', return_value=str(tool)), self.assertRaises(common.Refused) as raised:
            common.run_owned(IMAGE, source, inputs, output, ['/source/base.py', '--worker'])
        self.assertEqual(raised.exception.receipt['cleanup'], 'FAIL')
        self.assertFalse(any(r['argv'][1:3] == ['container', 'rm'] for r in raised.exception.receipt['commands']))


if __name__ == '__main__':
    unittest.main()
