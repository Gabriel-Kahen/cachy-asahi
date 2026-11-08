"""New HOST owned benign Python processes only; no native, ALPM or C callback."""
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P / 'overlay/native'))
O = importlib.import_module('security_interruption_owner')
PYTHON = sys.executable
ENV = {k: v for k, v in os.environ.items() if not k.startswith(('CACHY_SECURITY_', 'LD_'))}
BLOCK = r'''
import json,os,socket,time
fd=int(os.environ['CACHY_SECURITY_OBSERVER_FD'])
os.write(fd,(json.dumps({'fixture':'HOST_PYTHON_NOT_C','pid':os.getpid()})+'\n').encode());os.fsync(fd)
s=socket.socket(fileno=int(os.environ['CACHY_SECURITY_RECOVERY_FD']))
s.send(('RECOVERY_BLOCK_V1:'+os.environ['CACHY_SECURITY_RECOVERY_NONCE']).encode())
time.sleep(300)
'''


class Owned(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='owned-interrupt-host-')
        self.home = Path(self.tmp.name)
        self.runner = O.OwnedProcessRunner(self.home)
        self.before_subreaper = O._subreaper()

    def tearDown(self):
        self.assertEqual(O._subreaper(), self.before_subreaper)
        self.tmp.cleanup()

    def command(self, code, **kwargs):
        return self.runner.run([PYTHON, '-I', '-B', '-c', code], env=ENV,
                               cwd=self.home, seconds=3, output_cap=1048576, **kwargs)

    def interrupt(self, code=BLOCK, verify=None, seconds=3):
        fd = os.open(self.home/'record.jsonl', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            def check(raw, identity):
                row = json.loads(raw)
                self.assertEqual(row['pid'], identity['pid'])
                self.assertEqual(row['fixture'], 'HOST_PYTHON_NOT_C')
                return dict(fixture='UNBOUND_HOST_CHECKPOINT', pid=identity['pid'])
            return self.runner.interrupt([PYTHON, '-I', '-B', '-c', code], env=ENV,
                cwd=self.home, record_fd=fd, nonce='ab'*16,
                verify_checkpoint=verify or check, seconds=seconds, output_cap=1048576)
        finally:
            os.close(fd)

    def test_natural_owned_retirement_and_legacy_projection(self):
        result = self.command("print('host fixture')")
        r = result['retirement']
        self.assertEqual(result['stdout'], b'host fixture\n')
        self.assertTrue(r['passed'] and r['natural_exit'] and r['reaped'])
        self.assertTrue(r['group_absent'] and r['descendants_absent'] and r['pid_reserved_until_retirement'])
        self.assertTrue(r['leader_held_until_group_inspection'] and r['exit_observed_via_waitpid'])
        self.assertFalse(r['forced_cleanup'])
        self.assertGreaterEqual(r['wall_finished'], r['wall_started'])

    def test_nonzero_natural_is_not_success(self):
        r = self.command('raise SystemExit(7)')['retirement']
        self.assertEqual(r['exit'], 7)
        self.assertTrue(r['natural_exit'])
        self.assertFalse(r['passed'])

    def test_authenticated_host_checkpoint_owned_pidfd_kill(self):
        result = self.interrupt()
        r = result['retirement']
        self.assertEqual(r['exit'], -signal.SIGKILL)
        self.assertEqual(r['method'], 'OWNED_PIDFD_INTERRUPT')
        self.assertTrue(r['checkpoint_blocked_until_interrupt'] and r['reaped'])
        self.assertTrue(r['group_absent'] and r['descendants_absent'])
        self.assertFalse(r['forced_cleanup'])
        self.assertEqual(result['verified']['pid'], r['pid'])

    def test_wrong_nonce_refused_without_positive_interruption(self):
        code = BLOCK.replace("os.environ['CACHY_SECURITY_RECOVERY_NONCE']", "'ff'*16")
        with self.assertRaises(O.OwnedProcessFailure) as caught:
            self.interrupt(code)
        r = caught.exception.result['retirement']
        self.assertTrue(r['reaped'] and r['group_absent'])
        self.assertFalse(r['passed'])

    def test_child_sender_cannot_be_replaced_by_grandchild(self):
        code = BLOCK.replace("s.send((", "child=os.fork()\nif child: time.sleep(300)\ns.send((")
        with self.assertRaises(O.OwnedProcessFailure) as caught:
            self.interrupt(code)
        self.assertFalse(caught.exception.result['retirement']['passed'])
        self.assertTrue(caught.exception.result['retirement']['descendants_absent'])

    def test_checkpoint_rejection_stops_without_recovery_evidence(self):
        def reject(*args):
            raise ValueError('fixture snapshot rejected')
        with self.assertRaises(O.OwnedProcessFailure) as caught:
            self.interrupt(verify=reject)
        self.assertFalse(caught.exception.result['retirement']['checkpoint_blocked_until_interrupt'])
        self.assertTrue(caught.exception.result['retirement']['reaped'])

    def test_checkpoint_verifier_cannot_outlive_original_command_budget(self):
        import time
        def slow(*args):
            time.sleep(3)
            return {}
        with self.assertRaises(O.OwnedProcessFailure) as caught:
            self.interrupt(verify=slow, seconds=1)
        self.assertTrue(caught.exception.result['retirement']['reaped'])
        self.assertTrue(caught.exception.result['retirement']['timeout'])
        self.assertFalse(caught.exception.result['retirement']['passed'])
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_timeout_retires_owned_child(self):
        with self.assertRaises(O.OwnedProcessFailure) as caught:
            self.runner.run([PYTHON, '-I', '-B', '-c', 'import time;time.sleep(20)'],
                env=ENV, cwd=self.home, seconds=1, output_cap=1024)
        self.assertTrue(caught.exception.result['retirement']['reaped'])
        self.assertTrue(caught.exception.result['retirement']['timeout'])

    def test_output_limit_retains_bounded_prefix_and_retires(self):
        with self.assertRaises(O.OwnedProcessFailure) as caught:
            self.runner.run([PYTHON, '-I', '-B', '-c', "import os;os.write(1,b'x'*2000000)"],
                env=ENV, cwd=self.home, seconds=3, output_cap=1024)
        self.assertLessEqual(len(caught.exception.result['stdout']), 1024)
        self.assertTrue(caught.exception.result['retirement']['reaped'])

    def test_session_escape_is_adopted_retired_before_original_reap(self):
        code = "import os,time\np=os.fork()\nif not p:\n os.setsid();time.sleep(30)\nelse:\n time.sleep(.05)\n"
        result = self.command(code)
        r = result['retirement']
        self.assertTrue(r['reaped'] and r['group_absent'] and r['descendants_absent'])
        self.assertTrue(r['forced_cleanup'])
        self.assertFalse(r['passed'])

    def test_preexisting_child_is_held_and_untouched(self):
        p = subprocess.Popen([PYTHON, '-I', '-B', '-c', 'import time;time.sleep(20)'])
        try:
            with self.assertRaises(O.OwnedProcessFailure):
                self.command('pass')
            self.assertIsNone(p.poll())
        finally:
            p.terminate();p.wait(timeout=3)

    def test_no_numeric_leader_operation_after_direct_reap(self):
        state = dict(pid=None, reaped=False)
        spawn, waitpid, proc_stat, peek, kill = O.subprocess.Popen, O.os.waitpid, O._stat, O._peek, O.os.kill
        def start(*args, **kwargs):
            p = spawn(*args, **kwargs);state['pid'] = p.pid;return p
        def guarded(function):
            def call(pid, *args, **kwargs):
                if state['reaped'] and pid == state['pid']:
                    raise AssertionError('numeric leader operation after direct reap')
                return function(pid, *args, **kwargs)
            return call
        def reap(pid, *args, **kwargs):
            result = guarded(waitpid)(pid, *args, **kwargs)
            if pid == state['pid']:state['reaped'] = True
            return result
        with patch.object(O.subprocess, 'Popen', start), patch.object(O.os, 'waitpid', reap), \
             patch.object(O, '_stat', guarded(proc_stat)), patch.object(O, '_peek', guarded(peek)), \
             patch.object(O.os, 'kill', guarded(kill)):
            result = self.command('pass')
        self.assertTrue(state['reaped'] and result['retirement']['passed'])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Owned))
    (P/'result-owned-process.json').write_text(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL',
        tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        scope='HOST_OWNED_BENIGN_PYTHON_PROCESSES_NOT_NATIVE_OR_C_CALLBACK',
        actual_pacman_GPG_native_GET_reader_calls=0), sort_keys=True, indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
