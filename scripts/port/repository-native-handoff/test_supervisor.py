#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual harmless local processes only; no Docker, GPG or native actor proof."""
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('owned_handoff_supervisor',Path(__file__).with_name('supervisor.py'))
supervisor = importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='local-role-supervisor-');self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def setup_role(self, body, **limits):
        source = ('import os, signal, socket, sys, time\nfrom pathlib import Path\n'
                  'def callback():\n'+''.join('    '+line+'\n' for line in body.splitlines())).encode()
        path = self.root/'trusted_local_callback.py';path.write_bytes(source)
        module = types.ModuleType('captured_local_test');module.__file__ = str(path)
        exec(compile(source,str(path),'exec'),module.__dict__)
        grant = {'module':module.__name__,'source_file':str(path),'source_sha256':hashlib.sha256(source).hexdigest()}
        actor = supervisor.RoleSupervisor({'bind-metadata':grant},deadline=time.monotonic()+4,cleanup_seconds=limits.pop("cleanup_seconds",.3),**limits)
        return actor,module.callback

    def test_actual_json_and_bytes_result_with_separate_stdout_stderr(self):
        actor,callback = self.setup_role("print('actual stdout')\nprint('actual stderr',file=sys.stderr)\nreturn {'scope':'harmless-local','raw':b'\\x00\\xff','count':7}")
        result = actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(result,{'scope':'harmless-local','raw':b'\0\xff','count':7})
        receipt = actor.receipts[-1]
        self.assertEqual(receipt['stdout'],b'actual stdout\n');self.assertEqual(receipt['stderr'],b'actual stderr\n')
        self.assertEqual(receipt['natural_exit'],{'code':os.CLD_EXITED,'status':0})
        self.assertFalse(receipt['forced_kill']);self.assertTrue(receipt['ownership_verified'])
        self.assertEqual(receipt['cleanup']['status'],'PASS')
        self.assertEqual(receipt['status'],'PASS')

    def test_local_sets_id_grandchild_socket_removed_after_leader_pass(self):
        record = self.root/'child-pid';socket_path = self.root/'local.sock'
        actor,callback = self.setup_role(f"pid=os.fork()\nif pid==0:\n    os.setsid()\n    child=os.fork()\n    if child==0:\n        server=socket.socket(socket.AF_UNIX)\n        os.chdir({str(self.root)!r})\n        server.bind({socket_path.name!r})\n        Path({str(record)!r}).write_text(str(os.getpid()))\n        time.sleep(60)\n    os._exit(0)\nwhile not Path({str(record)!r}).exists(): time.sleep(.005)\nreturn {{'status':'PASS','scope':'harmless-local'}}")
        result = actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(result['scope'],'harmless-local')
        pid = int(record.read_text())
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)
        self.assertGreaterEqual(len(actor.receipts[-1]['owned_processes']),3)
        self.assertEqual(actor.receipts[-1]['cleanup']['status'],'PASS')

    def test_actual_deadline_kills_group_and_is_sticky(self):
        actor,callback = self.setup_role('time.sleep(60)\nreturn {}',cleanup_seconds=.15)
        started = time.monotonic()
        with self.assertRaises(supervisor.Refused) as caught:
            actor('bind-metadata',callback,deadline=time.monotonic()+.25)
        self.assertLess(time.monotonic()-started,1)
        self.assertTrue(caught.exception.receipt['forced_kill'])
        self.assertEqual(caught.exception.receipt['cleanup']['status'],'PASS')
        with self.assertRaises(supervisor.Refused):actor('bind-metadata',callback,deadline=time.monotonic()+1)

    def test_insufficient_cleanup_budget_refuses_before_fork(self):
        actor,callback = self.setup_role('return {}',cleanup_seconds=1)
        with mock.patch.object(os,'fork',side_effect=AssertionError('must not fork')), \
             self.assertRaisesRegex(supervisor.Refused,'insufficient-cleanup-budget'):
            actor('bind-metadata',callback,deadline=time.monotonic()+.08)
        self.assertEqual(actor.receipts,[])

    def test_sleeping_child_cleanup_reserved_inside_clipped_role_and_job(self):
        actor,callback = self.setup_role('time.sleep(60)\nreturn {}',cleanup_seconds=.15)
        start = time.monotonic();job_end = start+.5;role_end = start+.3
        actor.deadline = job_end
        actual,events = os.killpg,[]
        def delayed_kill(pid,number):
            if number == signal.SIGKILL and not events:
                events.append(time.monotonic());time.sleep(.06)
            return actual(pid,number)
        with mock.patch.object(os,'killpg',side_effect=delayed_kill),self.assertRaises(supervisor.Refused) as caught:
            actor('bind-metadata',callback,deadline=role_end)
        receipt = caught.exception.receipt
        self.assertEqual(receipt['deadline'],role_end)
        self.assertEqual(receipt['work_deadline'],role_end-.15)
        self.assertLess(events[0],role_end)
        self.assertLess(receipt['cleanup_finished'],min(role_end,job_end))
        self.assertEqual(receipt['cleanup']['status'],'PASS')
        with self.assertRaises(ProcessLookupError):os.kill(receipt['pid'],0)

    def test_slow_cleanup_cannot_claim_pass_after_clipped_cutoff(self):
        actor,callback = self.setup_role('return {}',cleanup_seconds=.1)
        actual,events = os.killpg,[]
        def delayed_kill(pid,number):
            if number == signal.SIGKILL and not events:
                events.append(time.monotonic());time.sleep(.3)
            return actual(pid,number)
        with mock.patch.object(os,'killpg',side_effect=delayed_kill),self.assertRaises(supervisor.Refused) as caught:
            actor('bind-metadata',callback,deadline=time.monotonic()+.2)
        receipt = caught.exception.receipt
        self.assertEqual(receipt['cleanup']['status'],'FAIL')
        self.assertEqual(receipt['status'],'FAIL')
        with self.assertRaises(ProcessLookupError):os.kill(receipt['pid'],0)

    def test_source_mode_inode_and_byte_drift_before_fork(self):
        for kind in ('mode','inode','bytes'):
            with self.subTest(kind=kind):
                actor,callback = self.setup_role('return {}')
                path = Path(callback.__globals__['__file__'])
                if kind == 'mode':path.chmod(0o755)
                elif kind == 'bytes':path.write_bytes(path.read_bytes()+b'\n')
                else:
                    replacement = path.with_suffix('.replacement')
                    replacement.write_bytes(path.read_bytes());replacement.chmod(path.stat().st_mode&0o777)
                    replacement.replace(path)
                with mock.patch.object(os,'fork',side_effect=AssertionError('must not fork')), \
                     self.assertRaisesRegex(supervisor.Refused,'callback-source'):
                    actor('bind-metadata',callback,deadline=time.monotonic()+2)

    def test_source_mode_inode_and_byte_drift_after_callback(self):
        bodies = ['Path(__file__).chmod(0o755)',
                  "path=Path(__file__)\nreplacement=path.with_suffix('.replacement')\nreplacement.write_bytes(path.read_bytes())\nreplacement.chmod(path.stat().st_mode&0o777)\nreplacement.replace(path)",
                  "path=Path(__file__)\npath.write_bytes(path.read_bytes()+b'\\n')"]
        for body in bodies:
            with self.subTest(body=body):
                actor,callback = self.setup_role(body+'\nreturn {}')
                with self.assertRaisesRegex(supervisor.Refused,'callback-source') as caught:
                    actor('bind-metadata',callback,deadline=time.monotonic()+2)
                receipt = caught.exception.receipt
                self.assertEqual(receipt['cleanup']['status'],'PASS')
                self.assertEqual(receipt['status'],'FAIL')
                with self.assertRaises(ProcessLookupError):os.kill(receipt['pid'],0)

    def test_whole_source_guard_constructor_prefork_postcleanup_and_repeat(self):
        marker = self.root/'closure-mode';marker.write_bytes(b'captured dependency');marker.chmod(0o644)
        calls = []
        def guard():
            calls.append(marker.stat().st_mode&0o777)
            supervisor.need(calls[-1] == 0o644,'whole-source-mode')
        actor,callback = self.setup_role('return {}',source_guard=guard)
        self.assertEqual(len(calls),1)
        actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(len(calls),4)
        marker.chmod(0o755)
        with mock.patch.object(os,'fork',side_effect=AssertionError('must not fork')),self.assertRaisesRegex(supervisor.Refused,'whole-source-mode'):
            actor('bind-metadata',callback,deadline=time.monotonic()+2)
        marker.chmod(0o644)
        actor,callback = self.setup_role(f'Path({str(marker)!r}).chmod(0o755)\nreturn {{}}',source_guard=guard)
        with self.assertRaisesRegex(supervisor.Refused,'whole-source-mode') as caught:
            actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(caught.exception.receipt['cleanup']['status'],'PASS')
        self.assertEqual(caught.exception.receipt['status'],'FAIL')

    def test_real_term_cancels_and_reaps(self):
        actor,callback = self.setup_role('time.sleep(60)\nreturn {}')
        original = {number:signal.getsignal(number) for number in supervisor.SIGNALS}
        alarm = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM,lambda *_:os.kill(os.getpid(),signal.SIGTERM))
        signal.setitimer(signal.ITIMER_REAL,.06)
        try:
            with self.assertRaises(supervisor.Cancelled) as caught:
                actor('bind-metadata',callback,deadline=time.monotonic()+2)
        finally:
            signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,alarm)
        self.assertEqual(caught.exception.receipt['cleanup']['status'],'PASS')
        self.assertEqual({number:signal.getsignal(number) for number in supervisor.SIGNALS},original)

    def test_real_int_during_late_cleanup_invalidates_pass(self):
        actor,callback = self.setup_role("return {'scope':'harmless-local'}")
        actual,fired = os.waitpid,[]
        def reap(*args):
            result = actual(*args)
            if result[0] and not fired:
                fired.append(True);os.kill(os.getpid(),signal.SIGINT)
            return result
        with mock.patch.object(os,'waitpid',side_effect=reap), self.assertRaises(supervisor.Cancelled) as caught:
            actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(fired,[True]);self.assertEqual(caught.exception.receipt['status'],'FAIL')
        self.assertEqual(caught.exception.receipt['cleanup']['status'],'PASS')

    def test_registration_barrier_cancellation_prevents_callback_file(self):
        marker = self.root/'must-not-be-created'
        actor,callback = self.setup_role(f"Path({str(marker)!r}).write_bytes(b'local-only')\nreturn {{}}")
        actual,fired = os.getpgid,[]
        def pgid(pid):
            value = actual(pid)
            if not fired:fired.append(True);os.kill(os.getpid(),signal.SIGTERM)
            return value
        with mock.patch.object(os,'getpgid',side_effect=pgid),self.assertRaises(supervisor.Refused):
            actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertFalse(marker.exists());self.assertTrue(fired)

    def test_wrong_source_and_code_identity_refuse_before_fork(self):
        actor,callback = self.setup_role('return {}')
        actor.grants['bind-metadata']['source_sha256']='f'*64
        with mock.patch.object(os,'fork',side_effect=AssertionError('must not fork')),self.assertRaises(supervisor.Refused):
            actor('bind-metadata',callback,deadline=time.monotonic()+2)
        actor,callback = self.setup_role('return {}')
        callback.__code__ = callback.__code__.replace(co_filename='/unregistered/source.py')
        with self.assertRaises(supervisor.Refused):actor('bind-metadata',callback,deadline=time.monotonic()+2)

    def test_bad_result_types_bounds_and_actual_failure_refuse(self):
        for body,limits in [('return 1.5',{}),('return {1:"bad"}',{}),('return b"x"*4096',{'result_limit':1024}),
                             ('print("x"*4096)\nreturn {}',{'stream_limit':1024}),
                             ('raise ValueError("actual harmless failure")',{})]:
            with self.subTest(body=body):
                actor,callback = self.setup_role(body,**limits)
                with self.assertRaises(supervisor.Refused) as caught:actor('bind-metadata',callback,deadline=time.monotonic()+2)
                self.assertEqual(caught.exception.receipt['status'],'FAIL')
                self.assertEqual(caught.exception.receipt['cleanup']['status'],'PASS')

    def test_constructor_no_actor_and_deadline_cannot_renew(self):
        actor,callback = self.setup_role('return {}')
        actor.deadline = time.monotonic()-.01
        with mock.patch.object(os,'fork',side_effect=AssertionError('must not fork')),self.assertRaises(supervisor.Refused):
            actor('bind-metadata',callback,deadline=time.monotonic()+2)
        with self.assertRaises(supervisor.Refused):supervisor.RoleSupervisor({},deadline=time.monotonic()+2)

    def test_existing_foreign_parent_child_refused_and_preserved(self):
        foreign = os.fork()
        if foreign == 0:
            os.setsid();time.sleep(60);os._exit(0)
        try:
            actor,callback = self.setup_role("return {'scope':'harmless-local'}")
            with mock.patch.object(os,'fork',side_effect=AssertionError('must not fork')), \
                 mock.patch.object(supervisor,'subreaper',side_effect=AssertionError('must not change subreaper')), \
                 self.assertRaisesRegex(supervisor.Refused,'preexisting-children'):
                actor('bind-metadata',callback,deadline=time.monotonic()+2)
            os.kill(foreign,0)
            self.assertEqual(actor.receipts,[]);self.assertTrue(actor.failed)
        finally:
            os.kill(foreign,signal.SIGKILL);os.waitpid(foreign,0)

    def test_existing_foreign_zombie_refused_without_reaping(self):
        foreign = os.fork()
        if foreign == 0:os._exit(0)
        try:
            while os.waitid(os.P_PID,foreign,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:time.sleep(.001)
            actor,callback = self.setup_role('return {}')
            with self.assertRaisesRegex(supervisor.Refused,'preexisting-children'):
                actor('bind-metadata',callback,deadline=time.monotonic()+2)
            observed = os.waitid(os.P_PID,foreign,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            self.assertEqual(observed.si_status,0)
        finally:os.waitpid(foreign,0)

    def test_foreign_fork_and_adoption_cannot_enter_supervision(self):
        # Reproduces the ambiguous case: a preexisting foreign child forks,
        # exits, and its fresh grandchild is adopted by this existing subreaper.
        reaper = supervisor.subreaper();supervisor.subreaper(1)
        record = self.root/'foreign-grandchild-pid'
        foreign = os.fork()
        if foreign == 0:
            grandchild = os.fork()
            if grandchild == 0:
                os.setsid();Path(record).write_text(str(os.getpid()));time.sleep(60);os._exit(0)
            os._exit(0)
        grandchild = None
        try:
            os.waitpid(foreign,0)
            while not record.exists():time.sleep(.001)
            grandchild = int(record.read_text())
            actor,callback = self.setup_role('return {}')
            with mock.patch.object(os,'kill',side_effect=AssertionError('must not kill foreign')), \
                 mock.patch.object(os,'waitpid',side_effect=AssertionError('must not reap foreign')), \
                 self.assertRaisesRegex(supervisor.Refused,'preexisting-children'):
                actor('bind-metadata',callback,deadline=time.monotonic()+2)
            os.kill(grandchild,0)
            self.assertEqual(actor.receipts,[])
        finally:
            if grandchild is not None:
                os.kill(grandchild,signal.SIGKILL);os.waitpid(grandchild,0)
            supervisor.subreaper(reaper)

    def test_actual_callback_resource_limits(self):
        actor,callback = self.setup_role("import resource\nreturn {'fd':list(resource.getrlimit(resource.RLIMIT_NOFILE)), 'memory':list(resource.getrlimit(resource.RLIMIT_AS)), 'file':list(resource.getrlimit(resource.RLIMIT_FSIZE))}")
        result = actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(result,{'fd':[128,128],'memory':[2*1024**3]*2,'file':[64*1024**2]*2})

    def test_real_term_during_handler_installation_cannot_start_actor(self):
        actor,callback = self.setup_role('return {}')
        actual,fired = signal.signal,[]
        def setter(number,handler):
            value = actual(number,handler)
            if getattr(handler,'__name__','') == 'cancel' and not fired:
                fired.append(True);os.kill(os.getpid(),signal.SIGTERM)
            return value
        with mock.patch.object(signal,'signal',side_effect=setter), mock.patch.object(os,'fork',side_effect=AssertionError('no actor before cancellation')):
            with self.assertRaises(supervisor.Refused):actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(fired,[True]);self.assertTrue(actor.failed)

    def test_extra_parent_thread_refused_before_fork(self):
        actor,callback = self.setup_role('return {}')
        done = threading.Event()
        thread = threading.Thread(target=done.wait);thread.start()
        try:
            with mock.patch.object(os,'fork',side_effect=AssertionError('must not fork')),self.assertRaisesRegex(supervisor.Refused,'single-thread'):
                actor('bind-metadata',callback,deadline=time.monotonic()+2)
        finally:done.set();thread.join()
        self.assertTrue(actor.failed)

    def test_repeated_calls_restore_descriptors_and_subreaper(self):
        actor,callback = self.setup_role("return {'scope':'harmless-local'}")
        baseline = len(os.listdir('/proc/self/fd'));reaper = supervisor.subreaper()
        for _ in range(3):actor('bind-metadata',callback,deadline=time.monotonic()+2)
        self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)
        self.assertEqual(supervisor.subreaper(),reaper)
        self.assertEqual(len(actor.receipts),3)

    def test_framing_duplicate_float_invalid_base64_refused(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":1.0}',b'{ "a":1}'):
            with self.assertRaises(supervisor.Refused):supervisor.decode(raw)
        for value in (['bytes','!'],['scalar',1.5],['bad',{}]):
            with self.assertRaises(supervisor.Refused):supervisor.unpack(value)


if __name__ == '__main__':unittest.main()
