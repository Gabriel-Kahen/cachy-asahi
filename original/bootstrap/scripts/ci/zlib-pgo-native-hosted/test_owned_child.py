# SPDX-License-Identifier: MIT
"""Five real short Python children only; no compiler, package or native workload."""
import importlib.util
from pathlib import Path
import signal,subprocess,sys,threading,unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_owned_controls',HERE/'owned_child.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
CMD=[sys.executable,'-I','-B','-c']

class OwnedChildControls(unittest.TestCase):
    def test_real_exit7_uses_direct_waitpid_and_never_popen_fallback(self):
        row={}
        with patch.object(subprocess.Popen,'wait',side_effect=AssertionError('Popen wait')),patch.object(subprocess.Popen,'poll',side_effect=AssertionError('Popen poll')):
            result=O.run([*CMD,'import sys; print("observed"); sys.exit(7)'],capture_output=True,text=True,timeout=2,lifecycle=row)
        self.assertEqual((result.returncode,result.stdout),(7,'observed\n'));self.assertEqual(row['exit'],7)
        self.assertTrue(row['exit_observed_via_waitpid']);self.assertFalse(row['ownership_lost']);self.assertEqual(row['retirement'],'REAPED')

    def test_real_timeout_has_no_numeric_action_after_final_reap(self):
        row={};reaped=[False];events=[];waitpid=O.os.waitpid;waitid=O.os.waitid;killpg=O.os.killpg;members=O._OwnedState.members
        def reap(pid,flags):
            self.assertFalse(reaped[0]);value=waitpid(pid,flags);reaped[0]=True;events.append('reap');return value
        def witness(*args):
            self.assertFalse(reaped[0],'probe after reap');events.append('witness');return waitid(*args)
        def kill(pid,sig):
            self.assertFalse(reaped[0],'signal after reap');events.append('signal');return killpg(pid,sig)
        def inspect(state):
            self.assertFalse(reaped[0],'group after reap');return members(state)
        with patch.object(O.os,'waitpid',side_effect=reap),patch.object(O.os,'waitid',side_effect=witness),patch.object(O.os,'killpg',side_effect=kill),patch.object(O._OwnedState,'members',inspect):
            with self.assertRaises(subprocess.TimeoutExpired):O.run([*CMD,'import time; time.sleep(30)'],capture_output=True,timeout=.05,lifecycle=row)
        self.assertEqual(row['exit'],-signal.SIGKILL);self.assertTrue(row['exit_observed_via_waitpid']);self.assertTrue(row['group_absent']);self.assertTrue(row['forced_cleanup'])
        self.assertEqual(events[-1],'reap');self.assertLess(events.index('signal'),events.index('reap'))

    def test_real_external_reap_is_unknown_and_has_no_later_probe_or_signal(self):
        row={};waitpid=O.os.waitpid;calls=[]
        def lost(which,pid,flags):
            calls.append('witness');waitpid(pid,0);raise ChildProcessError('external reap')
        with patch.object(O.os,'waitid',side_effect=lost),patch.object(O.os,'killpg',side_effect=AssertionError('signal after loss')),patch.object(O._OwnedState,'members',side_effect=AssertionError('group after loss')),patch.object(subprocess.Popen,'wait',return_value=0)as fallback:
            with self.assertRaises(O.OwnershipLost):O.run([*CMD,'pass'],capture_output=True,timeout=2,lifecycle=row)
        self.assertEqual(calls,['witness']);self.assertIsNone(row['exit']);self.assertTrue(row['ownership_lost']);self.assertFalse(row['exit_observed_via_waitpid']);self.assertEqual(row['retirement'],'UNKNOWN');fallback.assert_not_called()

    def test_sigchld_policy_and_setup_failure_refuse_before_launch(self):
        original=signal.getsignal(signal.SIGCHLD)
        try:
            signal.signal(signal.SIGCHLD,signal.SIG_IGN)
            with patch.object(subprocess,'Popen')as launch,self.assertRaises(O.ChildPolicyError):O.run([*CMD,'pass'])
            launch.assert_not_called()
        finally:signal.signal(signal.SIGCHLD,original)
        with patch.object(O.signal,'signal',side_effect=RuntimeError('setup failed')),patch.object(subprocess,'Popen')as launch,self.assertRaises((O.ChildPolicyError,RuntimeError)):O.run([*CMD,'pass'])
        launch.assert_not_called()
        with patch.object(subprocess,'Popen')as launch,self.assertRaises(O.ChildPolicyError):O.run([*CMD,'pass'],allowed_uids={-1})
        launch.assert_not_called()

    def test_nonmain_or_multithreaded_call_refuses_before_launch(self):
        errors=[]
        def call():
            try:O.run([*CMD,'pass'])
            except BaseException as error:errors.append(error)
        with patch.object(subprocess,'Popen')as launch:
            thread=threading.Thread(target=call);thread.start();thread.join(timeout=2);self.assertFalse(thread.is_alive());launch.assert_not_called()
        self.assertIsInstance(errors[0],O.ChildPolicyError)
        with patch.object(O.threading,'active_count',return_value=2),patch.object(subprocess,'Popen')as launch,self.assertRaises(O.ChildPolicyError):O.run([*CMD,'pass'])
        launch.assert_not_called()

    def test_synchronous_nested_inspection_uses_no_background_thread(self):
        rows=[];called=[]
        def tick():
            if called:return
            called.append(True);inner={};result=O.run([*CMD,'print("inner")'],capture_output=True,timeout=2,lifecycle=inner);self.assertEqual(result.stdout,b'inner\n');rows.append(inner)
        outer={};result=O.run([*CMD,'import time; time.sleep(.12); print("outer")'],capture_output=True,timeout=3,lifecycle=outer,on_tick=tick)
        self.assertEqual(result.stdout,b'outer\n');self.assertEqual(len(rows),1);self.assertTrue(all(r['exit_observed_via_waitpid']for r in[outer,*rows]));self.assertEqual(threading.active_count(),1)

if __name__=='__main__':unittest.main()
