#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small real owned Python controls, not a compiler/package/native-CI trial."""
import copy
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
DATA=HERE.parent/'fish-done-real-manager-data'
sys.path.insert(0,str(DATA))
import reserved_process as R
RESULTS={}


class RealOwnedControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def checked(self, code, seconds=1, **kwargs):
        original_waitpid,original_killpg,original_waitid=os.waitpid,os.killpg,os.waitid
        reaped=False;calls=[]
        def reap(pid,flags):
            nonlocal reaped
            self.assertFalse(reaped,'second leader reap/probe')
            row=original_waitpid(pid,flags)
            if row[0]:reaped=True;calls.append('reap')
            return row
        def kill(pgid,sig):
            self.assertFalse(reaped,'group signal after leader reap')
            self.assertIn(sig,(signal.SIGTERM,signal.SIGKILL),'numeric group probe forbidden')
            original_waitid(os.P_PID,pgid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            calls.append('signal:'+str(sig));return original_killpg(pgid,sig)
        with patch.object(R.os,'waitpid',side_effect=reap),patch.object(R.os,'killpg',side_effect=kill), \
             patch.object(R.os,'getpgid',side_effect=AssertionError('numeric PGID probe')), \
             patch.object(R.subprocess.Popen,'wait',side_effect=AssertionError('Popen.wait')), \
             patch.object(R.subprocess.Popen,'poll',side_effect=AssertionError('Popen.poll')), \
             patch.object(R.subprocess.Popen,'communicate',side_effect=AssertionError('Popen.communicate')):
            result=R.run([sys.executable,'-I','-B','-S','-c',code],seconds,
                         term_seconds=.1,kill_seconds=.5,**kwargs)
        self.assertEqual(result['reap_count'],1);self.assertEqual(calls[-1],'reap')
        RESULTS[self._testMethodName]=dict(receipt=result,syscall_order=calls)
        return result

    def test_natural_zero_and_single_observed_reap(self):
        result=self.checked('raise SystemExit(0)')
        R.assert_verified(result)
        self.assertEqual(result['signals'],[])

    def test_natural_nonzero_is_observed_not_success(self):
        result=self.checked('raise SystemExit(7)')
        self.assertEqual(result['exit'],7);self.assertTrue(result['completed'])
        with self.assertRaises(ValueError):R.assert_verified(result)

    def test_timeout_term_then_kill_before_reap(self):
        result=self.checked('import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(2)',.4)
        self.assertTrue(result['timed_out']);self.assertFalse(result['completed'])
        self.assertEqual(result['signals'],[signal.SIGTERM,signal.SIGKILL]);self.assertEqual(result['exit'],-signal.SIGKILL)
        self.assertEqual(result['retirement'],'VERIFIED_ABSENT')
        with self.assertRaises(ValueError):R.assert_verified(result)

    def test_graceful_timeout_exit_zero_is_not_completion(self):
        result=self.checked('import signal,sys,time; signal.signal(signal.SIGTERM,lambda *a:sys.exit(0)); time.sleep(2)',.4)
        self.assertTrue(result['timed_out']);self.assertFalse(result['completed']);self.assertEqual(result['exit'],0)
        self.assertEqual(result['retirement'],'VERIFIED_ABSENT')
        with self.assertRaises(ValueError):R.assert_verified(result)

    def test_cached_external_reap_never_becomes_observed_exit(self):
        original_popen,original_waitpid=R.subprocess.Popen,os.waitpid
        def reaped(*args,**kwargs):
            child=original_popen(*args,**kwargs)
            pid,status=original_waitpid(child.pid,0)
            self.assertEqual(pid,child.pid)
            child.returncode=os.waitstatus_to_exitcode(status)
            return child
        with patch.object(R.subprocess,'Popen',side_effect=reaped), \
             patch.object(R.os,'waitid',side_effect=AssertionError('cached-status PID probe')), \
             patch.object(R.os,'waitpid',side_effect=AssertionError('cached-status reap')), \
             patch.object(R.os,'killpg',side_effect=AssertionError('cached-status signal')):
            result=R.run([sys.executable,'-I','-B','-S','-c','raise SystemExit(0)'],1)
        self.assertEqual(result['reason'],'CACHED_REAPED_STATUS');self.assertIsNone(result['exit'])
        self.assertEqual(result['retirement'],'UNKNOWN');self.assertFalse(result['completed'])
        RESULTS[self._testMethodName]=dict(receipt=result)

    def test_genuine_echild_disables_all_later_numeric_actions(self):
        original_waitid,original_waitpid=os.waitid,os.waitpid
        external=[]
        def lost(which,pid,flags):
            external.append(original_waitpid(pid,0))
            return original_waitid(which,pid,flags)  # genuine kernel ECHILD
        with patch.object(R.os,'waitid',side_effect=lost), \
             patch.object(R.os,'waitpid',side_effect=AssertionError('waitpid after ECHILD')), \
             patch.object(R.os,'killpg',side_effect=AssertionError('group action after ECHILD')), \
             patch.object(R.os,'getpgid',side_effect=AssertionError('group probe')), \
             patch.object(R,'_census',side_effect=AssertionError('lost ownership census promotion')):
            result=R.run([sys.executable,'-I','-B','-S','-c','raise SystemExit(0)'],1)
            self.assertIs(R.refresh(result),result)
        self.assertEqual(len(external),1);self.assertEqual(result['reason'],'ECHILD')
        self.assertIsNone(result['exit']);self.assertIsNone(result['group_absent'])
        self.assertEqual(result['retirement'],'UNKNOWN');self.assertEqual(result['reap_count'],0)
        with self.assertRaises(ValueError):R.assert_verified(result)
        RESULTS[self._testMethodName]=dict(receipt=result,external_reap=external)

    def test_genuine_echild_at_final_reap_cannot_become_exit_zero(self):
        original=os.waitpid;calls=[]
        def outside_reaper(pid,flags):
            calls.append(original(pid,0))  # Controlled external reaper wins after WNOWAIT.
            return original(pid,flags)     # genuine ECHILD returned to the helper's one attempt
        with patch.object(R.os,'waitpid',side_effect=outside_reaper), \
             patch.object(R.os,'killpg',side_effect=AssertionError('unexpected or late group action')), \
             patch.object(R.os,'getpgid',side_effect=AssertionError('group probe')):
            result=R.run([sys.executable,'-I','-B','-S','-c','raise SystemExit(0)'],1)
        self.assertEqual(len(calls),1);self.assertEqual(result['reason'],'ECHILD')
        self.assertEqual(result['retirement'],'UNKNOWN');self.assertIsNone(result['exit'])
        self.assertEqual(result['reap_count'],0)
        with self.assertRaises(ValueError):R.assert_verified(result)
        RESULTS[self._testMethodName]=dict(receipt=result,external_reap=calls)

    def test_policy_and_invalid_budget_refuse_before_launch(self):
        for disposition in (signal.SIG_IGN,lambda *args:None):
            with patch.object(R.signal,'getsignal',return_value=disposition), \
                 patch.object(R.subprocess,'Popen',side_effect=AssertionError('launch before policy')):
                with self.assertRaises(ValueError):R.run(['/not-launched'],1)
        with patch.object(R.threading,'active_count',return_value=2), \
             patch.object(R.subprocess,'Popen',side_effect=AssertionError('multithreaded launch')):
            with self.assertRaises(ValueError):R.run(['/not-launched'],1)
        with patch.object(R.subprocess,'Popen',side_effect=AssertionError('invalid-budget launch')):
            with self.assertRaises(ValueError):R.run(['/not-launched'],float('inf'))

    def test_descendant_retirement_reserves_zombie_leader_until_last_signal(self):
        # A separate small control is the subreaper; this test process's child
        # policy and arbitrary children are untouched. The finite descendant
        # exits after1s even if the control fails before its assertions.
        program='''import ctypes,json,os,signal,sys,time
sys.path.insert(0,DATA)
import reserved_process as R
assert ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0
code="import os,signal,time; p=os.fork(); (os._exit(0) if p else None); signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(1)"
row=R.run([sys.executable,'-I','-B','-S','-c',code],1,term_seconds=.1,kill_seconds=.5)
assert row['exit']==0 and row['completed'] and row['reap_count']==1,row
adopted=[];end=time.monotonic()+2
while True:
 try:p,status=os.waitpid(-1,os.WNOHANG)
 except ChildProcessError:break
 if p:adopted.append(dict(pid=p,wait_status=status));continue
 assert time.monotonic()<end,'adopted descendant deadline'
 time.sleep(.01)
R.refresh(row);R.assert_verified(row)
assert adopted and row['signals'],(adopted,row)
assert any(r['event']=='SIGNAL_RESERVED_GROUP' for r in row['audit'])
assert max(i for i,r in enumerate(row['audit']) if r['event']=='SIGNAL_RESERVED_GROUP') < next(i for i,r in enumerate(row['audit']) if r['event']=='REAP_LEADER_ONCE')
print(json.dumps(dict(receipt=row,adopted=adopted)))
'''.replace('DATA',repr(str(DATA)))
        output=self.root/'descendant.json'
        with output.open('wb') as stream:outer=self.checked(program,5,stdout=stream)
        R.assert_verified(outer)
        inner=json.loads(output.read_text());self.assertTrue(inner['adopted'])
        RESULTS[self._testMethodName]['inner']=inner

    def test_offline_validator_rejects_reap_signal_reordering_and_unknown(self):
        result=self.checked('raise SystemExit(0)')
        changed=copy.deepcopy(result)
        changed['audit'].append(dict(event='SIGNAL_RESERVED_GROUP',signal=int(signal.SIGKILL)))
        with self.assertRaises(ValueError):R.assert_verified(changed)
        changed=copy.deepcopy(result);changed.update(ownership='LOST',exit=None,reap_count=0)
        with self.assertRaises(ValueError):R.assert_verified(changed)


if __name__=='__main__':
    suite=unittest.main(exit=False)
    print(json.dumps(dict(status='PASS_REAL_OWNED_PROCESS_CONTROLS' if suite.result.wasSuccessful() else 'FAIL',
        authority='SMALL_OWNED_HOST_PYTHON_PROCESSES_ONLY; NO_COMPILER_PACKAGE_DOCKER_NATIVE_CI',results=RESULTS),sort_keys=True))
    raise SystemExit(not suite.result.wasSuccessful())
