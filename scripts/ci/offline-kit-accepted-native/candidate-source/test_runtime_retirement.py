#!/usr/bin/env python3
"""Bounded owned-child controls and lost-ownership models; no native claim."""
import ast,importlib.util,os,signal,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('safe_candidate_runtime',HERE/'runtime.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def event(code=0,pid=424242):return types.SimpleNamespace(si_pid=pid,si_code=os.CLD_EXITED,si_status=code)
class RuntimeRetirement(unittest.TestCase):
 def group(self,returncode=None):return r._OwnedGroup(types.SimpleNamespace(pid=424242,returncode=returncode))
 def test_ECHILD_revokes_all_numeric_operations(self):
  group=self.group();trace=[]
  def missing(*args):trace.append(('waitid',args[1]));raise ChildProcessError()
  with patch.object(r.os,'waitid',side_effect=missing),patch.object(r.os,'killpg',side_effect=AssertionError('POST_ECHILD_SIGNAL')),patch.object(r.Path,'iterdir',side_effect=AssertionError('POST_ECHILD_CENSUS')):
   for operation in (group.observe,lambda:group.signal(signal.SIGKILL),group.members,group.retire,lambda:r._cleanup(group)):
    with self.assertRaises(r.OwnershipLost):operation()
  self.assertEqual(trace,[('waitid',424242)]);self.assertIsNone(group.process.returncode);self.assertFalse(group.nonleader_members_absent_before_reap)
 def test_pre_reaped_or_Popen_fake_zero_never_becomes_success(self):
  group=self.group(0)
  with patch.object(r.os,'waitid',side_effect=AssertionError('POST_REAP_WAITID')),patch.object(r.os,'killpg',side_effect=AssertionError('POST_REAP_SIGNAL')),patch.object(r.Path,'iterdir',side_effect=AssertionError('POST_REAP_CENSUS')):
   with self.assertRaises(r.OwnershipLost):r._cleanup(group)
  self.assertTrue(group.lost);self.assertFalse(group.retired)
 def test_final_reap_is_last_numeric_operation(self):
  group=self.group();trace=[]
  def observed(*args):trace.append(('waitid',args[1]));return event(7)
  def reaped(*args):trace.append(('waitpid',args[0]));return (424242,7<<8)
  def census(_):trace.append(('census',424242));return iter(())
  with patch.object(r.os,'waitid',side_effect=observed),patch.object(r.os,'waitpid',side_effect=reaped),patch.object(r.Path,'iterdir',census),patch.object(r.os,'killpg',side_effect=AssertionError('UNNECESSARY_SIGNAL')):
   self.assertEqual(r._cleanup(group),7);held=list(trace)
   for operation in (group.observe,group.members,lambda:group.signal(signal.SIGTERM)):
    with self.assertRaises(r.OwnershipLost):operation()
   self.assertEqual(trace,held)
  self.assertEqual(trace[-1],('waitpid',424242));self.assertEqual(group.process.returncode,7);self.assertTrue(group.retired);self.assertTrue(group.nonleader_members_absent_before_reap)
 def test_lost_reservation_before_signal_refuses_signal(self):
  group=self.group();trace=[]
  def observed(*args):
   trace.append('waitid')
   if len(trace)>1:raise ChildProcessError()
   return None
  with patch.object(r.os,'waitid',side_effect=observed),patch.object(r.os,'killpg',side_effect=AssertionError('LOST_SIGNAL')):
   self.assertIsNone(group.observe())
   with self.assertRaises(r.OwnershipLost):group.signal(signal.SIGKILL)
  self.assertTrue(group.lost)
 def test_final_reap_ECHILD_keeps_returncode_unknown(self):
  group=self.group()
  with patch.object(r.os,'waitid',return_value=event()),patch.object(r.Path,'iterdir',return_value=iter(())),patch.object(r.os,'waitpid',side_effect=ChildProcessError()):
   with self.assertRaises(r.OwnershipLost):group.retire()
  self.assertIsNone(group.process.returncode);self.assertTrue(group.lost);self.assertFalse(group.nonleader_members_absent_before_reap)
 def test_adopted_descendant_ECHILD_revokes_group_authority(self):
  group=self.group();trace=[]
  def waitid(kind,pid,flags):
   trace.append(pid)
   if pid==434343:raise ChildProcessError()
   return event(pid=pid)
  with patch.object(r.os,'waitid',side_effect=waitid),patch.object(r.os,'killpg',side_effect=AssertionError('POST_ECHILD_SIGNAL')),patch.object(r.Path,'iterdir',side_effect=AssertionError('POST_ECHILD_CENSUS')):
   with self.assertRaises(r.OwnershipLost):group.reap_adopted({434343:('Z',os.getpid())})
   held=list(trace)
   with self.assertRaises(r.OwnershipLost):group.signal(signal.SIGKILL)
   with self.assertRaises(r.OwnershipLost):group.members()
   self.assertEqual(trace,held)
 def test_default_policy_is_normalized_before_Popen(self):
  with tempfile.TemporaryDirectory() as folder:
   runner=self.runner(folder);trace=[];real_signal=signal.signal
   def normalized(number,handler):trace.append(('signal',number,handler));return real_signal(number,handler)
   def no_launch(*args,**kwargs):trace.append(('launch',));raise OSError('no-test-child')
   with patch.object(r.signal,'signal',side_effect=normalized),patch.object(r.subprocess,'Popen',side_effect=no_launch),self.assertRaisesRegex(OSError,'no-test-child'):
    runner.run(self.command('pass'),timeout=1)
   self.assertEqual(trace[0],('signal',signal.SIGCHLD,signal.SIG_DFL));self.assertEqual(trace[1],('launch',))
 def test_generic_observation_error_or_wrong_pid_revokes_authority(self):
  for outcome in (OSError('unknown-state'),event(pid=123456),types.SimpleNamespace(si_code=os.CLD_EXITED,si_status=0)):
   group=self.group()
   with patch.object(r.os,'waitid',side_effect=outcome if isinstance(outcome,Exception) else None,return_value=outcome),self.assertRaises(r.OwnershipLost):group.observe()
   self.assertTrue(group.lost);self.assertFalse(group.process._child_created);self.assertIsNone(group.process.returncode)
 def test_lost_ownership_suppresses_actual_Popen_destructor_polling(self):
  process=object.__new__(subprocess.Popen);process.pid=424242;process.returncode=None;process._child_created=True
  group=r._OwnedGroup(process)
  with patch.object(r.os,'waitid',side_effect=ChildProcessError()),self.assertRaises(r.OwnershipLost):group.observe()
  self.assertFalse(process._child_created);self.assertIsNone(process.returncode)
  with patch.object(r.os,'waitpid',side_effect=AssertionError('DESTRUCTOR_REAP')),patch.object(process,'_internal_poll',side_effect=AssertionError('DESTRUCTOR_POLL')):
   subprocess.Popen.__del__(process)
 def test_no_Popen_poll_wait_or_negative_group_reap_calls(self):
  for n in ast.walk(ast.parse((HERE/'runtime.py').read_bytes())):
   if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute):
    self.assertNotIn(n.func.attr,('poll','wait'))
    if n.func.attr=='waitpid':self.assertNotIsInstance(n.args[0],ast.UnaryOp)
 def runner(self,folder):return r.Runner(15,{'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'},Path(folder)/'logs')
 def command(self,code):return ['/usr/bin/python3','-I','-B','-c',code]
 def tracked(self):
  groups=[];original=r._OwnedGroup
  def create(process):
   group=original(process);groups.append(group);return group
  return groups,patch.object(r,'_OwnedGroup',side_effect=create)
 def assert_retired(self,groups):
  self.assertTrue(groups)
  for group in groups:self.assertTrue(group.retired and group.nonleader_members_absent_before_reap and not group.lost)
 def test_real_natural_child_output_and_nonzero_status(self):
  with tempfile.TemporaryDirectory() as folder:
   groups,track=self.tracked()
   with track:result=self.runner(folder).run(self.command("print('owned-output');raise SystemExit(7)"),timeout=3,log='child.log')
   self.assertEqual(result.returncode,7);self.assertEqual(result.stdout,b'owned-output\n');self.assert_retired(groups)
 def test_real_timeout_retires_only_owned_group(self):
  with tempfile.TemporaryDirectory() as folder:
   groups,track=self.tracked();start=time.monotonic()
   with track,self.assertRaisesRegex(ValueError,'command-timeout'):self.runner(folder).run(self.command('import time;time.sleep(30)'),timeout=.1,log='timeout.log')
   self.assertLess(time.monotonic()-start,4);self.assert_retired(groups)
 def test_real_natural_leader_with_TERM_resistant_descendant(self):
  code="import os,signal,time;child=os.fork();signal.signal(signal.SIGTERM,signal.SIG_IGN) if child==0 else None;print('descendant' if child==0 else 'leader',flush=True);time.sleep(30) if child==0 else None"
  with tempfile.TemporaryDirectory() as folder:
   groups,track=self.tracked();waitpid=os.waitpid;waits=[]
   def actual_wait(pid,flags):
    result=waitpid(pid,flags);waits.append((pid,result[0]));return result
   with track,patch.object(r.os,'waitpid',side_effect=actual_wait):result=self.runner(folder).run(self.command(code),timeout=4,log='descendant.log')
   self.assertEqual(result.returncode,0);self.assertIn(b'leader',result.stdout);self.assertIn(b'descendant',result.stdout);self.assert_retired(groups)
   self.assertTrue(any(pid!=groups[0].process.pid and actual==pid for pid,actual in waits))
 def test_real_cancellation_preserves_retirement_and_raises(self):
  with tempfile.TemporaryDirectory() as folder:
   groups,track=self.tracked()
   with track,r.cancellation_handlers(),self.assertRaises(r.Cancelled):self.runner(folder).run(self.command('import os,signal,time;os.kill(os.getppid(),signal.SIGTERM);time.sleep(30)'),timeout=4,log='cancel.log')
   self.assert_retired(groups)
 def test_real_output_bound_still_retires(self):
  with tempfile.TemporaryDirectory() as folder:
   groups,track=self.tracked()
   with track,self.assertRaisesRegex(ValueError,'output-bound'):self.runner(folder).run(self.command("import os,time;os.write(1,b'x'*4096);time.sleep(30)"),timeout=4,limit=32,log='bound.log')
   self.assert_retired(groups);self.assertEqual((Path(folder)/'logs/bound.log').stat().st_size,32)
 def test_real_parallel_one_failure_retires_both(self):
  with tempfile.TemporaryDirectory() as folder:
   groups,track=self.tracked()
   with track:results=self.runner(folder).run_many([self.command('raise SystemExit(3)'),self.command('import time;time.sleep(30)')],timeout=4,lognames=['a.log','b.log'])
   self.assertEqual(results[0].returncode,3);self.assertEqual(results[1].returncode,-signal.SIGTERM);self.assert_retired(groups)
 def test_ignored_custom_and_threaded_policy_reject_before_launch(self):
  with tempfile.TemporaryDirectory() as folder:
   runner=self.runner(folder);original=signal.getsignal(signal.SIGCHLD)
   try:
    for handler in (signal.SIG_IGN,lambda *_:None):
     signal.signal(signal.SIGCHLD,handler)
     with patch.object(r.subprocess,'Popen',side_effect=AssertionError('NO_LAUNCH')),self.assertRaisesRegex(ValueError,'unsafe-SIGCHLD'):runner.run(self.command('pass'),timeout=1)
   finally:signal.signal(signal.SIGCHLD,original)
   with patch.object(r.threading,'active_count',return_value=2),patch.object(r.subprocess,'Popen',side_effect=AssertionError('NO_LAUNCH')),self.assertRaisesRegex(ValueError,'threaded-runner'):runner.run(self.command('pass'),timeout=1)
 def test_default_policy_setup_failure_rejects_before_launch(self):
  with tempfile.TemporaryDirectory() as folder:
   runner=self.runner(folder)
   with patch.object(r.signal,'signal',side_effect=OSError('policy-setup')),patch.object(r.subprocess,'Popen',side_effect=AssertionError('NO_LAUNCH')),self.assertRaisesRegex(OSError,'policy-setup'):runner.run(self.command('pass'),timeout=1)
if __name__=='__main__':unittest.main(verbosity=2)
