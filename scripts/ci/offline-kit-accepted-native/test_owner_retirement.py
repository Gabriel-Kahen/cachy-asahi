#!/usr/bin/env python3
"""Bounded real owned-child controls and deterministic reservation-loss models."""
import ast,errno,importlib.util,json,os,signal,subprocess,sys,tempfile,threading,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_owned_actor_control',HERE/'owner_common.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
PYTHON=sys.executable
class OwnerRetirementControls(unittest.TestCase):
 def actor(self,d):return O.Actors(Path(d)/'actors',12)
 def command(self,text):return [PYTHON,'-I','-B','-c',text]
 def assert_retired(self,row,exit=None):
  self.assertTrue(row['group_absent']);self.assertTrue(row['leader_reaped']);self.assertTrue(row['leader_held_until_group_inspection']);self.assertEqual(row['reservation'],'REAPED')
  if exit is not None:self.assertEqual(row['exit'],exit)
 def test_real_natural_child_directly_reaped_and_output_retained(self):
  with tempfile.TemporaryDirectory() as d:
   a=self.actor(d);self.assertEqual(a.run(self.command("print('owned output')")),'owned output');self.assert_retired(a.rows[-1],0);self.assertEqual(a.rows[-1]['status'],'PASS');self.assertFalse(a.rows[-1]['forced_retirement'])
 def test_real_disallowed_nonzero_has_actual_status_and_no_pass(self):
  with tempfile.TemporaryDirectory() as d:
   a=self.actor(d)
   with self.assertRaisesRegex(ValueError,'actor exit: 7'):a.run(self.command('raise SystemExit(7)'))
   self.assert_retired(a.rows[-1],7);self.assertEqual(a.rows[-1]['status'],'FAIL')
 def test_real_explicit_allowed_nonzero_is_observed(self):
  with tempfile.TemporaryDirectory() as d:
   a=self.actor(d);a.run(self.command('raise SystemExit(7)'),allowed=(7,));self.assert_retired(a.rows[-1],7);self.assertEqual(a.rows[-1]['status'],'PASS')
 def test_real_timeout_retirement_requires_actual_status_and_stays_failed(self):
  with tempfile.TemporaryDirectory() as d:
   a=self.actor(d)
   with self.assertRaises(subprocess.TimeoutExpired):a.run(self.command('import time;time.sleep(10)'),timeout=.1)
   self.assert_retired(a.rows[-1],-signal.SIGTERM);self.assertTrue(a.rows[-1]['forced_retirement']);self.assertEqual(a.rows[-1]['status'],'FAIL')
 def test_real_orphan_descendant_retired_before_leader_reap(self):
  with tempfile.TemporaryDirectory() as d:
   a=self.actor(d)
   code="import os,time;pid=os.fork();print(pid,flush=True);time.sleep(10) if pid==0 else None"
   with self.assertRaisesRegex(ValueError,'natural actor group absence'):a.run(self.command(code),timeout=2)
   self.assert_retired(a.rows[-1],0);self.assertTrue(a.rows[-1]['forced_retirement']);self.assertEqual(a.rows[-1]['status'],'FAIL')
 def test_real_timeout_sigterm_ignored_escalates_before_reap(self):
  with tempfile.TemporaryDirectory() as d:
   a=self.actor(d)
   with self.assertRaises(subprocess.TimeoutExpired):a.run(self.command('import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(10)'),timeout=.2)
   self.assert_retired(a.rows[-1],-signal.SIGKILL);self.assertEqual(a.rows[-1]['status'],'FAIL')
 def test_real_trace_every_group_operation_precedes_final_reap(self):
  events=[];reaped=set();last=None;real_id=os.waitid;real_pid=os.waitpid;real_signal=os.killpg;real_members=O.group_members
  def waitid(kind,pid,flags):
   value=real_id(kind,pid,flags);events.append(('reserve',pid));self.assertNotIn(pid,reaped);return value
  def waitpid(pid,flags):
   value=real_pid(pid,flags);events.append(('reap',pid,value[0]));
   if value[0]:reaped.add(value[0])
   return value
  def members(pid,leader):
   self.assertEqual(events[-1],('reserve',pid));self.assertNotIn(pid,reaped);events.append(('census',pid));return real_members(pid,leader)
  def send(pid,number):
   self.assertEqual(events[-1],('reserve',pid));self.assertNotIn(pid,reaped);events.append(('signal',pid,number));return real_signal(pid,number)
  with tempfile.TemporaryDirectory() as d,patch.object(O.os,'waitid',side_effect=waitid),patch.object(O.os,'waitpid',side_effect=waitpid),patch.object(O.os,'killpg',side_effect=send),patch.object(O,'group_members',side_effect=members):
   a=self.actor(d)
   with self.assertRaises(subprocess.TimeoutExpired):a.run(self.command('import time;time.sleep(10)'),timeout=.1)
   self.assert_retired(a.rows[-1],-signal.SIGTERM)
  self.assertEqual(events[-1][0],'reap');self.assertTrue(any(e[0]=='signal'for e in events))
 def test_real_cancellation_retires_owned_child_and_remains_failed(self):
  old=signal.getsignal(signal.SIGINT);signal.signal(signal.SIGINT,signal.default_int_handler)
  try:
   with tempfile.TemporaryDirectory() as d:
    a=self.actor(d)
    with self.assertRaises(KeyboardInterrupt):a.run(self.command('import os,signal,time;os.kill(os.getppid(),signal.SIGINT);time.sleep(10)'),timeout=2)
    self.assert_retired(a.rows[-1],-signal.SIGTERM);self.assertFalse(a.rows[-1]['natural_exit']);self.assertEqual(a.rows[-1]['status'],'FAIL')
  finally:signal.signal(signal.SIGINT,old)
 def fake(self):
  return types.SimpleNamespace(pid=424242,returncode=None,_child_created=True,poll=lambda:(_ for _ in ()).throw(AssertionError('Popen poll forbidden')),wait=lambda **kw:(_ for _ in ()).throw(AssertionError('Popen wait forbidden')))
 def model(self,statuses,*,code=None,reap_error=None,signal_error=None):
  process=self.fake();events=[];remaining=list(statuses)
  def reserve(*a):
   events.append('reserve')
   value=remaining.pop(0)if len(remaining)>1 else remaining[0]
   if isinstance(value,BaseException):raise value
   return value
  def census(*a):events.append('census');return []
  def send(*a):
   events.append('signal')
   if signal_error:raise signal_error
  def reap(*a):
   events.append('reap')
   if reap_error:raise reap_error
   return process.pid,(0 if code is None else code<<8)
  return process,events,reserve,census,send,reap
 def test_initial_echild_has_no_census_signal_or_popen_fallback(self):
  p,events,reserve,census,send,reap=self.model([ChildProcessError(errno.ECHILD,'gone')])
  with tempfile.TemporaryDirectory() as d,patch.object(O,'reaping_policy'),patch.object(O.subprocess,'Popen',return_value=p),patch.object(O.os,'waitid',side_effect=reserve),patch.object(O,'group_members',side_effect=census),patch.object(O.os,'killpg',side_effect=send),patch.object(O.os,'waitpid',side_effect=reap):
   a=self.actor(d)
   with self.assertRaises(O.ReservationLost):a.run(['model'])
   row=a.rows[-1];self.assertIsNone(row['exit']);self.assertIsNone(row['group_absent']);self.assertFalse(row['leader_held_until_group_inspection']);self.assertFalse(p._child_created)
  self.assertEqual(events,['reserve'])
 def test_loss_after_natural_observation_stops_finally_census(self):
  state=types.SimpleNamespace(si_pid=424242,si_code=os.CLD_EXITED,si_status=0)
  p,events,reserve,census,send,reap=self.model([state,ChildProcessError(errno.ECHILD,'gone')])
  with tempfile.TemporaryDirectory() as d,patch.object(O,'reaping_policy'),patch.object(O.subprocess,'Popen',return_value=p),patch.object(O.os,'waitid',side_effect=reserve),patch.object(O,'group_members',side_effect=census),patch.object(O.os,'killpg',side_effect=send),patch.object(O.os,'waitpid',side_effect=reap):
   a=self.actor(d)
   with self.assertRaises(O.ReservationLost):a.run(['model'])
   self.assertIsNone(a.rows[-1]['exit']);self.assertIsNone(a.rows[-1]['group_absent']);self.assertFalse(a.rows[-1]['leader_reaped'])
  self.assertEqual(events,['reserve','reserve'])
 def test_loss_immediately_before_group_signal_stops_all_numeric_operations(self):
  state=types.SimpleNamespace(si_pid=424242,si_code=os.CLD_EXITED,si_status=0)
  p,events,reserve,census,send,reap=self.model([state,state,state,ChildProcessError(errno.ECHILD,'gone')])
  def descendants(*args):events.append('census');return [777777]
  with tempfile.TemporaryDirectory() as d,patch.object(O,'reaping_policy'),patch.object(O.subprocess,'Popen',return_value=p),patch.object(O.os,'waitid',side_effect=reserve),patch.object(O,'group_members',side_effect=descendants),patch.object(O.os,'killpg',side_effect=send),patch.object(O.os,'waitpid',side_effect=reap):
   a=self.actor(d)
   with self.assertRaises(O.ReservationLost):a.run(['model'])
   self.assertIsNone(a.rows[-1]['exit']);self.assertIsNone(a.rows[-1]['group_absent']);self.assertFalse(p._child_created)
  self.assertEqual(events,['reserve','reserve','reserve','census','reserve'])
 def test_changed_sigchld_policy_revokes_authority_before_group_probe(self):
  state=types.SimpleNamespace(si_pid=424242,si_code=os.CLD_EXITED,si_status=0)
  p,events,reserve,census,send,reap=self.model([state])
  with tempfile.TemporaryDirectory() as d,patch.object(O,'reaping_policy'),patch.object(O.subprocess,'Popen',return_value=p),patch.object(O.os,'waitid',side_effect=reserve),patch.object(O,'group_members',side_effect=census),patch.object(O.os,'killpg',side_effect=send),patch.object(O.os,'waitpid',side_effect=reap),patch.object(O.signal,'getsignal',side_effect=[signal.SIG_DFL,signal.SIG_IGN]):
   a=self.actor(d)
   with self.assertRaises(O.ReservationLost):a.run(['model'])
   self.assertIsNone(a.rows[-1]['exit']);self.assertIsNone(a.rows[-1]['group_absent']);self.assertFalse(p._child_created)
  self.assertEqual(events,['reserve'])
 def test_final_waitpid_echild_never_becomes_zero_or_postreap_probe(self):
  state=types.SimpleNamespace(si_pid=424242,si_code=os.CLD_EXITED,si_status=0)
  p,events,reserve,census,send,reap=self.model([state],reap_error=ChildProcessError(errno.ECHILD,'gone'))
  with tempfile.TemporaryDirectory() as d,patch.object(O,'reaping_policy'),patch.object(O.subprocess,'Popen',return_value=p),patch.object(O.os,'waitid',side_effect=reserve),patch.object(O,'group_members',side_effect=census),patch.object(O.os,'killpg',side_effect=send),patch.object(O.os,'waitpid',side_effect=reap):
   a=self.actor(d)
   with self.assertRaises(O.ReservationLost):a.run(['model'])
   self.assertIsNone(a.rows[-1]['exit']);self.assertIsNone(a.rows[-1]['group_absent']);self.assertFalse(p._child_created)
  self.assertEqual(events[-1],'reap');self.assertNotIn('signal',events)
 def test_final_status_mismatch_retains_actual_code_and_stays_failed(self):
  state=types.SimpleNamespace(si_pid=424242,si_code=os.CLD_EXITED,si_status=0)
  p,events,reserve,census,send,reap=self.model([state],code=7)
  with tempfile.TemporaryDirectory() as d,patch.object(O,'reaping_policy'),patch.object(O.subprocess,'Popen',return_value=p),patch.object(O.os,'waitid',side_effect=reserve),patch.object(O,'group_members',side_effect=census),patch.object(O.os,'killpg',side_effect=send),patch.object(O.os,'waitpid',side_effect=reap):
   a=self.actor(d)
   with self.assertRaisesRegex(ValueError,'differs from WNOWAIT'):a.run(['model'])
   self.assertEqual(a.rows[-1]['exit'],7);self.assertTrue(a.rows[-1]['leader_reaped']);self.assertEqual(a.rows[-1]['status'],'FAIL')
  self.assertEqual(events[-1],'reap');self.assertNotIn('signal',events)
 def test_apparent_popen_fake_zero_loses_authority_without_probe(self):
  p=self.fake();p.returncode=0;events=[]
  with tempfile.TemporaryDirectory() as d,patch.object(O,'reaping_policy'),patch.object(O.subprocess,'Popen',return_value=p),patch.object(O.os,'waitid',side_effect=lambda *a:events.append('reserve')),patch.object(O,'group_members',side_effect=lambda *a:events.append('census')),patch.object(O.os,'killpg',side_effect=lambda *a:events.append('signal')),patch.object(O.os,'waitpid',side_effect=lambda *a:events.append('reap')):
   a=self.actor(d)
   with self.assertRaises(O.ReservationLost):a.run(['model'])
   self.assertIsNone(a.rows[-1]['exit']);self.assertIsNone(a.rows[-1]['group_absent']);self.assertFalse(p._child_created)
  self.assertEqual(events,[])
 def test_ignored_and_custom_sigchld_refuse_before_launch(self):
  old=signal.getsignal(signal.SIGCHLD)
  try:
   for handler in (signal.SIG_IGN,lambda *a:None):
    signal.signal(signal.SIGCHLD,handler)
    with tempfile.TemporaryDirectory() as d,patch.object(O.subprocess,'Popen',side_effect=AssertionError('launch forbidden')):
     with self.assertRaisesRegex(ValueError,'incompatible child'):self.actor(d).run(['no'])
  finally:signal.signal(signal.SIGCHLD,old)
 def test_threaded_caller_refuses_before_launch(self):
  with tempfile.TemporaryDirectory() as d,patch.object(O.threading,'active_count',return_value=2),patch.object(O.subprocess,'Popen',side_effect=AssertionError('launch forbidden')):
   with self.assertRaisesRegex(ValueError,'incompatible child'):self.actor(d).run(['no'])
 def test_sigchld_policy_setup_failure_refuses_before_launch(self):
  with tempfile.TemporaryDirectory() as d,patch.object(O.signal,'signal',side_effect=OSError('policy denied')),patch.object(O.subprocess,'Popen',side_effect=AssertionError('launch forbidden')):
   with self.assertRaisesRegex(OSError,'policy denied'):self.actor(d).run(['no'])
 def test_source_has_no_popen_wait_poll_or_negative_group_reap(self):
  source=(HERE/'owner_common.py').read_text();node=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef)and n.name=='Actors')
  for n in ast.walk(node):
   if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute):self.assertNotIn(n.func.attr,('poll','wait'))
if __name__=='__main__':unittest.main(verbosity=2)
