#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real inert owned-child controls only. No ALPM, package, GPG or native actors."""
import importlib.util,os,signal,tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('retirement_candidate',HERE/'remove.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)

def complete(args,save):
 value=R.initial_result();value.update(status='APPLIED',phase='test-worker-complete');save(value);return value

def blocked(args,save):
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 while True:time.sleep(.05)

class Retirement(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.receipt=R.Receipt(Path(self.tmp.name)/'result');self.addCleanup(self.receipt.close);self.args=SimpleNamespace(timeout_seconds=.05)
 def test_real_natural_child_status_is_observed_without_signals(self):
  calls=[]
  with patch.object(R.os,'kill',side_effect=lambda *a:calls.append(a)):value=R.supervise(SimpleNamespace(timeout_seconds=2),self.receipt,work=complete)
  self.assertEqual(calls,[]);self.assertEqual(value['worker']['exitcode'],0);self.assertTrue(value['worker']['reaped']);self.assertEqual(value['status'],'APPLIED')
 def test_real_echild_loses_ownership_without_numeric_signal(self):
  waitid=os.waitid;waitpid=os.waitpid;signals=[];seen=[]
  def external_reap(kind,pid,flags):
   if not seen:seen.append(pid);waitpid(pid,0)
   return waitid(kind,pid,flags)
  with patch.object(R.os,'waitid',external_reap),patch.object(R.os,'kill',side_effect=lambda *a:signals.append(a)):value=R.supervise(self.args,self.receipt,work=complete)
  self.assertEqual(signals,[]);self.assertEqual(value['worker']['ownership'],'UNKNOWN');self.assertFalse(value['worker']['reaped']);self.assertIsNone(value['worker']['exitcode']);self.assertEqual(value['commit_started'],'UNKNOWN');self.assertEqual(value['packages_committed'],'UNKNOWN');self.assertEqual(value['status'],'FAILED')
 def test_real_timeout_checks_reservation_before_each_signal(self):
  real_kill=os.kill;events=[]
  def send(pid,sig):
   # WNOWAIT both succeeds on running children and retains terminal children.
   row=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT);events.append((pid,sig,None if row is None else row.si_pid));real_kill(pid,sig)
  with patch.object(R.os,'kill',side_effect=send):value=R.supervise(self.args,self.receipt,work=blocked)
  self.assertTrue(events);self.assertIn(signal.SIGKILL,[e[1] for e in events]);self.assertTrue(value['worker']['reaped']);self.assertEqual(value['worker']['exitcode'],-signal.SIGKILL);self.assertEqual(value['worker']['termination'],'TIMEOUT')
 def test_reap_assignment_interruption_cannot_signal_after_kernel_reap(self):
  real_wait=os.waitpid;real_kill=os.kill;signals=[];done=[]
  def wait(pid,flags):
   result=real_wait(pid,flags)
   if result[0]:done.append(pid);raise KeyboardInterrupt('after real reap before assignment')
   return result
  def send(pid,sig):
   self.assertNotIn(pid,done);signals.append((pid,sig));real_kill(pid,sig)
  with patch.object(R.os,'waitpid',wait),patch.object(R.os,'kill',side_effect=send):value=R.supervise(SimpleNamespace(timeout_seconds=2),self.receipt,work=complete)
  self.assertTrue(done);self.assertEqual(signals,[]);self.assertIsNone(value['worker']['exitcode']);self.assertEqual(value['packages_committed'],'UNKNOWN')
 def test_unexpected_waitid_result_is_unknown_and_never_signalled(self):
  real=os.waitid;seen=[];signals=[]
  def mismatch(kind,pid,flags):
   seen.append(pid);row=real(kind,pid,flags)
   return SimpleNamespace(si_pid=pid+1,si_code=os.CLD_EXITED) if row is not None else row
  try:
   with patch.object(R.os,'waitid',mismatch),patch.object(R.os,'kill',side_effect=lambda *a:signals.append(a)):value=R.supervise(SimpleNamespace(timeout_seconds=2),self.receipt,work=complete)
   self.assertEqual(signals,[]);self.assertEqual(value['worker']['ownership'],'UNKNOWN')
  finally:
   if seen:
    try:os.waitpid(seen[-1],0)
    except ChildProcessError:pass
 def test_pending_real_sigint_is_deferred_until_fork_registration(self):
  fork=os.fork;kill=os.kill;children=[]
  def interrupted_fork():
   pid=fork()
   if pid:children.append(pid);kill(os.getpid(),signal.SIGINT)
   return pid
  with patch.object(R.os,'fork',interrupted_fork):value=R.supervise(SimpleNamespace(timeout_seconds=2),self.receipt,work=blocked)
  self.assertEqual(len(children),1);self.assertTrue(value['worker']['reaped']);self.assertEqual(value['worker']['termination'],'CANCELLED')
  with self.assertRaises(ChildProcessError):os.waitpid(children[0],os.WNOHANG)
 def test_sigchld_dispositions_are_rejected_before_fork(self):
  before=signal.getsignal(signal.SIGCHLD)
  try:
   for handler in (signal.SIG_IGN,lambda *a:None):
    signal.signal(signal.SIGCHLD,handler)
    with patch.object(R.os,'fork') as fork,self.assertRaises(ValueError):R.supervise(self.args,self.receipt,work=complete)
    fork.assert_not_called()
  finally:signal.signal(signal.SIGCHLD,before)
 def test_nonmain_owner_rejected_without_child(self):
  errors=[]
  def call():
   try:R.supervise(self.args,self.receipt,work=complete)
   except BaseException as error:errors.append(error)
  with patch.object(R.os,'fork') as fork:
   thread=threading.Thread(target=call);thread.start();thread.join();fork.assert_not_called()
  self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],ValueError)

if __name__=='__main__':unittest.main()
