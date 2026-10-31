#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real inert session/descendant controls; no ALPM transactions or helpers.

The test process temporarily becomes a child subreaper, restores its prior state,
and independently retires/reaps only known fixture children/session descendants.
"""
import ctypes as C,importlib.util,json,os,signal,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('live_supervision_candidate',HERE/'live.py');L=importlib.util.module_from_spec(spec);spec.loader.exec_module(L)
FORK=os.fork;WAITID=os.waitid;WAITPID=os.waitpid;KILL=os.kill;KILLPG=os.killpg;GETSID=os.getsid

def complete(args,save):
    Path(args.marker).write_text('work granted\n');value=L.initial_result();value.update(status='APPLIED',phase='inert-work-complete');save(value);return value

def descendant(args,save):
    signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
    pid=os.fork()
    if pid==0:
        while True:time.sleep(.05)
    Path(args.descendant).write_text(str(pid));Path(args.marker).write_text('work granted\n')
    if args.block:
        while True:time.sleep(.05)
    value=L.initial_result();value.update(status='APPLIED',phase='inert-descendant-created');save(value);return value

class Supervision(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='orphans-live-supervision-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.leaders=[];self.reaped=[];self.parent=os.getpid()
        self.args=SimpleNamespace(timeout_seconds=2,descendant=self.root/'descendant',marker=self.root/'work',block=False)
        self.receipt=L.R.Receipt(self.root/'receipt');self.addCleanup(self.receipt.close)
        self.lib=C.CDLL(None,use_errno=True);self.lib.prctl.restype=C.c_int;old=C.c_int()
        self.assertEqual(self.lib.prctl(37,C.byref(old),0,0,0),0);self.old_subreaper=old.value;self.assertEqual(self.lib.prctl(36,1,0,0,0),0);self.addCleanup(self.restore_subreaper)
        def tracked_fork():
            pid=FORK()
            if pid and os.getpid()==self.parent:self.leaders.append(pid)
            return pid
        self.fork_patch=patch.object(L.os,'fork',tracked_fork);self.fork_patch.start();self.addCleanup(self.fork_patch.stop);self.addCleanup(self.cleanup_children)
    def restore_subreaper(self):self.assertEqual(self.lib.prctl(36,self.old_subreaper,0,0,0),0)
    def adopted(self):
        path=Path('/proc')/str(self.parent)/'task'/str(self.parent)/'children';result=[]
        for value in path.read_text().split():
            pid=int(value)
            try:
                if GETSID(pid) in self.leaders:result.append(pid)
            except ProcessLookupError:pass
        return result
    def reap_known(self,pid,*,kill=False):
        until=time.monotonic()+2;sent=False
        while True:
            try:row=WAITID(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            except ChildProcessError:return None
            if row is not None:
                child,status=WAITPID(pid,os.WNOHANG);self.assertEqual(child,pid);self.reaped.append(pid);return os.waitstatus_to_exitcode(status)
            if kill and not sent:
                # WNOWAIT just established direct-child ownership; no prior reap.
                KILL(pid,signal.SIGKILL);sent=True
            self.assertLess(time.monotonic(),until,'fixture child retirement deadline');time.sleep(.01)
    def cleanup_children(self):
        for pid in self.leaders:self.reap_known(pid,kill=True)
        children=self.adopted()
        if self.args.descendant.exists():children.append(int(self.args.descendant.read_text()))
        for pid in set(children):self.reap_known(pid,kill=True)
        self.assertEqual(self.adopted(),[],'fixture session descendants remain')
    def signal_spy(self,events,*,after_reap=()):
        def send(pid,sig,group):
            self.assertNotIn(pid,after_reap,'numeric signal after actual kernel reap')
            row=WAITID(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            if group:self.assertEqual(GETSID(pid),pid,'group leader session was not registered')
            events.append((group,pid,sig,None if row is None else row.si_pid))
            return (KILLPG if group else KILL)(pid,sig)
        return (lambda pid,sig:send(pid,sig,False)),(lambda pid,sig:send(pid,sig,True))
    def assert_descendant_reaped(self):
        self.assertTrue(self.args.descendant.exists(),'work did not create its fixture descendant');pid=int(self.args.descendant.read_text());self.assertEqual(self.reap_known(pid),-signal.SIGKILL)
        with self.assertRaises(ChildProcessError):WAITID(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    def test_natural_leader_keeps_reservation_for_final_descendant_group_kill(self):
        events=[];kill,killpg=self.signal_spy(events)
        with patch.object(L.os,'kill',kill),patch.object(L.os,'killpg',killpg):result=L.supervise(self.args,self.receipt,work=descendant)
        self.assertEqual(result['status'],'APPLIED',result);self.assertEqual(result['worker']['exitcode'],0);self.assertTrue(result['worker']['session_registered']);self.assertEqual([(e[0],e[2]) for e in events],[(True,signal.SIGKILL)]);self.assertEqual(events[-1][3],self.leaders[0]);self.assert_descendant_reaped()
    def test_timeout_retires_term_resistant_leader_and_grandchild(self):
        self.args.timeout_seconds=.1;self.args.block=True;events=[];kill,killpg=self.signal_spy(events);start=time.monotonic()
        with patch.object(L.os,'kill',kill),patch.object(L.os,'killpg',killpg):result=L.supervise(self.args,self.receipt,work=descendant)
        self.assertLess(time.monotonic()-start,4);self.assertTrue(result['worker']['reaped']);self.assertEqual(result['worker']['termination'],'TIMEOUT');self.assertEqual(result['worker']['exitcode'],-signal.SIGKILL);self.assertTrue(result['worker']['session_registered']);self.assertTrue(all(e[0] for e in events));self.assertIn(signal.SIGTERM,[e[2] for e in events]);self.assertIn(signal.SIGKILL,[e[2] for e in events]);self.assert_descendant_reaped()
    def test_real_external_reap_echild_disables_all_numeric_signals(self):
        events=[];reaped=[]
        def external_reap(kind,pid,flags):
            row=WAITID(kind,pid,flags)
            if row is not None and not reaped:WAITPID(pid,0);reaped.append(pid);return WAITID(kind,pid,flags)
            return row
        with patch.object(L.os,'waitid',external_reap),patch.object(L.os,'kill',side_effect=lambda *a:events.append(a)),patch.object(L.os,'killpg',side_effect=lambda *a:events.append(a)):result=L.supervise(self.args,self.receipt,work=complete)
        self.assertTrue(reaped);self.assertEqual(events,[]);self.assertIsNone(result['worker']['exitcode']);self.assertFalse(result['worker']['reaped']);self.assertEqual(result['worker']['ownership'],'UNKNOWN');self.assertEqual(result['commit_started'],'UNKNOWN');self.assertEqual(result['packages_committed'],'UNKNOWN')
    def test_real_sigint_is_deferred_through_fork_registration(self):
        def interrupted_fork():
            pid=FORK()
            if pid and os.getpid()==self.parent:self.leaders.append(pid);KILL(self.parent,signal.SIGINT)
            return pid
        events=[];kill,killpg=self.signal_spy(events)
        with patch.object(L.os,'fork',interrupted_fork),patch.object(L.os,'kill',kill),patch.object(L.os,'killpg',killpg):result=L.supervise(self.args,self.receipt,work=descendant)
        self.assertTrue(result['worker']['reaped']);self.assertEqual(result['worker']['termination'],'CANCELLED');self.assertFalse(self.args.marker.exists(),'pregrant cancellation ran work');self.assertTrue(all(not e[0] for e in events))
    def test_session_readiness_failure_never_signals_unregistered_group(self):
        events=[];kill,killpg=self.signal_spy(events)
        with patch.object(L.os,'setsid',side_effect=OSError('inert readiness failure')),patch.object(L.os,'kill',kill),patch.object(L.os,'killpg',killpg):result=L.supervise(self.args,self.receipt,work=complete)
        self.assertTrue(result['worker']['reaped']);self.assertFalse(result['worker']['session_registered']);self.assertFalse(self.args.marker.exists());self.assertTrue(all(not e[0] for e in events))
    def test_parent_group_registration_failure_never_grants_work(self):
        events=[];kill,killpg=self.signal_spy(events)
        with patch.object(L.os,'getpgid',side_effect=lambda pid:pid+1),patch.object(L.os,'kill',kill),patch.object(L.os,'killpg',killpg):result=L.supervise(self.args,self.receipt,work=complete)
        self.assertTrue(result['worker']['reaped']);self.assertFalse(result['worker']['session_registered']);self.assertFalse(self.args.marker.exists());self.assertTrue(all(not e[0] for e in events))
    def test_reap_assignment_interruption_never_returns_to_numeric_signals(self):
        done=[];events=[]
        def interrupted_reap(pid,flags):
            value=WAITPID(pid,flags)
            if value[0]:done.append(pid);raise KeyboardInterrupt('after actual final leader reap')
            return value
        kill,killpg=self.signal_spy(events,after_reap=done)
        with patch.object(L.os,'waitpid',interrupted_reap),patch.object(L.os,'kill',kill),patch.object(L.os,'killpg',killpg):result=L.supervise(self.args,self.receipt,work=descendant)
        self.assertTrue(done);self.assertEqual(result['worker']['ownership'],'UNKNOWN');self.assertIsNone(result['worker']['exitcode']);self.assertEqual(result['packages_committed'],'UNKNOWN');self.assertTrue(events);self.assert_descendant_reaped()

if __name__=='__main__':unittest.main()
