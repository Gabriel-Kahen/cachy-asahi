#!/usr/bin/env python3
"""Versioned retirement controls: explicit models and fresh host Python children."""
import ast
import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch

P=Path(__file__).resolve().parent
ROOT=P.parent
V2=ROOT/'scripts/virtual/owned_process_retirement_v2.py'
ORIGINAL=ROOT/'scripts/virtual/owned_process.py'
ORIGINAL_SHA='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
RECEIPTS=[]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
R=load('retirement_v2',V2)
OLD=load('canonical_retirement_reference',ORIGINAL)
WAITID,WAITPID,KILL,KILLPG,OPEN,SCANDIR=os.waitid,os.waitpid,os.kill,os.killpg,os.open,os.scandir

def actors(event,args):
    if event.startswith('socket.')or event in {'os.system','os.posix_spawn','os.exec'}:raise AssertionError('forbidden control actor')
    if event=='subprocess.Popen':
        executable,argv=args[:2]
        if executable!=sys.executable or argv[:4]!=[sys.executable,'-I','-B','-c']:raise AssertionError('only authored host Python children allowed')
sys.addaudithook(actors)

def terminal(pid):
    until=time.monotonic()+2
    while time.monotonic()<until:
        row=WAITID(os.P_PID,pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
        if row is not None:return row
        time.sleep(.002)
    raise AssertionError('fresh control child not terminal')

def record(name,kind,result,events):
    receipt=dict(result);receipt['output']=receipt['output'].hex()
    RECEIPTS.append(dict(name=name,kind=kind,result=receipt,events=events,native='NOT_RUN'))

class Model:
    """Deterministic reserved PID and later-reuse fixture, never actual PID reuse."""
    pid=424242
    def __init__(self,core,*,late_reuse=False,remaining=False,steal=None,wait_failure=None,incomplete=False):
        self.core,self.late_reuse,self.remaining=core,late_reuse,remaining
        self.steal,self.wait_failure,self.incomplete=steal,wait_failure,incomplete
        self.released=False;self.stolen=False;self.lost=False;self.raw_called=False
        self.role=None;self.in_scan=False;self.events=[]
    def numeric(self,kind):
        if self.lost or self.raw_called and not self.late_reuse:raise AssertionError('numeric operation after raw wait/ECHILD: '+kind)
        if self.stolen:raise AssertionError('numeric operation without detecting stolen wait: '+kind)
        self.events.append(kind)
    def waitid(self,kind,pid,flags):
        if self.raw_called or self.lost:raise AssertionError('waitid after raw wait/ECHILD')
        self.events.append('peek')
        if self.stolen:self.lost=True;self.events.append('ECHILD');raise ChildProcessError()
        return types.SimpleNamespace(si_pid=self.pid,si_code=os.CLD_EXITED,si_status=0)
    def waitpid(self,pid,flags):
        self.numeric('raw_wait');self.raw_called=True
        if self.wait_failure=='ECHILD':self.lost=True;self.events.append('ECHILD');raise ChildProcessError()
        if self.wait_failure=='error':raise OSError('modeled raw wait failure')
        if self.wait_failure=='zero':return 0,0
        self.released=True;return self.pid,0
    def stat(self,pid):
        self.numeric('stat:'+str(pid))
        state=b'S'if self.raw_called and self.late_reuse else b'Z'
        start=99 if self.raw_called and self.late_reuse else 17 if pid==self.pid else 18
        group=self.pid if pid==self.pid or self.remaining else self.pid+100
        row=(pid,state,group,group,start)
        if self.in_scan and self.steal==self.role and not self.stolen:
            self.stolen=True;self.events.append('external_wait_stolen')
        return row
    def scandir(self,path):
        self.numeric('scan:'+str(self.role))
        if self.incomplete and self.role=='reserved':raise TimeoutError('modeled incomplete final census')
        model=self
        class Directory:
            def __enter__(self):
                model.in_scan=True
                names=[str(model.pid)]
                if model.remaining or model.steal:names.append(str(model.pid+7))
                return iter(types.SimpleNamespace(name=n)for n in names)
            def __exit__(self,*args):model.in_scan=False
        return Directory()
    def __enter__(self):
        self.stack=contextlib.ExitStack();member=self.core._members;reserved=self.core._rss_members
        def members(*a,**kw):
            self.role='live'
            try:return member(*a,**kw)
            finally:self.role=None
        def rss_members(*a,**kw):
            self.role='reserved'
            try:return reserved(*a,**kw)
            finally:self.role=None
        for owner,name,value in ((self.core.os,'waitid',self.waitid),(self.core.os,'waitpid',self.waitpid),
            (self.core.os,'scandir',self.scandir),(self.core,'_stat',self.stat),
            (self.core,'_members',members),(self.core,'_rss_members',rss_members),
            (self.core.os,'kill',lambda *a: self.numeric('unexpected_signal')),
            (self.core.os,'killpg',lambda *a:self.numeric('unexpected_group_signal'))):
            self.stack.enter_context(patch.object(owner,name,value))
        return self
    def __exit__(self,*args):return self.stack.__exit__(*args)
    def run(self):return self.core.supervise(self.pid,cap=1,retirement=.4,streams=())

class DeterministicControls(unittest.TestCase):
    def test_old_later_reuse_signature_and_new_no_post_reap_census(self):
        with Model(OLD,late_reuse=True)as old:old_result=old.run()
        self.assertEqual({k:old_result[k]for k in('exit','reaped','ownership','output_complete','error','group_census','passed')},
            dict(exit=0,reaped=True,ownership='REAPED',output_complete=True,error=None,group_census='PRESENT_OR_REUSED',passed=False))
        self.assertTrue(any(e.startswith('stat:')for e in old.events[old.events.index('raw_wait')+1:]))
        with Model(R)as new:new_result=new.run()
        self.assertTrue(new_result['passed'],new_result);self.assertEqual(new_result['group_census'],'RESERVED_LEADER_ONLY')
        self.assertEqual(new.events[-1],'raw_wait')
        record(self._testMethodName,'DETERMINISTIC_LATER_REUSE_MODEL_NOT_NATIVE_CAUSE',new_result,new.events)
        record(self._testMethodName+'-old-signature','DETERMINISTIC_OLD_CORE_MODEL',old_result,old.events)

    def test_nonrss_live_census_stolen_wait_stops_per_member_numeric_reads(self):
        with Model(R,steal='live')as model:result=model.run()
        self.assertEqual(result['ownership'],'UNKNOWN');self.assertIsNone(result['exit']);self.assertFalse(result['passed']or result['reaped'])
        self.assertEqual(model.events[-1],'ECHILD');self.assertNotIn('raw_wait',model.events)
        record(self._testMethodName,'DETERMINISTIC_STOLEN_WAIT',result,model.events)

    def test_final_reserved_census_stolen_wait_stops_all_later_numeric_reads(self):
        with Model(R,steal='reserved')as model:result=model.run()
        self.assertEqual(result['ownership'],'UNKNOWN');self.assertEqual(result['group_census'],'UNKNOWN')
        self.assertFalse(result['passed']or result['reaped']);self.assertEqual(model.events[-1],'ECHILD')
        record(self._testMethodName,'DETERMINISTIC_STOLEN_WAIT',result,model.events)

    def test_failed_consuming_wait_never_probes_or_retries(self):
        for failure in ('ECHILD','error','zero'):
            with self.subTest(failure=failure),Model(R,wait_failure=failure)as model:result=model.run()
            self.assertEqual(result['ownership'],'UNKNOWN');self.assertIsNone(result['exit']);self.assertFalse(result['reaped']or result['passed'])
            self.assertEqual(model.events.count('raw_wait'),1)
            self.assertIn(model.events[-1],('raw_wait','ECHILD'))
            record(self._testMethodName+'-'+failure,'DETERMINISTIC_RAW_WAIT_FAILURE',result,model.events)

    def test_real_remaining_member_model_is_not_accepted(self):
        with Model(R,remaining=True)as model:result=model.run()
        self.assertTrue(result['reaped']);self.assertEqual(result['exit'],0)
        self.assertEqual(result['group_census'],'RESERVED_MEMBERS_REMAIN');self.assertFalse(result['passed'])
        self.assertEqual(model.events[-1],'raw_wait')
        record(self._testMethodName,'DETERMINISTIC_REMAINING_MEMBER',result,model.events)

    def test_incomplete_reserved_census_is_unknown_not_accepted(self):
        with Model(R,incomplete=True)as model:result=model.run()
        self.assertEqual(result['group_census'],'UNKNOWN');self.assertTrue(result['reaped']);self.assertFalse(result['passed'])
        self.assertIn('TimeoutError',result['error']);self.assertEqual(model.events[-1],'raw_wait')
        record(self._testMethodName,'DETERMINISTIC_INCOMPLETE_CENSUS',result,model.events)

    def test_original_hash_public_api_rss_helpers_and_clocks_held(self):
        self.assertEqual(hashlib.sha256(ORIGINAL.read_bytes()).hexdigest(),ORIGINAL_SHA)
        self.assertEqual(inspect.signature(R.supervise),inspect.signature(OLD.supervise))
        old,new=ast.parse(ORIGINAL.read_bytes()),ast.parse(V2.read_bytes())
        for name in ('prepare','_stat','_rss_members','_rss_identity','_rss_sample','_rss_summary','_rss_failure'):
            get=lambda tree:next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
            self.assertEqual(ast.dump(get(old),include_attributes=False),ast.dump(get(new),include_attributes=False),name)
        for name in ('TICK','PROC_LIMIT','RSS_MAX_TASKS','RSS_MAX_MEMBERS','RSS_MAX_SAMPLES','RSS_MAX_ROWS','RSS_SAMPLE_SECONDS','RSS_SCOPE'):
            self.assertEqual(getattr(R,name),getattr(OLD,name),name)
        self.assertNotIn('if reaped and group',V2.read_text())

class Audit:
    def __init__(self,pid,lease=None):self.pid,self.lease=pid,lease;self.released=False;self.lost=False;self.events=[]
    def numeric(self):
        if self.released or self.lost:raise AssertionError('numeric probe/signal after reap/ECHILD')
        if self.lease is not None:os.fstat(self.lease)
    def waitid(self,*args):
        self.numeric();self.events.append('peek')
        try:return WAITID(*args)
        except ChildProcessError:self.lost=True;self.events.append('ECHILD');raise
    def waitpid(self,*args):
        self.numeric();self.events.append('raw_wait');result=WAITPID(*args)
        if result[0]==self.pid:self.released=True
        return result
    def stat(self,pid):self.numeric();self.events.append('stat');return self.stat_original(pid)
    def scandir(self,path):self.numeric();self.events.append('scan');return SCANDIR(path)
    def killpg(self,pid,sig):
        self.numeric();self.assert_pid(pid);self.events.append(signal.Signals(sig).name)
        WAITID(os.P_PID,pid,os.WEXITED|os.WNOWAIT|os.WNOHANG);return KILLPG(pid,sig)
    def kill(self,pid,sig):self.numeric();self.assert_pid(pid);self.events.append(signal.Signals(sig).name);return KILL(pid,sig)
    def assert_pid(self,pid):
        if pid!=self.pid:raise AssertionError('foreign signal')
    def __enter__(self):
        self.stack=contextlib.ExitStack();self.stat_original=R._stat
        for owner,name,value in ((R.os,'waitid',self.waitid),(R.os,'waitpid',self.waitpid),(R.os,'scandir',self.scandir),
            (R.os,'killpg',self.killpg),(R.os,'kill',self.kill),(R,'_stat',self.stat)):
            self.stack.enter_context(patch.object(owner,name,value))
        return self
    def __exit__(self,*args):return self.stack.__exit__(*args)

class FreshHostChildren(unittest.TestCase):
    def setUp(self):R.prepare();self.children=[]
    def tearDown(self):
        for child in self.children:
            try:WAITID(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
            except ChildProcessError:continue
            R.supervise(child,cap=.9,retirement=.5,grace=.04)
    def launch(self,source,pass_fds=()):
        child=subprocess.Popen([sys.executable,'-I','-B','-c',source],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,pass_fds=pass_fds)
        self.children.append(child);return child
    def ready(self,source,pass_fds=()):
        read,write=os.pipe()
        try:
            child=self.launch(source.replace('@READY@',str(write)),(*pass_fds,write));os.close(write);write=None
            self.assertTrue(select.select([read],[],[],2)[0]);self.assertEqual(os.read(read,1),b'R');return child
        finally:
            os.close(read)
            if write is not None:os.close(write)
    def test_fresh_natural_python_child_proof_precedes_raw_reap(self):
        child=self.launch("import os; os.write(1,b'out'); os.write(2,b'err')")
        with Audit(child.pid)as audit:result=R.supervise(child,cap=1.5,retirement=.5)
        self.assertTrue(result['passed'],result);self.assertEqual(result['group_census'],'RESERVED_LEADER_ONLY')
        self.assertEqual((result['exit'],child.returncode),(0,0));self.assertEqual(audit.events[-1],'raw_wait')
        self.assertEqual(len(result['output']),6);self.assertFalse(result['signals'])
        record(self._testMethodName,'HOST_FRESH_PYTHON_CHILD',result,audit.events)
    def test_fresh_descendant_is_retired_and_reaped_by_its_leader(self):
        child=self.ready('''import os,signal,time
pid=os.fork()
if pid==0:
 def stop(sig,frame):os.write(1,b'descendant TERM\\n');os._exit(0)
 signal.signal(signal.SIGTERM,stop)
 os.write(@READY@,b'R');os.close(@READY@)
 while True:time.sleep(1)
def stop(sig,frame):os.waitpid(pid,0);os.write(1,b'leader reaped descendant\\n');os._exit(0)
signal.signal(signal.SIGTERM,stop)
while True:time.sleep(1)
''')
        with Audit(child.pid)as audit:result=R.supervise(child,cap=1.2,retirement=.5,grace=.2)
        self.assertTrue(result['reaped']and result['timeout'],result)
        self.assertEqual(result['signals'],['SIGTERM']);self.assertEqual(result['group_census'],'RESERVED_LEADER_ONLY')
        self.assertIn(b'leader reaped descendant',result['output']);self.assertFalse(result['passed'])
        self.assertEqual(audit.events[-1],'raw_wait')
        record(self._testMethodName,'HOST_FRESH_GROUP_DESCENDANT',result,audit.events)
    def test_lease_and_last_kill_precede_reap_without_later_probe(self):
        lease,unused=os.pipe()
        try:
            child=self.ready(f'import os,signal,time;os.fstat({lease});signal.signal(signal.SIGTERM,signal.SIG_IGN);os.write(@READY@,b"R");os.close(@READY@);time.sleep(60)',(lease,))
            with Audit(child.pid,lease)as audit:result=R.supervise(child,cap=.9,retirement=.4,grace=.04)
            self.assertEqual(result['signals'],['SIGTERM','SIGKILL']);self.assertTrue(result['reaped'])
            self.assertEqual(result['exit'],-signal.SIGKILL);self.assertEqual(result['group_census'],'RESERVED_LEADER_ONLY')
            self.assertLess(audit.events.index('SIGKILL'),audit.events.index('raw_wait'));self.assertEqual(audit.events[-1],'raw_wait');os.fstat(lease)
            self.assertLess(result['seconds'],1.1);record(self._testMethodName,'HOST_LEASE_SIGNAL_ORDER',result,audit.events)
        finally:os.close(lease);os.close(unused)
    def test_actual_stolen_wait_suppresses_every_later_numeric_operation(self):
        child=self.launch('import os;os._exit(23)');terminal(child.pid);self.assertEqual(os.waitstatus_to_exitcode(WAITPID(child.pid,0)[1]),23)
        with Audit(child.pid)as audit:result=R.supervise(child,cap=.8,retirement=.4)
        self.assertEqual(result['ownership'],'UNKNOWN');self.assertFalse(result['reaped']or result['passed'])
        self.assertIsNone(result['exit']);self.assertFalse(child._child_created);self.assertEqual(audit.events,['peek','ECHILD'])
        record(self._testMethodName,'HOST_REAL_STOLEN_WAIT',result,audit.events)
    def test_nonzero_exit_not_bypassed_by_complete_reserved_proof(self):
        child=self.launch('import os;os._exit(7)')
        with Audit(child.pid)as audit:result=R.supervise(child,cap=1,retirement=.4)
        self.assertEqual(result['exit'],7);self.assertEqual(result['group_census'],'RESERVED_LEADER_ONLY');self.assertFalse(result['passed'])
        self.assertEqual(audit.events[-1],'raw_wait');record(self._testMethodName,'HOST_NONZERO_REJECTION',result,audit.events)

# Eight original RSS behavior controls are reused unmodified with only R rebound
# to the new local core. The ninth compatibility control changes only the intended
# private _members AST assertion; public API and result fields stay exact.
RSS=load('retained_rss_controls',ROOT/'tests/test_owned_process_memory.py');RSS.R=R;RSS.STAT=R._stat
class RetainedRSSControls(RSS.OwnedMemory):
    def test_default_helpers_and_result_contract_stay_compatible(self):
        self.assertEqual(inspect.signature(R.supervise),inspect.signature(OLD.supervise))
        child=self.launch('os._exit(0)')
        for value in (True,float('nan'),0,.001,61):
            with self.assertRaises(ValueError):R.supervise(child,cap=1,retirement=.4,rss_interval=value)
        with patch.object(R,'_rss_sample',side_effect=AssertionError('default must never sample')):result=R.supervise(child,cap=1,retirement=.4)
        self.assertTrue(result['passed'],result);self.assertEqual(result['group_census'],'RESERVED_LEADER_ONLY')
        self.assertEqual(set(result),{'exit','reaped','ownership','timeout','signals','output','output_complete','group_census','error','seconds','passed'})

if __name__=='__main__':unittest.main(verbosity=2)
