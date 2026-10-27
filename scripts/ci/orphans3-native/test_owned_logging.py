#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small REAL inert-child controls; no ALPM/GPG/package/native/Docker/network/Git."""
import ast,copy,errno,importlib.util,io,json,os,signal,subprocess,sys,tempfile,textwrap,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve();SOURCE=HERE.parents[3] if HERE.parent.name=='orphans3-native' else HERE.parents[1]/'proposed'
spec=importlib.util.spec_from_file_location('owned_common',SOURCE/'scripts/virtual/common.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
REAL_WAITID=os.waitid;REAL_WAITPID=os.waitpid;REAL_KILLPG=os.killpg;REAL_POPEN=subprocess.Popen;REAL_OPEN=Path.open

def argv(code):return [sys.executable,'-I','-B','-c',code]
def dispose(process):
    try:
        REAL_WAITID(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        REAL_KILLPG(process.pid,signal.SIGKILL)
        pid,status=REAL_WAITPID(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
    except ChildProcessError:process._child_created=False
    except ProcessLookupError:
        try:pid,status=REAL_WAITPID(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
        except ChildProcessError:process._child_created=False

class Logging(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.previous=signal.getsignal(signal.SIGCHLD);signal.signal(signal.SIGCHLD,signal.SIG_DFL);self.addCleanup(signal.signal,signal.SIGCHLD,self.previous)
    def launch(self,code,**kw):
        item=M.LoggedProcess(argv(code),self.root/'log',**kw);self.addCleanup(dispose,item.process);return item
    def spy_signal(self,events):
        def send(pid,sig):
            row=REAL_WAITID(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            events.append(dict(pid=pid,signal=int(sig),terminal=row is not None))
            return REAL_KILLPG(pid,sig)
        return send
    def test_natural_zero_and_nonzero_observe_direct_wait_before_return(self):
        for code in (0,7):
            if (self.root/'log').exists():(self.root/'log').unlink()
            item=self.launch('print("inert");raise SystemExit('+str(code)+')');events=[]
            with patch.object(item.process,'wait',side_effect=AssertionError('Popen.wait forbidden')),patch.object(item.process,'poll',side_effect=AssertionError('Popen.poll forbidden')),patch.object(os,'killpg',self.spy_signal(events)):
                self.assertEqual(item.wait_owned(2),code)
            self.assertEqual(item.observed_returncode,code);self.assertTrue(item.retirement['leader_reaped']);self.assertTrue(item.retirement['log_drained']);self.assertEqual(len(events),1);self.assertTrue(events[0]['terminal'])
            with self.assertRaises(ChildProcessError):REAL_WAITID(os.P_PID,item.process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    def test_timeout_final_signal_is_before_direct_reap(self):
        item=self.launch('import time;time.sleep(30)');events=[]
        with patch.object(os,'killpg',self.spy_signal(events)),self.assertRaisesRegex(M.Refused,'timeout'):item.wait_owned(.03)
        self.assertEqual(item.observed_returncode,-signal.SIGKILL);self.assertTrue(item.retirement['leader_reaped']);self.assertEqual(len(events),1)
    def test_reap_assignment_interrupted_reports_unknown_and_never_signals_again(self):
        item=self.launch('pass');reaped=[];events=[]
        def wait(pid,flags):
            row=REAL_WAITPID(pid,flags)
            if row[0]:reaped.append(pid);raise KeyboardInterrupt('after kernel reap')
            return row
        def send(pid,sig):
            self.assertNotIn(pid,reaped);events.append(pid)
            REAL_WAITID(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            return REAL_KILLPG(pid,sig)
        with patch.object(os,'waitpid',wait),patch.object(os,'killpg',send),self.assertRaises(KeyboardInterrupt):item.wait_owned(2)
        self.assertEqual(len(events),1);self.assertTrue(reaped);self.assertIsNone(item.observed_returncode);self.assertIsNone(item.process.returncode);self.assertEqual(item.retirement['ownership'],'UNKNOWN');self.assertFalse(item.process._child_created)
    def test_real_echild_suppresses_all_numeric_signals_and_zero_inference(self):
        item=self.launch('pass');pid,status=REAL_WAITPID(item.process.pid,0);self.assertEqual(pid,item.process.pid);events=[]
        with patch.object(os,'killpg',side_effect=lambda *a:events.append(a)),patch.object(item.process,'wait',side_effect=AssertionError('Popen.wait forbidden')),patch.object(item.process,'poll',side_effect=AssertionError('Popen.poll forbidden')):
            with self.assertRaisesRegex(M.Refused,'reservation'):item.wait_owned(1)
        self.assertEqual(events,[]);self.assertIsNone(item.observed_returncode);self.assertIsNone(item.process.returncode);self.assertFalse(item.process._child_created);self.assertEqual(item.retirement['ownership'],'UNKNOWN');self.assertFalse(item.retirement['leader_reaped'])
    def test_unverified_observation_permanently_disables_signals(self):
        item=self.launch('import time;time.sleep(30)');events=[]
        try:
            start=time.monotonic()
            with patch.object(os,'waitid',side_effect=RuntimeError('unverified wait')),patch.object(os,'killpg',side_effect=lambda *a:events.append(a)),self.assertRaisesRegex(M.Refused,'reservation'):
                item.wait_owned(1,cleanup_timeout=.02)
            self.assertLess(time.monotonic()-start,.5);self.assertEqual(events,[]);self.assertIsNone(item.observed_returncode);self.assertEqual(item.retirement['ownership'],'UNKNOWN');self.assertFalse(item.retirement['log_drained']);self.assertFalse(item.process.stdout.closed)
        finally:
            dispose(item.process);item.thread.join(timeout=2)
    def delayed_failure(self,overflow):
        path=self.root/'log';release=threading.Event();entered=threading.Event();seen=[];original_observe=M.OwnedChild.observe
        class Writer:
            def __init__(self,real):self.real=real
            def __enter__(self):return self
            def __exit__(self,*a):self.real.close()
            def write(self,data):
                entered.set();assert release.wait(2),'terminal observation never released logger'
                if not overflow:raise OSError('delayed log write failure')
                return self.real.write(data)
            def flush(self):self.real.flush()
            def close(self):self.real.close()
        def opened(p,*a,**kw):
            real=REAL_OPEN(p,*a,**kw);return Writer(real) if p==path else real
        def observe(owner):
            row=original_observe(owner)
            if row is not None:seen.append(row.si_pid);release.set()
            return row
        events=[]
        with patch.object(Path,'open',opened):item=self.launch('import os;os.write(1,b"xx")',limit=1 if overflow else 100)
        try:
            self.assertTrue(entered.wait(2))
            with patch.object(M.OwnedChild,'observe',observe),patch.object(os,'killpg',self.spy_signal(events)),self.assertRaisesRegex(M.Refused,'logging failed'):item.wait_owned(2)
        finally:release.set()
        self.assertTrue(seen);self.assertEqual(item.observed_returncode,0);self.assertTrue(item.retirement['leader_reaped']);self.assertEqual(len(events),1);self.assertTrue(events[0]['terminal']);self.assertIn('overflow' if overflow else 'delayed',item.error)
    def test_delayed_overflow_holds_terminal_leader_until_last_signal(self):self.delayed_failure(True)
    def test_delayed_write_error_holds_terminal_leader_until_last_signal(self):self.delayed_failure(False)
    def test_thread_start_failure_uses_same_owned_retirement(self):
        processes=[];events=[]
        def popen(*a,**kw):
            p=REAL_POPEN(*a,**kw);processes.append(p);self.addCleanup(dispose,p);return p
        with patch.object(subprocess,'Popen',popen),patch.object(threading.Thread,'start',side_effect=RuntimeError('thread start failure')),patch.object(os,'killpg',self.spy_signal(events)),self.assertRaisesRegex(RuntimeError,'thread start') as caught:
            M.LoggedProcess(argv('import time;time.sleep(30)'),self.root/'log')
        self.assertEqual(len(processes),1);self.assertEqual(len(events),1);self.assertTrue(caught.exception.owned_retirement['leader_reaped']);self.assertEqual(caught.exception.owned_retirement['observed_returncode'],-signal.SIGKILL)
    def test_sigchld_ignore_and_custom_refuse_before_launch(self):
        for disposition in (signal.SIG_IGN,lambda *_:None):
            signal.signal(signal.SIGCHLD,disposition)
            with patch.object(subprocess,'Popen',side_effect=AssertionError('must refuse before launch')),self.assertRaisesRegex(M.Refused,'SIGCHLD'):
                M.LoggedProcess(argv('pass'),self.root/'log')
            self.assertFalse((self.root/'log').exists())
        signal.signal(signal.SIGCHLD,signal.SIG_DFL)
    def test_policy_reset_failure_prevents_launch(self):
        original=signal.signal
        def refused(sig,handler):
            if sig==signal.SIGCHLD:raise OSError('policy reset denied')
            return original(sig,handler)
        with patch.object(signal,'signal',refused),patch.object(subprocess,'Popen',side_effect=AssertionError('must refuse before launch')),self.assertRaisesRegex(OSError,'reset denied'):
            M.LoggedProcess(argv('pass'),self.root/'log')
    def test_nonmain_and_multiple_threads_refuse_before_launch(self):
        errors=[]
        def attempt():
            try:M.LoggedProcess(argv('pass'),self.root/'log')
            except BaseException as e:errors.append(e)
        t=threading.Thread(target=attempt);t.start();t.join();self.assertIsInstance(errors[0],M.Refused)
        release=threading.Event();t=threading.Thread(target=release.wait);t.start()
        try:
            with self.assertRaisesRegex(M.Refused,'one main thread'):M.LoggedProcess(argv('pass'),self.root/'log')
        finally:release.set();t.join()
    def test_used_run_command_records_retirement_without_popen_wait(self):
        path=SOURCE/'scripts/ci/orphans3-native/run.py';tree=ast.parse(path.read_bytes());node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='command');text=textwrap.dedent(ast.get_source_segment(path.read_text(),node)).replace('nonlocal active','global active')
        self.assertNotIn('.process.wait(',text);self.assertNotIn('.process.poll(',text);self.assertNotIn('killpg(',text)
        receipts=[];report={'commands':[]};space=dict(active=None,report=report,save=lambda p,v:receipts.append(copy.deepcopy(v)),out=self.root,common=M,C=SimpleNamespace(need=M.require),env=dict(os.environ))
        exec(compile(text,str(path),'exec'),space);space['command'](argv('print("owned")'),self.root/'command.log',2)
        row=receipts[-1]['commands'][0];self.assertEqual(row['exitcode'],0);self.assertTrue(row['retirement']['leader_reaped']);self.assertEqual(row['retirement']['observed_returncode'],0);self.assertIsNone(space['active'])
    def test_used_run_command_echild_keeps_exit_null_and_never_signals(self):
        path=SOURCE/'scripts/ci/orphans3-native/run.py';node=next(n for n in ast.walk(ast.parse(path.read_bytes())) if isinstance(n,ast.FunctionDef) and n.name=='command');text=textwrap.dedent(ast.get_source_segment(path.read_text(),node)).replace('nonlocal active','global active');receipts=[];events=[]
        def externally_reaped(*a,**kw):
            item=M.LoggedProcess(*a,**kw);self.addCleanup(dispose,item.process);pid,status=REAL_WAITPID(item.process.pid,0);self.assertEqual(pid,item.process.pid);return item
        space=dict(active=None,report={'commands':[]},save=lambda p,v:receipts.append(copy.deepcopy(v)),out=self.root,common=SimpleNamespace(LoggedProcess=externally_reaped,registered_spawn=M.registered_spawn),C=SimpleNamespace(need=M.require),env=dict(os.environ));exec(compile(text,str(path),'exec'),space)
        with patch.object(os,'killpg',side_effect=lambda *a:events.append(a)),self.assertRaises(M.Refused):space['command'](argv('pass'),self.root/'used-echild.log',2)
        row=receipts[-1]['commands'][0];self.assertEqual(events,[]);self.assertIsNone(row['exitcode']);self.assertEqual(row['retirement']['ownership'],'UNKNOWN');self.assertFalse(row['retirement']['leader_reaped']);self.assertIsNone(space['active'])
    def command_fixture(self,common):
        path=SOURCE/'scripts/ci/orphans3-native/run.py';node=next(n for n in ast.walk(ast.parse(path.read_bytes())) if isinstance(n,ast.FunctionDef) and n.name=='command');text=textwrap.dedent(ast.get_source_segment(path.read_text(),node)).replace('nonlocal active','global active');receipts=[]
        space=dict(active=None,report={'commands':[]},save=lambda p,v:receipts.append(copy.deepcopy(v)),out=self.root,common=common,C=SimpleNamespace(need=M.require),env=dict(os.environ));exec(compile(text,str(path),'exec'),space);return space,receipts
    def test_cancel_after_constructor_return_is_deferred_until_owner_assignment(self):
        items=[]
        def cancelled(*a,**kw):
            item=M.LoggedProcess(*a,**kw);items.append(item);self.addCleanup(dispose,item.process)
            os.kill(os.getpid(),signal.SIGINT)
            return item
        space,receipts=self.command_fixture(SimpleNamespace(LoggedProcess=cancelled,registered_spawn=M.registered_spawn));previous=signal.signal(signal.SIGINT,signal.default_int_handler)
        try:
            with self.assertRaises(KeyboardInterrupt):space['command'](argv('import time;time.sleep(30)'),self.root/'cancel-register.log',2)
        finally:signal.signal(signal.SIGINT,previous)
        self.assertEqual(len(items),1);self.assertTrue(items[0].settled);self.assertTrue(items[0].retirement['leader_reaped']);self.assertEqual(items[0].observed_returncode,-signal.SIGKILL);self.assertEqual(receipts[-1]['commands'][0]['error_type'],'KeyboardInterrupt');self.assertTrue(receipts[-1]['commands'][0]['retirement']['leader_reaped']);self.assertIsNone(space['active'])
    def test_wait_entry_exception_uses_owned_finally_cleanup_and_preserves_primary(self):
        items=[];calls=[];real_wait=M.LoggedProcess.wait_owned
        def create(*a,**kw):
            item=M.LoggedProcess(*a,**kw);items.append(item);self.addCleanup(dispose,item.process);return item
        def interrupted(item,*a,**kw):
            calls.append((a,kw))
            if len(calls)==1:raise RuntimeError('cancelled before wait body')
            return real_wait(item,*a,**kw)
        space,receipts=self.command_fixture(SimpleNamespace(LoggedProcess=create,registered_spawn=M.registered_spawn))
        with patch.object(M.LoggedProcess,'wait_owned',interrupted),self.assertRaisesRegex(RuntimeError,'before wait body'):
            space['command'](argv('import time;time.sleep(30)'),self.root/'entry-interrupt.log',2)
        self.assertEqual(len(calls),2);self.assertEqual(calls[1],((0,),{'cleanup_timeout':5}));self.assertTrue(items[0].settled);self.assertTrue(items[0].retirement['leader_reaped']);self.assertEqual(items[0].observed_returncode,-signal.SIGKILL);self.assertEqual(receipts[-1]['commands'][0]['error_type'],'RuntimeError');self.assertIsNone(space['active'])
    def test_drain_has_no_mutating_process_api(self):
        node=next(n for n in ast.walk(ast.parse((SOURCE/'scripts/virtual/common.py').read_bytes())) if isinstance(n,ast.FunctionDef) and n.name=='drain')
        calls=[n for n in ast.walk(node) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
        self.assertFalse(any(n.func.attr in ('kill','killpg','wait','waitpid','poll') for n in calls))
if __name__=='__main__':unittest.main()
