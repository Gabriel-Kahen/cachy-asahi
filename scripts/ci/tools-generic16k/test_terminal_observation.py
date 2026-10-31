# SPDX-License-Identifier: MIT
"""Mocked original PTY methods and bounded temporary evidence; never launch a shell or VM."""
import ast
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import substring_observer as O
import guest
import run as R

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'AGENTS.md').is_file())
FIXTURE=ROOT/'packages/tools/cachy-asahi-zsh-history-substring-search/check-module.py'
spec=importlib.util.spec_from_file_location('unchanged_original_substring',FIXTURE)
ORIGINAL=importlib.util.module_from_spec(spec);spec.loader.exec_module(ORIGINAL)


def point(returncode=None):
    if returncode is not None:return dict(status='ORIGINAL_ALREADY_REAPED',returncode=returncode)
    return dict(status='OBSERVED_UNREAPED_CHILD',returncode=None,waitid=None,uid=[23001]*4,gid=[23001]*4,cpu_limit=[10,10],
        proc=dict(pid=500,ppid=400,pgid=500,sid=500,state='S',utime=950,stime=49,start=7))


class Observation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name)/'coexist';self.home.mkdir()
        self.operations=[];ops=self.operations
        class Process:
            pid=500;returncode=None
            def poll(self):ops.append('original-poll');return self.returncode
            def wait(self,timeout):ops.append(('original-wait',timeout));self.returncode=-15;return -15
        class Parent:
            def __init__(self,zsh,home):self.process=Process();self.master=999999;self.output=bytearray()
            def read(self):return self.read_result
            wait=ORIGINAL.Terminal.wait
            close=ORIGINAL.Terminal.close
        self.module=SimpleNamespace(Terminal=Parent,noninteractive=lambda *a:dict(exit=0),main=lambda:7,
                                    interactive=ORIGINAL.interactive,limits=ORIGINAL.limits)
        self.original_main=self.module.main;self.original_limits=self.module.limits;self.original_interactive=self.module.interactive
        O.instrument(self.module,'a'*64)
        self.actor=patch.object(ORIGINAL.subprocess,'Popen',side_effect=AssertionError('actor forbidden'));self.actor.start();self.addCleanup(self.actor.stop)
        self.peek=patch.object(O,'peek',side_effect=lambda process,identity=None:point(process.returncode));self.peek.start();self.addCleanup(self.peek.stop)
        self.terminal=self.module.Terminal('/inert/zsh',self.home)

    def value(self):return json.loads((self.home/'terminal-exit.json').read_bytes())

    def close(self):
        real_close=os.close
        def close_fd(fd):
            if fd==999999:self.operations.append(('original-close-fd',fd))
            else:real_close(fd)
        with patch.object(ORIGINAL.os,'killpg',side_effect=lambda pid,sig:self.operations.append(('original-signal',pid,sig))),\
             patch.object(ORIGINAL.os,'close',side_effect=close_fd):
            self.terminal.close()

    def test_timeout_before_read_is_distinct_from_original_read_false(self):
        with patch.object(ORIGINAL.time,'monotonic',side_effect=[0,6]):
            with self.assertRaisesRegex(ValueError,'status=None'):self.terminal.wait(lambda:False)
        self.close();row=self.value()['events'][0]
        self.assertEqual(row['stage'],'WAIT_FAILURE_BEFORE_ORIGINAL_CLOSE');self.assertIsNone(row['original_read_return'])
        self.assertEqual(row['original_read_calls'],0);self.assertEqual(row['proc']['utime'],950)
        self.assertEqual(self.operations,['original-poll','original-poll',('original-signal',500,signal.SIGTERM),('original-wait',2),('original-close-fd',999999)])

    def test_original_read_false_preserved_and_no_extra_poll_or_reap(self):
        self.terminal.read_result=False
        with patch.object(ORIGINAL.time,'monotonic',side_effect=[0,1]):
            with self.assertRaisesRegex(ValueError,'status=None'):self.terminal.wait(lambda:False)
        self.close();row=self.value()['events'][0]
        self.assertIs(row['original_read_return'],False);self.assertEqual(row['original_read_calls'],1)
        self.assertEqual(self.operations.count('original-poll'),2)
        self.assertEqual(self.value()['events'][-1]['returncode'],-15)
        self.assertEqual(self.value()['events'][1]['returncode'],None)

    def test_original_main_limits_and_all_interactive_cases_are_same_functions(self):
        self.assertIs(self.module.main,self.original_main);self.assertIs(self.module.limits,self.original_limits)
        self.assertIs(self.module.interactive,self.original_interactive);self.assertEqual(O.sha(FIXTURE.read_bytes()),O.FIXTURE_SHA)
        self.assertEqual(O.CASES,guest.SUBSTRING_CASES)

    def test_success_keeps_original_close_order_and_no_failure_record(self):
        self.terminal.wait(lambda:True);self.close()
        self.assertEqual([r['stage'] for r in self.value()['events']],['BEFORE_ORIGINAL_CLOSE','AFTER_ORIGINAL_CLOSE'])
        self.assertEqual(self.operations,['original-poll',('original-signal',500,signal.SIGTERM),('original-wait',2),('original-close-fd',999999)])

    def test_original_timeout_escalation_signals_and_waits_are_unchanged(self):
        calls=[]
        def wait(timeout):
            self.operations.append(('original-wait',timeout));calls.append(timeout)
            if len(calls)==1:raise ORIGINAL.subprocess.TimeoutExpired('inert',timeout)
            self.terminal.process.returncode=-9;return -9
        self.terminal.process.wait=wait;self.close()
        self.assertEqual(self.operations,['original-poll',('original-signal',500,signal.SIGTERM),
            ('original-wait',2),('original-signal',500,signal.SIGKILL),('original-wait',2),('original-close-fd',999999)])
        self.assertEqual(self.value()['events'][-1]['returncode'],-9)

    def test_telemetry_failure_does_not_hide_original_wait_failure_or_close(self):
        error=ValueError('original predicate failure')
        with patch.object(O,'write',side_effect=OSError('fixture-only failure')):
            def predicate():raise error
            with self.assertRaises(ValueError) as caught:self.terminal.wait(predicate)
            self.close()
        self.assertIs(caught.exception,error);self.assertIn(('original-wait',2),self.operations)

    def test_noninteractive_original_called_once_with_same_arguments(self):
        work=Path(self.tmp.name);home=work/'noninteractive';home.mkdir()
        called=[];m=SimpleNamespace(Terminal=object,noninteractive=lambda *args:called.append(args) or dict(exit=0))
        O.instrument(m,'a'*64);self.assertEqual(m.noninteractive('z','w',work),dict(exit=0))
        self.assertEqual(called,[('z','w',work)]);v=json.loads((home/'terminal-exit.json').read_bytes())
        self.assertEqual(v['status'],'NO_PTY_ORIGINAL_NONINTERACTIVE_CASE');self.assertFalse(v['acceptance_credit'])

    def test_fixed_file_caps_and_aliases_refuse(self):
        with self.assertRaisesRegex(ValueError,'cap'):O.write(self.home/'terminal-exit.json',dict(pad='x'*3072))
        alias=self.home/'alias';alias.symlink_to(self.home/'terminal-exit.json')
        with self.assertRaises(ValueError):O.write(alias,{})
        os.link(self.home/'terminal-exit.json',self.home/'hardlink')
        with self.assertRaises(ValueError):O.write(self.home/'terminal-exit.json',{})

    def test_vm_entry_refuses_host_before_any_fixture_actor(self):
        with self.assertRaisesRegex(ValueError,'marked unprivileged16K VM'):O.main()

    def test_observer_source_has_no_poll_wait_reap_signal_budget_mutation(self):
        tree=ast.parse(Path(O.__file__).read_text());calls=[]
        for n in ast.walk(tree):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute):calls.append(n.func.attr)
        self.assertNotIn('poll',calls);self.assertNotIn('killpg',calls);self.assertNotIn('waitpid',calls)
        self.assertNotIn('setrlimit',calls);self.assertNotIn('prlimit',calls)
        self.assertIn('waitid',calls);self.assertIn('WNOWAIT',Path(O.__file__).read_text())
        self.assertLessEqual((self.home/'terminal-exit.json').stat().st_size,O.CAP)


class Peek(unittest.TestCase):
    def test_nonreaping_exit_and_exact_proc_identity_cpu_limits(self):
        fields=['S','400','500','500','0','0','0','0','0','0','0','950','49','0','0','0','0','1','0','7','1','1']
        stat_raw=('500 (zsh test) '+' '.join(fields)).encode()
        def bounded(path,cap):
            if str(path).endswith('/stat'):return stat_raw
            if str(path).endswith('/status'):return b'Uid:\t23001\t23001\t23001\t23001\nGid:\t23001\t23001\t23001\t23001\n'
            return b'Max cpu time              10                   10                   seconds\n'
        with patch.object(O,'bounded',side_effect=bounded),patch.object(O.os,'getpid',return_value=400),\
             patch.object(O.os,'getuid',return_value=23001),patch.object(O.os,'getgid',return_value=23001),\
             patch.object(O.os,'waitid',return_value=SimpleNamespace(si_pid=500,si_code=2,si_status=9)) as waitid:
            value=O.peek(SimpleNamespace(pid=500,returncode=None),7)
        self.assertEqual(value['status'],'OBSERVED_UNREAPED_CHILD');self.assertEqual(value['cpu_limit'],[10,10])
        self.assertEqual(value['proc']['utime']+value['proc']['stime'],999);self.assertEqual(value['waitid'],dict(code=2,status=9))
        waitid.assert_called_once_with(os.P_PID,500,os.WEXITED|os.WNOHANG|os.WNOWAIT)

    def test_original_reaped_pid_never_queried_again(self):
        with patch.object(O.os,'waitid',side_effect=AssertionError('reap forbidden')),patch.object(O,'bounded',side_effect=AssertionError('PID reuse query forbidden')):
            self.assertEqual(O.peek(SimpleNamespace(pid=500,returncode=-9)),dict(status='ORIGINAL_ALREADY_REAPED',returncode=-9))

    def test_not_our_child_is_unavailable_without_fallback_reaping(self):
        with patch.object(O.os,'waitid',side_effect=ChildProcessError()):
            self.assertEqual(O.peek(SimpleNamespace(pid=500,returncode=None))['status'],'UNAVAILABLE')


class Joins(unittest.TestCase):
    def setUp(self):
        self.receipt=dict(files={'fixtures/substring.py':dict(sha256=O.FIXTURE_SHA),
                                 'fixtures/substring_observer.py':dict(sha256='a'*64)})
        self.v=dict(schema_version=1,status='TERMINAL_OBSERVATION_ONLY',acceptance_credit=False,case='coexist',fixture_sha256=O.FIXTURE_SHA,
            observer_sha256='a'*64,observer_reaping='NONE',observer_signals='NONE',pid=500,parent_pid=400,uid=23001,gid=23001,clock_ticks=100,
            initial=dict(elapsed_ns=1,**point()),last_wait_before=dict(elapsed_ns=2,**point()),
            events=[dict(stage='BEFORE_ORIGINAL_CLOSE',elapsed_ns=3,**point()),dict(stage='AFTER_ORIGINAL_CLOSE',elapsed_ns=4,**point(-15))])

    def test_realistic_bounded_observation_validates_as_diagnostic_only(self):
        R.terminal_observation(self.v,'coexist',self.receipt)
        self.assertLess(len(json.dumps(self.v).encode()),3072)
        self.assertFalse(self.v['acceptance_credit'])

    def test_scope_source_identity_clock_and_pid_forgery_refused(self):
        for key,value in [('acceptance_credit',True),('fixture_sha256','0'*64),('observer_sha256','0'*64),('case','editing'),('uid',0),('clock_ticks',0),('observer_reaping','POLL')]:
            v=copy.deepcopy(self.v);v[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):R.terminal_observation(v,'coexist',self.receipt)
        v=copy.deepcopy(self.v);v['events'][0]['proc']['start']=8
        with self.assertRaisesRegex(ValueError,'starttime changed'):R.terminal_observation(v,'coexist',self.receipt)

    def test_original_cleanup_result_is_separate_from_preclose_exit_observation(self):
        self.v['events']=[dict(stage='WAIT_FAILURE_BEFORE_ORIGINAL_CLOSE',elapsed_ns=2,wait_elapsed_ns=5000000001,
            original_read_return=None,original_read_calls=0,error_type='ValueError',reason='original deadline',**point(-9)),
                          dict(stage='BEFORE_ORIGINAL_CLOSE',elapsed_ns=3,**point(-9)),
                          dict(stage='AFTER_ORIGINAL_CLOSE',elapsed_ns=4,**point(-9))]
        R.terminal_observation(self.v,'coexist',self.receipt)
        self.assertEqual(self.v['events'][0]['returncode'],-9);self.assertEqual(self.v['events'][-1]['returncode'],-9)
        v=copy.deepcopy(self.v);v['events'].reverse()
        with self.assertRaises(ValueError):R.terminal_observation(v,'coexist',self.receipt)


if __name__=='__main__':unittest.main(verbosity=2)
