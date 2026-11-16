# SPDX-License-Identifier: MIT
"""Exercise real held Commands.run with modeled process/core/signal boundaries."""
from contextlib import ExitStack
import copy
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in (
            'os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('local invocation DATA controls forbid '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


O=load('fenced_local_invocation_owner',HERE/'owner_delegated_v3.py')
WORKFLOW=HERE.parents[4]/'scripts/workflows/developer_workflow.py'
REAL_POPEN=subprocess.Popen
REAL_SIGNAL=signal.signal


class Clock:
    now=100.0
    def monotonic(self):return self.now


class Signals:
    SIGINT=2
    SIGTERM=15
    def __init__(self):self.handlers={2:'OLD_INT',15:'OLD_TERM'};self.calls=[]
    def signal(self,number,handler):
        old=self.handlers[number];self.handlers[number]=handler;self.calls.append((number,handler));return old


def result(expected):
    return dict(output=b'FENCED ACTUAL CORE OUTPUT\n',reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',
                output_complete=True,timeout=False,signals=[],error=None,exit=expected,seconds=.01,passed=expected==0)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fenced-local-invocation-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.output=self.root/'commands';self.output.mkdir()
        self.W=load('fenced_real_workflow_'+self.id().split('.')[-1],WORKFLOW)
        self.assertEqual(O.pin(WORKFLOW.read_bytes())['sha256'],'531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba')
        self.held_run=self.W.Commands.run;self.clock=Clock();self.signals=Signals();self.launches=[];self.forwarded=[];self.before_delegate=[]
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(O,'time',self.clock))
        self.stack.enter_context(patch.object(self.W,'time',self.clock))
        self.stack.enter_context(patch.object(self.W,'signal',self.signals))
        def popen(argv,**kwargs):
            child=SimpleNamespace(pid=424242,returncode=None);self.launches.append((argv,kwargs,child));return child
        self.stack.enter_context(patch.object(self.W,'subprocess',SimpleNamespace(Popen=popen,DEVNULL=-3,PIPE=-1,STDOUT=-2)))
    def model(self,expected=0,mode=None,change=None):
        test=self;self.step='no-agent-private-0' if expected==2 else 'fenced-command'
        self.argv=['/usr/bin/gpg-connect-agent','--homedir','/tmp/FENCED/trust','--no-autostart','/bye'] if expected==2 else ['/usr/bin/NEVER_EXECUTED','FENCED']
        self.core_result=result(expected)
        if change:self.core_result.update(change)
        class Core:
            def prepare(inner):
                if mode=='missing-hook':test.commands.core=inner
            def supervise(inner,child,**kwargs):
                test.assertIs(child,test.launches[-1][2]);test.forwarded.append(dict(kwargs))
                request_path=test.output/(test.step+'.invocation-request.json')
                supervision_path=test.output/(test.step+'.supervision-request.json')
                request=json.loads(request_path.read_bytes())
                if mode!='missing-hook':
                    supervision=json.loads(supervision_path.read_bytes())
                    test.assertEqual(supervision['request_pin'],O.pin(request_path.read_bytes()))
                    test.assertEqual({k:supervision[k] for k in ('cap_seconds','retirement_seconds','grace_seconds','max_output_bytes')},
                                     dict(cap_seconds=kwargs['cap'],retirement_seconds=kwargs['retirement'],grace_seconds=kwargs['grace'],max_output_bytes=kwargs['max_output']))
                    test.before_delegate.append((copy.deepcopy(request),copy.deepcopy(supervision)))
                return copy.deepcopy(test.core_result)
        self.core=Core();self.stack.enter_context(patch.object(self.W,'load_core',return_value=self.core))
        namespace=O.observed_local_workflow(self.W)
        self.commands=namespace.Commands(self.output,self.root/'home','/usr/bin:/bin',timeout=15,total=30,max_output=4096)
        self.clock.now=118.25  # Actual held remaining budget is 11.75, not timeout15.
        return self.commands
    def invoke(self,expected=0):return self.commands.run(self.step,self.argv,self.root,expected)
    def assert_links(self,row):
        proof=row['local_invocation_v1'];request_raw=(self.output/(self.step+'.invocation-request.json')).read_bytes()
        supervision_raw=(self.output/(self.step+'.supervision-request.json')).read_bytes()
        def public_fields(value):
            if type(value)is dict:
                self.assertFalse({'argv','cwd'}&set(value))
                for item in value.values():public_fields(item)
            elif type(value)is list:
                for item in value:public_fields(item)
        public_fields(proof)
        self.assertEqual(proof['schema'],1);self.assertEqual(proof['kind'],'DELEGATED_LOCAL_COMMAND_INVOCATION_V1')
        self.assertEqual(proof['request'],json.loads(request_raw));self.assertEqual(proof['request_pin'],O.pin(request_raw))
        self.assertEqual(proof['supervision_request'],json.loads(supervision_raw));self.assertEqual(proof['supervision_request_pin'],O.pin(supervision_raw))
        self.assertEqual(proof['held_receipt_pin'],O.pin(O.encoded(row['held_receipt'])))
        self.assertEqual(proof['supervision_result_pin'],O.pin(O.encoded(row['held_receipt']['supervision'])))
        for key in row['held_receipt']:self.assertEqual(row[key],row['held_receipt'][key])
        self.assertEqual(json.loads((self.output/'commands.json').read_bytes()),self.commands.records)
    def test_actual_held_run_captures_before_delegate_and_preserves_original_row(self):
        self.model();out=self.invoke();row=self.commands.records[-1]
        self.assertEqual(out,self.core_result['output']);self.assertEqual(len(self.before_delegate),1)
        self.assertEqual(self.forwarded,[dict(cap=11.75,retirement=1,grace=.2,max_output=4096)])
        self.assertEqual(row['timeout_seconds'],15);self.assertEqual(row['supervision_cap_seconds'],11.75)
        self.assertEqual((row['retirement_seconds'],row['grace_seconds'],row['max_output_bytes']),(1,.2,4096))
        self.assert_links(row);self.assertIs(self.commands.core,self.core);self.assertIs(self.W.Commands.run,self.held_run)
        self.assertEqual(self.signals.handlers,{2:'OLD_INT',15:'OLD_TERM'})
        self.assertIs(subprocess.Popen,REAL_POPEN);self.assertIs(signal.signal,REAL_SIGNAL)
        argv,kwargs,_=self.launches[0];self.assertEqual(argv,self.argv)
        self.assertTrue(kwargs['start_new_session']);self.assertEqual((kwargs['stdin'],kwargs['stdout'],kwargs['stderr']),(-3,-1,-2))
    def test_expected_two_keeps_original_passed_false_and_genuine_success(self):
        self.model(expected=2);self.invoke(2);row=self.commands.records[-1]
        self.assertEqual(row['expected'],2);self.assertTrue(row['success']);self.assertEqual(row['supervision']['exit'],2)
        self.assertIs(row['supervision']['passed'],False);self.assertIs(row['held_receipt']['supervision']['passed'],False)
        self.assert_links(row)
    def test_missing_supervise_hook_refuses_and_restores_original_core(self):
        self.model(mode='missing-hook')
        with self.assertRaisesRegex(ValueError,'supervision'):self.invoke()
        self.assertIs(self.commands.core,self.core);self.assertEqual(len(self.forwarded),1)
        self.assertNotIn('local_invocation_v1',self.commands.records[-1])
    def test_post_delegate_result_mutation_cannot_gain_joined_invocation(self):
        self.model();save=self.W.save
        def mutate(path,rows):
            save(path,rows);rows[-1]['supervision']['seconds']=.02
        with patch.object(self.W,'save',mutate),self.assertRaisesRegex(ValueError,'index|join'):self.invoke()
        self.assertIs(self.commands.core,self.core);self.assertNotIn('local_invocation_v1',self.commands.records[-1])
    def test_original_held_index_tampering_on_disk_refuses(self):
        self.model();save=self.W.save
        def mutate(path,rows):
            save(path,rows);altered=json.loads(Path(path).read_bytes());altered[-1]['expected']=1
            Path(path).write_bytes(O.encoded(altered))
        with patch.object(self.W,'save',mutate),self.assertRaisesRegex(ValueError,'index'):self.invoke()
        self.assertIs(self.commands.core,self.core);self.assertNotIn('local_invocation_v1',self.commands.records[-1])
    def test_changed_persisted_request_pin_refuses(self):
        self.model();save=self.W.save
        def mutate(path,rows):
            save(path,rows)
            request=self.output/(self.step+'.invocation-request.json');value=json.loads(request.read_bytes());value['timeout_seconds']=99
            request.write_bytes(O.encoded(value))
        with patch.object(self.W,'save',mutate),self.assertRaises((ValueError,OSError)):self.invoke()
    def test_changed_persisted_supervision_request_pin_refuses(self):
        self.model();save=self.W.save
        def mutate(path,rows):
            save(path,rows)
            request=self.output/(self.step+'.supervision-request.json');value=json.loads(request.read_bytes());value['cap_seconds']=99
            request.write_bytes(O.encoded(value))
        with patch.object(self.W,'save',mutate),self.assertRaises((ValueError,OSError)):self.invoke()
    def test_nonnatural_and_wrong_expected_exit_never_gain_success_proof(self):
        for name,change in (('forced',{'signals':[15]}),('timeout',{'timeout':True}),('unknown',{'ownership':'UNKNOWN'}),
                            ('wrong-exit',{'exit':1}),('late',{'seconds':12}),('emergency',{'emergency_retirement':True}),('invalid-passed',{'passed':None})):
            with self.subTest(name=name):
                self.output=self.root/name;self.output.mkdir();self.clock.now=100;self.model(change=change)
                with self.assertRaises(ValueError):self.invoke()
                self.assertIs(self.commands.core,self.core)
                if self.commands.records:self.assertNotIn('local_invocation_v1',self.commands.records[-1])
    def test_refusals_do_not_create_model_child_or_supervisor_call(self):
        self.model()
        for step,argv,expected in (('bad/name',self.argv,0),(self.step,self.argv,False),('other',self.argv,2),
                                   ('no-agent-private-1',['/usr/bin/false'],2)):
            with self.subTest(step=step,expected=expected),self.assertRaises(ValueError):self.commands.run(step,argv,self.root,expected)
        self.assertFalse(self.launches);self.assertFalse(self.forwarded)
        self.commands.timeout=float('inf')
        with self.assertRaises(ValueError):self.invoke()
        self.assertFalse(self.launches)


if __name__=='__main__':unittest.main(verbosity=2)
