#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Exact-method preservation and finite inert dispatch models; no roles run."""
import copy
import importlib.util
import marshal
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bankstown_controller_tests',HERE/'controller.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
E,C=M.E,M.C

def baseline():
    raw=(M.SOURCE/M.HELD_MEMBER).read_bytes()
    module=types.ModuleType('bankstown_exact_executor_baseline')
    module.__file__=str(M.SOURCE/M.HELD_MEMBER)
    exec(compile(raw,str(M.SOURCE/M.HELD_MEMBER),'exec'),module.__dict__)
    return module

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='bankstown-controller-MODEL-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for obj,name in ((socket,'socket'),(subprocess,'Popen')):
            p=mock.patch.object(obj,name,side_effect=AssertionError('NO_ACTORS_OR_NETWORK'));p.start();self.addCleanup(p.stop)
    def test_all_maintained_method_bytecode_unchanged(self):
        original=baseline()
        self.assertEqual(C.pin((M.SOURCE/M.HELD_MEMBER).read_bytes()),M.HELD_PIN)
        for name in ('Controller','Executor','CommandEngine'):
            for key,value in vars(getattr(original,name)).items():
                other=vars(getattr(E,name))[key]
                if isinstance(value,types.FunctionType):
                    self.assertEqual(marshal.dumps(value.__code__),marshal.dumps(other.__code__),(name,key))
                elif isinstance(value,property):
                    self.assertEqual(marshal.dumps(value.fget.__code__),marshal.dumps(other.fget.__code__))
        for name in ('kernel_domain','check_domain','alive','service_args','stderr_buffer','runtime_capabilities','validate_policy','admitted_inputs'):
            self.assertEqual(marshal.dumps(getattr(original,name).__code__),marshal.dumps(getattr(E,name).__code__),name)
        self.assertEqual(E.__file__,str(HERE/'controller.py'))
        self.assertEqual(original.__file__,str(M.SOURCE/M.HELD_MEMBER))
        self.assertIs(E.context_contract,C.context_contract)
    def test_source_dispatch_requires_audio_kind_and_exact_context_body(self):
        raw=(HERE/'context.py').read_bytes()
        d=dict(schema=1,kind=C.DELEGATION,issuer='Root',programs={'context':dict(member='scripts/ci/bankstown-qt3-native-source/context.py',**C.pin(raw))})
        self.assertEqual(E.context_contract(d,program=C,source_root=M.SOURCE),1)
        bad=copy.deepcopy(d);bad['kind']='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'
        with self.assertRaises(ValueError):E.context_contract(bad)
        bad=copy.deepcopy(d);bad['programs']['context']['sha256']='0'*64
        with self.assertRaises(ValueError):E.context_contract(bad,program=C,source_root=M.SOURCE)
    def test_unchanged_execute_launches_new_owner_and_keeps_custody(self):
        obj=object.__new__(E.Controller);obj.root=self.root;obj.out=self.root
        (self.root/'volume').mkdir()
        obj.nonce='c'*64;obj.end=time.monotonic()+10;obj.cleanup_end=obj.end+10
        obj.c={'binding':{'source':'a'*40,'run':'123','job':'456','attempt':1},'stage':'qt3'}
        obj.d={'programs':{'image_executor':dict(member='controller.py',**C.pin((HERE/'controller.py').read_bytes()))}}
        obj.policy={'image_endpoint_template':'unix:///MODEL/{nonce}/volume/docker.sock','image_storage_bytes':1234}
        obj.p={'service_seconds':20,'owner_poll_seconds':5};obj.units={r:{'runtime_seconds':20} for r in ('owner','daemon')}
        obj.controller_domain={'pid':7};obj.tools={};obj.pidfds={'owner':77}
        obj.setup=lambda:({'pid':8},'MODEL_ENGINE');obj.tool=lambda name:'/usr/bin/'+name
        launched=[]
        obj.start=lambda role,argv:(launched.append((role,argv)) or {'pid':9})
        obj.show_unit=lambda name:dict(SubState='exited',ActiveState='active',Result='success',ExecMainCode='1',ExecMainStatus='0')
        obj.run=lambda argv,*args,**kwargs:b''
        result=dict(status='DELEGATED_OWNER_RETURNED_DATA_ONLY',binding=obj.c['binding'],Root_final_acceptance=None)
        writes=[]
        with mock.patch.object(E,'write_data',side_effect=lambda path,value,**kw:writes.append((path,value))),mock.patch.object(E,'alive',return_value=False),mock.patch.object(E,'read_data',return_value=E.encoded(result)):
            self.assertEqual(obj.execute({'MODEL':'input'}),result)
        self.assertEqual(launched[0][0],'owner')
        self.assertEqual(launched[0][1][1:5],['-I','-B',str(HERE/'controller.py'),'owner'])
        observation=writes[1][1]
        self.assertEqual(observation['engine_id'],'MODEL_ENGINE')
        self.assertEqual(observation['daemon_domain'],{'pid':8})
        self.assertTrue(observation['exclusive_daemon'])
        self.assertEqual(obj.pidfds,{'owner':77})
    def test_held_cleanup_stops_both_before_retention_and_failure_holds_storage(self):
        obj=object.__new__(E.Controller);obj.output_created=True;obj.out=self.root/'uncreated'
        obj.p={'cleanup_seconds':10};obj.cleanup_end=time.monotonic()+10;obj.pidfds={};obj.loop=None;obj.mounted=False
        events=[]
        obj.stop=lambda role:(events.append(role) or {'natural':True})
        obj.retain=lambda:events.append('retain')
        self.assertEqual(obj.cleanup()['errors'],[])
        self.assertEqual(events,['owner','daemon','retain'])
        events=[]
        def failed(role):
            events.append(role)
            if role=='owner':raise ValueError('MODEL stop refusal')
            return {'natural':True}
        obj.stop=failed
        self.assertTrue(obj.cleanup()['errors']);self.assertEqual(events,['owner','daemon'])
    def test_controller_request_pin_refuses_before_held_entry(self):
        request={'MODEL':'input'};d={'inputs_pin':C.pin(C.encoded(request))}
        args=types.SimpleNamespace(source_root=self.root,delegation=self.root/'d',context=self.root/'c',delegation_sha256='0'*64,inputs=self.root/'i')
        data={args.delegation:b'RAW_ROOT_MODEL',args.context:b'{}\n',args.inputs:C.encoded(request)}
        with mock.patch.object(E,'read_data',side_effect=lambda path:data[path]),mock.patch.object(E,'admitted_inputs',return_value=(d,None,None,None)),mock.patch.object(M,'_controller_main',return_value=17) as held:
            self.assertEqual(M.controller_main(args),17);held.assert_called_once()
            data[args.inputs]=C.encoded({'MODEL':'tampered'});held.reset_mock()
            with self.assertRaisesRegex(ValueError,'REQUEST_PIN'):M.controller_main(args)
            held.assert_not_called()
    def test_owner_request_pin_refuses_before_held_entry(self):
        request={'MODEL':'input'};d={'inputs_pin':C.pin(C.encoded(request))}
        launch={'source_root':str(self.root),'delegation':{},'context':{'delegation_pin':{'sha256':'0'*64}},'inputs':request}
        with mock.patch.object(E,'read_data',side_effect=lambda path:C.encoded(launch)),mock.patch.object(E,'admitted_inputs',return_value=(d,None,None,None)),mock.patch.object(M,'_owner_main',return_value=19) as held:
            self.assertEqual(M.owner_main(self.root/'launch'),19);held.assert_called_once()
            launch['inputs']={'MODEL':'tampered'};held.reset_mock()
            with self.assertRaisesRegex(ValueError,'REQUEST_PIN'):M.owner_main(self.root/'launch')
            held.assert_not_called()
    def test_policy_guard_remains_real_and_not_relaxed(self):
        with self.assertRaises((ValueError,KeyError)):E.validate_policy({}, {'capability':{}})
        self.assertIs(E.controller_main,M.controller_main);self.assertIs(E.owner_main,M.owner_main)

if __name__=='__main__':unittest.main()
