#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/data controls only: no Docker/native/namespace/package actors."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).absolute().parents[2]
JOB_ENV={'GITHUB_RUN_ID':'123456','GITHUB_RUN_ATTEMPT':'1'}
DEV_PROFILE='cachy-asahi-p0-dev-123456-1'

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module; spec.loader.exec_module(module); return module

P=load('tested_native_preflight',ROOT/'scripts/install/native_preflight.py')
R=load('tested_native_receiver',ROOT/'scripts/install/native_arm_trial.py')
D=load('tested_p0_input_data',ROOT/'scripts/ci/development/p0_ci.py')
# Exact composed issuer fixture; the independently pinned assertion is below.
BASE=ROOT/P.HANDOFF


def inventory(raw):
    value=json.loads(raw)
    expected={row['name'][0]:row['version'][0] for row in value['rootfs_packages']}
    expected.update({row['name']:row['version'] for row in value['packages']})
    return ''.join(f'{name} {version}\n' for name,version in sorted(expected.items())).encode()


def record():
    return dict(schema_version=1,status='PASS_NATIVE_PREFLIGHT_ONLY',phase='complete',barrier='PASS',ABI='NOT_RUN',
        matrix='NOT_RUN',tests=1,failures=0,errors=0,skips=0,termination=False,owned_child_cleanup='PASS',first_failure='NONE')


class AuthorityControls(unittest.TestCase):
    def setUp(self):
        self.raw=BASE.read_bytes(); self.module=types.ModuleType('_published_issuer_model')
        self.module.__file__=str(BASE); exec(compile(self.raw,str(BASE),'exec'),self.module.__dict__)
    def test_published_issuer_source_authenticates_without_actors(self): P.issuer(self.module,self.raw)
    def test_changed_issuer_bytes_refuse(self):
        with self.assertRaisesRegex(ValueError,'ISSUER_PIN'): P.issuer(self.module,self.raw+b'\n')
    def test_rebound_issuer_method_refuses(self):
        self.module.Session.original_context=lambda *a,**k:{'status':'PASS'}
        with self.assertRaisesRegex(ValueError,'ISSUER_CODE'): P.issuer(self.module,self.raw)
    def test_changed_issuer_default_refuses(self):
        self.module.Sources.guard.__defaults__=(lambda:False,)
        with self.assertRaisesRegex(ValueError,'ISSUER_CODE'): P.issuer(self.module,self.raw)
    def test_changed_constant_refuses(self):
        self.module.FILE_LIMIT=1
        with self.assertRaisesRegex(ValueError,'ISSUER_CONSTANT'): P.issuer(self.module,self.raw)
    def test_foreign_import_refuses(self):
        self.module.sys=types.SimpleNamespace(_getframe=lambda:None)
        with self.assertRaisesRegex(ValueError,'ISSUER_IMPORT'): P.issuer(self.module,self.raw)
    def test_foreign_builtins_refuse(self):
        self.module.__builtins__={**vars(__builtins__)} if not isinstance(__builtins__,dict) else dict(__builtins__)
        self.module.__builtins__['len']=lambda _:0
        with self.assertRaisesRegex(ValueError,'ISSUER_BUILTINS'): P.issuer(self.module,self.raw)
    def test_receipt_cannot_be_live_owner(self):
        for fake in ({'status':'PASS'},types.SimpleNamespace(status='PASS',sources={'status':'PASS'})):
            with self.subTest(fake=type(fake)):
                with self.assertRaisesRegex(ValueError,'LIVE_OWNER_REQUIRED'): P.live(fake,object(),time.monotonic()+60)
    def test_same_name_foreign_class_cannot_be_owner(self):
        fake=types.ModuleType('development_repository_handoff'); fake.Session=type('Session',(),{})
        fake.Sources=type('Sources',(),{})
        obj=fake.Session(); obj.sources=fake.Sources(); obj.sources.raw={P.HANDOFF:self.raw,P.OWN:b'',P.RECEIVER:b''}
        with patch.dict(sys.modules,{'development_repository_handoff':fake}):
            with self.assertRaisesRegex((ValueError,AttributeError),'ISSUER_PIN|__file__'): P.live(obj,object(),time.monotonic()+60)
    def test_missing_registration_refuses_before_actors(self):
        self.module.__name__='development_repository_handoff'
        obj=object.__new__(self.module.Session); obj.sources=object.__new__(self.module.Sources); obj.sources.raw={}
        with patch.dict(sys.modules,{'development_repository_handoff':self.module}):
            with self.assertRaisesRegex(ValueError,'REGISTRATION_REQUIRED'): P.live(obj,object(),time.monotonic()+60)


class SelfNamespaceControls(unittest.TestCase):
    def setUp(self):
        self.raw=(ROOT/P.OWN).read_bytes(); self.pin=P.sha(self.raw)
        handoff=load('_self_namespace_captured_issuer',ROOT/P.HANDOFF)
        self.sources=object.__new__(handoff.Sources); self.sources.root=ROOT
        self.sources.original_root=None; self.sources.codes={}
        self.sources.raw={P.OWN:self.raw,P.HANDOFF:(ROOT/P.HANDOFF).read_bytes()}
        self.module=self.sources.module('_self_namespace_captured_bridge',P.OWN)
    def check(self): self.module.namespace(self.module,self.raw,self.pin)
    def test_actual_captured_loader_self_and_external_authenticate(self):
        self.sources.graph_namespace(self.module,P.OWN,{P.OWN:self.module},{},{})
        self.check(); P.namespace(self.module,self.raw,self.pin)
    def test_plain_captured_self_authenticates(self):
        plain=types.ModuleType('_plain_self_namespace'); plain.__file__=str(ROOT/P.OWN)
        exec(compile(self.raw,plain.__file__,'exec'),plain.__dict__)
        plain.namespace(plain,self.raw,self.pin)
    def test_code_contents_and_provenance_refuse(self):
        original=self.module.type_label; code=original.__code__
        changes=[{'co_code':code.co_code+b'\x00\x00'}, {'co_consts':code.co_consts+('foreign',)},
                 {'co_filename':code.co_filename+'.foreign'}, {'co_name':'foreign'},
                 {'co_qualname':'foreign'}, {'co_firstlineno':code.co_firstlineno+1},
                 {'co_linetable':code.co_linetable+b'\x00'},
                 {'co_exceptiontable':code.co_exceptiontable+b'\x00'},
                 {'co_argcount':code.co_argcount+1}, {'co_posonlyargcount':1},
                 {'co_kwonlyargcount':1}, {'co_stacksize':code.co_stacksize+1},
                 {'co_flags':code.co_flags^64}, {'co_names':code.co_names+('foreign',)},
                 {'co_varnames':('foreign',)+code.co_varnames[1:]},
                 {'co_cellvars':code.co_cellvars+('foreign',)},
                 {'co_nlocals':code.co_nlocals+1,'co_varnames':code.co_varnames+('foreign',)}]
        for change in changes:
            with self.subTest(field=next(iter(change))):
                original.__code__=code.replace(**change)
                try:
                    with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'): self.check()
                finally: original.__code__=code
        self.check()
    def test_slice_tuple_and_exact_numeric_constant_distinctions_refuse(self):
        for literal,replacement in (
            ("('slice', ('literal', 1), ('literal', 2), ('literal', 3))",slice(1,2,3)),
            ('True',1), ('0.0',-0.0), ("b'code'",'code'), ('(1,2)',frozenset((1,2))),
        ):
            raw=('def probe(): return '+literal+'\n').encode()
            module=types.ModuleType('_constant_shapes'); module.__file__=str(ROOT/P.OWN)
            exec(compile(raw,module.__file__,'exec'),module.__dict__)
            P.namespace(module,raw,P.sha(raw)); code=module.probe.__code__
            value=code.co_consts[-1]
            module.probe.__code__=code.replace(co_consts=tuple(replacement if item is value else item for item in code.co_consts))
            with self.subTest(literal=literal):
                with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'): P.namespace(module,raw,P.sha(raw))
    def test_foreign_code_constant_refuses_without_callbacks(self):
        calls=[]
        class Foreign:
            def __getattribute__(self,key): calls.append(key); raise RuntimeError('foreign getter')
            def __hash__(self): calls.append('hash'); raise RuntimeError('foreign hash')
            def __eq__(self,other): calls.append('equality'); raise RuntimeError('foreign equality')
        original=self.module.type_label; code=original.__code__
        original.__code__=code.replace(co_consts=code.co_consts+(Foreign(),))
        try:
            with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'): self.check()
        finally: original.__code__=code
        self.assertEqual(calls,[]); self.check()
    def test_nested_code_contents_refuse(self):
        original=self.module.namespace; code=original.__code__
        nested=next(c for c in code.co_consts if type(c) is types.CodeType)
        original.__code__=code.replace(co_consts=tuple(
            c.replace(co_consts=c.co_consts+('foreign',)) if c is nested else c for c in code.co_consts))
        try:
            with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'): self.check()
        finally: original.__code__=code
        original.__code__=code.replace(co_consts=tuple(
            c.replace(co_freevars=c.co_freevars+('foreign',)) if c is nested else c for c in code.co_consts))
        try:
            with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'): P.namespace(self.module,self.raw,self.pin)
        finally: original.__code__=code
        self.check()
    def test_foreign_globals_defaults_kwdefaults_and_closure_refuse(self):
        original=self.module.type_label
        def closed():
            foreign=True
            return lambda value: foreign
        for replacement in (types.FunctionType(original.__code__,{'__builtins__':__builtins__}),closed()):
            self.module.type_label=replacement
            try:
                with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'): self.check()
            finally: self.module.type_label=original
        for field,value in (('__defaults__',('foreign',)),('__kwdefaults__',{'foreign':True})):
            saved=getattr(original,field); setattr(original,field,value)
            try:
                with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'): self.check()
            finally: setattr(original,field,saved)
        self.check()


class DataControls(unittest.TestCase):
    def setUp(self):
        self.controller=types.SimpleNamespace(image='sha256:'+'a'*64,commit='b'*40)
        self.inputs=(ROOT/'scripts/ci/inputs.lock.json').read_bytes()
        self.packages=inventory(self.inputs)
        self.receiver=R
        self.assertEqual(P.sha(self.inputs),R.INPUTS_SHA)
        self.assertEqual(P.sha(self.packages),R.BASE_SHA)
        self.image={'Id':self.controller.image,'Architecture':'arm64','Os':'linux','Config':copy.deepcopy(P.CONFIG)}
    def test_exact_image_config_model(self):
        handoff=P.image_handoff([self.image],self.controller,self.receiver,self.inputs,self.packages)
        self.assertEqual(handoff['image_id'],self.controller.image)
    def test_only_reviewed_config_normalization(self):
        self.image['Config'].update(Entrypoint=[''],Labels=None)
        self.assertEqual(P.image_handoff([self.image],self.controller,self.receiver,self.inputs,self.packages)['Config']['Entrypoint'],[''])
    def test_foreign_image_or_architecture_refuses(self):
        for key,value in [('Id','sha256:'+'c'*64),('Architecture','amd64'),('Os','windows')]:
            with self.subTest(key=key):
                changed=copy.deepcopy(self.image);changed[key]=value
                with self.assertRaisesRegex(ValueError,'IMAGE_BINDING'): P.image_handoff([changed],self.controller,self.receiver,self.inputs,self.packages)
    def test_config_privilege_and_execution_substitutions_refuse(self):
        for key,value in [('User','0'),('Env',P.CONFIG['Env']+['LD_PRELOAD=x']),('Entrypoint',['/bin/sh']),('Volumes',{'/etc':{}}),('Labels',{'PASS':True})]:
            with self.subTest(key=key):
                changed=copy.deepcopy(self.image);changed['Config'][key]=value
                with self.assertRaisesRegex(ValueError,'IMAGE_CONFIG'): P.image_handoff([changed],self.controller,self.receiver,self.inputs,self.packages)
    def test_changed_input_or_inventory_refuses(self):
        for a,b in [(b'changed',self.packages),(self.inputs,b'changed')]:
            with self.assertRaisesRegex(ValueError,'IMAGE_BINDING'): P.image_handoff([self.image],self.controller,self.receiver,a,b)
    def test_selection_is_preflight_only_and_binds_exact_profile(self):
        sources=types.SimpleNamespace(raw={n:(ROOT/n).read_bytes() for n in P.SOURCE_PATHS})
        image=dict(Config=copy.deepcopy(P.CONFIG)); trial=P.selection(sources,self.controller,R,image,'d'*32)
        self.assertEqual(trial['phase'],'preflight'); self.assertEqual(trial['tool_profile_sha256'],P.PROFILE_SHA)
        self.assertEqual(trial['sources'][P.RECEIVER]['sha256'],P.RECEIVER_SHA)
    def test_nonce_refuses_before_constructor(self):
        with self.assertRaisesRegex(ValueError,'NONCE'): P.selection(None,None,R,{},'bad')
    def test_duplicate_json_and_nonfinite_refuse(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError): P.strict(raw)


class ContainerControls(unittest.TestCase):
    def setUp(self):
        self.cid='a'*64;self.name='cachy-asahi-install-'+'b'*32
        self.trial={'image_id':'sha256:'+'c'*64,'nonce':'b'*32}
        self.paths=(Path('/model/source'),Path('/model/inputs'),Path('/model/output'))
        self.row={'Id':self.cid,'Name':'/'+self.name,'Image':self.trial['image_id'],'AppArmorProfile':DEV_PROFILE,
            'Config':{'User':f'{os.getuid()}:{os.getgid()}','Entrypoint':['/usr/bin/python3'],
             'Cmd':['-I','-B','/source/scripts/install/native_arm_trial.py','--selection','/inputs/trial.json','--selection-sha256',P.sha(P.encoded(self.trial))],
             'Env':P.CONFIG['Env']+['CACHY_ASAHI_INSTALL_NONCE='+self.trial['nonce'],'CACHY_ASAHI_INSTALL_IMAGE='+self.trial['image_id']]},
            'HostConfig':dict(NetworkMode='none',CgroupnsMode='private',Privileged=False,ReadonlyRootfs=True,CapDrop=['ALL'],
                CapAdd=[],Devices=[],DeviceRequests=[],Memory=2*1024**3,NanoCpus=2*10**9,PidsLimit=128,
                SecurityOpt=['no-new-privileges','seccomp='+R.DEV_SECCOMP_BYTES.decode().rstrip('\n'),'apparmor='+DEV_PROFILE],Tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=512m,mode=1777'},
                PidMode='',IpcMode='private',UTSMode='',UsernsMode='',AutoRemove=False,
                RestartPolicy={'Name':'no','MaximumRetryCount':0}),
            'Mounts':[dict(Type='bind',Source=str(path),Destination=target,RW=rw,Propagation='rprivate')
                      for path,target,rw in zip(self.paths,('/source','/inputs','/out'),(False,False,True))]}
    def check(self,row):
        with patch.dict(os.environ,JOB_ENV): P.container_binding([row],self.cid,self.name,self.trial,*self.paths)
    def test_exact_created_container_model(self): self.check(self.row)
    def test_exact_dev_profile_and_policy_are_mandatory(self):
        for profile in ('docker-default','unconfined','cachy-asahi-p0-dev-123456-2',None):
            row=copy.deepcopy(self.row);row['AppArmorProfile']=profile
            with self.subTest(profile=profile),self.assertRaisesRegex(ValueError,'CONTAINER_BINDING'):self.check(row)
        for options in (['no-new-privileges'],['no-new-privileges','seccomp=unconfined','apparmor='+DEV_PROFILE],
                        self.row['HostConfig']['SecurityOpt'][:-1]+['apparmor=docker-default']):
            row=copy.deepcopy(self.row);row['HostConfig']['SecurityOpt']=options
            with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY'):self.check(row)
    def test_foreign_container_identity_refuses(self):
        for key,value in [('Id','d'*64),('Name','/foreign'),('Image','sha256:'+'d'*64)]:
            with self.subTest(key=key):
                row=copy.deepcopy(self.row);row[key]=value
                with self.assertRaisesRegex(ValueError,'CONTAINER_BINDING'): self.check(row)
    def test_privilege_network_and_resource_substitutions_refuse(self):
        for key,value in [('Privileged',True),('CapAdd',['SYS_ADMIN']),('SecurityOpt',['seccomp=unconfined']),
                          ('NetworkMode','host'),('CgroupnsMode','host'),('ReadonlyRootfs',False),('Memory',0),('PidsLimit',0),('Devices',[{}])]:
            with self.subTest(key=key):
                row=copy.deepcopy(self.row);row['HostConfig'][key]=value
                with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY'): self.check(row)
    def test_foreign_mount_and_writable_source_refuse(self):
        for key,value in [('Source','/'),('RW',True),('Propagation','rshared')]:
            with self.subTest(key=key):
                row=copy.deepcopy(self.row);row['Mounts'][0][key]=value
                with self.assertRaisesRegex(ValueError,'CONTAINER_MOUNTS'): self.check(row)
    def test_outerroot_and_foreign_execution_refuse(self):
        for key,value in [('User','0:0'),('Entrypoint',['/bin/sh']),('Cmd',['--matrix'])]:
            with self.subTest(key=key):
                row=copy.deepcopy(self.row);row['Config'][key]=value
                with self.assertRaisesRegex(ValueError,'CONTAINER_BINDING'): self.check(row)


class NamespaceLifecycleControls(unittest.TestCase):
    setUp=ContainerControls.setUp
    check=ContainerControls.check
    """Only new tests are collected; all old controls remain unchanged."""
    def test_documented_default_namespaces_and_disabled_lifecycle_accept(self): self.check(self.row)
    def test_host_namespace_or_sharing_substitutions_refuse(self):
        for key,value in [('PidMode','host'),('PidMode','container:foreign'),('PidMode','private'),
                          ('IpcMode','host'),('IpcMode','container:foreign'),('IpcMode','shareable'),
                          ('IpcMode',''),('IpcMode','none'),('UTSMode','host'),('UsernsMode','host')]:
            with self.subTest(key=key,value=value):
                row=copy.deepcopy(self.row);row['HostConfig'][key]=value
                with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY '+key):self.check(row)
    def test_missing_namespace_or_lifecycle_fact_refuses(self):
        for key in ('PidMode','IpcMode','UTSMode','UsernsMode','AutoRemove','RestartPolicy'):
            with self.subTest(key=key):
                row=copy.deepcopy(self.row);del row['HostConfig'][key]
                with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY '+key+':missing'):self.check(row)
    def test_wrong_types_are_not_empty_or_false_defaults(self):
        for key in ('PidMode','IpcMode','UTSMode','UsernsMode','AutoRemove','RestartPolicy'):
            for value in (None,False,0,[],{},''):
                if key!='RestartPolicy' and type(value) is type(self.row['HostConfig'][key]) and value==self.row['HostConfig'][key]:continue
                with self.subTest(key=key,value=value):
                    row=copy.deepcopy(self.row);row['HostConfig'][key]=value
                    with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY '+key):self.check(row)
    def test_auto_removal_and_restart_never_start(self):
        rows=[('AutoRemove',True),('AutoRemove',0),('RestartPolicy',{'Name':'always'}),
              ('RestartPolicy',{'Name':'unless-stopped','MaximumRetryCount':0}),
              ('RestartPolicy',{'Name':'on-failure','MaximumRetryCount':1}),
              ('RestartPolicy',{'Name':'','MaximumRetryCount':0}),
              ('RestartPolicy',{'Name':'no','MaximumRetryCount':False}),
              ('RestartPolicy',{'Name':'no','MaximumRetryCount':1}),
              ('RestartPolicy',{'Name':'no'}),('RestartPolicy',{'Name':'no','MaximumRetryCount':0,'extra':True})]
        for key,value in rows:
            with self.subTest(key=key,value=value):
                row=copy.deepcopy(self.row);row['HostConfig'][key]=value
                with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY '+key):self.check(row)
    def test_foreign_equal_types_do_not_supply_defaults(self):
        class ForeignString(str):pass
        class ForeignInt(int):pass
        class ForeignDict(dict):pass
        for key,value in [('PidMode',ForeignString('')),('IpcMode',ForeignString('private')),
                          ('UTSMode',ForeignString('')),('UsernsMode',ForeignString('')),
                          ('RestartPolicy',ForeignDict(Name='no',MaximumRetryCount=0)),
                          ('RestartPolicy',{'Name':ForeignString('no'),'MaximumRetryCount':0}),
                          ('RestartPolicy',{'Name':'no','MaximumRetryCount':ForeignInt(0)}),
                          ('RestartPolicy',{ForeignString('Name'):'no','MaximumRetryCount':0})]:
            with self.subTest(key=key,value=value):
                row=copy.deepcopy(self.row);row['HostConfig'][key]=value
                with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY '+key):self.check(row)
        row=copy.deepcopy(self.row);row['HostConfig'][ForeignString('PidMode')]=row['HostConfig'].pop('PidMode')
        with self.assertRaisesRegex(ValueError,'CONTAINER_INSPECT_SHAPE'):self.check(row)
    def test_nonobject_config_or_hostconfig_refuses(self):
        for key in ('Config','HostConfig'):
            for value in (None,[],False):
                with self.subTest(key=key,value=value):
                    row=copy.deepcopy(self.row);row[key]=value
                    with self.assertRaisesRegex(ValueError,'CONTAINER_INSPECT_SHAPE'):self.check(row)


class DiagnosticTypeControls(unittest.TestCase):
    setUp=ContainerControls.setUp
    check=ContainerControls.check
    def test_json_builtin_labels_preserve_normal_diagnostics(self):
        for value,label in ((None,'NoneType'),(False,'bool'),(0,'int'),(1.0,'float'),('', 'str'),([], 'list'),({},'dict')):
            with self.subTest(label=label):
                self.assertEqual(P.type_label(value),label)
                row=copy.deepcopy(self.row);row['HostConfig']['IpcMode']=value
                with self.assertRaisesRegex(ValueError,'^CONTAINER_POLICY IpcMode:'+label+'$'):self.check(row)
    def test_foreign_metaclass_getter_hash_and_equality_never_run(self):
        events=[]
        class Meta(type):
            def __getattribute__(self,key):
                events.append('getter');raise RuntimeError('getter trap')
            def __hash__(self):events.append('hash');raise RuntimeError('hash trap')
            def __eq__(self,other):events.append('equality');raise RuntimeError('equality trap')
        class Foreign(metaclass=Meta):pass
        value=Foreign()
        self.assertEqual(P.type_label(value),'UNKNOWN');self.assertEqual(events,[])
        for key in ('PidMode','IpcMode','UTSMode','UsernsMode','AutoRemove','RestartPolicy'):
            row=copy.deepcopy(self.row);row['HostConfig'][key]=value
            try:self.check(row)
            except ValueError as error:
                self.assertIs(type(error),ValueError)
                self.assertEqual(str(error),'CONTAINER_POLICY '+key+':UNKNOWN')
            else:self.fail('foreign policy value accepted')
        self.assertEqual(events,[])
    def test_config_metaclass_tripwire_keeps_controlled_refusal(self):
        events=[]
        class Meta(type):
            def __getattribute__(self,key):events.append('getter');raise RuntimeError('getter trap')
            def __hash__(self):events.append('hash');raise RuntimeError('hash trap')
            def __eq__(self,other):events.append('equality');raise RuntimeError('equality trap')
        class Foreign(metaclass=Meta):pass
        case=DataControls();case.setUp();case.image['Config']['ArgsEscaped']=Foreign()
        try:P.image_handoff([case.image],case.controller,case.receiver,case.inputs,case.packages)
        except ValueError as error:
            self.assertIs(type(error),ValueError);self.assertEqual(str(error),'IMAGE_CONFIG ArgsEscaped:UNKNOWN')
        else:self.fail('foreign Config accepted')
        self.assertEqual(events,[])
    def test_unknown_builtin_and_subclass_use_fixed_fallback(self):
        class ForeignString(str):pass
        for value in ((),b'opaque',set(),ForeignString('private'),object()):
            self.assertEqual(P.type_label(value),'UNKNOWN')
    def test_missing_facts_keep_exact_business_reason(self):
        for key in ('PidMode','IpcMode','UTSMode','UsernsMode','AutoRemove','RestartPolicy'):
            row=copy.deepcopy(self.row);del row['HostConfig'][key]
            with self.assertRaisesRegex(ValueError,'^CONTAINER_POLICY '+key+':missing$'):self.check(row)


class ResultControls(unittest.TestCase):
    def accepted(self,value=None,cleanup=None,end=None,exit_code=0):
        value=record() if value is None else value;raw=P.encoded(value)
        return P.accept({'exit_code':exit_code},raw,raw,R,cleanup or {'remove_exit':0,'absent':True},end or time.monotonic()+60)
    def test_complete_preflight_public_and_private_model(self): self.assertEqual(self.accepted()['tests'],1)
    def test_matrix_phase_never_accepted(self):
        value=record();value.update(status='PASS_NATIVE_FIXTURE_ONLY',ABI='PASS',matrix='PASS',tests=26)
        with self.assertRaisesRegex(ValueError,'P0_REFUSED'): self.accepted(value)
    def test_partial_phase_and_selfpass_refuse(self):
        for key,value in [('phase','preflight'),('tests',0),('barrier','NOT_RUN'),('owned_child_cleanup','UNKNOWN'),('termination',True),('skips',1)]:
            with self.subTest(key=key):
                changed=record();changed[key]=value
                with self.assertRaises(ValueError): self.accepted(changed)
    def test_cleanup_requires_remove_and_actual_absence(self):
        for row in ({'remove_exit':1,'absent':True},{'remove_exit':0,'absent':False},{'remove_exit':0,'absent':'PASS'},{'remove_exit':False,'absent':True},{'remove_exit':0,'absent':1}):
            with self.assertRaisesRegex(ValueError,'P0_REFUSED'): self.accepted(cleanup=row)
    def test_private_result_substitution_refuses(self):
        with self.assertRaisesRegex(ValueError,'RECEIVER_RESULT'):
            P.accept({'exit_code':0},P.encoded(record()),b'{}',R,{'remove_exit':0,'absent':True},time.monotonic()+60)
    def test_nonzero_launcher_exit_refuses(self):
        with self.assertRaisesRegex(ValueError,'P0_REFUSED'): self.accepted(exit_code=1)
    def test_expired_and_nonfinite_deadline_refuse(self):
        for end in (time.monotonic()-1,float('inf'),float('nan'),True):
            with self.subTest(end=end):
                with self.assertRaisesRegex(ValueError,'DEADLINE'): self.accepted(end=end)


class PipelineModels(unittest.TestCase):
    """Live grant and daemon events modeled explicitly; never actual owner authority."""
    def setUp(self):
        self.enterContext(patch.dict(os.environ,JOB_ENV))
        self.tmp=tempfile.TemporaryDirectory(prefix='native-preflight-model-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.source=self.root/'source';self.source.mkdir()
        self.native=self.root/'native';self.native.mkdir();self.view=self.root/'view';self.view.mkdir()
        self.output=self.root/'run';self.commands=[];self.mutation=None;self.closed=False;self.input_successor=None
        raw=(ROOT/'scripts/ci/inputs.lock.json').read_bytes();lock=json.loads(raw)
        expected={r['name'][0]:r['version'][0] for r in lock['rootfs_packages']}
        expected.update({r['name']:r['version'] for r in lock['packages']})
        packages=''.join(f'{name} {version}\n' for name,version in sorted(expected.items())).encode()
        self.assertEqual(P.sha(packages),R.BASE_SHA)
        (self.native/'inputs.lock.json').write_bytes(raw);(self.native/'packages.lock').write_bytes(packages)
        self.runtime=dict(cli_sha256='d'*64,endpoint_identity=[0]*6,env={})
        self.controller=types.SimpleNamespace(image='sha256:'+'c'*64,commit='b'*40,native_out=self.native)
        self.raw={n:(ROOT/n).read_bytes() for n in (P.OWN,*P.SOURCE_PATHS)};self.raw[P.HANDOFF]=BASE.read_bytes()
        model=self
        class Sources:
            root=model.source; raw=model.raw
            grant={'actor_contract_sha256':P.sha((json.dumps(model.runtime,sort_keys=True,indent=2)+'\n').encode())}
            def module(self,name,path):
                module=types.ModuleType(name);module.__file__=str(model.source/path)
                exec(compile(self.raw[path],module.__file__,'exec'),module.__dict__);return module
            def graph_namespace(self,*a): pass  # Modeled custody only.
        class CLI:
            def __init__(self,**kw):self.fd=3;self.env={}
            def _preflight(self): pass  # Modeled endpoint/CLI identity only.
            def close(self):model.closed=True
        def supervise(argv,**kw):
            args=argv[1:];model.commands.append((list(args),kw['deadline']))
            result={'exit_code':0,'stdout':b'','stderr':b''}
            if args[0]=='info':result['stdout']=P.encoded({'Architecture':'aarch64','OSType':'linux'})
            elif args[:2]==['image','inspect']:
                result['stdout']=P.encoded([dict(Id=model.controller.image,Architecture='arm64',Os='linux',Config=P.CONFIG)])
            elif args[0]=='create':
                cidfile=Path(args[args.index('--cidfile')+1]);cidfile.write_text('a'*64+'\n');result['stdout']=('a'*64+'\n').encode()
            elif args[:2]==['container','inspect']:
                case=ContainerControls();case.setUp();row=case.row
                trial=P.strict((model.output/'inputs/trial.json').read_bytes())
                row.update(Id='a'*64,Name='/cachy-asahi-install-'+'b'*32,Image=trial['image_id'])
                row['Config']['Cmd'][-1]=P.sha(P.encoded(trial))
                row['Mounts']=[dict(Type='bind',Source=str(p),Destination=t,RW=w,Propagation='rprivate')
                              for p,t,w in ((model.source,'/source',False),(model.output/'inputs','/inputs',False),
                                            (model.output/'child','/out',True))]
                if model.mutation in ('PidMode','IpcMode','UTSMode','UsernsMode'):row['HostConfig'][model.mutation]='host'
                elif model.mutation=='AutoRemove':row['HostConfig']['AutoRemove']=True
                elif model.mutation=='RestartPolicy':row['HostConfig']['RestartPolicy']={'Name':'always','MaximumRetryCount':0}
                result['stdout']=P.encoded([row])
                if model.mutation=='foreign-container':row['Image']='sha256:'+'e'*64;result['stdout']=P.encoded([row])
            elif args[0]=='start':
                if model.mutation=='actor-timeout':raise ValueError('modeled-actor-timeout')
                trial=P.strict((model.output/'inputs/trial.json').read_bytes());model.assertEqual(trial['phase'],'preflight')
                value=record()
                if model.input_successor is not None:
                    value.update(input_successor=R.validate_input_successor(model.input_successor),
                                 tool_profile_lineage=R.TOOL_PROFILE_LINEAGE)
                    if model.mutation=='current-result-lineage':value['tool_profile_lineage']='FRESH_CURRENT_AUDIT'
                    if model.mutation=='current-result-product':value['input_successor']['product']='foreign-product'
                result['stdout']=P.encoded(value);(model.output/'child/result.json').write_bytes(result['stdout'])
                if model.mutation=='actor-nonzero':result['exit_code']=1
            elif args[0]=='rm':
                if model.mutation=='remove-failed':result['exit_code']=1
            elif args[:2]==['container','ls']:
                if model.mutation=='still-present':result['stdout']=('a'*64+'\n').encode()
            else:raise AssertionError('unexpected modeled actor: '+str(args))
            return result,dict(direct_child_reaped=True,group_disposal_requested=True,forced_teardown=False,cancelled=False)
        self.session=types.SimpleNamespace(sources=Sources(),composition='installer-preflight',source_graph={
            'entry':None,'runtime':{'transport':types.SimpleNamespace(DockerTransport=CLI,supervise=supervise)},
            'collector':{},'phase':{},'original':{},'original_aliases':{},'native_preflight':P})
    def run_model(self):
        context={'root':self.view}
        if self.input_successor is not None:
            context.update(input_successor=R.validate_input_successor(self.input_successor),
                           inputs_raw=self.current_inputs,packages_raw=self.current_packages,
                           source_view_inputs_sha256=R.INPUTS_SHA)
        with patch.object(P,'live',return_value=context),patch.object(P.os,'uname',return_value=types.SimpleNamespace(machine='aarch64')):
            return P.run(self.session,self.controller,self.output,deadline=time.monotonic()+300,nonce='b'*32,runtime_contract=self.runtime)
    def test_model_causal_create_inspect_preflight_remove_absence(self):
        result=self.run_model();self.assertEqual(result['status'],'PASS');self.assertEqual(result['native_matrix'],'NOT RUN')
        self.assertEqual([r[0][0] for r in self.commands],['info','image','create','container','start','rm','container'])
        created=self.commands[2][0];self.assertIn('--cap-drop=ALL',created);self.assertNotIn('--privileged',created)
        trial=P.strict((self.output/'inputs/trial.json').read_bytes());self.assertEqual(trial['phase'],'preflight')
        self.assertTrue(self.closed);self.assertLessEqual(result['elapsed_seconds'],60)
        self.assertEqual(self.commands[-1][0][5],'id='+'a'*64)
    def test_foreign_created_container_refuses_before_native_start_but_cleans_owned_id(self):
        self.mutation='foreign-container'
        with self.assertRaisesRegex(ValueError,'CONTAINER_BINDING'):self.run_model()
        self.assertNotIn('start',[r[0][0] for r in self.commands]);self.assertTrue(self.closed)
        self.assertEqual(self.commands[-2][0],['rm','-f','a'*64])
    def test_failed_start_retains_cleanup_and_first_failure(self):
        self.mutation='actor-timeout'
        with self.assertRaisesRegex(ValueError,'modeled-actor-timeout'):self.run_model()
        self.assertEqual(self.commands[-2][0],['rm','-f','a'*64]);self.assertTrue(self.closed)
    def test_failed_daemon_cleanup_cannot_promote_child_pass(self):
        for mutation in ('remove-failed','still-present','actor-nonzero'):
            with self.subTest(mutation=mutation):
                # Each model needs a new output; no second actual-admission capability exists.
                self.output=self.root/('run-'+mutation);self.mutation=mutation
                with self.assertRaisesRegex(ValueError,'P0_REFUSED'):self.run_model()
    def test_namespace_lifecycle_substitution_refuses_before_start_and_removes_owned_id(self):
        for key in ('PidMode','IpcMode','UTSMode','UsernsMode','AutoRemove','RestartPolicy'):
            with self.subTest(key=key):
                self.output=self.root/('run-policy-'+key);self.mutation=key;self.commands=[]
                with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY '+key):self.run_model()
                self.assertNotIn('start',[r[0][0] for r in self.commands])
                self.assertEqual(self.commands[-2][0],['rm','-f','a'*64]);self.assertTrue(self.closed)
    def test_external_deadline_is_not_renewed_between_phases(self):
        started=time.monotonic();self.run_model()
        ends=[end for _,end in self.commands]
        self.assertLessEqual(max(ends),started+60.1)
        self.assertAlmostEqual(ends[0],ends[4]);self.assertAlmostEqual(ends[-1]-ends[0],10)


class LiveGraphBindingControls(unittest.TestCase):
    """Actual captured Session/Sources; stop before native context/frame admission."""
    COMPOSITION='installer-preflight'
    ADDITIONAL_SOURCES=(P.OWN,'scripts/install/test_native_preflight.py',*P.SOURCE_PATHS)
    @classmethod
    def setUpClass(cls):
        cls.fixture=load('_live_graph_fixture_builder',ROOT/'scripts/ci/development/test_repository_handoff.py')
        cls.fixture.CapturedGraphFixtures.setUpClass.__func__(cls)
    def check(self,*,end=None,returned=None):
        class BeforeNativeContext(BaseException): pass
        def trace(frame,event,arg):
            if event=='return' and frame.f_code is self.a.Sources.source_graph.__code__ and returned is not None:
                returned(arg)
            if event=='call' and frame.f_code is self.a.Session.original_context.__code__:
                raise BeforeNativeContext()
            return trace
        previous=sys.gettrace();sys.settrace(trace)
        try:
            with patch.dict(sys.modules,{'development_repository_handoff':self.a}):
                try:self.installer.live(self.session,object(),self.deadline if end is None else end)
                except BeforeNativeContext:return 'SOURCE_GATE_ONLY'
        finally:sys.settrace(previous)
        raise AssertionError('native admission must not complete in a source model')
    def test_selected_issuer_pin_and_captured_graph_reach_only_source_gate(self):
        self.assertEqual(P.ISSUER_SHA,'fea5348a93631157fa394ee12b9666ec54e2b667f5fc8f535a9aba9d634162db')
        self.assertEqual(P.sha(BASE.read_bytes()),P.ISSUER_SHA)
        self.assertEqual(self.check(),'SOURCE_GATE_ONLY')
        self.assertIsNone(self.session.native_consumer_observation)
        self.assertIsNone(self.session.result['initial_exit_code'])
    def test_legacy_composition_and_missing_or_wrong_selected_member_refuse(self):
        for value in ('repository-svg','installer',True):
            with patch.object(self.session,'composition',value):
                with self.assertRaises(ValueError):self.check()
        with patch.dict(self.session.source_graph):
            del self.session.source_graph['native_preflight']
            with self.assertRaises(ValueError):self.check()
        with patch.dict(self.session.source_graph,{'native_preflight':types.ModuleType('foreign')}):
            with self.assertRaises(ValueError):self.check()
    def test_returned_graph_missing_and_wrong_own_identity_refuse(self):
        for change in (lambda graph:graph.pop(P.OWN),lambda graph:graph.update({P.OWN:types.ModuleType('foreign')})):
            with self.assertRaisesRegex(ValueError,'^LIVE_GRAPH_REQUIRED$'):self.check(returned=change)
        self.assertEqual(self.check(),'SOURCE_GATE_ONLY')
    def test_returned_nonstring_key_and_foreign_composition_use_no_hooks(self):
        calls=[]
        class Foreign:
            def __eq__(self,other):calls.append('equality');raise RuntimeError('foreign equality')
            def __getattribute__(self,key):calls.append(key);raise RuntimeError('foreign getter')
        with patch.object(self.session,'composition',Foreign()):
            with self.assertRaises(ValueError):self.check()
        with self.assertRaisesRegex(ValueError,'^LIVE_GRAPH_REQUIRED$'):
            self.check(returned=lambda graph:graph.update({7:object()}))
        self.assertEqual(calls,[])
    def test_dict_subclasses_cannot_supply_graph_or_source_rows(self):
        calls=[]
        class ForeignDict(dict):
            def get(self,*args):calls.append('get');raise RuntimeError('foreign get')
            def __getitem__(self,key):calls.append('getitem');raise RuntimeError('foreign item')
            def __iter__(self):calls.append('iter');raise RuntimeError('foreign iter')
        for target,field in ((self.session,'source_graph'),(self.sources,'raw'),(self.sources,'grant')):
            with patch.object(target,field,ForeignDict()):
                with self.assertRaises(ValueError):self.check()
        self.assertEqual(calls,[])
    def test_ambient_registry_module_cannot_substitute_executing_namespace(self):
        with patch.dict(sys.modules,{'native_install_preflight':types.ModuleType('native_install_preflight')}):
            with self.assertRaisesRegex(ValueError,'^BRIDGE_NAMESPACE$'):self.check()
        self.assertEqual(self.check(),'SOURCE_GATE_ONLY')
    def test_wrong_session_source_classes_and_instance_method_shadow_refuse(self):
        class ForeignSession(type(self.session)): pass
        foreign=object.__new__(ForeignSession)
        with patch.dict(sys.modules,{'development_repository_handoff':self.a}):
            with self.assertRaisesRegex(ValueError,'^LIVE_OWNER_REQUIRED$'):
                self.installer.live(foreign,object(),self.deadline)
        calls=[]
        def trap(*args,**kwargs):calls.append('foreign method');raise RuntimeError('foreign method')
        with patch.object(self.sources,'class_state',trap,create=True):
            with self.assertRaises(ValueError):self.check()
        with patch.object(self.session,'sources',object()):
            with self.assertRaisesRegex(ValueError,'^LIVE_OWNER_REQUIRED$'):self.check()
        self.assertEqual(calls,[])
    def test_actual_issuer_source_method_default_and_globals_poison_refuse_before_graph(self):
        method=self.a.Sources.source_graph
        for replacement in (lambda *args,**kwargs:{P.OWN:self.installer},
                            types.FunctionType(method.__code__,{'__builtins__':__builtins__})):
            with patch.object(self.a.Sources,'source_graph',replacement):
                with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'):self.check()
        old=method.__kwdefaults__;method.__kwdefaults__={'capture':True}
        try:
            with self.assertRaisesRegex(ValueError,'^ISSUER_CODE$'):self.check()
        finally:method.__kwdefaults__=old
        self.assertEqual(self.check(),'SOURCE_GATE_ONLY')
    def test_expired_nonfinite_deadline_and_actual_guard_cancel_refuse(self):
        for end in (time.monotonic()-1,float('inf'),float('nan'),True):
            with self.assertRaisesRegex(ValueError,'^DEADLINE$'):self.check(end=end)
        first=KeyboardInterrupt('source-only cancellation')
        def cancelled():raise first
        with patch.object(self.session,'cancelled',cancelled):
            with self.assertRaises(KeyboardInterrupt) as caught:self.check()
        self.assertIs(caught.exception,first)
    def test_retained_bootstrap_pin_does_not_authenticate_selected_issuer(self):
        raw=BASE.read_bytes();module=types.ModuleType('_selected_b7');module.__file__=str(BASE)
        exec(compile(raw,str(BASE),'exec'),module.__dict__)
        with patch.object(P,'ISSUER_SHA','7202c974547c05ca8b7f0ad9772d4ac849d9d684d4105a979a3290e7d6622acb'):
            with self.assertRaisesRegex(ValueError,'^ISSUER_PIN$'):P.issuer(module,raw)


class CurrentDataControls(unittest.TestCase):
    """Real current/historical receiver guards; only public lock metadata is used."""
    def setUp(self):
        DataControls.setUp(self)
        self.selector=R.validate_input_successor(dict(R.P0_CURRENT_CONTRACT))
        self.current_inputs=D.current_inputs(self.inputs)
        self.current_packages=inventory(self.current_inputs)
        self.assertEqual(P.sha(self.current_inputs),'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
        self.assertEqual(P.sha(self.current_packages),'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25')
    def handoff(self,*,inputs=None,packages=None,selector=None):
        return P.image_handoff([self.image],self.controller,R,
            self.current_inputs if inputs is None else inputs,
            self.current_packages if packages is None else packages,
            input_successor=self.selector if selector is None else selector)
    def test_current_image_and_real_selection_bind_fixed_product_and_profile_lineage(self):
        image=self.handoff()
        sources=types.SimpleNamespace(raw={name:(ROOT/name).read_bytes() for name in P.SOURCE_PATHS})
        trial=P.selection(sources,self.controller,R,image,'d'*32,input_successor=self.selector)
        self.assertEqual(R.validate_selection(trial),trial)
        self.assertEqual(image['inputs_sha256'],self.selector['inputs_sha256'])
        self.assertEqual(image['packages_lock_sha256'],self.selector['packages_sha256'])
        self.assertEqual(image['input_successor'],self.selector)
        self.assertEqual(trial['input_successor'],self.selector)
        self.assertEqual(trial['tool_profile_lineage'],R.TOOL_PROFILE_LINEAGE)
        self.assertEqual(trial['phase'],'preflight')
        self.assertEqual(trial['sources'][P.RECEIVER]['sha256'],P.RECEIVER_SHA)
    def test_real_current_and_historical_pairs_require_their_own_selector(self):
        for inputs,packages in ((self.inputs,self.packages),(self.inputs,self.current_packages),
                                (self.current_inputs,self.packages)):
            with self.subTest(inputs=P.sha(inputs),packages=P.sha(packages)):
                with self.assertRaisesRegex(ValueError,'^IMAGE_BINDING$'):
                    self.handoff(inputs=inputs,packages=packages)
        with self.assertRaisesRegex(ValueError,'^IMAGE_BINDING$'):
            P.image_handoff([self.image],self.controller,R,self.current_inputs,self.current_packages)
        old=P.image_handoff([self.image],self.controller,R,self.inputs,self.packages)
        self.assertNotIn('input_successor',old)
        self.assertEqual(old['inputs_sha256'],R.INPUTS_SHA)
    def test_contract_exact_fields_types_and_values_refuse_before_handoff(self):
        for key,wanted in self.selector.items():
            for value in (None,True,False,'foreign',float(wanted) if type(wanted) is int else 0):
                if type(value) is type(wanted) and value==wanted:continue
                with self.subTest(key=key,kind=type(value).__name__):
                    with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):
                        self.handoff(selector={**self.selector,key:value})
            missing=dict(self.selector);del missing[key]
            with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):self.handoff(selector=missing)
        with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):self.handoff(selector={**self.selector,'foreign':1})
    def test_contract_foreign_keys_and_subclasses_use_no_hooks(self):
        events=[]
        class ForeignDict(dict):pass
        class ForeignInt(int):
            def __eq__(self,other):events.append('value-equality');raise AssertionError('foreign equality')
        class ForeignStr(str):
            def __eq__(self,other):events.append('value-equality');raise AssertionError('foreign equality')
        class Key(str):
            armed=False
            def __hash__(self):
                if self.armed:events.append('key-hash');raise AssertionError('foreign hash')
                return super().__hash__()
        key=Key('source_epoch');foreign={k:v for k,v in self.selector.items() if k!='source_epoch'}
        foreign[key]=self.selector['source_epoch'];key.armed=True
        cases=[ForeignDict(self.selector),foreign,{**self.selector,'packages':ForeignInt(341)},
               {**self.selector,'product':ForeignStr(self.selector['product'])},
               {**{k:v for k,v in self.selector.items() if k!='schema_version'},True:1}]
        for value in cases:
            with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):self.handoff(selector=value)
        self.assertEqual(events,[])
    def test_current_selection_refuses_matrix_relabeling_and_handoff_drift(self):
        image=self.handoff();sources=types.SimpleNamespace(raw={name:(ROOT/name).read_bytes() for name in P.SOURCE_PATHS})
        trial=P.selection(sources,self.controller,R,image,'d'*32,input_successor=self.selector)
        for patching in ({'phase':'matrix'},{'tool_profile_lineage':'FRESH_CURRENT_AUDIT'},
                         {'native_inputs_sha256':R.INPUTS_SHA},{'builder_packages_sha256':R.BASE_SHA}):
            with self.assertRaises(ValueError):R.validate_selection({**trial,**patching})
        for patching in ({'input_successor':{**self.selector,'schema_version':True}},
                         {'tool_profile_lineage':'FRESH_CURRENT_AUDIT'},
                         {'inputs_sha256':R.INPUTS_SHA},{'packages_lock_sha256':R.BASE_SHA}):
            with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):
                P.selection(sources,self.controller,R,{**image,**patching},'d'*32,input_successor=self.selector)
    def test_historical_tool_profile_is_held_and_contains_no_changed_vim_tools(self):
        profile=R.strict(R.PROFILE_BYTES)
        self.assertEqual(P.sha(R.PROFILE_BYTES),'b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8')
        self.assertEqual(profile['inputs_sha256'],R.INPUTS_SHA)
        self.assertEqual(len(profile['files']),136);self.assertEqual(len(profile['aliases']),137)
        self.assertFalse(any('vim' in (row['owner']+' '+row['path']).lower() for row in profile['files']))
        self.assertFalse(any('vim' in (key+value).lower() for key,value in profile['aliases'].items()))
        self.assertFalse(any('vim' in value.lower() for value in profile['roots']))
    def test_current_result_acceptance_cannot_inherit_historical_pass(self):
        value={**record(),'input_successor':dict(self.selector),'tool_profile_lineage':R.TOOL_PROFILE_LINEAGE}
        raw=R.public(value);end=time.monotonic()+60;cleanup={'remove_exit':0,'absent':True}
        self.assertEqual(P.accept({'exit_code':0},raw,raw,R,cleanup,end,input_successor=self.selector),value)
        old=R.public(record())
        with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):
            P.accept({'exit_code':0},old,old,R,cleanup,end,input_successor=self.selector)
        with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):
            P.accept({'exit_code':0},raw,raw,R,cleanup,end)
        for field,bad in (('tool_profile_lineage','FRESH_CURRENT_AUDIT'),('input_successor',{**self.selector,'packages':True})):
            badraw=P.encoded({**value,field:bad})
            with self.assertRaises(ValueError):P.accept({'exit_code':0},badraw,badraw,R,cleanup,end,input_successor=self.selector)


class CurrentPipelineModels(PipelineModels):
    """Actual bridge with modeled daemon/owner; no Docker or receiver actor runs."""
    def setUp(self):
        super().setUp()
        self.input_successor=R.validate_input_successor(dict(R.P0_CURRENT_CONTRACT))
        self.current_inputs=D.current_inputs((self.native/'inputs.lock.json').read_bytes())
        self.current_packages=inventory(self.current_inputs)
        (self.native/'inputs.lock.json').write_bytes(self.current_inputs)
        (self.native/'packages.lock').write_bytes(self.current_packages)
    def test_current_pipeline_evidence_binds_current_metadata(self):
        result=self.run_model()
        self.assertEqual(result['input_successor'],self.input_successor)
        self.assertEqual(result['receiver']['input_successor'],self.input_successor)
        self.assertEqual(result['receiver']['tool_profile_lineage'],R.TOOL_PROFILE_LINEAGE)
        self.assertEqual(P.strict((self.output/'inputs/image.json').read_bytes())['inputs_sha256'],self.input_successor['inputs_sha256'])
    def test_current_materialized_input_drift_refuses_before_container_creation(self):
        (self.native/'inputs.lock.json').write_bytes(b'foreign public metadata')
        with self.assertRaisesRegex(ValueError,'^INPUT_SUCCESSOR$'):self.run_model()
        self.assertNotIn('create',[row[0][0] for row in self.commands]);self.assertTrue(self.closed)
    def test_current_result_product_and_lineage_refuse_after_owned_cleanup(self):
        for mutation in ('current-result-lineage','current-result-product'):
            with self.subTest(mutation=mutation):
                self.output=self.root/mutation;self.commands=[];self.mutation=mutation
                with self.assertRaises(ValueError):self.run_model()
                self.assertEqual(self.commands[-2][0],['rm','-f','a'*64]);self.assertTrue(self.closed)


if __name__=='__main__': unittest.main()
