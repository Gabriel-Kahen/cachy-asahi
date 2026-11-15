#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable actor-fenced DATA controls; explicit complete Source69455 required."""
import argparse
import ast
from copy import deepcopy
import ctypes  # Initialize stdlib before fencing all subsequent ctypes actors.
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace as NS
import unittest

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--parent-source',type=Path,required=True)
ARGS=parser.parse_args()


def fence(event,args):
    if event.startswith(('subprocess.','os.exec','os.spawn','os.fork','socket.','ctypes.')) or event=='os.system':
        raise AssertionError('actor forbidden in context DATA controls: '+event)
sys.addaudithook(fence)


def data_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


C=data_module('_context_DATA_constructor',HERE/'prepare.py')
Q,P,OLD=C.constructors();BEFORE=P.snapshot(ARGS.parent_source);AFTER=C.transform(BEFORE,Q,P,OLD)
PROFILE=P.decode(C.read(HERE/'profile.json'));CHECKSUM=C.pin(C.read(HERE/'profile.json'))['sha256']
H=data_module('_held_namespace_DATA_fixtures',P.HERE/'test_preflight_data.py')
MAP='a'*64;TOKEN='b'*24;OPERATION='native-build-namespace-preflight-v1'
SOURCE=Path('/opt/native-'+OPERATION+'/source')


def functions(raw,names,extra=None):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name in names]
    C.need({n.name for n in nodes}==set(names),'all explicit pure DATA definitions')
    scope=dict(need=C.need,pin=C.pin,data_pin=C.pin,Path=Path,re=re,json=json,hashlib=hashlib,math=math,
               OPERATION=OPERATION,CASES=H.CASES,FRAME=H.FRAME,SOURCE=SOURCE)
    scope.update(extra or {});exec(compile(ast.Module(body=nodes,type_ignores=[]),'<selected-pure-DATA>','exec'),scope)
    return NS(**scope)


def guard(raw,message):
    calls=[n for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need'
           and len(n.args)==2 and isinstance(n.args[1],ast.Constant)and n.args[1].value==message]
    C.need(len(calls)==1,'one held context predicate');return compile(ast.Expression(calls[0].args[0]),'<pure-context-expression>','eval')


def context_scope(**changes):
    values=dict(machine='aarch64',uid=1001,euid=1001,gid=1001,egid=1001,alarm_uid=1001,alarm_gid=1001,pid=7,ppid=1,cwd='/tmp',baseline=b'genuine349\n')
    values.update(changes)
    class Paths:
        def __new__(cls,value):return Path(value)
        @staticmethod
        def cwd():return Path(values['cwd'])
    return dict(os=NS(uname=lambda:NS(machine=values['machine']),**{name:(lambda key=key:values[key])for name,key in
             [('getuid','uid'),('geteuid','euid'),('getgid','gid'),('getegid','egid'),('getpid','pid'),('getppid','ppid')]}),
                alarm=NS(pw_uid=values['alarm_uid'],pw_gid=values['alarm_gid']),Path=Paths,
                T=NS(ordinary=lambda path:values['baseline']),baseline=b'genuine349\n')


def frames(f,case,uid=1001,inside=True,tail=b''):
    raw=H.frames(f,case,inside);result=b''
    for line in raw.splitlines():
        value=json.loads(line[len(H.FRAME):]);context=value['context'];inner=value['phase']=='inner'
        for key in('uid','euid','gid','egid'):context[key]=0 if inner and case==H.CASES[1]else uid
        context['groups']=[uid]
        if inner and case==H.CASES[1]:context['maps']=dict(uid_map=[[0,uid,1]],gid_map=[[0,uid,1]])
        result+=H.FRAME+f.encoded(value)
    return result+tail


class ContextDataControls(unittest.TestCase):
    def test_complete_source_profile_and_six_leaf_inverse(self):
        after,_=C.compose(BEFORE,CHECKSUM);self.assertEqual(after,AFTER)
        self.assertEqual(C.facts(BEFORE,after,P),PROFILE);self.assertEqual(len(after),200)
        self.assertEqual({n for n in BEFORE if BEFORE[n]!=after[n]},C.CHANGED)
        self.assertEqual(sum(BEFORE[n]==after[n]for n in BEFORE),194)
        inverse=dict(after)
        for n in C.CHANGED:inverse[n]=BEFORE[n]
        self.assertEqual(inverse,BEFORE);self.assertEqual(P.tree(inverse),C.PARENT_TREE)
        with self.assertRaises(ValueError):C.compose(BEFORE,'0'*64)
        for name in('native/owner.py',C.ALPM,C.MAP):
            bad=dict(BEFORE);raw,mode=bad[name];bad[name]=(raw+b'\n',mode)
            with self.subTest(name=name),self.assertRaises(ValueError):C.transform(bad,Q,P,OLD)
        bad=dict(BEFORE);bad[C.ALPM]=(bad[C.ALPM][0],493)
        with self.assertRaises(ValueError):C.transform(bad,Q,P,OLD)

    def test_exact_retained_original1001_proof(self):
        value=C.evidence();self.assertEqual(value['proven_mismatch']['bootstrap_alarm_uid'],1001)
        self.assertEqual(value['proven_mismatch']['bootstrap_alarm_gid'],1001)
        self.assertEqual(value['proven_mismatch']['required_uid'],1000)  # The incorrect old diagnostic.
        self.assertEqual(value['mapped_bodies_verified'],87)
        dockerfile=C.read(HERE/'fixtures/bootstrap-Dockerfile.data')
        self.assertIn(b'groupmod -g 1001 alarm && usermod -u 1001 -g alarm alarm',dockerfile)
        log=C.read(HERE/'fixtures/tools-build-original.log.data')
        self.assertEqual(len(log),7503);self.assertEqual(C.pin(log)['sha256'],'5b8915fd1c9673f04dbec49dacce6d9b51b29fd1ab4c0b55e190277088a9e9da')
        self.assertIn(b'native original349 USER alarm RUN direct child of Bash PID1',log)

    def test_same1001_context_old_guard_fails_corrected_guard_passes(self):
        message='native original349 USER alarm RUN direct child of Bash PID1'
        self.assertFalse(eval(guard(BEFORE[C.ALPM][0],message),context_scope()))
        self.assertTrue(eval(guard(AFTER[C.ALPM][0],message),context_scope()))
        for key,value in [('machine','x86_64'),('uid',1000),('euid',0),('gid',1000),('egid',1002),
                          ('alarm_uid',1000),('alarm_gid',1000),('pid',1),('ppid',2),('cwd','/'),('baseline',b'changed349')]:
            with self.subTest(key=key):self.assertFalse(eval(guard(AFTER[C.ALPM][0],message),context_scope(**{key:value})))
        for uid in(0,999,1000,1002,65534):
            fields={key:uid for key in('uid','euid','gid','egid','alarm_uid','alarm_gid')}
            self.assertFalse(eval(guard(AFTER[C.ALPM][0],message),context_scope(**fields)))

    def test_private_home_owner_exact1001_and_mode_preserved(self):
        code=guard(AFTER[C.ALPM][0],'exact own diagnostic home')
        for uid,mode,alias,expected in[(1001,0o700,False,True),(1000,0o700,False,False),(1002,0o700,False,False),
                                       (1001,0o755,False,False),(1001,0o700,True,False)]:
            home=NS(is_symlink=lambda:alias,stat=lambda:NS(st_uid=uid,st_mode=stat.S_IFDIR|mode))
            self.assertIs(eval(code,dict(home=home,stat=stat)),expected)

    def test_namespace_and_mapped_root_effects_exact1001_match_reader(self):
        producer=functions(AFTER[C.TOOLS][0],H.PURE);reader=functions(AFTER[C.READER][0],H.PURE)
        for case in H.CASES:
            raw=frames(producer,case);expected=producer.namespace_outcome(raw,0,case,MAP,TOKEN)
            self.assertEqual(expected,reader.namespace_outcome(raw,0,case,MAP,TOKEN));self.assertEqual(expected['outcome'],'SUPPORTED')
            self.assertEqual(expected['policy_cause'],'UNKNOWN')
            for uid in(1000,1002):
                wrong=frames(producer,case,uid=uid)
                self.assertNotEqual(producer.namespace_outcome(wrong,0,case,MAP,TOKEN)['outcome'],'SUPPORTED')
                self.assertNotEqual(reader.namespace_outcome(wrong,0,case,MAP,TOKEN)['outcome'],'SUPPORTED')
            denied=frames(producer,case,inside=False,tail=b'Operation not permitted\n')
            self.assertEqual(producer.namespace_outcome(denied,1,case,MAP,TOKEN),reader.namespace_outcome(denied,1,case,MAP,TOKEN))
            self.assertEqual(reader.namespace_outcome(denied,1,case,MAP,TOKEN)['namespace_errno'],'UNKNOWN')
        raw=frames(producer,H.CASES[1]);wrong=raw.replace(b'[[0,1001,1]]',b'[[0,1000,1]]')
        self.assertNotEqual(reader.namespace_outcome(wrong,0,H.CASES[1],MAP,TOKEN)['outcome'],'SUPPORTED')

    def test_all_nonidentity_function_asts_and_identity_inverse_are_held(self):
        for name in(C.ALPM,C.TOOLS,C.READER,C.PROJECTION):
            original=BEFORE[name][0];changed=AFTER[name][0]
            if name in(C.READER,C.PROJECTION):
                for producer in(C.ALPM,C.TOOLS,C.CONTRACT):
                    changed=C.once(changed,C.pin(AFTER[producer][0])['sha256'].encode(),C.pin(BEFORE[producer][0])['sha256'].encode())
            for old,new in reversed(C.SEAMS.get(name,[])):changed=C.once(changed,new,old)
            self.assertEqual(changed,original,name)
        contract=P.decode(AFTER[C.CONTRACT][0]);old=P.decode(BEFORE[C.CONTRACT][0]);old.update(uid=1001,gid=1001)
        self.assertEqual(contract,old);self.assertFalse(contract['acceptance'])

    def test_dockerfile_original_domain_argv_and_bootstrap_unchanged(self):
        reader=functions(AFTER[C.READER][0],{'namespace_dockerfile'})
        expected=reader.namespace_dockerfile('native-developer-base:'+TOKEN,MAP,TOKEN)
        start=expected.index(b'COPY '+OPERATION.encode()+b'/source/');base=expected[:start].decode()+'USER alarm\nWORKDIR /tmp\n'
        tools=functions(AFTER[C.TOOLS][0],{'arguments'});tools.CASES=H.CASES;tools.OPERATION=OPERATION
        producer=functions(AFTER[C.ALPM][0],{'dockerfile'},dict(T=tools,STORE=SOURCE.parent/'evidence'))
        self.assertEqual(producer.dockerfile(base,MAP,dict(token=TOKEN)).encode(),expected)
        self.assertNotIn(b'groupmod',expected);self.assertNotIn(b'usermod',expected)
        self.assertIn(b'test \\"$BASHPID\\" -eq 1',expected)
        for name,func in[(C.ALPM,'dockerfile'),(C.READER,'namespace_dockerfile')]:
            def body(raw):return ast.dump(next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==func))
            self.assertEqual(body(BEFORE[name][0]),body(AFTER[name][0]))
        for name in('native/owner.py','native/image_lifecycle.py','bootstrap/scripts/ci/native_arm.py',
                     'native/build_tools_guest_v2.py','native/expected349.lock','native/invocation.json','.github/workflows/native-arm-build.yml'):
            self.assertEqual(AFTER[name],BEFORE[name],name)

    def test_producer_registry_map_privacy_and_resource_caps_held(self):
        for name in(C.READER,C.PROJECTION):
            node=next(n for n in ast.parse(AFTER[name][0]).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRODUCERS'for t in n.targets))
            registry=ast.literal_eval(node.value)
            for producer,digest in registry.items():self.assertEqual(C.pin(AFTER[producer][0])['sha256'],digest)
        mapping=P.decode(AFTER[C.MAP][0]);self.assertEqual(mapping['files'],{n:v for n,v in P.descriptors(AFTER).items()if n!=C.MAP})
        self.assertEqual(P.decode(AFTER[C.CONTRACT][0])['bounds'],P.decode(BEFORE[C.CONTRACT][0])['bounds'])
        raw=AFTER[C.PROJECTION][0].decode();old=BEFORE[C.PROJECTION][0].decode()
        self.assertEqual(next(x for x in raw.splitlines()if x.startswith('PRIVATE_MARKER=')),next(x for x in old.splitlines()if x.startswith('PRIVATE_MARKER=')))

    def test_actual_reference_keeps_same1001_account_and_only_identity_guard_changes(self):
        root=HERE/'reference-x86-1001';record=json.loads(C.read(root/'result.json'));raw=C.read(root/'build.log.data')
        self.assertEqual(C.pin(raw),record['log']);self.assertFalse(record['account_normalized']);self.assertFalse(record['native_acceptance'])
        before,after=record['observations'];self.assertFalse(before['identity_guard']);self.assertTrue(after['identity_guard'])
        for row in(before,after):
            for key in('uid','euid','gid','egid','alarm_uid','alarm_gid'):self.assertEqual(row[key],1001)
            self.assertEqual(row['machine'],'x86_64');self.assertGreater(row['pid'],1);self.assertEqual(row['ppid'],1);self.assertEqual(row['cwd'],'/tmp')
        dockerfile=C.read(root/'Dockerfile');self.assertNotIn(b'groupmod',dockerfile);self.assertNotIn(b'usermod',dockerfile)
        self.assertEqual(record['namespace_probes'],0);self.assertEqual(record['package_actors'],0);self.assertEqual(record['cap_add'],[])
        cleanup=json.loads(C.read(root/'cleanup.json'));self.assertTrue(cleanup['reference_images_absent']);self.assertTrue(cleanup['parent_base_preserved'])

    def test_null_future_selectors_missing_input_and_no_publication(self):
        self.assertEqual(PROFILE['actual'],dict(source=None,ref=None,run=None,job=None,artifact=None))
        self.assertEqual(PROFILE['alarm_identity']['uid'],1001);self.assertEqual(PROFILE['alarm_identity']['gid'],1001)
        self.assertFalse(PROFILE['alarm_identity']['account_mutation']);self.assertFalse(PROFILE['acceptance'])
        with self.assertRaises(FileNotFoundError):P.snapshot(Path('/MISSING-CONTEXT-PARENT-SOURCE'))


if __name__=='__main__':unittest.main(argv=[sys.argv[0]],verbosity=2)
