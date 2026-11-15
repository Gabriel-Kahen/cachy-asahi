#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Negative fenced component DATA controls; no admitted operational fixture."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('operational role forbidden in LLVM v2 admission DATA control: '+event)


sys.addaudithook(fence)
s=importlib.util.spec_from_file_location('rust_llvm_v2_gate_DATA',HERE/'payload/admission.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)


def declaration():
    # Deliberately incomplete old material gates; no package or accepted Root role.
    llvm={k:None for k in g.LLVM_KEYS}
    llvm.update(source=dict(sha=g.LLVM_SOURCE,ref=g.IDENTITY['ref'],run=None,job=None),
        source_identity=copy.deepcopy(g.IDENTITY),policy=copy.deepcopy(g.POLICY),
        reader=dict(program=copy.deepcopy(g.READER_PROGRAM),binding=None,result=None))
    return llvm


def binding():
    # FENCED component shape only. Never serialized or paired with Root acceptance.
    return dict(source=g.LLVM_SOURCE,ref=g.IDENTITY['ref'],run='1',job='2',source_map_sha256=g.IDENTITY['map_sha256'],
        approval='a'*64,export_sha256='b'*64,image='sha256:'+'c'*64,operation=g.IDENTITY['operation'],scope='ROOT_AUTHENTICATED_LLVM23_DATA_READER_ONLY')


def component():
    llvm=declaration();llvm['source'].update(run='1',job='2');llvm['archive']=dict(bytes=123,sha256='d'*64)
    llvm['reader'].update(binding={'sha256':'e'*64},result={'sha256':'f'*64})
    return llvm


class Controls(unittest.TestCase):
    def test_publication_null_run_job_and_old_source_never_qualify(self):
        for sha,ref,run,job in ((g.LLVM_SOURCE,g.IDENTITY['ref'],None,None),
            (g.OLD_LLVM_SOURCE,g.IDENTITY['ref'],'1','2'),(g.LLVM_SOURCE,'refs/heads/codex/OLD','1','2')):
            value=declaration();value['source'].update(sha=sha,ref=ref,run=run,job=job)
            with self.subTest(sha=sha,ref=ref),self.assertRaises(ValueError):g.llvm_declaration(value)
    def test_exact_static_identity_policy_and_reader_bytes_refuse_drift(self):
        for group,key in (('source_identity','tree'),('source_identity','map_sha256'),('source_identity','profile_sha256'),
            ('source_identity','ref'),('policy','sha256'),('reader','program')):
            value=declaration()
            if group=='reader':value[group][key]={**g.READER_PROGRAM,'sha256':'0'*64}
            else:value[group][key]='FENCED-DRIFT'
            with self.subTest(group=group,key=key),self.assertRaises(ValueError):g.llvm_declaration(value)
        value=declaration();value['policy']['resources']['schema']=True
        with self.assertRaises(ValueError):g.llvm_declaration(value)
        self.assertFalse(g.same({'schema':True},{'schema':1}))
        value=declaration();value['source_identity']['files']=251.0
        with self.assertRaises(ValueError):g.llvm_declaration(value)
        value=declaration();value['policy']['resources']['work_volume_initialization']['cpus']=1.0
        with self.assertRaises(ValueError):g.llvm_declaration(value)
    def test_missing_new_keys_cannot_fall_back_to_legacy_shape(self):
        for key in g.EXTRA:
            value=declaration();del value[key]
            with self.subTest(key=key),self.assertRaises(ValueError):g.projection({'llvm':value})
        with self.assertRaises(ValueError):g.projection({'llvm':{k:None for k in g.LLVM_KEYS}})
    def test_projection_preserves_original_material_and_root_gates(self):
        a={'llvm':declaration(),'FENCED':'NON_OPERATIONAL'};held=copy.deepcopy(a);projected=g.projection(a)
        self.assertEqual(set(projected['llvm']),g.LLVM_KEYS)
        self.assertEqual(projected,{**a,'llvm':{k:v for k,v in a['llvm'].items() if k not in g.EXTRA}})
        self.assertEqual(a,held)
        with self.assertRaises(ValueError):g.validate(a,False)
    def test_false_check_mode_and_null_runtime_refuse_without_external_reads(self):
        template=HERE/'payload/root-admission.TEMPLATE.json'
        if template.exists():a=json.loads(template.read_bytes())
        else:
            a=json.loads((HERE.parent/'root-admission.TEMPLATE.json').read_bytes());a['llvm']=declaration()
        with patch.object(g,'read_file',side_effect=AssertionError('external read')),patch.object(g.BASE,'read_file',side_effect=AssertionError('external read')):
            for check in (False,True):
                with self.subTest(check=check),self.assertRaises(ValueError):g.validate(a,check)
        self.assertIsNone(a['source']['run']);self.assertIsNone(a['source']['job'])
    def test_reader_binding_rejects_wrong_source_policy_role_and_job(self):
        llvm=component()
        for key,value in (('source',g.OLD_LLVM_SOURCE),('ref','refs/heads/codex/OLD'),('run','9'),('job','9'),
            ('source_map_sha256','0'*64),('operation','llvm23-source-reference-native-v1'),('scope','UNAUTHENTICATED'),
            ('approval',None),('export_sha256',None),('image','unqualified')):
            with self.subTest(key=key),self.assertRaises(ValueError):g.reader_binding({**binding(),key:value},llvm)
        with self.assertRaises(ValueError):g.reader_binding({**binding(),'schema':True},llvm)
    def test_reader_result_rejects_mismatches_and_acceptance_promotion(self):
        llvm=component();b=binding()
        value=dict(schema=1,status='PASS_LLVM23_NATIVE_BUILD_DATA_PARITY_ONLY',source=b['source'],run=b['run'],job=b['job'],image=b['image'],
            package={k:llvm['archive'][k] for k in ('bytes','sha256')},payload_entries=1,native_acceptance=False,holds=g.READER_HOLDS,scope=g.READER_SCOPE)
        mutations=(('status','FAIL'),('source',g.OLD_LLVM_SOURCE),('run','9'),('job','9'),('image','sha256:'+'0'*64),
            ('package',dict(bytes=124,sha256='d'*64)),('package',dict(bytes=123.0,sha256='d'*64)),('payload_entries',True),('payload_entries',400001),('native_acceptance',True),
            ('native_acceptance',0),('holds','CLEARED'),('scope','NATIVE_ACCEPTED'))
        for key,other in mutations:
            with self.subTest(key=key,other=other),self.assertRaises(ValueError):g.reader_result({**value,key:other},b,llvm)
    def test_root_decision_requires_exact_v2_reader_and_policy_rejoin(self):
        llvm=component();b=binding();expected=dict(source_identity=copy.deepcopy(g.IDENTITY),policy=copy.deepcopy(g.POLICY),
            reader_program_sha256=g.READER_PROGRAM['sha256'],reader_binding_sha256='e'*64,reader_result_sha256='f'*64,reader_binding=b)
        for missing in (None,{},dict(llvm_v2={})):
            with self.assertRaises(ValueError):g.decision_rejoin(missing,b,llvm)
        for key in expected:
            changed=copy.deepcopy(expected);changed[key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):g.decision_rejoin({'llvm_v2':changed},b,llvm)
        changed=copy.deepcopy(expected);changed['reader_binding']['export_sha256']='0'*64
        with self.assertRaises(ValueError):g.decision_rejoin({'llvm_v2':changed},b,llvm)
    def test_v2_package_bound_preserves_source_policy(self):
        for size in (True,1.0,0,g.POLICY['resources']['package_bytes']+1):
            with self.subTest(size=size),self.assertRaises(ValueError):g.llvm_package_bound(size)
    def test_legacy_scope_image_stage0_and_test_signature_guards_remain_present(self):
        # Import pins the exact frozen body; new Source literal changes only in memory.
        self.assertEqual(g.BASE.LLVM_SOURCE,g.LLVM_SOURCE)
        self.assertEqual(g.BASE.INPUTS_SHA,g.INPUTS_SHA);self.assertEqual(g.BASE.PROPOSAL,g.PROPOSAL)
        for name in ('candidate_qualification','readonly_subpath','material_rows','original_join'):
            self.assertIs(getattr(g,name),getattr(g.BASE,name))
        self.assertIsNone(g.METADATA['actual']['root_acceptance'])
        self.assertIsNone(g.METADATA['actual']['reader'])


if __name__=='__main__':unittest.main()
