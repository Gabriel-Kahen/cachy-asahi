# SPDX-License-Identifier: MIT
"""Actor-fenced canonical Main adoption; approved selectors below are MODEL DATA."""
import argparse
import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[4]
FAMILY='scripts/ci/first-login-enrollment-native-source'
CANONICAL=FAMILY+'/payload/native/hosted_current_v3.py'
OPERAND=FAMILY+'/successor_v7_source/payload/hosted.py'
REGISTRY=FAMILY+'/successor_v7_source/program.json'
PIN=dict(bytes=68455,sha256='d491626c309a4b0f1fc198fa1cc8515d2412326d0e4fb9947332590d9de0132e')
LEGACY_PIN=dict(bytes=66263,sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97')
ACTORS=[]
SOURCE=PROFILE=None


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn','os.fork')) or event in ('os.system','fcntl.flock','resource.setrlimit'):
        ACTORS.append(event);raise AssertionError('canonical route DATA controls deny actor: '+event)


sys.addaudithook(fence)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


T=load('route_legacy_cascade_helpers',HERE.parents[1]/'successor_v6_source/test_trusted_cascade.py')
LEGACY=T.L
L=load('route_adopted_canonical_main',REPO/CANONICAL)
T.L=L


def prefix():
    tree=ast.parse((REPO/CANONICAL).read_bytes())
    function=copy.deepcopy(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='preflight'))
    stops=[i for i,n in enumerate(function.body)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)
        and any(isinstance(a,ast.Constant)and a.value=='actual hosted Source/ref/workflow/stage selectors before GET or privilege'for a in n.value.args)]
    if len(stops)!=1:raise ValueError('exact preactor hosted-selector boundary')
    function.name='canonical_data_prefix';function.body=function.body[:stops[0]+1]+[ast.parse('return H,d,root').body[0]]
    scope=dict(L.__dict__);exec(compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),'<actual-canonical-Main-DATA-prefix>','exec'),scope)
    return scope[function.name]


class Controls(unittest.TestCase):
    seal=T.Controls.seal
    def setUp(self):
        T.Controls.setUp(self)
        raw=(REPO/CANONICAL).read_bytes()
        self.files[CANONICAL]=raw;(self.main/CANONICAL).write_bytes(raw);self.seal()
        self.d['programs']['hosted_launcher']=dict(member=CANONICAL,**PIN)
        self.d['binding']['source_lock']=L.pin((self.root/'source-map.json').read_bytes())
        self.d['binding']['ref']='refs/heads/codex/MODEL-unissued-source205'
        self.d['hosted']['workflow_ref']='example/MODEL/'+T.WORKFLOW+'@'+self.d['binding']['ref']
    def tearDown(self):self.assertEqual(ACTORS,[])
    def test_canonical_adopts_exact_source205_body_and_legacy_is_immutable(self):
        raw=(REPO/CANONICAL).read_bytes();self.assertEqual(L.pin(raw),PIN)
        self.assertEqual(raw,(REPO/OPERAND).read_bytes())
        self.assertEqual(L.pin((HERE/'legacy/hosted_v6.py').read_bytes()),LEGACY_PIN)
        self.assertNotEqual(PIN,LEGACY_PIN)
    def test_current_canonical_model_selectors_pass_before_any_actor(self):
        _,checked,root=prefix()(*T.call_inputs(self.root,self.main,self.d))
        self.assertEqual(checked,self.d);self.assertEqual(root,self.root)
        self.assertFalse((self.base/('cachy-current-hosted-'+self.d['nonce'])).exists())
    def test_source196_launcher_pin_is_not_retargeted_to_new_main(self):
        args=list(T.call_inputs(self.root,self.main,self.d));args[0]['launcher']=dict(member=CANONICAL,**LEGACY_PIN)
        with self.assertRaisesRegex(ValueError,'whole-pinned Main launcher'):prefix()(*args)
    def test_unbound_source_main_body_or_workflow_selector_refuses_before_actor(self):
        for mode in ('source','ref','launcher','Main-body','workflow','attempt'):
            d=copy.deepcopy(self.d);args=list(T.call_inputs(self.root,self.main,d))
            if mode=='source':d['binding']['source']=None
            elif mode=='ref':d['binding']['ref']=None
            elif mode=='launcher':d['programs']['hosted_launcher']['sha256']='0'*64
            elif mode=='workflow':args[4]['GITHUB_WORKFLOW_SHA']='0'*40
            elif mode=='attempt':args[4]['GITHUB_RUN_ATTEMPT']='2'
            if mode in ('source','ref','launcher'):args=list(T.call_inputs(self.root,self.main,d))
            previous=(self.main/CANONICAL).read_bytes()
            if mode=='Main-body':(self.main/CANONICAL).write_bytes(b'FOREIGN')
            try:
                with self.subTest(mode=mode),self.assertRaises(ValueError):prefix()(*args)
            finally:(self.main/CANONICAL).write_bytes(previous)
    def test_main_reader_retains_only_finite_v2_transport_data(self):
        R=load('route_sealed_finite_reader',REPO/FAMILY/'payload/native/reader_current_v3.py')
        packet=dict(schema=2,kind='CURRENT_MATERIAL_STAGE_FAILURE_V2',phase='TRANSPORT_NATIVE248',reason='COMMAND_FAILED',command_ordinal=2,
            transport=dict(schema=1,kind='CURRENT_RETAINED_TRANSPORT_FAILURE_V1',phase='REQUIRED_BLOBS_FETCH',operation='GIT_FETCH_BLOBS',
                error_class='VALIDATION',errno=None,command_ordinal=7,git_exit=128,git_timeout=False,http_status=None))
        self.assertEqual(R.diagnostic_packet(packet),packet)
        for key,value in (('http_status',503),('error_text','FENCED_PRIVATE'),('operation','FENCED_PRIVATE')):
            bad=copy.deepcopy(packet);bad['transport'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):R.diagnostic_packet(bad)
    def test_registration_readback_once_and_code_templates_remain_unissued(self):
        C=load('route_complete_operand_templates',HERE/'contract.py')
        for name in ('registration','readback','once'):
            raw=(HERE/(name+'.TEMPLATE.json')).read_bytes();value=C.decode(raw)
            self.assertIsNone(value['issuer']);self.assertIsNone(value['approved'])
            self.assertIsNone(value['binding']);self.assertIsNone(value['observed_epoch'])
            if name=='registration':self.assertIsNone(value['workflow_id']);self.assertIsNone(value['state'])
            if name=='readback':self.assertIsNone(value['source']);self.assertIsNone(value['main'])
            if name=='once':self.assertIsNone(value['prior_run_ids']);self.assertIsNone(value['post_count'])
        code=C.decode((HERE/'request-code.contract.json').read_bytes())
        for name in ('source_cid','source_ref','main_cid','workflow_id','Root_authority','Root_acceptance'):
            self.assertIsNone(code[name])
        self.assertEqual(code['POSTs'],0);self.assertEqual(set(code['qualifier']['required_operands']),set(C.OPERANDS))


def genuine_cases(root,profile_path):
    class GenuineRoute(unittest.TestCase):
        def test_exact_source205_registry_and_canonical_main_join_with_model_authority(self):
            profile=L.decode(profile_path.read_bytes());program=L.decode((root/REGISTRY).read_bytes())
            self.assertEqual(profile['schema'],7);self.assertEqual(profile['transport_commit'],'9e26ce819a258225cac866341e15d7099038ab9e')
            self.assertEqual(profile['source_map'],dict(bytes=40793,sha256='a6d22a528075c11f6fa2e87d894c41e0ed31befcd17f99a8b92d6c26fccdb815'))
            self.assertEqual(program['roles']['hosted_launcher'],dict(member=CANONICAL,**PIN))
            self.assertEqual((root/CANONICAL).read_bytes(),(REPO/CANONICAL).read_bytes())
            self.assertTrue(all(v is None for v in profile['actual'].values()))
            policy_member=program['roles']['policy']['member'];policy=dict(L.decode((root/policy_member).read_bytes()),_member=policy_member)
            d=T.model_delegation(root,profile['delegation_programs'],dict(profile['materials'],**profile['staging_materials']),policy)
            d['binding']['ref']='refs/heads/codex/MODEL-unissued-source205'
            d['hosted']['workflow_ref']='example/MODEL/'+T.WORKFLOW+'@'+d['binding']['ref']
            with tempfile.TemporaryDirectory(prefix='MODEL-Source205-main-route-')as directory:
                main=Path(directory)/'MODEL-main';target=main/CANONICAL;target.parent.mkdir(parents=True);target.write_bytes((REPO/CANONICAL).read_bytes())
                _,checked,actual=prefix()(*T.call_inputs(root,main,d))
                self.assertEqual(checked,d);self.assertEqual(actual,root)
            self.assertTrue(all(v is None for v in L.decode(profile_path.read_bytes())['actual'].values()));self.assertEqual(ACTORS,[])
    return GenuineRoute


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--source-root',type=Path);parser.add_argument('--profile',type=Path)
    chosen,remaining=parser.parse_known_args()
    if bool(chosen.source_root)!=bool(chosen.profile):parser.error('explicit --source-root and --profile required together')
    if chosen.source_root is not None:globals()['GenuineRoute']=genuine_cases(chosen.source_root,chosen.profile)
    unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
