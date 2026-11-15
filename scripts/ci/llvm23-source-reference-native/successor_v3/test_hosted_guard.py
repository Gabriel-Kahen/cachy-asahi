#!/usr/bin/env python3
"""Actual hosted guards over modeled DATA; no Git/network/actor process runs."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import math
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
PREVIOUS=None
CORRECTED=None
SOURCE='f'*40
REF='refs/heads/codex/FIXTURE-hosted-guard-DATA-NOT-A-ROOT-ADMISSION'
V2='.github/workflows/native-arm-llvm23-source-reference-v2.yml'
V1='.github/workflows/native-arm-llvm23-source-reference-v1.yml'


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn')) or event in ('os.system','os.fork','os.forkpty'):
        raise AssertionError('hosted guard DATA fence: '+event)


def selected(raw,names,namespace,constants=()):
    """Compile only named DATA definitions; never execute module imports/top level."""
    tree=ast.parse(raw)
    nodes=[]
    found=set()
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name in names:
            nodes.append(node);found.add(node.name)
        elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in constants:
            nodes.append(node);found.add(node.targets[0].id)
    if found!=set(names)|set(constants):raise AssertionError('exact named guard definitions required')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<selected actual DATA guards>','exec'),namespace)
    return namespace


class HostedGuardControls(unittest.TestCase):
    def setUp(self):
        if CORRECTED is None:raise AssertionError('explicit --parent-source CLI is required')
        self.tmp=tempfile.TemporaryDirectory(prefix='llvm23-guard-FIXTURE-DATA-')
        self.addCleanup(self.tmp.cleanup)
        self.parent=Path(self.tmp.name);self.parent.chmod(0o700)
        self.root=self.parent/'source';self.root.mkdir(mode=0o700)
        self.work=self.parent/'proof-output'
        self.calls=[];self.git_fault=None
        for name in ('candidate-map.json','policy.json','hosted/common.py','hosted/entry.py',
                     '.github/workflows/native-arm-build.yml',V2):
            body,mode=CORRECTED[name]
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(body);path.chmod(mode)
        ns={'__builtins__':__builtins__,'ROOT':self.root,'Path':Path,'hashlib':hashlib,
            'os':os,'json':json,'math':math,'re':re,'stat':stat}
        selected(CORRECTED['hosted/common.py'][0],
                 {'need','encode','pin','path','read','decode','verify_source','context'},ns,
                 {'COMPONENT_MAP','ACTUAL','ALIASES','OPERATION','MAX_JSON'})
        ns['load']=lambda *a,**k:(_ for _ in ()).throw(AssertionError('payload import forbidden'))
        self.common_globals=ns
        self.c=SimpleNamespace(**ns)
        files={}
        for path in sorted(self.root.rglob('*')):
            if path.is_file():files[str(path.relative_to(self.root))]=dict(**self.c.pin(path.read_bytes()),mode=stat.S_IMODE(path.stat().st_mode))
        manifest={'schema':1,'actual':copy.deepcopy(self.c.ACTUAL),'files':files}
        raw=self.c.encode(manifest);(self.root/'source-map.json').write_bytes(raw);(self.root/'source-map.json').chmod(0o644)
        self.args=SimpleNamespace(source_sha=SOURCE,map_sha256=self.c.pin(raw)['sha256'],approval_sha256=None)
        approval={'status':'ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT','operation':self.c.OPERATION,
                  'source':SOURCE,'ref':REF,'source_map_sha256':self.args.map_sha256,
                  'resources':self.c.decode((self.root/'policy.json').read_bytes()),
                  'source_reviewed':True,'holds_preserved':True,
                  'authority':'FIXTURE DATA ONLY; no actual Root authority exists'}
        self.approval_path=self.parent/'llvm23-root-admission.json'
        raw=self.c.encode(approval);self.approval_path.write_bytes(raw)
        self.args.approval_sha256=self.c.pin(raw)['sha256']
        self.environment={'RUNNER_TEMP':str(self.parent),'GITHUB_REF':REF,'GITHUB_RUN_ID':'123',
            'GITHUB_SHA':SOURCE,'GITHUB_WORKFLOW_SHA':SOURCE,'GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':'Gabriel-Kahen/cachy-asahi',
            'GITHUB_WORKFLOW_REF':'Gabriel-Kahen/cachy-asahi/'+V2+'@'+REF,
            'GITHUB_ACTIONS':'true','RUNNER_ARCH':'ARM64','RUNNER_OS':'Linux','LLVM23_OPERATION':self.c.OPERATION}
        case=self
        class FakeCommands:
            def __init__(self,work,deadline,scope):
                case.assertEqual(work,case.work);case.assertEqual(scope,'proof')
                case.assertGreater(deadline,time.monotonic());self.rows=[]
            def __call__(self,argv,timeout):
                prefix=['/usr/bin/git','--no-replace-objects','--git-dir='+str(case.root/'.git'),
                        '--work-tree='+str(case.root),'-c','protocol.allow=never','-c','core.fsmonitor=false']
                case.assertEqual(argv[:len(prefix)],prefix)
                operands=argv[len(prefix):]
                self.rows.append({'argv':argv,'modeled_DATA_command_boundary':True})
                case.calls.append(operands)
                if operands==['rev-parse','--verify','HEAD']:
                    case.assertEqual(timeout,30)
                    return SimpleNamespace(returncode=0,stdout=((('0'*40) if case.git_fault=='head' else SOURCE)+'\n').encode())
                if operands==['ls-tree','-rz','--full-tree',SOURCE]:
                    case.assertEqual(timeout,60)
                    records=[]
                    paths=sorted(p for p in case.root.rglob('*') if p.is_file())
                    if case.git_fault=='member':paths=paths[:-1]
                    for index,path in enumerate(paths):
                        body=path.read_bytes();blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
                        mode='100755' if path.stat().st_mode&0o111 else '100644'
                        if index==0 and case.git_fault=='blob':blob='0'*40
                        if index==0 and case.git_fault=='mode':mode='100755' if mode=='100644' else '100644'
                        records.append((mode+' blob '+blob+'\t'+str(path.relative_to(case.root))).encode()+b'\0')
                    return SimpleNamespace(returncode=0,stdout=b''.join(records))
                raise AssertionError('only two modeled Git DATA calls are permitted')
        self.entry_globals={'__builtins__':__builtins__,'c':self.c,'ROOT':self.root,'Path':Path,
            'os':os,'time':time,'hashlib':hashlib,'Commands':FakeCommands,
            'storage_record':lambda path:{'status':'MODELED_STORAGE_DATA_NOT_QUALIFICATION','path':str(path)}}
        selected(CORRECTED['hosted/entry.py'][0],{'base_binding','proof'},self.entry_globals)

    def invoke(self,name='proof'):
        real_stat=Path.stat
        def parent_stat(path,*args,**kwargs):
            info=real_stat(path,*args,**kwargs)
            return SimpleNamespace(st_uid=1001,st_mode=info.st_mode) if path==self.parent else info
        with patch.dict(os.environ,self.environment,clear=True),patch.object(Path,'stat',parent_stat), \
             patch.object(os,'getuid',return_value=1001),patch.object(os,'geteuid',return_value=1001), \
             patch.object(os,'getgid',return_value=1001),patch.object(os,'getegid',return_value=1001):
            if name=='base_binding':return self.entry_globals[name](self.args)
            return self.entry_globals[name](self.args,self.work)

    def test_corrected_actual_base_binding_and_proof_positive(self):
        b=self.invoke('base_binding')
        self.assertEqual(self.calls,[]);self.assertEqual(b['operation'],'llvm23-source-reference-native-v2')
        result=self.invoke()
        self.assertEqual(result['status'],'PASS_EXACT_HOSTED_SOURCE_READBACK')
        self.assertEqual(result['binding'],b)
        self.assertEqual(len(self.calls),2)
        self.assertTrue(all(r['modeled_DATA_command_boundary'] for r in result['actors']))
        self.assertEqual(json.loads((self.work/'source-readback.json').read_bytes()),result)
        self.assertEqual(result['storage_before_inputs']['status'],'MODELED_STORAGE_DATA_NOT_QUALIFICATION')

    def test_old_v1_alias_reproduces_before_any_command(self):
        self.common_globals['ALIASES']=('.github/workflows/native-arm-build.yml',V1)
        with self.assertRaises(FileNotFoundError):self.invoke()
        self.assertEqual(self.calls,[]);self.assertFalse(self.work.exists())

    def test_missing_current_alias_refuses_before_commands(self):
        (self.root/V2).unlink()
        with self.assertRaisesRegex(ValueError,'membership'):self.invoke()
        self.assertEqual(self.calls,[])

    def test_wrong_map_hash_refuses_before_commands(self):
        self.args.map_sha256='0'*64
        with self.assertRaisesRegex(ValueError,'Source map'):self.invoke()
        self.assertEqual(self.calls,[])

    def test_changed_source_bytes_and_modes_refuse(self):
        path=self.root/'policy.json'
        original=path.read_bytes();path.write_bytes(original+b' ')
        with self.assertRaisesRegex(ValueError,'byte/mode drift'):self.invoke()
        path.write_bytes(original);path.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'byte/mode drift'):self.invoke()
        self.assertEqual(self.calls,[])

    def test_wrong_named_workflow_ref_refuses_before_commands(self):
        self.environment['GITHUB_WORKFLOW_REF']='Gabriel-Kahen/cachy-asahi/'+V1+'@'+REF
        with self.assertRaisesRegex(ValueError,'dedicated manual'):self.invoke()
        self.assertEqual(self.calls,[])

    def test_wrong_outer_operation_and_approval_digest_refuse(self):
        self.environment['LLVM23_OPERATION']='llvm23-source-reference-native-v1'
        with self.assertRaisesRegex(ValueError,'ambient policy'):self.invoke()
        self.environment['LLVM23_OPERATION']=self.c.OPERATION
        self.args.approval_sha256='0'*64
        with self.assertRaisesRegex(ValueError,'admission digest'):self.invoke()
        self.assertEqual(self.calls,[])

    def test_git_head_must_equal_bound_fixture_source(self):
        self.git_fault='head'
        with self.assertRaisesRegex(ValueError,'Git HEAD'):self.invoke()
        self.assertEqual(len(self.calls),1)
        self.assertFalse((self.work/'source-readback.json').exists())

    def test_git_member_membership_must_be_complete(self):
        self.git_fault='member'
        with self.assertRaisesRegex(ValueError,'published membership'):self.invoke()
        self.assertEqual(len(self.calls),2)
        self.assertFalse((self.work/'source-readback.json').exists())

    def test_git_blob_and_mode_must_match_read_source_data(self):
        for fault in ('blob','mode'):
            self.git_fault=fault
            if self.work.exists():
                (self.work/'home').rmdir();self.work.rmdir()
            with self.subTest(fault=fault),self.assertRaisesRegex(ValueError,'Git blob/mode'):self.invoke()

    def test_prospective_selectors_and_four_python_actors_unchanged(self):
        manifest=json.loads(CORRECTED['source-map.json'][0])
        self.assertTrue(manifest['actual']);self.assertTrue(all(v is None for v in manifest['actual'].values()))
        actor_names={n for n in PREVIOUS if n.startswith('actor/') and n.endswith('.py')}
        self.assertEqual(len(actor_names),4)
        self.assertTrue(all(CORRECTED[n]==PREVIOUS[n] for n in actor_names))
        self.assertEqual(CORRECTED['actor/entry.sh'],PREVIOUS['actor/entry.sh'])
        template=json.loads(CORRECTED['root-admission.TEMPLATE.json'][0])
        self.assertIsNone(template['source']);self.assertIsNone(template['authority'])


def main():
    global PREVIOUS,CORRECTED
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source',type=Path,required=True)
    args,remaining=parser.parse_known_args()
    # Read/render the admitted parent as DATA before the permanent process fence.
    spec=importlib.util.spec_from_file_location('llvm23_successor_v3_data_factory',HERE/'prepare.py')
    factory=importlib.util.module_from_spec(spec);spec.loader.exec_module(factory)
    PREVIOUS=factory.parent(args.parent_source);CORRECTED=factory.render(PREVIOUS)
    sys.addaudithook(fence)
    unittest.main(argv=[sys.argv[0],*remaining])


if __name__=='__main__':main()
