"""New variant DATA boundaries only. No constructor, Native or actual Reader call."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import os
import sys
import tarfile
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
NATIVE=HERE/'overlay/native'
POLICY=json.loads((NATIVE/'build-tools-contract-v2.json').read_bytes())
PROFILE=json.loads((HERE/'profile.json').read_bytes())

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
T=load('_new_build_tools_policy',NATIVE/'build_tools_tools_v2.py')
B=load('_new_build_tools_probe_data',NATIVE/'build_tools_probe_v2.py')
F=load('_new_build_tools_constructor_definitions',HERE/'prepare.py')

def extracted(path,name):
    tree=ast.parse(path.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
    namespace=dict(re=re,json=json,need=T.need);exec(compile(ast.Module(body=[node],type_ignores=[]),'<MODELED_PURE_READER_CHECK_AST>','exec'),namespace);return namespace[name]
PRODUCER_CHECK=extracted(NATIVE/'build_tools_alpm_v2.py','check_result')
MODELED_READER_CHECK=extracted(NATIVE/'build_tools_reader_v2.py','build_tools_check_result')

def modeled_check_log(names=None):
    names=POLICY['recipe']['expected_test_names']if names is None else names
    return ('==> Starting check()...\n'+''.join(n+' (__main__.PackageTests.'+n+') ... ok\n'for n in names)+'\nRan 11 tests in 2.641s\n\nOK\n').encode()

def object_tree(rows):
    root={}
    for path,row in rows.items():
        at=root;parts=path.split('/')
        for part in parts[:-1]:at=at.setdefault(part,{})
        at[parts[-1]]=(row['mode'],row['oid'])
    def walk(node):
        body=b''
        for name,row in sorted(node.items(),key=lambda x:(x[0]+('/'if type(x[1])is dict else'')).encode()):
            mode,oid=('40000',walk(row))if type(row)is dict else row
            body+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)
        return hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest()
    return walk(root)

ACTIVE=False
ACTOR_ATTEMPTS=[]
def actor_fence(event,args):
    if ACTIVE and(event.startswith(('socket.','subprocess.','os.exec','os.spawn','os.fork','os.posix_spawn','ctypes.'))or event=='os.system'):
        ACTOR_ATTEMPTS.append(event);raise AssertionError('Source DATA controls forbid actors: '+event)
sys.addaudithook(actor_fence)

class FactoryDataTests(unittest.TestCase):
    def setUp(self):
        global ACTIVE
        self.before=len(ACTOR_ATTEMPTS);ACTIVE=True
        self.addCleanup(self.finish_data_control)
    def finish_data_control(self):
        global ACTIVE
        ACTIVE=False
        self.assertEqual(len(ACTOR_ATTEMPTS),self.before)

    def test_actual_16_recipe_members_and_new_four_mib_bundle(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);target=root/POLICY['bundle']['path'];target.parent.mkdir();target.write_bytes((NATIVE/'build-tools-sources-v2.tar').read_bytes())
            members=T.recipe_members(root,POLICY)
        self.assertEqual(len(members),16);self.assertEqual(POLICY['bundle']['bytes'],1648640)
        self.assertEqual(POLICY['bundle']['max_bytes'],4*1024**2)
        self.assertEqual(T.data_pin(members['recipe/check-inputs.tar.gz']),dict(bytes=1509703,sha256='112fa3eb9c18245ad95ea874f66c4943dc2678b0927e63a6ac705ff398e6ac72'))

    def test_bundle_tamper_refuses_even_with_recomputed_outer_pin(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);target=root/POLICY['bundle']['path'];target.parent.mkdir()
            raw=(NATIVE/'build-tools-sources-v2.tar').read_bytes();out=io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as src,tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT)as dst:
                for index,node in enumerate(src):
                    with src.extractfile(node)as stream:body=stream.read()
                    if index==0:body=b'changed';node.size=len(body)
                    dst.addfile(node,io.BytesIO(body))
            changed=out.getvalue();target.write_bytes(changed);policy=copy.deepcopy(POLICY);policy['bundle'].update(T.data_pin(changed))
            with self.assertRaises(ValueError):T.recipe_members(root,policy)

    def test_exact_real_fixture_decodes_under_held_eight_mib_cap(self):
        with tarfile.open(NATIVE/'build-tools-sources-v2.tar','r:')as src:
            with src.extractfile('recipe/check-inputs.tar.gz')as stream:raw=stream.read()
        files=T.fixture_members(raw,POLICY);self.assertEqual(len(files),14)
        self.assertEqual(T.data_pin(files['zlib-1.3.2.tar.gz']),dict(bytes=1502830,sha256='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'))
        with self.assertRaises(ValueError):T.fixture_members(raw+b'changed',POLICY)

    def test_source_row_extension_does_not_extend_installed_payload_rows(self):
        row=dict(bytes=1509703,sha256='a'*64,mode=0o644)
        self.assertFalse(T._pin_row(row));self.assertTrue(T._pin_row(row,4*1024**2))
        row['bytes']=4*1024**2+1;self.assertFalse(T._pin_row(row,4*1024**2))
        self.assertEqual(len(POLICY['recipe']['payload_files']),12)

    def test_genuine_399_394_license_and_dependency_closure(self):
        origin=POLICY['package_origin'];proof=origin['merge_proof'];checker=origin['checker_merge_proof']
        self.assertEqual(proof['main'],'39af4cc7d12573ac73d13c8832b42b72be1e1174')
        self.assertEqual(proof['tested_head'],'7ef85998fbede9730355806b4e6d10649fe32d31');self.assertEqual(proof['merge_PUTs'],1)
        self.assertEqual(checker['Main'],'8dd2a730540693a04e148557f6971d370471ba8a')
        self.assertEqual(checker['head'],'9a225d5bc2d60c69a7ef06094251871ef0fe3988')
        self.assertEqual(origin['checker'],{k:POLICY['recipe']['source_files']['recipe_metadata_consistency.py'][k]for k in('bytes','sha256')})
        self.assertEqual(origin['license']['sha256'],'51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7')
        self.assertEqual(POLICY['package_dependencies']['runtime'],['python>=3.12']);self.assertEqual(len(POLICY['buildinfo_installed']),349)
        host=T._metadata((HERE/'host-PKGINFO.txt').read_bytes());self.assertEqual(host['pkgname'],['cachy-asahi-build-tools']);self.assertEqual(host['pkgver'],['0.2.0-1']);self.assertEqual(host['arch'],['any']);self.assertEqual(host['license'],['MIT']);self.assertEqual(host['depend'],['python>=3.12']);self.assertEqual(host.get('checkdepend',[]),[])
        self.assertIn('X86_64_HOST',POLICY['host_archive_scope']);self.assertEqual(POLICY['recipe']['archive'],'cachy-asahi-build-tools-0.2.0-1-any.pkg.tar.zst')

    def test_new_eleven_check_log_grammar_is_modeled_only_and_shared(self):
        raw=modeled_check_log();left=PRODUCER_CHECK(raw);right=MODELED_READER_CHECK(raw)
        self.assertEqual(left,right);self.assertEqual(left['tests'],11);self.assertEqual(left['namespace_acceptance'],'NOT_ESTABLISHED')
        self.assertEqual(len(left['names']),11)
        for invalid in(raw.replace(b'Ran 11',b'Ran 10'),raw.replace(b' ... ok',b' ... skipped',1),raw+b'OK\n',modeled_check_log(POLICY['recipe']['expected_test_names'][:-1]),raw.replace(b'OK\n',b'FAILED (failures=1)\n')):
            for checker in(PRODUCER_CHECK,MODELED_READER_CHECK):
                with self.assertRaises(ValueError):checker(invalid)

    def test_six_commands_have_nine_fixed_observations(self):
        rows=B.requests('/usr/bin/cachy-asahi-build-tools','/fixture','/work',POLICY)
        self.assertEqual(tuple(r[0]for r in rows),B.STEPS);self.assertEqual(len(rows),9)
        self.assertEqual(len({r[1][0]for r in rows}),6);self.assertEqual([r[2]for r in rows], [0,0,0,0,0,0,0,1,2])
        self.assertFalse(any('bwrap'in arg or '--repo-root'in arg for _,args,_ in rows for arg in args))

    def test_metadata_statuses_and_inert_operand_pins_do_not_cross_accept(self):
        work=Path('/work')
        for key,status,recipe,info in(('consistency-match','MATCH_MODELED_LITERAL_DECLARATIONS',B.MATCH_RECIPE,B.MATCH_INFO),('consistency-mismatch','MISMATCH',B.MATCH_RECIPE,B.MISMATCH_INFO),('consistency-unsupported','UNSUPPORTED',B.UNSUPPORTED_RECIPE,B.MATCH_INFO)):
            value=dict(status=status,shell_evaluation=False,inputs=dict(PKGBUILD=B.data_pin(recipe),SRCINFO=B.data_pin(info)),mismatches=[dict(field='pkgver',PKGBUILD=['1'],SRCINFO=['0'])]if key.endswith('mismatch')else[],unsupported=[dict(input='PKGBUILD',reason='modeled')]if key.endswith('unsupported')else[])
            self.assertEqual(B.validate_result(key,value,POLICY,work),value)
            wrong=copy.deepcopy(value);wrong['status']='MISMATCH'if status!='MISMATCH'else'MATCH_MODELED_LITERAL_DECLARATIONS'
            with self.assertRaises(ValueError):B.validate_result(key,wrong,POLICY,work)

    def test_new_profile_16_seams_closed200_and_null_actuals(self):
        raw=(HERE/'profile.json').read_bytes();value=F.profile(raw,hashlib.sha256(raw).hexdigest())
        self.assertEqual(value,PROFILE);self.assertEqual(len(value['overlay']),16);self.assertEqual(value['source_files'],200)
        self.assertEqual(len(F.ADDITIONS),9);self.assertEqual(len(F.SEAMS),7);self.assertEqual(value['actual'],dict(source=None,ref=None,run=None))
        for field,replacement in(('operation','source-tools-alpm-v1'),('source_files',201),('actual',dict(source='a'*40,ref=None,run=None))):
            changed=copy.deepcopy(value);changed[field]=replacement;b=T.encoded(changed)
            with self.assertRaises(ValueError):F.profile(b,hashlib.sha256(b).hexdigest())

    def test_virtual_git_tree_and_nonrecursive_map_match(self):
        before=json.loads((HERE/'parent-git-objects.json').read_bytes());self.assertEqual(len(before),191);self.assertEqual(object_tree(before),PROFILE['parent_tree'])
        after=dict(before)
        for name,row in PROFILE['overlay'].items():
            body=(HERE/'overlay'/name).read_bytes();self.assertEqual(dict(**T.data_pin(body),mode=0o644),row)
            after[name]=dict(mode='100644',oid=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest())
        self.assertEqual(len(after),200);self.assertEqual(object_tree(after),PROFILE['prospective_tree'])
        manifest=json.loads((NATIVE/'source-map.json').read_bytes());self.assertEqual(len(manifest['files']),199);self.assertNotIn('native/source-map.json',manifest['files'])
        self.assertEqual(manifest['actual'],dict(source=None,ref=None,run=None));self.assertEqual(manifest['build_tools_operation'],'build-tools-alpm-v2')

    def test_reader_local_closure_precedes_ingress_and_no_namespace_actor(self):
        tree=ast.parse((NATIVE/'build_tools_reader_v2.py').read_bytes());validate=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate');text=ast.get_source_segment((NATIVE/'build_tools_reader_v2.py').read_text(),validate)
        self.assertLess(text.index('build_tools_local_binding'),text.index('open_capsule'))
        producer=(NATIVE/'build_tools_alpm_v2.py').read_text();self.assertNotIn('observe_namespace_failure(',producer);self.assertNotIn('namespace_failure(label',producer)
        self.assertNotIn('/usr/bin/bwrap',(NATIVE/'build_tools_probe_v2.py').read_text());self.assertIn('NO_BUILD_TOOLS_BWRAP_COVERAGE',POLICY['required_namespace'])

    def test_exact_consumer_probe_and_deadline_caps_are_held(self):
        owner=(NATIVE/'owner.py').read_text()
        for token in('--cpus=1','--memory=128m','--pids-limit=32','--pids-limit=256','--memory=4g','--cpus=2','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges'):self.assertIn(token,owner)
        producer=(NATIVE/'build_tools_alpm_v2.py').read_text();self.assertIn('timeout=180,total=450,max_output=1024**2',producer);self.assertIn('timeout=20,total=90,max_output=1024**2',producer)
        self.assertEqual(POLICY['resources']['consumer']['memory_bytes'],4*1024**3)
        self.assertIn('DAEMON_DEFAULTS',POLICY['resources']['image_build'])

if __name__=='__main__':unittest.main(verbosity=2)
