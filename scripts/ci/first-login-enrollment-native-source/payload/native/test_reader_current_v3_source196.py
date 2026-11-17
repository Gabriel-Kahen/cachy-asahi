# SPDX-License-Identifier: MIT
"""Explicit public Source196 DATA controls; Source programs remain opaque bytes."""
import argparse
import ast
import copy
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
CAPTURE_SOURCE=None
DIAGNOSTIC_SOURCE=None
ACTORS=[]


def actor_fence(event,args):
    denied=(event.startswith(('subprocess.','socket.','os.exec','os.spawn','os.posix_spawn','os.fork'))
        or event in ('os.system','fcntl.flock','ctypes.dlsym','ctypes.call_function')
        or event=='ctypes.dlopen' and args!=(None,))
    if denied:
        ACTORS.append(event)
        raise AssertionError('DATA controls forbid actor/native event: '+event)


sys.addaudithook(actor_fence)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


B=load('FENCED_preserved_reader_controls',HERE/'test_reader_current_v3.py')
R=load('FENCED_source196_reader',HERE/'reader_current_v3.py')
FAMILY='scripts/ci/first-login-enrollment-native-source/'
PREFIX=FAMILY+'successor_v6_source/'


def selection(files,prefix):
    program=R.receipt(files[prefix+'program.json'])
    paths=dict(profile=FAMILY+'successor_v2/profile.json',program=prefix+'program.json',
        **{role:program['roles'][role]['member'] for role in ('policy','retention','encoder')})
    return dict(source_lock_pin=R.pin(files['source.lock.json']),binding=dict(source_lock=R.pin(files['source.lock.json'])),
        source={role:dict(path=name,**R.pin(files[name])) for role,name in paths.items()},
        fingerprint=R.SELECTED_TEST_FINGERPRINT,resources=B.RESOURCES,
        reader_pin=R.pin((HERE/'reader_current_v3.py').read_bytes()),stage='backend')


def inverse(files,prefix,map_name):
    value=R.receipt(files[prefix+'inverse.json'])
    result={name:raw for name,raw in files.items() if name not in set(value['remove'])|{'source.lock.json','source-map.json'}}
    for target,backup in value.get('restore',{}).items():result[target]=files[backup]
    result['source.lock.json']=result['source-map.json']=files[map_name]
    return result


def parse(expected,files,delegated=True):
    with patch.object(Path,'read_bytes',side_effect=AssertionError('Reader must consume provided Source bytes only')):
        return R.source_data(expected,files,delegated=delegated)


class CaptureSource196(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CAPTURE_SOURCE is None:raise unittest.SkipTest('explicit --genuine-capture-source ABS_PATH required')
        root=Path(CAPTURE_SOURCE);raw=(root/'source.lock.json').read_bytes()
        if R.pin(raw)!=R.CAPTURE_SOURCE['source_map']:raise ValueError('fixed external Source196 map')
        cls.files=B.genuine_source_files(root,raw,196,45726789,'e85302474308dbf579b79bd6d501f5ad86b66bbb')
        cls.expected=selection(cls.files,PREFIX)
    def test_relocated_source196_and_all_three_inverse_tuples(self):
        files=self.files;lock=R.receipt(files['source.lock.json']);program=R.receipt(files[PREFIX+'program.json'])
        with tempfile.TemporaryDirectory(prefix='FENCED-Source196-relocated-') as temporary:
            root=Path(temporary);rows=dict(lock['files']);rows.update({name:dict(mode=0o644) for name in ('source.lock.json','source-map.json')})
            for name,raw in files.items():
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(rows[name]['mode'])
            relocated=B.genuine_source_files(root,files['source.lock.json'],196,45726789,R.CAPTURE_SOURCE['tree'])
            profile,checked,policy=parse(self.expected,relocated)
        self.assertEqual(relocated,files);self.assertEqual(checked,program)
        self.assertEqual((program['schema'],len(program['roles']),len(program['delegation_programs']),len(program['staging_materials'])),(6,27,25,5))
        basis188=inverse(files,PREFIX,'provenance/v6/source188-map.json')
        basis179=inverse(basis188,R.DIAGNOSTIC_PREFIX,'provenance/v5/source179-map.json')
        prefix139=FAMILY+'successor_v4_source/'
        basis139=inverse(basis179,prefix139,'provenance/v4/v3-source-map.json')
        for basis,wanted in ((basis188,R.DIAGNOSTIC_SOURCE),(basis179,R.DIAGNOSTIC_BASIS),
                (basis139,dict(files=139,bytes=43544563,tree='dcab30972b74d62df099d8ae12997dc0e557ff00'))):
            rows=dict(R.receipt(basis['source.lock.json'])['files']);rows.update({name:dict(mode=0o644,**R.pin(basis['source.lock.json'])) for name in ('source.lock.json','source-map.json')})
            self.assertEqual(set(basis),set(rows));self.assertEqual((len(basis),sum(map(len,basis.values()))),(wanted['files'],wanted['bytes']))
            self.assertTrue(all(R.pin(raw)==R.whole(rows[name]) for name,raw in basis.items()))
            self.assertEqual(R.source_git_tree(basis,rows),wanted['tree'])
        self.assertEqual(parse(selection(basis188,R.DIAGNOSTIC_PREFIX),basis188)[1],R.receipt(basis188[R.DIAGNOSTIC_PREFIX+'program.json']))
        if DIAGNOSTIC_SOURCE is not None:self.assertEqual(basis188,B.genuine_diagnostic_source_files(DIAGNOSTIC_SOURCE))
        self.assertEqual(profile['operation'],R.OP);self.assertIsNone(policy['material_domain_executor_current_v3']['Root_issuance'])
    def test_frozen_reader_v5_materials_and_authority_are_preserved(self):
        files=self.files;program=parse(self.expected,files)[1];basis=inverse(files,PREFIX,'provenance/v6/source188-map.json')
        original=R.receipt(basis[R.DIAGNOSTIC_PREFIX+'program.json'])
        frozen=R.whole(program['roles']['public_reader'])
        self.assertEqual(frozen,dict(bytes=248531,sha256='4f3ddd10cbe8c008254985e6ab82f8f3d8fa8c0b579d89c3d70c2dc70d399724'))
        self.assertNotEqual(frozen,self.expected['reader_pin'])
        changed={row['member'] for row in R.CAPTURE_REPLACEMENTS.values()}|{'source.lock.json','source-map.json'}
        self.assertTrue(all(files[name]==raw for name,raw in basis.items() if name not in changed))
        self.assertEqual(program['staging_materials'],original['staging_materials'])
        self.assertEqual(program['rebind_provenance'],original['rebind_provenance'])
        self.assertEqual(program['diagnostics_commit'],original['diagnostics_commit'])
        for value in (program,R.receipt(files['source.lock.json']),R.receipt(files['provenance/v6/rebind.json'])):
            self.assertTrue(all(v is None for v in value['actual'].values()))
        projected=R.material_projection_data(files['inputs/delegated-materials-v4.json'],files['inputs/material-staging-materials-v4.json'],program)
        self.assertEqual(len(projected['materials']),64);self.assertFalse(projected['Root_authentication'])
        with self.assertRaises(ValueError):parse(self.expected,files,delegated=False)
    def test_rehashed_source196_claims_refuse_tampering(self):
        cases=['map_alias','extra','missing','mode','issued_map','selector','old_registry','inverse','backup','basis_map',
            'constructor','provenance','launcher','domain','stager','old_v5_registry','policy','archive','role_missing','role_extra',
            'mapping','authority','kind','schema_bool','frozen_reader']
        for mode in cases:
            with self.subTest(mode=mode):
                files=dict(self.files);expected=copy.deepcopy(self.expected);lock=R.receipt(files['source.lock.json']);program=R.receipt(files[PREFIX+'program.json'])
                if mode=='map_alias':files['source-map.json']+=b' ';changed=set()
                elif mode=='extra':files['FENCED-extra.data']=b'FENCED';lock['files']['FENCED-extra.data']=dict(mode=0o644,**R.pin(b'FENCED'));changed=set()
                elif mode=='missing':files.pop(next(iter(R.CAPTURE_CONSTRUCTION)));changed=set()
                elif mode=='mode':lock['files'][R.CAPTURE_REPLACEMENTS['material_domain_executor']['member']]['mode']=0o755;changed=set()
                elif mode=='issued_map':lock['actual']['publication']={};changed=set()
                elif mode=='selector':expected['source']['policy']=dict(expected['source']['encoder']);changed=set()
                elif mode=='old_registry':expected['source']['program']=dict(path=R.DIAGNOSTIC_PREFIX+'program.json',**R.pin(files[R.DIAGNOSTIC_PREFIX+'program.json']));changed=set()
                else:
                    changed={PREFIX+'program.json'}
                    if mode=='role_missing':program['roles'].pop('private_seed')
                    elif mode=='role_extra':program['roles']['FENCED_extra']=dict(program['roles']['private_seed'])
                    elif mode=='mapping':program['delegation_programs']['hosted_launcher']=dict(program['delegation_programs']['material_domain_executor'])
                    elif mode=='authority':program['actual']['Root_delegation']={}
                    elif mode=='kind':program['kind']='DELEGATED_CURRENT_DIAGNOSTIC_PROGRAM_REGISTRY_V5'
                    elif mode=='schema_bool':program['schema']=True
                    elif mode=='frozen_reader':program['roles']['public_reader'].update(expected['reader_pin'])
                    else:
                        if mode=='inverse':name=PREFIX+'inverse.json'
                        elif mode=='backup':name=next(n for n in files if n.startswith('provenance/v6/original/'))
                        elif mode=='basis_map':name='provenance/v6/source188-map.json'
                        elif mode=='constructor':name=PREFIX+'prepare.py'
                        elif mode=='provenance':name='provenance/v6/rebind.json'
                        elif mode=='old_v5_registry':name=R.DIAGNOSTIC_PREFIX+'program.json'
                        elif mode=='archive':name='inputs/public-carrier.tar'
                        else:name=program['roles'][dict(launcher='hosted_launcher',domain='material_domain_executor',stager='materials_stager',policy='policy')[mode]]['member']
                        files[name]+=b' ';changed.add(name)
                        for table in ('roles','delegation_programs'):
                            for row in program[table].values():
                                if row['member']==name:row.update(R.pin(files[name]))
                        for row in expected['source'].values():
                            if row['path']==name:row.update(R.pin(files[name]))
                    files[PREFIX+'program.json']=R.encoded(program)
                    expected['source']['program'].update(R.pin(files[PREFIX+'program.json']))
                for name in changed:lock['files'][name].update(R.pin(files[name]))
                if mode!='map_alias':files['source.lock.json']=files['source-map.json']=R.encoded(lock)
                expected['source_lock_pin']=expected['binding']['source_lock']=R.pin(files['source.lock.json'])
                with self.assertRaises((ValueError,KeyError)):parse(expected,files)
    def test_inverse_registry_and_provenance_guards_survive_rebased_outer_claims(self):
        # Explicit MODEL rebasing exercises the inner predicates independently
        # of the immutable real196 whole-map/tree guard already tested above.
        cases=('inverse_remove','inverse_restore','basis','backup','untouched','constructor','provenance',
            'role','mapping','registry_actual','registry_extra','registry_schema','old_provenance')
        for mode in cases:
            with self.subTest(mode=mode):
                files=dict(self.files);lock=R.receipt(files['source.lock.json']);expected=copy.deepcopy(self.expected)
                if mode in ('inverse_remove','inverse_restore','basis'):
                    name=PREFIX+'inverse.json';value=R.receipt(files[name])
                    if mode=='inverse_remove':value['remove'].pop()
                    elif mode=='inverse_restore':value['restore'].pop(next(iter(value['restore'])))
                    else:value['basis']['tree']='0'*40
                elif mode=='provenance':name='provenance/v6/rebind.json';value=R.receipt(files[name]);value['capture_commit']='0'*40
                elif mode in ('backup','untouched','constructor'):
                    name=(next(n for n in files if n.startswith('provenance/v6/original/')) if mode=='backup'
                        else PREFIX+'prepare.py' if mode=='constructor' else R.DIAGNOSTIC_PREFIX+'README.md')
                    files[name]+=b' ';value=None
                else:
                    name=PREFIX+'program.json';value=R.receipt(files[name])
                    if mode=='role':value['roles'].pop('private_seed')
                    elif mode=='mapping':value['delegation_programs']['hosted_launcher']=dict(value['delegation_programs']['material_domain_executor'])
                    elif mode=='registry_actual':value['actual']['Root_delegation']={}
                    elif mode=='registry_extra':value['FENCED_extra']=None
                    elif mode=='registry_schema':value['schema']=6.0
                    else:value['rebind_provenance']['sha256']='0'*64
                if value is not None:files[name]=R.encoded(value)
                lock['files'][name].update(R.pin(files[name]));files['source.lock.json']=files['source-map.json']=R.encoded(lock)
                expected['source_lock_pin']=expected['binding']['source_lock']=R.pin(files['source.lock.json'])
                expected['source']['program'].update(R.pin(files[PREFIX+'program.json']))
                rows=dict(lock['files']);rows.update({n:dict(mode=0o644,**R.pin(files[n])) for n in ('source.lock.json','source-map.json')})
                modeled=dict(files=len(files),bytes=sum(map(len,files.values())),tree=R.source_git_tree(files,rows),source_map=R.pin(files['source.lock.json']))
                with patch.multiple(R,CAPTURE_SOURCE=modeled,CAPTURE_PROGRAM_PIN=R.pin(files[PREFIX+'program.json'])):
                    with self.assertRaises((ValueError,KeyError)):parse(expected,files)
    def test_six_declared_capture_helpers_have_independent_ast_guards(self):
        program=R.receipt(self.files[PREFIX+'program.json'])
        verdict=R.capture_source_contract(self.files,program)
        self.assertEqual(verdict,dict(status='CAPTURE_SOURCE_CONTRACT_DATA_ONLY_V6',Root_authentication=False,Root_acceptance=None))
        self.assertEqual(len(R.CAPTURE_HELPER_SHA256),6)
        for (role,name),digest in R.CAPTURE_HELPER_SHA256.items():
            with self.subTest(helper=name):
                files=dict(self.files);member=program['roles'][role]['member'];text=files[member].decode();nodes=ast.parse(text).body
                for part in name.split('.'):
                    node=next(n for n in nodes if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==part);nodes=node.body
                body=ast.get_source_segment(text,node);self.assertEqual(hashlib.sha256(body.encode()).hexdigest(),digest)
                # One AST body drift, with all other Source declarations intact.
                files[member]=text.replace(body,body+'\n'+(' '*node.col_offset)+'    pass',1).encode()
                with self.assertRaises(ValueError):R.capture_source_contract(files,program)
    def test_literal_hosted_domain_pin_cannot_drift(self):
        program=R.receipt(self.files[PREFIX+'program.json']);files=dict(self.files)
        member=program['roles']['hosted_launcher']['member']
        files[member]=files[member].replace(R.CAPTURE_REPLACEMENTS['material_domain_executor']['sha256'].encode(),b'0'*64)
        with self.assertRaises(ValueError):R.capture_source_contract(files,program)
    def test_no_actor_native_or_network_event_was_attempted(self):self.assertEqual(ACTORS,[])
    @classmethod
    def tearDownClass(cls):
        if ACTORS:raise AssertionError('actor/native attempts: '+repr(ACTORS))


if __name__=='__main__':
    arguments=argparse.ArgumentParser(add_help=False)
    arguments.add_argument('--genuine-capture-source',type=Path);arguments.add_argument('--genuine-diagnostic-source',type=Path)
    chosen,remaining=arguments.parse_known_args();CAPTURE_SOURCE=chosen.genuine_capture_source;DIAGNOSTIC_SOURCE=chosen.genuine_diagnostic_source
    for option in ('--genuine-capture-source','--genuine-diagnostic-source'):
        if sys.argv.count(option)>1:arguments.error('select at most one '+option)
    unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
