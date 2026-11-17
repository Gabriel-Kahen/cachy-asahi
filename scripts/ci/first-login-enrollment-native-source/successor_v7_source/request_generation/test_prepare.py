# SPDX-License-Identifier: MIT
"""Actor-fenced MODEL selectors only; no publication, Root issuance or dispatch."""
import argparse
import copy
import dis
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ATTEMPTS=[]

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn','os.fork')) or event in ('os.system','fcntl.flock','resource.setrlimit'):
        ATTEMPTS.append(event);raise AssertionError('MODEL template controls forbid actor: '+event)

sys.addaudithook(fence)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module

P=load('MODEL_request_generator',HERE/'prepare.py')


def model_inputs():
    """Synthetic readback/Main claims, never evidence that publication occurred."""
    profile=dict.fromkeys(P.PROFILE_KEYS)
    profile.update(schema=7,kind='UNISSUED_CURRENT_ONBOARDING_TRANSPORT_SOURCE_PROFILE_V7',
        operation='first-login-enrollment-ui-current-v2',transport_commit=P.CONSTRUCTOR,
        files=P.SOURCE205['files'],bytes=P.SOURCE205['bytes'],prospective_tree=P.SOURCE205['tree'],
        source_map=copy.deepcopy(P.SOURCE205['source_map']),program=copy.deepcopy(P.PROGRAM),
        actual=dict.fromkeys(P.ACTUAL_KEYS),**copy.deepcopy(P.BASES))
    def row(role):return dict(member='MODEL/'+role+'.data',bytes=1,sha256='c'*64)
    profile['delegation_programs']={role:row(role)for role in P.PROGRAM_ROLES}
    profile['delegation_programs']['hosted_launcher']=dict(member=P.LAUNCHER,**P.LAUNCHER_PIN)
    profile['materials']={('MODEL_material_%02d'%i):row('material_%02d'%i)for i in range(59)}
    profile['staging_materials']={role:row(role)for role in P.STAGING_ROLES}
    raw=P.encoded(profile);cid='a'*40;main='b'*40;ref='refs/heads/codex/MODEL-unissued-Source205'
    publication=dict(schema=1,kind='SOURCE205_PUBLICATION_READBACK_DATA_ONLY',status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY',
        source=cid,ref=ref,profile=P.pin(raw),**copy.deepcopy(P.SOURCE205))
    selected=dict(schema=1,kind='EXPLICIT_MAIN_REQUEST_SELECTORS_DATA_ONLY',commit=main,
        launcher=dict(member=P.LAUNCHER,**P.LAUNCHER_PIN),provenance_operand=dict(member=P.OPERAND,**P.LAUNCHER_PIN),
        reader=dict(member=P.READER,bytes=1,sha256='d'*64),
        workflow=dict(member='.github/workflows/MODEL-unadopted-route.yml',bytes=1,sha256='e'*64))
    return cid,ref,main,profile,publication,selected


def render(values=None,*,model_profile=True):
    cid,ref,main,profile,publication,selected=model_inputs()if values is None else values
    profile_raw=P.encoded(profile);publication_raw=P.encoded(publication);main_raw=P.encoded(selected)
    args=dict(published_source_cid=cid,source_ref=ref,main_commit=main,
        profile_raw=profile_raw,profile_sha256=P.pin(profile_raw)['sha256'],
        publication_raw=publication_raw,publication_sha256=P.pin(publication_raw)['sha256'],
        main_raw=main_raw,main_sha256=P.pin(main_raw)['sha256'])
    if model_profile:
        # Synthetic body only: never confuse MODEL descriptors with real Source205.
        with patch.object(P,'PROFILE_PIN',P.pin(profile_raw)):return P.render(**args)
    return P.render(**args)


class Controls(unittest.TestCase):
    def tearDown(self):self.assertEqual(ATTEMPTS,[])
    def test_model_plan_is_unissued_once_and_always_route_hold(self):
        value=render();P.unissued(value)
        self.assertTrue(value['once']);self.assertFalse(value['retry']);self.assertFalse(value['dispatch_ready'])
        self.assertEqual(value['route_hold'],'CANONICAL_MAIN_V7_LAUNCHER_AND_WORKFLOW_ADOPTION_REQUIRED')
        for key in ('issuer','approved','issued_epoch','expires_epoch','authority','resources'):self.assertIsNone(value[key])
        self.assertEqual(value['publication']['authenticity'],'UNVERIFIED_DATA_ONLY')
        self.assertEqual(value['main']['launcher']['member'],P.LAUNCHER)
        self.assertEqual(value['main']['provenance_operand']['member'],P.OPERAND)
        for request in value['request_templates'].values():
            for key in ('issuer','approved','issued_epoch','expires_epoch'):self.assertIsNone(request.get(key))
        self.assertEqual(len(value['request_templates']['delegation']['programs']),25)
        self.assertEqual(len(value['request_templates']['delegation']['materials']),64)
        self.assertIsNone(value['request_templates']['launch']['authorization'])
    def test_missing_cids_source196_constructor_and_bad_refs_refuse(self):
        for index,changes in ((0,(None,'',P.SOURCE196,P.CONSTRUCTOR,'b'*40)),(1,('',None,'main','refs/heads/codex/../bad','refs/heads/codex/x.lock')),(2,(None,'','main'))):
            for changed in changes:
                values=list(model_inputs());values[index]=changed
                with self.subTest(index=index,value=changed),self.assertRaises(ValueError):render(values)
    def test_old_map_schema_basis_unknown_keys_or_issued_profile_refuse(self):
        for mode in ('schema','files','map','basis','constructor','unknown','actual','role','materials'):
            values=list(model_inputs());profile=values[3]
            if mode=='schema':profile['schema']=6
            elif mode=='files':profile['files']=196
            elif mode=='map':profile['source_map']=P.BASES['source196_basis']['source_map']
            elif mode=='basis':profile['source196_basis']={}
            elif mode=='constructor':profile['transport_commit']='0'*40
            elif mode=='unknown':profile['Root_approval']=True
            elif mode=='actual':profile['actual']['source']='a'*40
            elif mode=='role':profile['delegation_programs']['FENCED_extra']=profile['delegation_programs'].pop('context')
            else:profile['staging_materials'].pop('public14_profile')
            with self.subTest(mode=mode),self.assertRaises(ValueError):render(values)
    def test_publication_claim_must_join_explicit_cid_ref_profile_and_tuple(self):
        for key,changed in (('source',P.SOURCE196),('ref','refs/heads/codex/MODEL-other'),('files',196),('schema',True),('unknown','FENCED'),('profile',P.pin(b'other'))):
            values=list(model_inputs());values[4][key]=changed
            with self.subTest(key=key),self.assertRaises(ValueError):render(values)
    def test_frozen_main_new_path_only_unknown_and_unbounded_selectors_refuse(self):
        for mode in ('v6','new-path-only','operand','reader','workflow','unknown','commit','boolean','oversize'):
            values=list(model_inputs());main=values[5]
            if mode=='v6':main['launcher'].update(bytes=66263,sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97')
            elif mode=='new-path-only':main['launcher']['member']=P.OPERAND
            elif mode=='operand':main.pop('provenance_operand')
            elif mode=='reader':main['reader']['member']='../reader.py'
            elif mode=='workflow':main['workflow']['member']='native.yml'
            elif mode=='unknown':main['approved']=True
            elif mode=='commit':main['commit']='0'*40
            elif mode=='boolean':main['reader']['bytes']=True
            else:main['workflow']['bytes']=P.MAX_INPUT+1
            with self.subTest(mode=mode),self.assertRaises(ValueError):render(values)
    def test_bad_whole_pins_duplicate_noncanonical_and_input_output_caps_refuse(self):
        for raw,digest in ((b'{}\n','0'*64),(b'x'*(P.MAX_INPUT+1),'0'*64),(b'{"a":1,"a":1}\n',None),(b'{"a": 1}',None)):
            with self.subTest(bytes=len(raw)),self.assertRaises(ValueError):P.checked(raw,digest or P.pin(raw)['sha256'])
        with patch.object(P,'MAX_OUTPUT',100),self.assertRaises(ValueError):render()
    def test_live_validators_refuse_unissued_templates_without_actor_entry(self):
        H=load('FENCED_live_hosted_validator',HERE.parent/'payload/hosted.py')
        S=load('FENCED_live_stager_validator',HERE.parent/'payload/stager.py')
        C=load('FENCED_live_context_validator',HERE.parents[1]/'payload/native/delegated_context_v4.py')
        values=render()['request_templates']
        self.assertEqual((values['delegation']['schema'],values['delegation']['kind']),(4,C.DELEGATION))
        self.assertEqual(C.DELEGATION,C._CORE.DELEGATION)
        self.assertTrue(any(instruction.opname in ('LOAD_CONST','LOAD_SMALL_INT')and instruction.argval==4
            for instruction in dis.get_instructions(C._CORE.validate_delegation)))
        self.assertEqual(values['launch']['schema'],3);self.assertEqual(values['material_grant']['schema'],3)
        with tempfile.TemporaryDirectory(prefix='MODEL-',dir=HERE)as directory:
            path=Path(directory)/'unissued-launch.json';raw=P.encoded(values['launch']);path.write_bytes(raw)
            with self.assertRaises(ValueError):H.request(path,P.pin(raw)['sha256'])
        raw=P.encoded(values['delegation'])
        with self.assertRaises(ValueError):C.validate_delegation(raw,P.pin(raw)['sha256'],now=0)
        raw=P.encoded(values['material_grant'])
        with self.assertRaises(ValueError):S.validate_grant(raw,P.pin(raw)['sha256'],{},{},{})
    def test_publish_writes_only_fresh_private_unissued_data_and_rejects_authority(self):
        with tempfile.TemporaryDirectory(prefix='MODEL-',dir=HERE)as directory:
            root=Path(directory);output=root/'fresh';value=render();P.publish(value,output)
            self.assertEqual((output/'ONCE.UNISSUED.json').read_bytes(),P.encoded(value))
            self.assertEqual((output/'ONCE.UNISSUED.json').stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):P.publish(value,output)
            for key,changed in (('approved',True),('issuer','Root'),('dispatch_ready',True)):
                bad=copy.deepcopy(value);bad[key]=changed
                with self.subTest(key=key),self.assertRaises(ValueError):P.publish(bad,root/('bad-'+key))
            bad=copy.deepcopy(value);bad['request_templates']['launch']['authorization']={'privileged_controller':True}
            with self.assertRaises(ValueError):P.publish(bad,root/'bad-inner')
            bad=copy.deepcopy(value);bad['request_templates']['delegation']['release_acceptance']=True
            with self.assertRaises(ValueError):P.publish(bad,root/'bad-acceptance')
    def test_cli_has_no_selector_defaults_or_implicit_head_lookup(self):
        with patch.object(sys,'argv',['prepare.py']),patch.object(sys,'stderr',io.StringIO()):
            with self.assertRaises(SystemExit)as raised:P.main()
        self.assertEqual(raised.exception.code,2)
    def test_literal_real_profile_pin_rejects_self_rehashed_model_descriptors(self):
        self.assertEqual(P.PROFILE_PIN,dict(bytes=21451,sha256='99198c00308780aaf95e803c43d01ab185b55a049731287b7644c2425dd90a12'))
        for mode in ('base-model','old-stager'):
            values=list(model_inputs())
            if mode=='old-stager':values[3]['delegation_programs']['materials_stager'].update(bytes=35550,sha256='58c5d0842c17a914239b5f24e9e1ac2987ad8ec9ce9e2a03e63a04f2e2e99282')
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'deterministic Source205 profile'):render(values,model_profile=False)
    def test_full_cli_uses_only_supplied_pins_and_writes_an_unissued_plan(self):
        cid,ref,main,profile,publication,selected=model_inputs()
        with tempfile.TemporaryDirectory(prefix='MODEL-',dir=HERE)as directory:
            root=Path(directory);argv=['prepare.py','--published-source-cid',cid,'--source-ref',ref,'--main-commit',main]
            for option,value in (('root-profile',profile),('publication-readback',publication),('main-selectors',selected)):
                path=root/(option+'.json');raw=P.encoded(value);path.write_bytes(raw)
                argv.extend(['--'+option,str(path),'--'+option+'-sha256',P.pin(raw)['sha256']])
            argv.extend(['--output',str(root/'fresh')])
            with patch.object(P,'PROFILE_PIN',P.pin(P.encoded(profile))),patch.object(sys,'argv',argv):P.main()
            value=P.decode((root/'fresh/ONCE.UNISSUED.json').read_bytes());P.unissued(value)
            self.assertEqual(value,render());self.assertFalse(value['dispatch_ready'])
            alias=root/'alias.json';alias.symlink_to(root/'root-profile.json')
            with self.assertRaises(ValueError):P.read(alias)
            bad=list(argv);bad[bad.index('--root-profile-sha256')+1]='0'*64
            bad[-1]=str(root/'not-created')
            with patch.object(P,'PROFILE_PIN',P.pin(P.encoded(profile))),patch.object(sys,'argv',bad),self.assertRaises(ValueError):P.main()
            self.assertFalse((root/'not-created').exists())
    def test_static_template_is_canonical_unbound_and_non_authoritative(self):
        raw=(HERE/'ONCE.TEMPLATE.json').read_bytes();self.assertEqual(P.decode(raw),P.template())
        P.unissued(P.decode(raw));self.assertIsNone(P.decode(raw)['source']);self.assertIsNone(P.decode(raw)['main'])


def genuine_controls(profile_path):
    class GenuineUnissuedProfile(unittest.TestCase):
        def test_exact_deterministic_profile_with_model_publication_and_main_selectors(self):
            raw=P.read(profile_path);self.assertEqual(P.pin(raw),P.PROFILE_PIN)
            values=list(model_inputs());values[3]=P.decode(raw);values[4]['profile']=P.pin(raw)
            value=render(values,model_profile=False);P.unissued(value)
            self.assertFalse(value['dispatch_ready']);self.assertEqual(value['root_profile'],P.PROFILE_PIN)
            self.assertEqual(value['publication']['authenticity'],'UNVERIFIED_DATA_ONLY')
            self.assertEqual(ATTEMPTS,[])
    return GenuineUnissuedProfile


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--genuine-profile',type=Path)
    chosen,remaining=parser.parse_known_args()
    if sys.argv.count('--genuine-profile')>1:parser.error('select one genuine unissued profile')
    if chosen.genuine_profile is not None:globals()['GenuineUnissuedProfile']=genuine_controls(chosen.genuine_profile)
    unittest.main(argv=[sys.argv[0],*remaining])
