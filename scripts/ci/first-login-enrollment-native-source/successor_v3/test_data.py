#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Committed tiny model owner + public DATA constructor controls, never actor entry."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]


def fence(event,args):
    if event.startswith(('socket.','ctypes.'))or event in ('os.system','os.fork','os.exec','resource.setrlimit'):
        raise RuntimeError('constructor DATA fence: '+event)
    if event in ('subprocess.Popen','os.posix_spawn'):
        executable,argv=args[:2]
        if executable not in ('/usr/bin/git','git')or argv[0]not in ('/usr/bin/git','git'):
            raise RuntimeError('only local Git DATA operations permitted')
        if any(item in argv for item in ('fetch','push','pull','clone','remote')):
            raise RuntimeError('Git network is forbidden')


sys.addaudithook(fence)


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


P=module('current_v3_prepare_controls',HERE/'prepare.py');C=P.C;D=module('current_v3_registry_controls',HERE/'dispatch.py')


def tar(rows,change=None):
    result=io.BytesIO()
    with tarfile.open(fileobj=result,mode='w',format=tarfile.USTAR_FORMAT)as archive:
        for row in rows:
            body=Path(row['source']['path']).read_bytes();info=tarfile.TarInfo(row['member']);info.mode=0o644;info.size=len(body)
            if change is not None:change(info)
            archive.addfile(info,io.BytesIO(body)if info.isfile()else None)
    return result.getvalue()


def model_data(home):
    """All bodies and identity pins are inert class-local MODEL data, not archives."""
    where=home/'model-materials';where.mkdir();rows=[];bodies={};refs={}
    def add(role,member,body,filename=None):
        path=where/('%02d.DATA'%len(rows));path.write_bytes(body)
        row=dict(role=role,member=member,mode=0o644,source=dict(path=str(path),**C.pin(body)))
        if filename is not None:row['original_filename']=filename
        rows.append(row);bodies[role]=body;refs[role]=row['source'];return row['source']
    baseline={('model-base-%03d'%i):'0.0-model-1'for i in range(349)}
    lock=lambda values:''.join(n+' '+v+'\n'for n,v in sorted(values.items())).encode()
    packages={};files={}
    identities={'enrollment':('cachy-asahi-repository-enrollment','0.4.0-1',11,16),
                'first-login':('cachy-asahi-first-login','0.1.0-3',13,6),'ui':('cachy-asahi-first-login-ui','0.2.0-2',18,8)}
    payload=lambda name,count:{('usr/share/MODEL/'+name+'/leaf-%02d'%i):dict(bytes=1,sha256=C.pin(b'M')['sha256'],mode=0o644)for i in range(count)}
    for kind,(name,version,count,installed)in identities.items():
        packages[kind]=dict(name=name,version=version,payload_files=payload(kind,installed))
        for i in range(count):files['packages/MODEL/'+kind+'/leaf-%02d.DATA'%i]=(b'MODEL inert recipe leaf, never buildable\n',0o644)
    archive=b'MODEL SETUP8 ARCHIVE DATA, NOT A PACKAGE'
    profile=dict(kind='MODEL_BASIS_NEVER_NATIVE',operation=C.OPERATION,actual={'source':None},packages=packages,
                 setup8=dict(name='cachy-asahi-setup',version='0.3.0-1',archive_pin=C.pin(archive),payload_files=payload('setup8',10)))
    files[C.FAMILY+'/successor_v2/profile.json']=(C.encoded(profile),0o644)
    for i in range(15):files['MODEL-basis/held-%02d.DATA'%i]=(b'MODEL held helper metadata\n',0o644)
    assert len(files)==58
    old_lock=C.encoded(dict(schema=1,kind='MODEL_CURRENT_V2_BASIS',operation=C.OPERATION,files=C.descriptors(files),actual={'source':None}))
    selected={};table={}
    for i,name in enumerate(sorted(P.OFFICIAL)):
        version='1:0.0-model-1'if name=='gtk4'else'0.0-model-1';arch='aarch64'
        filename=name+'-'+version+'-'+arch+'.pkg.tar.xz'
        a=b'MODEL OFFICIAL ARCHIVE NOT A PACKAGE: '+name.encode();sig=b'MODEL DETACHED SIGNATURE NOT CRYPTO: '+name.encode()
        ar=add('official/'+name+'/archive','inputs/materials/official/%02d.archive'%i,a,filename)
        sr=add('official/'+name+'/signature','inputs/materials/official/%02d.signature'%i,sig,filename+'.sig')
        selected[name]=dict(name=name,version=version,arch=arch,filename=filename,archive=C.pin(a),signature=C.pin(sig))
        table[name]=dict(name=name,version=version,arch=arch,filename=filename,archive=ar,signature=sr,current_official_trust=None,current_verification=None)
    setup=add('Setup8/archive','inputs/materials/setup8/archive',archive)
    sig=add('Setup8/current_signature','inputs/public/setup8-current.sig',b'MODEL SETUP8 SIGNATURE NOT CRYPTO')
    pub=add('Setup8/current_public_key','inputs/public/setup8-current.asc',b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nMODEL NOT A REAL KEY\n-----END PGP PUBLIC KEY BLOCK-----\n')
    key=dict(bytes=pub['bytes'],sha256=pub['sha256'],fingerprint='A'*40,trust_scope='TEST_ONLY')
    proof=dict(model_identity='MODEL_ONLY_NOT_ROOT_ISSUANCE',Root_issuer='Root',status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',verified=True,
               archive=C.pin(archive),signature={k:sig[k]for k in ('bytes','sha256')},public_test_key=key,trust_scope='TEST_ONLY')
    vr=add('Setup8/current_verification','inputs/public/setup8-current.verification.json',C.encoded(proof))
    decision=dict(model_identity='MODEL_ONLY_NOT_ROOT_ISSUANCE',issuer='Root',accepted=True,holds_preserved=True,
                  status='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY',signature={k:sig[k]for k in ('bytes','sha256')},
                  public_test_key=key,verification_proof_sha256=vr['sha256'],archive=dict(C.pin(archive),package='cachy-asahi-setup',version='0.3.0-1',arch='any'))
    add('Setup8/current_decision','inputs/public/setup8-current.Root-decision.json',C.encoded(decision))
    official={n:r['version']for n,r in selected.items()}
    stages=dict(backend=dict(baseline,**{'cachy-asahi-setup':'0.3.0-1'}),
                ui=dict(baseline,**official,**{'cachy-asahi-setup':'0.3.0-1','cachy-asahi-first-login':'0.1.0-3'}),lifecycle=dict(baseline,**official))
    for stage,values in stages.items():add('expected/'+stage,'inputs/stages/'+stage+'.expected.lock',lock(values))
    catalog=dict(model_identity='MODEL_ONLY',selected=selected,addition_count=23,expected_final_official_count=372,
                 unresolved=[],ambiguous=[],conflicts=[],ordering_comparisons_pending=[],conflict_ordering_pending=[],
                 Root_acceptance=None,Root_current_official_signature_admission=None)
    add('official/exact_closure','inputs/catalog/official-closure.json',C.encoded(catalog))
    add('official/archive_signature_inputs','inputs/catalog/official-archive-signature-inputs.json',C.encoded(dict(packages=table,Root_current_official_trust=None,Root_current_verification=None)))
    inputs=dict.fromkeys(('source','source_date_epoch','Root_admission','Root_capacity','builder_image','builder_inventory','ui_builder_image',
                         'ui_builder_inventory','image_namespace_qualification','matching_Reader'))
    inputs.update(setup8=dict(archive=setup,signature=sig,current_TEST_signature_verification=None),
                  first_login_backend=dict.fromkeys(('native_pair','archive','signature','current_TEST_signature_verification')),
                  official_ui_dependencies=dict(verification=None))
    add('prospective/inputs','inputs/inputs.DRAFT.json',C.encoded(inputs))
    add('expected/stage_vectors','inputs/stage-vectors.json',C.encoded(dict(model_identity='MODEL_ONLY',future={'Root_admission':None},actual_images=None,installed_inventory_observations=None)))
    signed={kind:dict(name=row['name'],version=row['version'],payload_files=row['payload_files'],archive=None,signature=None,archive_pin=None,signature_pin=None)
            for kind,row in {'setup8':profile['setup8'],**packages}.items()}
    signed['setup8'].update(archive=setup['path'],archive_pin=C.pin(archive),signature=sig['path'],signature_pin={k:sig[k]for k in ('bytes','sha256')})
    add('prospective/signed_lifecycle','inputs/signed-lifecycle-inputs.DRAFT.json',C.encoded(dict(model_identity='MODEL_ONLY',signed=signed,
        common_TEST_fingerprint=None,Root_admission=None,runtime=None,official_trust=None,installed_inventory_observations=None,
        expected_inventory_counts=[372,373,376,373,376,373,372])))
    manifest=dict(model_identity='MODEL_ONLY_NO_ACTUAL_INPUTS',kind='DATA_ONLY_NO_SOURCE_FREEZE',operation=C.OPERATION,materials=rows,
                  **dict.fromkeys(('source','source_lock','owner_hook','operation_registry','resources','runtime','official_trust','current_stage_TEST_verification','publication')))
    assert len(rows)==59
    return manifest,files,profile,old_lock,lock(baseline)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='onboarding-v3-MODEL-DATA-');cls.addClassCleanup(cls.temp.cleanup);cls.home=Path(cls.temp.name)
        cls.repo=cls.home/'repo';cls.repo.mkdir()
        cls.git_env=dict(PATH='/usr/bin:/bin',HOME=str(cls.home),LC_ALL='C',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
        subprocess.run(['/usr/bin/git','init','--quiet',str(cls.repo)],check=True,env=cls.git_env)
        cls.owner='model/owner_current_v2.py';cls.route='model/owned_route.py'
        (cls.repo/'model').mkdir()
        # Test model only. Operational entry is explicitly forbidden in this fixture.
        (cls.repo/cls.owner).write_text("API='CURRENT_ONBOARDING_OWNED_CALLBACKS_V2'\ndef open_current_session(*args,**kwargs):\n raise RuntimeError('MODEL NEVER AN ACTUAL OWNER')\ndef launch_lifecycle(*args,**kwargs):\n raise RuntimeError('MODEL NEVER AN ACTUAL LIFECYCLE LAUNCHER')\n")
        (cls.repo/cls.route).write_text("OPERATION='first-login-enrollment-ui-current-v2'\ndef admission(*args):\n raise RuntimeError('MODEL NEVER ACTUAL ROOT ADMISSION')\ndef run_registered(**kwargs):\n raise RuntimeError('MODEL NEVER ACTUAL NATIVE ROUTE')\n")
        env=dict(cls.git_env,GIT_AUTHOR_NAME='DATA model',GIT_AUTHOR_EMAIL='model@test.invalid',GIT_COMMITTER_NAME='DATA model',GIT_COMMITTER_EMAIL='model@test.invalid')
        subprocess.run(['/usr/bin/git','-C',str(cls.repo),'add','model'],check=True,env=env)
        subprocess.run(['/usr/bin/git','-C',str(cls.repo),'commit','--quiet','-m','explicit MODEL owner only'],check=True,env=env)
        cls.commit=subprocess.check_output(['/usr/bin/git','-C',str(cls.repo),'rev-parse','HEAD'],text=True,env=cls.git_env).strip()
        files={n:dict(C.pin((cls.repo/n).read_bytes()),mode=0o644)for n in (cls.owner,cls.route)}
        cls.closure=dict(schema=1,kind='CURRENT_ONBOARDING_COMMITTED_OWNER_ROUTE_CLOSURE_V3',commit=cls.commit,api=C.API,operation=C.OPERATION,owner=cls.owner,route=cls.route,files=files)
        cls.manifest,cls.model_basis_files,cls.model_profile,cls.model_lock,cls.model_baseline=model_data(cls.home)
        cls.carrier=tar(cls.manifest['materials'])
        with mock.patch.object(P,'basis',side_effect=cls.model_basis), mock.patch.object(P,'BASIS',cls.commit), mock.patch.object(P,'PROFILE',C.pin(C.encoded(cls.model_profile))):
            cls.files,cls.result=P.assemble(cls.repo,C.encoded(cls.closure),cls.carrier,C.encoded(cls.manifest))
        cls.output=cls.home/'MODEL-SOURCE-NOT-ACTUAL';P.publish(cls.files,cls.output)

    @classmethod
    def model_basis(cls,repo):
        return dict(cls.model_basis_files),copy.deepcopy(cls.model_profile),cls.model_lock,cls.model_baseline

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_operational_basis_still_refuses_missing_historical_commit(self):
        self.assertFalse((self.repo/'.git/objects/info/alternates').exists())
        with self.assertRaises(ValueError):P.basis(self.repo)

    def test_model_constructor_preserves42_and_typed_model_vectors(self):
        self.assertEqual(self.result['status'],'CLOSED_CURRENT_SOURCE_DATA_RUNTIME_UNQUALIFIED')
        value,program=C.source(self.output,self.result['source_map']['sha256'])
        self.assertEqual(len([n for n in value['files']if n.startswith('packages/')]),42)
        for stage,count in C.STAGES.items():self.assertEqual(program['expected_inventories'][stage]['packages'],count)
        self.assertEqual(program['owner']['path'],self.owner)
        self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertTrue(all(v is None for v in program['actual'].values()))

    def test_committed_body_selected_and_uncommitted_body_pin_refuses(self):
        previous=(self.repo/self.owner).read_bytes()
        try:
            (self.repo/self.owner).write_bytes(previous+b'# uncommitted\n')
            _,files=P.owner_closure(self.repo,C.encoded(self.closure))
            self.assertEqual(files[self.owner][0],previous)
            changed=copy.deepcopy(self.closure);changed['files'][self.owner].update(C.pin((self.repo/self.owner).read_bytes()))
            with self.assertRaises(ValueError):P.owner_closure(self.repo,C.encoded(changed))
        finally:(self.repo/self.owner).write_bytes(previous)

    def test_absent_or_null_owner_commit_refuses(self):
        for key,value in [('commit',None),('commit','0'*40),('owner','model/missing.py'),('api','OLD_FROZEN_V1')]:
            changed=copy.deepcopy(self.closure);changed[key]=value
            with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):P.owner_closure(self.repo,C.encoded(changed))

    def test_wrong_committed_mode_or_body_refuses(self):
        for key,value in [('mode',0o755),('sha256','0'*64),('bytes',1)]:
            changed=copy.deepcopy(self.closure);changed['files'][self.owner][key]=value
            with self.assertRaises(ValueError):P.owner_closure(self.repo,C.encoded(changed))

    def test_generated_slot_and_extra_route_hook_missing_refuse(self):
        changed=copy.deepcopy(self.closure);changed['files'][C.PREFIX+'/dispatch.py']=dict(bytes=1,sha256='0'*64,mode=420)
        with self.assertRaises(ValueError):P.owner_closure(self.repo,C.encoded(changed))

    def test_whole_59_carrier_ordinary_bytes_and_closed_tail(self):
        members,roles,_=P.carrier(self.carrier,C.encoded(self.manifest));self.assertEqual(len(members),59)
        self.assertEqual(len(roles),59)
        with self.assertRaises(ValueError):P.carrier(self.carrier+b'hidden',C.encoded(self.manifest))

    def test_missing_extra_duplicate_or_wrong_pin_carrier_refuses(self):
        for rows in (self.manifest['materials'][:-1],[*self.manifest['materials'],self.manifest['materials'][0]]):
            changed=copy.deepcopy(self.manifest);changed['materials']=rows
            with self.assertRaises(ValueError):P.carrier(self.carrier,C.encoded(changed))
        changed=copy.deepcopy(self.manifest);changed['materials'][0]['source']['sha256']='0'*64
        with self.assertRaises(ValueError):P.carrier(self.carrier,C.encoded(changed))

    def test_symlink_executable_and_owner_tar_metadata_refuse(self):
        def link(info):info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd'
        for change in (link,lambda info:setattr(info,'mode',0o755),lambda info:setattr(info,'uid',1000)):
            with self.assertRaises((ValueError,tarfile.TarError)):P.carrier(tar(self.manifest['materials'],change),C.encoded(self.manifest))

    def test_epoch_paths_preserved_in_metadata_without_unsafe_tar_path(self):
        gtk=[r for r in self.manifest['materials']if r['role']=='official/gtk4/archive'][0]
        self.assertIn('1:0.0-model-1',gtk['original_filename']);self.assertNotIn(':',gtk['member'])
        changed=copy.deepcopy(self.manifest);changed['materials'][0]['member']='../escape'
        with self.assertRaises(ValueError):P.carrier(self.carrier,C.encoded(changed))

    def test_wrong_stage_baseline_or_future_grant_refuses(self):
        members,roles,_=P.carrier(self.carrier,C.encoded(self.manifest));_,profile,_,baseline=self.model_basis(self.repo)
        for role in ('expected/backend','expected/ui','expected/lifecycle'):
            changed=dict(members);name=roles[role];raw=changed[name][0];changed[name]=(raw.replace(b'model-base-000 ',b'forged-tools '),0o644)
            with self.assertRaises(ValueError):P.join_inputs(changed,roles,profile,baseline)
        changed=dict(members);name=roles['prospective/inputs'];value=C.decode(changed[name][0]);value['Root_capacity']={}
        changed[name]=(C.encoded(value),0o644)
        with self.assertRaises(ValueError):P.join_inputs(changed,roles,profile,baseline)

    def test_source_aliases_and_every_leaf_are_bound(self):
        self.assertEqual((self.output/'source-map.json').read_bytes(),(self.output/'source.lock.json').read_bytes())
        with tempfile.TemporaryDirectory()as name:
            target=Path(name)/'copy';shutil.copytree(self.output,target)
            (target/'source.lock.json').chmod(0o755)
            with self.assertRaises(ValueError):C.source(target,self.result['source_map']['sha256'])
            (target/'source.lock.json').chmod(0o644);(target/self.owner).write_bytes(b'changed')
            with self.assertRaises(ValueError):C.source(target,self.result['source_map']['sha256'])

    def test_existing_output_never_replaced(self):
        before=(self.output/'source-map.json').read_bytes()
        with self.assertRaises(ValueError):P.publish(self.files,self.output)
        self.assertEqual((self.output/'source-map.json').read_bytes(),before)

    def test_registry_resolves_committed_owner_and_refuses_other_hook(self):
        owner=self.closure['files'][self.owner]
        grant=dict(operation=C.OPERATION,stage='backend',source_root=str(self.output),output=str(self.home/'future-stage'),
                   binding=dict(source_lock=self.result['source_lock']),owner=dict(api=C.API,code=dict(path=str(self.output/self.owner),**{k:owner[k]for k in ('bytes','sha256')})))
        program=D.registry(self.output,self.result['source_map']['sha256'],grant,{},self.home/'future-stage','backend')
        self.assertEqual(program['owner']['path'],self.owner)
        changed=copy.deepcopy(grant);changed['owner']['code']['sha256']='0'*64
        with self.assertRaises(ValueError):D.registry(self.output,self.result['source_map']['sha256'],changed,{},self.home/'future-stage','backend')
        changed=copy.deepcopy(grant);changed['operation']='first-login-enrollment-alpm-v1'
        with self.assertRaises(ValueError):D.registry(self.output,self.result['source_map']['sha256'],changed,{},self.home/'future-stage','backend')

    def test_lifecycle_uses_outer_launcher_and_literal_pinned_operands(self):
        class Provider:
            def __init__(self):self.calls=[]
            def launch_lifecycle(self,*args):self.calls.append(args);return {'status':'MODELED_OUTER_ENTRY_ONLY'}
            def open_current_session(self,*args):raise AssertionError('host direct lifecycle callback forbidden')
        provider=Provider()
        with tempfile.TemporaryDirectory()as name:
            home=Path(name);ip=home/'inputs.json';ap=home/'admission.json'
            inputs={'mode':'synthetic test DATA'};ib=C.encoded(inputs);ip.write_bytes(ib)
            grant={'owner':{'admission_path':str(ap),'inputs':dict(path=str(ip),**C.pin(ib))}}
            ab=C.encoded(grant);ap.write_bytes(ab);sha=C.pin(ab)['sha256']
            result=D.lifecycle_entry(provider,grant,inputs,self.output,home/'future-stage',ap,sha,ip)
            self.assertEqual(result['status'],'MODELED_OUTER_ENTRY_ONLY')
            self.assertEqual(provider.calls,[(ap,sha,ip,self.output,home/'future-stage')])
            with self.assertRaises(ValueError):D.lifecycle_entry(provider,grant,inputs,self.output,home/'future-stage',ap,'0'*64,ip)
            changed=copy.deepcopy(grant);changed['owner']['admission_path']='/wrong/path'
            with self.assertRaises(ValueError):D.lifecycle_entry(provider,changed,inputs,self.output,home/'future-stage',ap,sha,ip)
            self.assertEqual(len(provider.calls),1)

    def test_during_construction_no_model_owner_is_imported(self):
        self.assertNotIn('root_committed_current_owner_v3',sys.modules)
        self.assertNotIn('root_committed_current_route_v3',sys.modules)
        self.assertFalse((self.home/'future-stage').exists())

    def test_malformed_json_and_inventory_duplicates_refuse(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e9999}'):
            with self.assertRaises(ValueError):C.decode(raw)
        with self.assertRaises(ValueError):C.inventory(b'a 1\na 1\n',2)


if __name__=='__main__':unittest.main()
