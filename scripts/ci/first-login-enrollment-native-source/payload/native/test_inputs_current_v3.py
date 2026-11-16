# SPDX-License-Identifier: MIT
"""FENCED tiny component DATA, never a qualified operational Root fixture."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('FENCED component DATA only: '+event)
sys.addaudithook(fence)

HERE=Path(__file__).resolve().parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
A=module('current_inputs_controls',HERE/'inputs_current_v3.py')
IMAGE=Path(os.environ.get('CACHY_CURRENT_INPUTS_IMAGE',str(HERE/'image_current_v3.py')))
IMAGE_PIN=dict(bytes=55783,sha256='f4e590532d7f6115f830215810f9dee5f2a1eb714351a9a7e572d22c5a255f90') # committedbc5df257
assert A.pin(IMAGE.read_bytes())==IMAGE_PIN,'exact committed signed341 plus fixed8 image consumer'
I=module('actual_committed_image_selected_inputs',IMAGE)

def put(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
    return dict(path=str(path),**A.pin(raw))
def data(path,value):return put(path,A.encoded(value))
def lock(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode()

class FencedContext:
    OPERATION=A.OP
    DELEGATION='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'
    CONTEXT='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3'
    ISSUER='DELEGATED_CONTEXT_PROGRAM_V3'
    def __init__(self,source,rows):self.root,self.rows=source,rows
    def descriptor(self,row):return {k:row[k]for k in('bytes','sha256')}
    def validate_delegation(self,raw,sha):
        value=A.decoded(raw);assert A.pin(raw)['sha256']==sha and value['FENCED']=='NOT_ROOT_AUTHORITY';return value
    def validate_context(self,d,c):assert c['FENCED']=='NOT_PROVIDER_OBSERVATION'
    def source(self,d,root):
        assert root==self.root
        actual={p.relative_to(root).as_posix():dict(mode=p.stat().st_mode&0o777,**A.pin(p.read_bytes()))for p in root.rglob('*')if p.is_file()}
        A.need(actual==self.rows,'FENCED closed Source pin');return root,self.rows
    def adopt_pair(self,d,c,**kwargs):
        # Pure image selected_inputs callback contract; never an actual qualification.
        pair=A.decoded(kwargs['pair_raw'])
        return dict(kind='DELEGATED_CURRENT_ONBOARDING_PAIR_ADOPTION_V3',binding=c['binding'],archives=pair['archives'],**A.FINAL)

class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='FENCED-current-inputs-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir();self.stage=self.root/'staged';self.stage.mkdir()
        self.rows={};self.refs={};self.materials={};original={'fenced-base-%03d'%n:'0.0-1'for n in range(341)}
        self.baseline=dict(original,**{name:'0.0-1'for name in A.SUPPLEMENT})
        self.fingerprint='A'*40;self.test_fingerprint='B'*40
        setup=put(self.stage/'setup.archive',b'FENCED not a native Setup8 archive')
        profile=A.decoded((HERE.parent.parent/'successor_v2/profile.json').read_bytes())
        profile['setup8']['archive_pin']={k:setup[k]for k in('bytes','sha256')};self.profile=profile
        self.closed(A.PROFILE,A.encoded(profile));self.closed('inputs/stages/baseline349.expected.lock',lock(self.baseline))
        self.closed('programs/inputs.py',Path(A.__file__).read_bytes())
        def public(role,raw):
            row=self.closed('carrier/'+A.ALIASES[role]+'.data',raw);self.refs[role]=row
            self.materials[A.ALIASES[role]]=dict(member=str(Path(row['path']).relative_to(self.source)),**{k:row[k]for k in('bytes','sha256')})
        key=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nFENCED ONLY\n'
        public('Setup8/archive',Path(setup['path']).read_bytes());public('Setup8/current_signature',b'FENCED Setup8 signature');public('Setup8/current_public_key',key)
        self.test_key=dict(public_key=self.refs['Setup8/current_public_key'],fingerprint=self.test_fingerprint)
        decision,proof=self.proofs('cachy-asahi-setup','0.3.0-1',self.refs['Setup8/archive'],self.refs['Setup8/current_signature'])
        public('Setup8/current_verification',A.encoded(proof));decision['verification_proof_sha256']=self.refs['Setup8/current_verification']['sha256'];public('Setup8/current_decision',A.encoded(decision))
        selected={};table={}
        for name in A.OFFICIAL:
            version='1:0.0-1'if name=='gtk4'else'0.0-1';row=dict(name=name,version=version,arch='aarch64',filename=name+'.pkg.tar.xz')
            for kind in('archive','signature'):
                role='official/'+name+'/'+kind;public(role,('FENCED '+role).encode());row[kind]={k:self.refs[role][k]for k in('bytes','sha256')}
            selected[name]=copy.deepcopy(row);table[name]=copy.deepcopy(row)
        self.selected=selected
        public('official/exact_closure',A.encoded(dict(selected=selected,addition_count=23,expected_final_official_count=372,
            unresolved=[],ambiguous=[],conflicts=[],ordering_comparisons_pending=[],conflict_ordering_pending=[],Root_acceptance=None,Root_current_official_signature_admission=None)))
        public('official/archive_signature_inputs',A.encoded(dict(packages=table,Root_current_official_trust=None,Root_current_verification=None)))
        self.vectors=dict(backend=dict(self.baseline,**{'cachy-asahi-setup':'0.3.0-1'}),lifecycle=dict(self.baseline,**{n:r['version']for n,r in selected.items()}))
        self.vectors['ui']=dict(self.vectors['lifecycle'],**{'cachy-asahi-setup':'0.3.0-1','cachy-asahi-first-login':'0.1.0-3'})
        for stage in A.COUNTS:public('expected/'+stage,lock(self.vectors[stage]))
        for role in('prospective/inputs','expected/stage_vectors','prospective/signed_lifecycle'):public(role,A.encoded(dict(FENCED='not future authority')))
        self.closed('inputs/delegated-materials-v4.json',A.encoded(dict(schema=4,kind='DELEGATED_SOURCE_RELATIVE_MATERIALS_V4',aliases=A.ALIASES,materials=self.materials)))
        self.H=FencedContext(self.source,self.rows)
        self.binding=dict(source='c'*40,ref='refs/heads/codex/FENCED',run=None,job=None,attempt=1,source_lock=dict(bytes=1,sha256='d'*64))
        own=dict(member='programs/inputs.py',**A.pin(Path(A.__file__).read_bytes()))
        context_ref=self.closed('programs/context.py',(HERE/'delegated_context_v3.py').read_bytes())
        context_program=dict(member='programs/context.py',**{k:context_ref[k]for k in('bytes','sha256')})
        self.assertEqual({k:context_program[k]for k in('bytes','sha256')},I.CONTEXT_PROGRAM_PINS[3])
        policy=self.closed('policy.json',A.encoded(dict(private_stage=dict(test=dict(fingerprint=self.test_fingerprint,public_key_role='setup8_current_public_key')))))
        self.d=dict(FENCED='NOT_ROOT_AUTHORITY',issuer='Root',schema=3,kind=self.H.DELEGATION,stage='backend',binding=self.binding,materials=self.materials,programs=dict(inputs_assembler=own,context=context_program),
            policy=dict(member='policy.json',**{k:policy[k]for k in('bytes','sha256')}),private_stage_producers={},capability=dict(allow_pair_adoption=True))
        base_rows=[];base_materials={}
        rootfs=put(self.stage/'rootfs',b'FENCED rootfs body');sig=put(self.stage/'rootfs.sig',b'FENCED rootfs signature')
        rootfs_row=dict(filename='rootfs',size=rootfs['bytes'],sha256=rootfs['sha256'],signature_size=sig['bytes'],signature_sha256=sig['sha256'])
        base_materials.update(rootfs=rootfs,**{'rootfs.sig':sig})
        for n in range(93,341):
            name='fenced-base-%03d'%n;ar=put(self.stage/(name+'.pkg'),('FENCED '+name).encode());sig=put(self.stage/(name+'.pkg.sig'),('FENCED sig '+name).encode())
            base_materials[name+'.pkg']=ar;base_materials[name+'.pkg.sig']=sig
            base_rows.append(dict(name=name,version='0.0-1',arch='aarch64',filename=name+'.pkg',size=ar['bytes'],sha256=ar['sha256'],signature_size=sig['bytes'],signature_sha256=sig['sha256']))
        supplemental={};extra=[]
        for name in sorted(A.SUPPLEMENT):
            ar=put(self.stage/(name+'.pkg'),('FENCED supplemental '+name).encode());sig=put(self.stage/(name+'.pkg.sig'),('FENCED supplement sig '+name).encode())
            supplemental[name+'.pkg']=ar;supplemental[name+'.pkg.sig']=sig
            extra.append(dict(name=name,version='0.0-1',arch='any'if name in('meson','python-tqdm')else'aarch64',filename=name+'.pkg',size=ar['bytes'],sha256=ar['sha256'],signature_size=sig['bytes'],signature_sha256=sig['sha256']))
        keyring_materials={};keyring_rows=[]
        for name in sorted(A.KEYRINGS):
            value=put(self.stage/name,b''if name.endswith('revoked')else('FENCED '+name).encode());keyring_materials[name]=value
            keyring_rows.append(dict(filename=name,size=value['bytes'],sha256=value['sha256']))
        base=data(self.stage/'base.json',dict(rootfs=rootfs_row,packages=base_rows,rootfs_packages=[dict(name=['fenced-base-%03d'%n],version=['0.0-1'],arch=['aarch64'])for n in range(165)],signer_fingerprint=self.fingerprint,keyring_files=keyring_rows))
        bootstrap=data(self.stage/'bootstrap.json',dict(FENCED='NOT_OPERATIONAL_BOOTSTRAP',original341=dict(package_count=341,packages=original),
            additions=dict(rows=extra,count=8,expected_augmented_package_count=349,unresolved=[])))
        factory=dict(FENCED='NOT_OPERATIONAL_FACTORY',parent_files={name:dict(wanted,mode=0o644)for name,wanted in(
            ('bootstrap/scripts/ci/inputs.lock.json',{k:base[k]for k in('bytes','sha256')}),('native/input-profile.json',{k:bootstrap[k]for k in('bytes','sha256')}),('native/expected349.lock',A.pin(lock(self.baseline))))})
        self.closed(A.FACTORY,A.encoded(factory))
        official_key=put(self.stage/'official.public',key+b'official')
        self.request=dict(A.template(),stage='backend',source_date_epoch=1,base_lock=base,bootstrap_profile=bootstrap,
            base_materials=base_materials,supplemental_materials=supplemental,keyring_materials=keyring_materials,products={})
        for kind,fpr,public_key in(('official',self.fingerprint,official_key),('test',self.test_fingerprint,self.refs['Setup8/current_public_key'])):
            trust=dict(public_key=public_key,fingerprint=fpr)
            trust['Root_admission']=data(self.stage/(kind+'-trust.json'),dict(FENCED_ONLY=True,issuer='Root',approved=True,scope='CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY',
                issued_epoch=0,expires_epoch=2**62,public_key=public_key,fingerprint=fpr))
            self.request[kind+'_trust']=trust
        self.addCleanup(patch.stopall)
        patch.object(A,'PROFILE_PIN',A.pin(A.encoded(profile))).start();patch.object(A,'BASE_SHA',base['sha256']).start();patch.object(A,'BASELINE_SHA',A.pin(lock(self.baseline))['sha256']).start()
        patch.object(A,'BASE_BYTES',base['bytes']).start();patch.object(A,'BOOTSTRAP_PIN',{k:bootstrap[k]for k in('bytes','sha256')}).start();patch.object(A,'FACTORY_PIN',A.pin(A.encoded(factory))).start()
        patch.object(I,'PROFILE_SHA',A.pin(A.encoded(profile))['sha256']).start();patch.object(I,'BASE_LOCK_SHA',base['sha256']).start();patch.object(I,'BASE_INVENTORY_SHA',A.pin(lock(self.baseline))['sha256']).start()
        patch.object(I,'BOOTSTRAP_PROFILE_PIN',{k:bootstrap[k]for k in('bytes','sha256')}).start();patch.object(I,'FACTORY_PROFILE_PIN',A.pin(A.encoded(factory))).start()
        real=A._context
        patch.object(A,'_context',side_effect=lambda raw,sha,c,source,H:real(raw,sha,c,source,self.H)).start()

    def closed(self,name,raw):
        ref=put(self.source/name,raw);self.rows[name]=dict(mode=0o600,**A.pin(raw));return ref

    def proofs(self,name,version,archive,signature):
        ar={k:archive[k]for k in('bytes','sha256')};sig={k:signature[k]for k in('bytes','sha256')}
        key=dict({k:self.test_key['public_key'][k]for k in('bytes','sha256')},fingerprint=self.test_fingerprint,trust_scope='TEST_ONLY')
        proof=dict(FENCED_ONLY=True,schema=1,Root_issuer='Root',status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',verified=True,trust_scope='TEST_ONLY',archive=ar,signature=sig,public_test_key=key)
        decision=dict(FENCED_ONLY=True,schema=1,issuer='Root',accepted=True,holds_preserved=True,status='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY'if name=='cachy-asahi-setup'else'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY',
            trust_scope='TEST_ONLY',archive=dict(ar,package=name,version=version,arch='any'),signature=sig,public_test_key=key,verification_proof_sha256=A.pin(A.encoded(proof))['sha256'])
        return decision,proof

    def product(self,kind):
        recipe=self.profile['packages'][kind];stage='ui'if kind=='ui'else'backend';out=self.stage/kind;out.mkdir()
        archives=[put(out/(label+'.archive'),('FENCED '+kind+' native body').encode())for label in('a','b')];sig=put(out/'signature',('FENCED '+kind+' signature').encode())
        producer=dict(FENCED='NOT_ROOT_AUTHORITY',stage=stage,nonce='e'*64,programs=dict(owner=dict(member='FENCED-owner',bytes=1,sha256='f'*64)),policy=dict(member='FENCED-policy',bytes=2,sha256='a'*64))
        delegation=data(out/'producer.json',producer);observed=dict(FENCED='NOT_PROVIDER_OBSERVATION',binding=dict(self.binding,run='11',job='12'))
        pair=dict(schema=3,kind='DELEGATED_CURRENT_ONBOARDING_PAIR_V3',issuer='DELEGATED_CURRENT_OWNER_V3',binding=observed['binding'],nonce=producer['nonce'],
            program_pin=self.H.descriptor(producer['programs']['owner']),policy_pin=self.H.descriptor(producer['policy']),package=recipe['name'],version=recipe['version'],matching_pair=True,archives=[A.pin(Path(x['path']).read_bytes())for x in archives],**A.FINAL)
        pair_ref=data(out/'pair.json',pair)
        status='[GNUPG:] VALIDSIG '+self.test_fingerprint+' 0 0 0 0 0 0 0 0 '+self.test_fingerprint+'\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'
        natural=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,timeout=False,signals=[],error=None,exit=0)
        test=dict(pair,kind='DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V3',pair_pin={k:pair_ref[k]for k in('bytes','sha256')},public_test_key_pin=self.H.descriptor(self.materials['setup8_current_public_key']),
            fingerprint=self.test_fingerprint,trust_scope='TEST_ONLY',verifications=[dict(archive=pair['archives'][0],signature={k:sig[k]for k in('bytes','sha256')},supervision=natural,status=status)]*2)
        decision,proof=self.proofs(recipe['name'],recipe['version'],archives[0],sig)
        self.d['private_stage_producers'][stage]={k:delegation[k]for k in('bytes','sha256')}
        return dict(archives=archives,signature=sig,Root_decision=data(out/'decision.json',decision),Root_verification=data(out/'verification.json',proof),
            producer_delegation=delegation,producer_context=data(out/'context.json',observed),pair=pair_ref,test=data(out/'test.json',test))

    def assemble(self,stage='backend'):
        self.d['stage']=stage;self.request['stage']=stage
        raw=A.encoded(self.d)
        return A.assemble_inputs(delegation_raw=raw,delegation_sha256=A.pin(raw)['sha256'],source_root=self.source,request=self.request,output=self.stage/('output-'+stage),context_program=self.H)

    def source_data(self,member,value):
        row=self.closed(member,A.encoded(value));Path(row['path']).chmod(0o644);self.rows[member]['mode']=0o644
        return row

    def staging(self):
        extra={};expected={}
        for role,(member,_)in A.STAGING_MATERIALS.items():
            raw=Path(self.request['base_lock'if role=='staging_base_lock'else'bootstrap_profile']['path']).read_bytes()if role in('staging_base_lock','staging_bootstrap_profile')else A.encoded(dict(FENCED='NOT_OPERATIONAL_STAGING',role=role))
            row=self.closed(member,raw);Path(row['path']).chmod(0o644);self.rows[member]['mode']=0o644
            extra[role]=dict(member=member,**A.pin(raw));expected[role]=(member,row['sha256'])
        patch.object(A,'STAGING_MATERIALS',expected).start()
        self.d['materials']=dict(self.materials,**extra)
        self.source_data(A.STAGING_TABLE,dict(schema=4,kind='DELEGATED_MATERIAL_STAGING_SOURCE_MATERIALS_V4',materials=extra))
        self.source_data(A.REGISTRY,dict(schema=4,kind='DELEGATED_CURRENT_PROGRAM_REGISTRY_V4',operation=A.OP,staging_materials=extra,FENCED='NOT_ROOT_AUTHORITY'))
        return extra

    def test_optional_staging64_preserves_original59_bytes_and_assembles(self):
        original=(self.source/'inputs/delegated-materials-v4.json').read_bytes();extra=self.staging()
        refs,_=A.source_inputs(self.source,self.d,self.H,self.rows)
        self.assertEqual(len(refs),59);self.assertEqual(len(self.d['materials']),64);self.assertEqual(set(extra),set(A.STAGING_MATERIALS))
        envelope=self.assemble();A.validate_hosted_inputs_v3(inputs=envelope,delegation=self.d,source_root=self.source)
        self.assertEqual((self.source/'inputs/delegated-materials-v4.json').read_bytes(),original)

    def test_staging_omissions_extras_cross_role_and_original_aliases_refuse(self):
        self.staging();original=copy.deepcopy(self.d['materials'])
        roles=list(A.STAGING_MATERIALS)
        for mutate in(lambda v:v.pop(roles[0]),lambda v:v.update(unselected=v[roles[0]]),
            lambda v:v.update({roles[0]:v[roles[1]]}),lambda v:v.update({roles[0]:v['setup8_archive']})):
            self.d['materials']=copy.deepcopy(original);mutate(self.d['materials'])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):A.source_inputs(self.source,self.d,self.H,self.rows)

    def test_staging_table_registry_and_whole_source_pins_are_mandatory(self):
        extra=self.staging();table=A.decoded((self.source/A.STAGING_TABLE).read_bytes());registry=A.decoded((self.source/A.REGISTRY).read_bytes())
        for mutate in(lambda t,r:t.update(extra=True),lambda t,r:t['materials'].pop('staging_base_lock'),
            lambda t,r:r['staging_materials'].pop('public14_profile'),lambda t,r:r.update(operation='different'),
            lambda t,r:t['materials']['staging_base_lock'].update(sha256='0'*64)):
            t=copy.deepcopy(table);r=copy.deepcopy(registry);mutate(t,r)
            self.source_data(A.STAGING_TABLE,t);self.source_data(A.REGISTRY,r)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):A.source_inputs(self.source,self.d,self.H,self.rows)
        self.source_data(A.STAGING_TABLE,table);self.source_data(A.REGISTRY,registry)
        for member in(A.STAGING_TABLE,A.REGISTRY):
            row=self.rows.pop(member)
            with self.subTest(member=member),self.assertRaises(ValueError):A.source_inputs(self.source,self.d,self.H,self.rows)
            self.rows[member]=row
        path=self.source/extra['public14_profile']['member'];path.write_bytes(b'stale Source staging profile')
        with self.assertRaises(ValueError):A.source_inputs(self.source,self.d,self.H,self.rows)

    def test_staging_registry_signal_cannot_silently_fall_back_to_default59(self):
        self.staging();self.d['materials']=dict(self.materials);row=self.rows.pop(A.STAGING_TABLE)
        with self.assertRaises(ValueError):A.source_inputs(self.source,self.d,self.H,self.rows)
        self.rows[A.STAGING_TABLE]=row
        with self.assertRaises(ValueError):A.source_inputs(self.source,self.d,self.H,self.rows)

    def test_backend_and_pure_preflight_match_real_image_selected_inputs(self):
        value=self.assemble();owner=value['owner_inputs'];before={p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        actual=A.validate_hosted_inputs_v3(inputs=value,delegation=self.d,source_root=self.source)
        self.assertTrue(actual['valid']);self.assertEqual(actual['required_refs'],value['staged_refs'])
        self.assertEqual(before,{p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()})
        base,rows,additions,baseline,expected=self.image_selection(owner,'backend')
        self.assertEqual(expected,self.vectors['backend']);self.assertEqual(len(rows),257);self.assertEqual(len(additions),1)
        self.assertIsNone(self.d['binding']['run']);self.assertEqual(set(owner),{'image_inputs','stage_inputs'})

    def image_selection(self,owner,stage):
        context=dict(FENCED='NOT_PROVIDER_OBSERVATION',schema=3,kind=self.H.CONTEXT,issuer=self.H.ISSUER,operation=A.OP,
            program_pin=self.H.descriptor(self.d['programs']['context']),binding=dict(self.binding,run='11',job='12'))
        args=(owner['image_inputs'],stage,self.source,self.H,self.d,context)
        result=I.selected_inputs(*args);self.assertEqual(result[-1],self.vectors[stage]);return result

    def test_canonical_inner_and_outer_are_distinct_and_share_one_validator(self):
        envelope=self.assemble();inner=envelope['owner_inputs']
        self.assertEqual(set(envelope),{'schema','kind','owner_inputs','staged_refs'})
        self.assertEqual(set(inner),{'image_inputs','stage_inputs'})
        direct=A.validate_owner_inputs_v3(inputs=inner,delegation=self.d,source_root=self.source)
        with patch.object(A,'validate_owner_inputs_v3',wraps=A.validate_owner_inputs_v3)as validator:
            hosted=A.validate_hosted_inputs_v3(inputs=envelope,delegation=self.d,source_root=self.source)
        validator.assert_called_once_with(inputs=inner,delegation=self.d,source_root=self.source)
        self.assertEqual(direct,hosted)
        with self.assertRaises(ValueError):A.validate_owner_inputs_v3(inputs=envelope,delegation=self.d,source_root=self.source)
        with self.assertRaises(ValueError):A.validate_hosted_inputs_v3(inputs=inner,delegation=self.d,source_root=self.source)

    def test_old_inner_and_unknown_authority_or_missing_trust_fields_refuse(self):
        envelope=self.assemble();inner=envelope['owner_inputs']
        old=dict(image=inner['image_inputs'],stage_inputs=inner['stage_inputs'],schema=3,kind='ASSEMBLED_CURRENT_ONBOARDING_INPUTS_V3',request={},provenance={})
        with self.assertRaises(ValueError):A.validate_owner_inputs_v3(inputs=old,delegation=self.d,source_root=self.source)
        for mutate in(lambda v:v['image_inputs'].update(Root_grant=True),lambda v:v['stage_inputs'].update(Root_grant=None),
            lambda v:v['image_inputs'].pop('test_trust')):
            bad=copy.deepcopy(inner);mutate(bad)
            with self.subTest(mutate=mutate),self.assertRaises((ValueError,KeyError)):A.validate_owner_inputs_v3(inputs=bad,delegation=self.d,source_root=self.source)

    def test_full517_handoff_includes_fixed8_and_empty_revoked_keyring_in_closure(self):
        envelope=self.assemble();inner=envelope['owner_inputs'];image=inner['image_inputs']
        self.assertEqual([len(image[k])for k in('base_materials','supplemental_materials','keyring_materials')],[498,16,3])
        self.assertEqual(image['bootstrap_profile'],self.request['bootstrap_profile'])
        result=A.validate_owner_inputs_v3(inputs=inner,delegation=self.d,source_root=self.source)
        for group in('base_materials','supplemental_materials','keyring_materials'):
            for value in image[group].values():self.assertIn(value,result['required_refs']);self.assertIn(value,envelope['staged_refs'])
        revoked=image['keyring_materials']['archlinuxarm-revoked'];self.assertEqual(revoked['bytes'],0);A.whole(revoked)
        for group in('supplemental_materials','keyring_materials'):
            bad=copy.deepcopy(envelope);bad['staged_refs'].remove(next(iter(image[group].values())))
            with self.subTest(group=group),self.assertRaises(ValueError):A.validate_hosted_inputs_v3(inputs=bad,delegation=self.d,source_root=self.source)

    def test_supplement_missing_extra_stale_pin_and_archive_refuse_before_output(self):
        original=copy.deepcopy(self.request)
        for group in('supplemental_materials','keyring_materials'):
            for mutate in(lambda v:v.pop(next(iter(v))),lambda v:v.update(invented=next(iter(v.values()))),lambda v:next(iter(v.values())).update(sha256='0'*64)):
                self.request=copy.deepcopy(original);mutate(self.request[group])
                with self.subTest(group=group,mutate=mutate),self.assertRaises(ValueError):self.assemble()
                self.assertFalse((self.stage/'output-backend').exists())
        self.request=copy.deepcopy(original);value=next(iter(self.request['supplemental_materials'].values()));Path(value['path']).write_bytes(b'stale supplemental archive')
        with self.assertRaises(ValueError):self.assemble()

    def test_pure_preflight_declares_supplement_and_keyring_body_checks_for_launcher(self):
        envelope=self.assemble();image=envelope['owner_inputs']['image_inputs']
        for group in('supplemental_materials','keyring_materials'):
            value=next(iter(image[group].values()));Path(value['path']).write_bytes(b'stale external body')
            result=A.validate_owner_inputs_v3(inputs=envelope['owner_inputs'],delegation=self.d,source_root=self.source)
            self.assertIn(value,result['required_refs'])
            with self.assertRaises(ValueError):A.whole(value)

    def test_ui_and_lifecycle_current_products_and_hydration(self):
        for stage,kinds in(('ui',('first-login',)),('lifecycle',('enrollment','first-login','ui'))):
            # Each stage has its own independent fixture and output directory.
            self.request['products']={kind:self.product(kind)for kind in kinds if not(self.stage/kind).exists()}
            if stage=='lifecycle':
                existing=self._first_product;self.request['products']['first-login']=existing
                self.request['retention']={name:data(self.stage/(name+'.capsule.json'),dict(FENCED='opaque capsule reference, retainer not exercised',actual=None))for name in('prior_backend','prior_ui')}
            else:self._first_product=self.request['products']['first-login']
            value=self.assemble(stage);owner=value['owner_inputs'];A.validate_hosted_inputs_v3(inputs=value,delegation=self.d,source_root=self.source)
            self.image_selection(owner,stage);hydrated=A.stage_inputs(owner)
            self.assertEqual(set(hydrated['products']),set(kinds));self.assertIsInstance(hydrated['products'][kinds[0]]['archives'][0],bytes)

    def test_lifecycle_retention_is_explicit_complete_and_in_staged_ref_closure(self):
        self.d['stage']='lifecycle';self.request['stage']='lifecycle'
        for retention in(None,{},dict(prior_backend=None,prior_ui=None)):
            self.request['retention']=retention
            with self.subTest(retention=retention),self.assertRaises(A.MissingInput):self.assemble('lifecycle')
        self.request['products']={kind:self.product(kind)for kind in('enrollment','first-login','ui')}
        refs={name:data(self.stage/(name+'.capsule.json'),dict(FENCED='not an authenticated public capsule',actual=None))for name in('prior_backend','prior_ui')}
        self.request['retention']=refs;envelope=self.assemble('lifecycle');inner=envelope['owner_inputs']
        direct=A.validate_owner_inputs_v3(inputs=inner,delegation=self.d,source_root=self.source)
        for value in refs.values():self.assertIn(value,direct['required_refs']);self.assertIn(value,envelope['staged_refs'])
        self.assertEqual(A.stage_inputs(inner)['retention'],refs)
        bad=copy.deepcopy(envelope);bad['staged_refs'].remove(refs['prior_backend'])
        with self.assertRaises(ValueError):A.validate_hosted_inputs_v3(inputs=bad,delegation=self.d,source_root=self.source)
        bad=copy.deepcopy(inner);bad['stage_inputs']['retention']['discovered_private_path']=refs['prior_ui']
        with self.assertRaises(ValueError):A.validate_owner_inputs_v3(inputs=bad,delegation=self.d,source_root=self.source)
        Path(refs['prior_ui']['path']).write_bytes(b'stale capsule')
        with self.assertRaises(ValueError):A.whole(refs['prior_ui'],64*1024**2)

    def test_backend_retention_empty_or_absent_only(self):
        self.request['retention']={};envelope=self.assemble()
        self.assertEqual(envelope['owner_inputs']['stage_inputs']['retention'],{})
        A.validate_owner_inputs_v3(inputs=envelope['owner_inputs'],delegation=self.d,source_root=self.source)
        bad=copy.deepcopy(envelope['owner_inputs']);bad['stage_inputs']['retention']={'prior_backend':self.refs['Setup8/archive']}
        with self.assertRaises(ValueError):A.validate_owner_inputs_v3(inputs=bad,delegation=self.d,source_root=self.source)

    def test_missing_root_trust_and_materials_refuse_before_output(self):
        for key in('base_materials','bootstrap_profile','supplemental_materials','keyring_materials','official_trust','test_trust','source_date_epoch','products'):
            old=self.request[key];self.request[key]=None
            with self.subTest(key=key),self.assertRaises(A.MissingInput):self.assemble()
            self.request[key]=old
        self.assertFalse((self.stage/'output-backend').exists())

    def test_missing_or_stale_package_and_proof_wholehash_refuse(self):
        ref=next(iter(self.request['base_materials'].values()));old=ref['sha256'];ref['sha256']='0'*64
        with self.assertRaises(ValueError):self.assemble()
        ref['sha256']=old
        proof=Path(self.refs['Setup8/current_verification']['path']);proof.write_bytes(proof.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.assemble()

    def test_alias_symlink_hardlink_and_unknown_roles_refuse(self):
        ref=next(iter(self.request['base_materials'].values()));old=ref['path'];alias=self.stage/'alias';alias.symlink_to(old);ref['path']=str(alias)
        with self.assertRaises(ValueError):self.assemble()
        alias.unlink();os.link(old,alias);ref['path']=str(alias)
        with self.assertRaises(ValueError):self.assemble()
        alias.unlink();ref['path']=old;self.d['materials']['invented_package']=next(iter(self.materials.values()))
        with self.assertRaises(ValueError):self.assemble()

    def test_preflight_ref_omission_extra_stale_owner_image_and_unknown_fields_refuse(self):
        value=self.assemble()
        mutations=[lambda v:v['staged_refs'].pop(),lambda v:v['staged_refs'].append(v['staged_refs'][0]),
            lambda v:v['owner_inputs'].pop('image_inputs'),lambda v:v['owner_inputs'].pop('stage_inputs'),
            lambda v:v['owner_inputs']['image_inputs']['setup8'].update(version='0.2.0-1'),
            lambda v:v['owner_inputs']['stage_inputs']['setup8'].update(archive_role='invented'),
            lambda v:v['owner_inputs'].update(Root_grant=True)]
        for mutation in mutations:
            bad=copy.deepcopy(value);mutation(bad)
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,KeyError)):A.validate_hosted_inputs_v3(inputs=bad,delegation=self.d,source_root=self.source)

    def test_wrong_product_version_and_missing_native_pair_refuse(self):
        self.request['products']={'first-login':self.product('first-login')};self.d['stage']='ui';self.request['stage']='ui'
        row=self.request['products']['first-login'];path=Path(row['pair']['path']);pair=A.decoded(path.read_bytes());pair['version']='0.1.0-2';row['pair']=data(path,pair)
        with self.assertRaises(ValueError):self.assemble('ui')
        row['pair']=None
        with self.assertRaises((ValueError,TypeError)):self.assemble('ui')

    def test_stale_hydrated_body_refuses_and_json_is_strict(self):
        self.request['products']={'first-login':self.product('first-login')};value=self.assemble('ui')
        Path(self.request['products']['first-login']['archives'][0]['path']).write_bytes(b'stale')
        with self.assertRaises(ValueError):A.stage_inputs(value['owner_inputs'])
        for raw in(b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1e999}'):
            with self.assertRaises(ValueError):A.decoded(raw)

    def test_preflight_declares_large_body_check_for_caller_without_claiming_it(self):
        value=self.assemble();ref=next(iter(self.request['base_materials'].values()));path=Path(ref['path']);raw=path.read_bytes()
        path.write_bytes(b'X'*len(raw))
        result=A.validate_hosted_inputs_v3(inputs=value,delegation=self.d,source_root=self.source)
        self.assertTrue(result['valid']);self.assertIn(ref,result['required_refs'])
        with self.assertRaises(ValueError):A.whole(ref)

    def test_expired_trust_and_root_proof_package_substitution_refuse(self):
        row=self.request['official_trust'];path=Path(row['Root_admission']['path']);trust=A.decoded(path.read_bytes());trust['expires_epoch']=0
        row['Root_admission']=data(path,trust)
        with self.assertRaises(ValueError):self.assemble()
        setup=dict(archive=self.refs['Setup8/archive'],signature=self.refs['Setup8/current_signature'],Root_decision=self.refs['Setup8/current_decision'],Root_verification=self.refs['Setup8/current_verification'])
        with self.assertRaises(ValueError):A.project_proof(setup,self.request['test_trust'],'cachy-asahi-first-login','0.1.0-2')

    def test_original59_aliases_match_constructor_and_source_test_policy_refuses(self):
        tree=ast.parse((HERE.parent.parent/'successor_v4_source/prepare.py').read_bytes())
        official=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='OFFICIAL'for t in n.targets))
        updates=next(ast.literal_eval(n.value.args[0])for n in tree.body if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and isinstance(n.value.func.value,ast.Name)and n.value.func.value.id=='ALIASES'and n.value.func.attr=='update')
        expected={'official/'+name+'/'+kind:'official_'+name.replace('-','_')+'_'+kind for name in official for kind in('archive','signature')};expected.update(updates)
        self.assertEqual(A.ALIASES,expected);self.assertEqual(len(expected),59)
        policy=A.decoded((self.source/'policy.json').read_bytes());policy['private_stage']['test']['public_key_role']='unknown_key'
        ref=self.closed('policy.json',A.encoded(policy));self.d['policy']=dict(member='policy.json',**{k:ref[k]for k in('bytes','sha256')})
        with self.assertRaises(ValueError):self.assemble()

    def selected_product(self):
        old=self.product('first-login');producer=A.decoded(Path(old['producer_delegation']['path']).read_bytes())
        producer.update(schema=3,binding=copy.deepcopy(self.binding),expires_epoch=1)
        old['producer_delegation']=data(Path(old['producer_delegation']['path']),producer)
        observed=A.decoded(Path(old['producer_context']['path']).read_bytes());now=int(A.time.time());completed=now-30
        row=dict(kind=A.SELECTED_KIND,selection_role='first_login',archives=old['archives'],
            signatures=[old['signature'],put(self.stage/'signature-b',b'FENCED second actual signature')],producer_delegation=old['producer_delegation'],producer_context=old['producer_context'],pair=old['pair'])
        component=dict(name=self.profile['packages']['first-login']['name'],version='0.1.0-3',architecture='any')
        pair=A.decoded(Path(old['pair']['path']).read_bytes());pair['component']=component;row['pair']=data(Path(old['pair']['path']),pair)
        body=dict(schema=1,kind='CURRENT_ONBOARDING_COMPLETED_PRODUCER_V4',producer_binding=observed['binding'],producer_delegation_pin=A.pin(A.encoded(producer)),
            producer_context_pin=A.pin(A.encoded(observed)),observed_epoch=completed)
        row['completion']=data(self.stage/'completion.json',body)
        selection=dict(component=component,producer_binding=observed['binding'],test_fingerprint=self.test_fingerprint,
            public_test_key_pin=self.H.descriptor(self.materials['setup8_current_public_key']),max_producer_age_seconds=3600,
            archives=[{k:r[k]for k in('bytes','sha256')}for r in row['archives']],signatures=[{k:r[k]for k in('bytes','sha256')}for r in row['signatures']])
        for field,key in(('producer_delegation','producer_delegation_pin'),('producer_context','producer_context_pin'),('completion','completion_pin'),('pair','pair_pin')):selection[key]={k:row[field][k]for k in('bytes','sha256')}
        for field,kind in(('root_component','ROOT_SELECTED_CURRENT_ONBOARDING_COMPONENT_V4'),('root_test','ROOT_SELECTED_CURRENT_ONBOARDING_TEST_V4')):
            decision=dict(schema=4,kind=kind,issuer='Root',approved=True,operation=A.OP,scope='CURRENT_PRIVATE_COMPONENT_ONLY',issued_epoch=now-10,expires_epoch=now+60,
                Root_final_acceptance=None,hardware_acceptance=False,release_acceptance=False,**{k:selection[k]for k in('producer_binding','producer_delegation_pin','producer_context_pin','completion_pin','component','pair_pin','archives')})
            if field=='root_test':decision.update(signatures=selection['signatures'],public_test_key_pin=selection['public_test_key_pin'],test_fingerprint=self.test_fingerprint,trust_scope='TEST_ONLY')
            row[field]=data(self.stage/(field+'.json'),decision);selection[field+'_decision_pin']={k:row[field][k]for k in('bytes','sha256')}
        self.H.DELEGATION='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4'
        self.d.update(schema=4,kind=self.H.DELEGATION,issued_epoch=now,pair_selections=dict(first_login=selection),context_limits=dict(max_delegation_seconds=3600))
        self.d['capability'].update(allow_pair_adoption=False,allow_selected_pair_adoption=True)
        return row

    def test_v4_preflight_preserves_expired_historical_producer_and_pending_consumer(self):
        row=self.selected_product();self.request['products']={'first-login':row};value=self.assemble('ui')
        A.validate_hosted_inputs_v3(inputs=value,delegation=self.d,source_root=self.source)
        image=value['owner_inputs']['image_inputs']['cli03'];self.assertEqual(image['pair_adoption'],row)
        self.assertIsNone(self.d['binding']['run']);self.assertIsNone(self.d['binding']['job'])
        self.assertEqual(A.decoded(Path(row['producer_delegation']['path']).read_bytes())['expires_epoch'],1)
        hydrated=A.stage_inputs(value['owner_inputs'])['products']['first-login']
        self.assertEqual(hydrated['root_test_raw'],Path(row['root_test']['path']).read_bytes())
        self.assertEqual(len(hydrated['signatures']),2);self.assertNotIn('Root_final_acceptance',value['owner_inputs'])

    def test_v4_missing_stale_unknown_selected_proof_and_v3_relabelling_refuse(self):
        row=self.selected_product();key=self.request['test_trust']
        for field in('completion','root_component','root_test'):
            bad=copy.deepcopy(row);bad[field]['sha256']='0'*64
            with self.subTest(field=field),self.assertRaises(ValueError):A.selected_product('first-login',bad,self.profile,self.d,self.H,key)
        bad=copy.deepcopy(row);bad['selection_role']='unselected'
        with self.assertRaises(ValueError):A.selected_product('first-login',bad,self.profile,self.d,self.H,key)
        bad_d=dict(self.d,schema=3)
        with self.assertRaises(ValueError):A.selected_product('first-login',row,self.profile,bad_d,self.H,key)

    def test_v4_runtime_adapter_forwards_both_bodies_and_authentic_decisions_after_capture(self):
        row=self.selected_product();self.request['products']={'first-login':row};value=self.assemble('ui');document=value['owner_inputs']
        raw=A.encoded(self.d)
        with self.assertRaisesRegex(A.MissingInput,'actual_poststart_consumer_context'):
            A.adopt_selected_inputs(document=document,delegation_raw=raw,delegation_sha256=A.pin(raw)['sha256'],context=None,source_root=self.source)
        c=dict(source_root=str(self.source),stage='ui',FENCED='NOT_PROVIDER_OBSERVATION',binding=dict(self.binding,run='22',job='23'))
        calls=[]
        def adopt(d,c,**kwargs):
            calls.append(kwargs);return dict(kind='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4',binding=c['binding'],test_fingerprint=self.test_fingerprint,current_stage_gpg_required=True,**A.FINAL)
        with patch.object(self.H,'adopt_selected_pair',side_effect=adopt,create=True):
            raw=A.encoded(self.d);receipts=A.adopt_selected_inputs(document=document,delegation_raw=raw,delegation_sha256=A.pin(raw)['sha256'],context=c,source_root=self.source)
        self.assertEqual(calls[0]['root_component_raw'],Path(row['root_component']['path']).read_bytes());self.assertEqual(len(calls[0]['archive_bodies']),2)
        self.assertEqual(len(calls[0]['signature_bodies']),2);self.assertEqual(calls[0]['selection_role'],'first_login')
        self.assertEqual(receipts['first-login']['binding']['run'],'22');self.assertTrue(receipts['first-login']['current_stage_gpg_required'])

class GenuineBaseMetadata(unittest.TestCase):
    def test_unmodified_frozen_descriptors_and_real341_plus8_feed_actual_assembler_seam(self):
        repo=HERE.parents[4]
        with tempfile.TemporaryDirectory(prefix='FENCED-genuine-base-metadata-')as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();rows={}
            for member,path in((A.FACTORY,repo/A.FACTORY),('inputs/stages/baseline349.expected.lock',HERE.parent.parent/'fixtures/expected349.lock')):
                value=put(source/member,path.read_bytes());rows[member]=dict(mode=0o600,**{k:value[k]for k in('bytes','sha256')})
            base=put(root/'original-lock.json',(repo/'scripts/ci/inputs.lock.json').read_bytes())
            bootstrap=put(root/'original-bootstrap.json',(repo/'scripts/ci/desktop-current011-native-source/fixtures/native/input-profile.json').read_bytes())
            lockdoc=A.load(base);profile=A.load(bootstrap);groups={}
            for key,records,signed in(('base_materials',[lockdoc['rootfs'],*lockdoc['packages']],True),('supplemental_materials',profile['additions']['rows'],True),('keyring_materials',lockdoc['keyring_files'],False)):
                values={}
                for row in records:
                    for suffix in(('', '.sig')if signed else('',)):
                        name=row['filename']+suffix;values[name]=dict(path=str(root/'FENCED_UNAVAILABLE_ARCHIVES'/name),bytes=row['signature_size']if suffix else row['size'],sha256=row['signature_sha256']if suffix else row['sha256'])
                groups[key]=values
            request=dict(base_lock=base,bootstrap_profile=bootstrap,**groups)
            fields,actual,baseline=A.base349_inputs(source_root=source,source_rows=rows,request=request,verify_archives=False)
            self.assertEqual(actual,lockdoc);self.assertEqual(len(baseline),349)
            self.assertEqual([len(fields[k])for k in groups],[498,16,3]);self.assertEqual(baseline['meson'],'1.12.1-2')
            self.assertEqual({r['name']:r['arch']for r in profile['additions']['rows']}['python-tqdm'],'any')
            self.assertEqual(fields['base_lock']['sha256'],'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
            # Actual missing5 remain explicit refusal, never an acquired or passing fixture.
            request['base_materials']=dict(groups['base_materials']);request['base_materials'].pop(lockdoc['rootfs']['filename'])
            with self.assertRaisesRegex(A.MissingInput,'base_materials/ArchLinuxARM-2026.08'):
                A.base349_inputs(source_root=source,source_rows=rows,request=request,verify_archives=False)

if __name__=='__main__':unittest.main()
