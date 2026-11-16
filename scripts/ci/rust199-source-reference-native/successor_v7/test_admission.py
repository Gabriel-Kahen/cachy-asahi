# SPDX-License-Identifier: MIT
"""FENCED admission component controls; no qualified operational Root fixture."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
support_spec=importlib.util.spec_from_file_location('v7_test_support_DATA',HERE/'test_support.py');support=importlib.util.module_from_spec(support_spec);support_spec.loader.exec_module(support);PAYLOAD=support.assembled()
s=importlib.util.spec_from_file_location('v7_admission_DATA',PAYLOAD/'admission.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)


def reader_component():
    """FENCED Reader DATA only; no TEST proof, Root decision or admission."""
    m=g.metadata();case=g.EXPECTED_NATIVE_CASE;program=m['independent_reader']
    actual=dict(source=g.EXPECTED_SOURCE,ref=g.EXPECTED_REF,run=case['run'],job=case['job'],attempt=1,approval='c'*64,authority='FENCED_NOT_ROOT',image='sha256:'+'d'*64,artifact=case['Original']['id'],reader='FENCED_NOT_A_READER_RUN')
    llvm=dict(source={k:actual[k]for k in ('run','job')},artifact=copy.deepcopy(case['Original']),archive=dict(bytes=1,sha256='f'*64),reader=dict(binding=dict(sha256='1'*64)))
    binding=dict(schema=1,scope='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V7',actual=actual,export_sha256='2'*64,full_original_decode=dict(bytes=1,files=1,map_sha256='3'*64),holds_preserved=True,operation=g.EXPECTED_IDENTITY['operation'],original_archive={k:case['Original'][k]for k in ('bytes','sha256')},package_sha256='f'*64,pins_sha256=program['files']['pins.json']['sha256'],policy_sha256=m['policy_pin']['sha256'],provider_sha256='4'*64,reader_sha256=program['sha256'],source_commit_sha256='5'*64,source_map_sha256=g.EXPECTED_MAP,source_tree=g.EXPECTED_TREE,publication=dict(path='/FENCED/publication.json',**m['publication_pin']),storage_profile=None)
    spec=g.decode((g.HERE/'llvm-v2/independent-reader-v7/pins.json').read_bytes())['output_namespace']
    proof=lambda a,b,n:dict(before_sha256=a,after_sha256=b,seams=n,inverse='EXACT_FUNCTION_BYTES')
    projection=dict(commands=proof('c0ecf2118bc95709ef778511f0914e0684457066a49d9372c95f548f98edb3b8','ad0389032f75ac7cce845203501aa76f1d0a10c2e656fcd539708aa55292b189',5),replay=proof('8c5983d5533345eb9246f0e34551275deca04c5613143cebde8dc40da1075508','17ce8dd7407010505cba6dbc51a67bf3e2c779ab7e4d2c6f3636ca2bb1f049a0',1),absent_image_stdout=proof('c2b59ef95f7fba1738c8e3fc41674fc758c69e7cdac2d6e1f97ba30feeea1de2','6c43d85fec3c3e727bcb3404dfdb23cec1a04d008ab2bc8811e1b7efaa203d98',1),actual_tuple_projection=False)
    projection.update(buildinfo=proof('17ce8dd7407010505cba6dbc51a67bf3e2c779ab7e4d2c6f3636ca2bb1f049a0','1054bf8582245500cb8e7fa5917a3b4f1b7ace491c12645eb6a660d379c482c9',1),architecture_basis='LLVM23_SOURCE260_BASE349_ARCHITECTURE_METADATA_V1')
    result=dict(schema=1,status='PASS_INDEPENDENT_LLVM23_BUILDINFO_ARCHITECTURE_SUCCESSOR_DATA_ONLY',binding_sha256='1'*64,actual=copy.deepcopy(actual),source_tree=g.EXPECTED_TREE,source_files=260,verified_historical_inverse=[256,253,251,248],package=dict(bytes=1,sha256='f'*64),native_acceptance=False,Root_authentication=False,Root_acceptance=None,holds='native16K/M2/performance/release remain held',command_namespace=dict(files=44,bytes=1,command_receipts=spec['command_receipts'],facts=spec['facts'],runtime_and_build_success_separate=True),passive_projection=projection,storage=dict(mode='STRICT_REPORTED_INODES',reservation=False))
    result['buildinfo_architecture']=dict(rows=349,architectures=dict(aarch64=300,any=49),selected_packages=256,rootfs_only_packages=93,selected_version_replacements=71,basis='SOURCE_PINNED_SIGNED_BOOTSTRAP_INPUT_METADATA_NOT_OUTPUT_BUILDINFO',required_external_architecture_input=None,fresh_signature_verification=False,rootfs_body_reread=False,output_BUILDINFO_used_as_architecture_authority=False)
    return llvm,binding,result,m


class Controls(unittest.TestCase):
    def test_notice_binding_projects_only_after_exact_successor_validation(self):
        binding=g.candidate_binding()
        candidate=dict(commit=binding['base_commit'],inputs_sha256=g.base().INPUTS_SHA,
                       qualification={'FENCED':'NOT_A_QUALIFICATION'},notice_binding=binding)
        llvm={key:{'FENCED':'NOT_ACCEPTED_LLVM'} for key in ('source','archive','signature','public_test_key','verification_proof','root_decision','artifact','original')}
        value=dict(candidate=candidate,authorization={'FENCED':'NOT_ROOT'},llvm=llvm)
        projected=g.projection(value)
        self.assertEqual(projected['candidate'],{key:candidate[key] for key in ('commit','inputs_sha256','qualification')})
        self.assertEqual(value['candidate']['notice_binding'],binding)
        self.assertNotIn('authorization',projected)
        self.assertEqual(g.base().CANDIDATE,binding['base_commit'])
        for mutation in ('missing','tree','extra','base'):
            bad=copy.deepcopy(value)
            if mutation=='missing':bad['candidate'].pop('notice_binding')
            elif mutation=='extra':bad['candidate']['notice_binding']['waiver']=True
            elif mutation=='base':bad['candidate']['notice_binding']['base_commit']='0'*40
            else:bad['candidate']['notice_binding']['tree']='0'*40
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):g.projection(bad)
    def test_source_audit_stays_exactly_five_fields_before_material_gate(self):
        audit=dict(status='REVIEWED_FOR_THIS_PRIVATE_BUILD',library_cargo_config_sha256='a'*64,
                   consumed_git_dependencies_and_paths_reviewed=True,compiler_rt_libunwind_members_and_notices_reviewed=True,
                   retained_source_authentication_rejoined=True)
        value=dict(schema=4,status='ROOT_ADMITTED_RUST199_SOURCE_RESOURCE_ONCE',source=dict(sha='a'*40,ref='refs/heads/codex/FENCED_NOT_ROOT',map_sha256='b'*64,approval='c'*64,run=None,job=None),
                   resources=g.decode((g.HERE/'resource-policy.json').read_bytes()),once=True,retry=False,holds_preserved=True,
                   reviews={key:True for key in g.REVIEWS},source_audit=audit,delivery={},bootstrap={},llvm={},claims=g.CLAIMS)
        with patch.object(g,'llvm_declaration',side_effect=ValueError('FENCED_AFTER_EXACT_SOURCE_AUDIT')):
            with self.assertRaisesRegex(ValueError,'FENCED_AFTER_EXACT_SOURCE_AUDIT'):g.validate_dispatch(value)
            for mutation in ('extra','missing','false','digest'):
                bad=copy.deepcopy(value)
                if mutation=='extra':bad['source_audit']['waiver']=True
                elif mutation=='missing':bad['source_audit'].pop('status')
                elif mutation=='false':bad['source_audit']['retained_source_authentication_rejoined']=False
                else:bad['source_audit']['library_cargo_config_sha256']=None
                with self.subTest(mutation=mutation),self.assertRaises(ValueError) as error:g.validate_dispatch(bad)
                self.assertNotEqual(str(error.exception),'FENCED_AFTER_EXACT_SOURCE_AUDIT')
    def test_null_or_incomplete_dispatch_refuses_before_delivery(self):
        for value in ({},None,dict(schema=4,status='UNADMITTED'),dict(schema=1,status='ROOT_ADMITTED_RUST199_NATIVE_PRIVATE_BUILD')):
            with self.assertRaises(ValueError):g.validate_dispatch(value)
    def test_source_resource_and_provider_bindings_are_separate(self):
        source=dict(sha='a'*40,ref='refs/heads/codex/FENCED',map_sha256='b'*64,approval='c'*64,run=None,job=None)
        g.source_binding(source,True)
        with self.assertRaises(ValueError):g.source_binding(source,False)
        actual=dict(source,run='1',job='2');g.source_binding(actual,False)
        with self.assertRaises(ValueError):g.source_binding(actual,True)
    def test_missing_authorization_cannot_fall_back_to_old_full_admission(self):
        with self.assertRaises(ValueError):g.projection({'schema':1,'status':'ROOT_ADMITTED_RUST199_NATIVE_PRIVATE_BUILD'})
    def test_published260_metadata_and_final_reader_static_with_acceptance_pending(self):
        m=g.metadata();self.assertTrue(g.same(m['identity'],g.EXPECTED_IDENTITY))
        self.assertEqual(m['identity']['sha'],g.EXPECTED_SOURCE);self.assertEqual(m['identity']['ref'],g.EXPECTED_REF)
        self.assertEqual(m['actual']['publication'],m['publication_pin'])
        self.assertTrue(all(x is None for key,x in m['actual'].items()if key!='publication'))
        self.assertTrue(g.same(m['independent_reader'],g.FINAL_READER));self.assertIsNone(m['pending'])
    def test_final_reader_contract_pins_all_nine_archived_leaves_without_execution(self):
        m=g.metadata();self.assertTrue(g.same(g.reader_contract(m),g.FINAL_READER))
        bad=copy.deepcopy(m);bad['independent_reader']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'final Root Reader'):g.reader_contract(bad)
        source=g.HERE/'llvm-v2/independent-reader-v7';leaves=tuple(g.FINAL_READER['files'])
        bodies={name:(source/name).read_bytes()for name in leaves}
        with tempfile.TemporaryDirectory(prefix='FENCED-reader-static-')as temp:
            root=Path(temp);target=root/'llvm-v2/independent-reader-v7';target.mkdir(parents=True)
            for name,raw in bodies.items():(target/name).write_bytes(raw)
            with patch.object(g,'HERE',root):
                g.reader_contract(m)
                for name,raw in bodies.items():
                    (target/name).write_bytes(raw+b'FENCED_TAMPER')
                    with self.subTest(leaf=name),self.assertRaisesRegex(ValueError,'final Reader DATA leaf pin'):g.reader_contract(m)
                    (target/name).write_bytes(raw)
        text=(PAYLOAD/'admission.py').read_text();self.assertNotIn('PASS_INDEPENDENT_ROOT_BOUND_LLVM23_CORRECTED253_DATA_ONLY',text)
    def test_llvm260_exact_publication_is_required_before_material_gate(self):
        m=g.metadata();identity=copy.deepcopy(m['identity'])
        publication=copy.deepcopy(m['publication'])
        llvm=dict.fromkeys(('archive','signature','public_test_key','verification_proof','root_decision','artifact','original','reader'))
        llvm['artifact']=copy.deepcopy(g.EXPECTED_NATIVE_CASE['Original'])
        llvm.update(source=dict(sha=g.EXPECTED_SOURCE,ref=g.EXPECTED_REF,run=g.EXPECTED_NATIVE_CASE['run'],job=g.EXPECTED_NATIVE_CASE['job']),source_identity=identity,publication=publication,policy=dict(**m['policy_pin'],resources=m['policy']))
        with patch.object(g,'reader_contract',side_effect=ValueError('FENCED_AFTER_EXACT_PUBLICATION_JOIN')):
            with self.assertRaisesRegex(ValueError,'FENCED_AFTER_EXACT_PUBLICATION_JOIN'):g.llvm_declaration(llvm,True)
            for section,field in (('source','sha'),('source','ref'),('source','run'),('source','job'),('artifact','id'),('artifact','bytes'),('artifact','sha256'),('source_identity','tree'),('source_identity','profile_sha256'),('publication','source'),('publication','tree'),('publication','files'),('publication','actual_observed_utc')):
                bad=copy.deepcopy(llvm);bad[section][field]='FENCED_WRONG'
                with self.subTest(section=section,field=field),self.assertRaises(ValueError)as error:g.llvm_declaration(bad,True)
                self.assertNotEqual(str(error.exception),'FENCED_AFTER_EXACT_PUBLICATION_JOIN')
    def test_new_reader_component_joins_all_provider_commit_export_and_decode_pins(self):
        llvm,binding,result,m=reader_component();g._reader_evidence(llvm,binding,result,m)
        for key in ('provider_sha256','source_commit_sha256','export_sha256','reader_sha256','pins_sha256','package_sha256'):
            bad=copy.deepcopy(binding);bad[key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):g._reader_evidence(llvm,bad,result,m)
        for key,value in (('bytes',True),('bytes',8*1024**3+1),('files',1.0),('files',4097),('map_sha256',None)):
            bad=copy.deepcopy(binding);bad['full_original_decode'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):g._reader_evidence(llvm,bad,result,m)
    def test_new_reader_refuses_old_status_wrong_source_or_acceptance_claims(self):
        llvm,binding,result,m=reader_component()
        for key,value in (('status','PASS_INDEPENDENT_ROOT_BOUND_LLVM23_PUBLISHED256_DATA_ONLY'),('status','PASS_INDEPENDENT_LLVM23_RECEIPT_SUCCESSOR_DATA_ONLY'),('status','PASS_INDEPENDENT_LLVM23_ABSENT_IMAGE_STDOUT_SUCCESSOR_DATA_ONLY'),('source_files',256),('source_files',260.0),('verified_historical_inverse',[256,251,248]),('native_acceptance',True),('Root_authentication',True),('Root_acceptance',True)):
            bad=copy.deepcopy(result);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):g._reader_evidence(llvm,binding,bad,m)
        bad=copy.deepcopy(binding);bad['actual']['source']='6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0'
        with self.assertRaises(ValueError):g._reader_evidence(llvm,bad,result,m)
        for scope in ('ROOT_BOUND_LLVM23_INDEPENDENT_READER_V4','ROOT_BOUND_LLVM23_INDEPENDENT_READER_V5','ROOT_BOUND_LLVM23_INDEPENDENT_READER_V6'):
            bad=copy.deepcopy(binding);bad['scope']=scope
            with self.assertRaises(ValueError):g._reader_evidence(llvm,bad,result,m)
    def test_reader7_publication_namespace_and_absent_stdout_projection_refuse_tamper(self):
        llvm,binding,result,m=reader_component()
        for field,value in (('sha256','0'*64),('bytes',True),('path','/../FENCED')):
            bad=copy.deepcopy(binding);bad['publication'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):g._reader_evidence(llvm,bad,result,m)
        for mode in ('receipt_alias','missing_stdout_proof','wrong_stdout_proof','projected_tuple'):
            bad=copy.deepcopy(result)
            if mode=='receipt_alias':bad['command_namespace']['command_receipts']['tools']='tools.json'
            elif mode=='missing_stdout_proof':bad['passive_projection'].pop('absent_image_stdout')
            elif mode=='wrong_stdout_proof':bad['passive_projection']['absent_image_stdout']['after_sha256']='0'*64
            else:bad['passive_projection']['actual_tuple_projection']=True
            with self.subTest(mode=mode),self.assertRaises(ValueError):g._reader_evidence(llvm,binding,bad,m)
    def test_reader7_storage_profile_is_whole_bounded_and_preserves_real_domains(self):
        llvm,binding,result,m=reader_component();binding['storage_profile']=dict(path='/FENCED/storage.json',bytes=1,sha256='a'*64)
        with self.assertRaises(ValueError):g._reader_evidence(llvm,binding,result,m)
        result['storage']=dict(mode='ROOT_REVIEWED_BTRFS_UNREPORTED_INODES',available_bytes=20*1024**3,inode_accounting='UNREPORTED',fstat_device=54,kernel_mount_device='0:33',mount_id=62,reservation=False,quota_claim=None)
        g._reader_evidence(llvm,binding,result,m)
        for field,value in (('available_bytes',20*1024**3-1),('fstat_device',True),('kernel_mount_device','54'),('mount_id',54),('reservation',True),('quota_claim','FENCED')):
            bad=copy.deepcopy(result);bad['storage'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):g._reader_evidence(llvm,binding,bad,m)
    def test_reader7_349_architecture_map_and_epoch_projection_refuse_tamper(self):
        llvm,binding,result,m=reader_component();g._reader_evidence(llvm,binding,result,m)
        for field,value in (('rows',348),('rows',349.0),('architectures',dict(aarch64=349,any=0)),('architectures',dict(aarch64=300,any=49,x86_64=0)),('selected_packages',255),('rootfs_only_packages',94),('selected_version_replacements',70),('basis','OUTPUT_BUILDINFO'),('required_external_architecture_input','FENCED'),('fresh_signature_verification',True),('rootfs_body_reread',True),('output_BUILDINFO_used_as_architecture_authority',True)):
            bad=copy.deepcopy(result);bad['buildinfo_architecture'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):g._reader_evidence(llvm,binding,bad,m)
        for field in ('before_sha256','after_sha256'):
            bad=copy.deepcopy(result);bad['passive_projection']['buildinfo'][field]='0'*64
            with self.subTest(epoch_encoding_proof=field),self.assertRaises(ValueError):g._reader_evidence(llvm,binding,bad,m)
        bad=copy.deepcopy(result);bad['passive_projection']['architecture_basis']='OUTPUT_BUILDINFO'
        with self.assertRaises(ValueError):g._reader_evidence(llvm,binding,bad,m)
    def test_unqualified_or_wrong_test_proofs_stop_before_reader_or_root_acceptance(self):
        row=lambda:dict(local_path='/FENCED/not-a-file',bytes=1,sha256='a'*64)
        llvm={name:row()for name in g.ROLES};llvm['reader']=dict(binding=row(),result=row());llvm['public_test_key'].update(fingerprint='F'*40,trust_scope='TEST_ONLY')
        files={role:row()for role in (*g.ROLES.values(),'reader_binding','reader_result')}
        signature=dict(schema=1,status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',verified=True,archive=dict(bytes=1,sha256='a'*64),signature=dict(bytes=1,sha256='a'*64),public_test_key=dict(bytes=1,sha256='a'*64,fingerprint='F'*40,trust_scope='TEST_ONLY'),trust_scope='TEST_ONLY')
        for mode in ('unqualified','wrong_package','wrong_key','wrong_scope','no_Root_decision','boolean_schema'):
            bad=copy.deepcopy(signature)
            if mode=='unqualified':bad['verified']=False
            elif mode=='wrong_package':bad['archive']['sha256']='0'*64
            elif mode=='wrong_key':bad['public_test_key']['fingerprint']='B'*40
            elif mode=='wrong_scope':bad['trust_scope']='PRODUCTION'
            elif mode=='boolean_schema':bad['schema']=True
            with self.subTest(mode=mode),patch.object(g,'llvm_declaration'),patch.object(g,'_json',side_effect=[bad,dict(schema=1,issuer='FENCED_NOT_ROOT',accepted=False),{},{}]),patch.object(g,'read_file',side_effect=AssertionError('material reads forbidden'))as material,patch.object(g,'_reader_evidence')as reader:
                with self.assertRaises(ValueError):g.validate_llvm_material(llvm,files)
                reader.assert_not_called();material.assert_not_called()
    def test_missing_root_decision_or_reader_result_refuses_before_material_reads(self):
        row=lambda:dict(local_path='/FENCED/not-a-file',bytes=1,sha256='a'*64)
        llvm={name:row()for name in g.ROLES};llvm['reader']=dict(binding=row(),result=row())
        files={role:row()for role in (*g.ROLES.values(),'reader_binding','reader_result')}
        for position in (1,3):
            answers=[{'FENCED':'NOT_A_PROOF'}]*4;answers[position]=FileNotFoundError('FENCED missing external proof')
            with self.subTest(position=position),patch.object(g,'llvm_declaration'),patch.object(g,'_json',side_effect=answers),patch.object(g,'read_file',side_effect=AssertionError('material reads forbidden'))as material:
                with self.assertRaises(FileNotFoundError):g.validate_llvm_material(llvm,files)
                material.assert_not_called()
    def test_root_decision_false_wrong_archive_wrong_proof_pin_or_boolean_schema_refuses(self):
        # Every selector and package name below is explicitly non-operational.
        # Only the earlier declaration/file seams are mocked; no admitted grant.
        row=lambda:dict(local_path='/FENCED/not-a-file',bytes=1,sha256='a'*64)
        llvm={name:row()for name in g.ROLES};llvm.update(reader=dict(binding=row(),result=row()),source={'FENCED':'NOT_A_SOURCE'},artifact={'FENCED':'NOT_AN_ARTIFACT'},original={'FENCED':'NOT_AN_ORIGINAL'})
        llvm['archive'].update(package='FENCED_NOT_LLVM',version='FENCED',arch='FENCED');llvm['public_test_key'].update(fingerprint='F'*40,trust_scope='TEST_ONLY')
        files={role:row()for role in (*g.ROLES.values(),'reader_binding','reader_result')}
        pin=lambda r:{k:r[k]for k in ('bytes','sha256')}
        key={**pin(llvm['public_test_key']),**{k:llvm['public_test_key'][k]for k in ('fingerprint','trust_scope')}}
        signature=dict(schema=1,status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',verified=True,archive=pin(llvm['archive']),signature=pin(llvm['signature']),public_test_key=key,trust_scope='TEST_ONLY')
        decision=dict(FENCED='NOT_AN_ACTUAL_ROOT_DECISION',schema=1,issuer='Root',accepted=False,holds_preserved=True,status='ACCEPTED_PRIVATE_LLVM23_PACKAGE_TEST_ONLY',source=llvm['source'],artifact=llvm['artifact'],original=llvm['original'],archive={k:llvm['archive'][k]for k in ('bytes','sha256','package','version','arch')},signature=pin(llvm['signature']),public_test_key=key,verification_proof_sha256='a'*64)
        for mode in ('unaccepted','archive','proof_pin','boolean_schema'):
            bad=copy.deepcopy(decision)
            if mode!='unaccepted':bad['accepted']=True
            if mode=='archive':bad['archive']['sha256']='0'*64
            elif mode=='proof_pin':bad['verification_proof_sha256']='0'*64
            elif mode=='boolean_schema':bad['schema']=True
            with self.subTest(mode=mode),patch.object(g,'llvm_declaration'),patch.object(g,'_json',side_effect=[signature,bad,{},{}]),patch.object(g,'read_file',side_effect=AssertionError('material reads forbidden'))as material,patch.object(g,'_reader_evidence',side_effect=AssertionError('Reader must not follow refused Root claim'))as reader:
                with self.assertRaises(ValueError):g.validate_llvm_material(llvm,files)
                material.assert_not_called();reader.assert_not_called()
    def test_native_qualification_cannot_skip_actual_provider_and_nine_probes(self):
        with self.assertRaises((ValueError,KeyError,TypeError)):g.check_phase_bridge({'source':{}},{},dict(status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY'))
        good=dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0)
        self.assertTrue(g.natural(good))
        for key in good:
            bad=dict(good);bad.pop(key);self.assertFalse(g.natural(bad))
    def test_canonical_typed_join_rejects_boolean_and_float_aliases(self):
        self.assertFalse(g.same({'schema':1},{'schema':True}));self.assertFalse(g.same({'bytes':1},{'bytes':1.0}))
    def test_actor_namespace_expands_exactly_three_proof_operands(self):
        raw=(PAYLOAD/'actor/entry.py').read_text();self.assertIn("len(seen)==16",raw)
        self.assertEqual(set(g.AUTH_PATHS),{'dispatch','provider','qualification'})
        self.assertIn('admission.external_proofs(mapped)',raw);self.assertIn('volume.verify_work(',raw)


if __name__=='__main__':unittest.main()
