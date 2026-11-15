# SPDX-License-Identifier: MIT
"""FENCED admission component controls; no qualified operational Root fixture."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('v5_admission_DATA',HERE/'payload/admission.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)


def reader_component():
    """FENCED binding shape only: no Root decision or operational admission."""
    m=g.metadata();m['independent_reader']=dict(sha256='a'*64,pins=dict(sha256='b'*64))
    actual=dict(source=g.EXPECTED_SOURCE,ref=g.EXPECTED_REF,run='101',job='102',attempt=1,approval='c'*64,authority='FENCED_NOT_ROOT',image='sha256:'+'d'*64,artifact='103',reader='FENCED_NOT_A_READER_RUN')
    llvm=dict(source=dict(sha=g.EXPECTED_SOURCE,ref=g.EXPECTED_REF,run='101',job='102'),artifact=dict(id='103',bytes=1,sha256='e'*64),archive=dict(bytes=1,sha256='f'*64),reader=dict(binding=dict(sha256='1'*64)))
    binding=dict(schema=1,scope='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V4',actual=actual,export_sha256='2'*64,full_original_decode=dict(bytes=1,files=1,map_sha256='3'*64),holds_preserved=True,operation=g.EXPECTED_IDENTITY['operation'],original_archive=dict(bytes=1,sha256='e'*64),package_sha256='f'*64,pins_sha256='b'*64,policy_sha256=m['policy_pin']['sha256'],provider_sha256='4'*64,reader_sha256='a'*64,source_commit_sha256='5'*64,source_map_sha256=g.EXPECTED_MAP,source_tree=g.EXPECTED_TREE)
    result=dict(schema=1,status='PASS_INDEPENDENT_ROOT_BOUND_LLVM23_PUBLISHED256_DATA_ONLY',binding_sha256='1'*64,actual=copy.deepcopy(actual),source_tree=g.EXPECTED_TREE,source_files=256,verified_historical_inverse=[253,251,248],package=dict(bytes=1,sha256='f'*64),native_acceptance=False,Root_authentication=False,Root_acceptance=None,holds='native16K/M2/performance/release remain held')
    return llvm,binding,result,m


class Controls(unittest.TestCase):
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
    def test_published256_metadata_and_final_reader_static_with_acceptance_pending(self):
        m=g.metadata();self.assertTrue(g.same(m['identity'],g.EXPECTED_IDENTITY))
        self.assertEqual(m['identity']['sha'],g.EXPECTED_SOURCE);self.assertEqual(m['identity']['ref'],g.EXPECTED_REF)
        self.assertEqual(m['actual']['publication'],m['publication_pin'])
        self.assertTrue(all(x is None for key,x in m['actual'].items()if key!='publication'))
        self.assertTrue(g.same(m['independent_reader'],g.FINAL_READER));self.assertIsNone(m['pending'])
    def test_final_reader_contract_pins_all_four_archived_leaves_without_execution(self):
        m=g.metadata();self.assertTrue(g.same(g.reader_contract(m),g.FINAL_READER))
        bad=copy.deepcopy(m);bad['independent_reader']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'final Root Reader'):g.reader_contract(bad)
        source=g.HERE/'llvm-v2/independent-reader-v4';leaves=('reader.py','base.py','profile.json','pins.json')
        bodies={name:(source/name).read_bytes()for name in leaves}
        with tempfile.TemporaryDirectory(prefix='FENCED-reader-static-')as temp:
            root=Path(temp);target=root/'llvm-v2/independent-reader-v4';target.mkdir(parents=True)
            for name,raw in bodies.items():(target/name).write_bytes(raw)
            with patch.object(g,'HERE',root):
                g.reader_contract(m)
                for name,raw in bodies.items():
                    (target/name).write_bytes(raw+b'FENCED_TAMPER')
                    with self.subTest(leaf=name),self.assertRaisesRegex(ValueError,'final Reader DATA leaf pin'):g.reader_contract(m)
                    (target/name).write_bytes(raw)
        text=(HERE/'payload/admission.py').read_text();self.assertNotIn('PASS_INDEPENDENT_ROOT_BOUND_LLVM23_CORRECTED253_DATA_ONLY',text)
    def test_llvm256_exact_publication_is_required_before_material_gate(self):
        m=g.metadata();identity=copy.deepcopy(m['identity'])
        publication=copy.deepcopy(m['publication'])
        llvm=dict.fromkeys(('archive','signature','public_test_key','verification_proof','root_decision','artifact','original','reader'))
        llvm.update(source=dict(sha=g.EXPECTED_SOURCE,ref=g.EXPECTED_REF,run=None,job=None),source_identity=identity,publication=publication,policy=dict(**m['policy_pin'],resources=m['policy']))
        with patch.object(g,'reader_contract',side_effect=ValueError('FENCED_AFTER_EXACT_PUBLICATION_JOIN')):
            with self.assertRaisesRegex(ValueError,'FENCED_AFTER_EXACT_PUBLICATION_JOIN'):g.llvm_declaration(llvm,True)
            for section,field in (('source','sha'),('source','ref'),('source_identity','tree'),('source_identity','profile_sha256'),('publication','source'),('publication','tree'),('publication','files'),('publication','actual_observed_utc')):
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
        for key,value in (('status','PASS_INDEPENDENT_ROOT_BOUND_LLVM23_CORRECTED253_DATA_ONLY'),('source_files',253),('source_files',256.0),('verified_historical_inverse',[251,248]),('native_acceptance',True),('Root_authentication',True),('Root_acceptance',True)):
            bad=copy.deepcopy(result);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):g._reader_evidence(llvm,binding,bad,m)
        bad=copy.deepcopy(binding);bad['actual']['source']='6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0'
        with self.assertRaises(ValueError):g._reader_evidence(llvm,bad,result,m)
    def test_native_qualification_cannot_skip_actual_provider_and_nine_probes(self):
        with self.assertRaises((ValueError,KeyError,TypeError)):g.check_phase_bridge({'source':{}},{},dict(status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY'))
        good=dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0)
        self.assertTrue(g.natural(good))
        for key in good:
            bad=dict(good);bad.pop(key);self.assertFalse(g.natural(bad))
    def test_canonical_typed_join_rejects_boolean_and_float_aliases(self):
        self.assertFalse(g.same({'schema':1},{'schema':True}));self.assertFalse(g.same({'bytes':1},{'bytes':1.0}))
    def test_actor_namespace_expands_exactly_three_proof_operands(self):
        raw=(HERE/'payload/actor/entry.py').read_text();self.assertIn("len(seen)==16",raw)
        self.assertEqual(set(g.AUTH_PATHS),{'dispatch','provider','qualification'})
        self.assertIn('admission.external_proofs(mapped)',raw);self.assertIn('volume.verify_work(',raw)


if __name__=='__main__':unittest.main()
