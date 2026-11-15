# SPDX-License-Identifier: MIT
"""FENCED admission component controls; no qualified operational Root fixture."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('v4_admission_DATA',HERE/'payload/admission.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)


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
    def test_corrected253_metadata_static_only_and_closed6d_not_selected(self):
        m=g.metadata();self.assertEqual(m['identity']['tree'],g.EXPECTED_TREE);self.assertEqual(m['identity']['map_sha256'],g.EXPECTED_MAP)
        self.assertIsNone(m['identity']['sha']);self.assertIsNone(m['identity']['ref'])
        self.assertTrue(all(x is None for x in m['actual'].values()))
        self.assertEqual(m['independent_reader']['sha256'],'1edb14485c8df4b880750e0d783fe4f732e88ed9d17119ef491fb7cfe65cd8c6')
    def test_root_decision_and_reader_are_not_generated_by_runtime_qualification(self):
        text=(HERE/'payload/admission.py').read_text()
        self.assertIn("decision['accepted']is True",text);self.assertIn("result['Root_acceptance']is None",text)
        self.assertIn('validate_llvm_material(dispatch[\'llvm\'],delivered[\'files\'])',text)
        self.assertIn("proof=dict(schema=1,status='QUALIFIED_FOR_THIS_SOURCE'",text)
        self.assertIn("check_phase_bridge(dispatch,provider,qualification)",text)
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
