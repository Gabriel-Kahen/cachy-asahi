# SPDX-License-Identifier: MIT
"""Portable finite constructor controls; no archived program or native role executes."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('rust_llvm_v2_source_DATA',HERE/'prepare.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p)


class SourceControls(unittest.TestCase):
    def test_exact_actor_namespace_projection_and_inverse(self):
        before=(HERE/'fixtures/actor-entry-v2.py.data').read_bytes();after=p.actor_entry(before)
        old=b"need(len(seen)==11,'complete eleven Root external proof operands')";new=b"need(len(seen)==13,'complete thirteen Root external proof operands')"
        self.assertEqual(after.replace(new,old),before);ast.parse(after)
        for drift in (before.replace(old,b'FENCED-drift'),before+old):
            with self.assertRaises(ValueError):p.actor_entry(drift)
        self.assertIn(b'WORK_VOLUME_ADMISSION_SHA256',after)
        self.assertIn(b'volume.verify_work(',after)
    def test_finite_metadata_policy_reader_and_frozen_gate_pins(self):
        root=HERE/'payload';m=json.loads((root/'llvm-v2/source.json').read_bytes())
        self.assertEqual(m['identity'],p.LLVM);self.assertTrue(all(v is None for v in m['actual'].values()))
        for source,key in (('policy.json','policy_pin'),('reader.py','reader_program'),('contract.json','contract_pin'),('candidate-map.json','candidate_map_pin')):
            raw=(root/'llvm-v2'/source).read_bytes();self.assertEqual(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),{k:m[key][k] for k in ('bytes','sha256')})
        self.assertEqual(hashlib.sha256((root/'frozen/rust199-admission-v1.py').read_bytes()).hexdigest(),'a548f56b0759ae2ecd90ee79fed8c1e254a032dbaa0726f15e673e139b946c30')
        self.assertEqual(m['policy']['work_volume_initialization']['seconds'],120)
    def test_future_template_does_not_invent_runtime_or_acceptance(self):
        m=json.loads((HERE/'payload/llvm-v2/source.json').read_bytes());before=(HERE.parent/'root-admission.TEMPLATE.json').read_bytes()
        a=json.loads(p.template(before,m));self.assertEqual(a['status'],'UNADMITTED');llvm=a['llvm']
        self.assertEqual(llvm['source']['sha'],p.LLVM['sha']);self.assertEqual(llvm['source']['ref'],p.LLVM['ref'])
        self.assertIsNone(llvm['source']['run']);self.assertIsNone(llvm['source']['job'])
        self.assertTrue(all(v is None for v in llvm['original'].values()))
        self.assertIsNone(llvm['archive']['sha256']);self.assertIsNone(llvm['root_decision']['sha256'])
        for name in ('binding','result'):
            for key in ('local_path','bytes','sha256'):self.assertIsNone(llvm['reader'][name][key])
    def test_capture_closes_fenced_data_bytes_modes_membership(self):
        # A tiny FENCED data tree exercises the reader, never render()/construct().
        with tempfile.TemporaryDirectory(prefix='FENCED-Source-DATA-') as temp:
            root=Path(temp);files={'data':(b'FENCED_NOT_A_SOURCE_PACKET',0o644)}
            files['source-map.json']=(p.encode(dict(schema='FENCED',files=p.fs.descriptors(files))),0o644)
            for name,(raw,mode) in files.items():(root/name).write_bytes(raw);(root/name).chmod(mode)
            identity=dict(files=2,bytes=sum(len(raw) for raw,_ in files.values()),tree=p.fs.tree(files),map_sha256=p.fs.pin(files['source-map.json'][0])['sha256'])
            self.assertEqual(p.capture(root,identity),files)
            (root/'data').chmod(0o755)
            with self.assertRaises(ValueError):p.capture(root,identity)
            (root/'data').chmod(0o644);(root/'extra').write_bytes(b'FENCED')
            with self.assertRaises(ValueError):p.capture(root,identity)
    def test_render_refuses_fenced_or_wrong_parent_before_any_overlay(self):
        for before,llvm in (({},{}),({'FENCED':(b'DATA',0o644)},{})):
            with self.assertRaises(ValueError):p.render(before,llvm)
    def test_frozen_llvm_snapshot_programs_are_parseable_data_only(self):
        ast.parse((HERE/'payload/llvm-v2/reader.py').read_bytes())
        ast.parse((HERE/'payload/frozen/rust199-admission-v1.py').read_bytes())
        text=(HERE/'prepare.py').read_text()
        self.assertNotIn('subprocess',text);self.assertNotIn('reader.read(',text)
        self.assertIn("LLVM_V2_SOURCE_POLICY_READER_ROOT_DECISION_REJOIN_ONLY_NO_ROLES",text)
    def test_ci_routing_requires_separate_processes(self):
        route=json.loads((HERE/'ci-routing.json').read_bytes())
        self.assertEqual(route['isolation'],'ONE_PYTHON_PROCESS_PER_SCRIPT')
        self.assertEqual(route['base_test_changes'],[]);self.assertFalse(route['relax_permanent_audit_fence'])
        self.assertEqual(len(route['commands']),2)


if __name__=='__main__':unittest.main()
