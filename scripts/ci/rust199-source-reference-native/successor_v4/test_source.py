# SPDX-License-Identifier: MIT
"""Portable v4 Source DATA/closure controls; no archived Reader executes."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('FENCED_v4_source',HERE/'prepare.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

class SourceControls(unittest.TestCase):
    def test_checkpoint_and_unadmitted_template_hold(self):
        metadata=json.loads((HERE/'payload/llvm-v2/source.json').read_bytes());policy=json.loads((HERE/'payload/resource-policy.json').read_bytes())
        value=json.loads(p.template((HERE.parent/'root-admission.TEMPLATE.json').read_bytes(),metadata,policy))
        self.assertEqual(value['status'],'UNADMITTED');self.assertEqual(value['schema'],4)
        self.assertTrue(all(v is None for v in value['source'].values()));self.assertFalse(any(value['reviews'].values()))
        self.assertIsNone(value['llvm']['publication']);self.assertIsNone(value['llvm']['source']['sha']);self.assertIsNone(value['bootstrap']['transfer_redirect_hosts'])
        for kind in ('llvm_original','stage0_carrier','root_proof_carrier'):
            self.assertIsNone(value['delivery'][kind]['id']);self.assertFalse(value['delivery'][kind]['accepted_by_root'])
        self.assertIn('SUPERSEDED',p.PENDING)
    def test_frozen_bootstrap_gate_and_reader_data_pins(self):
        root=HERE/'payload';m=json.loads((root/'llvm-v2/source.json').read_bytes());self.assertEqual(m['identity'],p.LLVM)
        for leaf,key in (('policy.json','policy_pin'),('reader.py','reader_program'),('contract.json','contract_pin'),('candidate-map.json','candidate_map_pin')):
            self.assertEqual(p.fs.pin((root/'llvm-v2'/leaf).read_bytes()),{k:m[key][k]for k in ('bytes','sha256')})
        self.assertEqual(p.fs.pin((root/'frozen/bootstrap349.py').read_bytes())['sha256'],'27e17683ba185d6959307b081ab86be4c7740ef5dbb8dff9c850670eda2ec008')
        self.assertEqual(p.fs.pin((root/'frozen/rust199-admission-v1.py').read_bytes())['sha256'],'a548f56b0759ae2ecd90ee79fed8c1e254a032dbaa0726f15e673e139b946c30')
    def test_exact_data_capture_and_drift(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-v4-DATA-')as directory:
            root=Path(directory);rows={'data':(b'FENCED NOT A SOURCE',0o644)};rows['source-map.json']=(p.encode(dict(files=p.fs.descriptors(rows))),0o644)
            for n,(raw,mode)in rows.items():(root/n).write_bytes(raw);(root/n).chmod(mode)
            identity=dict(files=2,bytes=sum(len(v)for v,_ in rows.values()),tree=p.fs.tree(rows),map_sha256=p.fs.pin(rows['source-map.json'][0])['sha256'])
            self.assertEqual(p.capture(root,identity),rows)
            (root/'data').write_bytes(b'FENCED CHANGED DATA')
            with self.assertRaises(ValueError):p.capture(root,identity)
    def test_wrong_parents_refuse_before_overlay(self):
        with self.assertRaises(ValueError):p.render({},{})
    def test_all_new_python_parse_as_data(self):
        for path in HERE.rglob('*.py'):ast.parse(path.read_bytes(),filename=str(path))
        raw=(HERE/'prepare.py').read_text();self.assertNotIn('subprocess',raw);self.assertNotIn('reader.read(',raw)
    def test_constructor_closure_is_exact_and_profiled(self):
        profile=json.loads((HERE/'constructor-profile.json').read_bytes())
        self.assertEqual(profile['constructor_files'],p.inputs());self.assertEqual(profile['parent'],p.PARENT);self.assertEqual(profile['pending'],p.PENDING)

if __name__=='__main__':unittest.main()
