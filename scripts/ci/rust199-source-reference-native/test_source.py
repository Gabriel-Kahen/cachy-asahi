# SPDX-License-Identifier: MIT
"""Fenced Source DATA/inverse and early refusal controls; no actor entry import."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('rust_source_constructor',HERE/'prepare.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
FROZEN=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-rust-submodule-closure-20261115/scripts/ci/llvm23-source-reference-native/work/source-tree-r3')


class SourceControls(unittest.TestCase):
    def test_recipe_seams_inverse_and_no_dependency_bypass(self):
        raw=(HERE/'candidate/PKGBUILD').read_bytes();new,changes=p.recipe(raw)
        self.assertEqual(len(changes),3)
        for row in reversed(changes):new=new.replace(row['after'].encode(),row['before'].encode())
        self.assertEqual(new,raw)
        with self.assertRaises(ValueError):p.recipe(raw.replace(b'python -I',b'python -B',1))
        self.assertIn(b"'cachy-asahi-llvm23-source-reference=23.1.1'",raw)
        self.assertNotIn(b'--nodeps',(HERE/'payload/actor/entry.py').read_bytes())
    def test_data_membership_modes_inverse_and_opaque_exclusion(self):
        files=p.render(FROZEN);m=json.loads(files['source-map.json'][0]);inverse=json.loads(files['inverse.json'][0])
        self.assertEqual(m['files'],p.fs.descriptors({n:v for n,v in files.items() if n!='source-map.json'}))
        original={n:v for n,v in files.items() if n not in inverse['additions']}
        self.assertEqual(len(original),200);self.assertEqual(p.fs.tree(original),inverse['before_tree'])
        self.assertTrue(all(v is None for v in m['actual'].values()))
        self.assertFalse(any(n.endswith(('.tar.xz','.pkg.tar.zst')) for n in files))
        self.assertEqual(files['.github/workflows/native-arm-build.yml'],files['.github/workflows/native-arm-rust199-source-reference-v1.yml'])
        self.assertTrue(all(mode in (0o644,0o755) for _,mode in files.values()))
    def test_helper_exact_one_literal_inverse(self):
        d=json.loads((HERE/'derivation.json').read_bytes())['owned_child'];raw=(HERE/'payload/helpers/owned_child.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),d['after_sha256'])
        self.assertEqual(raw.count(d['new_literal'].encode()),1)
        before=raw.replace(d['new_literal'].encode(),d['old_literal'].encode())
        self.assertEqual(hashlib.sha256(before).hexdigest(),d['before_sha256'])
    def test_wrong_profile_and_preexisting_output_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700);output=root/'source';output.mkdir()
            with self.assertRaises(ValueError):p.construct(FROZEN,output,'0'*64)
            with self.assertRaises(ValueError):p.fs.publish({'x':(b'x',0o644)},output)
    def test_pipeline_python_is_source_parseable(self):
        for name,row in p.profile_inputs().items():
            if name.endswith('.py'):ast.parse((HERE/name).read_bytes(),filename=name)
    def test_unqualified_template_refuses_without_external_reads(self):
        s=importlib.util.spec_from_file_location('rust_gate_data',HERE/'admission.py');gate=importlib.util.module_from_spec(s);s.loader.exec_module(gate)
        original=gate.read_file
        def forbidden(*a,**k):raise AssertionError('NULL gate must refuse before reading external inputs')
        gate.read_file=forbidden
        try:
            with self.assertRaises((ValueError,KeyError,TypeError)):gate.validate(json.loads((HERE/'root-admission.TEMPLATE.json').read_bytes()))
        finally:gate.read_file=original


if __name__=='__main__':unittest.main()
