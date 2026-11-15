# SPDX-License-Identifier: MIT
"""Synthetic Source DATA controls; never import or execute payload code."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('baseline_observation_prepare_test',HERE/'prepare.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def put(root,name,raw,mode=0o644):
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode);return path


def fixture(root):
    home,frozen=root/'constructor',root/'frozen';home.mkdir();frozen.mkdir()
    original={'original/data/held%03d.txt'%i:(b'PASSIVE BOOTSTRAP FIXTURE\n',0o644) for i in range(198)}
    original['original/native/expected349.lock']=(b'FIXTURE INVENTORY DATA\n',0o644)
    nested=p.encode(dict(schema=1,actual=dict(source=None,ref=None,run=None),files=p.fs.descriptors({name.removeprefix('original/'):row for name,row in original.items()})))
    original['original/native/source-map.json']=(nested,0o644)
    leaves=dict(original)
    leaves.update({'foreign/unused%03d.txt'%i:(b'PASSIVE NONREUSED FIXTURE\n',0o644) for i in range(71)})
    for name,(raw,mode) in leaves.items():put(frozen,name,raw,mode)
    outer=p.encode(dict(schema=1,actual=dict(source=None,ref=None,run=None),files=p.fs.descriptors(leaves)))
    put(frozen,'source-map.json',outer)
    pins=dict(schema=1,frozen_bootstrap_source_map_sha256=p.fs.pin(outer)['sha256'],original_source_map_sha256=p.fs.pin(nested)['sha256'],expected349_sha256=p.fs.pin(original['original/native/expected349.lock'][0])['sha256'])
    put(home,'held-source.json',p.encode(pins))
    for name in ('LICENSE','expected349.lock','policy.json','observer-policy.json','root-admission.TEMPLATE.json'):
        body=b'PASSIVE FIXTURE LICENSE\n'
        if name=='expected349.lock':body=original['original/native/expected349.lock'][0]
        if name in ('policy.json','observer-policy.json'):body=p.encode(dict(schema=1,operation=p.OPERATION))
        if name=='root-admission.TEMPLATE.json':body=p.encode(dict(status='UNADMITTED',source=None,authority=None))
        put(home,name,body)
    for name in p.PAYLOAD:put(home/'payload',name,b'PASSIVE SOURCE TEXT; NEVER IMPORTED\n')
    put(home,'workflow.yml.in',b'common=__COMMON_SHA__\nentry=__ENTRY_SHA__\n')
    return home,frozen,original,pins


class SourceTests(unittest.TestCase):
    def test_held_pins_and_separate_operation_are_concrete(self):
        pins=json.loads((HERE/'held-source.json').read_bytes())
        self.assertEqual(pins['frozen_bootstrap_source_map_sha256'],'4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96')
        self.assertEqual(pins['original_source_map_sha256'],'0c37bef7218caa6cb0f0e6d1b22ed5053b10a228f53e15076f5803d2fcf86b3e')
        self.assertEqual(p.OPERATION,'perl5423-baseline-observation-native-v1')
        self.assertEqual(hashlib.sha256((HERE/'filesystem.py').read_bytes()).hexdigest(),p.FS_SHA)

    def test_closed_source_has_null_selectors_and_no_future_config_prerequisite(self):
        with tempfile.TemporaryDirectory() as temporary:
            home,frozen,original,_pins=fixture(Path(temporary))
            with patch.object(p,'HERE',home):files=p.render(frozen)
            m=json.loads(files['source-map.json'][0]);contract=json.loads(files['contract.json'][0])
            self.assertEqual(m['files'],p.fs.descriptors({k:v for k,v in files.items() if k!='source-map.json'}))
            self.assertEqual(m['actual'],p.ACTUAL)
            self.assertTrue(all(value is None for value in m['actual'].values()))
            self.assertEqual(contract['operation'],p.OPERATION)
            self.assertEqual(contract['observer_policy_sha256'],p.fs.pin(files['observer-policy.json'][0])['sha256'])
            self.assertTrue(contract['mutation_qualification'].startswith('NOT_ISSUED'))
            self.assertNotIn('input-review.json',files)
            self.assertNotIn('image_expectations',contract)
            self.assertEqual(len(original),200)
            self.assertLessEqual(len(files),256)

    def test_exact_inverse_restores_all_original200_bytes_and_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            home,frozen,original,_pins=fixture(Path(temporary))
            with patch.object(p,'HERE',home):files=p.render(frozen)
            inverse=json.loads(files['inverse.json'][0])
            undo={name:row for name,row in files.items() if name not in inverse['additions']}
            self.assertEqual(undo,original)
            self.assertEqual(inverse['held'],p.fs.descriptors(original))
            self.assertEqual(inverse['before_tree'],p.fs.tree(original))

    def test_workflow_aliases_and_guard_hashes_are_identical_and_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            home,frozen,_original,_pins=fixture(Path(temporary))
            with patch.object(p,'HERE',home):files=p.render(frozen)
            self.assertEqual(files[p.ALIASES[0]],files[p.ALIASES[1]])
            workflow=files[p.ALIASES[0]][0]
            self.assertIn(p.fs.pin(files['hosted/common.py'][0])['sha256'].encode(),workflow)
            self.assertIn(p.fs.pin(files['hosted/entry.py'][0])['sha256'].encode(),workflow)
            self.assertNotIn(b'__COMMON_SHA__',workflow)

    def test_deterministic_fresh_atomic_publication_and_preexisting_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home,frozen,_original,_pins=fixture(root)
            with patch.object(p,'HERE',home):
                first=p.construct(frozen,root/'published')
                second=p.construct(frozen,root/'published-again')
                self.assertEqual(first,second)
                self.assertTrue(all(value is None for value in first['actual'].values()))
                self.assertEqual(first['mutation_qualification'],'NOT_ISSUED')
                with self.assertRaisesRegex(ValueError,'fresh absent'):
                    p.construct(frozen,root/'published')

    def test_full_frozen_map_hash_mode_content_and_membership_are_independent(self):
        for variant in ('hash','mode','body','extra','missing'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as temporary:
                home,frozen,_original,pins=fixture(Path(temporary))
                target=frozen/'foreign/unused000.txt'
                if variant=='hash':
                    pins['frozen_bootstrap_source_map_sha256']='0'*64;put(home,'held-source.json',p.encode(pins))
                elif variant=='mode':target.chmod(0o755)
                elif variant=='body':target.write_bytes(b'CHANGED DATA\n')
                elif variant=='extra':put(frozen,'extra.txt',b'EXTRA DATA\n')
                else:target.unlink()
                with patch.object(p,'HERE',home),self.assertRaises(ValueError):p.render(frozen)

    def test_internal_original_map_membership_is_checked_after_outer_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            home,frozen,_original,pins=fixture(Path(temporary))
            path=frozen/'original/native/source-map.json';inner=json.loads(path.read_bytes())
            inner['files'].pop('data/held000.txt');raw=p.encode(inner);path.write_bytes(raw)
            outer=json.loads((frozen/'source-map.json').read_bytes());outer['files']['original/native/source-map.json']=dict(**p.fs.pin(raw),mode=0o644)
            outer_raw=p.encode(outer);(frozen/'source-map.json').write_bytes(outer_raw)
            pins.update(frozen_bootstrap_source_map_sha256=p.fs.pin(outer_raw)['sha256'],original_source_map_sha256=p.fs.pin(raw)['sha256'])
            put(home,'held-source.json',p.encode(pins))
            with patch.object(p,'HERE',home),self.assertRaisesRegex(ValueError,'internal original200'):p.render(frozen)

    def test_payload_closure_refuses_unmapped_alias_special_and_extra_files(self):
        for variant in ('missing','extra','symlink','fifo'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as temporary:
                home,frozen,_original,_pins=fixture(Path(temporary));target=home/'payload/hosted/observer.py'
                if variant=='extra':put(home/'payload','hosted/unmapped.py',b'PASSIVE EXTRA\n')
                else:
                    target.unlink()
                    if variant=='symlink':target.symlink_to(home/'LICENSE')
                    if variant=='fifo':os.mkfifo(target)
                with patch.object(p,'HERE',home),self.assertRaises((ValueError,OSError)):p.render(frozen)

    def test_constructor_refuses_actual_root_authority_or_wrong_policy(self):
        for variant in ('status','authority','source','operation','inventory','guard'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as temporary:
                home,frozen,_original,_pins=fixture(Path(temporary))
                if variant in ('status','authority','source'):
                    template=dict(status='UNADMITTED',source=None,authority=None);template[variant]='CLAIMED_ACTUAL_ROOT_VALUE';put(home,'root-admission.TEMPLATE.json',p.encode(template))
                elif variant=='operation':put(home,'observer-policy.json',p.encode(dict(schema=1,operation='perl5423-installed-lifecycle-native-v1')))
                elif variant=='inventory':put(home,'expected349.lock',b'CHANGED INVENTORY\n')
                else:put(home,'workflow.yml.in',b'__COMMON_SHA__ __COMMON_SHA__ __ENTRY_SHA__\n')
                with patch.object(p,'HERE',home),self.assertRaises(ValueError):p.render(frozen)

    def test_disjoint_paths_and_unsafe_output_parent_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home,frozen,_original,_pins=fixture(root)
            with patch.object(p,'HERE',home):
                for output in (frozen/'nested',home/'nested',root):
                    with self.subTest(output=output),self.assertRaisesRegex(ValueError,'disjoint'):p.construct(frozen,output)
                public=root/'writable-parent';public.mkdir();public.chmod(0o777)
                with self.assertRaisesRegex(ValueError,'owned output parent'):p.construct(frozen,public/'output')


if __name__=='__main__':unittest.main(verbosity=2)
