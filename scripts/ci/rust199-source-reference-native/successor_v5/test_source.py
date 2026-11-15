# SPDX-License-Identifier: MIT
"""Portable v5 constructor DATA controls; execute no Reader or native role."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('FENCED_v5_source',HERE/'prepare.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class SourceControls(unittest.TestCase):
    def test_unadmitted_template_preserves_only_published_source_facts(self):
        metadata=json.loads((HERE/'payload/llvm-v2/source.json').read_bytes());policy=json.loads((HERE/'payload/resource-policy.json').read_bytes())
        legacy=json.loads((HERE.parent/'root-admission.TEMPLATE.json').read_bytes())
        before=dict(llvm=legacy['llvm'],source=legacy['source'],claims=legacy['claims'],reviews={'source':True},source_audit=dict(status='FENCED',reviewed=True),delivery={name:dict(repository='Gabriel-Kahen/cachy-asahi',id='FENCED',accepted_by_root=True)for name in ('llvm_original','stage0_carrier','root_proof_carrier')})
        value=json.loads(p.template(p.encode(before),metadata,policy))
        self.assertEqual(value['status'],'UNADMITTED');self.assertEqual(value['schema'],4)
        self.assertTrue(all(v is None for v in value['source'].values()));self.assertFalse(any(value['reviews'].values()));self.assertFalse(any(value['claims'].values()))
        self.assertEqual(value['llvm']['source'],dict(sha=p.LLVM['sha'],ref=p.LLVM['ref'],run=None,job=None))
        self.assertEqual(value['llvm']['publication'],metadata['publication']);self.assertEqual(value['llvm']['source_identity'],p.LLVM)
        self.assertEqual(set(metadata['actual']),{'job','original','package','publication','reader','root_acceptance','run'})
        self.assertEqual(metadata['actual']['publication'],metadata['publication_pin'])
        self.assertTrue(all(v is None for k,v in metadata['actual'].items()if k!='publication'))
        for name in ('artifact','original'):self.assertTrue(all(v is None for v in value['llvm'][name].values()))
        for name in ('archive','signature','public_test_key','verification_proof','root_decision'):
            for key in ('bytes','sha256','local_path','fingerprint'):
                if key in value['llvm'][name]:self.assertIsNone(value['llvm'][name][key])
        for kind in ('llvm_original','stage0_carrier','root_proof_carrier'):
            self.assertIsNone(value['delivery'][kind]['id']);self.assertFalse(value['delivery'][kind]['accepted_by_root'])
    def test_new_reader_requires_whole_static_four_leaf_closure(self):
        actual=p.fs.snapshot(HERE/'payload');static=json.loads(actual['llvm-v2/source.json'][0])
        self.assertIsNone(static['pending'])
        self.assertEqual(static['independent_reader']['path'],'scripts/port/llvm23-native-independent-reader/v4/reader.py')
        self.assertEqual(static['independent_reader']['sha256'],'c4c738fd3260990babe0a814b597c1930c203aeaf7994b3d70d9738bf00431bf')
        p.reader_pins(actual,static)
        for name in p.READER_LEAVES:self.assertEqual(actual[name][1],0o644)
        # Mutable FENCED fixtures exercise refusal independently of the real static closure.
        files={p.READER+n:(('FENCED '+n).encode(),0o644)for n in ('reader.py','base.py','profile.json','pins.json')}
        metadata=dict(pending=None,independent_reader=dict(p.fs.pin(files[p.READER+'reader.py'][0]),**{key:p.fs.pin(files[p.READER+leaf][0])for key,leaf in (('base','base.py'),('profile','profile.json'),('pins','pins.json'))}))
        p.reader_pins(files,metadata)
        for leaf in files:
            changed=dict(files);changed[leaf]=(b'FENCED CHANGED',0o644)
            with self.subTest(leaf=leaf),self.assertRaises(ValueError):p.reader_pins(changed,metadata)
        p.reader_pins({},dict(pending=p.PENDING,independent_reader=None))
        with self.assertRaises(ValueError):p.reader_pins(files,dict(pending=p.PENDING,independent_reader=None))
        with self.assertRaises(ValueError):p.reader_pins({},dict(pending=None,independent_reader=None))
    def test_publication_source_readback_is_separate_from_future_roles(self):
        value=dict(issuer='Root',status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY',source=p.LLVM['sha'],ref=p.LLVM['ref'],tree=p.LLVM['tree'],source_map_sha256=p.LLVM['map_sha256'],files=256,bytes=p.LLVM['bytes'],native='NOT RUN',M2='NOT RUN')
        raw=p.encode(value);metadata=dict(publication=value,publication_pin=p.fs.pin(raw));p.publication({p.PUBLICATION:(raw,0o644)},metadata)
        for key,replacement in (('source','0'*40),('files',253),('native','PASS'),('M2','PASS')):
            bad=copy.deepcopy(value);bad[key]=replacement;body=p.encode(bad)
            with self.subTest(key=key),self.assertRaises(ValueError):p.publication({p.PUBLICATION:(body,0o644)},dict(publication=bad,publication_pin=p.fs.pin(body)))
    def test_exact_data_capture_refuses_whole_source_drift(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-v5-DATA-')as directory:
            root=Path(directory);rows={'data':(b'FENCED NOT A SOURCE',0o644)};rows['source-map.json']=(p.encode(dict(files=p.fs.descriptors(rows))),0o644)
            for name,(raw,mode)in rows.items():(root/name).write_bytes(raw);(root/name).chmod(mode)
            identity=dict(files=2,bytes=sum(len(v)for v,_ in rows.values()),tree=p.fs.tree(rows),map_sha256=p.fs.pin(rows['source-map.json'][0])['sha256'])
            self.assertEqual(p.capture(root,identity),rows);(root/'data').write_bytes(b'FENCED CHANGED')
            with self.assertRaises(ValueError):p.capture(root,identity)
    def test_wrong_parents_refuse_before_overlay(self):
        with self.assertRaises(ValueError):p.render({},{})
        self.assertEqual(p.PARENT['files'],298);self.assertEqual(p.LLVM['files'],256)
    def test_inverse_refuses_changed_map_or_protected_parent_leaf(self):
        before={'FENCED-data':(b'BEFORE',0o644),'native-successor-v4.json':(b'FENCED HISTORICAL',0o644)}
        before['source-map.json']=(p.encode(dict(files=p.fs.descriptors(before))),0o644)
        model=dict(FENCED='NOT_AN_ACCEPTED_SOURCE',tree=p.fs.tree(before));files=dict(before);files['FENCED-data']=(b'AFTER',0o644)
        changes={'FENCED-data':dict(before=p.fs.descriptors(before)['FENCED-data'],after=p.fs.descriptors(files)['FENCED-data'])}
        revision=dict(schema=5,parent=model,llvm=p.LLVM,scope=p.SCOPE,changes=changes)
        files[p.REVISION]=(p.encode(revision),0o644)
        files['source-map.json']=(p.encode(dict(schema=1,operation=p.OPERATION,actual=p.ACTUAL,files=p.fs.descriptors({n:v for n,v in files.items()if n!='source-map.json'}))),0o644)
        with patch.object(p,'PARENT',model):
            self.assertEqual(p.undo(files,before,revision),before)
            for name in ('source-map.json','native-successor-v4.json','FENCED-data'):
                changed=dict(files);changed[name]=(b'FENCED CHANGED',0o644)
                with self.subTest(name=name),self.assertRaises(ValueError):p.undo(changed,before,revision)
    def test_constructor_has_no_operational_role_or_old_marker_write(self):
        raw=(HERE/'prepare.py').read_text();ast.parse(raw)
        self.assertNotIn('subprocess',raw);self.assertNotIn('reader.read(',raw);self.assertNotIn("files['native-successor-v4.json']=",raw)
        self.assertEqual(p.SCOPE,'LLVM256_PUBLISHED_SOURCE_READER_REJOIN_ONLY_NO_ROLES')
        self.assertTrue(all(value is None for value in p.ACTUAL.values()))


if __name__=='__main__':unittest.main()
