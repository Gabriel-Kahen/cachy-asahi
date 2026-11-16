# SPDX-License-Identifier: MIT
"""Portable v6 constructor DATA controls; execute no Reader or native role."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('FENCED_v6_source',HERE/'prepare.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class SourceControls(unittest.TestCase):
    def test_unadmitted_template_preserves_only_published_source_facts(self):
        metadata=json.loads((HERE/'payload/llvm-v2/source.json').read_bytes());policy=json.loads((HERE.parent/'successor_v5/payload/resource-policy.json').read_bytes())
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
        self.assertEqual(value['llvm']['reader']['program'],metadata['independent_reader'])
        for name in ('binding','result'):
            self.assertTrue(all(value['llvm']['reader'][name][key]is None for key in ('bytes','sha256','local_path')))
        for name in ('artifact','original'):self.assertTrue(all(v is None for v in value['llvm'][name].values()))
        for name in ('archive','signature','public_test_key','verification_proof','root_decision'):
            for key in ('bytes','sha256','local_path','fingerprint'):
                if key in value['llvm'][name]:self.assertIsNone(value['llvm'][name][key])
        for kind in ('llvm_original','stage0_carrier','root_proof_carrier'):
            self.assertIsNone(value['delivery'][kind]['id']);self.assertFalse(value['delivery'][kind]['accepted_by_root'])
    def test_reader7_whole_nine_leaf_static_closure_and_refusals(self):
        actual=p.fs.snapshot(HERE/'payload');static=json.loads(actual['llvm-v2/source.json'][0])
        self.assertIsNone(static['pending']);self.assertEqual(static['reader_development_commit'],p.READER_COMMIT)
        self.assertEqual(static['independent_reader']['sha256'],'936053e2e62a7c0a8c37772f083a22b59657db91746dcbc283f5aa73c74d9fcd')
        p.reader_pins(actual,static)
        self.assertEqual(len(p.READER_LEAVES),9);self.assertNotIn('profile',static['independent_reader'])
        # FENCED leaf bytes exercise refusal independently of the real archived code.
        files={name:(('FENCED '+name).encode(),0o644)for name in p.READER_LEAVES}
        pins={name.removeprefix(p.READER):p.fs.pin(raw)for name,(raw,mode)in files.items()}
        descriptor=dict(path='scripts/port/llvm23-native-independent-reader/v7/reader.py',files=pins,**pins['reader.py'])
        metadata=dict(pending=None,independent_reader=descriptor);p.reader_pins(files,metadata)
        for name in files:
            for mode in ('bytes','mode','missing'):
                changed=dict(files)
                if mode=='bytes':changed[name]=(b'FENCED CHANGED',0o644)
                elif mode=='mode':changed[name]=(changed[name][0],0o755)
                else:changed.pop(name)
                with self.subTest(name=name,mode=mode),self.assertRaises(ValueError):p.reader_pins(changed,metadata)
        with self.assertRaises(ValueError):p.reader_pins(dict(files,**{p.READER+'profile.json':(b'FENCED',0o644)}),metadata)
        with self.assertRaises(ValueError):p.reader_pins(files,dict(metadata,pending='FENCED_PENDING'))
    def test_publication_source_readback_is_separate_from_future_roles(self):
        value=dict(issuer='Root',status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY',source=p.LLVM['sha'],ref=p.LLVM['ref'],tree=p.LLVM['tree'],source_map_sha256=p.LLVM['map_sha256'],files=260,bytes=p.LLVM['bytes'],native='NOT RUN',M2='NOT RUN')
        raw=p.encode(value);metadata=dict(publication=value,publication_pin=p.fs.pin(raw));p.publication({p.PUBLICATION:(raw,0o644)},metadata)
        for key,replacement in (('source','0'*40),('files',256),('native','PASS'),('M2','PASS')):
            bad=copy.deepcopy(value);bad[key]=replacement;body=p.encode(bad)
            with self.subTest(key=key),self.assertRaises(ValueError):p.publication({p.PUBLICATION:(body,0o644)},dict(publication=bad,publication_pin=p.fs.pin(body)))
    def test_architecture_source_input_tamper_and_extra_authority_refusals(self):
        profile=json.loads((HERE/'payload'/p.READER/'architecture-profile.json').read_bytes())
        self.assertEqual(profile['kind'],'LLVM23_SOURCE260_BASE349_ARCHITECTURE_METADATA_V1')
        self.assertEqual(set(profile['files']),{'expected349.lock','original/bootstrap/scripts/ci/inputs.lock.json','original/native/input-profile.json'})
        # Only FENCED DATA replaces the three inputs; no Reader or BUILDINFO code runs.
        source={name:(('FENCED '+name).encode(),0o644)for name in profile['files']}
        profile['files']={name:p.fs.pin(raw)for name,(raw,mode)in source.items()}
        files={p.READER+'architecture-profile.json':(p.encode(profile),0o644)};p.architecture_inputs(files,source)
        for name in source:
            changed=dict(source);changed[name]=(b'FENCED CHANGED',0o644)
            with self.subTest(name=name),self.assertRaises(ValueError):p.architecture_inputs(files,changed)
        for key,value in (('installed_rows',348),('rootfs_rows',166),('selected_rows',255),('fixed_addition_rows',9),('Root_grants',True),('actual_selectors',{}),('required_external_architecture_input','FENCED'),('basis','OUTPUT_BUILDINFO'),('allowed_architectures',['aarch64'])):
            changed=copy.deepcopy(profile);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):p.architecture_inputs({p.READER+'architecture-profile.json':(p.encode(changed),0o644)},source)
    def test_exact_data_capture_refuses_whole_source_drift(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-v6-DATA-')as directory:
            root=Path(directory);rows={'data':(b'FENCED NOT A SOURCE',0o644)};rows['source-map.json']=(p.encode(dict(files=p.fs.descriptors(rows))),0o644)
            for name,(raw,mode)in rows.items():(root/name).write_bytes(raw);(root/name).chmod(mode)
            identity=dict(files=2,bytes=sum(len(v)for v,_ in rows.values()),tree=p.fs.tree(rows),map_sha256=p.fs.pin(rows['source-map.json'][0])['sha256'])
            self.assertEqual(p.capture(root,identity),rows);(root/'data').write_bytes(b'FENCED CHANGED')
            with self.assertRaises(ValueError):p.capture(root,identity)
    def test_wrong_parents_refuse_before_overlay(self):
        with self.assertRaises(ValueError):p.render({},{})
        self.assertEqual(p.PARENT['files'],304);self.assertEqual(p.LLVM['files'],260)
    def test_inverse_refuses_changed_map_or_protected_parent_leaf(self):
        before={'FENCED-data':(b'BEFORE',0o644),'native-successor-v4.json':(b'FENCED HISTORICAL V4',0o644),'llvm256-rejoin.json':(b'FENCED HISTORICAL V5',0o644)}
        before['source-map.json']=(p.encode(dict(files=p.fs.descriptors(before))),0o644)
        model=dict(FENCED='NOT_AN_ACCEPTED_SOURCE',tree=p.fs.tree(before));files=dict(before);files['FENCED-data']=(b'AFTER',0o644)
        changes={'FENCED-data':dict(before=p.fs.descriptors(before)['FENCED-data'],after=p.fs.descriptors(files)['FENCED-data'])}
        revision=dict(schema=6,parent=model,llvm=p.LLVM,scope=p.SCOPE,changes=changes)
        files[p.REVISION]=(p.encode(revision),0o644)
        files['source-map.json']=(p.encode(dict(schema=1,operation=p.OPERATION,actual=p.ACTUAL,files=p.fs.descriptors({n:v for n,v in files.items()if n!='source-map.json'}))),0o644)
        with patch.object(p,'PARENT',model):
            self.assertEqual(p.undo(files,before,revision),before)
            for name in ('source-map.json','native-successor-v4.json','llvm256-rejoin.json','FENCED-data'):
                changed=dict(files);changed[name]=(b'FENCED CHANGED',0o644)
                with self.subTest(name=name),self.assertRaises(ValueError):p.undo(changed,before,revision)
    def test_constructor_has_no_operational_role_or_old_marker_write(self):
        raw=(HERE/'prepare.py').read_text();ast.parse(raw)
        self.assertNotIn('subprocess',raw);self.assertNotIn('reader.read(',raw);self.assertNotIn("files['native-successor-v4.json']=",raw)
        self.assertEqual(p.SCOPE,'LLVM260_READER7_PROSPECTIVE_REJOIN_ONLY_NO_ROLES')
        self.assertTrue(all(value is None for value in p.ACTUAL.values()))


if __name__=='__main__':unittest.main()
