# SPDX-License-Identifier: MIT
"""Inert input refusals and original locally retained native-pair inspection."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ.get('EXPANDED604_SOURCE',Path.cwd())).absolute()


def load(name,path,bindings=None):
    missing=object();previous={key:sys.modules.get(key,missing) for key in (bindings or {})}
    try:
        sys.modules.update(bindings or {})
        spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
    finally:
        for key,old in previous.items():
            if old is missing:sys.modules.pop(key,None)
            else:sys.modules[key]=old


C=load('_604_test_original_contract',SOURCE/'scripts/ci/expanded600-installer-vm/contract.py')
C.scoped_load=load
I=load('_604_test_inputs',HERE/'inputs.py',{'contract':C})


class Inputs(unittest.TestCase):
    def packet_root(self,key,default):
        if key in os.environ:
            self.assertTrue(os.environ[key],key+' must name an actual input directory')
            root=Path(os.environ[key]).absolute()
            self.assertTrue(root.is_dir(),key+' provided but actual input directory is absent: '+str(root))
            return root
        root=Path(default).absolute()
        if not root.is_dir():self.skipTest('original local packet absent; native input gate remains mandatory: '+key)
        return root

    def binding(self):
        return dict(welcome=dict(status='ROOT_ACCEPTED_NATIVE_WELCOME2_PAIR_AND_CLI_LIFECYCLE',
            source='a'*40,carrier_source='c'*40,candidate_source='b'*40,index=dict(path='index.json',bytes=1,sha256='c'*64)))

    def test_unbound_refuses_before_any_filesystem_or_helper_import(self):
        with patch.object(I,'tools',side_effect=AssertionError('helper imported')):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):
                I.validate_inputs(*(['/absent']*7),dict(welcome=dict(status='UNBOUND',source=None,index=None)))

    def test_validation_restores_original_reader_path_on_failure(self):
        previous=list(sys.path)
        def failure(*args):
            sys.path.insert(0,'/unexpected-original-reader-path')
            raise ValueError('original rejection')
        with patch.object(I,'_validate_inputs',side_effect=failure):
            with self.assertRaisesRegex(ValueError,'original rejection'):
                I.validate_inputs(*(['/absent']*7),self.binding())
        self.assertEqual(sys.path,previous)

    def test_validation_restores_original_reader_path_on_success(self):
        previous=list(sys.path)
        def success(*args):
            sys.path.insert(0,'/unexpected-original-reader-path')
            return {'inert_control':True}
        with patch.object(I,'_validate_inputs',side_effect=success):
            self.assertEqual(I.validate_inputs(*(['/absent']*7),self.binding()),{'inert_control':True})
        self.assertEqual(sys.path,previous)

    def test_missing_root_native_acceptance_refused(self):
        for field in ('status','source','carrier_source','candidate_source','index'):
            value=self.binding();value['welcome'].pop(field)
            with self.subTest(field=field),self.assertRaises(ValueError):I.require_welcome(value)

    def test_scoped_helper_load_restores_generic_module(self):
        sentinel=object();previous=sys.modules.get('contract');sys.modules['contract']=sentinel
        try:
            C.scoped_load('_604_real_materializer_load',SOURCE/'scripts/ci/expanded600-installer-vm/materializer.py',{'contract':C})
            self.assertIs(sys.modules['contract'],sentinel)
        finally:
            if previous is None:sys.modules.pop('contract',None)
            else:sys.modules['contract']=previous

    def test_scoped_helper_load_failure_restores_generic_module(self):
        sentinel=object();previous=sys.modules.get('contract');sys.modules['contract']=sentinel
        try:
            with self.assertRaises(FileNotFoundError):C.scoped_load('_604_no_helper',Path('/absent-604-helper.py'),{'contract':C})
            self.assertIs(sys.modules['contract'],sentinel)
        finally:
            if previous is None:sys.modules.pop('contract',None)
            else:sys.modules['contract']=previous

    def test_complete_comparison_required(self):
        good=dict(status='contents-reproduced',errors=[],packages={'original':dict(bytes_equal=True,pkginfo_equal=True,buildinfo_equal=True,installed_contents_equal=True)})
        I.comparison(good)
        for key in good['packages']['original']:
            bad=copy.deepcopy(good);bad['packages']['original'][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):I.comparison(bad)
        with self.assertRaises(ValueError):I.comparison(dict(good,packages={}))

    def test_exact_management_binding_rejects_before_packet(self):
        checks,_=I.tools(SOURCE)
        with self.assertRaisesRegex(ValueError,'exact accepted four-pair'):
            I.management_pairs(SOURCE,Path('/absent'),{},checks)

    def test_exact_setup_binding_rejects_before_packet(self):
        checks,bind=I.tools(SOURCE)
        with self.assertRaisesRegex(ValueError,'exact accepted Setup5'):
            I.setup_pair(SOURCE,Path('/absent'),{},checks,bind)

    def test_welcome_wrong_carrier_kind_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'index.json';path.write_text('{}')
            binding=self.binding()['welcome'];binding['index']=dict(path=path.name,bytes=path.stat().st_size,sha256=C.sha(path))
            checks,bind=I.tools(SOURCE)
            with self.assertRaisesRegex(ValueError,'carrier identity'):I.welcome_pair(SOURCE,root,binding,checks,bind)

    def test_original_eight_pairs_and_complete184_retention(self):
        eight=self.packet_root('EXPANDED604_EIGHT_ROOT',SOURCE/'artifacts/development/expanded600-final-inputs-20261016/payload')
        seven=self.packet_root('EXPANDED604_SEVEN_ROOT',SOURCE/'artifacts/development/expanded-candidate-inputs-20261016/payload')
        legacy=self.packet_root('EXPANDED604_LEGACY_ROOT',SOURCE)
        policy=C.read(SOURCE/'scripts/ci/expanded600-installer-vm/input-policy.json')
        accepted=C.scoped_load('_604_test_eight_contract',SOURCE/'scripts/ci/expanded600-installer-vm/contract.py',{})
        accepted.load=lambda name,path:C.scoped_load(name,path,{'contract':accepted})
        materializer=C.scoped_load('_604_test_eight_reader',SOURCE/'scripts/ci/expanded600-installer-vm/materializer.py',{'contract':accepted})
        rows=materializer.accepted_pairs(eight,seven,legacy,policy)
        self.assertEqual(len(rows),8);self.assertEqual(rows[I.WELCOME]['version'],'0.1.0-1')
        refs=I.eight_refs(eight,policy)
        self.assertEqual(len(refs),184)
        public=set()
        for child in eight.iterdir():
            if child.name=='.git':continue
            for path in ([child] if child.is_file() else child.rglob('*')):
                if path.is_file():public.add(path.relative_to(eight).as_posix())
        self.assertEqual(set(refs),public)

    def test_passive_stage_copies_only_exact_index_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);root=directory/'checkout';root.mkdir();(root/'.git').mkdir()
            (root/'.git/config').write_text('must never enter public packet')
            (root/'data').write_bytes(b'actual public record')
            ref=dict(path='data',bytes=(root/'data').stat().st_size,sha256=C.sha(root/'data'))
            (root/'index.json').write_text(json.dumps(dict(record=ref)))
            index=dict(path='index.json',bytes=(root/'index.json').stat().st_size,sha256=C.sha(root/'index.json'))
            out=I.stage_packet(root,directory/'staged',index)
            self.assertEqual({p.name for p in out.iterdir()},{'data','index.json'})
            self.assertEqual((out/'data').read_bytes(),b'actual public record')
            self.assertEqual((root/'.git/config').read_text(),'must never enter public packet')

    def test_passive_stage_checks_every_original_before_copying(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);root=directory/'checkout';root.mkdir()
            ref=dict(path='missing',bytes=1,sha256='b'*64)
            (root/'index.json').write_text(json.dumps(dict(record=ref)))
            index=dict(path='index.json',bytes=(root/'index.json').stat().st_size,sha256=C.sha(root/'index.json'))
            out=directory/'staged'
            with self.assertRaises(FileNotFoundError):I.stage_packet(root,out,index)
            self.assertFalse(out.exists())

    def test_exact_empty_original_record_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'empty').write_bytes(b'')
            ref=dict(path='empty',bytes=0,sha256=__import__('hashlib').sha256(b'').hexdigest())
            self.assertEqual(I.source_ref(root,ref),root/'empty')
            with self.assertRaises(ValueError):I.source_ref(root,dict(ref,sha256='a'*64))
            (root/'empty').write_bytes(b'x')
            with self.assertRaises(ValueError):I.source_ref(root,ref)

    def test_original_management_packet_four_pairs(self):
        root=self.packet_root('EXPANDED604_MANAGEMENT_ROOT',SOURCE/'artifacts/development/management-tools-native-inputs-20261016/payload')
        api=C.scoped_load('_604_test_management',SOURCE/'scripts/ci/management-tools-generic16k/contract.py',{})
        checks,_=I.tools(SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            staged=I.stage_packet(root,Path(directory)/'management',I.MANAGEMENT_INDEX)
            rows=I.management_pairs(SOURCE,staged,api.policy(),checks)
            self.assertEqual(set(rows),set(api.VERSIONS))
            self.assertEqual({n:r['version'] for n,r in rows.items()},api.VERSIONS)
            self.assertTrue(all(Path(r['archive']).is_file() and r['files']['a']['path']!=r['files']['b']['path'] and r['sources'] and r['payload'] for r in rows.values()))

    def test_original_setup5_native_pair_and_legacy_receipt(self):
        root=self.packet_root('EXPANDED604_SETUP_ROOT',SOURCE/'artifacts/development/setup5-accepted-pair-inputs-20261016/payload')
        checks,bind=I.tools(SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            staged=I.stage_packet(root,Path(directory)/'setup5',I.SETUP_INDEX,setup_packet=True)
            row=I.setup_pair(SOURCE,staged,dict(source=I.SETUP_SOURCE,index=I.SETUP_INDEX),checks,bind)
            self.assertEqual(row['version'],'0.1.0-5');self.assertEqual(len(row['sources']),12)
            self.assertEqual(len(row['payload']),6);self.assertEqual(row['native_run'],38934198468)
            self.assertEqual(row['files']['a']['sha256'],row['files']['b']['sha256'])


    def test_original_welcome2_native_pair_and_cli_receipt(self):
        root=self.packet_root('EXPANDED604_WELCOME_ROOT',SOURCE/'artifacts/development/welcome2-native-inputs-20261016/payload')
        policy=C.read(HERE/'input-policy.json')
        checks,bind=I.tools(SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            staged=I.stage_packet(root,Path(directory)/'welcome2',policy['welcome']['index'])
            row=I.welcome_pair(SOURCE,staged,policy['welcome'],checks,bind)
            self.assertEqual(row['version'],'0.1.0-2');self.assertEqual(len(row['sources']),24)
            self.assertEqual(row['native_run'],38974893566)
            self.assertEqual(row['files']['a']['sha256'],row['files']['b']['sha256'])


if __name__=='__main__':unittest.main()
