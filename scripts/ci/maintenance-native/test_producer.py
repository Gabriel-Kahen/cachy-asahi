# SPDX-License-Identifier: MIT
"""Corrected source seam controls; proof, copying and exec are explicit routing stubs."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import contract as C
import job as J
import prepare as P
import producer as M

HERE=Path(__file__).resolve().parent
SOURCE=next(p for p in HERE.parents if (p/'scripts/ci/maintained_desktop574.py').is_file())
RECIPE=SOURCE/'packages/tools/cachy-asahi-maintenance'


class ExecReached(Exception):pass


class ProducerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='maintenance-producer-controls-');cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.context=cls.root/'context';P.prepare(SOURCE,cls.context,RECIPE)

    def setUp(self):
        self.work=Path(tempfile.mkdtemp(prefix='maintenance-producer-case-'));self.addCleanup(shutil.rmtree,self.work)

    def value(self):return dict(status='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY',source=M.CARRIER,mode='desktop574',
        actual=None,receipt=dict(actual_authority=False,cache=dict(all_previous_inode_metadata_bytes_unchanged=True)))

    def bound_fixture(self):
        source=self.work/'bound-source';shutil.copytree(self.context,source)
        path=source/C.LANE/'input-policy.json';value=json.loads(path.read_bytes());value['candidate_source']='d'*40
        path.write_text(json.dumps(value)+'\n');output=self.work/'output';output.mkdir(mode=0o700)
        return source,output

    def test_null_source_refuses_before_loader_or_exec(self):
        with patch.object(C,'HERE',self.context/C.LANE):
            with self.assertRaisesRegex(ValueError,'Root-bound frozen package'):
                M.run(self.context,self.work/'carrier',self.work/'unused','a'*16,
                      loader=lambda _:self.fail('no helper before source binding'),execute=lambda *_:self.fail('no actor'))

    def test_original_lock_cache_deadline_token_and_exec_vector_are_held(self):
        source,output=self.bound_fixture();seen={}
        def prepare(*args):seen['prepare']=args;return self.value()
        def execute(binary,args):seen['exec']=(binary,args);raise ExecReached()
        with patch.object(C,'verify_source',lambda _:None),patch.object(C,'HERE',self.context/C.LANE):
            with self.assertRaises(ExecReached):M.run(source,self.work/'carrier',output,'a'*16,
                loader=lambda _:types.SimpleNamespace(prepare=prepare),execute=execute,clock=iter((100.,101.)).__next__)
        self.assertEqual(seen['prepare'],(self.work/'carrier',output/'context/deps','desktop574',
            source/'scripts/ci/maintained-desktop574-inputs.json',2400.,self.work/'carrier/.git'))
        self.assertEqual(seen['exec'],(sys.executable,[sys.executable,'-I','-B',str(source/'scripts/ci/maintained_desktop574.py'),
            'build','--inputs',str(source/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(output),'--job-token','a'*16]))
        self.assertEqual(json.loads((output/'maintenance-retained-inputs.json').read_bytes()),self.value())

    def test_deadline_exhaustion_never_execs_or_writes_success_receipt(self):
        source,output=self.bound_fixture()
        with patch.object(C,'verify_source',lambda _:None),patch.object(C,'HERE',self.context/C.LANE):
            with self.assertRaisesRegex(ValueError,'budget exhausted'):
                M.run(source,self.work/'carrier',output,'a'*16,loader=lambda _:types.SimpleNamespace(prepare=lambda *a:self.value()),
                    execute=lambda *_:self.fail('no exec after budget'),clock=iter((100.,2401.)).__next__)
        self.assertFalse((output/'maintenance-retained-inputs.json').exists())

    def test_bad_carrier_authority_or_previous_cache_maps_refuse(self):
        for kind in ('source','authority','cache','mode'):
            source,output=self.bound_fixture() if kind=='source' else (self.work/'bound-source',self.work/'output')
            value=self.value()
            if kind=='source':value['source']='f'*40
            elif kind=='authority':value['receipt']['actual_authority']=True
            elif kind=='cache':value['receipt']['cache']['all_previous_inode_metadata_bytes_unchanged']=False
            else:value['mode']='compiler6'
            with patch.object(C,'verify_source',lambda _:None),patch.object(C,'HERE',self.context/C.LANE):
                with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'DATA-only preparation'):
                    M.run(source,self.work/'carrier',output,'a'*16,loader=lambda _:types.SimpleNamespace(prepare=lambda *a:value),
                        execute=lambda *_:self.fail('no exec after invalid DATA'))

    def test_unique_loader_does_not_reuse_constructor_prepare_namespace(self):
        sentinel=types.ModuleType('prepare')
        with patch.dict(sys.modules,{'prepare':sentinel}):
            module=M.helper(self.context)
            self.assertIs(sys.modules['prepare'],sentinel)
            self.assertEqual(module.__name__,'_maintenance_exact_retained_prepare')
            self.assertEqual(Path(module.__file__),self.context/'scripts/ci/retained-build-inputs/prepare.py')

    def test_only_fixed_external_carrier_namespace_is_excluded_from_source_scan(self):
        source=self.work/'with-carrier';shutil.copytree(self.context,source)
        external=source/'retained574/packages';external.mkdir(parents=True);(external/'DATA-only').write_bytes(b'CONTROL ONLY')
        manifest=json.loads((source/C.LANE/'source-manifest.json').read_bytes())
        J.manifest_files(source,manifest)
        (source/'unreviewed-extra').write_bytes(b'not allowed')
        with self.assertRaisesRegex(ValueError,'unmanifested'):J.manifest_files(source,manifest)

    def test_source_workflow_keeps_budgets_and_prefill_before_unchanged_build(self):
        text=(self.context/C.ACTOR).read_text()
        self.assertEqual((self.context/C.ACTOR).read_bytes(),(self.context/C.ALIAS).read_bytes())
        self.assertIn('ref: '+M.CARRIER,text);self.assertIn('path: retained574',text)
        self.assertLess(text.index('Checkout exact complete original574 retained inputs'),text.index('Reconstruct pinned inputs'))
        self.assertIn('2300s',text);self.assertIn('timeout-minutes: 40',text);self.assertIn('timeout-minutes: 100',text)
        self.assertIn('python3 -I -B "$SLICE/producer.py"',text)
        self.assertIn("copy(base/'maintenance-retained-inputs.json','base/maintenance-retained-inputs.json',2*1024**2)",
                      (self.context/C.LANE/'job.py').read_text())


if __name__=='__main__':unittest.main(verbosity=2)
