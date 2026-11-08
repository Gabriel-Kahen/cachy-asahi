#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Atomic complete-release context controls; no builders/native actors."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class ReleaseContextControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='.release-context-test-',dir=HERE)
        cls.root=Path(cls.temporary.name)
        cls.consumer=load('release_set_real_consumer',RUNTIME/'build/mirror_consumer.py')
        cls.deps=cls.consumer.dependencies(RUNTIME/'build');cls.m=cls.deps['mirror']
        cls.catalog=load('release_set_real_catalog',HERE/'source_mirror_catalog.py')
        cls.helper=load('release_set_under_test',HERE/'source_release_context.py')
        cls.fixtures=json.loads((FIXTURES/'fixtures.json').read_bytes())['fixtures']
        old,current=cls.fixtures;md=cls.m.dependencies(RUNTIME/'release')
        single,_,_=cls.m.build(FIXTURES/old['label'],old['release_sha256'],md,directory=RUNTIME/'release')
        cls.history,_,_=cls.m.update(single,cls.m.digest(single),old['release_sha256'],
            FIXTURES/current['label'],current['release_sha256'],md,directory=RUNTIME/'release')
        cls.patch=patch.object(cls.catalog,'mirror_helper',return_value=cls.m);cls.patch.start()

    @classmethod
    def tearDownClass(cls):cls.patch.stop();cls.temporary.cleanup()

    def setUp(self):
        self.work=self.root/self._testMethodName;self.work.mkdir(mode=0o700)

    def create(self,fixture=None,label='release-set',raw=None):
        fixture=self.fixtures[-1]if fixture is None else fixture;raw=self.history if raw is None else raw
        output=self.work/label
        result=self.helper.materialize_release(raw,self.m.digest(raw),fixture['release_sha256'],output,
            self.deps,self.catalog,self.consumer)
        return output,result

    def verified(self,root,pin):return self.helper.verify_release_context(root,pin,self.deps,self.catalog,self.consumer)

    def read_manifest(self,root):return json.loads((root/self.helper.MANIFEST).read_bytes())

    def repin_manifest(self,root,value):
        path=root/self.helper.MANIFEST;path.chmod(0o600);path.write_bytes(self.m.encoded(value));path.chmod(0o400)
        return self.m.digest(path.read_bytes())

    def absent(self,path):
        self.assertFalse(os.path.lexists(path));self.assertEqual(list(self.work.glob('.release-context-*')),[])

    def test_complete_legacy_and_current_sets_verify_every_selected_package_with_null_builders(self):
        for fixture in self.fixtures:
            with self.subTest(release=fixture['label']):
                output,result=self.create(fixture,fixture['label'])
                self.assertEqual(result['status'],'MATERIALIZED_RELEASE_CONTEXT_SET')
                self.assertEqual(result['package_count'],2)
                self.assertEqual(result['release_sha256'],fixture['release_sha256'])
                self.assertEqual({p.name for p in output.iterdir()},{'mirror.tar',self.helper.MANIFEST,'contexts'})
                verified=self.verified(output,result['manifest_sha256'])
                self.assertEqual(verified['status'],'VERIFIED_RELEASE_CONTEXT_SET')
                self.assertEqual(verified['contexts'],result['contexts'])
                for index,(row,expected)in enumerate(zip(result['contexts'],fixture['packages'])):
                    self.assertEqual(row['selector']['package'],expected['name'])
                    self.assertEqual(row['selector']['srcinfo_sha256'],expected['srcinfo_sha256'])
                    self.assertEqual(row['context'],self.helper.context_path(index,row['selector'],self.m))
                    checked=self.consumer.verify_context(output/row['context'],row['selection_sha256'],self.deps)
                    self.assertEqual(checked['package']['sha256'],expected['package_sha256'])
                    request=json.loads((output/row['context']/'builder-request.json').read_bytes())
                    self.assertTrue(all(value is None for value in request['actual_selectors'].values()))
                self.assertEqual(verified['actual_selectors'],'ALL_NULL')
                self.assertEqual(verified['native_build'],'NOT_RUN')

    def test_set_is_self_contained_after_move_without_original_bundle_path(self):
        output,result=self.create();moved=output.with_name('moved-complete-set');output.rename(moved)
        self.assertEqual(self.verified(moved,result['manifest_sha256'])['contexts'],result['contexts'])
        self.assertEqual((moved/'mirror.tar').read_bytes(),self.history)

    def test_independent_outputs_have_deterministic_manifest_and_selection_pins(self):
        first,a=self.create(label='first');second,b=self.create(label='second')
        self.assertEqual(a,b);self.assertEqual((first/self.helper.MANIFEST).read_bytes(),(second/self.helper.MANIFEST).read_bytes())

    def test_full_authentication_precedes_staging_for_wrong_pins_and_corrupt_recovery(self):
        output=self.work/'must-not-exist'
        for checksum,release in (('0'*64,self.fixtures[-1]['release_sha256']),
                                (self.m.digest(self.history),'0'*64)):
            with self.assertRaises(ValueError):self.helper.materialize_release(self.history,checksum,release,output,
                self.deps,self.catalog,self.consumer)
            self.absent(output)
        files=self.m.canonical_files(self.history,self.m.digest(self.history));history=self.m.decode(files['history.json'])
        files['objects/'+history['releases'][0]['manifest']['sha256']]+=b' '
        raw=self.m.tar_bytes(files)
        with self.assertRaises(ValueError):self.create(raw=raw,label=output.name)
        self.absent(output)

    def test_failure_on_second_package_leaves_no_partial_set_or_staging_tree(self):
        original=self.consumer.materialize;calls=[]
        def fail_second(prepared,path,deps):
            calls.append(path)
            if len(calls)==2:
                Path(path).mkdir(mode=0o700);(Path(path)/'partial').write_bytes(b'injected fixture failure')
                raise ValueError('SYNTHETIC_SECOND_PACKAGE_FAILURE')
            return original(prepared,path,deps)
        with patch.object(self.consumer,'materialize',side_effect=fail_second),self.assertRaises(ValueError):self.create()
        self.assertEqual(len(calls),2);self.absent(self.work/'release-set')

    def test_existing_output_and_racing_output_are_never_replaced(self):
        output=self.work/'release-set';output.mkdir();(output/'keep').write_bytes(b'user-owned')
        with self.assertRaises(ValueError):self.create()
        self.assertEqual((output/'keep').read_bytes(),b'user-owned')
        shutil.rmtree(output);original=self.helper.publish_no_replace
        def appeared(parent,staging,name):
            os.mkdir(name,mode=0o700,dir_fd=parent)
            fd=os.open(name+'/keep',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=parent)
            with os.fdopen(fd,'wb')as stream:stream.write(b'racing-owned')
            return original(parent,staging,name)
        with patch.object(self.helper,'publish_no_replace',side_effect=appeared),self.assertRaises(ValueError):self.create()
        self.assertEqual({p.name for p in output.iterdir()},{'keep'})
        self.assertEqual((output/'keep').read_bytes(),b'racing-owned')
        self.assertEqual(list(self.work.glob('.release-context-*')),[])

    def test_existing_context_bounds_refuse_before_writing_an_oversize_member(self):
        with patch.object(self.helper,'context_cost',return_value=(self.m.MAX_TOTAL+1,1,1)),\
             patch.object(self.consumer,'materialize',side_effect=AssertionError('oversize context written')),self.assertRaises(ValueError):self.create()
        self.absent(self.work/'release-set')

    def test_repinned_partial_or_reordered_manifest_cannot_claim_a_complete_release(self):
        output,result=self.create();original=self.read_manifest(output)
        for rows in (original['packages'][:1],list(reversed(original['packages'])),
                     [original['packages'][0],original['packages'][0]]):
            value=copy.deepcopy(original);value['packages']=rows;value['package_count']=len(rows)
            pin=self.repin_manifest(output,value)
            with self.assertRaises(ValueError):self.verified(output,pin)
        value=copy.deepcopy(original);value['native_build']='PASS';pin=self.repin_manifest(output,value)
        with self.assertRaises(ValueError):self.verified(output,pin)

    def test_exact_inventory_refuses_extra_nodes_symlinks_hardlinks_and_tampered_child(self):
        for kind in ('extra','directory','symlink','hardlink','child'):
            with self.subTest(kind=kind):
                output,result=self.create(label=kind);row=result['contexts'][0]
                if kind=='extra':(output/'extra').write_bytes(b'unlisted')
                elif kind=='directory':(output/'contexts/extra').mkdir(mode=0o700)
                elif kind=='symlink':(output/'alias').symlink_to(output/'mirror.tar')
                elif kind=='hardlink':os.link(output/'mirror.tar',output/'extra-link')
                else:
                    path=output/row['context']/'recipe/PKGBUILD';path.chmod(0o600);path.write_bytes(path.read_bytes()+b'\n# altered\n');path.chmod(0o400)
                with self.assertRaises((ValueError,OSError)):self.verified(output,result['manifest_sha256'])

    def test_context_mapping_preserves_same_name_variants_and_repeated_ordered_rows(self):
        row=self.catalog.catalog(self.history,self.m.digest(self.history),self.fixtures[-1]['release_sha256'])['packages'][0]
        variant=dict(row,arch='aarch64')
        paths=[self.helper.context_path(0,row,self.m),self.helper.context_path(1,variant,self.m),
               self.helper.context_path(2,row,self.m)]
        self.assertEqual(len(paths),len(set(paths)))
        self.assertTrue(all(path.startswith('contexts/') and len(Path(path).parts)==2 for path in paths))

    def test_no_builder_download_or_context_code_import_during_materialize_and_verify(self):
        forbidden=AssertionError('release context must not execute builder or network')
        original=importlib.util.spec_from_file_location
        def trusted_only(name,filename,*args,**kwargs):
            if Path(filename).is_relative_to(self.work):raise AssertionError('retained context program imported')
            return original(name,filename,*args,**kwargs)
        with patch.object(subprocess,'Popen',side_effect=forbidden),patch.object(socket,'socket',side_effect=forbidden),\
             patch.object(socket,'getaddrinfo',side_effect=forbidden),\
             patch.object(importlib.util,'spec_from_file_location',side_effect=trusted_only):
            output,result=self.create();self.verified(output,result['manifest_sha256'])
        self.assertFalse(list(output.rglob('__pycache__')))

    def test_both_command_parsers_refuse_duplicate_abbreviated_and_missing_options_before_import(self):
        schemas={'materialize':('--bundle','--sha256','--release-sha256','--output'),
                 'verify':('--context-set','--manifest-sha256')}
        for operation,flags in schemas.items():
            for flag in flags:
                for pair in ((flag,'one',flag,'two'),(flag+'=one',flag,'two'),(flag,'one',flag+'=two'),(flag+'=one',flag+'=one')):
                    output=io.StringIO()
                    with self.subTest(operation=operation,flag=flag),patch.object(self.helper,'helpers',side_effect=AssertionError('import before refusal')),\
                         contextlib.redirect_stderr(output),self.assertRaises(SystemExit)as caught:self.helper.main([operation,*pair])
                    self.assertEqual(caught.exception.code,2);self.assertIn('repeated option refused',output.getvalue())
            for args in ([operation],[operation,'--unknown=x'],[operation,flags[0][:-1]+'=x']):
                with patch.object(self.helper,'helpers',side_effect=AssertionError('import before refusal')),\
                     contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as caught:self.helper.main(args)
                self.assertEqual(caught.exception.code,2)

    def test_relocated_standalone_cli_creates_and_verifies_moved_complete_set(self):
        runtime=self.work/'runtime';shutil.copytree(RUNTIME,runtime)
        for source in (HERE/'source_mirror_catalog.py',HERE/'source_release_context.py'):
            shutil.copyfile(source,runtime/'release'/source.name)
        moved=runtime.with_name('moved-runtime');runtime.rename(moved)
        bundle=self.work/'input.tar';bundle.write_bytes(self.history);output=self.work/'release-set'
        prefix=[sys.executable,'-I','-B',str(moved/'release/source_release_context.py')]
        run=subprocess.run(prefix+['materialize','--bundle',str(bundle),'--sha256',self.m.digest(self.history),
            '--release-sha256',self.fixtures[-1]['release_sha256'],'--output',str(output)],capture_output=True,timeout=60)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);result=json.loads(run.stdout)
        relocated=output.with_name('relocated-set');output.rename(relocated);bundle.unlink()
        run=subprocess.run(prefix+['verify','--context-set',str(relocated),'--manifest-sha256',result['manifest_sha256']],
            capture_output=True,timeout=60)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);self.assertEqual(json.loads(run.stdout)['package_count'],2)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root',type=Path,required=True)
    parser.add_argument('--fixture-root',type=Path,required=True)
    args=parser.parse_args();RUNTIME=args.runtime_root.resolve();FIXTURES=args.fixture_root.resolve()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ReleaseContextControls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),
        errors=len(result.errors),skipped=len(result.skipped),evidence='REAL_ATOMIC_COMPLETE_RELEASE_CONTEXT_CONTROLS',
        packages_per_release=2,retained_releases=2,immutable_Source_constructor=0,native='NOT_RUN',ALPM='NOT_RUN',actual_reader='NOT_RUN'),sort_keys=True))
    raise SystemExit(not result.wasSuccessful()or bool(result.skipped))
