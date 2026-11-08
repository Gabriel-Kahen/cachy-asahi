#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real materialized context summaries; no builders or native actors."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class ContextInfoControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='.context-info-test-',dir=HERE)
        cls.root=Path(cls.temporary.name)
        cls.consumer=load('context_info_real_consumer',RUNTIME/'build/mirror_consumer.py')
        cls.deps=cls.consumer.dependencies(RUNTIME/'build');cls.m=cls.deps['mirror']
        cls.helper=load('context_info_under_test',HERE/'source_context_info.py')
        cls.fixtures=json.loads((FIXTURES/'fixtures.json').read_bytes())['fixtures']
        old,current=cls.fixtures;md=cls.m.dependencies(RUNTIME/'release')
        single,_,_=cls.m.build(FIXTURES/old['label'],old['release_sha256'],md,directory=RUNTIME/'release')
        cls.history,_,_=cls.m.update(single,cls.m.digest(single),old['release_sha256'],
            FIXTURES/current['label'],current['release_sha256'],md,directory=RUNTIME/'release')

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def setUp(self):
        self.work=self.root/self._testMethodName;self.work.mkdir(mode=0o700)

    def context(self,fixture=None,package=None,label='context'):
        fixture=self.fixtures[-1]if fixture is None else fixture
        package=fixture['packages'][0]if package is None else package
        prepared=self.consumer.prepare(self.history,self.m.digest(self.history),fixture['release_sha256'],
            *(package[key]for key in('name','version','arch','package_sha256','recipe_sha256','srcinfo_sha256')),self.deps)
        path=self.work/label;result=self.consumer.materialize(prepared,path,self.deps)
        return path,result['selection_sha256']

    def summary(self,path,pin):return self.helper.summarize(path,pin,self.deps,self.consumer)

    def changed(self,path,value):
        path.chmod(0o600);path.write_bytes(self.m.encoded(value)if isinstance(value,dict)else value);path.chmod(0o400)

    def snapshot(self,root):
        return {p.relative_to(root).as_posix():(p.read_bytes(),stat.S_IMODE(p.stat().st_mode))
                for p in root.rglob('*')if p.is_file()}

    def test_actual_four_contexts_show_missing_selection_sources_and_held_inputs(self):
        for fixture in self.fixtures:
            for package in fixture['packages']:
                with self.subTest(release=fixture['label'],package=package['name']):
                    path,pin=self.context(fixture,package,fixture['label']+'-'+package['name'])
                    before=self.consumer.verify_context(path,pin,self.deps)
                    self.assertEqual(set(before),{'status','selection_sha256','package','native_build','hardware','release'})
                    result=self.summary(path,pin)
                    self.assertEqual(result['status'],'VERIFIED_MIRROR_BUILDER_CONTEXT_SUMMARY')
                    self.assertEqual(result['package'],dict(name=package['name'],version=package['version'],
                        arch=package['arch'],sha256=package['package_sha256']))
                    self.assertEqual(result['release_sha256'],fixture['release_sha256'])
                    self.assertEqual(result['mirror_sha256'],self.m.digest(self.history))
                    self.assertEqual(result['recipe_sha256'],package['recipe_sha256'])
                    self.assertEqual(result['srcinfo_sha256'],package['srcinfo_sha256'])
                    self.assertEqual({row['path']:row['sha256']for row in result['recipe_inputs']},package['sources'])
                    self.assertEqual(result['recipe_inputs'],sorted(result['recipe_inputs'],key=lambda row:row['path']))
                    self.assertEqual(result['builder']['status'],'HELD_ACTUAL_SELECTORS_NULL')
                    self.assertTrue(all(value is None for value in result['builder']['actual_selectors'].values()))
                    self.assertEqual(result['builder']['required_inputs'],sorted(result['builder']['actual_selectors']))
                    self.assertFalse(result['builder']['execution_allowed'])
                    self.assertIsNone(result['builder']['actual_archive_sha256'])
                    self.assertFalse(result['legal_acceptance'])
                    self.assertEqual(result['native_build'],'NOT_RUN')
                    self.assertEqual(result['installation'],'NOT_RUN')
                    self.assertEqual(result['release'],'NOT_ADMITTED')
                    self.assertEqual(result['file_counts']['recipe_inputs'],len(package['sources']))

    def test_moved_context_summary_is_identical_and_deterministic(self):
        path,pin=self.context();before=self.summary(path,pin);moved=path.with_name('moved-context');path.rename(moved)
        self.assertEqual(before,self.summary(moved,pin));self.assertEqual(before,self.summary(moved,pin))

    def test_wrong_pin_tampered_missing_or_extra_files_and_aliases_refuse(self):
        path,pin=self.context()
        with self.assertRaises(ValueError):self.summary(path,'0'*64)
        source=path/'recipe/PKGBUILD';raw=source.read_bytes();self.changed(source,raw+b'\n# altered\n')
        with self.assertRaises((ValueError,OSError)):self.summary(path,pin)
        self.changed(source,raw);extra=path/'extra';extra.write_bytes(b'unlisted')
        with self.assertRaises(ValueError):self.summary(path,pin)
        extra.unlink();source.unlink()
        with self.assertRaises(OSError):self.summary(path,pin)
        source.write_bytes(raw);source.chmod(0o400);held=self.work/'held-data';source.rename(held);source.symlink_to(held)
        with self.assertRaises((ValueError,OSError)):self.summary(path,pin)

    def test_forged_selection_pin_cannot_turn_held_builder_into_executable_request(self):
        path,_=self.context();selection=json.loads((path/'selection.json').read_bytes());request_path=path/'builder-request.json'
        request=json.loads(request_path.read_bytes());request['actual_selectors']['builder_image']='unauthorized:image'
        self.changed(request_path,request);raw=request_path.read_bytes()
        selection['files']['builder-request.json'].update(bytes=len(raw),sha256=self.m.digest(raw))
        self.changed(path/'selection.json',selection)
        with self.assertRaises(ValueError):self.summary(path,self.m.digest((path/'selection.json').read_bytes()))

    def test_selection_reread_is_bound_after_trusted_verification(self):
        path,pin=self.context();original=self.consumer.verify_context
        def changed_after_verify(*args):
            result=original(*args);selection=json.loads((path/'selection.json').read_bytes())
            selection['release_sha256']='0'*64;self.changed(path/'selection.json',selection);return result
        with patch.object(self.consumer,'verify_context',side_effect=changed_after_verify),self.assertRaises(ValueError):
            self.summary(path,pin)

    def test_request_reread_is_bound_after_trusted_verification(self):
        path,pin=self.context();original=self.consumer.verify_context
        def changed_after_verify(*args):
            result=original(*args);request=json.loads((path/'builder-request.json').read_bytes())
            request['actual_selectors']['output']='not-held';self.changed(path/'builder-request.json',request);return result
        with patch.object(self.consumer,'verify_context',side_effect=changed_after_verify),self.assertRaises(ValueError):
            self.summary(path,pin)

    def test_summary_preserves_context_and_does_not_execute_retained_code_or_download(self):
        path,pin=self.context();before=self.snapshot(path);original=importlib.util.spec_from_file_location
        def trusted_only(name,filename,*args,**kwargs):
            if Path(filename).is_relative_to(path):raise AssertionError('retained context code imported')
            return original(name,filename,*args,**kwargs)
        forbidden=AssertionError('context summary must not launch builder or network')
        with patch.object(importlib.util,'spec_from_file_location',side_effect=trusted_only),\
             patch.object(subprocess,'Popen',side_effect=forbidden),patch.object(socket,'socket',side_effect=forbidden),\
             patch.object(socket,'getaddrinfo',side_effect=forbidden):self.summary(path,pin)
        self.assertEqual(before,self.snapshot(path))

    def test_duplicate_full_options_abbreviations_and_missing_values_refuse_before_import(self):
        for flag in ('--context','--selection-sha256'):
            for pair in ((flag,'one',flag,'two'),(flag+'=one',flag,'two'),(flag,'one',flag+'=two'),(flag+'=one',flag+'=one')):
                with self.subTest(flag=flag,pair=pair),patch.object(self.helper,'consumer_helper',side_effect=AssertionError('import before refusal')),\
                     contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as caught:self.helper.main(['show',*pair])
                self.assertEqual(caught.exception.code,2)
        for args in (['show','--cont=inert'],['show','--unknown=x'],['show']):
            with self.subTest(args=args),patch.object(self.helper,'consumer_helper',side_effect=AssertionError('import before refusal')),\
                 contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as caught:self.helper.main(args)
            self.assertEqual(caught.exception.code,2)

    def test_refusal_prints_no_partial_source_or_builder_summary(self):
        path,_=self.context();output=io.StringIO()
        with patch.object(self.helper,'consumer_helper',return_value=self.consumer),contextlib.redirect_stdout(output):
            status=self.helper.main(['show','--context',str(path),'--selection-sha256','0'*64])
        result=json.loads(output.getvalue());self.assertEqual(status,1)
        self.assertEqual(set(result),{'status','reason'});self.assertEqual(result['status'],'REFUSED')

    def test_relocated_standalone_summary_uses_only_adjacent_trusted_runtime(self):
        path,pin=self.context();before=self.snapshot(path);prefix=self.work/'initial-runtime';shutil.copytree(RUNTIME,prefix)
        shutil.copyfile(HERE/'source_context_info.py',prefix/'release/source_context_info.py')
        moved=prefix.with_name('moved-runtime');prefix.rename(moved)
        run=subprocess.run([sys.executable,'-I','-B',str(moved/'release/source_context_info.py'),'show',
            '--context',str(path),'--selection-sha256',pin],capture_output=True,cwd=self.work,
            env={'PATH':'/usr/bin:/bin','PYTHONPATH':'/unavailable','PYTHONDONTWRITEBYTECODE':'1'},timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertEqual(json.loads(run.stdout),self.summary(path,pin))
        self.assertEqual(before,self.snapshot(path));self.assertFalse(list(moved.rglob('__pycache__')))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root',type=Path,required=True)
    parser.add_argument('--fixture-root',type=Path,required=True)
    args=parser.parse_args();RUNTIME=args.runtime_root.resolve();FIXTURES=args.fixture_root.resolve()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ContextInfoControls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),
        errors=len(result.errors),skipped=len(result.skipped),actual_context_selections=4,mirror_fixture_builds=2,
        immutable_Source_constructor=0,native='NOT_RUN',ALPM='NOT_RUN',actual_reader='NOT_RUN',
        evidence='REAL_VERIFIED_CONTEXT_SUMMARY_CONTROLS'),sort_keys=True))
    raise SystemExit(not result.wasSuccessful()or bool(result.skipped))
