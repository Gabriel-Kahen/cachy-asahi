#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verified mirror comparison controls; retained archive programs stay DATA."""
import argparse
import contextlib
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class MirrorDiffControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='.mirror-diff-test-', dir=HERE)
        cls.root = Path(cls.temporary.name)
        cls.runtime = RUNTIME
        cls.m = load('diff_real_trusted_mirror', RUNTIME/'release/release_source_mirror.py')
        cls.catalog = load('diff_real_trusted_catalog', HERE/'source_mirror_catalog.py')
        cls.diff = load('diff_under_test', HERE/'source_mirror_diff.py')
        cls.info = json.loads((FIXTURES/'fixtures.json').read_bytes())['fixtures']
        cls.old, cls.current = cls.info
        deps=cls.m.dependencies(RUNTIME/'release')
        cls.single,_,_=cls.m.build(FIXTURES/cls.old['label'],cls.old['release_sha256'],deps,directory=RUNTIME/'release')
        cls.history,_,_=cls.m.update(cls.single,cls.m.digest(cls.single),cls.old['release_sha256'],
            FIXTURES/cls.current['label'],cls.current['release_sha256'],deps,directory=RUNTIME/'release')
        cls.mirror_sha=cls.m.digest(cls.history)
        cls.patch=patch.object(cls.catalog,'mirror_helper',return_value=cls.m);cls.patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop();cls.temporary.cleanup()

    def compared(self, raw=None, before=None, after=None):
        raw=self.history if raw is None else raw
        return self.diff.compare(raw,self.m.digest(raw),
            self.old['release_sha256'] if before is None else before,
            self.current['release_sha256'] if after is None else after,self.catalog)

    def test_real_history_reports_exact_two_changed_package_pins(self):
        result=self.compared()
        self.assertEqual(result['status'],'VERIFIED_OFFLINE_SOURCE_MIRROR_DIFF')
        self.assertEqual(result['counts'],dict(added=0,removed=0,changed=2,unchanged=0))
        self.assertEqual(result['from_release']['release_sha256'],self.old['release_sha256'])
        self.assertEqual(result['to_release']['release_sha256'],self.current['release_sha256'])
        self.assertEqual([row['package']for row in result['packages']],sorted(p['name']for p in self.old['packages']))
        for row,old,new in zip(result['packages'],self.old['packages'],self.current['packages']):
            self.assertEqual(row['change'],'changed')
            self.assertEqual(row['changed_fields'],['version','package_sha256','recipe_sha256','srcinfo_sha256'])
            self.assertEqual(row['before']['package_sha256'],old['package_sha256'])
            self.assertEqual(row['after']['srcinfo_sha256'],new['srcinfo_sha256'])
        self.assertEqual(result,self.compared())
        self.assertFalse(result['legal_acceptance'])
        self.assertEqual(result['native_build_validation'],'NOT_PERFORMED')
        self.assertEqual(result['corresponding_source_completeness'],'NOT_ASSERTED')
        self.assertEqual(result['release_acceptance'],'NOT_ADMITTED')

    def test_reverse_order_reports_rollback_direction_without_version_guessing(self):
        forward=self.compared();backward=self.compared(before=self.current['release_sha256'],after=self.old['release_sha256'])
        self.assertEqual(backward['counts'],forward['counts'])
        for left,right in zip(forward['packages'],backward['packages']):
            self.assertEqual(left['before'],right['after']);self.assertEqual(left['after'],right['before'])

    def test_same_release_single_or_history_is_explicitly_unchanged(self):
        for raw in (self.single,self.history):
            result=self.compared(raw,before=self.old['release_sha256'],after=self.old['release_sha256'])
            self.assertEqual(result['counts'],dict(added=0,removed=0,changed=0,unchanged=2))
            self.assertTrue(all(row['before']==row['after'] and row['changed_fields']==[] for row in result['packages']))

    def test_added_removed_and_same_version_recipe_changes_are_not_hidden(self):
        # Synthetic classification vectors exercise catalog set differences;
        # real mirror authentication is covered by the other controls.
        rows=self.catalog.catalog(self.single,self.m.digest(self.single),self.old['release_sha256'])['packages']
        before=copy.deepcopy(rows);after=copy.deepcopy(rows[:1])
        after[0]['recipe_sha256']='f'*64
        addition=copy.deepcopy(rows[0]);addition['package']='newly-retained-package';after.append(addition)
        changes=self.diff.package_changes(before,after)
        byname={row['package']:row for row in changes}
        self.assertEqual(byname[rows[0]['package']]['changed_fields'],['recipe_sha256'])
        self.assertEqual(byname[rows[0]['package']]['before']['version'],byname[rows[0]['package']]['after']['version'])
        self.assertEqual(byname[rows[1]['package']]['change'],'removed')
        self.assertIsNone(byname[rows[1]['package']]['after'])
        self.assertEqual(byname['newly-retained-package']['change'],'added')
        self.assertIsNone(byname['newly-retained-package']['before'])

    def test_duplicate_or_malformed_package_classification_data_refuses(self):
        rows=self.catalog.catalog(self.single,self.m.digest(self.single),self.old['release_sha256'])['packages']
        for malformed in ([rows[0],rows[0]], [dict(rows[0],recipe_sha256='not-a-pin')],
                          [dict(rows[0],package='../bad')], [dict(rows[0],extra='ignored')], [dict(rows[0],arch=None)]):
            with self.subTest(rows=malformed),self.assertRaises(ValueError):self.diff.package_changes(malformed,rows)

    def test_wrong_mirror_pin_or_unretained_from_or_to_release_refuses(self):
        for checksum,before,after in (('0'*64,self.old['release_sha256'],self.current['release_sha256']),
                (self.mirror_sha,'0'*64,self.current['release_sha256']),
                (self.mirror_sha,self.old['release_sha256'],'0'*64)):
            with self.subTest(before=before,after=after),self.assertRaises(ValueError):
                self.diff.compare(self.history,checksum,before,after,self.catalog)

    def test_corrupt_unselected_recovery_data_refuses_even_same_current_comparison(self):
        files=self.m.canonical_files(self.history,self.mirror_sha);history=self.m.decode(files['history.json'])
        key='objects/'+history['releases'][0]['manifest']['sha256'];files[key]+=b' '
        raw=self.m.tar_bytes(files)
        with self.assertRaises(ValueError):self.compared(raw,before=self.current['release_sha256'],after=self.current['release_sha256'])

    def test_archived_python_remains_inert_and_comparison_does_not_write_or_fetch(self):
        files=self.m.canonical_files(self.single,self.m.digest(self.single))
        files['verify.py']=b"raise RuntimeError('ARCHIVED_CODE_EXECUTED')\n"
        manifest=self.m.decode(files['mirror.json']);manifest['verifier_sha256']=self.m.digest(files['verify.py'])
        files['mirror.json']=self.m.encoded(manifest);raw=self.m.tar_bytes(files)
        forbidden=AssertionError('diff must not write, execute, extract or download')
        with patch.object(socket,'socket',side_effect=forbidden),patch.object(socket,'getaddrinfo',side_effect=forbidden),\
             patch.object(subprocess,'Popen',side_effect=forbidden),patch.object(os,'open',side_effect=forbidden),\
             patch.object(Path,'write_bytes',side_effect=forbidden):
            self.assertEqual(self.compared(raw,before=self.old['release_sha256'],after=self.old['release_sha256'])['counts']['unchanged'],2)

    def test_refusal_prints_no_partial_comparison(self):
        output=io.StringIO()
        with patch.object(self.diff,'catalog_helper',return_value=self.catalog),\
             patch.object(self.m,'read_file',return_value=self.history),contextlib.redirect_stdout(output):
            status=self.diff.main(['diff','--bundle','inert.tar','--sha256',self.mirror_sha,
                '--from-release-sha256',self.old['release_sha256'],'--to-release-sha256','0'*64])
        self.assertEqual(status,1);result=json.loads(output.getvalue())
        self.assertEqual(set(result),{'status','reason'});self.assertEqual(result['status'],'REFUSED')

    def test_all_four_scalar_options_refuse_duplicate_forms_before_import(self):
        flags=('--bundle','--sha256','--from-release-sha256','--to-release-sha256')
        for flag in flags:
            for pair in ((flag,'one',flag,'two'),(flag+'=one',flag,'two'),
                         (flag,'one',flag+'=two'),(flag+'=one',flag+'=one')):
                with self.subTest(flag=flag,pair=pair),patch.object(self.diff,'catalog_helper',side_effect=AssertionError('import before refusal')),\
                     contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as caught:
                    self.diff.main(['diff',*pair])
                self.assertEqual(caught.exception.code,2)
        for argv in (['diff','--bund=inert'],['diff','--unknown=x'],['diff']):
            with self.subTest(argv=argv),patch.object(self.diff,'catalog_helper',side_effect=AssertionError('import before refusal')),\
                 contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as caught:self.diff.main(argv)
            self.assertEqual(caught.exception.code,2)

    def test_actual_moved_standalone_helper_reports_verified_comparison(self):
        prefix=self.root/'initial-prefix'
        shutil.copytree(self.runtime,prefix)
        for source in (HERE/'source_mirror_catalog.py',HERE/'source_mirror_diff.py'):
            shutil.copyfile(source,prefix/'release'/source.name)
        moved=prefix.with_name('moved-prefix');prefix.rename(moved)
        bundle=self.root/'history.tar';bundle.write_bytes(self.history)
        argv=[sys.executable,'-I','-B',str(moved/'release/source_mirror_diff.py'),'diff','--bundle',str(bundle),'--sha256',self.mirror_sha,
            '--from-release-sha256',self.old['release_sha256'],'--to-release-sha256',self.current['release_sha256']]
        run=subprocess.run(argv,cwd=self.root,env={'PATH':'/usr/bin:/bin','HOME':str(self.root),
            'PYTHONPATH':'/unavailable','PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertEqual(json.loads(run.stdout),self.compared())
        self.assertFalse(list(moved.rglob('__pycache__')))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root',type=Path,required=True)
    parser.add_argument('--fixture-root',type=Path,required=True)
    args=parser.parse_args();RUNTIME=args.runtime_root.resolve();FIXTURES=args.fixture_root.resolve()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(MirrorDiffControls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report=dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),
        errors=len(result.errors),skipped=len(result.skipped),fixture_scope='REAL_FROZEN_RUNTIME_TWO_RELEASE_MIRRORS_SYNTHETIC_PACKAGE_ARCHIVES',
        mirror_fixture_builds=2,immutable_Source_constructor_calls=0,native='NOT_RUN',installation='NOT_RUN',Reader='NOT_RUN')
    print(json.dumps(report,sort_keys=True));raise SystemExit(not result.wasSuccessful()or bool(result.skipped))
