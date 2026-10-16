#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/data-only check-repair regressions; no compiler, recipe or package actor."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
RECIPE=ROOT/'packages/core/cachy-asahi-glibc-official-release'

def load(name):
    spec=importlib.util.spec_from_file_location('repair_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
M=load('materialize');A=load('abi');T=load('collect_tests');S=load('stage');R=load('run')


class CheckRepair(unittest.TestCase):
    def test_private_layout_retains_exact_18_byte_configured_object(self):
        lock=json.loads((RECIPE/'source-lock.json').read_text());recipe=(RECIPE/'PKGBUILD').read_text()
        self.assertEqual(lock['prefix'],'/opt/caa/g243a1');self.assertEqual(S.PREFIX,R.PREFIX)
        self.assertEqual('/'+S.PREFIX,lock['prefix']);self.assertEqual(lock['layout']['gettext_catalogs'],lock['prefix']+'/l')
        self.assertEqual(len(lock['layout']['gettext_catalogs'].encode('ascii'))+1,18)
        self.assertIn('--localedir="$_prefix/l"',recipe);self.assertNotIn('/usr/share/locale',recipe)
        self.assertEqual(S.VERSION,'2.43.caa1-3');self.assertIn('pkgrel=3',recipe)

    def test_exact_reviewed_patch_order_and_bytes_are_required(self):
        lock=json.loads((RECIPE/'source-lock.json').read_text());M.verify_patches(RECIPE,lock)
        for change in ('reverse','missing','unknown','digest'):
            bad=copy.deepcopy(lock)
            if change=='reverse':bad['patch_order'].reverse()
            elif change=='missing':bad['patch_order'].pop()
            elif change=='unknown':bad['patch_order'][0]['path']='unreviewed.patch'
            else:bad['patch_order'][0]['sha256']='0'*64
            with self.subTest(change=change),self.assertRaises(ValueError):M.verify_patches(RECIPE,bad)
        with tempfile.TemporaryDirectory() as d:
            target=Path(d);shutil.copytree(RECIPE,target/'recipe')
            (target/'recipe'/next(iter(M.PATCH_FILES))).write_text('tampered')
            with self.assertRaises(ValueError):M.verify_patches(target/'recipe',lock)

    def test_timeout_is_one_standard_harness_variable_and_all_tests_stay(self):
        recipe=(RECIPE/'PKGBUILD').read_text()
        self.assertEqual(recipe.count('TIMEOUTFACTOR=5'),1)
        self.assertIn('tst-malloc-too-large-malloc-hugetlb2-ENV += TIMEOUTFACTOR=5',recipe)
        self.assertIn('make -s -k -j4 check >',recipe);self.assertIn('make -s -j4 check-abi >',recipe)
        self.assertIn('(( check_status == 0 && abi_status == 0 ))',recipe)
        for forbidden in ('--nocheck','tests-exclude','update-abi','libc.abilist'):
            self.assertNotIn(forbidden,recipe)

    def test_only_five_stale_xfail_annotations_are_removed_no_test_code(self):
        patch=(RECIPE/'0002-held-builder-test-expectations.patch').read_text()
        removed=[line[1:] for line in patch.splitlines() if line.startswith('-') and not line.startswith('---')]
        self.assertEqual(set(removed),{'test-xfail-tst-protected1a = yes','test-xfail-tst-protected1b = yes',
            'test-xfail-UNIX98/ndbm.h/linknamespace = yes','test-xfail-XOPEN2K/ndbm.h/linknamespace = yes',
            'test-xfail-XOPEN2K8/ndbm.h/linknamespace = yes'})
        self.assertEqual(len(removed),5)
        self.assertFalse(any(line.startswith('+') and not line.startswith('+++') for line in patch.splitlines()))

    def test_gnu_abi_expectations_and_independent_size_gate_stay_strict(self):
        self.assertEqual(hashlib.sha256((HERE/'abi.py').read_bytes()).hexdigest(),'b2ae51e792fc125fa664ba116794827fe5350912861256df8cdad1de479d5ff0')
        before='1: 00000000 18 OBJECT GLOBAL DEFAULT 12 _nl_default_dirname@@GLIBC_2.17\n'
        wrong=before.replace(' 18 OBJECT',' 67 OBJECT')
        self.assertNotEqual(A.symbols(before),A.symbols(wrong))
        for name in M.PATCH_FILES:self.assertNotIn('.abilist',(RECIPE/name).read_text())

    def test_unknown_fail_xpass_and_new_timeout_are_not_waived(self):
        for status in ('FAIL','XPASS','ERROR'):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);build=root/'build';out=root/'out';build.mkdir();out.mkdir()
                (build/'one.test-result').write_text('PASS: passing\n')
                (build/'two.test-result').write_text(status+': unknown-new-test\n')
                (out/'check-exit').write_text('0');(out/'abi-exit').write_text('0')
                result=T.collect(build,out)
                self.assertEqual(result['status'],'FAIL_UPSTREAM_TESTS');self.assertEqual(result['counts'][status],1)

    def test_mount_patch_keeps_upstream_macro_values_when_defined(self):
        patch=(RECIPE/'0001-mount-macro-guards.patch').read_text()
        added=[line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++')]
        self.assertEqual(added,['#ifndef OPEN_TREE_CLONE','# define OPEN_TREE_CLONE    1 /* Clone the target tree and attach the clone */','#endif',
            '#ifndef OPEN_TREE_CLOEXEC','# define OPEN_TREE_CLOEXEC  O_CLOEXEC /* Close the file on execve() */','#endif'])
        self.assertNotIn('#undef',patch)


if __name__=='__main__':unittest.main()
