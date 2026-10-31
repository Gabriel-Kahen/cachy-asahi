#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert baseline-choice and strict ABI regressions; no recipe/native actors."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
RECIPE=HERE.parents[2]/'packages/core/cachy-asahi-glibc-official-release'

def load(name):
    spec=importlib.util.spec_from_file_location('multiarch_'+name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

M=load('materialize');A=load('abi');S=load('stage');J=load('job');R=load('run')


class MultiarchRepair(unittest.TestCase):
    def setUp(self):
        self.lock=json.loads((RECIPE/'source-lock.json').read_text())
        self.recipe=(RECIPE/'PKGBUILD').read_text()

    def test_concrete_baseline_choice_matches_source_lock(self):
        M.verify_configuration(RECIPE,self.lock)
        self.assertEqual(self.lock['layout']['multiarch'],'disabled')
        self.assertEqual(self.lock['feature_choices']['multiarch'],'disabled')
        self.assertEqual(self.lock['pkgrel'],3)

    def test_missing_duplicated_commented_or_enabled_option_is_refused(self):
        option='    --disable-multi-arch '+chr(92)+'\n'
        for changed in (self.recipe.replace(option,''),self.recipe.replace(option,option*2),
                        self.recipe.replace(option,'#'+option),self.recipe.replace('--disable-multi-arch','--enable-multi-arch')):
            with self.subTest(mutation_sha256=hashlib.sha256(changed.encode()).hexdigest()),tempfile.TemporaryDirectory() as root:
                path=Path(root);(path/'PKGBUILD').write_text(changed)
                with self.assertRaises(ValueError):M.verify_configuration(path,self.lock)

    def test_old_or_contradictory_configuration_cannot_use_new_recipe(self):
        for field in ('pkgrel','layout','feature_choices'):
            changed=copy.deepcopy(self.lock)
            if field=='pkgrel':changed[field]=2
            else:changed[field]['multiarch']='enabled'
            with self.subTest(field=field),self.assertRaises(ValueError):M.verify_configuration(RECIPE,changed)

    def test_old_recipe_cannot_claim_new_identity(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);(path/'PKGBUILD').write_text(self.recipe.replace('pkgrel=3','pkgrel=2'))
            with self.assertRaises(ValueError):M.verify_configuration(path,self.lock)

    def test_stage_runtime_and_public_archive_identity_agree(self):
        self.assertEqual(S.VERSION,'2.43.caa1-3')
        self.assertEqual(J.PACKAGE,S.NAME+'-'+S.VERSION+'-aarch64.pkg.tar.xz')
        self.assertEqual(R.PACKAGE,J.PACKAGE)
        info='pkgname = '+S.NAME+'\npkgver = 2.43.caa1-2\narch = aarch64\n'
        build='pkgname = '+S.NAME+'\npkgver = 2.43.caa1-2\npkgarch = aarch64\npkgbuild_sha256sum = '+'a'*64+'\n'
        with self.assertRaises(ValueError):S.package_identity(info,build,'a'*64)

    def test_func_ifunc_and_weak_global_are_not_interchangeable(self):
        for name,binding in (('memchr','WEAK'),('memcpy','GLOBAL'),('memmove','GLOBAL'),('memset','GLOBAL'),('strlen','WEAK')):
            before=f'1: 00000000 64 FUNC {binding} DEFAULT 12 {name}@@GLIBC_2.17\n'
            for after in (before.replace(' FUNC ',' IFUNC '),before.replace(' DEFAULT ',' PROTECTED '),before.replace('@@','@')):
                with self.subTest(name=name,after=after):self.assertNotEqual(A.symbols(before),A.symbols(after))
            if binding=='WEAK':self.assertNotEqual(A.symbols(before),A.symbols(before.replace(' WEAK ',' GLOBAL ')))

    def test_existing_size_checks_and_abi_source_are_unchanged(self):
        self.assertEqual(hashlib.sha256((HERE/'abi.py').read_bytes()).hexdigest(),'b2ae51e792fc125fa664ba116794827fe5350912861256df8cdad1de479d5ff0')
        for kind in ('OBJECT','TLS'):
            row=f'1: 00000000 18 {kind} GLOBAL DEFAULT 12 state@@GLIBC_2.17\n'
            self.assertNotEqual(A.symbols(row),A.symbols(row.replace(' 18 ',' 19 ')))
        self.assertEqual(self.lock['layout']['gettext_catalogs'],'/opt/caa/g243a1/l')
        self.assertEqual(len(self.lock['layout']['gettext_catalogs'].encode())+1,18)
        for path in M.PATCH_FILES:self.assertNotIn('.abilist',(RECIPE/path).read_text())


if __name__=='__main__':unittest.main()
