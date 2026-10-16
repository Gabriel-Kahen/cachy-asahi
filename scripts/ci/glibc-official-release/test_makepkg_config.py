#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only config regressions. Never source PKGBUILD or execute makepkg."""
import re,shlex,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
# makepkg's config OPTIONS table is narrower than its recipe build-options table.
CONFIG_OPTIONS={'autodeps','debug','docs','emptydirs','libtool','lto','purge','staticlibs','strip','zipman'}
BROKEN_CONFIG="""BUILDENV=(!distcc !color !ccache check !sign)
OPTIONS=(staticlibs !strip !debug !lto !buildflags !makeflags)
PACKAGER='cachy-asahi project-owned rebuild'
PKGEXT=.pkg.tar.xz
"""


def array(text,name):
    match=re.search(r'^'+re.escape(name)+r'=\(([^\n]*)\)$',text,re.M)
    if not match:raise ValueError('literal array required: '+name)
    return shlex.split(match[1])


def scalar(text,name):
    match=re.search(r'^'+re.escape(name)+r'=(.*)$',text,re.M)
    if not match:return ''
    values=shlex.split(match[1]);return values[0] if len(values)==1 else ''


def problems(text):
    errors=['unknown OPTIONS '+item for item in array(text,'OPTIONS') if item.lstrip('!') not in CONFIG_OPTIONS]
    for name,prefix in (('PKGEXT','.pkg.tar'),('SRCEXT','.src.tar')):
        value=scalar(text,name)
        if not value.startswith(prefix) or value==prefix:errors.append('invalid '+name)
    packager=scalar(text,'PACKAGER')
    warnings=[] if packager=='Unknown Packager' or re.fullmatch(r'([^<>]+ )?<[^<>]*>',packager) else ['PACKAGER format']
    return errors,warnings


class MakepkgConfigControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry=(HERE/'build-entry.sh').read_text()
        cls.config=cls.entry.split("<<'CONF'\n",1)[1].split('\nCONF\n',1)[0]
        cls.recipes=[(ROOT/'packages/core'/name/file).read_text() for name,file in (
            ('cachy-asahi-glibc-official-release','PKGBUILD'),('cachy-asahi-glibc-rebuild','PKGBUILD.in'))]
    def test_actual_failure_shape_reproduced_as_data(self):
        self.assertEqual(problems(BROKEN_CONFIG),(['unknown OPTIONS !buildflags','unknown OPTIONS !makeflags','invalid SRCEXT'],['PACKAGER format']))
    def test_private_config_has_only_supported_options(self):
        self.assertEqual(problems(self.config),([],[]))
        self.assertEqual(array(self.config,'OPTIONS'),['staticlibs','!strip','!debug','!lto'])
    def test_source_archive_extension_and_compressor_present(self):
        self.assertEqual(scalar(self.config,'SRCEXT'),'.src.tar.xz')
        self.assertEqual(scalar(self.config,'PKGEXT'),'.pkg.tar.xz')
        self.assertEqual(array(self.config,'COMPRESSXZ'),['xz','-c','-T1','-6'])
    def test_packager_has_project_label_and_explicit_invalid_contact(self):
        self.assertEqual(scalar(self.config,'PACKAGER'),'cachy-asahi project-owned rebuild <build@cachy-asahi.invalid>')
    def test_both_recipes_use_common_supported_option_subset(self):
        for recipe in self.recipes:
            with self.subTest(recipe=recipe.splitlines()[2]):
                self.assertEqual(array(recipe,'options'),['staticlibs','!strip','!debug','!lto'])
    def test_fixed_flags_are_explicit_in_config_and_recipe_build_functions(self):
        expected=dict(CFLAGS='-O2 -g',CXXFLAGS='-O2 -g',LDFLAGS='',MAKEFLAGS='-j4')
        for key,value in expected.items():self.assertEqual(scalar(self.config,key),value)
        for recipe in self.recipes:
            build=recipe.split('\nbuild() {\n',1)[1].split('\ncheck() {\n',1)[0]
            flags=shlex.split(next(line for line in build.splitlines() if line.strip().startswith('export CFLAGS=')))
            values=dict(item.split('=',1) for item in flags[1:])
            self.assertEqual(values,dict(expected,CPPFLAGS=''))
    def test_actual_check_and_source_verification_stay_enabled(self):
        self.assertIn('check',array(self.config,'BUILDENV'));self.assertNotIn('!check',array(self.config,'BUILDENV'))
        self.assertIn(' --verifysource ',self.entry)
        self.assertNotIn('--nocheck',self.entry);self.assertNotIn('--skipchecksums',self.entry);self.assertNotIn('--skippgpcheck',self.entry)
        for recipe in self.recipes:
            self.assertIn('make -s -k -j4 check >',recipe);self.assertIn('make -s -j4 check-abi >',recipe)
            self.assertIn('(( check_status == 0 && abi_status == 0 ))',recipe)
    def test_private_config_is_explicit_for_every_makepkg_command(self):
        commands=[line for line in self.entry.splitlines() if line.startswith('makepkg ')]
        self.assertEqual(len(commands),3)
        self.assertTrue(all(line.startswith('makepkg --config /work/makepkg.conf ') for line in commands))


if __name__=='__main__':unittest.main()
