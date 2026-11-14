#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite recipe, metadata, staging and refusal controls; no install/build actors."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from stage_commands import COMMANDS, deliver

HERE = Path(__file__).resolve().parent
LOCK = json.loads((HERE/'source-lock.json').read_bytes())


def inspector():
    raw = (HERE/'check_stage.py').read_text()
    nodes = [n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)]
    import stat
    scope = dict(Path=Path,stat=stat,hashlib=hashlib,os=os,COMMANDS=COMMANDS)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'isolated stage DATA controls','exec'),scope)
    return scope['inspect']


def model(root):
    paths = {
        'usr/bin/perl':b'\x7fELF\x02\x01'+bytes(12)+(62).to_bytes(2,'little')+bytes(44),
        'usr/lib/perl5/5.42/core_perl/CORE/libperl.so':b'\x7fELF\x02\x01'+bytes(12)+(62).to_bytes(2,'little')+bytes(44),
        'usr/lib/perl5/5.42/core_perl/Config.pm':b'MODELED CONFIG DATA',
        'usr/share/perl5/core_perl/strict.pm':b'MODELED MODULE DATA',
        'usr/share/perl5/core_perl/pod/perldiag.pod':b'MODELED RUNTIME DIAGNOSTIC DATA',
        **{'usr/share/licenses/perl/'+n:(HERE/('UPSTREAM-'+n)).read_bytes() for n in ('README','Artistic','Copying')},
        **{'usr/bin/core_perl/'+n:b'#!/usr/bin/perl\n# MODELED script DATA\n' for n in COMMANDS},
    }
    for name,body in paths.items():
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);p.chmod(0o755 if name.startswith('usr/bin/') else 0o644)
    deliver(root)
    return paths


class RecipeTests(unittest.TestCase):
    def test_source_and_patch_pins_are_exact_official_candidate(self):
        self.assertEqual(LOCK['version'],'5.42.3-1.2')
        self.assertEqual(LOCK['source']['commit'],'bc3dab4d4f66de5ea67dda34e5feb5230a54c603')
        self.assertEqual(LOCK['source']['sha256'],'16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725')
        self.assertEqual(LOCK['source']['bytes'],22610875)
        self.assertEqual([x['commit'] for x in LOCK['patches']],['568e6fd238867bb9e99fa3f47cba3169009239e0','54cf3d44cbbedd17d774e9a37921963e8fd5d0cb'])
        for row in LOCK['patches']:
            raw=(HERE/row['path']).read_bytes()
            self.assertEqual(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),{k:row[k] for k in ('bytes','sha256')})
            self.assertTrue(raw.startswith(('From '+row['commit']).encode()))
        self.assertEqual(LOCK['historical_binary']['recipe_correspondence'],'UNRESOLVED_NOT_CLAIMED')
        self.assertFalse(LOCK['historical_binary']['observed_hook']['candidate_copy'])
        self.assertEqual(LOCK['provider_reconciliation']['selected_source_version'],'1.69')
        self.assertIn('perl-scalar-list-utils=1.69',(HERE/'provides.txt').read_text().splitlines())

    def test_verbatim_dual_source_notices_and_original_packaging_license(self):
        for name,row in LOCK['notices'].items():
            raw=(HERE/('UPSTREAM-'+name)).read_bytes()
            self.assertEqual(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),row)
        self.assertIn(b'The "Artistic License"',(HERE/'UPSTREAM-Artistic').read_bytes())
        self.assertIn(b'Version 1, February 1989',(HERE/'UPSTREAM-Copying').read_bytes())
        self.assertIn(b'Permission is hereby granted',(HERE/'LICENSE.packaging').read_bytes())

    def test_srcinfo_matches_actual_recipe_and_pinned_local_sources(self):
        raw=subprocess.run(['/usr/bin/makepkg','--printsrcinfo'],cwd=HERE,check=True,capture_output=True).stdout
        self.assertEqual(raw,(HERE/'.SRCINFO').read_bytes())
        rows={}
        for line in raw.decode().splitlines():
            if ' = ' in line:
                name,value=line.strip().split(' = ',1);rows.setdefault(name,[]).append(value)
        self.assertEqual(rows['pkgrel'],['1.2']);self.assertEqual(rows['arch'],['aarch64','x86_64'])
        self.assertEqual(len(rows['source']),len(rows['sha256sums']))
        self.assertEqual(rows['sha256sums'][0],LOCK['source']['sha256'])
        for name,digest in zip(rows['source'][1:],rows['sha256sums'][1:]):
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)
        self.assertEqual(rows['provides'],(HERE/'provides.txt').read_text().splitlines())
        self.assertEqual(len(rows['provides']),113)
        self.assertEqual(rows['optdepends'],['perl-text-diff: ptardiff archive comparisons'])
        self.assertIn('!purge',rows['options'])

    def test_actual_build_and_check_have_no_test_or_dependency_waiver(self):
        source=(HERE/'PKGBUILD').read_text()
        self.assertIn('TEST_JOBS=2 make test_harness || return',source)
        self.assertIn('make DESTDIR="$pkgdir" install || return',source)
        self.assertIn('--batch --fuzz=0',source)
        for forbidden in ('--nodeps','--nocheck','--syncdeps','sudo ','post_install','post_upgrade','-march=native','--privileged'):
            self.assertNotIn(forbidden,source)
        self.assertIsNone(re.search(r'^install=',source,re.M))
        self.assertIn('BUILD_ZLIB=0 BUILD_BZIP2=0',source)
        self.assertIn("grep -F '[libz.so.1]' || return",source)
        self.assertIn("grep -F '[libbz2.so.1.0]' || return",source)
        checks=(HERE/'check_config.pl').read_text()
        self.assertIn('$Module::CoreList::version{5.042003}',checks)
        self.assertIn('DB_File GDBM_File Compress::Raw::Zlib Compress::Raw::Bzip2 threads',checks)

    def test_package_and_prepare_refuse_unsafe_inputs_before_actions(self):
        for function,values in [('prepare',{}),('package',dict(pkgdir='/')),('package',dict(pkgdir='/MODELED',srcdir='/MODELED'))]:
            code='source "$1"; '+function
            env=dict(PATH='/usr/bin:/bin',HOME='/tmp',startdir='/OTHER',srcdir='/SOURCE',**{k:v for k,v in values.items() if k!='srcdir'})
            if 'srcdir' in values:env['srcdir']=values['srcdir']
            result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',code,'recipe-control',str(HERE/'PKGBUILD')],env=env,capture_output=True)
            self.assertEqual(result.returncode,2,result.stderr.decode())

    def test_model_stage_passes_without_executing_payload(self):
        with tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
            root=Path(temporary);paths=model(root)
            value=inspector()(root,'x86_64')
            self.assertEqual(value['files'],len(paths));self.assertEqual(value['installation'],'NOT_RUN')

    def test_wrong_or_missing_elf_architecture_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
            root=Path(temporary);model(root)
            with self.assertRaisesRegex(ValueError,'ELF architecture'):inspector()(root,'aarch64')
            (root/'usr/bin/perl').write_bytes(b'not an interpreter')
            with self.assertRaisesRegex(ValueError,'ELF architecture'):inspector()(root,'x86_64')

    def test_missing_dual_notice_or_core_config_is_refused(self):
        for name in ('usr/share/licenses/perl/Artistic','usr/lib/perl5/5.42/core_perl/Config.pm','usr/share/perl5/core_perl/pod/perldiag.pod'):
            with tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
                root=Path(temporary);model(root);(root/name).unlink()
                with self.assertRaisesRegex(ValueError,'dual notices'):inspector()(root,'x86_64')

    def test_hooks_local_modules_and_system_mutation_paths_are_refused(self):
        for name in ('etc/profile.d/perl.sh','usr/local/lib/operator.pm','usr/share/libalpm/hooks/old.hook','usr/lib/systemd/system/perl.service'):
            with tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
                root=Path(temporary);model(root);p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'MODELED forbidden DATA')
                with self.assertRaises(ValueError):inspector()(root,'x86_64')

    def test_relative_internal_link_only_and_special_modes_refuse(self):
        with tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
            root=Path(temporary);model(root);link=root/'usr/bin/alias';link.symlink_to('perl')
            self.assertEqual(inspector()(root,'x86_64')['links'],30)
            link.unlink();link.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError,'escaping stage link'):inspector()(root,'x86_64')
            link.unlink();(root/'usr/bin/perl').chmod(0o4755)
            with self.assertRaisesRegex(ValueError,'set-id'):inspector()(root,'x86_64')

    def test_command_delivery_refuses_all_collision_types_before_creating_links(self):
        for kind in ('file','directory','link','dangling'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
                root=Path(temporary);model(root)
                for name in COMMANDS:(root/'usr/bin'/name).unlink()
                collision=root/'usr/bin'/COMMANDS[-1]
                if kind=='file':collision.write_bytes(b'OTHER OWNER')
                elif kind=='directory':collision.mkdir()
                else:collision.symlink_to('perl' if kind=='link' else 'missing')
                with self.assertRaisesRegex(ValueError,'destination already exists'):deliver(root)
                self.assertFalse(any((root/'usr/bin'/n).is_symlink() for n in COMMANDS[:-1]))
                self.assertTrue(collision.exists() or collision.is_symlink())

    def test_incomplete_nonexecutable_or_linked_script_refused_before_delivery(self):
        for kind in ('missing','nonexecutable','symlink','extra'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
                root=Path(temporary);model(root)
                for name in COMMANDS:(root/'usr/bin'/name).unlink()
                script=root/'usr/bin/core_perl'/COMMANDS[-1]
                if kind=='missing':script.unlink()
                elif kind=='nonexecutable':script.chmod(0o644)
                elif kind=='symlink':script.unlink();script.symlink_to(COMMANDS[0])
                else:(script.parent/'unexpected').write_bytes(b'EXTRA DATA')
                with self.assertRaises(ValueError):deliver(root)
                self.assertFalse(any((root/'usr/bin'/n).is_symlink() for n in COMMANDS))

    def test_missing_or_misdirected_command_alias_refused(self):
        for target in (None,'perl','core_perl/'+COMMANDS[1]):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix='perl-stage-DATA-') as temporary:
                root=Path(temporary);model(root);link=root/'usr/bin'/COMMANDS[0];link.unlink()
                if target is not None:link.symlink_to(target)
                with self.assertRaisesRegex(ValueError,'normal-PATH command link'):inspector()(root,'x86_64')


if __name__=='__main__':unittest.main()
