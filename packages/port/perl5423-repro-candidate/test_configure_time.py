#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Metadata controls only: no compiler, full Configure, make or package actor.

--source supplies the exact retained tarball. Selected upstream shell fragments
are executed unchanged; modeled Configure/make callbacks are labeled separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
PARENT=HERE.with_name('perl5423-source-candidate')
LOCK=json.loads((HERE/'source-lock.json').read_bytes())
EXPECTED="cf_time='Sun Aug  2 00:00:00 UTC 2026'\n"
SOURCE={}


def source_members(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size!=LOCK['source']['bytes']:
        raise ValueError('exact ordinary retained source required')
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    if digest!=LOCK['source']['sha256']:raise ValueError('source checksum differs')
    root='perl5-'+LOCK['source']['commit']+'/'
    result={}
    with tarfile.open(path) as archive:
        for name in ('Configure','INSTALL','Porting/Glossary','config_h.SH','utils/perlbug.PL'):
            member=archive.getmember(root+name)
            if not member.isfile() or member.size>2*1024**2:raise ValueError('bounded ordinary source member required')
            result[name]=archive.extractfile(member).read().decode()
    return result


def modeled_build(root,*,epoch='1785628800',recipe=HERE,config=EXPECTED,extra='',zone='Pacific/Honolulu'):
    tree=root/'src'/('perl5-'+LOCK['source']['commit']);tree.mkdir(parents=True,exist_ok=True)
    script='''source "$1"
sh() {
  printf '%s\\0' "$@" > configure-args
  printf '%s' "$MODELED_CONFIG" > config.sh
}
make() { printf 'MODELED make reached\\n' > make-marker; return 73; }
'''+extra+'\nbuild\n'
    env=dict(PATH='/usr/bin:/bin',HOME=str(root),srcdir=str(root/'src'),LC_ALL='C',TZ=zone,MODELED_CONFIG=config)
    if epoch is not None:env['SOURCE_DATE_EPOCH']=epoch
    result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',script,'metadata-model',str(recipe/'PKGBUILD')],
        env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
    return result,tree


class MetadataControls(unittest.TestCase):
    def test_modeled_generation_and_configure_flags_match_parent(self):
        with tempfile.TemporaryDirectory(prefix='perl-time-DATA-') as temporary:
            root=Path(temporary);new,tree=modeled_build(root/'new');old,parent=modeled_build(root/'old',recipe=PARENT)
            self.assertEqual((new.returncode,old.returncode),(73,73))
            self.assertEqual((tree/'config.over').read_text(),EXPECTED)
            self.assertEqual((tree/'configure-args').read_bytes(),(parent/'configure-args').read_bytes())
            self.assertTrue((tree/'make-marker').is_file())

    def test_missing_different_or_malformed_epoch_refuses_before_actions(self):
        for epoch in (None,'','0','1785628801','+1785628800','1785628800; false'):
            with self.subTest(epoch=epoch),tempfile.TemporaryDirectory(prefix='perl-time-DATA-') as temporary:
                result,tree=modeled_build(Path(temporary),epoch=epoch)
                self.assertEqual(result.returncode,2)
                self.assertEqual(list(tree.iterdir()),[])

    def test_date_error_or_unexpected_output_refuses_before_override(self):
        for callback in ('date() { return 71; }','date() { printf "UNEXPECTED\\n"; }'):
            with self.subTest(callback=callback),tempfile.TemporaryDirectory(prefix='perl-time-DATA-') as temporary:
                result,tree=modeled_build(Path(temporary),extra=callback)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(list(tree.iterdir()),[])

    def test_unexpected_existing_override_or_link_is_preserved(self):
        for kind in ('custom','directory','symlink','dangling'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='perl-time-DATA-') as temporary:
                root=Path(temporary);tree=root/'src'/('perl5-'+LOCK['source']['commit']);tree.mkdir(parents=True)
                path=tree/'config.over'
                if kind=='custom':path.write_text("cc='OPERATOR VALUE'\n")
                elif kind=='directory':path.mkdir()
                else:
                    if kind=='symlink':(tree/'target').write_text(EXPECTED)
                    path.symlink_to('target')
                before=path.lstat();result,_=modeled_build(root)
                self.assertEqual(result.returncode,2);after=path.lstat()
                self.assertEqual((after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns),(before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns))
                self.assertFalse((tree/'configure-args').exists())

    def test_exact_override_retry_and_timezone_independence(self):
        with tempfile.TemporaryDirectory(prefix='perl-time-DATA-') as temporary:
            root=Path(temporary);first,tree=modeled_build(root,zone='Asia/Tokyo');before=(tree/'config.over').stat()
            second,_=modeled_build(root,zone='America/New_York')
            self.assertEqual((first.returncode,second.returncode),(73,73))
            self.assertEqual((tree/'config.over').read_text(),EXPECTED)
            self.assertEqual((tree/'config.over').stat().st_ino,before.st_ino)
            self.assertEqual((tree/'config.over').stat().st_mtime_ns,before.st_mtime_ns)

    def test_modeled_wrong_effective_config_stops_before_make(self):
        with tempfile.TemporaryDirectory(prefix='perl-time-DATA-') as temporary:
            result,tree=modeled_build(Path(temporary),config="cf_time='WRONG'\n")
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((tree/'make-marker').exists())

    def test_pinned_upstream_documents_order_and_consumers(self):
        raw=SOURCE['Configure'];assignment=raw.index('cf_time=`LC_ALL=C;');override=raw.index(": configuration may be patched via a 'config.over' file")
        emission=raw.index(': create config.sh file',override)
        self.assertLess(assignment,override);self.assertLess(override,emission)
        self.assertNotIn('cf_time=',raw[override:emission])
        self.assertIn('It will get loaded up at the very end, just',SOURCE['INSTALL'])
        self.assertIn('before config.sh is created.',SOURCE['INSTALL'])
        self.assertIn('* Configuration time: $cf_time',SOURCE['config_h.SH'])
        self.assertIn("$Config{cf_time}",SOURCE['utils/perlbug.PL'],'pinned perlbug consumer uses Config cf_time')

    def test_actual_upstream_myread_and_late_override_fragments(self):
        raw=SOURCE['Configure'];begin=raw.index(': set up the echo used in my read\n');finish=raw.index('\nEOSC\n',begin)+len('\nEOSC\n')
        generator=raw[begin:finish]
        begin=raw.index(": configuration may be patched via a 'config.over' file")
        finish=raw.index(': in case they want portability',begin);loader=raw[begin:finish]
        with tempfile.TemporaryDirectory(prefix='perl-real-fragment-') as temporary:
            root=Path(temporary);(root/'UU').mkdir();(root/'config.over').write_text(EXPECTED)
            script='''exec 4>&1
startsh='#!/bin/sh'; n=''; c=''; COLUMNS=80; trnl='\\n'
fastread=yes; silent=true; test=test
cd UU
'''+generator+'''
cd ..
cf_time='EARLIER WALL-CLOCK VALUE'
cc='UNCHANGED COMPILER'
'''+loader+'''
test "$cf_time" = 'Sun Aug  2 00:00:00 UTC 2026'
test "$cc" = 'UNCHANGED COMPILER'
printf '%s\\n' "$cf_time"
'''
            result=subprocess.run(['/bin/sh','-e','-c',script],cwd=root,env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC'),
                stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Sun Aug  2 00:00:00 UTC 2026',result.stdout)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',required=True,type=Path)
    args,remaining=parser.parse_known_args();SOURCE=source_members(args.source)
    unittest.main(argv=[__file__,*remaining])
