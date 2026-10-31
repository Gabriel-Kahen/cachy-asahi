#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Actual package() staging and real TEST-GPG installed-v2 controls; no host install."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--recipe-root',type=Path,default=Path(__file__).resolve().parent)
parser.add_argument('--runtime-recipe-root',type=Path)
args=parser.parse_args();ROOT=args.recipe_root.absolute()


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def command(argv,**kwargs):
    return subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=60,**kwargs)


STAGING=tempfile.TemporaryDirectory(prefix='client-v2-stage-')
STAGE=Path(STAGING.name)/'installed';STAGE.mkdir()
OWN_STAGE=Path(STAGING.name)/'companion';OWN_STAGE.mkdir()
PINS=json.loads((ROOT/'helper-pins.json').read_bytes())

def stage(recipe,target):
    result=command(['/bin/bash','--noprofile','--norc','-c','source "$1"; package','stage',recipe/'PKGBUILD'],
        env=dict(PATH='/usr/bin:/bin',srcdir=str(recipe),pkgdir=str(target)))
    if result.returncode:raise RuntimeError(result.stderr)

def files(path):return {p.relative_to(path).as_posix():p.read_bytes()for p in path.rglob('*')if p.is_file()}

PREFIX=STAGE/'usr/share/cachy-asahi/repository-runtime'
if args.runtime_recipe_root:
    stage(args.runtime_recipe_root.absolute(),STAGE)
else:
    # makepkg's exact runtime dependency is read only; no host installation.
    installed=Path('/usr/share/cachy-asahi/repository-runtime')
    for name in PINS['required_runtime']['files']:
        target=PREFIX/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(installed/name,target)
ORIGINAL=files(STAGE)
for name,row in PINS['required_runtime']['files'].items():
    raw=(PREFIX/name).read_bytes()
    if len(raw)!=row['bytes']or __import__('hashlib').sha256(raw).hexdigest()!=row['sha256']:
        raise RuntimeError('required original runtime helper differs: '+name)
stage(ROOT,OWN_STAGE);OWNED=files(OWN_STAGE)
if set(ORIGINAL)&set(OWNED):raise RuntimeError('companion/runtime ownership overlap')
stage(ROOT,STAGE)
if any((STAGE/name).read_bytes()!=raw for name,raw in ORIGINAL.items()):raise RuntimeError('original runtime payload changed')
V2=PREFIX/'scripts/client/client_v2.py'
C=load('installed_runtime_v2',V2)
FIXTURE=load('unchanged_client_v2_TEST_fixture',ROOT/'test_client_v2.py')
FIXTURE.c=C  # All actual verifier/association calls resolve to installed helper bytes.


class StageTests(unittest.TestCase):
    def test_actual_package_closed_stage_and_help(self):
        row=command([sys.executable,'-I','-B',ROOT/'check_source.py','--recipe-root',ROOT,'--stage',OWN_STAGE])
        self.assertEqual(row.returncode,0,row.stdout+row.stderr)
        self.assertEqual(json.loads(row.stdout)['installed_files'],6)
        for options in (['--help'],['sources','--help']):
            row=command([sys.executable,'-I','-B',V2,*options],cwd=STAGE)
            self.assertEqual(row.returncode,0,row.stderr);self.assertIn('sources' if options==['--help'] else '--artifact-sha256',row.stdout)
        self.assertEqual(Path(C.source_delivery_helper().__file__).absolute(),PREFIX/'scripts/release/source_delivery.py')

    def test_original_three_helpers_are_byte_held_and_load_from_installed_layout(self):
        files=PINS['required_runtime']['files']
        expected={'scripts/client/client.py':'48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7',
          'scripts/release/release.py':'e4ab44f7cc020ae1d705b64362e8b1b05fa0c29c19ce64d886116055619c0435',
          'scripts/release/source_delivery.py':'8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'}
        for name,digest in expected.items():
            self.assertEqual(files[name]['sha256'],digest)
            self.assertEqual(C.digest((PREFIX/name).read_bytes()),digest)
        self.assertFalse(set(ORIGINAL)&set(OWNED))
        self.assertEqual(len(OWNED),6)
        self.assertTrue(all((STAGE/name).read_bytes()==raw for name,raw in ORIGINAL.items()))
        original=load('installed_runtime_v1',PREFIX/'scripts/client/client.py')
        self.assertEqual(Path(original.source_delivery_helper().__file__).absolute(),PREFIX/'scripts/release/source_delivery.py')
        self.assertEqual(original.digest(b'held'),C.digest(b'held'))

    def test_changed_v2_stage_is_refused_without_changing_v1(self):
        target=OWN_STAGE/'usr/share/cachy-asahi/repository-runtime/scripts/client/client_v2.py'
        raw=target.read_bytes();original=(PREFIX/'scripts/client/client.py').read_bytes()
        try:
            target.write_bytes(raw+b'\nCHANGED')
            row=command([sys.executable,'-I','-B',ROOT/'check_source.py','--recipe-root',ROOT,'--stage',OWN_STAGE])
            self.assertNotEqual(row.returncode,0)
            self.assertEqual((PREFIX/'scripts/client/client.py').read_bytes(),original)
        finally:target.write_bytes(raw)


class InstalledGPGTests(FIXTURE.GPGTests):
    def test_installed_cli_tilde_signed_lookup_export_tamper_preserves_checkpoint(self):
        self.apply();before=self.checkpoint_bytes();mtime=(self.state/C.CHECKPOINT).stat().st_mtime_ns
        self.source_fixture('1.0~rc1-1')
        fresh=copy.copy(self.build_args);fresh.output=str(self.directory/'installed-tilde.json');fresh.sequence=2
        C.build(fresh);self.sign(Path(fresh.output))
        argv=[sys.executable,'-I','-B',str(V2),'sources']
        values=dict(bundle=str(self.local_bundle),metadata=fresh.output,signature=fresh.output+'.sig',
            public_keyring=str(self.keyring),signer=self.key,namespace='dev.example',state_dir=str(self.state),
            package='fixture',version='1.0~rc1-1',arch='any',artifact_sha256=self.source_args.artifact_sha256)
        for key,value in values.items():argv+=['--'+key.replace('_','-'),value]
        def invoke(extra=()):
            return command([*argv,*extra],cwd=STAGE,env=dict(PATH='/usr/bin:/bin',HOME=str(self.directory),LC_ALL='C',TZ='UTC'))
        lookup=invoke();self.assertEqual(lookup.returncode,0,lookup.stderr)
        row=json.loads(lookup.stdout);self.assertEqual(row['package']['version'],'1.0~rc1-1');self.assertFalse(row['state_changed'])
        target=self.directory/'installed-sources';export=invoke(['--output',str(target)])
        self.assertEqual(export.returncode,0,export.stderr);self.assertFalse(json.loads(export.stdout)['source_completeness_accepted'])
        self.assertEqual(target.stat().st_mode&0o777,0o700)
        self.assertEqual(self.checkpoint_bytes(),before);self.assertEqual((self.state/C.CHECKPOINT).stat().st_mtime_ns,mtime)
        notice=self.local_bundle/'evidence/fixture-notice.txt';notice.write_bytes(notice.read_bytes()+b'TAMPER')
        refused=invoke(['--output',str(self.directory/'must-not-exist')])
        self.assertNotEqual(refused.returncode,0);self.assertIn('payload checksum',refused.stderr)
        self.assertFalse((self.directory/'must-not-exist').exists());self.assertEqual(self.checkpoint_bytes(),before)
        self.assertEqual((self.state/C.CHECKPOINT).stat().st_mtime_ns,mtime)


if __name__=='__main__':
    try:
        if not all(shutil.which(name)for name in ('gpg','gpgconf')):raise RuntimeError('real TEST GPG controls require installed gnupg')
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(StageTests)
        suite.addTest(InstalledGPGTests('test_installed_cli_tilde_signed_lookup_export_tamper_preserves_checkpoint'))
        suite.addTest(InstalledGPGTests('test_sources_tilde_version_real_signed_lookup_export_and_tamper_refusal'))
        outcome=unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(not outcome.wasSuccessful())
    finally:STAGING.cleanup()
