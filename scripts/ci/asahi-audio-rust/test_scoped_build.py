#!/usr/bin/env python3
"""Inert recipe, protected-payload and cleanup regressions; no Docker/audio actors."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

# CACHY_ASAHI_TEST_ROOT/PROPOSED permit bounded scratch checks before integration.
# After integration, this file runs directly against the ordinary repository.
import os
ROOT=Path(os.environ.get('CACHY_ASAHI_TEST_ROOT',Path(__file__).resolve().parents[3]))
PROPOSED=Path(os.environ.get('CACHY_ASAHI_AUDIO_PROPOSED',ROOT))
TMP=Path(os.environ.get('TMPDIR',tempfile.gettempdir()))
sys.path.insert(0,str(ROOT/'scripts/ci/asahi-audio-rust'))
import scoped_build as scoped
spec=importlib.util.spec_from_file_location('audio_test_run',ROOT/'scripts/ci/asahi-audio-rust/run.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class AudioBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=TMP);self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)

    def fixture(self,name='speakersafetyd',mutate=None):
        row=next(r for r in scoped.RECIPES if r['name']==name)
        directory=PROPOSED/row['path']
        content={}
        with tarfile.open(directory/row['metadata']['source'][0]) as stream:
            source={str(Path(m.name).relative_to(Path(m.name).parts[0])):stream.extractfile(m).read() for m in stream if m.isfile() or m.issym()}
        with tarfile.open(directory/'audio-rust-notices-v1.tar.xz') as stream:
            notices={str(Path('usr/share/licenses')/Path(m.name).relative_to('audio-rust-notices')):stream.extractfile(m).read() for m in stream if m.isfile()}
        if name=='speakersafetyd':
            work=self.base/'patch-source';target=work/'conf/apple/j504.conf';target.parent.mkdir(parents=True)
            target.write_bytes(source['conf/apple/j504.conf'])
            subprocess.run(['patch','--batch','--fuzz=0','--no-backup-if-mismatch','-p1','-d',str(work),'-i',str(directory/'0001-j504-Write-the-full-speaker-names-in-conf.patch')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            source['conf/apple/j504.conf']=target.read_bytes()
        # A minimal inert ELF fixture exercises the real structural parser. It
        # contains no executable program and is never run.
        header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),3,183,1,0,64,0,0,64,56,1,0,0,0)
        elf=header+struct.pack('<IIQQQQQQ',1,5,0,0,0,120,120,16384)
        for path,expected in row['payload'].items():
            if expected['ELF']:content[path]=elf
            elif path.endswith('.conf'):content[path]=source['conf/apple/'+Path(path).name]
            elif path in notices:content[path]=notices[path]
            else:content[path]=source[Path(path).name]
        data=scoped.existing_build.normalize_metadata(row['metadata'])
        pkg={'pkgname':data['pkgname'],'pkgbase':data['pkgbase'],'pkgver':[row['version']],'arch':data['arch'],'license':data['license']}
        for source,target in [('depends','depend'),('makedepends','makedepend'),('checkdepends','checkdepend'),('optdepends','optdepend'),('provides','provides'),('conflicts','conflict'),('replaces','replaces'),('backup','backup')]:pkg[target]=data[source]
        content['.PKGINFO']=''.join(f'{k} = {v}\n' for k,values in pkg.items() for v in values).encode()
        content['.BUILDINFO']=('format = 2\npkgname = '+name+'\npkgver = '+row['version']+'\npkgarch = aarch64\npkgbuild_sha256sum = '+row['input_sha256']['PKGBUILD']+'\n').encode()
        content['.MTREE']=b''
        if mutate:mutate(content)
        target=self.base/(name+'.pkg.tar.xz')
        with tarfile.open(target,'w:xz') as stream:
            parents=sorted({str(p) for n in content for p in Path(n).parents if str(p)!='.'})
            for name in parents:
                m=tarfile.TarInfo(name);m.type=tarfile.DIRTYPE;m.mode=0o755;stream.addfile(m)
            for name,raw in sorted(content.items()):
                m=tarfile.TarInfo(name);m.size=len(raw);m.mode=row['payload'].get(name,{}).get('mode',0o644);stream.addfile(m,io.BytesIO(raw))
        return target

    def test_fixed_recipe_scope_and_changed_input_refusal(self):
        for row in scoped.RECIPES:self.assertEqual(scoped.recipe(PROPOSED/row['path']/'PKGBUILD')['errors'],[])
        source=PROPOSED/'packages/audio/speakersafetyd'
        self.assertIn('protected platform package name: speakersafetyd',scoped.checks.recipe(source/'PKGBUILD')['errors'])
        candidate=self.base/'candidate';shutil.copytree(source,candidate);(candidate/'unexpected').write_text('unreviewed')
        with self.assertRaises(ValueError):scoped.recipe(candidate/'PKGBUILD')

    def test_exact_three_payloads_and_generic_protection_preserved(self):
        for name in ('speakersafetyd','bankstown','triforce-lv2'):
            path=self.fixture(name);self.assertEqual(scoped.package(path)['errors'],[])
            if name=='speakersafetyd':self.assertTrue(scoped.checks.package(path)['errors'])

    def test_unexpected_protected_payload_refused(self):
        path=self.fixture(mutate=lambda c:c.update({'usr/lib/udev/rules.d/unreviewed.rules':b'unreviewed'}))
        with self.assertRaisesRegex(ValueError,'unexpected audio payload'):scoped.package(path)

    def test_changed_safety_data_refused(self):
        def mutate(c):c['usr/share/speakersafetyd/apple/j413.conf']+=b'\nchanged'
        with self.assertRaisesRegex(ValueError,'reviewed audio data differs'):scoped.package(self.fixture(mutate=mutate))

    def test_non_arm_daemon_refused(self):
        def mutate(c):
            raw=bytearray(c['usr/bin/speakersafetyd']);struct.pack_into('<H',raw,18,62);c['usr/bin/speakersafetyd']=bytes(raw)
        with self.assertRaisesRegex(ValueError,'ELF check failed'):scoped.package(self.fixture(mutate=mutate))

    def test_wrong_metadata_refused(self):
        version=next(r['version'] for r in scoped.RECIPES if r['name']=='speakersafetyd')
        def mutate(c):c['.PKGINFO']=c['.PKGINFO'].replace(f'pkgver = {version}\n'.encode(),f'pkgver = {version}-unreviewed\n'.encode())
        with self.assertRaisesRegex(ValueError,'metadata/source binding'):scoped.package(self.fixture(mutate=mutate))

    def test_unknown_bootstrap_cleanup_fails(self):
        self.assertEqual(runner.cleanup(self.base,['docker'],True,[])['status'],'FAIL')

    def test_scoped_image_removal_requires_absence_and_no_prune(self):
        image='sha256:'+'a'*64;(self.base/'native').mkdir();(self.base/'native/image-id').write_text(image)
        with patch.object(runner.native,'run',return_value='') as command:
            self.assertEqual(runner.cleanup(self.base,['docker'],True,[])['status'],'PASS')
        self.assertIn((['docker','image','rm','--no-prune',image],),[call.args for call in command.call_args_list])
        with patch.object(runner.native,'run',return_value=image):
            self.assertEqual(runner.cleanup(self.base,['docker'],True,[])['status'],'FAIL')

    def test_build_failure_retains_failure_and_runs_cleanup(self):
        output=self.base/'out';inputs=json.loads((ROOT/'scripts/ci/asahi-audio-rust/inputs.lock.json').read_text())
        def build(_inputs,_cache,directory,_reviews):
            (directory/'image-id').write_text('sha256:'+'a'*64)
            (directory/'packages.lock').write_bytes((ROOT/'scripts/ci/asahi-audio-rust/expected-packages.lock').read_bytes())
            return 'sha256:'+'a'*64
        with patch.object(runner,'preflight',return_value=inputs),patch.object(runner.native,'probe',return_value={'docker_endpoint':'unix:///var/run/docker.sock'}),patch.object(runner.native,'audit'),patch.object(runner.native,'build',side_effect=build),patch.object(runner.native,'run',side_effect=ValueError('inert build failure')),patch.object(runner,'cleanup',return_value={'status':'PASS'}) as cleanup:
            self.assertEqual(runner.run(SimpleNamespace(output=output,cache=self.base/'cache',source_commit='1'*40)),1)
        report=json.loads((output/'summary/result.json').read_text());self.assertEqual(report['status'],'FAIL');self.assertEqual(report['pairs'],{})
        self.assertTrue(cleanup.call_args.args[2]);self.assertEqual(cleanup.call_args.args[3],['speakersafetyd-build-1'])


if __name__=='__main__':unittest.main()
