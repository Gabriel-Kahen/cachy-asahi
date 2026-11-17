#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced finite constructor/native-postcondition DATA controls."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def module(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module(HERE/'prepare.py','llhttp_prepare_test')
D=module(HERE/'owner/data.py','llhttp_data_test')
F=module(HERE/'base/finish_pair.py','llhttp_finish_test')

def fence(event,args):
    if event in ('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','socket.connect','socket.bind','socket.getaddrinfo'):
        raise AssertionError('actor forbidden in DATA control: '+event)
sys.addaudithook(fence)

# The recipe fixture is optional only for constructor DATA controls. No material
# fallback exists in the actual constructor. Tests use the exact external source
# paths deliberately supplied by the caller, never execute anything from them.
RECIPE_ENV='LLHTTP_DATA_RECIPE_ROOT'
ARCHIVE_ENV='LLHTTP_DATA_ARCHIVE'

def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(value if isinstance(value,bytes) else P.encoded(value));path.chmod(0o644)

def elf_bytes(soname='libllhttp.so.9.3',dependency='libc.so.6',align=65536):
    data=bytearray(768);data[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',data,16,3,183);struct.pack_into('<Q',data,32,64);struct.pack_into('<HH',data,54,56,2)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0,0,len(data),len(data),align)
    struct.pack_into('<IIQQQQQQ',data,120,2,6,256,256,256,80,80,8)
    strings=b'\0'+soname.encode()+b'\0'+dependency.encode()+b'\0';data[400:400+len(strings)]=strings
    for i,row in enumerate(((5,400),(10,len(strings)),(14,1),(1,len(soname)+2),(0,0))):struct.pack_into('<qQ',data,256+16*i,*row)
    return bytes(data)

class SourceControls(unittest.TestCase):
    def test_whole_framework_derivation(self):
        value=D.decode(D.read(HERE/'derivation.json'))
        for name,row in value['files'].items():
            raw=D.read(ROOT/row['source_path']);self.assertEqual(D.pin(raw),row['original']);text=raw.decode()
            for change in row['changes']:
                self.assertIn(change['before'],text);text=text.replace(change['before'],change['after'])
            self.assertEqual(text.encode(),D.read(HERE/name));self.assertEqual(D.pin(text.encode()),row['projected'])

    def test_unchanged_build_inverse_and_normal_dependencies(self):
        profile=D.decode(D.read(HERE/'base/profile.json'));row=profile['held_inputs']['runtime/scripts/build/build_v2.py'];raw=D.read(ROOT/row['source_path']);C=P.C
        self.assertEqual(D.pin(raw),{k:row[k] for k in ('bytes','sha256')});projected=C.projected_build(raw).decode()
        for before,after in reversed(C.BUILD_EDITS):self.assertEqual(projected.count(after),1);projected=projected.replace(after,before)
        self.assertEqual(projected.encode(),raw)
        entry=D.read(ROOT/'scripts/build/container-entry-v2.sh');self.assertIn(b'makepkg --verifysource --noconfirm',entry);self.assertIn(b'makepkg --cleanbuild --clean --force --log --noconfirm',entry)
        self.assertNotIn(b'--nodeps',entry);self.assertNotIn(b'--nocheck',entry)

    def test_no_foreign_acceptance_or_signer(self):
        self.assertTrue(all(v is None for v in D.decode(D.read(HERE/'base/profile.json'))['actual'].values()))
        for sub in ('base','owner'):
            for n in ('admission.TEMPLATE.json','runtime.TEMPLATE.json'):
                value=D.decode(D.read(HERE/sub/n));self.assertIs(value['accepted'],False);self.assertIsNone(value['source'])
        workflow=D.read(ROOT/P.WORKFLOW);self.assertIn(b'workflow_dispatch:',workflow);self.assertNotIn(b'pull_request:',workflow);self.assertNotIn(b'PRIVATE_KEY',workflow);self.assertNotIn(b'--nodeps',workflow)
        self.assertIn(b'ROOT_LLHTTP_REFERENCE_ADMISSION_JSON',workflow);self.assertIn(b'--property=MemorySwapMax=0',workflow)

    def test_resource_domain_refusals(self):
        policy=D.decode(D.read(HERE/'owner/policy.json'));self.assertEqual(policy['storage_bytes'],12*1024**3);self.assertEqual(policy['pair_seconds'],1200)
        expected=D.domain({'memory.max':str(policy['owner']['memory_bytes']),'memory.swap.max':'0','pids.max':str(policy['owner']['pids']),'cpu.max':'100000 100000'},policy['owner'])
        for key in expected:
            wrong=dict(expected);wrong[key]='max'
            with self.assertRaises(ValueError):D.domain(wrong,policy['owner'])
        args=D.service_args('a'*32,'owner',policy['owner'],['/usr/bin/true'],Path('/owned/owner.log'),1000,1000)
        self.assertIn('--property=NoNewPrivileges=yes',args);self.assertIn('--property=MemorySwapMax=0',args);self.assertIn('--property=KillMode=control-group',args)

    def test_template_refusal_before_actor(self):
        with self.assertRaises((ValueError,FileNotFoundError)):
            D.admission(Path('/nonexistent-llhttp-Source'),'0'*64,D.read(HERE/'owner/admission.TEMPLATE.json'),D.read(HERE/'owner/runtime.TEMPLATE.json'),'0'*64,'0'*64,{},0)

    def test_safe_upstream_closure(self):
        # The genuine material is deliberately external, not downloaded by tests.
        archive=os.environ.get(ARCHIVE_ENV)
        if not archive:self.skipTest('set '+ARCHIVE_ENV+' for genuine source DATA')
        raw=D.read(Path(archive));proof=D.decode(D.read(HERE/'recipe-pin.json'))['upstream'];members=P.archive_closure(raw,proof)
        self.assertTrue(any(n.endswith('/LICENSE-MIT') for n in members));self.assertTrue(any(n.endswith('/src/llhttp.c') for n in members))
        with self.assertRaises(ValueError):P.archive_closure(raw+b'changed',proof)

    def test_complete_constructor_and_namespace_custody(self):
        recipe=os.environ.get(RECIPE_ENV);archive=os.environ.get(ARCHIVE_ENV)
        if not(recipe and archive):self.skipTest('set exact external recipe/archive DATA paths')
        with tempfile.TemporaryDirectory(prefix='llhttp-Source-DATA-',dir='/home/gabe') as name:
            root=Path(name);source=root/'Source';result=P.construct(ROOT,Path(recipe),Path(archive),source)
            self.assertEqual(result['files'],len([p for p in source.rglob('*') if p.is_file()]));self.assertLess(result['bytes'],2*1024**2);self.assertEqual(result['native_build'],'NOT RUN')
            D.source(source,result['source_map']['sha256'])
            checker=module(source/'held-source'/D.BASE_PREFIX/'runtime/scripts/checks/package_checks.py','llhttp_static_recipe')
            report=checker.recipe(source/'held-source'/D.BASE_PREFIX/'recipe/PKGBUILD')
            self.assertEqual(report['errors'],[])
            self.assertEqual(report['input_sha256'],D.decode(D.read(source/'held-source'/D.BASE_PREFIX/'reviewed-inputs.json')))
            self.assertEqual(report['metadata']['arch'],['aarch64']);self.assertEqual(report['metadata']['depends'],['glibc'])
            with self.assertRaises(ValueError):D.source(source,'0'*64)
            write(source/'extra',b'not declared')
            with self.assertRaises(ValueError):D.source(source,result['source_map']['sha256'])
            (source/'extra').unlink();body=source/D.PREFIX/'policy.json';original=body.read_bytes();body.write_bytes(original+b' ')
            with self.assertRaises(ValueError):D.source(source,result['source_map']['sha256'])
            body.write_bytes(original);body.chmod(0o666)
            with self.assertRaises(ValueError):D.source(source,result['source_map']['sha256'])

class NativePostconditionControls(unittest.TestCase):
    def test_exact_native_dynamic_closure(self):
        result=F.elf(elf_bytes());self.assertEqual(result['soname'],'libllhttp.so.9.3');self.assertEqual(result['needed'],['libc.so.6']);self.assertTrue(result['structural16K']);self.assertEqual(result['M2'],'NOT RUN')
        self.assertFalse(F.elf(elf_bytes(align=4096))['structural16K'])

    def test_wrong_elf_and_dynamic_closure_refuse(self):
        for raw in (elf_bytes('libllhttp.so.9'),elf_bytes(dependency='libevil.so'),elf_bytes(align=2048),elf_bytes()[:100],b'not ELF'):
            with self.assertRaises(ValueError):F.elf(raw)
        raw=bytearray(elf_bytes());struct.pack_into('<H',raw,18,62)
        with self.assertRaises(ValueError):F.elf(bytes(raw))

    def pair_fixture(self,root):
        recipe=D.decode(D.read(HERE/'recipe-pin.json'));reviewed={'PKGBUILD':'1'*64};write(root/'reviewed-inputs.json',reviewed);write(root/'recipe-pin.json',recipe)
        lock=D.read(ROOT/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock');write(root/'expected349.lock',lock)
        archive_name=F.PACKAGE+'xz';library='usr/lib/libllhttp.so.9.3.1';license_name=recipe['license']['path'];license_row=next((v for n,v in recipe['upstream']['members'].items() if n.endswith('/LICENSE-MIT')))
        # Genuine upstream license fixture copied from external material if supplied;
        # synthetic body otherwise receives an explicit synthetic expected pin.
        bodies={'.PKGINFO':b'pkgname = cachy-asahi-llhttp-reference\n','.BUILDINFO':b'format = 2\n','.MTREE':gzip.compress(b'#mtree\n./usr type=dir\n',mtime=0),license_name:b'MODEL MIT license\n',library:elf_bytes()}
        recipe['license'].update(D.pin(bodies[license_name]));write(root/'recipe-pin.json',recipe)
        for i in (1,2):
            build=root/('build-'+str(i));art=build/'artifacts';write(art/archive_name,b'MODEL archive bytes; never an actual package')
            write(art/'environment.txt',b'Linux MODEL aarch64\n4096\n');write(art/'cachy-asahi-llhttp-reference-9.3.1-1-aarch64-check.log',F.MARKER+b'\n')
            report=dict(artifact=archive_name,sha256=D.pin((art/archive_name).read_bytes())['sha256'],errors=[],members={n:dict(sha256=D.pin(b)['sha256']) for n,b in bodies.items()},elf={library:dict(errors=[])})
            write(build/'validation.json',dict(errors=[],artifacts=[report]))
            write(build/'provenance.json',dict(status='built-package-static-pass',exit_code=0,mode='native',image_id='sha256:'+'a'*64,recipe_inputs=reviewed,expected_packages_sha256=D.pin(lock)['sha256'],builder_host_arch='aarch64',clean_environment_id='MODEL-clean-'+str(i),artifacts={archive_name:report['sha256']}))
        write(root/'comparison.json',dict(status='contents-reproduced',errors=[],packages={archive_name:dict(installed_contents_equal=True,pkginfo_equal=True,buildinfo_equal=True,bytes_equal=True)}))
        class Result:
            def __init__(self,raw):self.stdout=raw
        def runner(argv,seconds):
            self.assertEqual(argv[:2],['/usr/bin/bsdtar','-xOf']);self.assertEqual(seconds,30);self.assertIn(argv[3],bodies);return Result(bodies[argv[3]])
        return bodies,runner

    def test_pair_model_and_failure_postconditions(self):
        with tempfile.TemporaryDirectory(prefix='llhttp-pair-MODEL-',dir='/home/gabe') as name:
            root=Path(name);bodies,runner=self.pair_fixture(root);original=F.HERE;F.HERE=root
            try:
                def run():return F.finish(root/'build-1',root/'build-2',root/'comparison.json','sha256:'+'a'*64,runner)
                result=run();self.assertEqual(result['builds'],2);self.assertEqual(result['signature'],'NOT RUN; Root offline follow-up');self.assertEqual(result['installation'],'NOT RUN')
                marker=root/'build-2/artifacts/cachy-asahi-llhttp-reference-9.3.1-1-aarch64-check.log';body=marker.read_bytes();marker.write_bytes(b'stale successful compilation\n')
                with self.assertRaises(ValueError):run()
                marker.write_bytes(body);path=root/'build-2/provenance.json';record=D.decode(path.read_bytes());record['clean_environment_id']='MODEL-clean-1';write(path,record)
                with self.assertRaises(ValueError):run()
                record['clean_environment_id']='MODEL-clean-2';write(path,record);comparison=D.decode((root/'comparison.json').read_bytes());next(iter(comparison['packages'].values()))['bytes_equal']=False;write(root/'comparison.json',comparison)
                with self.assertRaises(ValueError):run()
            finally:F.HERE=original

if __name__=='__main__':unittest.main()
