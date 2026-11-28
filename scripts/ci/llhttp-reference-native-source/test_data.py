#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced finite constructor/native-postcondition DATA controls."""
import ast
import gzip
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def module(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module(HERE/'prepare.py','llhttp_prepare_test')
D=module(HERE/'owner/data.py','llhttp_data_test')
F=module(HERE/'base/finish_pair.py','llhttp_finish_test')
HELD_BASE = (ROOT / 'scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source'
             / P.BASE)

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

def held_input(name, row):
    raw = D.read(HELD_BASE / name)
    P.C.need(D.pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact held test operand: ' + name)
    return raw

def constructor_fixture(root):
    derivation = D.decode(D.read(HERE / 'derivation.json'))
    files = {row['source_path'] for row in derivation['files'].values()}
    files.update((P.WORKFLOW, 'LICENSE', derivation['no_host_apt_seam']['deleted_original_host_prerequisite']['source_path']))
    for name in files:
        write(root / name, D.read(ROOT / name))
    profile = D.decode(D.read(HERE / 'base/profile.json'))
    for name, row in profile['held_inputs'].items():
        write(root / row['source_path'], held_input(name, row))
    return root

def elf_bytes(soname='libllhttp.so.9.3',dependency='libc.so.6',align=65536):
    data=bytearray(768);data[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',data,16,3,183);struct.pack_into('<Q',data,32,64);struct.pack_into('<HHH',data,52,64,56,2)
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
        profile=D.decode(D.read(HERE/'base/profile.json'));name='runtime/scripts/build/build_v2.py'
        row=profile['held_inputs'][name];raw=held_input(name,row);C=P.C
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
        with tempfile.TemporaryDirectory(prefix='llhttp-Source-DATA-') as name:
            root=Path(name).resolve();framework=constructor_fixture(root/'framework')
            source=root/'Source';result=P.construct(framework,Path(recipe),Path(archive),source)
            self.assertEqual(result['files'],len([p for p in source.rglob('*') if p.is_file()]));self.assertLess(result['bytes'],2*1024**2);self.assertEqual(result['native_build'],'NOT RUN')
            D.source(source,result['source_map']['sha256'])
            for name,(_, binding) in P.ARTIFACT_BINDINGS.items():
                operand=source/'held-source'/D.BASE_PREFIX/'runtime/scripts/build'/name
                self.assertIn(binding.encode(),D.read(operand))
            helper=source/'held-source'/D.BASE_PREFIX/'package_metadata.py'
            self.assertEqual(D.read(helper),D.read(HERE/'base/package_metadata.py'))
            historical=P.construct(framework,Path(recipe),Path(archive),root/'Historical',historical_source=True)
            self.assertEqual(historical['files'],62)
            self.assertEqual(historical['source_map'],dict(bytes=13601,
                sha256='d6240a8a32bd363e75542e3e5896356e24d28e010f99e24edfff380b67afa050'))
            admission=D.read(HERE/'owner/admission.TEMPLATE.json');runtime=D.read(HERE/'owner/runtime.TEMPLATE.json')
            with self.assertRaisesRegex(ValueError,'actual Root issuance'):
                D.admission(source,result['source_map']['sha256'],admission,runtime,D.pin(admission)['sha256'],D.pin(runtime)['sha256'],{},0)
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

    def test_zero_host_package_manager_surface(self):
        H=module(HERE/'owner/host_tools.py','llhttp_host_tools')
        O=module(HERE/'owner/hosted_owner.py','llhttp_owner')
        self.assertNotIn('bsdtar',H.NAMES);self.assertFalse(hasattr(H,'CI_CANDIDATES'))
        self.assertFalse((HERE/'owner/host_prerequisites.py').exists());self.assertFalse(hasattr(O.Controller,'run_prerequisite'))
        policy=D.decode(D.read(HERE/'owner/policy.json'));self.assertNotIn('host_prerequisites',policy)
        value=dict(status='PASS_EXISTING_HOST_TOOLS_ONLY',declaration=policy['host_tools'],commands=[],package_manager_invocations=0,host_package_mutations=0,tools=sorted(H.NAMES))
        D.existing_host(value,policy)
        for key in ('package_manager_invocations','host_package_mutations'):
            wrong=dict(value);wrong[key]=1
            with self.assertRaises(ValueError):D.existing_host(wrong,policy)
        wrong=dict(value,commands=[['apt-get','update']])
        with self.assertRaises(ValueError):D.existing_host(wrong,policy)
        owner=object.__new__(O.Controller);owner.tools={n:dict(path='/usr/bin/'+n) for n in H.NAMES}
        for program in ('apt-get','apt-cache','dpkg','dpkg-query','bsdtar'):
            with self.assertRaises(ValueError):owner.run(['/usr/bin/'+program,'--version'])
        for n in ('hosted_owner.py','host_tools.py','data.py','payload.py','admit.py'):
            source=D.read(HERE/'owner'/n)
            self.assertNotIn(b'apt-get',source);self.assertNotIn(b'apt-cache',source);self.assertNotIn(b'libarchive-tools',source)

class NativePostconditionControls(unittest.TestCase):
    def test_generated_providers_bind_exact_library_and_other_metadata(self):
        with patch.object(sys,'path',[str(HERE/'base'),*sys.path]), patch.dict(sys.modules):
            binder=module(HERE/'base/package_metadata.py','llhttp_package_metadata_test')
            builder=module(ROOT/'scripts/build/build_v2.py','llhttp_generic_artifact_test')
        recipe=builder.recipe(ROOT/'packages/libraries/cachy-asahi-llhttp-reference/PKGBUILD')
        self.assertEqual(recipe['errors'],[])
        reviewed, recipe_hash=recipe['metadata'],recipe['input_sha256']['PKGBUILD']
        library='usr/lib/libllhttp.so.9.3.1'
        providers=b'provides = llhttp=9.3.1\nprovides = libllhttp.so=9.3-64\n'
        pkginfo=(b'pkgname = cachy-asahi-llhttp-reference\npkgbase = cachy-asahi-llhttp-reference\n'
                 b'pkgver = 9.3.1-1\narch = aarch64\nlicense = MIT\nconflict = llhttp\n'
                 b'depend = glibc\nmakedepend = cmake>=3.25\nmakedepend = ninja\n')
        buildinfo=(b'format = 2\npkgname = cachy-asahi-llhttp-reference\n'
                   b'pkgver = 9.3.1-1\npkgarch = aarch64\npkgbuild_sha256sum = '+recipe_hash.encode()+b'\n')
        with tempfile.TemporaryDirectory(prefix='llhttp-generated-metadata-') as directory:
            archive=Path(directory)/(F.PACKAGE+'xz')
            def check(provides=providers, soname='libllhttp.so.9.3', metadata=pkginfo):
                with tarfile.open(archive,'w:xz') as output:
                    for name,body in {'.PKGINFO':metadata+provides,'.BUILDINFO':buildinfo,
                                      '.MTREE':b'model',library:elf_bytes(soname=soname)}.items():
                        row=tarfile.TarInfo(name)
                        row.size=len(body)
                        output.addfile(row,io.BytesIO(body))
                report=builder.package(archive)
                self.assertEqual(report['errors'],[])
                return binder.bind_llhttp_artifact(reviewed,report,recipe_hash,archive,builder.bind_artifact)
            self.assertEqual(check(),[])
            for bad in (b'',providers.replace(b'-64',b'-32'),providers+b'provides = alien=1\n',providers*2):
                self.assertEqual(check(bad),['artifact metadata differs from reviewed provides'])
            self.assertRegex(check(providers.replace(b'9.3-64',b'9.4-64'),'libllhttp.so.9.4')[0],
                             'exact llhttp SONAME and DT_NEEDED closure')
            self.assertEqual(check(metadata=pkginfo.replace(b'depend = glibc\n',b'depend = glib2\n')),
                             ['artifact metadata differs from reviewed depend'])

    def test_exact_native_dynamic_closure(self):
        result=F.elf(elf_bytes());self.assertEqual(result['soname'],'libllhttp.so.9.3');self.assertEqual(result['needed'],['libc.so.6']);self.assertTrue(result['structural16K']);self.assertEqual(result['M2'],'NOT RUN')
        self.assertFalse(F.elf(elf_bytes(align=4096))['structural16K'])

    def test_wrong_elf_and_dynamic_closure_refuse(self):
        for raw in (elf_bytes('libllhttp.so.9'),elf_bytes(dependency='libevil.so'),elf_bytes(align=2048),elf_bytes()[:100],b'not ELF'):
            with self.assertRaises(ValueError):F.elf(raw)
        raw=bytearray(elf_bytes());struct.pack_into('<H',raw,18,62)
        with self.assertRaises(ValueError):F.elf(bytes(raw))

    def test_other_archive_compression_refuses_before_inspection(self):
        C=P.C;rows=D.decode(D.read(HERE/'base/profile.json'))['held_inputs']
        name='runtime/scripts/build/compare_v2.py';original=held_input(name,rows[name])
        projected=C.projected_compare(original).decode();self.assertEqual(projected.replace(C.COMPARE_AFTER,C.COMPARE_BEFORE).encode(),original)
        self.assertLess(projected.index('fixed llhttp XZ-only archive'),projected.index('report = package(item)'))
        name='runtime/scripts/build/build_v2.py';builder=held_input(name,rows[name])
        text=C.projected_build(builder).decode();tree=ast.parse(text)
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        attempt=next(n for n in main.body if isinstance(n,ast.Try))
        index=next(i for i,n in enumerate(attempt.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='paths' for t in n.targets))
        gate=ast.Module(body=attempt.body[index:index+2],type_ignores=[]);ast.fix_missing_locations(gate)
        with tempfile.TemporaryDirectory(prefix='llhttp-format-gate-DATA-') as name:
            artifacts=Path(name);write(artifacts/'model.pkg.tar.zst',b'not admitted')
            with self.assertRaises(ValueError):exec(compile(gate,'<fixed-XZ-gate>','exec'),dict(artifacts=artifacts))
            (artifacts/'model.pkg.tar.zst').unlink();write(artifacts/'model.pkg.tar.xz',b'MODEL filename only')
            exec(compile(gate,'<fixed-XZ-gate>','exec'),dict(artifacts=artifacts))
        with tempfile.TemporaryDirectory(prefix='llhttp-compression-DATA-') as name:
            root=Path(name);path=root/(F.PACKAGE+'gz');write(path,gzip.compress(b'MODEL',mtime=0))
            with self.assertRaises(ValueError):F.archive_members(path,('.PKGINFO',))
            path=root/(F.PACKAGE+'xz');write(path,gzip.compress(b'MODEL',mtime=0))
            with self.assertRaises(ValueError):F.archive_members(path,('.PKGINFO',))

    def pair_fixture(self,root):
        recipe=D.decode(D.read(HERE/'recipe-pin.json'));reviewed={'PKGBUILD':'1'*64};write(root/'reviewed-inputs.json',reviewed);write(root/'recipe-pin.json',recipe)
        lock=D.read(ROOT/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock');write(root/'expected349.lock',lock)
        archive_name=F.PACKAGE+'xz';library='usr/lib/libllhttp.so.9.3.1';license_name=recipe['license']['path'];license_row=next((v for n,v in recipe['upstream']['members'].items() if n.endswith('/LICENSE-MIT')))
        # Genuine upstream license fixture copied from external material if supplied;
        # synthetic body otherwise receives an explicit synthetic expected pin.
        bodies={'.PKGINFO':b'pkgname = cachy-asahi-llhttp-reference\n','.BUILDINFO':b'format = 2\n','.MTREE':gzip.compress(b'#mtree\n./usr type=dir\n',mtime=0),license_name:b'MODEL MIT license\n',library:elf_bytes()}
        recipe['license'].update(D.pin(bodies[license_name]));write(root/'recipe-pin.json',recipe)
        for i in (1,2):
            build=root/('build-'+str(i));art=build/'artifacts'
            tar=io.BytesIO()
            with tarfile.open(fileobj=tar,mode='w:xz') as stream:
                for n,b in bodies.items():
                    member=tarfile.TarInfo(n);member.size=len(b);member.mode=0o644;member.uid=member.gid=member.mtime=0;stream.addfile(member,io.BytesIO(b))
            write(art/archive_name,tar.getvalue())
            write(art/'environment.txt',b'Linux MODEL aarch64\n4096\n');write(art/'cachy-asahi-llhttp-reference-9.3.1-1-aarch64-check.log',F.MARKER+b'\n')
            report=dict(artifact=archive_name,sha256=D.pin((art/archive_name).read_bytes())['sha256'],errors=[],members={n:dict(sha256=D.pin(b)['sha256']) for n,b in bodies.items()},elf={library:dict(errors=[])})
            write(build/'validation.json',dict(errors=[],artifacts=[report]))
            write(build/'provenance.json',dict(status='built-package-static-pass',exit_code=0,mode='native',image_id='sha256:'+'a'*64,recipe_inputs=reviewed,expected_packages_sha256=D.pin(lock)['sha256'],builder_host_arch='aarch64',clean_environment_id='MODEL-clean-'+str(i),artifacts={archive_name:report['sha256']}))
        write(root/'comparison.json',dict(status='contents-reproduced',errors=[],packages={archive_name:dict(installed_contents_equal=True,pkginfo_equal=True,buildinfo_equal=True,bytes_equal=True)}))
        return bodies

    def test_pair_model_and_failure_postconditions(self):
        with tempfile.TemporaryDirectory(prefix='llhttp-pair-MODEL-') as name:
            root=Path(name);bodies=self.pair_fixture(root);original=F.HERE;F.HERE=root
            try:
                def run():return F.finish(root/'build-1',root/'build-2',root/'comparison.json','sha256:'+'a'*64)
                result=run();self.assertEqual(result['builds'],2);self.assertEqual(result['signature'],'NOT RUN; Root offline follow-up');self.assertEqual(result['installation'],'NOT RUN')
                marker=root/'build-2/artifacts/cachy-asahi-llhttp-reference-9.3.1-1-aarch64-check.log';body=marker.read_bytes();marker.write_bytes(b'stale successful compilation\n')
                with self.assertRaises(ValueError):run()
                marker.write_bytes(body);path=root/'build-2/provenance.json';record=D.decode(path.read_bytes());record['clean_environment_id']='MODEL-clean-1';write(path,record)
                with self.assertRaises(ValueError):run()
                record['clean_environment_id']='MODEL-clean-2';write(path,record);comparison=D.decode((root/'comparison.json').read_bytes());next(iter(comparison['packages'].values()))['bytes_equal']=False;write(root/'comparison.json',comparison)
                with self.assertRaises(ValueError):run()
            finally:F.HERE=original

if __name__=='__main__':unittest.main()
