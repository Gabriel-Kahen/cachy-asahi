#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced DATA controls; MODEL receipts confer no Root acceptance."""
import ast
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

def fence(event,args):
    if event in ('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','socket.connect','socket.bind','socket.getaddrinfo'):
        raise AssertionError('actor forbidden in DATA control: '+event)
sys.addaudithook(fence)

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

P=module(HERE/'prepare.py','libgit2_prepare_test')
D=module(HERE/'owner/data.py','libgit2_data_test')
F=module(HERE/'base/finish_pair.py','libgit2_finish_test')
T=module(HERE/'project_test.py','libgit2_project_test')
DEP=module(HERE/'dependency.py','libgit2_dependency_test')
RECIPE_ENV='LIBGIT2_DATA_RECIPE_ROOT'
ARCHIVE_ENV='LIBGIT2_DATA_ARCHIVE'
LLHTTP_ARCHIVE_ENV='LLHTTP_DATA_ARCHIVE'

def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value if isinstance(value,bytes) else encoded(value));path.chmod(0o644)

def compatible_fixture(test,root):
    consumer=os.environ.get('LIBGIT2_CONSUMER_ROOT')
    if not consumer:test.skipTest('set LIBGIT2_CONSUMER_ROOT for immutable consumer interoperability DATA')
    I=module(HERE/'test_interop.py','libgit2_complete_consumer_model')
    return I.fixture(root,Path(consumer)),Path(consumer)

def elf_bytes(soname='libgit2.so.1.9',needed=None,align=65536):
    if needed is None:needed=['libc.so.6','libcrypto.so.3','libllhttp.so.9.3','libpcre2-8.so.0','libssh2.so.1','libssl.so.3','libz.so.1']
    raw=bytearray(2048);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',raw,16,3,183);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,2)
    extent=(4+len(needed))*16
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0,0,len(raw),len(raw),align)
    struct.pack_into('<IIQQQQQQ',raw,120,2,6,256,256,256,extent,extent,8)
    strings=b'\0'+soname.encode()+b'\0';offsets=[]
    for name in needed:offsets.append(len(strings));strings+=name.encode()+b'\0'
    raw[1024:1024+len(strings)]=strings
    rows=[(5,1024),(10,len(strings)),(14,1)]+[(1,n) for n in offsets]+[(0,0)]
    for i,row in enumerate(rows):struct.pack_into('<qQ',raw,256+16*i,*row)
    return bytes(raw)

class SourceControls(unittest.TestCase):
    def test_whole_framework_derivation(self):
        value=D.decode(D.read(HERE/'derivation.json'))
        for name,row in value['files'].items():
            raw=D.read(ROOT/row['source_path']);self.assertEqual(pin(raw),row['original']);text=raw.decode()
            for change in row['changes']:
                self.assertIn(change['before'],text);text=text.replace(change['before'],change['after'])
            self.assertEqual(text.encode(),D.read(HERE/name));self.assertEqual(pin(text.encode()),row['projected'])

    def test_unchanged_build_inverse_and_normal_dependencies(self):
        profile=D.decode(D.read(HERE/'base/profile.json'));name='runtime/scripts/build/build_v2.py'
        row=profile['held_inputs'][name];raw=P.held_framework_body(ROOT,name,row);C=P.C
        self.assertEqual(pin(raw),{k:row[k] for k in ('bytes','sha256')});projected=C.projected_build(raw).decode()
        with self.assertRaisesRegex(ValueError,'exact held framework dependency'):
            P.held_framework_body(ROOT,name,dict(row,sha256='0'*64))
        with self.assertRaisesRegex(ValueError,'exact original framework role'):
            P.held_framework_body(ROOT,name,dict(row,source_path='scripts/build/compare_v2.py'))
        for before,after in reversed(C.BUILD_EDITS):
            self.assertEqual(projected.count(after),1);projected=projected.replace(after,before)
        self.assertEqual(projected.encode(),raw)
        entry=D.read(ROOT/'scripts/build/container-entry-v2.sh')
        self.assertIn(b'makepkg --verifysource --noconfirm',entry);self.assertIn(b'makepkg --cleanbuild --clean --force --log --noconfirm',entry)
        self.assertNotIn(b'--nodeps',entry);self.assertNotIn(b'--nocheck',entry)

    def test_unissued_selectors_and_manual_workflow(self):
        self.assertTrue(all(v is None for v in D.decode(D.read(HERE/'base/profile.json'))['actual'].values()))
        for sub in ('base','owner'):
            for name in ('admission.TEMPLATE.json','runtime.TEMPLATE.json'):
                value=D.decode(D.read(HERE/sub/name));self.assertIs(value['accepted'],False);self.assertIsNone(value['source'])
        workflow=D.read(ROOT/P.WORKFLOW)
        for present in (b'workflow_dispatch:',b'ROOT_LIBGIT2_REFERENCE_ADMISSION_JSON',b'--property=MemorySwapMax=0'):self.assertIn(present,workflow)
        for absent in (b'pull_request:',b'PRIVATE_KEY',b'--nodeps'):self.assertNotIn(absent,workflow)

    def test_resource_domain_refusals(self):
        policy=D.decode(D.read(HERE/'owner/policy.json'));self.assertEqual(policy['storage_bytes'],12*1024**3);self.assertEqual(policy['pair_seconds'],2400)
        expected=D.domain({'memory.max':str(policy['owner']['memory_bytes']),'memory.swap.max':'0','pids.max':str(policy['owner']['pids']),'cpu.max':'100000 100000'},policy['owner'])
        for key in expected:
            wrong=dict(expected);wrong[key]='max'
            with self.assertRaises(ValueError):D.domain(wrong,policy['owner'])
        args=D.service_args('a'*32,'owner',policy['owner'],['/usr/bin/true'],Path('/owned/owner.log'),1000,1000)
        for value in ('--property=NoNewPrivileges=yes','--property=MemorySwapMax=0','--property=KillMode=control-group'):self.assertIn(value,args)

    def test_template_refusal_before_actor(self):
        with self.assertRaises((ValueError,FileNotFoundError)):
            D.admission(Path('/nonexistent-libgit2-Source'),'0'*64,D.read(HERE/'owner/admission.TEMPLATE.json'),D.read(HERE/'owner/runtime.TEMPLATE.json'),'0'*64,'0'*64,{},0)

    def test_constructor_unbound_dependency_refuses_without_output(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-unbound-DATA-',dir='/home/gabe') as name:
            output=Path(name)/'Source'
            with self.assertRaisesRegex(ValueError,'explicit Root-accepted PROJECT TEST'):
                P.construct(ROOT,ROOT,Path('/nonexistent-libgit2-archive'),output)
            self.assertFalse(output.exists())

    def test_genuine_upstream_complete_closure(self):
        archive=os.environ.get(ARCHIVE_ENV)
        if not archive:self.skipTest('set '+ARCHIVE_ENV+' for genuine source DATA')
        raw=Path(archive).read_bytes();proof=json.loads((HERE/'recipe-pin.json').read_bytes())['upstream'];members=P.archive_closure(raw,proof)
        self.assertTrue(any(n.endswith('/COPYING') for n in members));self.assertTrue(any(n.endswith('/AUTHORS') for n in members));self.assertGreater(len(members),11000)
        with self.assertRaises(ValueError):P.archive_closure(raw+b'changed',proof)

    def test_genuine_recipe_namespace_and_license_pins(self):
        recipe_root=os.environ.get(RECIPE_ENV)
        if not recipe_root:self.skipTest('set '+RECIPE_ENV+' for genuine original recipe DATA')
        proof=json.loads((HERE/'recipe-pin.json').read_bytes());base=Path(recipe_root)/proof['recipe_path']
        self.assertEqual({str(p.relative_to(base)) for p in base.rglob('*') if p.is_file() or p.is_symlink()},set(proof['files']))
        for name,row in proof['files'].items():self.assertEqual(pin(P.C.read(base/name,16*1024**2)),row)
        src=(base/'PKGBUILD').read_bytes();self.assertIn(b"PKGEXT='.pkg.tar.xz'",src);self.assertIn(b"'llhttp=9.3.1'",src);self.assertNotIn(b'--nodeps',src)
        archive=os.environ.get(ARCHIVE_ENV)
        if not archive:self.skipTest('set '+ARCHIVE_ENV+' to join original COPYING/AUTHORS DATA')
        with tarfile.open(fileobj=io.BytesIO(Path(archive).read_bytes()),mode='r:gz') as stream:
            for row in proof['licenses']:
                member=next(m for m in stream.getmembers() if m.name==row['source_member'])
                with stream.extractfile(member) as body:self.assertEqual(pin(body.read()),{k:row[k] for k in ('bytes','sha256')})

    def test_model_constructor_complete_custody_with_genuine_source(self):
        recipe=os.environ.get(RECIPE_ENV);archive=os.environ.get(ARCHIVE_ENV)
        if not(recipe and archive):self.skipTest('set exact external original recipe/archive DATA paths')
        with tempfile.TemporaryDirectory(prefix='libgit2-Source-MODEL-',dir='/home/gabe') as name:
            root=Path(name);f,consumer=compatible_fixture(self,root/'MODEL-operands');paths,expected=f.paths,f.expected;source=root/'MODEL-Source'
            result=P.construct(ROOT,Path(recipe),Path(archive),source,dependency_paths=paths,dependency_expected=expected,consumer_root=consumer)
            self.assertEqual(result['files'],len([p for p in source.rglob('*') if p.is_file()]));self.assertLess(result['bytes'],40*1024**2);self.assertEqual(result['native_build'],'NOT RUN');self.assertTrue(all(v is None for v in result['actual'].values()))
            D.source(source,result['source_map']['sha256']);P.C.verify_source(source/'held-source',json.loads((source/D.PREFIX/'base-binding.json').read_bytes())['map']['sha256'])
            held=source/'held-source'/P.BASE;binding=json.loads((held/'project-test.json').read_bytes())
            copied=module(held/'project_test.py','libgit2_copied_consumer_tuple')
            copied_paths={key:held/('dependency-evidence' if key=='native_receipt' else 'project-test')/binding['paths'][key] for key in copied.KEYS}
            joined=copied.validate_compatible_tuple(copied_paths,binding['expected'],consumer_root=held/'consumer-v1')
            self.assertFalse(joined['admitted']);self.assertEqual(joined['tuple_sha256'],binding['project_test_tuple_sha256']);self.assertEqual(joined['consumer']['row'],pin(f.A.encode(f.row)))
            admission=D.read(HERE/'owner/admission.TEMPLATE.json');runtime=D.read(HERE/'owner/runtime.TEMPLATE.json')
            with self.assertRaisesRegex(ValueError,'actual Root issuance'):
                D.admission(source,result['source_map']['sha256'],admission,runtime,pin(admission)['sha256'],pin(runtime)['sha256'],{},0)
            with self.assertRaises(ValueError):D.source(source,'0'*64)
            write(source/'extra',b'not declared')
            with self.assertRaises(ValueError):D.source(source,result['source_map']['sha256'])
            (source/'extra').unlink();body=source/D.PREFIX/'policy.json';original=body.read_bytes();write(body,original+b' ')
            with self.assertRaises(ValueError):D.source(source,result['source_map']['sha256'])
            write(body,original);body.chmod(0o666)
            with self.assertRaises(ValueError):D.source(source,result['source_map']['sha256'])
        self.assertFalse(source.exists())

    def test_zero_host_package_manager_surface(self):
        H=module(HERE/'owner/host_tools.py','libgit2_host_tools');O=module(HERE/'owner/hosted_owner.py','libgit2_owner')
        self.assertNotIn('bsdtar',H.NAMES);self.assertFalse(hasattr(H,'CI_CANDIDATES'));self.assertFalse((HERE/'owner/host_prerequisites.py').exists());self.assertFalse(hasattr(O.Controller,'run_prerequisite'))
        policy=D.decode(D.read(HERE/'owner/policy.json'));self.assertNotIn('host_prerequisites',policy)
        value=dict(status='PASS_EXISTING_HOST_TOOLS_ONLY',declaration=policy['host_tools'],commands=[],package_manager_invocations=0,host_package_mutations=0,tools=sorted(H.NAMES));D.existing_host(value,policy)
        for key in ('package_manager_invocations','host_package_mutations'):
            wrong=dict(value);wrong[key]=1
            with self.assertRaises(ValueError):D.existing_host(wrong,policy)
        wrong=dict(value,commands=[['apt-get','update']])
        with self.assertRaises(ValueError):D.existing_host(wrong,policy)
        owner=object.__new__(O.Controller);owner.tools={n:dict(path='/usr/bin/'+n) for n in H.NAMES}
        for program in ('apt-get','apt-cache','dpkg','dpkg-query','bsdtar'):
            with self.assertRaises(ValueError):owner.run(['/usr/bin/'+program,'--version'])

class ProjectTestControls(unittest.TestCase):
    def model_tuple(self,root):
        """Synthetic package/key/signature/receipts, genuine source-bound MIT bytes.

        Receipt labels deliberately exercise the parser; they are MODEL DATA,
        never genuine Root issuance or cryptographic/native evidence.
        """
        archive=os.environ.get(LLHTTP_ARCHIVE_ENV)
        if not archive:self.skipTest('set '+LLHTTP_ARCHIVE_ENV+' for genuine llhttp license DATA')
        raw=Path(archive).read_bytes();self.assertEqual(pin(raw),T.DEFAULT_EXPECTED['source']['upstream_archive'])
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as stream:
            member=next(m for m in stream if m.name.endswith('/LICENSE-MIT'))
            with stream.extractfile(member) as source:license_body=source.read()
        expected=copy.deepcopy(T.DEFAULT_EXPECTED);self.assertEqual(pin(license_body),{k:expected['license'][k] for k in ('bytes','sha256')})
        info=b'pkgname = cachy-asahi-llhttp-reference\npkgver = 9.3.1-1\narch = aarch64\nlicense = MIT\ndepend = glibc\nprovides = llhttp=9.3.1\nprovides = libllhttp.so=9.3-64\nconflict = llhttp\n'
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:xz') as stream:
            for name,body in (('.PKGINFO',info),(expected['license']['path'],license_body)):
                member=tarfile.TarInfo(name);member.size=len(body);member.mode=0o644;stream.addfile(member,io.BytesIO(body))
        paths={k:root/({'package':expected['filename'],'signature':expected['filename']+'.sig'}.get(k,k+'.MODEL')) for k in T.KEYS}
        write(paths['package'],output.getvalue());write(paths['signature'],b'MODEL detached signature; NOT CRYPTOGRAPHIC')
        write(paths['public_key'],b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nMODEL PUBLIC DATA ONLY\n-----END PGP PUBLIC KEY BLOCK-----\n')
        expected['fingerprint']='A'*40
        current=lambda:{k:pin(paths[k].read_bytes()) for k in T.KEYS if paths[k].exists()}
        actual=current();write(paths['native_receipt'],dict(status='LLHTTP_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED',builds=2,archive=expected['filename'],package=actual['package'],source=expected['source'],license=expected['license'],MODEL=True))
        actual=current();write(paths['signing_receipt'],dict(status='PROJECT_TEST_DETACHED_SIGNATURE_CREATED',test_only=True,fingerprint=expected['fingerprint'],MODEL=True,**{k:actual[k] for k in ('package','signature','public_key','native_receipt')}))
        actual=current();binding=dict(schema=1,kind=T.KIND,source=expected['source'],license=expected['license'],fingerprint=expected['fingerprint'],operands={k:actual[k] for k in T.KEYS[:-1]});digest=pin(T.canonical(binding))['sha256']
        write(paths['root_receipt'],dict(accepted=True,issued_by='Root',scope=T.KIND,tuple_sha256=digest,MODEL=True))
        expected['pins']=current()
        return paths,expected,dict(project_test_tuple_sha256=digest,project_test_root_receipt_sha256=expected['pins']['root_receipt']['sha256'])

    def test_unbound_dependency_operands_refuse(self):
        for paths in ({},{k:None for k in T.KEYS},{k:Path('/nonexistent') for k in T.KEYS}):
            with self.assertRaises(ValueError):T.validate_tuple(paths)
        self.assertNotIn('pins',T.DEFAULT_EXPECTED);self.assertNotIn('fingerprint',T.DEFAULT_EXPECTED)

    def test_model_shape_is_unadmitted_and_crypto_not_run(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-TEST-tuple-MODEL-',dir='/home/gabe') as name:
            paths,expected,authorization=self.model_tuple(Path(name));result=T.validate_tuple(paths,expected)
            self.assertIs(result['admitted'],False);self.assertEqual(result['crypto'],'NOT RUN');self.assertIsNone(result['Root_authorization'])
            wrong=dict(authorization,project_test_tuple_sha256='0'*64)
            with self.assertRaises(ValueError):T.validate_tuple(paths,expected,wrong)
            wrong=dict(authorization,project_test_root_receipt_sha256='0'*64)
            with self.assertRaises(ValueError):T.validate_tuple(paths,expected,wrong)

    def test_model_tuple_mutations_refuse(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-TEST-refusals-MODEL-',dir='/home/gabe') as name:
            paths,expected,authorization=self.model_tuple(Path(name))
            for key in T.KEYS:
                original=paths[key].read_bytes();write(paths[key],original+b'changed')
                with self.subTest(operand=key),self.assertRaises(ValueError):T.validate_tuple(paths,expected)
                write(paths[key],original)
            for key,value in (('fingerprint','B'*40),('package','llhttp'),('version','9.3.1-2'),('arch','x86_64')):
                wrong=copy.deepcopy(expected);wrong[key]=value
                with self.subTest(identity=key),self.assertRaises(ValueError):T.validate_tuple(paths,wrong)
            wrong=copy.deepcopy(expected);wrong['source']['recipe_origin']='ALARM_SIGNER_SUBSTITUTION'
            with self.assertRaises(ValueError):T.validate_tuple(paths,wrong)
            for key in ('signature','public_key','root_receipt'):
                wrong=dict(paths);wrong.pop(key)
                with self.subTest(missing=key),self.assertRaises(ValueError):T.validate_tuple(wrong,expected)

    def test_model_unowned_or_aliased_operands_refuse(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-TEST-custody-MODEL-',dir='/home/gabe') as name:
            root=Path(name);paths,expected,_=self.model_tuple(root);target=paths['signature'];alias=root/'alias';alias.symlink_to(target)
            wrong=dict(paths,signature=alias)
            with self.assertRaises(ValueError):T.validate_tuple(wrong,expected)
            alias.unlink();os.link(target,alias)
            with self.assertRaises(ValueError):T.validate_tuple(paths,expected)
            alias.unlink();target.chmod(0o666)
            with self.assertRaises(ValueError):T.validate_tuple(paths,expected)

    def test_package_metadata_and_trust_substitutions_refuse(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-package-MODEL-',dir='/home/gabe') as name:
            paths,expected,_=self.model_tuple(Path(name));raw=paths['package'].read_bytes()
            with self.assertRaises(ValueError):T.package_data(raw+b'trailing',expected)
            with self.assertRaises(ValueError):T.package_data(gzip.compress(b'MODEL'),expected)
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:xz') as stream:
                with stream.extractfile('.PKGINFO') as body:info=body.read()
                with stream.extractfile(expected['license']['path']) as body:license_body=body.read()
            for before,after in ((b'pkgname = cachy-asahi-llhttp-reference',b'pkgname = llhttp'),(b'pkgver = 9.3.1-1',b'pkgver = 9.3.1-2'),(b'arch = aarch64',b'arch = x86_64'),(b'provides = llhttp=9.3.1',b'provides = llhttp=9.3.0'),(b'depend = glibc',b'depend = glibc\ndepend = foreign-provider')):
                output=io.BytesIO()
                with tarfile.open(fileobj=output,mode='w:xz') as stream:
                    for name,body in (('.PKGINFO',info.replace(before,after)),(expected['license']['path'],license_body)):
                        member=tarfile.TarInfo(name);member.size=len(body);member.mode=0o644;stream.addfile(member,io.BytesIO(body))
                with self.subTest(metadata=before),self.assertRaises(ValueError):T.package_data(output.getvalue(),expected)
            public=paths['public_key'];original=public.read_bytes();write(public,original.replace(b'PUBLIC KEY',b'PRIVATE KEY'));wrong=copy.deepcopy(expected);wrong['pins']['public_key']=pin(public.read_bytes())
            with self.assertRaises(ValueError):T.validate_tuple(paths,wrong)
            write(public,original);signing=json.loads(paths['signing_receipt'].read_bytes());signing['fingerprint']='B'*40;write(paths['signing_receipt'],signing);wrong=copy.deepcopy(expected);wrong['pins']['signing_receipt']=pin(paths['signing_receipt'].read_bytes())
            with self.assertRaises(ValueError):T.validate_tuple(paths,wrong)

    def test_foreign_receipt_issuer_or_source_refuses_even_with_new_pins(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-receipts-MODEL-',dir='/home/gabe') as name:
            paths,expected,_=self.model_tuple(Path(name))
            for key,field,value in (('root_receipt','issued_by','ALARM'),('root_receipt','accepted',False),('native_receipt','builds',1),('native_receipt','source',dict(expected['source'],recipe_origin='HOST_UNSIGNED_OR_ALARM'))):
                original=paths[key].read_bytes();receipt=json.loads(original);receipt[field]=value;write(paths[key],receipt);wrong=copy.deepcopy(expected);wrong['pins'][key]=pin(paths[key].read_bytes())
                with self.subTest(receipt=key,field=field),self.assertRaises(ValueError):T.validate_tuple(paths,wrong)
                write(paths[key],original)
            write(paths['signature'],b'');wrong=copy.deepcopy(expected);wrong['pins']['signature']=pin(b'')
            with self.assertRaises(ValueError):T.validate_tuple(paths,wrong)
            with self.assertRaises(ValueError):T.load(b'{"accepted":true,"accepted":false}')

class DependencyPlanControls(unittest.TestCase):
    def test_complete349_is_preserved_plus_one_project_provider(self):
        raw=(ROOT/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock').read_bytes();result=DEP.expected350(raw)
        before=raw.decode().splitlines();after=result.decode().splitlines();self.assertEqual(len(before),349);self.assertEqual(len(after),350)
        self.assertEqual(set(after)-set(before),{'cachy-asahi-llhttp-reference 9.3.1-1'});self.assertTrue(set(before)<set(after));self.assertEqual(after,sorted(after))
        for name in ('cmake','ninja','openssl','libssh2','pcre2','zlib','glibc','pkgconf','python'):
            self.assertEqual([r for r in before if r.startswith(name+' ')],[r for r in after if r.startswith(name+' ')])
        for wrong in (raw[:-1],b'package 1-1\n',raw+raw.splitlines(keepends=True)[0],raw.replace(b'abseil-cpp ',b'llhttp ',1)):
            with self.assertRaises(ValueError):DEP.expected350(wrong)

    def test_unadmitted_model_cannot_create_context(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-no-plan-MODEL-',dir='/home/gabe') as name:
            root=Path(name);paths,expected,_=ProjectTestControls.model_tuple(self,root/'operands');metadata=T.validate_tuple(paths,expected);context=root/'context'
            with self.assertRaisesRegex(ValueError,'unbound PROJECT TEST'):
                DEP.prepare_context(metadata,paths,ROOT/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock','sha256:'+'b'*64,context,nonce='a'*32)
            self.assertFalse(context.exists())

    def test_model_offline_required_signature_plan_only(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-plan-MODEL-',dir='/home/gabe') as name:
            root=Path(name);f,consumer=compatible_fixture(self,root/'operands');paths,expected,authorization=f.paths,f.expected,f.authorization
            # A matching MODEL authorization exercises DATA generation only. The
            # audit fence forbids executing this inert Docker/GPG/pacman source.
            metadata=T.validate_compatible_tuple(paths,expected,authorization,consumer_root=consumer);self.assertEqual(metadata['crypto'],'NOT RUN')
            plan=DEP.prepare_context(metadata,paths,ROOT/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock','sha256:'+'b'*64,root/'context',nonce='a'*32)
            self.assertEqual(plan['status'],'ROOT_BOUND_DATA_PLAN_ONLY');command=plan['build_command'];self.assertEqual(command[:2],['/usr/bin/docker','build']);self.assertIn('--network=none',command);self.assertIn('--pull=false',command);self.assertIn('--platform=linux/arm64',command)
            for item in ('--memory=4294967296','--memory-swap=4294967296','--cpu-period=100000','--cpu-quota=400000'):self.assertIn(item,command)
            dockerfile=(Path(plan['context'])/'Dockerfile').read_text().splitlines();self.assertEqual(dockerfile[1],'LABEL '+DEP.LABEL+'=""');self.assertIn(DEP.LABEL+'='+'a'*32,command)
            context=Path(plan['context']);config=(context/'pacman-project-test.conf').read_text();self.assertIn('SigLevel = Required TrustedOnly',config);self.assertIn('LocalFileSigLevel = Required TrustedOnly',config);self.assertIn('GPGDir = /project-test-gnupg',config);self.assertNotIn('[core]',config);self.assertNotIn('Server',config)
            script=(context/'install-project-test.py').read_text();ast.parse(script)
            for text in ('--no-auto-key-retrieve','--auto-key-locate','--status-fd','VALIDSIG','TRUST_FULLY',"'--gpgdir',K,'-U','--noconfirm'",'official349 pacman trust must remain byte-identical','not official_fingerprints.intersection(test_fingerprints)','all349 existing package-owned paths and bytes unchanged','all349 original local package database bytes unchanged'):self.assertIn(text,script)
            for text in ('--nodeps','--nocheck','--assume-installed','TrustAll','Optional','pacman-key','--recv-key','apt-get','-Sy'):self.assertNotIn(text,script+config)
            self.assertEqual((context/'expected350.lock').read_bytes(),DEP.expected350((context/'expected349.lock').read_bytes()))
            self.assertEqual((context/'public_key').read_bytes(),paths['public_key'].read_bytes())
            for wrong_image,inventory in ((plan['base_image'],b''),('sha256:'+'c'*64,b'wrong inventory\n')):
                with self.assertRaises(ValueError):DEP.verify_result(plan,wrong_image,inventory,b'{}')
            # Fully synthetic verifier MODEL, never actual runtime evidence.
            manifest=plan['manifest'];custody=dict(paths=349,payload_bytes=349,sha256='d'*64);trust=pin(b'MODEL official trust bytes')
            evidence=dict(MODEL=True,schema=1,status='PROJECT_TEST_DEPENDENCY_INSTALLED',test_only=True,tuple_sha256=plan['tuple_sha256'],root_receipt=manifest['root_receipt'],crypto='GPG_VALIDSIG',fingerprint=manifest['fingerprint'],primary_fingerprint=manifest['fingerprint'],signer_fingerprint=manifest['fingerprint'],trust_keyring=DEP.KEYRING,official_trust_before=trust,official_trust_after=trust,inventory_before=manifest['expected349'],inventory_after=manifest['expected350'],official_key_overlap=False,official_key_count=1,test_key_fingerprints=[manifest['fingerprint']],provider_before=custody,provider_after=custody,database_before=custody,database_after=custody,package=manifest['copies'][manifest['package']],signature=manifest['copies'][manifest['signature']],public_key=manifest['copies']['public_key'],transaction=['/usr/bin/pacman','--config','/project-test-input/pacman-project-test.conf','--gpgdir',DEP.KEYRING,'-U','--noconfirm','/project-test-input/'+manifest['package']])
            evidence.update(installed_providers=manifest['providers'],loader='LLHTTP_PROJECT_TEST_RTLD_NOW_PASSED')
            inventory=(context/'expected350.lock').read_bytes();model_result=DEP.verify_result(plan,'sha256:'+'c'*64,inventory,encoded(evidence));self.assertEqual(model_result['package_count'],350);self.assertEqual(model_result['M2'],'NOT RUN');self.assertEqual(model_result['release'],'NOT ADMITTED')
            mutations=dict(official_key_overlap=True,official_key_count=0,test_key_fingerprints=[],provider_after=dict(custody,sha256='e'*64),database_after=dict(custody,sha256='e'*64),official_trust_after=pin(b'changed MODEL trust'),crypto=None,primary_fingerprint='B'*40,transaction=evidence['transaction']+['--nodeps'],installed_providers={},loader='NOT RUN',signer_fingerprint='B'*40)
            for key,value in mutations.items():
                wrong=copy.deepcopy(evidence);wrong[key]=value
                with self.subTest(model_evidence=key),self.assertRaises(ValueError):DEP.verify_result(plan,'sha256:'+'c'*64,inventory,encoded(wrong))
            reader=DEP.reader_arguments('sha256:'+'c'*64,'a'*32)
            for item in ('--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory-swap=268435456'):self.assertIn(item,reader)

class NativePostconditionControls(unittest.TestCase):
    def pair_model(self,root):
        archive=os.environ.get(ARCHIVE_ENV)
        if not archive:self.skipTest('set '+ARCHIVE_ENV+' for genuine upstream license DATA')
        recipe=json.loads((HERE/'recipe-pin.json').read_bytes());reviewed={n:r['sha256'] for n,r in recipe['files'].items()};reviewed[recipe['upstream']['archive']['filename']]=recipe['upstream']['archive']['sha256']
        lock=DEP.expected350((ROOT/'scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock').read_bytes());write(root/'recipe-pin.json',recipe);write(root/'reviewed-inputs.json',reviewed);write(root/'expected350.lock',lock)
        info='pkgname = cachy-asahi-libgit2-reference\npkgver = 1:1.9.7-1\narch = aarch64\nlicense = LicenseRef-libgit2\n'+''.join('depend = '+n+'\n' for n in F.DEPENDS)
        build='format = 2\npkgname = cachy-asahi-libgit2-reference\npkgver = 1:1.9.7-1\npkgarch = aarch64\npkgbuild_sha256sum = '+reviewed['PKGBUILD']+'\n'
        build+=''.join('installed = '+row.replace(' ','-')+'-aarch64\n' for row in lock.decode().splitlines())
        bodies={'.PKGINFO':info.encode(),'.BUILDINFO':build.encode(),'.MTREE':gzip.compress(b'#mtree\n./usr type=dir\n',mtime=0),F.LIBRARY:elf_bytes()}
        with tarfile.open(fileobj=io.BytesIO(Path(archive).read_bytes()),mode='r:gz') as stream:
            for row in recipe['licenses']:
                with stream.extractfile(row['source_member']) as source:bodies[row['path']]=source.read()
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:xz') as stream:
            for name,body in bodies.items():
                member=tarfile.TarInfo(name);member.size=len(body);member.mode=0o644;stream.addfile(member,io.BytesIO(body))
        name=F.PACKAGE+'xz';raw=output.getvalue()
        for index in (1,2):
            build=root/('build-'+str(index));art=build/'artifacts';write(art/name,raw);write(art/'environment.txt',b'Linux MODEL aarch64\n4096\n');write(art/'packages.lock',lock);write(build/'expected-packages.lock',lock);write(build/'build.log',b'MODEL makepkg Starting check()\n')
            write(art/'cachy-asahi-libgit2-reference-1.9.7-1-aarch64-check.log',b'MODEL parser fixture only\nTest #1: offline ............ Passed 0.1 sec\nTest #2: util ............ Passed 0.1 sec\n100% tests passed, 0 tests failed out of 2\n'+F.MARKER+b'\n')
            report=dict(artifact=name,sha256=pin(raw)['sha256'],errors=[],members={n:dict(sha256=pin(body)['sha256']) for n,body in bodies.items()},elf={F.LIBRARY:dict(errors=[])})
            write(build/'validation.json',dict(errors=[],artifacts=[report]));write(build/'provenance.json',dict(status='built-package-static-pass',exit_code=0,mode='native',image_id='sha256:'+'a'*64,recipe_inputs=reviewed,expected_packages_sha256=pin(lock)['sha256'],builder_host_arch='aarch64',clean_environment_id='MODEL-clean-'+str(index),artifacts={name:report['sha256']},MODEL=True))
        write(root/'comparison.json',dict(status='contents-reproduced',errors=[],packages={name:dict(installed_contents_equal=True,pkginfo_equal=True,buildinfo_equal=True,bytes_equal=True)},MODEL=True))

    def test_pair_model_and_failure_postconditions(self):
        with tempfile.TemporaryDirectory(prefix='libgit2-pair-MODEL-',dir='/home/gabe') as name:
            root=Path(name);self.pair_model(root);original=F.HERE;F.HERE=root
            try:
                def run():return F.finish(root/'build-1',root/'build-2',root/'comparison.json','sha256:'+'a'*64)
                result=run();self.assertEqual(result['builds'],2);self.assertEqual(result['signature'],'NOT RUN; Root offline follow-up');self.assertEqual(result['installation'],'NOT RUN');self.assertIsNone(result['Root_acceptance'])
                for path,wrong in ((root/'build-2/artifacts/cachy-asahi-libgit2-reference-1.9.7-1-aarch64-check.log',b'compilation alone\n'),(root/'build-2/build.log',b'no check phase\n'),(root/'build-2/artifacts/packages.lock',b'stale inventory\n')):
                    raw=path.read_bytes();write(path,wrong)
                    with self.subTest(custody=path.name),self.assertRaises(ValueError):run()
                    write(path,raw)
                path=root/'build-2/provenance.json';raw=path.read_bytes();record=json.loads(raw);record['clean_environment_id']='MODEL-clean-1';write(path,record)
                with self.assertRaises(ValueError):run()
                write(path,raw);comparison=json.loads((root/'comparison.json').read_bytes());next(iter(comparison['packages'].values()))['bytes_equal']=False;write(root/'comparison.json',comparison)
                with self.assertRaises(ValueError):run()
            finally:F.HERE=original

    def test_exact_native_dynamic_closure_model(self):
        result=F.elf(elf_bytes());self.assertEqual(result['soname'],'libgit2.so.1.9');self.assertIn('libllhttp.so.9.3',result['needed']);self.assertTrue(result['structural16K']);self.assertEqual(result['M2'],'NOT RUN')
        self.assertFalse(F.elf(elf_bytes(align=4096))['structural16K'])

    def test_wrong_elf_and_dynamic_closure_refuse(self):
        for raw in (elf_bytes('libgit2.so.1'),elf_bytes(needed=['libc.so.6']),elf_bytes(needed=['libevil.so']),elf_bytes(align=2048),elf_bytes()[:100],b'not ELF'):
            with self.assertRaises(ValueError):F.elf(raw)
        raw=bytearray(elf_bytes());struct.pack_into('<H',raw,18,62)
        with self.assertRaises(ValueError):F.elf(bytes(raw))

    def test_other_archive_compression_refuses_before_inspection(self):
        C=P.C;rows=D.decode(D.read(HERE/'base/profile.json'))['held_inputs']
        name='runtime/scripts/build/compare_v2.py';original=P.held_framework_body(ROOT,name,rows[name]);projected=C.projected_compare(original).decode()
        self.assertEqual(projected.replace(C.COMPARE_AFTER,C.COMPARE_BEFORE).encode(),original)
        name='runtime/scripts/build/build_v2.py';builder=P.held_framework_body(ROOT,name,rows[name])
        tree=ast.parse(C.projected_build(builder).decode());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main');attempt=next(n for n in main.body if isinstance(n,ast.Try));index=next(i for i,n in enumerate(attempt.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='paths' for t in n.targets));gate=ast.Module(body=attempt.body[index:index+2],type_ignores=[]);ast.fix_missing_locations(gate)
        with tempfile.TemporaryDirectory(prefix='libgit2-format-DATA-',dir='/home/gabe') as name:
            root=Path(name);write(root/'model.pkg.tar.zst',b'MODEL')
            with self.assertRaises(ValueError):exec(compile(gate,'<fixed-XZ-gate>','exec'),dict(artifacts=root))
            (root/'model.pkg.tar.zst').unlink();write(root/'model.pkg.tar.xz',b'MODEL filename only');exec(compile(gate,'<fixed-XZ-gate>','exec'),dict(artifacts=root))
            for suffix in ('gz','xz'):
                path=root/(F.PACKAGE+suffix);write(path,gzip.compress(b'MODEL',mtime=0))
                with self.assertRaises(ValueError):F.archive_members(path,('.PKGINFO',))

if __name__=='__main__':unittest.main()
