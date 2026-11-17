#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""One actor-fenced MODEL interoperability control using genuine source DATA.

Synthetic key/signature/archive/native records never confer actual signature,
Root, native, loader or hardware acceptance. The two-package Rust policy remains
separate; this control exercises its unchanged single-provider predicates.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ATTEMPTS=[]
def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn')) or event in ('os.system','fcntl.flock'):
        ATTEMPTS.append(event);raise AssertionError('INTEROP_MODEL_NO_ACTOR: '+event)
sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
CONSUMER_ENV='LIBGIT2_CONSUMER_ROOT'
RECIPE_ENV='LIBGIT2_DATA_RECIPE_ROOT'
SOURCE_ENV='LLHTTP_DATA_ARCHIVE'
NAME='cachy-asahi-llhttp-reference'
FILENAME=NAME+'-9.3.1-1-aarch64.pkg.tar.xz'
PREFIX='dependency-provenance/'+NAME+'/'
KEY_BODY=b'\x04\0\0\0\x01\x01MODEL_PUBLIC_PACKET_NOT_A_REAL_KEY'
KEY=bytes((0xc6,len(KEY_BODY)))+KEY_BODY
FPR=hashlib.sha1(b'\x99'+len(KEY_BODY).to_bytes(2,'big')+KEY_BODY).hexdigest().upper()
SIGNATURE_BODY=b'MODEL_DETACHED_SIGNATURE_NOT_CRYPTOGRAPHIC'
SIGNATURE=bytes((0xc2,len(SIGNATURE_BODY)))+SIGNATURE_BODY
ELF=b'\x7fELF\x02\x01\x01'+bytes(9)+b'\x03\x00\xb7\x00'+bytes(44)+b'MODEL_NOT_EXECUTABLE_OR_LOADABLE'

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)

def ref(root,path):return dict(path=str(path.relative_to(root)),**pin(path.read_bytes()))

class Fixture:
    """Full synthetic native records, exact genuine original recipe/source bytes."""
    def __init__(self,root,A,recipe_root,source_path):
        self.root,self.A=root,A;D=A.D;self.D=D
        selected=A.SPECS[NAME]
        proof=json.loads((HERE.parent/'llhttp-reference-native-source/recipe-pin.json').read_bytes())
        self.recipe={}
        for name,wanted in proof['files'].items():
            raw=(recipe_root/proof['recipe_path']/name).read_bytes()
            if pin(raw)!=wanted:raise ValueError('genuine original recipe input differs: '+name)
            self.recipe[name]=raw
        source=source_path.read_bytes()
        if pin(source)!={k:selected['source'][k] for k in ('bytes','sha256')}:raise ValueError('genuine llhttp source differs')
        self.recipe[selected['source']['filename']]=source
        with tarfile.open(fileobj=io.BytesIO(source),mode='r:gz') as archive:
            with archive.extractfile(selected['source']['archive_prefix']+'/LICENSE-MIT') as stream:license_raw=stream.read()
        if pin(license_raw)!={k:proof['license'][k] for k in ('bytes','sha256')}:raise ValueError('genuine MIT source bytes differ')
        for name,raw in self.recipe.items():write(root/PREFIX/name,raw)
        write(root/(PREFIX+'sources/'+selected['source']['filename']),source)
        write(root/(PREFIX+'licenses/LICENSE-MIT'),license_raw)
        self.public_key=root/'project-test/public.gpg';write(self.public_key,KEY)
        metadata=dict(pkgname=[NAME],pkgver=['9.3.1-1'],arch=['aarch64'],license=['MIT'],depend=['glibc'],provides=['llhttp=9.3.1','libllhttp.so=9.3-64'],conflict=['llhttp'],replaces=[])
        buildinfo=('format = 2\npkgname = '+NAME+'\npkgver = 9.3.1-1\npkgarch = aarch64\npkgbuild_sha256sum = '+pin(self.recipe['PKGBUILD'])['sha256']+'\n').encode()
        self.bodies={'.PKGINFO':b''.join((key+' = '+value+'\n').encode() for key,values in metadata.items() for value in values),'.BUILDINFO':buildinfo,'.MTREE':b'MODEL_MTREE_DATA', 'usr/lib/libllhttp.so.9.3.1':ELF,'usr/share/licenses/'+NAME+'/LICENSE-MIT':license_raw}
        providers={'usr/lib/libllhttp.so.9.3.1':dict(kind='file',mode=0o755,**pin(ELF)),'usr/lib/libllhttp.so.9.3':dict(kind='symlink',mode=0o777,target='libllhttp.so.9.3.1'),'usr/lib/libllhttp.so':dict(kind='symlink',mode=0o777,target='libllhttp.so.9.3')}
        self.package=root/'build-dependencies'/FILENAME
        self.package.parent.mkdir(parents=True)
        with tarfile.open(self.package,'w:xz') as archive:
            for name,raw in self.bodies.items():
                entry=tarfile.TarInfo(name);entry.mode=providers[name]['mode'] if name in providers else 0o644;entry.size=len(raw);archive.addfile(entry,io.BytesIO(raw))
            for name,item in providers.items():
                if item['kind']=='symlink':
                    entry=tarfile.TarInfo(name);entry.type=tarfile.SYMTYPE;entry.mode=0o777;entry.linkname=item['target'];archive.addfile(entry)
        self.signature=self.package.with_name(FILENAME+'.sig');write(self.signature,SIGNATURE)
        source_name=PREFIX+'sources/'+selected['source']['filename']
        self.row=dict(name=NAME,version='9.3.1-1',filename=FILENAME,archive=pin(self.package.read_bytes()),signature=pin(SIGNATURE),url='https://MODEL.invalid/'+FILENAME,metadata=metadata,providers=providers,
            license_provenance=dict(url='https://github.com/Gabriel-Kahen/cachy-asahi/blob/'+selected['recipe_revision']+'/'+selected['recipe_path']+'/PKGBUILD',revision=selected['recipe_revision'],licenses=['MIT'],pkgbuild=dict(path=PREFIX+'PKGBUILD',**pin(self.recipe['PKGBUILD'])),buildinfo=pin(buildinfo),license_files={PREFIX+'licenses/LICENSE-MIT':pin(license_raw)},recipe_files={PREFIX+n:pin(raw) for n,raw in self.recipe.items()},sources={source_name:{k:selected['source'][k] for k in ('url','revision','bytes','sha256')}}),native=dict(builds=[],comparison={}))
        self.trust=dict(scope='PROJECT_TEST_ONLY',public_key=ref(root,self.public_key),primary_fingerprint=FPR,signing_fingerprint=FPR,ALARM_authentication=False)
        self.N=A.module(A.HERE/'native.py');self.AR=A.module(A.HERE/'archive.py')
        lock=(HERE.parent/'hyprland03-native-source-v1/fixtures/expected349.lock').read_bytes()
        # A genuine lock is DATA, not a native execution receipt.
        self.records=[]
        for index in (1,2):
            folder=root/('build-'+str(index))
            for name,raw in self.recipe.items():write(folder/'inputs'/name,raw)
            for name in self.N.REQUIRED:write(folder/name,b'MODEL_RETAINED_DATA\n')
            write(folder/'expected-packages.lock',lock);write(folder/'artifacts/packages.lock',lock)
            write(folder/'artifacts/environment.txt',b'Linux MODEL aarch64\n4096\n')
            write(folder/'artifacts/generated.SRCINFO',self.recipe['.SRCINFO'])
            write(folder/'artifacts'/FILENAME,self.package.read_bytes())
            members={name:dict(type='0',mode=providers[name]['mode'] if name in providers else 0o644,size=len(raw),sha256=pin(raw)['sha256']) for name,raw in self.bodies.items()}
            members.update({name:dict(type='2',mode=0o777,link=item['target']) for name,item in providers.items() if item['kind']=='symlink'})
            report=dict(errors=[],artifacts=[dict(artifact=FILENAME,sha256=self.row['archive']['sha256'],errors=[],members=members,metadata={'.PKGINFO':metadata,'.BUILDINFO':D.pkginfo(buildinfo)},elf={'usr/lib/libllhttp.so.9.3.1':dict(machine=183,errors=[],hardware_status='MODEL NOT RUN')})])
            write(folder/'validation.json',D.encode(report))
            record=dict(schema_version=1,status='built-package-static-pass',exit_code=0,mode='native',builder_host_arch='aarch64',image='sha256:'+'a'*64,image_id='sha256:'+'a'*64,network='none',source_date_epoch=1791748800,clean_environment_id='MODEL-llhttp-native-'+str(index),recipe_inputs={n:pin(raw)['sha256'] for n,raw in self.recipe.items()},recipe_metadata=dict(pkgname=[NAME],arch=['aarch64'],depends=['glibc']),expected_packages_sha256=pin(lock)['sha256'],entry_script_sha256='9be3db97efde70536a81d1c97f9ac69893a6004ab403566f8453704a2a189d2a',artifacts={FILENAME:self.row['archive']['sha256']},MODEL=True)
            record['command']=['docker','run','--rm','--name',record['clean_environment_id'],'--pull=never','--platform','linux/arm64','--user','1000:1000','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','512','--memory','4g','--memory-swap','4g','--cpus','4','--network','none','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g','--env','CACHY_ASAHI_CONTAINER=1','--env','SOURCE_DATE_EPOCH=1791748800','--mount','type=bind,src=/MODEL/inputs,dst=/inputs,readonly','--mount','type=bind,src=/MODEL/out,dst=/out','--mount','type=bind,src=/MODEL/entry.sh,dst=/builder-entry.sh,readonly','--mount','type=bind,src=/MODEL/expected.lock,dst=/expected-packages.lock,readonly','--label','org.cachy-asahi.llhttp-reference.nonce='+'a'*32,'--entrypoint','/bin/bash',record['image_id'],'/builder-entry.sh']
            self.records.append(record);self.row['native']['builds'].append({});self.refresh(index-1)
        comparison=dict(status='contents-reproduced',errors=[],packages={FILENAME:dict.fromkeys(('installed_contents_equal','pkginfo_equal','buildinfo_equal','bytes_equal'),True)},MODEL=True)
        path=root/'comparison.json';write(path,D.encode(comparison));self.row['native']['comparison']=ref(root,path)

    def refresh(self,index):
        folder=self.root/('build-'+str(index+1));record=self.records[index]
        record['files']={str(path.relative_to(folder)):pin(path.read_bytes())['sha256'] for path in folder.rglob('*') if path.is_file() and path.name!='provenance.json' and not path.is_relative_to(folder/'inputs')}
        write(folder/'provenance.json',self.D.encode(record));self.row['native']['builds'][index]=dict(provenance=ref(self.root,folder/'provenance.json'),validation=ref(self.root,folder/'validation.json'))

    def selected_files(self):
        q=self.row['license_provenance'];names=set(q['recipe_files'])|set(q['license_files'])|set(q['sources'])
        names.add(self.row['native']['comparison']['path'])
        for evidence in self.row['native']['builds']:
            names.update(evidence[key]['path'] for key in ('provenance','validation'))
            folder=Path(evidence['provenance']['path']).parent
            record=json.loads((self.root/evidence['provenance']['path']).read_bytes())
            names.update(str(folder/name) for name in record['files'])
            names.update(str(folder/'inputs'/name) for name in record['recipe_inputs'])
        return {name:pin((self.root/name).read_bytes()) for name in sorted(names)}

    def bind_producer(self,T):
        # These are explicitly MODEL Root-shaped documents. External hashes in
        # a real caller remain genuine Root custody, never this fixture.
        self.paths=dict(package=self.package,signature=self.signature,public_key=self.public_key,
            native_receipt=self.root/'native_receipt',signing_receipt=self.root/'signing_receipt',root_receipt=self.root/'root_receipt')
        self.expected=copy.deepcopy(T.DEFAULT_EXPECTED)
        self.expected.update(fingerprint=FPR,signing_fingerprint=FPR)
        native=dict(status='LLHTTP_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED',builds=2,archive=FILENAME,
            package=pin(self.package.read_bytes()),source=self.expected['source'],license=self.expected['license'],
            consumer=dict(row=self.row,files=self.selected_files()),MODEL=True)
        write(self.paths['native_receipt'],T.canonical(native))
        actual={name:pin(path.read_bytes()) for name,path in self.paths.items() if name not in ('signing_receipt','root_receipt')}
        signing=dict(status='PROJECT_TEST_DETACHED_SIGNATURE_CREATED',test_only=True,fingerprint=FPR,signing_fingerprint=FPR,MODEL=True,**actual)
        write(self.paths['signing_receipt'],T.canonical(signing));actual['signing_receipt']=pin(self.paths['signing_receipt'].read_bytes())
        digest=pin(T.canonical(T.tuple_binding(actual,self.expected)))['sha256']
        write(self.paths['root_receipt'],T.canonical(dict(accepted=True,issued_by='Root',scope=T.KIND,tuple_sha256=digest,MODEL=True)))
        self.expected['pins']={name:pin(path.read_bytes()) for name,path in self.paths.items()}
        self.authorization=dict(project_test_tuple_sha256=digest,project_test_root_receipt_sha256=self.expected['pins']['root_receipt']['sha256'])
        return self

def fixture(root,consumer_root):
    """Reusable explicit MODEL fixture for the old constructor/plan controls."""
    A=module(Path(consumer_root)/'scripts/ci/rust199-source-reference-native/project_test_provider_v1/admission.py','frozen_consumer_fixture')
    T=module(HERE/'project_test.py','producer_common_tuple_fixture')
    return Fixture(Path(root),A,Path(os.environ[RECIPE_ENV]),Path(os.environ[SOURCE_ENV])).bind_producer(T)

class Interoperability(unittest.TestCase):
    def test_one_llhttp_tuple_uses_unchanged_consumer_predicates(self):
        operands={name:os.environ.get(name) for name in (CONSUMER_ENV,RECIPE_ENV,SOURCE_ENV)}
        if not all(operands.values()):self.skipTest('explicit consumer checkout, recipe checkout and genuine llhttp source DATA required')
        consumer=Path(operands[CONSUMER_ENV])/'scripts/ci/rust199-source-reference-native/project_test_provider_v1'
        A=module(consumer/'admission.py','frozen_consumer_interop')
        with tempfile.TemporaryDirectory(prefix='llhttp-common-tuple-MODEL-',dir='/home/gabe/.cache') as name:
            f=Fixture(Path(name),A,Path(operands[RECIPE_ENV]),Path(operands[SOURCE_ENV]))
            A.public_key(KEY,f.trust)
            source=A.audit_source(f.root,f.row)
            native=f.N.validate(f.root,f.row)
            archive=f.AR.audit(f.package,f.row,A.D)
            self.assertEqual(source['sources'],f.row['license_provenance']['sources'])
            self.assertEqual(native['archive'],f.row['archive']);self.assertFalse(native['native_acceptance']);self.assertIsNone(native['Root_acceptance'])
            self.assertTrue(archive['complete_provider_inventory']);self.assertEqual(archive['providers'],f.row['providers'])
            self.assertFalse(archive['native_acceptance']);self.assertIsNone(archive['Root_acceptance'])
            T=module(HERE/'project_test.py','producer_common_tuple_control');f.bind_producer(T)
            consumer_root=Path(operands[CONSUMER_ENV])
            data=T.validate_compatible_tuple(f.paths,f.expected,consumer_root=consumer_root)
            self.assertFalse(data['admitted']);self.assertEqual(data['crypto'],'NOT RUN')
            admitted=T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            self.assertTrue(admitted['admitted']);self.assertEqual(admitted['crypto'],'NOT RUN')
            self.assertEqual(admitted['fingerprint'],FPR)
            self.assertEqual(admitted['consumer']['interface_commit'],'14ddf20677652e1d4057798ddf04734924668ae9')
            self.assertEqual(admitted['consumer']['row'],pin(A.encode(f.row)))
            self.assertEqual(admitted['consumer']['primary_fingerprint'],admitted['consumer']['signing_fingerprint'])
            self.assertFalse(admitted['consumer']['signature_mathematics_verified'])
            self.assertFalse(admitted['consumer']['native_acceptance']);self.assertIsNone(admitted['consumer']['Root_acceptance'])
            self.assertEqual(admitted['consumer']['providers'],f.row['providers'])
            DEP=module(HERE/'dependency.py','producer_common_dependency_plan')
            lock=HERE.parent/'hyprland03-native-source-v1/fixtures/expected349.lock'
            with self.assertRaises(ValueError):
                DEP.prepare_context(data,f.paths,lock,'sha256:'+'b'*64,f.root/'unadmitted-context',nonce='a'*32)
            legacy=T.validate_tuple(f.paths,f.expected,f.authorization)
            with self.assertRaisesRegex(ValueError,'complete immutable consumer'):
                DEP.prepare_context(legacy,f.paths,lock,'sha256:'+'b'*64,f.root/'aggregate-only-context',nonce='a'*32)
            plan=DEP.prepare_context(admitted,f.paths,lock,'sha256:'+'b'*64,f.root/'dependency-context',nonce='a'*32)
            self.assertEqual(plan['manifest']['providers'],f.row['providers'])
            self.assertEqual(plan['manifest']['signing_fingerprint'],FPR)
            self.assertEqual(plan['manifest']['copies']['public_key'],pin(KEY))
            self.assertEqual(plan['tuple_sha256'],admitted['tuple_sha256'])
            with self.assertRaises((ValueError,TypeError)):
                T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=None)
            # Changed genuine sources, selected providers, native receipts and
            # public keys refuse even with fresh MODEL receipt byte bindings.
            source_path=f.root/next(iter(f.row['license_provenance']['sources']))
            before=source_path.read_bytes();write(source_path,before+b'CHANGED')
            with self.assertRaises(ValueError):T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            write(source_path,before)
            original=copy.deepcopy(f.row['providers']);f.row['providers']['usr/lib/libllhttp.so.9.3.1']['mode']=0o644;f.bind_producer(T)
            with self.assertRaises(ValueError):T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            f.row['providers']=original;f.bind_producer(T)
            before=f.records[0]['mode'];f.records[0]['mode']='host';f.refresh(0);f.bind_producer(T)
            with self.assertRaises(ValueError):T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            f.records[0]['mode']=before;f.refresh(0);f.bind_producer(T)
            original_argv=list(f.records[0]['command']);f.records[0]['command'].insert(2,'--nodeps');f.refresh(0);f.bind_producer(T)
            with self.assertRaises(ValueError):T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            f.records[0]['command']=original_argv;f.refresh(0);f.bind_producer(T)
            before=(f.root/'build-1/expected-packages.lock').read_bytes()
            changed=before+b'zz-model-extra 1-1\n'
            for index in (0,1):
                folder=f.root/('build-'+str(index+1));write(folder/'expected-packages.lock',changed);write(folder/'artifacts/packages.lock',changed)
                f.records[index]['expected_packages_sha256']=pin(changed)['sha256'];f.refresh(index)
            f.bind_producer(T)
            with self.assertRaises(ValueError):T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            for index in (0,1):
                folder=f.root/('build-'+str(index+1));write(folder/'expected-packages.lock',before);write(folder/'artifacts/packages.lock',before)
                f.records[index]['expected_packages_sha256']=pin(before)['sha256'];f.refresh(index)
            f.bind_producer(T)
            before=f.public_key.read_bytes();write(f.public_key,before+b'CHANGED');f.bind_producer(T)
            with self.assertRaises(ValueError):T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            write(f.public_key,before);f.bind_producer(T)
            wrong=copy.deepcopy(f.authorization);wrong['project_test_tuple_sha256']='0'*64
            with self.assertRaises(ValueError):T.validate_compatible_tuple(f.paths,f.expected,wrong,consumer_root=consumer_root)
            final=T.validate_compatible_tuple(f.paths,f.expected,f.authorization,consumer_root=consumer_root)
            self.assertTrue(final['admitted']);self.assertEqual(final['crypto'],'NOT RUN')
            self.assertEqual(ATTEMPTS,[])

if __name__=='__main__':unittest.main(verbosity=2)
