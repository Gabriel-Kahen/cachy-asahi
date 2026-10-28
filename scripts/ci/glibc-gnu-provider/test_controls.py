#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert controls only: no compiler, Docker, recipe execution or package install."""
import contextlib,gzip,hashlib,importlib.util,io,json,os,tarfile,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
RECIPE=HERE.parents[2]/'packages/core/cachy-asahi-glibc-gnu-provider'


def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

M=module('materialize');S=module('stage');T=module('collect_tests');A=module('abi');R=module('run');H=module('header_check')


def write_json(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def source_rows():
    return [(name,b'x',0o644,None) for name in ('configure','Makefile','COPYINGv2','COPYING.LESSERv2','LICENSES')]+[
        ('COPYING.LIB',b'',0o777,'COPYING.LESSERv2'),('sub/run',b'#!test\n',0o755,None)]


def tree_hash(rows):
    # Independent fixture encoder; no production inspector functions used.
    def object_hash(kind,data):return hashlib.sha1(kind+b' '+str(len(data)).encode()+b'\0'+data).digest()
    sub=b'100755 run\0'+object_hash(b'blob',b'#!test\n')
    entries=[]
    for name,data,mode,target in rows:
        if '/' in name:continue
        entries.append((name.encode(),(b'120000' if target else b'100644')+b' '+name.encode()+b'\0'+object_hash(b'blob',target.encode() if target else data)))
    entries.append((b'sub/',b'40000 sub\0'+object_hash(b'tree',sub)))
    return object_hash(b'tree',b''.join(row for _,row in sorted(entries))).hex()


def archive(path,rows,root='source'):
    with tarfile.open(path,'w:gz') as out:
        for name,data,mode,target in rows:
            member=tarfile.TarInfo(root+'/'+name);member.mode=mode
            if target is not None:member.type=tarfile.SYMTYPE;member.linkname=target
            else:member.size=len(data)
            out.addfile(member,io.BytesIO(data))


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.limits=dict(source_compressed=1024**2,source_file=65536,source_members=100,source_bytes=1024**2,seconds=5)
    def tearDown(self):self.tmp.cleanup()
    def source(self,rows=None):
        rows=source_rows() if rows is None else rows;path=self.root/'source.tar.gz';archive(path,rows);return path
    def test_known_git_tree(self):
        rows=source_rows();result=M.inspect(self.source(),tree_hash(rows),self.limits)
        self.assertEqual(result['files'],7);self.assertEqual(result['root'],'source')
    def test_changed_git_blob(self):
        rows=source_rows();expected=tree_hash(rows);rows[0]=('configure',b'changed',0o644,None)
        with self.assertRaisesRegex(ValueError,'tree differs'):M.inspect(self.source(rows),expected,self.limits)
    def test_executable_bit_is_tree_identity(self):
        rows=source_rows();expected=tree_hash(rows);rows[-1]=('sub/run',b'#!test\n',0o644,None)
        with self.assertRaisesRegex(ValueError,'tree differs'):M.inspect(self.source(rows),expected,self.limits)
    def test_path_traversal(self):
        with self.assertRaisesRegex(ValueError,'canonical'):M.inspect(self.source(source_rows()+[('../escape',b'x',0o644,None)]),'0'*40,self.limits)
    def test_source_symlink_escape(self):
        with self.assertRaisesRegex(ValueError,'escapes'):M.inspect(self.source(source_rows()+[('escape',b'',0o777,'../../outside')]),'0'*40,self.limits)
    def test_duplicate_source(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):M.inspect(self.source(source_rows()+[source_rows()[0]]),'0'*40,self.limits)
    def test_source_file_bound(self):
        limits=dict(self.limits,source_file=1)
        with self.assertRaisesRegex(ValueError,'file bound'):M.inspect(self.source(),tree_hash(source_rows()),limits)
    def test_compressed_bound(self):
        with self.assertRaisesRegex(ValueError,'bounded ordinary'):M.inspect(self.source(),'0'*40,dict(self.limits,source_compressed=1))
    def test_html_is_not_source(self):
        path=self.root/'html';path.write_text('<html>challenge</html>')
        with self.assertRaises((ValueError,tarfile.ReadError,gzip.BadGzipFile)):M.inspect(path,'0'*40,self.limits)
    def test_missing_source_no_output(self):
        output=self.root/'bundle'
        with self.assertRaisesRegex(ValueError,'MISSING_PREREQUISITE'):M.materialize(RECIPE,None,output)
        self.assertFalse(output.exists())
    def test_tampered_release_no_bundle(self):
        output=self.root/'bundle';inputs=self.root/'inputs';inputs.mkdir()
        (inputs/'glibc-2.43.tar.gz').write_text('partial source')
        with self.assertRaisesRegex(ValueError,'hash/size differs'):M.materialize(RECIPE,inputs,output)
        self.assertFalse(output.exists())
    def package_info(self):
        info='pkgname = '+S.NAME+'\npkgver = '+S.VERSION+'\narch = aarch64\nprovides = glibc=2.43\nconflict = glibc\nbackup = etc/gai.conf\n'+''.join('depend = '+d+'\n' for d in ('linux-api-headers>=4.10','filesystem','tzdata'))
        build='format = 2\npkgname = '+S.NAME+'\npkgver = '+S.VERSION+'\npkgarch = aarch64\npkgbuild_sha256sum = '+'a'*64+'\n'
        return info,build
    def test_concrete_pkgbuild_binding(self):S.package_identity(*self.package_info(),'a'*64)
    def test_wrong_pkgbuild_refused(self):
        with self.assertRaisesRegex(ValueError,'BUILDINFO'):S.package_identity(*self.package_info(),'b'*64)
    def test_duplicate_package_name_refused(self):
        info,build=self.package_info()
        with self.assertRaises(ValueError):S.package_identity(info+'pkgname = glibc\n',build,'a'*64)
    def test_glibc_replacement_refused(self):
        info,build=self.package_info()
        with self.assertRaises(ValueError):S.package_identity(info+'replaces = glibc\n',build,'a'*64)
    def results(self,lines,check=0,abi=0):
        build=self.root/'build';output=self.root/'evidence';build.mkdir();output.mkdir()
        for index,line in enumerate(lines):(build/(str(index)+'.test-result')).write_text(line)
        (output/'check-exit').write_text(str(check));(output/'abi-exit').write_text(str(abi))
        return T.collect(build,output)
    def test_unsupported_kept_by_name(self):
        result=self.results(['PASS: one\n','UNSUPPORTED: needs-kernel-feature\n','XFAIL: expected\n'])
        self.assertEqual(result['status'],'PASS_UPSTREAM_APPLICABLE_TESTS');self.assertEqual(result['counts']['UNSUPPORTED'],1)
        self.assertIn('needs-kernel-feature',[r['name'] for r in result['results']])
    def test_failed_upstream_make_not_waived(self):self.assertEqual(self.results(['PASS: one\n'],check=2)['status'],'FAIL_UPSTREAM_TESTS')
    def test_upstream_abi_failure_not_waived(self):self.assertEqual(self.results(['PASS: one\n'],abi=2)['status'],'FAIL_UPSTREAM_TESTS')
    def test_xpass_fails(self):self.assertEqual(self.results(['PASS: one\n','XPASS: unexpected\n'])['status'],'FAIL_UPSTREAM_TESTS')
    def test_malformed_result_fails(self):self.assertEqual(self.results(['PASS: one\n','arbitrary\n'])['status'],'FAIL_UPSTREAM_TESTS')
    def test_no_real_pass_fails(self):self.assertEqual(self.results(['UNSUPPORTED: all\n'])['status'],'FAIL_UPSTREAM_TESTS')
    def test_abi_default_version_not_collapsed(self):
        one=' 1: 0000000000000000 8 FUNC GLOBAL DEFAULT 12 malloc@@GLIBC_2.17\n'
        self.assertNotEqual(A.symbols(one),A.symbols(one.replace('@@','@')))
    def test_object_size_is_abi(self):
        one=' 1: 0000000000000000 8 OBJECT GLOBAL DEFAULT 12 data@@GLIBC_2.17\n'
        self.assertNotEqual(A.symbols(one),A.symbols(one.replace(' 8 OBJECT',' 16 OBJECT')))
    def test_private_undefined_ignored(self):
        one=' 1: 0000000000000000 8 FUNC GLOBAL DEFAULT 12 malloc@@GLIBC_2.17\n'
        extra=' 2: 0000000000000000 8 FUNC GLOBAL DEFAULT UND unknown@@GLIBC_2.17\n 3: 0000000000000000 8 FUNC GLOBAL DEFAULT 12 secret@@GLIBC_PRIVATE\n'
        self.assertEqual(A.symbols(one),A.symbols(one+extra))
    def test_manifest_symlink_refused(self):
        (self.root/'real').write_text('x');(self.root/'alias').symlink_to('real')
        with self.assertRaisesRegex(ValueError,'ordinary'):R.checked_files(self.root,{'alias':dict(bytes=1,sha256=R.sha(self.root/'real'))})
    def test_forged_release_receipt_refused(self):
        bundle=self.root/'bundle';bundle.mkdir();(bundle/'glibc-2.43.tar.gz').write_bytes(self.source().read_bytes())
        (bundle/'PKGBUILD').write_text('inert data');(bundle/'source-lock.json').write_bytes((RECIPE/'source-lock.json').read_bytes())
        for name in M.PATCH_FILES:(bundle/name).write_bytes((RECIPE/name).read_bytes())
        files={p.name:dict(bytes=p.stat().st_size,sha256=R.sha(p)) for p in bundle.iterdir()}
        receipt=dict(status='SOURCE_BUNDLE_READY_UNSELECTED_GNU_PROVIDER',release='2.43',payload_tree=M.PAYLOAD_TREE,files=files)
        write_json(bundle/'bundle.json',receipt)
        with self.assertRaisesRegex(ValueError,'hash/size differs'):R.inputs(bundle,R.sha(bundle/'bundle.json'))
    def test_missing_bundle_pre_actor(self):
        with self.assertRaises(FileNotFoundError):R.inputs(self.root/'absent','0'*64)
    def test_hostile_shell_filename_quoted(self):
        command=R.smoke_script("a'; echo bad; '.pkg.tar.xz",'a'*64)
        self.assertNotIn('$(find',command);self.assertIn("'\"'\"'",command)
    def test_container_policy(self):
        args=R.docker_args('sha256:'+'a'*64,'owned','token',*[self.root]*6,23001,23001,self.root)
        for value in ('--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user','23001:23001','--env=CACHY_ASAHI_GLIBC_RUNTIME_SMOKE=1'):
            self.assertIn(value,args)
        self.assertNotIn('--privileged',args);self.assertNotIn('install',args)
    def runtime_fixture(self):
        manifest=self.root/'runtime-inputs.json';write_json(manifest,{role:{'sha256':role*8} for role in ('loader','libc','libm')})
        files={name:dict(sha256=name,bytes=1) for name in ('abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py')}
        receipt=dict(status='PASS_OWNED_CANDIDATE_GLIBC_RUNTIME_SMOKE',mode='NATIVE_EXECUTE',host_architecture='aarch64',
            input_sha256=R.sha(manifest),runtime=dict(status='PASS',cases=8,page_size=4096),cases=sorted(R.CASES),sources=files,
            candidate_roles={role:{'sha256':role*8} for role in ('loader','libc','libm')},runtime_files=dict(a={},b={},c={}))
        path=self.root/'receipt.json';write_json(path,receipt);return path,manifest,files,receipt
    def test_canonical_runtime_receipt_required(self):
        path,manifest,files,_=self.runtime_fixture();R.runtime_receipt(path,manifest,files)
    def test_exit0_without_complete_runtime_refused(self):
        path,manifest,files,receipt=self.runtime_fixture();receipt['status']='HOST_COMPILE_ONLY_NOT_EXECUTED';write_json(path,receipt)
        with self.assertRaisesRegex(ValueError,'canonical native'):R.runtime_receipt(path,manifest,files)
    def test_mixed_libc_receipt_refused(self):
        path,manifest,files,receipt=self.runtime_fixture();receipt['candidate_roles']['libc']['sha256']='wrong';write_json(path,receipt)
        with self.assertRaisesRegex(ValueError,'hash differs'):R.runtime_receipt(path,manifest,files)

    def test_cancelled_actor_cleanup_fixture(self):self.cleanup_fixture(False)
    def test_foreign_container_not_deleted_fixture(self):self.cleanup_fixture(True)
    def cleanup_fixture(self,foreign):
        base=self.root/'base';bundle=self.root/'bundle';smoke=self.root/'smoke';source=self.root/'source-root'
        for path in (base,bundle,smoke,source):path.mkdir()
        image='sha256:'+'b'*64
        lock=''.join(sorted('fixture-'+str(i)+' 1-1\n' for i in range(574))).encode();(base/'installed-packages.lock').write_bytes(lock)
        (base/'image-id').write_text(image);write_json(base/'report.json',dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',image=image,ownership=dict(token='base-fixture')))
        for name in ('PKGBUILD','source-lock.json','glibc-2.43.tar.gz'):(bundle/name).write_text('inert fixture only')
        files={p.name:dict(bytes=p.stat().st_size,sha256=R.sha(p)) for p in bundle.iterdir()}
        selected=dict(status='SOURCE_BUNDLE_READY_UNSELECTED_GNU_PROVIDER',release='2.43',payload_tree=M.PAYLOAD_TREE,authentication={},files=files,declared_patches=[],configured_layout={},configured_features={'multiarch':'disabled'},package_version='2.43.caa1-1')
        write_json(bundle/'bundle.json',selected)
        smoke_files={}
        for name in ('abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py'):
            (smoke/name).write_text('inert fixture');smoke_files[name]=dict(bytes=13,sha256=R.sha(smoke/name))
        write_json(smoke/'source-manifest.json',dict(files=smoke_files))
        harness=dict(files={'run.py':dict(bytes=(HERE/'run.py').stat().st_size,sha256=R.sha(HERE/'run.py'))})
        args=SimpleNamespace(base_dir=base,bundle=bundle,smoke_dir=smoke,source_root=source,output=self.root/'out',
            smoke_manifest=smoke/'source-manifest.json',bundle_manifest_sha256=R.sha(bundle/'bundle.json'),harness_manifest_sha256='fixture',owner_token='d'*32,private16k_admission=dict(status='INERT_TEST_FIXTURE'))
        containers={};removed=[];budgets=[]
        class Cancelled(BaseException):pass
        class Runner:
            def __init__(self,seconds,*_):budgets.append(seconds)
            def run(self,argv,**_):
                data=b'';code=0
                if argv[1:]==['context','show']:data=b'default\n'
                elif argv[1:]==['context','inspect','default']:data=json.dumps([{'Endpoints':{'docker':{'Host':'unix:///var/run/docker.sock'}}}]).encode()
                elif argv[1:3]==['image','inspect']:
                    data=json.dumps([dict(Id=image,Architecture='arm64',Os='linux',Config=dict(Labels={'org.cachy-asahi.bootstrap574.job':'base-fixture'}))]).encode()
                elif argv[1]=='create':
                    name=argv[argv.index('--name')+1];token=argv[argv.index('--label')+1].split('=',1)[1]
                    containers[name]=dict(Id=name,Image=image,Config=dict(Labels={R.LABEL:token}))
                elif argv[1:3]==['start','-a']:
                    if argv[-1].endswith('-probe'):data=b'root:x:0:0::/root:/bin/bash\n\n__GROUP__\nroot:x:0:\n\n__PACKAGES__\n'+lock
                    else:raise Cancelled('inert simulated cancellation')
                elif argv[1:3]==['container','inspect']:
                    name=argv[-1]
                    if name not in containers:code=1;data=('Error: No such container: '+name).encode()
                    else:
                        value=containers[name]
                        if foreign and name.endswith('-a'):value=dict(value,Config=dict(Labels={R.LABEL:'other-owner'}))
                        data=json.dumps([value]).encode()
                elif argv[1:3]==['rm','-f']:removed.append(argv[-1]);del containers[argv[-1]]
                else:raise AssertionError('unexpected inert actor '+repr(argv))
                return SimpleNamespace(returncode=code,stdout=data)
        runtime=SimpleNamespace(Runner=Runner,defer_signals=lambda:contextlib.nullcontext([]))
        with patch.object(R,'inputs',return_value=selected),patch.object(R,'LOCK',hashlib.sha256(lock).hexdigest()),patch.object(R.platform,'system',return_value='Linux'),\
             patch.object(R.platform,'machine',return_value='aarch64'),patch.object(R.os,'getuid',return_value=23001),\
             patch.object(R.os,'geteuid',return_value=23001),patch.object(R.os,'getgid',return_value=23001),patch.object(R.os,'getegid',return_value=23001),\
             patch.object(R.shutil,'disk_usage',return_value=SimpleNamespace(free=100*1024**3)),patch.dict(os.environ,{},clear=True),\
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(R.execute(args,selected,dict(files=smoke_files),harness,runtime),1)
        receipt=json.loads((args.output/'result.json').read_bytes())
        self.assertEqual(receipt['status'],'FAIL');self.assertEqual(receipt['error_type'],'Cancelled',receipt);self.assertEqual(budgets,[15000,900])
        self.assertEqual(receipt['source_bundle_preserved'],True)
        if foreign:
            self.assertEqual(len(containers),1);self.assertTrue(next(iter(containers)).endswith('-a'))
            self.assertEqual(len(removed),1);self.assertEqual(receipt['cleanup'][0]['status'],'FAIL_OR_UNKNOWN')
        else:
            self.assertFalse(containers);self.assertEqual(len(removed),2)
            self.assertTrue(all(r['status']=='PASS-absence-verified' for r in receipt['cleanup']))

    def status(self):return '[GNUPG:] VALIDSIG '+M.SUBKEY+' 2026-01-23 1769208137 0 4 0 1 10 00 '+M.PRIMARY+'\n'
    def test_expired_publisher_key_limit_retained(self):
        auth=M.signature_status('[GNUPG:] KEYEXPIRED 1775499585\n'+self.status(),0)
        self.assertTrue(auth['current_key_expiration_reported']);self.assertIn('UNSELECTED',auth['trust'])
    def test_wrong_signature_authority_refused(self):
        with self.assertRaises(ValueError):M.signature_status(self.status().replace(M.PRIMARY,'A'*40),0)
    def test_duplicate_valid_signature_refused(self):
        with self.assertRaises(ValueError):M.signature_status(self.status()*2,0)
    def test_crypto_error_not_expiration_waiver(self):
        with self.assertRaises(ValueError):M.signature_status(self.status()+'[GNUPG:] BADSIG key name\n',0)
    def test_signature_failure_exit_refused(self):
        with self.assertRaises(ValueError):M.signature_status(self.status(),2)
    def test_foreign_bootstrap_header_refused(self):
        include=self.root/'candidate';include.mkdir();(include/'features.h').write_text('candidate')
        foreign=self.root/'bootstrap.h';foreign.write_text('baseline')
        with self.assertRaisesRegex(ValueError,'fallback'):H.dependencies('target: '+str(foreign),(include,))
    def test_candidate_header_dependency_recorded(self):
        include=self.root/'candidate';include.mkdir();header=include/'features.h';header.write_text('candidate')
        self.assertEqual(H.dependencies('target: '+str(header),(include,))[str(header)]['sha256'],R.sha(header))
    def test_header_alias_escape_refused(self):
        include=self.root/'candidate';include.mkdir();foreign=self.root/'bootstrap.h';foreign.write_text('baseline')
        (include/'features.h').symlink_to(foreign)
        with self.assertRaisesRegex(ValueError,'fallback'):H.dependencies('target: '+str(include/'features.h'),(include,))


if __name__=='__main__':unittest.main()
