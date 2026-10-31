#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Provider-specific inert metadata, ownership, gating and source controls."""
import ast,base64,copy,hashlib,importlib.util,io,json,os,shlex,struct,subprocess,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('GLIBC_PROVIDER_REPO_ROOT',Path.cwd()))
RECIPE=HERE.parents[2]/'packages/core/cachy-asahi-glibc-gnu-provider'


def load(name):
    spec=importlib.util.spec_from_file_location('provider_test_'+name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


M=load('materialize');D=load('metadata');O=load('ownership');S=load('stage');J=load('job');R=load('run')
N=load('normal_clients')


def image(interp=None):
    """Synthetic data, never executable evidence: ELF64 LE AArch64 tables."""
    raw=bytearray(624);count=2 if interp else 1
    struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,b'\x7fELF\x02\x01\x01'+b'\0'*9,3,183,1,0,64,384,0,64,56,count,64,3,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0,0,624,624,16384)
    table=b'\0_nl_default_dirname\0';raw[184:184+len(table)]=table
    struct.pack_into('<IBBHQQ',raw,248,1,17,0,1,288,18)
    raw[288:306]=b'/usr/share/locale\0'
    if interp:
        value=interp.encode()+b'\0';raw[320:320+len(value)]=value
        struct.pack_into('<IIQQQQQQ',raw,120,3,4,320,320,320,len(value),len(value),1)
    struct.pack_into('<IIQQQQIIQQ',raw,448,0,3,0,0,184,len(table),0,0,1,0)
    struct.pack_into('<IIQQQQIIQQ',raw,512,0,11,0,0,224,48,1,0,8,24)
    return bytes(raw)


class Temporary(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)


class Provider(Temporary):
    def test_actual_reviewed_recipe_and_helper(self):
        lock=json.loads((RECIPE/'source-lock.json').read_bytes());M.verify_configuration(RECIPE,lock);M.verify_patches(RECIPE,lock)
        self.assertEqual((HERE/'provider_stage.py').read_bytes(),(RECIPE/'stage.py').read_bytes())
        self.assertEqual(len('/usr/share/locale'.encode())+1,18)

    def test_recipe_change_refused(self):
        (self.root/'PKGBUILD').write_text((RECIPE/'PKGBUILD').read_text().replace('--disable-multi-arch','--enable-multi-arch'))
        with self.assertRaisesRegex(ValueError,'exact reviewed'):M.verify_configuration(self.root,json.loads((RECIPE/'source-lock.json').read_bytes()))

    def test_srcinfo_expectation_matches_literal_recipe_without_sourcing(self):
        text=(RECIPE/'PKGBUILD').read_text();expected=D.fields((HERE/'expected.SRCINFO').read_text())
        for key,values in expected.items():
            if key=='pkgbase':continue
            import re
            match=re.search(r'^'+key+r'=(\([^)]*\)|[^\n]*)',text,re.M)
            self.assertIsNotNone(match,key);raw=match[1]
            self.assertEqual(shlex.split(raw[1:-1] if raw.startswith('(') else raw),values,key)
        D.srcinfo((HERE/'expected.SRCINFO').read_text(),(HERE/'expected.SRCINFO').read_text())

    def test_missing_extra_and_changed_actual_srcinfo_refused(self):
        expected=(HERE/'expected.SRCINFO').read_text()
        for changed in (expected.replace('\tprovides = glibc=2.43\n',''),expected+'\treplaces = glibc\n',expected.replace('glibc=2.43','glibc=2.43+r22')):
            with self.subTest(changed=changed),self.assertRaises(ValueError):D.srcinfo(changed,expected)

    def test_conventional_loader_link_and_escape(self):
        self.assertEqual(S.local_link('usr/bin/ld.so','../lib/ld-linux-aarch64.so.1'),'usr/lib/ld-linux-aarch64.so.1')
        for path in ('/usr/lib/libc.so.6','../../../etc/passwd','../../../opt/caa/g243a1/usr/lib/libc.so.6'):
            with self.subTest(path=path),self.assertRaises(ValueError):S.local_link('usr/lib/libc.so',path)

    def test_archive_scope_rejects_scriptlets_aliases_and_foreign_config(self):
        for name in ('.INSTALL','lib','bin','sbin','usr/sbin','etc/ld.so.conf','etc/nsswitch.conf','opt/caa/g243a1/usr/lib/libc.so.6'):
            self.assertFalse(S.allowed(name),name)

    def test_native_stage_refuses_host_execution(self):
        with patch.dict(os.environ,{},clear=True),self.assertRaisesRegex(ValueError,'owned native'):
            S.stage(self.root/'absent',self.root/'output','a'*64,self.root/'lock',self.root/'audit',self.root/'owners')

    def test_accepted_abi_header_test_collectors_unchanged(self):
        for name in ('abi.py','header_check.py','header_probe.c','collect_tests.py'):
            self.assertEqual((HERE/name).read_bytes(),(ROOT/'scripts/ci/glibc-official-release'/name).read_bytes(),name)

    def test_full_checks_and_native_actual_srcinfo_are_required(self):
        recipe=(RECIPE/'PKGBUILD').read_text();entry=(HERE/'build-entry.sh').read_text()
        for command in ('make -s -k -j4 check >','make -s -j4 check-abi >','(( check_status == 0 && abi_status == 0 ))'):
            self.assertIn(command,recipe)
        self.assertIn('--actual /work/evidence/generated.SRCINFO --expected /runner/expected.SRCINFO',entry)
        self.assertIn('cmp /inputs/stage.py /runner/provider_stage.py',entry)
        self.assertNotIn('--nocheck',entry);self.assertNotIn('--nodeps',entry)

    def test_runtime_commands_use_new_stage_with_strict_checks(self):
        command=R.smoke_script(R.PACKAGE,'a'*64)
        self.assertIn('--stage /work/stage/root',command)
        self.assertIn('--ownership-output /work/evidence/provider-ownership.json',command)
        self.assertIn('--workspace /work/runtime-smoke --execute',command)
        self.assertNotIn('/opt/',command)


class Ownership(Temporary):
    def fixture(self):
        packages=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']
        lock=self.root/'lock';lock.write_text(''.join(sorted(p['name']+' '+p['version']+'\n' for p in packages)))
        database=self.root/'local';database.mkdir();paths={}
        for row in packages:
            p=database/(row['name']+'-'+row['version']);p.mkdir();paths[row['name']]=p
            (p/'desc').write_text('%NAME%\n'+row['name']+'\n\n%VERSION%\n'+row['version']+'\n')
            (p/'files').write_text('%FILES%\n')
        (database/'ALPM_DB_VERSION').write_text('9\n')
        (paths['glibc']/'files').write_text('%FILES%\nusr/\nusr/lib/\nusr/lib/libc.so.6\netc/gai.conf\n')
        (paths['tzdata']/'files').write_text('%FILES%\nusr/bin/zic\nusr/bin/zdump\nusr/bin/tzselect\n')
        (paths['filesystem']/'files').write_text('%FILES%\nlib\netc/ld.so.conf\netc/nsswitch.conf\n')
        return database,lock,paths

    def test_complete_574_scan_allows_replaced_glibc_paths(self):
        database,lock,_=self.fixture();value=O.check(database,lock,{'usr/lib/libc.so.6','etc/gai.conf','usr/share/licenses/new/LICENSES'})
        self.assertEqual(value['checked_packages'],574);self.assertEqual(value['overlapping_removed_glibc_paths'],2)

    def test_exact_fileless_metapackages_allow_zero_byte_alpm_records(self):
        database,lock,paths=self.fixture()
        for name in ('base','base-devel','ca-certificates','dbus-units','gcc-libs','linux-firmware'):(paths[name]/'files').write_bytes(b'')
        value=O.check(database,lock,{'usr/lib/libc.so.6'})
        self.assertEqual(value['checked_packages'],574)
        self.assertEqual(value['overlapping_removed_glibc_paths'],1)
        self.assertEqual(value['other_owner_collisions'],{})

    def test_fileless_records_do_not_hide_other_owner_collisions(self):
        database,lock,paths=self.fixture()
        for name in ('base','base-devel','ca-certificates','dbus-units','gcc-libs','linux-firmware'):(paths[name]/'files').write_bytes(b'')
        with self.assertRaisesRegex(ValueError,'tzdata'):O.check(database,lock,{'usr/bin/zic'})
        (paths['base']/'files').write_text('%FILES%\nusr/lib/libc.so.6\n')
        with self.assertRaisesRegex(ValueError,'base'):O.check(database,lock,{'usr/lib/libc.so.6'})

    def test_empty_non_metapackage_and_malformed_fileless_records_refused(self):
        database,lock,paths=self.fixture()
        for name,raw in (('glibc',b''),('base',b'\n'),('base',b'%BACKUP%\n'),
                         ('base',b'garbage\n'),('base',b'%FILES%\n%FILES%\n')):
            with self.subTest(name=name,raw=raw):
                original=(paths[name]/'files').read_bytes();(paths[name]/'files').write_bytes(raw)
                try:
                    with self.assertRaises(ValueError):O.check(database,lock,set())
                finally:(paths[name]/'files').write_bytes(original)

    def test_zero_byte_fileless_records_still_require_exact_identity_and_regular_file(self):
        database,lock,paths=self.fixture();p=paths['base']
        (p/'files').write_bytes(b'');(p/'desc').write_text('%NAME%\nbase\n\n%VERSION%\nwrong\n')
        with self.assertRaisesRegex(ValueError,'identity differs'):O.check(database,lock,set())
        (p/'desc').write_text('%NAME%\nbase\n\n%VERSION%\n3-3\n')
        (p/'files').unlink();(p/'files').symlink_to(lock)
        with self.assertRaisesRegex(ValueError,'ordinary ALPM'):O.check(database,lock,set())

    def test_exact_held_base_devel_archive_is_metadata_only_and_identity_bound(self):
        evidence=json.loads((HERE/'base-devel-fileless-evidence.json').read_bytes())
        package=next(r for r in json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages'] if r['name']=='base-devel')
        self.assertEqual(evidence['package'],package)
        raw=base64.b64decode(evidence['archive_base64'],validate=True)
        self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(package['size'],package['sha256']))
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:xz') as archive:
            self.assertEqual(set(archive.getnames()),{'.BUILDINFO','.MTREE','.PKGINFO'})
            self.assertTrue(all(m.isfile() for m in archive.getmembers()))
            metadata=D.fields(archive.extractfile('.PKGINFO').read().decode())
        self.assertEqual((metadata['pkgname'],metadata['pkgver'],metadata['size']),(['base-devel'],['1-2'],['0']))
        reference=evidence['host_format'];desc=base64.b64decode(reference['desc_base64'],validate=True)
        self.assertEqual(hashlib.sha256(desc).hexdigest(),reference['desc_sha256'])
        self.assertEqual((O.blocks(desc)['%NAME%'],O.blocks(desc)['%VERSION%']),(['base-devel'],['1-2']))
        self.assertEqual(base64.b64decode(reference['files_base64']),b'')
        self.assertEqual(evidence['native_database'],'NOT_EXPORTED_BY_ACTUAL38953883080')

    def test_missing_base_devel_entry_reproduces_ownership_failure_then_six_records_pass(self):
        database,lock,paths=self.fixture()
        for name in O.FILELESS:(paths[name]/'files').write_bytes(b'')
        previous={name:version for name,version in O.FILELESS.items() if name!='base-devel'}
        with patch.dict(O.FILELESS,previous,clear=True),self.assertRaisesRegex(ValueError,'file list required: base-devel 1-2'):
            O.check(database,lock,{'usr/lib/libc.so.6'})
        self.assertEqual(O.check(database,lock,{'usr/lib/libc.so.6'})['checked_packages'],574)

    def test_fileless_exception_is_six_exact_identities_not_zero_install_size(self):
        self.assertEqual(O.FILELESS,{'base':'3-3','base-devel':'1-2','ca-certificates':'20240618-1','dbus-units':'37-3','gcc-libs':'16.1.1+r12+g301eb08fa2c5-1','linux-firmware':'20260916-1'})
        database,lock,paths=self.fixture();(paths['dbus-broker-units']/'files').write_bytes(b'')
        # This held package declares size0 but owns real symlink paths. Never infer
        # a fileless exception from the installed-size metadata alone.
        with self.assertRaisesRegex(ValueError,'dbus-broker-units'):O.check(database,lock,set())

    def test_base_devel_nonempty_collision_and_malformed_records_are_not_ignored(self):
        database,lock,paths=self.fixture();path=paths['base-devel']/'files'
        path.write_text('%FILES%\nusr/lib/libc.so.6\n')
        with self.assertRaisesRegex(ValueError,'base-devel'):O.check(database,lock,{'usr/lib/libc.so.6'})
        for raw in (b'\n',b'%BACKUP%\n',b'garbage\n',b'%FILES%\n%FILES%\n',b'%FILES%\n../escape\n'):
            path.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):O.check(database,lock,set())

    def test_empty_base_devel_requires_exact_version_and_ordinary_record(self):
        database,lock,paths=self.fixture();directory=paths['base-devel'];path=directory/'files';path.write_bytes(b'')
        (directory/'desc').write_text('%NAME%\nbase-devel\n\n%VERSION%\n1-3\n')
        with self.assertRaisesRegex(ValueError,'identity differs'):O.check(database,lock,set())
        (directory/'desc').write_text('%NAME%\nbase-devel\n\n%VERSION%\n1-2\n');path.unlink();path.symlink_to(lock)
        with self.assertRaisesRegex(ValueError,'ordinary ALPM'):O.check(database,lock,set())

    def test_tzdata_collision_fails_without_overwrite(self):
        database,lock,_=self.fixture()
        with self.assertRaisesRegex(ValueError,'tzdata'):O.check(database,lock,{'usr/bin/zic'})

    def test_filesystem_owned_config_fails(self):
        database,lock,_=self.fixture()
        with self.assertRaisesRegex(ValueError,'filesystem'):O.check(database,lock,{'etc/ld.so.conf'})

    def test_wrong_inventory_and_missing_package_refused(self):
        database,lock,paths=self.fixture();(paths['tzdata']/'desc').write_text('%NAME%\ntzdata\n\n%VERSION%\nwrong\n')
        with self.assertRaisesRegex(ValueError,'identity differs'):O.check(database,lock,set())
        lock.write_text('glibc wrong\n')
        with self.assertRaisesRegex(ValueError,'exact held574'):O.check(database,lock,set())

    def test_symlinked_database_evidence_refused(self):
        database,lock,paths=self.fixture();target=paths['tzdata']/'files';target.unlink();target.symlink_to(lock)
        with self.assertRaisesRegex(ValueError,'ordinary ALPM'):O.check(database,lock,set())


class Archive(Temporary):
    def package(self,extra=None):
        source=self.root/'payload';source.mkdir()
        for name in S.provider_stage.REQUIRED:
            p=source/name;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(image() if name.startswith('usr/lib/') and '/locale/' not in name else b'fixture')
        p=source/'usr/bin/ld.so';p.parent.mkdir(parents=True);p.symlink_to('../lib/ld-linux-aarch64.so.1')
        info='pkgname = '+D.NAME+'\npkgver = '+D.VERSION+'\narch = aarch64\nprovides = glibc=2.43\nconflict = glibc\nbackup = etc/gai.conf\n'+''.join('depend = '+n+'\n' for n in D.DEPENDS)
        build='format = 2\npkgname = '+D.NAME+'\npkgver = '+D.VERSION+'\npkgarch = aarch64\npkgbuild_sha256sum = '+'a'*64+'\n'
        (source/'.PKGINFO').write_text(info);(source/'.BUILDINFO').write_text(build);(source/'.MTREE').write_bytes(b'fixture')
        if extra:
            p=source/extra;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('forbidden fixture')
        archive=self.root/'package.pkg.tar.xz'
        with tarfile.open(archive,'w:xz') as stream:
            for p in sorted(source.rglob('*')):
                entry=stream.gettarinfo(p,arcname=p.relative_to(source).as_posix());entry.uid=entry.gid=0
                if p.is_file() and not p.is_symlink():
                    with p.open('rb') as data:stream.addfile(entry,data)
                else:stream.addfile(entry)
        return archive

    def stage(self,package):
        database,lock,_=Ownership.fixture(self)
        def check(_,expected,payload):return O.check(database,expected,payload)
        with patch.dict(os.environ,{'CACHY_ASAHI_GLIBC_BUILD':'1'}),patch.object(S.os,'uname',return_value=type('U',(),{'machine':'aarch64'})()),patch.object(S.ownership,'check',side_effect=check):
            return S.stage(package,self.root/'stage','a'*64,lock,self.root/'audit.json',self.root/'ownership.json')

    def test_full_synthetic_archive_metadata_audit_and_574_ownership(self):
        result=self.stage(self.package());self.assertEqual(result['stage_root'],str(self.root/'stage/root'))
        self.assertEqual(json.loads((self.root/'audit.json').read_bytes())['dirname_object_bytes'],18)
        self.assertEqual(json.loads((self.root/'ownership.json').read_bytes())['checked_packages'],574)
        self.assertTrue((self.root/'stage/.BUILDINFO').is_file());self.assertFalse((self.root/'stage/root/.BUILDINFO').exists())

    def test_install_scriptlet_rejected_before_extraction(self):
        with self.assertRaisesRegex(ValueError,'outside conventional'):self.stage(self.package('.INSTALL'))
        self.assertFalse((self.root/'stage').exists())

    def test_tzdata_file_cannot_survive_package_audit(self):
        with self.assertRaisesRegex(ValueError,'excluded staged path'):self.stage(self.package('usr/bin/zic'))


class NormalClients(Temporary):
    def test_exact_lifecycle_source_delta_and_bound_patch(self):
        policy=N.policy();change=json.loads((HERE/'normal-exec-change.json').read_bytes())
        before=(ROOT/change['original_source']).read_bytes();self.assertEqual(hashlib.sha256(before).hexdigest(),change['before_sha256'])
        self.assertEqual(before.decode().count(change['replacement_before']),1)
        after=before.decode().replace(change['replacement_before'],change['replacement_after']).encode()
        self.assertEqual(dict(bytes=len(after),sha256=hashlib.sha256(after).hexdigest()),policy['patched_abi_smoke'])
        self.assertEqual(hashlib.sha256(after).hexdigest(),change['after_sha256'])
        for name in ('allocation','dlopen_dlsym','pthread_tls_join','utf8_iconv_locale','numeric_math','fd_stat_clock_random','numeric_address_lookup','fork_exec_wait'):
            self.assertEqual(before.count(name.encode()),after.count(name.encode()),name)

    def fixture(self):
        source=json.loads((ROOT/'scripts/ci/glibc-owned-runtime/source-manifest.json').read_bytes())['files']
        original={n:source[n] for n in N.SOURCES};patched=dict(bytes=1,sha256='d'*64)
        report=dict(status='PASS_COMPILED_NORMAL_INTERPRETER_CLIENTS_NOT_EXECUTED',policy_sha256=N.identity(HERE/'normal-client-policy.json')['sha256'],runtime_manifest_sha256=N.SMOKE,commands=[dict(exit_code=0,group_absence_verified=True) for _ in range(13)],source_patch_command=dict(exit_code=0,group_absence_verified=True),source_patch_tool=dict(bytes=1,sha256='a'*64),original_sources=original,sources=dict(original,**{'abi_smoke.c':patched}),bootstrap_headers={'fixture':{}},toolchain={n:dict(bytes=1,sha256='a'*64) for n in ('gcc','cc1','collect2','as','ld')},compiled_files={})
        report['toolchain']['version']='synthetic';(self.root/'bin').mkdir()
        for name in N.BINARIES:
            interp=None if name=='plugin.so' else '/lib/ld-linux-aarch64.so.1';raw=image(interp);(self.root/'bin'/name).write_bytes(raw)
            report['compiled_files'][name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),artifact='bin/'+name,elf_machine=183,interpreter=interp)
        return report,source,dict(patched_abi_smoke=patched)

    def test_normal_interpreter_compile_receipt_only(self):
        report,source,policy=self.fixture()
        with patch.object(N,'policy',return_value=policy):N.validate(report,self.root,source)

    def test_private_loader_cannot_be_called_normal(self):
        report,source,policy=self.fixture();raw=image('/opt/caa/g243a1/usr/lib/ld-linux-aarch64.so.1');name='smoke-normal';(self.root/'bin'/name).write_bytes(raw)
        report['compiled_files'][name].update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),interpreter='/opt/caa/g243a1/usr/lib/ld-linux-aarch64.so.1')
        with patch.object(N,'policy',return_value=policy),self.assertRaisesRegex(ValueError,'system PT_INTERP'):N.validate(report,self.root,source)

    def test_partial_compile_and_missing_source_identity_refused(self):
        report,source,policy=self.fixture()
        for key,new in (('commands',report['commands'][:-1]),('original_sources',{}),('bootstrap_headers',{})):
            changed=copy.deepcopy(report);changed[key]=new
            with self.subTest(key=key),patch.object(N,'policy',return_value=policy),self.assertRaises(ValueError):N.validate(changed,self.root,source)

    def test_changed_original_driver_cannot_match_manifest(self):
        report,source,policy=self.fixture();report['original_sources']['runner.py']={'bytes':1,'sha256':'c'*64}
        with patch.object(N,'policy',return_value=policy),self.assertRaises(ValueError):N.validate(report,self.root,source)

    def test_native_normal_compiler_never_runs_on_host(self):
        with patch.dict(os.environ,{},clear=True),self.assertRaisesRegex(ValueError,'owned native'):
            N.compile_clients(self.root,self.root/'compile')

    def test_pending_child_source_patch_refused(self):
        value=json.loads((HERE/'normal-client-policy.json').read_bytes());value['status']='PENDING'
        with patch.object(N,'data',return_value=json.dumps(value).encode()),self.assertRaisesRegex(ValueError,'pending exact'):N.policy()

    def test_compile_suite_separate_from_original_and_not_executed(self):
        tree=ast.parse((HERE/'normal_clients.py').read_bytes())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='driver' and n.func.attr=='compile_suite']
        self.assertEqual(len(calls),1);self.assertIsInstance(calls[0].args[-1],ast.Constant);self.assertIsNone(calls[0].args[-1].value)
        text=(HERE/'normal_clients.py').read_text();self.assertNotIn('driver.execute',text);self.assertNotIn('driver.validate_runtime',text)


class Admission(Temporary):
    def fixture(self):
        row=dict(path='private.json',source='a'*40,run=12345,attempt=1)
        runtime=dict(kind='result',status='PASS',cases=8,page_size=16384)
        cases={'allocation','dlopen_dlsym','pthread_tls_join','utf8_iconv_locale','numeric_math','fd_stat_clock_random','numeric_address_lookup','fork_exec_wait'}
        roles=['/opt/caa/g243a1/usr/lib/'+n for n in ('ld-linux-aarch64.so.1','libc.so.6','libm.so.6')]
        records=[dict(kind='test',process='parent',name=n,status='PASS') for n in sorted(cases)]+[dict(kind='test',process='child',name='exec_child',status='PASS'),runtime]
        for process in ('parent','child'):
            paths=roles+(['/work/clients/plugin.so','/opt/caa/g243a1/usr/lib/gconv/ISO8859-1.so','/opt/caa/g243a1/usr/lib/locale/C.utf8/LC_CTYPE'] if process=='parent' else [])
            records.append(dict(kind='identity',process=process,objects=[dict(path=n) for n in paths],mapped_files=[dict(path=n) for n in paths],providers=[dict(symbol=n,path='/opt/caa/g243a1/usr/lib/'+('libm.so.6' if n=='cos' else 'libc.so.6')) for n in ('malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos')]))
        compile=dict(status='COMPILED_ONCE_NOT_EXECUTED',compiled_files={n:{} for n in ('smoke','exec-child','plugin.so')},sources={n:{} for n in ('abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py')},commands=[dict(exit_code=0,group_absence_verified=True) for _ in range(13)])
        guest=dict(status='PASS_PRIVATE_GLIBC_GENERIC16K_RUNTIME',architecture='aarch64',page_size=16384,uid=23001,gid=23001,groups=[],runtime=runtime,runtime_records=records,cases=sorted(cases),commands=compile['commands']+[dict(exit_code=0,group_absence_verified=True)],owned_processes_absent=True,payload_preserved=True,sources_preserved=True,candidate_preserved=True,hardware='NOT_RUN',performance='NOT_MEASURED',installation='NOT_RUN',security='NO_CREDIT',release='NOT_ADMITTED')
        image='sha256:'+'e'*64
        value=dict(status='PASS_PRIVATE_GLIBC_GENERIC16K_AND_ORDERED_CLEANUP',source_commit=row['source'],job_token=hashlib.sha256(('glibc16k:12345:1:'+row['source']).encode()).hexdigest()[:16],pair_source='18569401aa28e2be86f4ada20489913f28739b92',pair_sha256='04e481dc5b3ac711760ca42749044b0be85283b3aa9c9c631cb6738ac7d699fb',natural_VM_exit=True,QEMU_exit=0,kernel_work_removed=True,kernel=dict(kernel_build='PASS'),consumer_cleanup=dict(capture_absent=True,private_removed=True),producer_cleanup=dict(status='PASS',probe=dict(absence_verified=True),image=dict(absence_verified=True,id=image)),image_id=image,actors=[dict(natural_exit=True,exit=0,group_absent=True) for _ in range(2)],capture=dict(compile=compile),guest=guest)
        binding=dict(schema_version=1,status='ROOT_BOUND_ACCEPTED_PRIVATE16K_AND_GNU_INPUT_PACKET',private16k=row,gnu_inputs=dict(ref='b'*40,index_sha256='c'*64,index_bytes=10))
        acceptance=dict(status='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME',run_id=row['run'],source_sha=row['source'],page_size=16384,cases=8,runtime_records=12,commands=14,compile_commands=13,candidate_package_sha256=value['pair_sha256'],actual_parent_child_providers='PASS',source_archive_payload_join='PASS',ordered_cleanup='PASS',hardware='NOT_RUN',installation='NOT_RUN',security='NO_CREDIT',performance='NOT_MEASURED',release='NOT_ADMITTED',limitation='synthetic receipt protocol only')
        path=self.root/'acceptance.json';path.write_text(json.dumps(acceptance));row['root_verification']=dict(path='acceptance.json',bytes=path.stat().st_size,sha256=J.sha(path))
        self.persist(binding,value)
        # Import only the existing strict receipt definitions via a read-only
        # reference; no runtime, Docker or VM actor is invoked.
        target=self.root/'scripts/ci/glibc-generic16k';target.mkdir(parents=True)
        (target/'common.py').write_bytes((ROOT/'scripts/ci/glibc-generic16k/common.py').read_bytes())
        return binding,value

    def persist(self,binding,value):
        path=self.root/'private.json';path.write_text(json.dumps(value));binding['private16k'].update(bytes=path.stat().st_size,sha256=J.sha(path))

    def test_pending_binding_stops_before_receipts_or_actors(self):
        value=json.loads((HERE/'bindings.json').read_bytes());value['status']='PENDING'
        with self.assertRaisesRegex(ValueError,'pending Root'):J.admission(self.root,value)

    def test_complete_synthetic_receipt_protocol(self):
        binding,_=self.fixture();self.assertEqual(J.admission(self.root,binding)['status'],'PASS_BOUND_ROOT_ACCEPTED_PRIVATE16K')

    def test_failed_or_incomplete_vm_and_cleanup_refused(self):
        binding,value=self.fixture()
        for key,new in (('status','FAIL'),('natural_VM_exit',False),('kernel_work_removed',False),('pair_sha256','d'*64)):
            bad=copy.deepcopy(value);bad[key]=new;self.persist(binding,bad)
            with self.subTest(key=key),self.assertRaises(ValueError):J.admission(self.root,binding)

    def test_missing_case_not_rescued_by_final_pass_string(self):
        binding,value=self.fixture();value['guest']['cases'].pop();self.persist(binding,value)
        with self.assertRaises(ValueError):J.admission(self.root,binding)

    def test_packet_cannot_use_mutable_or_unbound_identity(self):
        value=json.loads((HERE/'bindings.json').read_bytes());value['status']='PENDING'
        with self.assertRaisesRegex(ValueError,'pending Root'):J.packet(self.root,value)


class Workflow(unittest.TestCase):
    def test_manual_gate_and_no_new_source_fetcher(self):
        text=(HERE.parents[2]/'.github/workflows/native-arm-glibc-gnu-provider.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('\n  push:',text);self.assertNotIn('\n  schedule:',text)
        self.assertLess(text.index('job.py" proof'),text.index('secrets.CACHY_'))
        self.assertLess(text.index('job.py" packet'),text.index('secrets.CACHY_'))
        self.assertNotIn('/acquire.py',text);self.assertNotIn('curl ',text)
        self.assertIn('steps.proof.outputs.gnu_source_sha',text)
        self.assertIn('--harness-manifest-sha256',text)

    def test_shell_blocks_parse_without_running(self):
        lines=(HERE.parents[2]/'.github/workflows/native-arm-glibc-gnu-provider.yml').read_text().splitlines();i=0;blocks=[]
        while i<len(lines):
            if lines[i]=='        run: |':
                i+=1;body=[]
                while i<len(lines) and (lines[i].startswith('          ') or not lines[i]):body.append(lines[i][10:]);i+=1
                blocks.append('\n'.join(body)+'\n')
            else:i+=1
        self.assertGreater(len(blocks),5)
        for block in blocks:subprocess.run(['bash','-n'],input=block,text=True,check=True,capture_output=True)


if __name__=='__main__':unittest.main()
