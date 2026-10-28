# SPDX-License-Identifier: MIT
"""Inert and data-only controls. No subprocess actors, signing or acceptance output."""
import ast,base64,copy,hashlib,importlib.util,io,json,os,shutil,stat,struct,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'scripts/ci/tools-generic16k/run.py').is_file())
sys.path.insert(0,str(HERE))
import contract as C
import guest
import run

class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('actor forbidden'));self.block.start();self.addCleanup(self.block.stop)
    def test_unbound_before_source_or_actors(self):
        with patch.object(C,'read',return_value=C.encoded(dict(schema_version=1,status='UNBOUND',versions=C.VERSIONS))),self.assertRaisesRegex(ValueError,'UNBOUND'):run.trial(SimpleNamespace())
        self.assertFalse(any(self.root.iterdir()))
    def test_ordinary_guard_refuses_host_before_mutation(self):
        with self.assertRaisesRegex(ValueError,'marked actual'):guest.exercise('a'*32,'fake-kernel')
    def test_duplicate_json_alias_hardlink_and_drift_refuse(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):C.decode(b'{"x":1,"x":2}')
        real=self.root/'one';real.write_bytes(b'x');other=self.root/'two';os.link(real,other)
        with self.assertRaisesRegex(ValueError,'single-link'):C.read(real)
        other.unlink();link=self.root/'alias';link.symlink_to(real)
        with self.assertRaisesRegex(ValueError,'ordinary'):C.read(link)
        pin=dict(path='one',bytes=1,sha256='f'*64)
        with self.assertRaisesRegex(ValueError,'hash differs'):C.checked(self.root,pin)
    def test_source_manifest_closed_pins_replay_and_mutation(self):
        pins=C.decode(C.read(HERE/'source-manifest.json'));stage=self.root/'source';stage.mkdir()
        for name,row in pins['files'].items():
            src=HERE/Path(name).name if name.startswith('scripts/ci/management-tools-generic16k/') else HERE.parents[3]/name if name.startswith('.github/workflows/native-arm-management') else ROOT/name
            if name.startswith('.github/workflows/native-arm-management'):src=HERE.parents[2]/'.github'/Path(name).relative_to('.github')
            dest=stage/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
        shutil.copyfile(HERE/'source-manifest.json',stage/'scripts/ci/management-tools-generic16k/source-manifest.json')
        with patch.object(C,'HERE',stage/'scripts/ci/management-tools-generic16k'):C.verify_source(stage)
        file=stage/'scripts/ci/tools-generic16k/run.py';file.write_bytes(file.read_bytes()+b'\n')
        with patch.object(C,'HERE',stage/'scripts/ci/management-tools-generic16k'),self.assertRaisesRegex(ValueError,'hash differs'):C.verify_source(stage)
    def test_held_supervisor_kernel_elf_and_capture_bounds_remain_reused(self):
        source=(HERE/'run.py').read_text();tree=ast.parse(source)
        self.assertNotIn('def supervise(',source);self.assertNotIn('def kernel(',source);self.assertNotIn('def vm_observation(',source)
        for text in ('base.supervise(','base.vm_observation(','base.kernel(','base.retire(','generic.cpio(','base.s.aligned(',"'900'"):
            if text!="'900'":self.assertIn(text,source)
        self.assertIn("'uart.log',900",source);self.assertIn("'capture.log',240",source);self.assertIn("'compile.log',60",source)
        self.assertIn("'-smp','1','-m','1024'",source);self.assertIn('len(files)<4096',source);self.assertIn('total<=256*1024**2',source)
        self.assertIn('original.command(argv,env,expected,30)',(HERE/'guest.py').read_text())
    def test_fixture_archive_rejects_escape_hardlinks_and_private_members(self):
        for name,kind in (('../escape',tarfile.REGTYPE),('bundle/hard',tarfile.LNKTYPE),('bundle/special',tarfile.FIFOTYPE)):
            buffer=io.BytesIO()
            with tarfile.open(fileobj=buffer,mode='w') as archive:
                member=tarfile.TarInfo(name);member.type=kind;archive.addfile(member)
            target=self.root/str(len(list(self.root.iterdir())))
            with self.assertRaises(ValueError):guest.fixture(buffer.getvalue(),target)
    def test_actual_physical_metadata_fixture_is_fileless_or_exact_paths(self):
        db=self.root/'target/var/lib/pacman';guest.records(db,[dict(name='sample',version='1-1',provides=['virtual=2']),dict(name='other',version='2-1',files=['usr/share/fixture'])])
        self.assertEqual((db/'local/sample-1-1/files').read_bytes(),b'');self.assertEqual((db/'local/ALPM_DB_VERSION').read_bytes(),b'9\n')
        self.assertEqual((db/'local/other-2-1/files').read_text(),'%FILES%\nusr/share/fixture\n\n')
        before=guest.state(db);self.assertEqual(before,guest.state(db));(db/'local/sample-1-1/desc').write_bytes(b'changed');self.assertNotEqual(before,guest.state(db))
    def test_owned_ALPM_lock_observes_metadata_without_read_chmod_or_unlink(self):
        root=self.root/'target';db=root/'var/lib/pacman';db.mkdir(parents=True);lock=db/'db.lck';lock.write_bytes(b'');lock.chmod(0)
        read=Path.read_bytes
        def guarded(path):
            if path==lock:raise AssertionError('never read ALPM lock')
            return read(path)
        try:
            with patch.object(Path,'read_bytes',guarded):result=guest.state(root,lock)
            self.assertEqual(result['var/lib/pacman/db.lck']['sha256'],'NOT_READ_ALPM_LOCK_METADATA_ONLY');self.assertEqual(stat.S_IMODE(lock.stat().st_mode),0)
        finally:lock.chmod(0o600)

    def test_native_cleanup_proof_requires_real_absence(self):
        value=dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP',consumer=dict(status='PASS_CONSUMERS_RETIRED',containers=[dict(status='PASS',absence_verified=True)]),producer=dict(status='PASS',image=dict(absence_verified=True),probe=dict(absence_verified=True)))
        C.cleanup_proof(value);value['producer']['image']['absence_verified']=False
        with self.assertRaises(ValueError):C.cleanup_proof(value)
    def test_missing_unknown_consumer_retirement_blocks_producer(self):
        output=self.root/'public';output.mkdir();self.assertTrue(run.producer_ready(output))
        (output/'runtime.json').write_bytes(C.encoded(dict(status='FAIL')))
        with self.assertRaisesRegex(ValueError,'retirement unknown'):run.producer_ready(output)
        (output/'runtime.json').write_bytes(C.encoded(dict(consumer_cleanup=dict(capture_absent=True,private_removed=True))))
        self.assertTrue(run.producer_ready(output))
    def test_manual_workflow_pending_gate_and_packet_precede_secrets(self):
        path=HERE.parents[2]/'.github/workflows/native-arm-management-tools-generic16k.yml'
        if not path.exists():path=ROOT/'.github/workflows/native-arm-management-tools-generic16k.yml'
        text=path.read_text();self.assertIn('  workflow_dispatch:',text);self.assertNotIn('  push:',text)
        self.assertLess(text.index('binding=C.policy()'),text.index('${{ secrets.'))
        self.assertLess(text.index('Validate actual native pairs decisions'),text.index('${{ secrets.'))
        self.assertIn('producer-ready --output',text);self.assertIn('--packet "$GITHUB_WORKSPACE/retained-management-inputs/payload"',text)
        self.assertIn('test "$(git -C retained-management-inputs rev-parse HEAD)" = "$PACKET_SOURCE"',text)
        self.assertIn('timeout-minutes: 170',text);self.assertIn('contents: read',text)
    def test_guest_installed_prefix_groups_NNP_and_no_host_targets(self):
        source=(HERE/'guest.py').read_text()
        for value in ('os.setgroups([])','prctl(38,1,0,0,0)','os.setuid(23001)',"'/usr/bin/cachy-asahi-apps'", "'/usr/bin/cachy-asahi-cache'", "'/usr/bin/cachy-asahi-orphans'",'shutil.rmtree(work)'):
            self.assertIn(value,source)
        self.assertNotIn('--repository-source',source);self.assertNotIn('remove --',source)
        self.assertEqual(len(run.CASES),19);self.assertEqual(len(set(run.CASES)),19)

class NativeArchiveData(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        actor=patch.object(subprocess,'Popen',side_effect=AssertionError('actor forbidden'));actor.start();self.addCleanup(actor.stop)
        self.checked=C.load('management16k_test_package_checks',ROOT/'scripts/checks/package_checks.py')
    def native(self,name,payload):
        source=self.root/name;source.mkdir();refs={};nodes={}
        def ref(path):return dict(path=path.relative_to(self.root).as_posix(),bytes=path.stat().st_size,sha256=C.sha(path.read_bytes()))
        files={'PKGBUILD':b'# modeled inert recipe\n','LICENSE':b'MIT\n','NOTICE':b'original project\n','.SRCINFO':b'# modeled only\n'}
        for dest,(raw,mode) in payload.items():
            base=Path(dest).name;files[base]=raw;nodes[dest]=dict(source=base,mode=mode)
        version,rel=C.VERSIONS[name].rsplit('-',1)
        fields={'pkgname':[name],'pkgver':[version],'pkgrel':[rel],'arch':['any'],'license':['MIT'],
            'source':[n for n in files if n not in ('PKGBUILD','.SRCINFO')],
            'sha256sums':[C.sha(raw) for n,raw in files.items() if n not in ('PKGBUILD','.SRCINFO')]}
        files['.SRCINFO']=''.join('    '+key+' = '+item+'\n' for key,values in fields.items() for item in values).encode()
        for file,raw in files.items():path=source/file;path.write_bytes(raw);refs[file]=ref(path)
        path=source/(name+'-'+C.VERSIONS[name]+'-any.pkg.tar.xz')
        meta=(f'pkgname = {name}\npkgver = {C.VERSIONS[name]}\narch = any\nlicense = MIT\n').encode()
        build=(f'format = 2\npkgname = {name}\npkgver = {C.VERSIONS[name]}\npkgarch = any\npkgbuild_sha256sum = {refs["PKGBUILD"]["sha256"]}\n').encode()
        with tarfile.open(path,'w:xz') as archive:
            for dest,(raw,mode) in {'.PKGINFO':(meta,0o644),'.BUILDINFO':(build,0o644),'.MTREE':(b'modeled\n',0o644),**payload}.items():
                member=tarfile.TarInfo(dest);member.size=len(raw);member.mode=mode;archive.addfile(member,io.BytesIO(raw))
        second=source/('second-'+path.name);shutil.copyfile(path,second)
        return dict(version=C.VERSIONS[name],files=dict(a=ref(path),b=ref(second)),source_files=refs,payload=nodes)
    def test_exact_real_archive_source_buildinfo_and_unchanged_helpers(self):
        prefix='usr/share/cachy-asahi/repository-runtime/';runtime={prefix+n:(ROOT.joinpath(n).read_bytes(),0o644) for n in C.HELPERS}
        rows={}
        for name in C.VERSIONS:
            if name.endswith('repository-runtime'):data=runtime
            elif name.endswith('apps'):data={'usr/lib/cachy-asahi-apps/helper-pins.json':(C.encoded(dict(files=C.HELPERS)),0o644)}
            else:data={'usr/bin/'+name:(b'#!/usr/bin/python3\n# inert data fixture\n',0o755)}
            rows[name]=self.native(name,data)
        packet=dict(packages=rows);files,origins=C.package_payload(self.root,packet,self.checked)
        self.assertEqual(len(files),6);self.assertEqual(len([n for n in files if n.startswith(prefix)]),3)
        row=rows['cachy-asahi-cache'];row['payload']['usr/bin/cachy-asahi-cache']['mode']=0o644
        with self.assertRaisesRegex(ValueError,'payload differs'):C.package_payload(self.root,packet,self.checked)
    def test_pair_archive_drift_refuses(self):
        row=self.native('cachy-asahi-cache',{'usr/bin/cachy-asahi-cache':(b'fixture\n',0o755)})
        path=self.root/row['files']['b']['path'];path.write_bytes(path.read_bytes()+b'changed')
        with self.assertRaisesRegex(ValueError,'hash differs'):C.package_payload(self.root,dict(packages={'cachy-asahi-cache':row}),self.checked)


    def test_modeled_packet_closure_and_root_decision_joins_refuse_drift(self):
        # Protocol data only, under TemporaryDirectory. No actual acceptance is
        # generated or retained; policy() is mocked, the shipped policy UNBOUND.
        prefix='usr/share/cachy-asahi/repository-runtime/';packages={}
        for name in C.VERSIONS:
            data={prefix+n:(ROOT.joinpath(n).read_bytes(),0o644) for n in C.HELPERS} if name.endswith('repository-runtime') else {
                'usr/lib/cachy-asahi-apps/helper-pins.json':(C.encoded(dict(files=C.HELPERS)),0o644)} if name.endswith('apps') else {
                'usr/bin/'+name:(b'# inert protocol data\n',0o755)}
            packages[name]=self.native(name,data)
        def ref(name,value):
            path=self.root/name;path.write_bytes(C.encoded(value));return dict(path=name,bytes=path.stat().st_size,sha256=C.sha(path.read_bytes()))
        cleanup=dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP',consumer=dict(status='PASS_CONSUMERS_RETIRED',containers=[dict(status='PASS',absence_verified=True)]),
            producer=dict(status='PASS',image=dict(absence_verified=True),probe=dict(absence_verified=True)))
        for number,(name,row) in enumerate(packages.items()):
            row.update(native_source='a'*40,native_run='42',qualification='NATIVE_PAIR_AND_DISPOSABLE_LIFECYCLE',check_markers=['MODELED CHECK OK'])
            row['comparison']=ref(str(number)+'-comparison.json',dict(status='contents-reproduced',errors=[],packages={name:{k:True for k in ('bytes_equal','pkginfo_equal','buildinfo_equal','installed_contents_equal')}}))
            row['collection']=ref(str(number)+'-collection.json',dict(modeled=True));row['cleanup']=ref(str(number)+'-cleanup.json',cleanup)
            logs=self.root/(str(number)+'-checks.log');logs.write_text('Starting check()\nMODELED CHECK OK\n');log=dict(path=logs.name,bytes=logs.stat().st_size,sha256=C.sha(logs.read_bytes()));other=self.root/(str(number)+'-checks-b.log');other.write_bytes(logs.read_bytes());row['checks']=dict(a=log,b=dict(path=other.name,bytes=other.stat().st_size,sha256=C.sha(other.read_bytes())))
        joint=dict(status='ROOT_ACCEPTED_APPS_RUNTIME_CACHE_NATIVE_PAIRS_AND_INSTALLED_LIFECYCLE',run_id=42,source_sha='a'*40,distinct_native_builds=6,cleanup='PASS',hardware='NOT_RUN',
            products={n:dict(version=r['version'],archive_bytes=r['files']['a']['bytes'],archive_sha256=r['files']['a']['sha256'],comparison=C.decode(C.checked(self.root,r['comparison']))) for n,r in packages.items() if n!='cachy-asahi-orphans'},
            lifecycle=dict(status='PASS_APPS_CACHE_INSTALLED_LIFECYCLE',base_count=574,installed_count=577,base574_preserved=True,user_preserved=True,plans_applied='NOT_APPLIED',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION'))
        original=ref('MODELED-joint-decision.json',joint)
        for name,row in packages.items():
            if name!='cachy-asahi-orphans':row['decision']=original
            else:row['decision']=ref('MODELED-orphans-decision.json',dict(status='ROOT_ACCEPTED_ORPHANS_NATIVE_PAIR_AND_READONLY_LIFECYCLE',version=row['version'],source_sha='a'*40,run_id=42,
                archive_sha256=row['files']['a']['sha256'],archive_bytes=row['files']['a']['bytes'],comparison=C.decode(C.checked(self.root,row['comparison'])),cleanup='PASS',native_checks_per_build=18,hardware='NOT_RUN',
                lifecycle=dict(status='PASS_ORPHANS_INSTALLED_READONLY_LIFECYCLE',base574_preserved=True,user_preserved=True)))
        value=dict(schema_version=1,kind='ROOT_ACCEPTED_MANAGEMENT16K_NATIVE_INPUTS',assembly_kind='FOUR_ROOT_ACCEPTED_NATIVE_PAIRS_FOR_PRIVATE16K_DATA_STAGE',packages=packages)
        index=ref('index.json',value);policy=dict(packet_source='b'*40,packet_index=index)
        with patch.object(C,'policy',return_value=policy):self.assertEqual(C.packet(self.root),value)
        # Index bytes cannot name their future carrier commit. Only Root policy binds it.
        self.assertNotIn('source',value);policy['packet_source']='c'*40
        with patch.object(C,'policy',return_value=policy):self.assertEqual(C.packet(self.root),value)
        extra=self.root/'extra';extra.write_bytes(b'unreferenced')
        with patch.object(C,'policy',return_value=policy),self.assertRaisesRegex(ValueError,'closure'):C.packet(self.root)
        extra.unlink();changed=copy.deepcopy(value);changed['packages']['cachy-asahi-cache']['native_source']='c'*40
        index=ref('index.json',changed);policy['packet_index']=index
        with patch.object(C,'policy',return_value=policy),self.assertRaisesRegex(ValueError,'decision identity'):C.packet(self.root)

class ReportAndELF(unittest.TestCase):
    def setUp(self):
        actor=patch.object(subprocess,'Popen',side_effect=AssertionError('actor forbidden'));actor.start();self.addCleanup(actor.stop)
    def report(self):
        nonce='a'*32;release='fixture-kernel';receipt=dict(source_commit='a'*40,fixture_archive_sha256='f'*64,fixture_authority=dict(signer='A'*40))
        seed=run.startup_seed('a'*40,'b'*16,nonce,receipt)
        clock=dict(status='SET_VM_REALTIME_FROM_OBSERVED_RUNNER_UTC',seed=seed,seed_sha256=C.sha(C.encoded(seed)),before=dict(realtime_ns=0,monotonic_ns=1),after=dict(realtime_ns=seed['host_realtime_ns'],monotonic_ns=2),uid=0,authority='RECORDED_STARTUP_ANCHOR_NOT_CONTINUOUS_UTC_SYNCHRONIZATION')
        rows=[]
        for name in run.CASES:
            tool='apps' if name.startswith('apps-') else 'cache' if name.startswith('cache-') else 'orphans'
            raw=C.encoded(dict(status='INERT_PROTOCOL_TEST_ONLY'))
            command=dict(case=name,argv=['/usr/bin/cachy-asahi-'+tool],exit=1 if name=='cache-concurrent-refusal' or name.startswith('orphans-refuse-') else 0,
                stdout_bytes=len(raw),stdout_sha256=C.sha(raw),stderr_bytes=0,stderr_sha256=C.sha(b''),seconds=.1,group_absent=True,owned_processes_absent=True)
            rows.append(dict(case=name,command=command,stdout_base64=base64.b64encode(raw).decode()))
        result=dict(clock_setup=clock,status=C.STATUS,nonce=nonce,kernel=release,architecture='aarch64',page_size=16384,uid=23001,gid=23001,groups=[],NNP=True,capabilities_zero=True,
            package_registration=C.SCOPE,payload_manifest_sha256=C.sha(C.encoded(receipt)),fixture_archive_sha256='f'*64,GUI='NOT_RUN',hardware='NOT_RUN',release_admission=False,
            payload_preserved=True,user_config_preserved=True,owned_processes_absent=True,private_fixtures_removed=True,commands=[r['command'] for r in rows],results=dict(
                apps=dict(default_prefix=True,repository_override=False,Git_checkout=False,signer='A'*40,observed_plans=[dict(operation=n,not_applied=True,db_preserved=True,inventory=dict(observation=dict(payload_verified=False,hardware_verified=False)),inventory_sha256=C.sha(C.encoded(dict(observation=dict(payload_verified=False,hardware_verified=False))))) for n in ('install','remove')]),
                cache=dict(real_ALPM_version='16.fixture',concurrent_refusal=True,protected_unselected_database_preserved=True,lock_released=True,removed_objects=['selected-1-1-any.pkg.tar.xz','selected-1-1-any.pkg.tar.xz.sig'],disk_space='NOT_MEASURED',journal=dict(phase='APPLIED',lock_release='OWN_LOCK_RELEASED',alpm=dict(version='16.fixture'))),
                orphans=dict(libalpm='16.fixture',required_provided_optional_protected=True,not_applied=True,database_preserved=True,explicit_selected=['sample-leaf','sample-oldprovider'],assessment=dict(scope='LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF',apply_supported=False),plan=dict(status='NOT_APPLIED',apply_supported=False))))
        def uart(result,rows):return (f'UNAME16K aarch64 {release}\nGETCONF16K 16384\nSMOKE16K: mmap,mprotect,file-offset PASS\n'+''.join('MANAGEMENT16K_COMMAND '+nonce+' '+json.dumps(row)+'\n' for row in rows)+'MANAGEMENT16K_REPORT '+json.dumps(result)+'\nTOOLS16K PASS '+nonce+'\n').encode()
        return nonce,release,receipt,result,rows,uart
    def test_protocol_requires_exact_page_all_cases_raw_hashes_cleanup_and_scope(self):
        nonce,release,receipt,result,rows,uart=self.report();run.guest_report(uart(result,rows),0,nonce,release,receipt)
        for key,value in [('page_size',4096),('NNP',False),('private_fixtures_removed',False),('package_registration','ALPM_INSTALLED'),('hardware','PASS')]:
            changed=copy.deepcopy(result);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):run.guest_report(uart(changed,rows),0,nonce,release,receipt)
        for changed in (rows[:-1],[*rows,rows[-1]],list(reversed(rows))):
            with self.assertRaises(ValueError):run.guest_report(uart(result,changed),0,nonce,release,receipt)
        changed=copy.deepcopy(rows);changed[0]['stdout_base64']=base64.b64encode(b'corruption').decode()
        with self.assertRaises(ValueError):run.guest_report(uart(result,changed),0,nonce,release,receipt)
        with self.assertRaises(ValueError):run.guest_report(uart(result,rows).replace(b'GETCONF16K 16384',b'GETCONF16K 4096'),0,nonce,release,receipt)
    def test_complete_elf_parser_rejects4k_alignment_and_foreign_architecture(self):
        helper=C.load('management16k_elf_parser',ROOT/'scripts/virtual/generic16k/fixture.py')
        support=C.load('management16k_elf_support',ROOT/'scripts/ci/tools-generic16k/support.py')
        raw=bytearray(512);raw[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HHI',raw,16,3,183,1);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1)
        struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,len(raw),len(raw),16384);support.aligned(bytes(raw),helper)
        struct.pack_into('<Q',raw,112,4096)
        with self.assertRaisesRegex(ValueError,'16K aligned'):support.aligned(bytes(raw),helper)
        struct.pack_into('<Q',raw,112,16384);struct.pack_into('<H',raw,18,62)
        with self.assertRaises(ValueError):support.aligned(bytes(raw),helper)
    def test_capture_mounts_packet_readonly_and_preserves_original_isolation(self):
        support=SimpleNamespace(HERE=ROOT/'scripts/ci/tools-generic16k')
        base=SimpleNamespace(s=support)
        actual=C.load('management16k_capture_command_base',ROOT/'scripts/ci/tools-generic16k/run.py')
        base.capture_command=actual.capture_command
        args=SimpleNamespace(source_commit='a'*40,private=Path('/tmp/private'),job_token='a'*16,source_root=ROOT,base_dir=Path('/tmp/base'),packet=Path('/tmp/packet'))
        argv=run.capture_command(args,base,'sha256:'+'b'*64,'owned',Path('/tmp/out'))
        self.assertIn('type=bind,src=/tmp/packet,dst=/inputs,readonly',argv);self.assertIn('--network=none',argv);self.assertIn('--read-only',argv)
        self.assertIn('--cap-drop=ALL',argv);self.assertIn('--security-opt=no-new-privileges',argv);self.assertIn('--pids-limit=128',argv);self.assertIn('--memory=2g',argv)
        self.assertNotIn('--privileged',argv)

if __name__=='__main__':unittest.main()
