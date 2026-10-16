# SPDX-License-Identifier: MIT
"""Inert data/ownership controls; no package, compiler, Docker, QEMU or GUI actor."""
import ast
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import runpy
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import capture
import recorder_adapter
import guest
import run
import support as s

ROOT=Path(os.environ.get('DONE16K_SOURCE_ROOT',str(Path(__file__).resolve().parents[3])))


def elf(align=16384,needed=False):
    raw=bytearray(512);raw[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HHI',raw,16,3,183,1)
    struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,2 if needed else 1)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,len(raw),len(raw),align)
    if needed:
        struct.pack_into('<IIQQQQQQ',raw,120,2,4,256,0x400100,0,48,48,8)
        struct.pack_into('<QQQQQQ',raw,256,1,1,5,0x400140,0,0);raw[320:337]=b'\0libmissing.so.0\0\0'
    return bytes(raw)


def transport_fixture(files):
    row=dict(argv=s.COMPILE,exit=0,expected_exit=0,natural_exit=True,group_absent=True,pid=12345,pgid=12345,
        seconds=.1,stdout_bytes=0,stderr_bytes=0,stdout_sha256=s.sha(b''),stderr_sha256=s.sha(b''))
    build=dict(status='BUILT_NATIVE_C_TEST_RECORDER',compile_count=1,architecture='aarch64',source_commit='c'*40,
        source_sha256=files[s.SOURCE]['sha256'],binary_sha256=files[s.RECORDER]['sha256'],deadline_seconds=30,output_cap=131072,
        command=row,compiler=dict(path='/usr/bin/cc',resolved='/usr/bin/gcc',bytes=3,sha256=s.sha(b'gcc')))
    return dict(kind='NATIVE_C_RECORDER_PREPARE_ONLY',product_change='NONE',original_fixture_execution='NOT_RUN_UNCHANGED_CAPTURED_ONLY',
        original_case_bodies=18,transport_timeout='UNCHANGED_2S_TERM_1S_KILL',adaptation='ONLY_PREPARE_RECORDER_SUBSTITUTED',
        original_fixture_sha256=files['fixtures/done.py']['sha256'],adapted_fixture_sha256=files[s.ADAPTED]['sha256'],
        recorder_source_sha256=files[s.SOURCE]['sha256'],adapter_sha256=files[s.ADAPTER]['sha256'],
        recorder_binary_sha256=files[s.RECORDER]['sha256'],native_build=build)


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('actor execution forbidden'))
        blocked.start();self.addCleanup(blocked.stop);self.generic=s.load(ROOT,'scripts/virtual/generic16k/fixture.py')

    def test_exact_source_only_map_and_entry(self):
        s.check_source(ROOT);mapping=s.mapping()
        self.assertEqual(len(mapping['products']),1);self.assertEqual(len(mapping['fixtures']),3)
        self.assertEqual(sum(len(r['payload']) for r in mapping['products'].values()),8)
        value=run.trial(SimpleNamespace(source_root=ROOT,execute=False))
        self.assertEqual(value['status'],'SOURCE_INPUTS_VERIFIED_NOT_EXECUTED');self.assertEqual(len(value['products']),1)

    def test_changed_source_is_refused_before_import(self):
        (self.root/'one.py').write_bytes(b'wrong')
        with patch.object(s,'pins',return_value=dict(files={'one.py':dict(bytes=5,sha256=s.sha(b'fixed'))})):
            with self.assertRaises(ValueError):s.load(self.root,'one.py')

    def test_isolated_python_capture_help_resolves_own_support_without_actors(self):
        with patch.object(sys,'argv',['capture.py','--help']),patch.object(sys,'path',[p for p in sys.path if p!=str(s.HERE)]),contextlib.redirect_stdout(io.StringIO()):
            saved=sys.modules.pop('support',None)
            try:
                with self.assertRaises(SystemExit) as error:runpy.run_path(str(s.HERE/'capture.py'),run_name='__main__')
                self.assertEqual(error.exception.code,0)
            finally:
                if saved is not None:sys.modules['support']=saved

    def test_host_and_unmarked_guest_refuse_before_mutation(self):
        with patch.object(guest.os,'geteuid',return_value=0),patch.object(guest.os,'uname',return_value=SimpleNamespace(machine='aarch64',release='test')),patch.object(guest.os,'sysconf',return_value=4096):
            with self.assertRaises(ValueError):guest.exercise('a'*32,'test')
        with patch.object(capture.platform,'machine',return_value='x86_64'):
            with self.assertRaises(ValueError):capture.guard()

    def test_readonly_bind_override_cannot_be_hidden_by_root_mount(self):
        mounts='1 0 0:0 / / ro - overlay overlay ro\n2 1 0:1 / /repo rw - ext4 disk rw\n'
        self.assertTrue(capture.readonly('/source',mounts));self.assertFalse(capture.readonly('/repo/file',mounts))

    def test_structural_16k_gate_rejects_4k_even_with_arm64_header(self):
        self.assertEqual(s.aligned(elf(),self.generic),(None,[]))
        with self.assertRaises(ValueError):s.aligned(elf(4096),self.generic)

    def payload_fixture(self,missing_library=False):
        names=['usr/bin/'+n for n in s.TOOLS]
        data={n:elf(needed=missing_library and n.endswith('/fish')) for n in names}
        data['guest.py']=b'# inert\n'
        mapped={**{n:r for product in s.mapping()['products'].values() for n,r in product['payload'].items()},**s.mapping()['fixtures']}
        data.update({n:(ROOT/r['source']).read_bytes() for n,r in mapped.items()})
        data[s.RECORDER]=elf();data[s.ADAPTED]=recorder_adapter.adapt(data['fixtures/done.py'])
        archive=self.root/'payload.tar';files={};elfs={}
        with tarfile.open(archive,'w') as stream:
            for name,raw in data.items():
                mode=mapped[name]['mode'] if name in mapped else 0o644 if name==s.ADAPTED else 0o755
                entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=mode;stream.addfile(entry,io.BytesIO(raw))
                files[name]=dict(bytes=len(raw),mode=mode,sha256=s.sha(raw))
                if raw.startswith(b'\x7fELF'):
                    interpreter,needed=s.aligned(raw,self.generic);elfs[name]=dict(interpreter=interpreter,needed=needed)
        receipt=dict(status='CAPTURED_UNPACKED_NATIVE574_PAYLOAD',inventory_sha256=s.LOCK,payload_map_sha256=s.MAP_SHA,
            files=files,elf=elfs,products=s.mapping()['products'],archive=dict(bytes=archive.stat().st_size,sha256=s.sha(archive.read_bytes())))
        receipt.update(source_commit='c'*40,test_transport=transport_fixture(files))
        return archive,receipt

    def test_closed_payload_and_manifest_hashes_are_required(self):
        archive,receipt=self.payload_fixture();self.assertEqual(len(run.payload(archive,receipt,self.generic)),28)
        for field in ('inventory_sha256','payload_map_sha256'):
            bad=copy.deepcopy(receipt);bad[field]='0'*64
            with self.assertRaises(ValueError):run.payload(archive,bad,self.generic)
        archive.write_bytes(archive.read_bytes()+b'changed')
        with self.assertRaises(ValueError):run.payload(archive,receipt,self.generic)

    def test_missing_dt_needed_library_refuses_before_vm(self):
        archive,receipt=self.payload_fixture(True)
        with self.assertRaisesRegex(ValueError,'DT_NEEDED closure absent'):run.payload(archive,receipt,self.generic)

    def test_payload_alias_escape_and_extra_elf_metadata_refuse(self):
        archive,receipt=self.payload_fixture();bad=copy.deepcopy(receipt);bad['elf']['foreign']=dict(interpreter=None,needed=[])
        with self.assertRaises(ValueError):run.payload(archive,bad,self.generic)
        for name,kind in (('../outside',tarfile.REGTYPE),('usr/bin/bash',tarfile.SYMTYPE)):
            with tarfile.open(archive,'w') as stream:
                entry=tarfile.TarInfo(name);entry.type=kind;entry.linkname='/etc/passwd';stream.addfile(entry)
            receipt['archive']=dict(bytes=archive.stat().st_size,sha256=s.sha(archive.read_bytes()))
            with self.assertRaises(ValueError):run.payload(archive,receipt,self.generic)

    def test_capture_command_has_scoped_guards_and_no_install(self):
        args=SimpleNamespace(private=self.root,source_root=ROOT,source_commit='a'*40,base_dir=self.root/'base',job_token='a'*16)
        argv=run.capture_command(args,'sha256:'+'b'*64,'done16k-capture-'+'a'*16,self.root/'capture')
        for flag in ('--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pull=never','--cidfile'):
            self.assertIn(flag,argv)
        self.assertIn('CACHY_DONE16K_CAPTURE=1',argv);self.assertIn('/source/capture.py',argv)
        self.assertNotIn('pacman -U',' '.join(argv));self.assertNotIn('--privileged',argv)

    def report_fixture(self):
        nonce='a'*32;release='test-generic16k';receipt=dict(files={n:r for p in s.mapping()['products'].values() for n,r in p['payload'].items()})
        names=['noninteractive','foreground','background','watch-rejection','disown','repeat-preserve','command-data','transport-failure',
               'transport-timeout','disable','existing-function','existing-autoload','existing-variable','existing-wrapper','existing-public',
               'no-bus','notify-send','timeout']
        for name,row in s.mapping()['fixtures'].items():receipt['files'][name]=dict(bytes=row['bytes'],mode=row['mode'],sha256=row['sha256'])
        adapted=recorder_adapter.adapt((ROOT/'packages/tools/cachy-asahi-fish-done/check-module.py').read_bytes())
        receipt['files'][s.ADAPTED]=dict(bytes=len(adapted),mode=0o644,sha256=s.sha(adapted))
        receipt['files'][s.RECORDER]=dict(bytes=len(elf()),mode=0o755,sha256=s.sha(elf()))
        receipt.update(source_commit='c'*40,elf={s.RECORDER:dict(interpreter=None,needed=[])})
        receipt['test_transport']=transport_fixture(receipt['files'])
        enabled=set(names[1:10]);cases={n:dict(exit=0,notifications=0,**(dict(activation='enabled' if n in enabled else 'yielded',proofs=[]) if n!='noninteractive' else {})) for n in names}
        def invocation(failed=False,kind='Foreground command',status=7,private=True):
            return dict(argv=['--hint=int:transient:1','--urgency='+('critical' if failed else 'normal'),
                '--icon=utilities-terminal','--app-name=fish','--expire-time=3000','--',
                'Failed ('+str(status)+') after 0s' if failed else 'Done in 0s',
                kind+' completed.' if private else 'sleep .12 # &lt;tag&gt; $HOME $(touch PWNED) --leading'])
        cases['foreground']['proofs']=[invocation(),invocation(True)]
        cases['background']['proofs']=[invocation(kind='Watched job'),invocation(True,'Watched job'),invocation(True,'Watched job',143)]
        cases['command-data']['proofs']=[invocation(private=False)]
        for n in ('transport-failure','transport-timeout'):cases[n]['proofs']=[dict(elapsed_seconds=.2,invocation=invocation())]
        cases['repeat-preserve']['notifications']=1
        proof=dict(status='PASS',machine='aarch64',fish='fish, version 4.9.3',cases=cases,
            scope='local notify-send process shim invocation only; no actual notification manager or visual display',
            wrapper_sha256=receipt['files']['usr/share/cachy-asahi/fish-done/opt-in.fish']['sha256'],
            runtime_sha256=receipt['files']['usr/share/cachy-asahi/fish-done/done.fish']['sha256'])
        command=dict(argv=['/usr/bin/python3','-I','-B','/fixtures/done-native.py','--source','/usr/share/cachy-asahi/fish-done','--output','/tmp/done16k/cases'],
            exit=0,group_absent=True,owned_processes_absent=True,seconds=.1,stdout_bytes=1,stderr_bytes=0,stdout_sha256='b'*64,stderr_sha256=s.sha(b''))
        value=dict(status=s.STATUS,nonce=nonce,architecture='aarch64',page_size=16384,kernel=release,
            uid=23001,commands=[command],done=proof,done_receipt_sha256='d'*64,case_inputs_preserved=dict.fromkeys(names,True),
            config_preserved=True,payload_preserved=True,owned_processes_absent=True,notification_transport=s.TRANSPORT,
            notification_manager='NOT_RUN',DBus='NOT_RUN',display='NOT_RUN',package_registration='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY',
            GUI='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',release_admission=False,
            payload_manifest_sha256=s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()))
        value['test_transport']=receipt['test_transport']
        value['native_recorder_cases']={n:dict(recorder_present=n!='notify-send',recorder_sha256=receipt['files'][s.RECORDER]['sha256'] if n!='notify-send' else None,
            notification_count=cases[n]['notifications'],fixture_notification_delta=cases[n]['notifications'],
            recorded_pids=list(range(200,200+cases[n]['notifications'])),notifications_sha256=s.sha(b'')) for n in names}
        return value,receipt,nonce,release

    def output(self,value,nonce,release):
        return (f'UNAME16K aarch64 {release}\nGETCONF16K 16384\nSMOKE16K: mmap,mprotect,file-offset PASS\nDONE16K_REPORT '+
                json.dumps(value)+f'\nDONE16K PASS {nonce}\n').encode()

    def test_actual_guest_markers_behavior_identity_and_natural_exit_required(self):
        value,receipt,nonce,release=self.report_fixture();raw=self.output(value,nonce,release)
        self.assertEqual(run.guest_report(raw,0,nonce,release,receipt)['page_size'],16384)
        for wrong,code in ((raw,-9),(raw+b'Kernel panic - not syncing\n',0),(raw+f'DONE16K PASS {nonce}\n'.encode(),0),(raw.replace(b'GETCONF16K 16384',b'GETCONF16K 4096'),0)):
            with self.assertRaises(ValueError):run.guest_report(wrong,code,nonce,release,receipt)

    def test_guest_cannot_claim_gui_hardware_or_omit_preservation_and_commands(self):
        value,receipt,nonce,release=self.report_fixture()
        for field,wrong in (('GUI','PASS'),('hardware','PASS'),('release_admission',True),('config_preserved',False),
                            ('owned_processes_absent',False),('uid',0),('page_size',4096)):
            bad=copy.deepcopy(value);bad[field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)
        for mutate in ('command','privacy','payload','status','case','scope','transport'):
            bad=copy.deepcopy(value)
            if mutate=='command':bad['commands'][0]['exit']=1
            elif mutate=='privacy':bad['done']['cases']['foreground']['proofs'][0]['argv'][7]='private command leaked'
            elif mutate=='payload':bad['payload_manifest_sha256']='c'*64
            elif mutate=='status':bad['done']['cases']['foreground']['proofs'][1]['argv'][6]='Failed (9) after 0s'
            elif mutate=='case':bad['done']['cases'].pop('no-bus')
            elif mutate=='transport':bad['done']['cases']['transport-timeout']['proofs'][0]['elapsed_seconds']=4.5
            else:bad['notification_manager']='PASS'
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)

    def final_fixture(self):
        base=self.root/'base';base.mkdir();out=self.root/'public';out.mkdir();work=self.root/'done16k-kernel';work.mkdir()
        image='sha256:'+'b'*64;token='a'*16
        report=dict(status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT',job_token=token,image_id=image,natural_VM_exit=True,QEMU_exit=0,
            actors=[dict(natural_exit=True,exit=0,group_absent=True)]*3,consumer_cleanup=dict(capture_absent=True,private_removed=True,producer='BORROWED_PRESERVED'),
            kernel=dict(status='BUILT_ONLY',kernel_build='PASS',helper=dict(path=str(work/'helper/build_kernel.py'))))
        guest_value,capture_value,_,_=self.report_fixture();report.update(guest=guest_value,capture=capture_value)
        owner=dict(ownership=dict(token=token),owned_cleanup=dict(status='PASS',probe=dict(absence_verified=True),image=dict(id=image,absence_verified=True)))
        s.save(out/'runtime.json',report);s.save(base/'report.json',owner)
        return SimpleNamespace(base_dir=base,output=out,kernel_work=work,job_token=token),report,owner

    def test_final_pass_waits_for_owned_producer_and_kernel_work_retirement(self):
        args,report,owner=self.final_fixture()
        with patch.dict(os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],s.STATUS);self.assertFalse(args.kernel_work.exists())

    def test_unproved_producer_or_wrong_kernel_path_cannot_be_removed_or_pass(self):
        args,report,owner=self.final_fixture();owner['owned_cleanup']['image']['absence_verified']=False;s.save(args.base_dir/'report.json',owner)
        with patch.dict(os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(args.kernel_work.exists())

    def test_foreign_capture_owner_never_signalled_or_removed(self):
        private=self.root/'private';private.mkdir();(private/'capture.cid').write_text('b'*64)
        args=SimpleNamespace(private=private,job_token='a'*16)
        foreign=[dict(Id='b'*64,Name='/done16k-capture-'+'a'*16,Image='sha256:'+'c'*64,Config=dict(Labels={}))]
        with patch.object(run,'query',side_effect=['done16k-capture-'+'a'*16,json.dumps(foreign)]) as query:
            with self.assertRaises(ValueError):run.retire(args,'done16k-capture-'+'a'*16,'sha256:'+'c'*64,True)
        self.assertEqual(query.call_count,2);self.assertTrue(private.exists())

    def fake_process(self):
        pipes=[]
        for raw in (b'bounded',b''):
            read,write=os.pipe();os.write(write,raw);os.close(write);pipes.append(os.fdopen(read,'rb'))
        return SimpleNamespace(pid=23456,stdout=pipes[0],stderr=pipes[1],wait=lambda timeout:0)

    def test_guest_command_records_natural_exit_and_group_absence(self):
        process=self.fake_process()
        def signal(pid,sig):
            if sig==0:raise ProcessLookupError()
        with patch.object(guest.subprocess,'Popen',return_value=process),patch.object(guest.os,'waitid',return_value=object()),patch.object(guest.os,'killpg',side_effect=signal):
            row,out=guest.command(['inert'],{})
        self.assertEqual(out,b'bounded');self.assertEqual(row['exit'],0);self.assertTrue(row['group_absent'])

    def test_guest_command_deadline_retires_without_candidate_actor(self):
        process=self.fake_process()
        with patch.object(guest.subprocess,'Popen',return_value=process),patch.object(guest.time,'monotonic',side_effect=[0,31]),patch.object(guest.os,'killpg') as kill:
            with self.assertRaisesRegex(ValueError,'guest command deadline'):guest.command(['inert'],{})
        self.assertEqual([call.args[1] for call in kill.call_args_list],[guest.signal.SIGTERM,guest.signal.SIGKILL])

    def test_guest_snapshot_refuses_symlink_and_tracks_configuration_bytes(self):
        (self.root/'sentinel').write_bytes(b'original');before=guest.snapshot(self.root)
        (self.root/'sentinel').write_bytes(b'changed');self.assertNotEqual(guest.snapshot(self.root),before)
        (self.root/'alias').symlink_to('sentinel')
        with self.assertRaises(ValueError):guest.snapshot(self.root)

    def test_map_source_drift_refuses_even_if_paths_are_regular(self):
        mapping=s.mapping();bad=copy.deepcopy(mapping)
        first=next(iter(bad['products'].values()));next(iter(first['payload'].values()))['sha256']='0'*64
        with patch.object(s,'mapping',return_value=bad):
            with self.assertRaisesRegex(ValueError,'mapped source payload differs'):s.products(ROOT)

    def test_actual_mapped_capture_bytes_cannot_be_substituted_with_forged_receipt(self):
        archive,receipt=self.payload_fixture();members=[]
        with tarfile.open(archive,'r:') as stream:
            for entry in stream:
                data=stream.extractfile(entry).read()
                if entry.name=='usr/share/cachy-asahi/fish-done/done.fish':
                    data=b'# substituted source';entry.size=len(data)
                    receipt['files'][entry.name].update(bytes=len(data),sha256=s.sha(data))
                members.append((entry,data))
        with tarfile.open(archive,'w') as stream:
            for entry,data in members:stream.addfile(entry,io.BytesIO(data))
        receipt['archive'].update(bytes=archive.stat().st_size,sha256=s.sha(archive.read_bytes()))
        with self.assertRaisesRegex(ValueError,'actual captured bytes differ'):run.payload(archive,receipt,self.generic)

    def test_derived_kernel_profile_is_narrow_and_accepted_fragment_unchanged(self):
        old=ast.parse((ROOT/'scripts/virtual/generic16k/build_kernel.py').read_text());new=ast.parse((ROOT/'scripts/ci/tools-generic16k/build_kernel.py').read_text())
        def functions(tree):return {n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,ast.FunctionDef)}
        before,after=functions(old),functions(new)
        self.assertEqual(set(before),set(after))
        self.assertEqual({k for k in before if before[k]!=after[k]},{'main','usage','run'})
        self.assertTrue(all(before[k]==after[k] for k in before if k not in ('main','usage','run')))
        self.assertEqual((ROOT/'scripts/ci/tools-generic16k/kernel.fragment').read_bytes(),(ROOT/'scripts/virtual/generic16k/kernel.fragment').read_bytes())
        helper=s.load(ROOT,'scripts/ci/tools-generic16k/build_kernel.py')
        self.assertEqual(helper.DIAGNOSTIC_FRAGMENT,'CONFIG_KALLSYMS=y\nCONFIG_PRINTK_TIME=y\nCONFIG_UNIX98_PTYS=y\nCONFIG_EVENTFD=y\nCONFIG_FILE_LOCKING=y\n')

    def kernel_fixture(self):
        helper=s.load(ROOT,'scripts/ci/tools-generic16k/build_kernel.py');config=self.root/'config';image=self.root/'Image'
        base=(ROOT/'scripts/ci/tools-generic16k/kernel.fragment').read_bytes();config.write_bytes(base+helper.DIAGNOSTIC_FRAGMENT.encode())
        raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);image.write_bytes(raw)
        return dict(profile='TOOLS16K_PTY_DERIVED_DIAGNOSTIC',derivation=dict(base_helper_sha256=s.pins()['files']['scripts/virtual/generic16k/build_kernel.py']['sha256'],
            diagnostic_extension='CONFIG_UNIX98_PTYS=y;CONFIG_EVENTFD=y;CONFIG_FILE_LOCKING=y',
               workspace_scan='ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',accepted_profile_modified=False),status='BUILT_ONLY',kernel_build='PASS',boot_diagnostics=True,
            image_check=dict(header_page_size=16384),module_policy=dict(CONFIG_MODULES='n'),archive=dict(sha256='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'),
            source_commit='94fb23346d522edf53722357c426a3e58030beea',helper=dict(sha256=s.sha((ROOT/'scripts/ci/tools-generic16k/build_kernel.py').read_bytes())),
            fragment=dict(sha256=s.sha(base)),diagnostic_fragment=dict(sha256=s.sha(base+helper.DIAGNOSTIC_FRAGMENT.encode())),
            image=dict(path=str(image),bytes=64,sha256=s.sha(raw)),config=dict(path=str(config),sha256=s.sha(config.read_bytes())))

    def test_kernel_receipt_requires_separate_profile_and_actual_pty_config(self):
        receipt=self.kernel_fixture();self.assertEqual(run.kernel(receipt,ROOT),self.root/'Image')
        bad=copy.deepcopy(receipt);bad['derivation']['accepted_profile_modified']=True
        with self.assertRaises(ValueError):run.kernel(bad,ROOT)
        config=self.root/'config';original=config.read_text()
        for key in ('CONFIG_UNIX98_PTYS','CONFIG_EVENTFD','CONFIG_FILE_LOCKING'):
            config.write_text(original.replace(key+'=y','# '+key+' is not set'))
            receipt['config']['sha256']=s.sha(config.read_bytes())
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,key):run.kernel(receipt,ROOT)

    def test_init_mounts_devpts_in_private_vm_and_requires_actual_page_geometry(self):
        raw=run.init('a'*32,'test-generic16k').decode()
        self.assertIn('mount -t devtmpfs',raw);self.assertIn('mount -t devpts -o newinstance,ptmxmode=0666,mode=0620',raw)
        self.assertIn('"$page" == 16384',raw);self.assertIn('exec /smoke poweroff',raw)
        self.assertNotIn('WELCOME16K',raw);self.assertNotIn('pacman',raw)

    def test_owned_guest_process_absence_checks_other_fixture_uid_before_credit(self):
        def proc(pid,uid):return SimpleNamespace(name=str(pid),__truediv__=None)
        class Entry:
            def __init__(self,pid,uid):self.name=str(pid);self.uid=uid
            def __truediv__(self,key):return SimpleNamespace(read_text=lambda:'Uid:\t'+('\t'.join([str(self.uid)]*4))+'\n')
        entries=[Entry(100,23001),Entry(1,0)]
        with patch.object(guest,'Path',return_value=SimpleNamespace(iterdir=lambda:entries)),patch.object(guest.os,'getpid',return_value=100):
            self.assertTrue(guest.owned_absent());entries.append(Entry(101,23001))
            with self.assertRaisesRegex(ValueError,'owned fixture process remains'):guest.owned_absent()

    def test_done_source_case_inputs_and_groups_are_required(self):
        value,receipt,nonce,release=self.report_fixture()
        for field in ('runtime_sha256','wrapper_sha256'):
            bad=copy.deepcopy(value);bad['done'][field]='0'*64
            with self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)
        bad=copy.deepcopy(value);bad['case_inputs_preserved']['foreground']=False
        with self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)
        for key in ('group_absent','owned_processes_absent'):
            bad=copy.deepcopy(value);bad['commands'][0][key]=False
            with self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)

    def test_host_supervision_keeps_leader_until_signals_and_requires_absence(self):
        read,write=os.pipe();os.write(write,b'bounded actor output');os.close(write)
        pipe=os.fdopen(read,'rb');events=[]
        process=SimpleNamespace(pid=23456,stdout=pipe,wait=lambda timeout:events.append('wait') or 0)
        def signal(pid,sig):
            events.append(sig)
            if sig==0:raise ProcessLookupError()
        with patch.object(run.subprocess,'Popen',return_value=process),patch.object(run.os,'waitid',return_value=object()),patch.object(run.os,'killpg',side_effect=signal):
            code,raw,proof=run.supervise(['inert'],self.root/'actor.log',30)
        self.assertEqual(code,0);self.assertEqual(raw,b'bounded actor output');self.assertTrue(proof['group_absent'])
        self.assertEqual(events,[run.signal.SIGTERM,run.signal.SIGKILL,'wait',0])

    def test_finalization_cannot_skip_actor_group_proof(self):
        args,report,owner=self.final_fixture();report['actors'][0]['group_absent']=False;s.save(args.output/'runtime.json',report)
        with patch.dict(os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(args.kernel_work.exists())

    def test_exact_done_twelve_sources_eight_payloads_and_recorder_only_transport(self):
        sources={n for n in s.pins()['files'] if n.startswith('packages/tools/cachy-asahi-fish-done/')}
        self.assertEqual(len(sources),12)
        payload=s.mapping()['products']['cachy-asahi-fish-done']['payload']
        self.assertEqual(len(payload),8);self.assertEqual(set(s.mapping()['fixtures']),{'fixtures/done.py',s.SOURCE,s.ADAPTER})
        self.assertNotIn('notify-send',s.TOOLS);self.assertNotIn('usr/bin/notify-send',payload)
        self.assertTrue({'sleep','sh','timeout','kill','fish'}<=set(s.TOOLS))
        source=(s.HERE/'guest.py').read_text()
        self.assertIn("not Path('/usr/bin/notify-send').exists()",source)
        self.assertIn("'fish_done16k=1'",source)
        self.assertIn("+' fish_done16k=1'",(s.HERE/'run.py').read_text())


if __name__=='__main__':unittest.main()
