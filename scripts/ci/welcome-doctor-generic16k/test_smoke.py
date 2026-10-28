# SPDX-License-Identifier: MIT
"""Inert data/ownership controls; no package, compiler, Docker, QEMU or GUI actor."""
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
import guest
import run
import support as s

ROOT=Path(os.environ.get('WELCOME16K_SOURCE_ROOT',str(Path(__file__).resolve().parents[3])))
ASSETS=Path(os.environ.get('WELCOME16K_ASSETS',str(ROOT/'artifacts/development/welcome-native-inputs-20261016/payload')))


def elf(align=16384,needed=False):
    raw=bytearray(512);raw[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HHI',raw,16,3,183,1)
    struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,2 if needed else 1)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,len(raw),len(raw),align)
    if needed:
        struct.pack_into('<IIQQQQQQ',raw,120,2,4,256,0x400100,0,48,48,8)
        struct.pack_into('<QQQQQQ',raw,256,1,1,5,0x400140,0,0);raw[320:337]=b'\0libmissing.so.0\0\0'
    return bytes(raw)


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('actor execution forbidden'))
        blocked.start();self.addCleanup(blocked.stop);self.generic=s.load(ROOT,'scripts/virtual/generic16k/fixture.py')

    def test_exact_four_archives_23_sources_and_source_only_entry(self):
        s.check_source(ROOT);index=json.loads(s.read(ASSETS/'index.json'))
        self.assertEqual(len(index['files']),4);self.assertEqual(len(index['recipe_sources']),23)
        value=run.trial(SimpleNamespace(source_root=ROOT,assets=ASSETS,execute=False))
        self.assertEqual(value['status'],'SOURCE_INPUTS_VERIFIED_NOT_EXECUTED');self.assertEqual(len(value['products']),2)
        self.assertEqual(sum(row['bytes'] for row in index['files'].values()),68152)

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
        names=['usr/bin/'+n for n in ('bash','env','uname','getconf','mount','python3','cachy-asahi-welcome')]
        data={n:elf(needed=missing_library and n.endswith('welcome')) for n in names}
        data.update({'usr/bin/cachy-asahi-doctor':b'#!inert\n','guest.py':b'# inert\n'})
        archive=self.root/'payload.tar';files={};elfs={}
        with tarfile.open(archive,'w') as stream:
            for name,raw in data.items():
                entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=0o755;stream.addfile(entry,io.BytesIO(raw))
                files[name]=dict(bytes=len(raw),mode=0o755,sha256=s.sha(raw))
                if raw.startswith(b'\x7fELF'):
                    interpreter,needed=s.aligned(raw,self.generic);elfs[name]=dict(interpreter=interpreter,needed=needed)
        receipt=dict(status='CAPTURED_UNPACKED_NATIVE574_PAYLOAD',inventory_sha256=s.LOCK,product_input_source=s.INPUT_SOURCE,index_sha256=s.INDEX,
            files=files,elf=elfs,products={'welcome':dict(payload={'usr/bin/cachy-asahi-welcome':{}})},
            archive=dict(bytes=archive.stat().st_size,sha256=s.sha(archive.read_bytes())))
        return archive,receipt

    def test_closed_payload_and_manifest_hashes_are_required(self):
        archive,receipt=self.payload_fixture();self.assertEqual(len(run.payload(archive,receipt,self.generic)),9)
        for field in ('inventory_sha256','index_sha256'):
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
        args=SimpleNamespace(private=self.root,source_root=ROOT,assets=ASSETS,base_dir=self.root/'base',job_token='a'*16)
        argv=run.capture_command(args,'sha256:'+'b'*64,'welcome16k-capture-'+'a'*16,self.root/'capture')
        for flag in ('--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pull=never','--cidfile'):
            self.assertIn(flag,argv)
        self.assertIn('CACHY_WELCOME16K_CAPTURE=1',argv);self.assertIn('/source/capture.py',argv)
        self.assertNotIn('pacman -U',' '.join(argv));self.assertNotIn('--privileged',argv)

    def report_fixture(self):
        nonce='a'*32;release='test-generic16k';guides={n:s.sha(n.encode()) for n in ('first-run','updates','recovery')}
        receipt=dict(files={'usr/share/doc/cachy-asahi-welcome/'+n+'.txt':dict(sha256=pin) for n,pin in guides.items()})
        args=[['cachy-asahi-welcome','--help'],['cachy-asahi-welcome','--version'],['cachy-asahi-welcome','--status'],['cachy-asahi-welcome','--status','--json'],
            *[['cachy-asahi-welcome','--guide',n] for n in guides],['cachy-asahi-welcome','--guide','../../etc/shadow'],
            ['cachy-asahi-doctor','--help'],['cachy-asahi-doctor','--json'],['cachy-asahi-doctor','--json','--output','/tmp/welcome16k/reports/report.json'],
            ['cachy-asahi-doctor','--output','/tmp/welcome16k/reports/report.json'],['cachy-asahi-doctor','--output','/tmp/welcome16k/reports/alias']]
        commands=[dict(argv=['/usr/bin/'+a[0],*a[1:]],exit=2 if i in (7,11,12) else 0,group_absent=True,seconds=.01,
                       stdout_bytes=1,stderr_bytes=0,stdout_sha256='b'*64,stderr_sha256=s.sha(b'')) for i,a in enumerate(args)]
        for i,n in enumerate(guides,4):commands[i]['stdout_sha256']=guides[n]
        value=dict(status='PASS_GENERIC_16K_WELCOME_DOCTOR_CLI_ONLY',nonce=nonce,architecture='aarch64',page_size=16384,kernel=release,
            commands=commands,guide_sha256=guides,private_report_mode='0600',no_overwrite='PASS',symlink_refusal='PASS',config_preserved=True,
            payload_preserved=True,package_registration='NOT_INSTALLED_EXACT_PAYLOADS_UNPACKED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',release_admission=False,
            welcome_status=dict(architecture='aarch64',page_size=16384,kernel=release,hardware_compatibility='not-assessed',welcome_version='0.1.0',package_database='unavailable'),
            doctor_platform=dict(architecture='aarch64',page_size_bytes=16384,kernel=release),doctor_scope='local observations only',
            payload_manifest_sha256=s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()))
        return value,receipt,nonce,release

    def output(self,value,nonce,release):
        return (f'UNAME16K aarch64 {release}\nGETCONF16K 16384\nSMOKE16K: mmap,mprotect,file-offset PASS\nWELCOME16K_REPORT '+
                json.dumps(value)+f'\nWELCOME16K PASS {nonce}\n').encode()

    def test_actual_guest_markers_behavior_identity_and_natural_exit_required(self):
        value,receipt,nonce,release=self.report_fixture();raw=self.output(value,nonce,release)
        self.assertEqual(run.guest_report(raw,0,nonce,release,receipt)['page_size'],16384)
        for wrong,code in ((raw,-9),(raw+b'Kernel panic - not syncing\n',0),(raw+f'WELCOME16K PASS {nonce}\n'.encode(),0),(raw.replace(b'GETCONF16K 16384',b'GETCONF16K 4096'),0)):
            with self.assertRaises(ValueError):run.guest_report(wrong,code,nonce,release,receipt)

    def test_guest_cannot_claim_gui_hardware_or_omit_preservation_and_commands(self):
        value,receipt,nonce,release=self.report_fixture()
        for field,wrong in (('GUI','PASS'),('hardware','PASS'),('release_admission',True),('config_preserved',False),('no_overwrite','FAIL'),('page_size',4096)):
            bad=copy.deepcopy(value);bad[field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)
        for mutate in ('command','guide','payload','platform'):
            bad=copy.deepcopy(value)
            if mutate=='command':bad['commands'][0]['exit']=2
            elif mutate=='guide':bad['guide_sha256']['updates']='c'*64
            elif mutate=='payload':bad['payload_manifest_sha256']='c'*64
            else:bad['doctor_platform']['page_size_bytes']=4096
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)

    def final_fixture(self):
        base=self.root/'base';base.mkdir();out=self.root/'public';out.mkdir();work=self.root/'welcome16k-kernel';work.mkdir()
        image='sha256:'+'b'*64;token='a'*16
        report=dict(status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT',job_token=token,image_id=image,natural_VM_exit=True,QEMU_exit=0,
            consumer_cleanup=dict(capture_absent=True,private_removed=True,producer='BORROWED_PRESERVED'),
            kernel=dict(status='BUILT_ONLY',kernel_build='PASS',helper=dict(path=str(work/'helper/build_kernel.py'))))
        owner=dict(ownership=dict(token=token),owned_cleanup=dict(status='PASS',probe=dict(absence_verified=True),image=dict(id=image,absence_verified=True)))
        s.save(out/'runtime.json',report);s.save(base/'report.json',owner)
        return SimpleNamespace(base_dir=base,output=out,kernel_work=work,job_token=token),report,owner

    def test_final_pass_waits_for_owned_producer_and_kernel_work_retirement(self):
        args,report,owner=self.final_fixture()
        with patch.dict(os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],'PASS_GENERIC_16K_WELCOME_DOCTOR_CLI_ONLY');self.assertFalse(args.kernel_work.exists())

    def test_unproved_producer_or_wrong_kernel_path_cannot_be_removed_or_pass(self):
        args,report,owner=self.final_fixture();owner['owned_cleanup']['image']['absence_verified']=False;s.save(args.base_dir/'report.json',owner)
        with patch.dict(os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(args.kernel_work.exists())

    def test_foreign_capture_owner_never_signalled_or_removed(self):
        private=self.root/'private';private.mkdir();(private/'capture.cid').write_text('b'*64)
        args=SimpleNamespace(private=private,job_token='a'*16)
        foreign=[dict(Id='b'*64,Name='/welcome16k-capture-'+'a'*16,Image='sha256:'+'c'*64,Config=dict(Labels={}))]
        with patch.object(run,'query',side_effect=['welcome16k-capture-'+'a'*16,json.dumps(foreign)]) as query:
            with self.assertRaises(ValueError):run.retire(args,'welcome16k-capture-'+'a'*16,'sha256:'+'c'*64,True)
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


if __name__=='__main__':unittest.main()
