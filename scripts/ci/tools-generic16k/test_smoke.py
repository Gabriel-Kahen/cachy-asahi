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
import guest
import run
import support as s

ROOT=Path(os.environ.get('TOOLS16K_SOURCE_ROOT',str(Path(__file__).resolve().parents[3])))


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

    def test_exact_source_only_map_and_entry(self):
        s.check_source(ROOT);mapping=s.mapping()
        self.assertEqual(len(mapping['products']),4);self.assertEqual(len(mapping['fixtures']),5)
        self.assertEqual(sum(len(r['payload']) for r in mapping['products'].values()),39)
        value=run.trial(SimpleNamespace(source_root=ROOT,execute=False))
        self.assertEqual(value['status'],'SOURCE_INPUTS_VERIFIED_NOT_EXECUTED');self.assertEqual(len(value['products']),4)

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
        data={n:elf(needed=missing_library and n.endswith('/zsh')) for n in names}
        data['guest.py']=b'# inert\n'
        mapped={**{n:r for product in s.mapping()['products'].values() for n,r in product['payload'].items()},**s.mapping()['fixtures']}
        data.update({n:(ROOT/r['source']).read_bytes() for n,r in mapped.items()})
        archive=self.root/'payload.tar';files={};elfs={}
        with tarfile.open(archive,'w') as stream:
            for name,raw in data.items():
                mode=mapped[name]['mode'] if name in mapped else 0o755
                entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=mode;stream.addfile(entry,io.BytesIO(raw))
                files[name]=dict(bytes=len(raw),mode=mode,sha256=s.sha(raw))
                if raw.startswith(b'\x7fELF'):
                    interpreter,needed=s.aligned(raw,self.generic);elfs[name]=dict(interpreter=interpreter,needed=needed)
        receipt=dict(status='CAPTURED_UNPACKED_NATIVE574_PAYLOAD',inventory_sha256=s.LOCK,payload_map_sha256=s.MAP_SHA,
            files=files,elf=elfs,products=s.mapping()['products'],archive=dict(bytes=archive.stat().st_size,sha256=s.sha(archive.read_bytes())))
        return archive,receipt

    def test_closed_payload_and_manifest_hashes_are_required(self):
        archive,receipt=self.payload_fixture();self.assertEqual(len(run.payload(archive,receipt,self.generic)),57)
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
        argv=run.capture_command(args,'sha256:'+'b'*64,'tools16k-capture-'+'a'*16,self.root/'capture')
        for flag in ('--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pull=never','--cidfile'):
            self.assertIn(flag,argv)
        self.assertIn('CACHY_TOOLS16K_CAPTURE=1',argv);self.assertIn('/source/capture.py',argv)
        self.assertNotIn('pacman -U',' '.join(argv));self.assertNotIn('--privileged',argv)

    def report_fixture(self):
        nonce='a'*32;release='test-generic16k';receipt=dict(files={n:r for p in s.mapping()['products'].values() for n,r in p['payload'].items()})
        work='/tmp/tools16k';paths=work+'/mirrors/';mirror='/usr/bin/cachy-asahi-mirrors';prefix=['/usr/bin/python3','-I','-B']
        activate=[mirror,'activate',paths+'catalog.json','--candidate',paths+'candidate','--repository','core','--target',paths+'mirrorlist','--state']
        restore=[mirror,'restore','--repository','core','--target',paths+'mirrorlist','--state']
        args=[prefix+['/fixtures/highlighting.py',work+'/highlighting'],prefix+['/fixtures/substring_observer.py','--module-dir',
            '/usr/share/cachy-asahi/zsh-history-substring-search','--work',work+'/substring','--highlight-wrapper',
            '/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh'],prefix+['/fixtures/autopair.py','--source',
            '/usr/share/cachy-asahi/fish-autopair','--output',work+'/autopair'],[mirror,'--version'],[mirror,'check',paths+'catalog.json'],
            activate+[paths+'journal.json'],activate+[paths+'journal.json'],restore+[paths+'journal.json'],restore+[paths+'journal.json'],
            activate+[paths+'conflict.json'],restore+[paths+'conflict.json']]
        commands=[dict(argv=a,exit=1 if i==10 else 0,group_absent=True,owned_processes_absent=True,seconds=.01,
            stdout_bytes=1,stderr_bytes=0,stdout_sha256='b'*64,stderr_sha256=s.sha(b'')) for i,a in enumerate(args)]
        highlighting=dict(status='PASS_INSTALLED_ZLE',natural_exit=0,snapshots=[['inert'],['inert']],noninteractive_noop=True,
            preexisting_module_wins=True,repeated_source=True,custom_binding_preserved=True,unknown_token_highlight=True)
        substring=dict(status='PASS_HOST_ZSH_PTY_CONTROLS',host_architecture='aarch64',
            wrapper_sha256=receipt['files']['usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh']['sha256'],
            tests=[dict(name=n,status='PASS',exit=0,**(dict(snapshots=[{}]*10) if n in ('editing','coexist') else {})) for n in
                ('noninteractive','editing','preexisting-function','preexisting-widget','preexisting-private','coexist')])
        fish=dict(status='PASS',platform='aarch64',fish='fish, version 4.9.3',
            wrapper_sha256=receipt['files']['usr/share/cachy-asahi/fish-autopair/opt-in.fish']['sha256'],
            cases={n:dict(exit=0,**(dict(snapshots=[{}]*19,activation='enabled') if n in ('default','vi','hybrid') else {})) for n in
                ('noninteractive','default','vi','hybrid','custom-key','custom-prefix','custom-generic','custom-tab','preset-key',
                 'existing-function','existing-autoload','existing-variable','custom-keymap','existing-wrapper')})
        ec=dict(schema_version=1,architecture='aarch64',base='asahi-alarm',repository='core',database=dict(bytes=1,sha256=s.sha(b'x')),
            mirrors=[dict(id='private',server='https://example.invalid/$arch/$repo')])
        cs=s.sha((json.dumps(ec,sort_keys=True)+'\n').encode());candidate=('# Separate candidate; selected repository: core\n# Exact catalog SHA256: '+cs+'\nServer = https://example.invalid/$arch/$repo\n').encode()
        mirrors=dict(version='0.2.0',network='NOT_USED',conflict_journal_phase='ACTIVE',restored_bytes_mode_uid_gid=True,
            retry_preserved=True,edited_target_preserved=True,catalog_sha256=cs,candidate_sha256=s.sha(candidate),
            original_sha256=s.sha(b'# preserve caller mirror bytes\nServer = https://original.invalid/$arch/$repo\n'))
        commands[3]['stdout_sha256']=s.sha(b'cachy-asahi-mirrors 0.2.0\n')
        value=dict(status='PASS_GENERIC_16K_MAPPED_TOOLS_PTY_CLI_ONLY',nonce=nonce,architecture='aarch64',page_size=16384,kernel=release,
            uid=23001,commands=commands,fixtures=dict(highlighting=highlighting,substring=substring,autopair=fish),mirrors=mirrors,
            config_preserved=True,payload_preserved=True,owned_processes_absent=True,
            package_registration='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',release_admission=False,
            payload_manifest_sha256=s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()))
        return value,receipt,nonce,release

    def output(self,value,nonce,release):
        return (f'UNAME16K aarch64 {release}\nGETCONF16K 16384\nSMOKE16K: mmap,mprotect,file-offset PASS\nTOOLS16K_REPORT '+
                json.dumps(value)+f'\nTOOLS16K PASS {nonce}\n').encode()

    def test_actual_guest_markers_behavior_identity_and_natural_exit_required(self):
        value,receipt,nonce,release=self.report_fixture();raw=self.output(value,nonce,release)
        self.assertEqual(run.guest_report(raw,0,nonce,release,receipt)['page_size'],16384)
        for wrong,code in ((raw,-9),(raw+b'Kernel panic - not syncing\n',0),(raw+f'TOOLS16K PASS {nonce}\n'.encode(),0),(raw.replace(b'GETCONF16K 16384',b'GETCONF16K 4096'),0)):
            with self.assertRaises(ValueError):run.guest_report(wrong,code,nonce,release,receipt)

    def test_guest_cannot_claim_gui_hardware_or_omit_preservation_and_commands(self):
        value,receipt,nonce,release=self.report_fixture()
        for field,wrong in (('GUI','PASS'),('hardware','PASS'),('release_admission',True),('config_preserved',False),
                            ('owned_processes_absent',False),('uid',0),('page_size',4096)):
            bad=copy.deepcopy(value);bad[field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)
        for mutate in ('command','fish','payload','mirror','substring','binding'):
            bad=copy.deepcopy(value)
            if mutate=='command':bad['commands'][10]['exit']=0
            elif mutate=='fish':bad['fixtures']['autopair']['cases']['vi']['snapshots']=[]
            elif mutate=='payload':bad['payload_manifest_sha256']='c'*64
            elif mutate=='mirror':bad['mirrors']['edited_target_preserved']=False
            elif mutate=='substring':bad['fixtures']['substring']['tests'].pop()
            else:bad['fixtures']['highlighting']['custom_binding_preserved']=False
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):run.guest_report(self.output(bad,nonce,release),0,nonce,release,receipt)

    def final_fixture(self):
        base=self.root/'base';base.mkdir();out=self.root/'public';out.mkdir();work=self.root/'tools16k-kernel';work.mkdir()
        image='sha256:'+'b'*64;token='a'*16
        report=dict(status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT',job_token=token,image_id=image,natural_VM_exit=True,QEMU_exit=0,
            actors=[dict(natural_exit=True,exit=0,group_absent=True)]*3,consumer_cleanup=dict(capture_absent=True,private_removed=True,producer='BORROWED_PRESERVED'),
            kernel=dict(status='BUILT_ONLY',kernel_build='PASS',helper=dict(path=str(work/'helper/build_kernel.py'))))
        owner=dict(ownership=dict(token=token),owned_cleanup=dict(status='PASS',probe=dict(absence_verified=True),image=dict(id=image,absence_verified=True)))
        s.save(out/'runtime.json',report);s.save(base/'report.json',owner)
        return SimpleNamespace(base_dir=base,output=out,kernel_work=work,job_token=token),report,owner

    def test_final_pass_waits_for_owned_producer_and_kernel_work_retirement(self):
        args,report,owner=self.final_fixture()
        with patch.dict(os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],'PASS_GENERIC_16K_MAPPED_TOOLS_PTY_CLI_ONLY');self.assertFalse(args.kernel_work.exists())

    def test_unproved_producer_or_wrong_kernel_path_cannot_be_removed_or_pass(self):
        args,report,owner=self.final_fixture();owner['owned_cleanup']['image']['absence_verified']=False;s.save(args.base_dir/'report.json',owner)
        with patch.dict(os.environ,RUNNER_TEMP=str(self.root)):result=run.finalize(args)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(args.kernel_work.exists())

    def test_foreign_capture_owner_never_signalled_or_removed(self):
        private=self.root/'private';private.mkdir();(private/'capture.cid').write_text('b'*64)
        args=SimpleNamespace(private=private,job_token='a'*16)
        foreign=[dict(Id='b'*64,Name='/tools16k-capture-'+'a'*16,Image='sha256:'+'c'*64,Config=dict(Labels={}))]
        with patch.object(run,'query',side_effect=['tools16k-capture-'+'a'*16,json.dumps(foreign)]) as query:
            with self.assertRaises(ValueError):run.retire(args,'tools16k-capture-'+'a'*16,'sha256:'+'c'*64,True)
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
                if entry.name=='usr/bin/cachy-asahi-mirrors':
                    data=b'# substituted source';entry.size=len(data)
                    receipt['files'][entry.name].update(bytes=len(data),sha256=s.sha(data))
                members.append((entry,data))
        with tarfile.open(archive,'w') as stream:
            for entry,data in members:stream.addfile(entry,io.BytesIO(data))
        receipt['archive'].update(bytes=archive.stat().st_size,sha256=s.sha(archive.read_bytes()))
        with self.assertRaisesRegex(ValueError,'actual captured bytes differ'):run.payload(archive,receipt,self.generic)

    def test_derived_kernel_profile_is_narrow_and_accepted_fragment_unchanged(self):
        old=ast.parse((ROOT/'scripts/virtual/generic16k/build_kernel.py').read_text());new=ast.parse((s.HERE/'build_kernel.py').read_text())
        def functions(tree):return {n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,ast.FunctionDef)}
        before,after=functions(old),functions(new)
        self.assertEqual(set(before),set(after))
        self.assertEqual({k for k in before if before[k]!=after[k]},{'main','usage','run'})
        self.assertTrue(all(before[k]==after[k] for k in before if k not in ('main','usage','run')))
        self.assertEqual((s.HERE/'kernel.fragment').read_bytes(),(ROOT/'scripts/virtual/generic16k/kernel.fragment').read_bytes())
        helper=s.load(ROOT,'scripts/ci/tools-generic16k/build_kernel.py')
        self.assertEqual(helper.DIAGNOSTIC_FRAGMENT,'CONFIG_KALLSYMS=y\nCONFIG_PRINTK_TIME=y\nCONFIG_UNIX98_PTYS=y\nCONFIG_EVENTFD=y\nCONFIG_FILE_LOCKING=y\n')

    def kernel_fixture(self):
        helper=s.load(ROOT,'scripts/ci/tools-generic16k/build_kernel.py');config=self.root/'config';image=self.root/'Image'
        base=(s.HERE/'kernel.fragment').read_bytes();config.write_bytes(base+helper.DIAGNOSTIC_FRAGMENT.encode())
        raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);image.write_bytes(raw)
        return dict(profile='TOOLS16K_PTY_DERIVED_DIAGNOSTIC',derivation=dict(base_helper_sha256=s.pins()['files']['scripts/virtual/generic16k/build_kernel.py']['sha256'],
            diagnostic_extension='CONFIG_UNIX98_PTYS=y;CONFIG_EVENTFD=y;CONFIG_FILE_LOCKING=y',
               workspace_scan='ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',accepted_profile_modified=False),status='BUILT_ONLY',kernel_build='PASS',boot_diagnostics=True,
            image_check=dict(header_page_size=16384),module_policy=dict(CONFIG_MODULES='n'),archive=dict(sha256='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'),
            source_commit='94fb23346d522edf53722357c426a3e58030beea',helper=dict(sha256=s.sha((s.HERE/'build_kernel.py').read_bytes())),
            fragment=dict(sha256=s.sha(base)),diagnostic_fragment=dict(sha256=s.sha(base+helper.DIAGNOSTIC_FRAGMENT.encode())),
            image=dict(path=str(image),bytes=64,sha256=s.sha(raw)),config=dict(path=str(config),sha256=s.sha(config.read_bytes())))

    def test_kernel_receipt_requires_separate_profile_and_actual_pty_locking_config(self):
        receipt=self.kernel_fixture();self.assertEqual(run.kernel(receipt,ROOT),self.root/'Image')
        bad=copy.deepcopy(receipt);bad['derivation']['accepted_profile_modified']=True
        with self.assertRaises(ValueError):run.kernel(bad,ROOT)
        config=self.root/'config';original=config.read_text()
        for key in ('CONFIG_UNIX98_PTYS','CONFIG_EVENTFD','CONFIG_FILE_LOCKING'):
            config.write_text(original.replace(key+'=y','# '+key+' is not set'))
            receipt['config']['sha256']=s.sha(config.read_bytes())
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,key):run.kernel(receipt,ROOT)

    def test_kernel_file_locking_cannot_be_absent_disabled_or_modular(self):
        receipt=self.kernel_fixture();config=self.root/'config';original=config.read_text()
        for replacement in ('','# CONFIG_FILE_LOCKING is not set','CONFIG_FILE_LOCKING=n','CONFIG_FILE_LOCKING=m'):
            config.write_text(original.replace('CONFIG_FILE_LOCKING=y',replacement))
            receipt['config']['sha256']=s.sha(config.read_bytes())
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'CONFIG_FILE_LOCKING'):
                run.kernel(receipt,ROOT)

    def test_old_kernel_derivation_cannot_claim_new_locking_profile(self):
        receipt=self.kernel_fixture();receipt['derivation']['diagnostic_extension']='CONFIG_UNIX98_PTYS=y;CONFIG_EVENTFD=y'
        with self.assertRaisesRegex(ValueError,'separately derived'):run.kernel(receipt,ROOT)

    def test_accepted_base_config_contract_stays_unchanged(self):
        helper=s.load(ROOT,'scripts/ci/tools-generic16k/build_kernel.py')
        config=self.root/'base-config';base=(s.HERE/'kernel.fragment').read_text();config.write_text(base)
        self.assertEqual(helper.config_check(config,False)['page_size'],16384)
        config.write_text(base+helper.DIAGNOSTIC_FRAGMENT.replace('CONFIG_FILE_LOCKING=y\n',''))
        with self.assertRaisesRegex(ValueError,'CONFIG_FILE_LOCKING'):helper.config_check(config,True)

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

    def test_wrong_mirror_known_input_hash_and_command_group_are_refused(self):
        value,receipt,nonce,release=self.report_fixture()
        for field in ('catalog_sha256','candidate_sha256','original_sha256'):
            bad=copy.deepcopy(value);bad['mirrors'][field]='0'*64
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


if __name__=='__main__':unittest.main()
