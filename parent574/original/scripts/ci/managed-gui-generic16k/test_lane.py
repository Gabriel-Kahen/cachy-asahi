#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source, synthetic metadata and mocked GUI controls; no native/build/VM actors."""
import argparse
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s
import prepare
import kernel_contract as K
import elf_audit as E
import run as R


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def fake_elf(align=16384,machine=183,offset=0):
    raw=bytearray(120);raw[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HH',raw,16,2,machine)
    struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,offset,0,0,120-offset,120,align);return bytes(raw)


def profile():
    return dict(schema_version=1,profile=K.PROFILE,release=K.RELEASE,architecture='aarch64',page_size=16384,
        source_revision=K.REVISION,archive_sha256=K.ARCHIVE,helper_sha256=K.HELPER_SHA,fragment_sha256=K.FRAGMENT_SHA,
        diagnostic_fragment_sha256=K.DIAGNOSTIC_SHA,Image=dict(bytes=64,sha256='a'*64),
        config=dict(bytes=1,sha256=s.sha(b'x')),modules='DISABLED')


class Lane(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup);cls.root=Path(cls.tmp.name)
        cls.source=cls.root/'source';cls.source.mkdir()
        # Copy only pinned inputs. Never erase unrelated shared-tree bytecode or files.
        for name in s.pins():
            if name.startswith(s.PREFIX):continue
            target=cls.source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(SOURCE/name,target)
        cls.runner=prepare.prepare(cls.source,cls.root/'runner',ASSETS)
        cls.helper=s.load(cls.source,'scripts/ci/managed-gui-generic16k/build_kernel.py')
        cls.reader=load('control_elf_reader',cls.runner/'elf_reader.py')
        s.save(cls.runner/'kernel-profile.json',profile())
        sys.path.insert(0,str(cls.runner))
        # Reuse existing full phase fixtures. Their native actors stay mocked.
        gui=load('test_gui',SOURCE/'scripts/ci/welcome-managed-gui/test_gui.py');sys.modules['test_gui']=gui
        gui.ROOT=cls.source;gui.ASSETS=ASSETS
        phase=load('control_phase',SOURCE/'scripts/ci/welcome-managed-gui/test_phase.py')
        phase.ROOT=cls.source;phase.ASSETS=ASSETS;old=phase.doctor
        def doctor16k(*a,**kw):
            value=old(*a,**kw);value['doctor']['checks'][0]['value'].update(page_size_bytes=16384,kernel=K.RELEASE);return value
        phase.doctor=doctor16k;phase.Phase.setUpClass()
        actor=phase.Phase('test_exact_real_interface_sequence_seven_frames_preservation_and_retirement');actor.setUp()
        try:
            actor.run_phase();actor.retired();cls.events=phase.managed_events(actor.events);cls.lock=copy.deepcopy(actor.lock)
        finally:actor.doCleanups()
        raw=(cls.runner/'kernel-profile.json').read_bytes()
        cls.events.insert(0,dict(event='boot',architecture='aarch64',kernel=K.RELEASE,page_size=16384,kernel_profile_sha256=s.sha(raw)))
        cls.contract=load('control_generated_contract',cls.runner/'contract.py')
        cls.caller=load('control_gui16k_caller',Path(__file__).resolve().parent/'ci/caller.py')

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)

    def test_01_exact_dependency_closure_and_native_pairs(self):
        s.check_source(self.source);self.assertEqual(len(self.lock['products']),2)
        self.assertEqual(sum(len(r['payload']) for r in self.lock['products'].values()),13)
        self.assertEqual(self.lock['producer_lifecycle'],'FAIL_USER_PRESERVATION_CHECK')

    def test_02_generated_sources_parse_and_fixture_shell(self):
        for path in self.runner.glob('*.py'):ast.parse(path.read_text())
        subprocess.run(['bash','-n',str(self.runner/'desktop574_fixture.sh')],check=True)
        manifest=json.loads(s.read(s.HERE/'ci/source-manifest.json'))
        self.caller.verify_kernel_contract_pin(manifest)
        self.caller.verify_files(self.runner,manifest['generated_runner'])

    def test_03_only_main_usage_run_change_kernel_helper_functions(self):
        old=ast.parse((SOURCE/'scripts/virtual/generic16k/build_kernel.py').read_text());new=ast.parse((s.HERE/'build_kernel.py').read_text())
        funcs=lambda t:{n.name:ast.dump(n) for n in t.body if isinstance(n,ast.FunctionDef) and n.name not in ('main','usage','run')}
        self.assertEqual(funcs(old),funcs(new));self.assertEqual(len((s.HERE/'kernel.fragment').read_text().splitlines()),91)

    def test_04_image_16k_and_4k_header_refusal(self):
        p=self.work/'Image';raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);p.write_bytes(raw)
        self.assertEqual(self.helper.image_check(p)['header_page_size'],16384)
        struct.pack_into('<Q',raw,24,2);p.write_bytes(raw)
        with self.assertRaises(ValueError):self.helper.image_check(p)

    def test_05_all_fragment_values_and_required_api_refusals(self):
        p=self.work/'config';text=(s.HERE/'kernel.fragment').read_text()+self.helper.DIAGNOSTIC_FRAGMENT;p.write_text(text)
        self.helper.config_check(p,True)
        for name in ('DRM_VIRTIO_GPU','DRM_VIRTIO_GPU_KMS','PCI_HOST_GENERIC','VIRTIO_BLK','VIRTIO_CONSOLE','NET','UNIX','CGROUPS','USER_NS','EVENTFD','SECCOMP_FILTER','FILE_LOCKING'):
            with self.subTest(name=name):
                p.write_text(text.replace('CONFIG_'+name+'=y','CONFIG_'+name+'=n'))
                with self.assertRaises(ValueError):self.helper.config_check(p,True)
        p.write_text(text+'CONFIG_ARM64_4K_PAGES=y\n')
        with self.assertRaises(ValueError):self.helper.config_check(p,True)

    def test_06_exact_profile_rejects_old_or_drifted_identities(self):
        K.validate(profile())
        for key,value in (('page_size',4096),('release','7.2.10-1-aarch64-ARCH'),('modules','ENABLED'),
            ('helper_sha256','0'*64),('fragment_sha256','0'*64),('source_revision','0'*40),('architecture','x86_64')):
            with self.subTest(key=key),self.assertRaises(ValueError):K.validate(profile()|{key:value})

    def test_07_actual_boot_requires_single_hash_joined_16k_profile(self):
        K.boot(self.events,self.runner/'kernel-profile.json')
        for change in ({'page_size':4096},{'kernel_profile_sha256':'0'*64},{'kernel':'other'}):
            bad=copy.deepcopy(self.events);bad[0].update(change)
            with self.assertRaises(ValueError):K.boot(bad,self.runner/'kernel-profile.json')
        with self.assertRaises(ValueError):K.boot(self.events+[self.events[0]],self.runner/'kernel-profile.json')

    def test_08_staged_native_elf_alignment_machine_and_congruence(self):
        p=self.work/'bin';p.write_bytes(fake_elf());self.assertEqual(len(E.audit(self.work,self.reader)['ELF']),1)
        for raw in (fake_elf(4096),fake_elf(machine=62),fake_elf(offset=1)):
            p.write_bytes(raw)
            with self.assertRaises(ValueError):E.audit(self.work,self.reader)

    def test_09_known_guile_vm_bytecode_is_data_but_unknown_em_none_refused(self):
        (self.work/'bin').write_bytes(fake_elf());p=self.work/'usr/lib/guile/3.0/a.go';p.parent.mkdir(parents=True);p.write_bytes(fake_elf(machine=0))
        result=E.audit(self.work,self.reader);self.assertEqual(len(result['ELF']),1);self.assertEqual(len(result['non_native_assets']),1)
        (self.work/'unknown.go').write_bytes(p.read_bytes())
        with self.assertRaises(ValueError):E.audit(self.work,self.reader)

    def test_10_symlink_elf_not_followed(self):
        (self.work/'native').write_bytes(fake_elf());(self.work/'alias').symlink_to(self.work/'native')
        self.assertEqual(len(E.audit(self.work,self.reader)['ELF']),1)

    def test_11_full_fourteen_views_sixteen_actions_and_pending_pixels(self):
        result=self.contract.verify_result(self.events,self.lock)
        self.assertEqual(result['diagnostic_kernel'],profile());self.assertEqual(result['hardware'],'NOT_RUN')
        self.assertEqual(len([r for r in self.events if r.get('event')=='frame_ready']),14)
        self.assertEqual(len([r for r in self.events if r.get('event')=='welcome_action']),16)
        self.assertEqual(result['GUI'],'NATIVE_METADATA_PASS_PIXELS_PENDING_REVIEW')

    def test_12_every_capture_and_action_still_required(self):
        for index,event in enumerate(self.events):
            if event.get('event') not in ('frame_ready','welcome_action'):continue
            with self.subTest(event=event.get('view',event.get('label'))),self.assertRaises((ValueError,IndexError,StopIteration)):
                self.contract.verify_result(self.events[:index]+self.events[index+1:],self.lock)

    def test_13_doctor_4k_proof_refused(self):
        bad=copy.deepcopy(self.events);row=next(e for e in bad if e.get('event')=='doctor_result')
        row['proof']['doctor']['checks'][0]['value']['page_size_bytes']=4096
        row['proof_sha256']=s.sha((json.dumps(row['proof'],sort_keys=True,indent=2)+'\n').encode())
        with self.assertRaises(ValueError):self.contract.verify_result(bad,self.lock)

    def test_14_preservation_and_normal_exit_gates_remain(self):
        for key,value in (('config_preserved',False),('launch_actions','FAIL')):
            bad=copy.deepcopy(self.events);next(e for e in bad if e.get('event')=='phase_pass')[key]=value
            with self.assertRaises(ValueError):self.contract.verify_result(bad,self.lock)
        bad=copy.deepcopy(self.events);next(e for e in bad if e.get('event')=='compositor_log_summary')['returncode']=1
        with self.assertRaises(ValueError):self.contract.verify_result(bad,self.lock)

    def test_15_fixture_builtins_alignment_gate_and_unmodified_gui_session(self):
        text=(self.runner/'desktop574_fixture.sh').read_text()
        self.assertNotIn('modprobe',text);self.assertNotIn('depmod',text);self.assertEqual(text.count('-Wl,-z,max-page-size=16384'),2)
        self.assertLess(text.index('/runner/elf_audit.py'),text.index('mkfs.ext4'))
        for name in ('session.py','doctor_worker.py','observed.py','a11y_driver.c','compositor_log.py','managed_session.py'):
            self.assertEqual((self.runner/name).read_bytes(),(SOURCE/'scripts/ci/welcome-managed-gui'/name).read_bytes())
        self.assertIn('deadline = time.monotonic() + 1300',(self.runner/'desktop574_runtime.py').read_text())
        self.assertIn('signal.setitimer(signal.ITIMER_REAL, 1750)',(self.runner/'desktop574_runtime.py').read_text())

    def test_16_no_actors_without_execute_flag(self):
        with patch.object(R.subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(R,'kernel',side_effect=AssertionError('kernel')):
            self.assertEqual(R.trial(SimpleNamespace(source=self.source,execute=False))['status'],'SOURCE_INPUTS_VERIFIED_NOT_EXECUTED')

    def test_17_fresh_prepare_and_anchor_drift_refusal(self):
        with self.assertRaises(ValueError):prepare.prepare(self.source,self.runner,ASSETS)
        with self.assertRaises(ValueError):prepare.replace('missing','anchor','new')
        with self.assertRaises(ValueError):prepare.replace('x x','x','new')

    def test_18_regular_source_and_profile_symlinks_refused(self):
        p=self.work/'file';p.write_text('{}');alias=self.work/'alias';alias.symlink_to(p)
        with self.assertRaises(ValueError):s.read(alias)
        with self.assertRaises(ValueError):K.read(alias)

    def test_19_source_identity_and_arm_runner_required(self):
        p=self.work/'file';p.write_text('fixed');mf=dict(files={'file':dict(bytes=5,sha256=s.sha(b'fixed'))})
        name=self.caller.SLICE+'/kernel_contract.py';target=self.work/name
        target.parent.mkdir(parents=True);target.write_text('contract fixture')
        row=dict(bytes=target.stat().st_size,sha256=s.sha(target.read_bytes()))
        mf['files'][name]=row;mf['generated_runner']={'kernel_contract.py':dict(row)}
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        self.assertEqual(self.caller.prove(self.work,mf,env)['status'],'SOURCE_PROOF_PASS')
        for change in ({'GITHUB_WORKFLOW_SHA':'b'*40},{'RUNNER_ARCH':'X64'},{'SOURCE_SHA':'main'}):
            with self.assertRaises(ValueError):self.caller.prove(self.work,mf,env|change)
        p.write_text('drift')
        with self.assertRaises(ValueError):self.caller.prove(self.work,mf,env)

    def test_20_source_profile_constants_bind_actual_files(self):
        self.assertEqual(s.sha((s.HERE/'build_kernel.py').read_bytes()),K.HELPER_SHA)
        self.assertEqual(s.sha((s.HERE/'kernel.fragment').read_bytes()),K.FRAGMENT_SHA)
        self.assertEqual(s.sha((s.HERE/'kernel.fragment').read_bytes()+self.helper.DIAGNOSTIC_FRAGMENT.encode()),K.DIAGNOSTIC_SHA)


    def kernel_fixture(self):
        work=self.work/'managed-gui16k-kernel';folder=work/'helper';folder.mkdir(parents=True)
        for name in ('build_kernel.py','kernel.fragment'):shutil.copyfile(s.HERE/name,folder/name)
        built=folder/'built';(built/'build/arch/arm64/boot').mkdir(parents=True)
        cfg=built/'build/.config';cfg.write_text((s.HERE/'kernel.fragment').read_text()+self.helper.DIAGNOSTIC_FRAGMENT)
        image=built/'build/arch/arm64/boot/Image';raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);image.write_bytes(raw)
        identity=lambda p:dict(path=str(p),bytes=p.stat().st_size,sha256=s.sha(p.read_bytes()))
        receipt=dict(status='BUILT_ONLY',kernel_build='PASS',profile=K.PROFILE,
            derivation=dict(base_helper_sha256='e94adb4474183feea30ce1e2949b55c03e4969eeb1addb4c36892e8664ba9aaa',
                base_fragment_sha256='6d91180b80138d2d8039efafaaa9ca31349baea22b90430cbb15e07bce02e8f6',
                workspace_scan='ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',accepted_profiles_modified=False),
            source_commit=K.REVISION,archive=dict(sha256=K.ARCHIVE,bytes=262965559),boot_diagnostics=True,kernel_release=K.RELEASE,
            module_policy=dict(CONFIG_MODULES='n'),helper=identity(folder/'build_kernel.py'),fragment=identity(folder/'kernel.fragment'),
            diagnostic_fragment=dict(sha256=K.DIAGNOSTIC_SHA),image=identity(image),config=identity(cfg))
        receipt_path=built/'build-receipt.json';s.save(receipt_path,receipt)
        return SimpleNamespace(kernel_work=work,kernel_receipt=receipt_path,source=self.source),receipt,image,cfg

    def test_21_build_receipt_binds_actual_files_and_exact_owned_paths(self):
        args,receipt,image,cfg=self.kernel_fixture()
        with patch.dict(os.environ,RUNNER_TEMP=str(self.work)):
            result=R.kernel(args);self.assertEqual(result[0]['Image']['sha256'],s.sha(image.read_bytes()))
            image.write_bytes(image.read_bytes()+b'drift')
            with self.assertRaises(ValueError):R.kernel(args)
        self.assertTrue(args.kernel_work.exists())

    def test_22_build_receipt_wrong_profile_and_incomplete_build_refused(self):
        args,receipt,image,cfg=self.kernel_fixture()
        for change in ({'profile':'TOOLS16K_PTY_DERIVED_DIAGNOSTIC'},{'status':'CONFIGURED_ONLY'},
            {'source_commit':'0'*40},{'kernel_release':'7.2.10-1-aarch64-ARCH'}):
            s.save(args.kernel_receipt,receipt|change)
            with patch.dict(os.environ,RUNNER_TEMP=str(self.work)),self.assertRaises(ValueError):R.kernel(args)

    def test_23_kernel_helper_copy_drift_refused(self):
        args,receipt,image,cfg=self.kernel_fixture();p=args.kernel_work/'helper/build_kernel.py';p.write_bytes(p.read_bytes()+b'\n# drift\n')
        with patch.dict(os.environ,RUNNER_TEMP=str(self.work)),self.assertRaises(ValueError):R.kernel(args)

    def test_24_finalize_removes_only_completed_owned_kernel_after_producer(self):
        runner=self.work/'managed-gui16k-runner';runner.mkdir();image=runner/'diagnostic.Image';image.write_bytes(b'Image')
        work=self.work/'managed-gui16k-kernel';work.mkdir();(work/'owned').write_text('fixture')
        base=self.work/'base';base.mkdir();out=self.work/'runtime';out.mkdir()
        cleanup=dict(status='PASS',image=dict(id='base',absence_verified=True),probe=dict(absence_verified=True))
        s.save(base/'report.json',dict(owned_cleanup=cleanup,ownership=dict(token='a'*16)))
        report=dict(status=R.AWAITING,controller_runtime_status=R.PASS,job_token='a'*16,
            controller=dict(exit=0,natural_exit=True,group_absent=True),cleanup=[dict(exit=0) for _ in range(13)]+[dict(guest_disk_removed=True)],
            base_reference_cleanup=dict(ok=True),base_image='base',kernel_build=dict(helper=dict(path=str(work/'helper/build_kernel.py'))),
            diagnostic_kernel=dict(Image=dict(sha256=s.sha(b'Image'))))
        args=SimpleNamespace(output=out,base_dir=base,job_token='a'*16,runner=runner,kernel_work=work)
        bad=copy.deepcopy(report);bad['controller']['natural_exit']=False;s.save(out/'runtime.json',bad)
        with patch.dict(os.environ,RUNNER_TEMP=str(self.work)):
            self.assertEqual(R.finalize(args)['status'],'FAIL');self.assertTrue(work.exists());self.assertTrue(image.exists())
            s.save(out/'runtime.json',report);self.assertEqual(R.finalize(args)['status'],R.FINAL)
        self.assertFalse(work.exists());self.assertFalse(image.exists());self.assertTrue(base.exists())

    def public_fixture(self):
        base=self.work/'base';base.mkdir();runtime=self.work/'runtime';runtime.mkdir();(runtime/'frames').mkdir()
        cleanup=dict(status='PASS',image=dict(id='base',absence_verified=True),probe=dict(absence_verified=True))
        original=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',image='base',ownership=dict(token='a'*16),owned_cleanup=cleanup)
        s.save(base/'report.json',original);(base/'installed-packages.lock').write_text('fixture 1\n')
        generated={str(p.relative_to(self.runner)):dict(bytes=p.stat().st_size,sha256=s.sha(p.read_bytes()))
            for p in self.runner.rglob('*') if p.is_file() and p.name!='kernel-profile.json'}
        manifest=self.work/'manifest.json';s.save(manifest,dict(generated_runner=generated))
        proof=self.work/'proof.json';s.save(proof,dict(status='SOURCE_PROOF_PASS',generated_runner='PASS',job_token='a'*16,
            source_sha='b'*40,manifest_sha256=s.sha(manifest.read_bytes())))
        observed=self.contract.verify_result(self.events,self.lock);kernel=profile()
        report=dict(status=R.FINAL,configuration='desktop-container-verifier-pass',workflow_scope='installed-welcome-doctor-managed-gui',
            physical_input='NOT_RUN',candidate_input=self.lock,events=self.events,gui_contract=observed,base_image='base',
            runtime_package_count=593,base_reference_cleanup=dict(ok=True),cleanup=[dict(exit=0) for _ in range(13)]+[dict(guest_disk_removed=True)],
            frames={},diagnostic_kernel=kernel,kernel_config='x',kernel_work_removed=True,runtime_Image_removed=True,producer_cleanup=cleanup,
            job_token='a'*16,source_sha='b'*40,controller=dict(natural_exit=True,group_absent=True,exit=0),controller_runtime_status=R.PASS,
            kernel_build=dict(status='BUILT_ONLY',kernel_build='PASS',profile=K.PROFILE,helper=dict(sha256=K.HELPER_SHA),
                fragment=dict(sha256=K.FRAGMENT_SHA),diagnostic_fragment=dict(sha256=K.DIAGNOSTIC_SHA),
                image=kernel['Image'],config=kernel['config']))
        pixels=b'P6\n1024 768\n255\n'+b'\1\0\0'+b'\0'*(1024*768*3-3)
        for name in self.caller.FRAMES:
            (runtime/'frames'/(name+'.ppm')).write_bytes(pixels);report['frames'][name]=dict(sha256=s.sha(pixels))
        for name in ('guest.log','events.log'):(runtime/name).write_text('synthetic control diagnostics\n')
        names=('usr/bin/cachy-asahi-welcome','usr/bin/python3.14','usr/lib/systemd/systemd','usr/local/bin/gbm-probe','usr/local/bin/welcome-a11y')
        s.save(runtime/'elf16k.json',dict(status='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT',ELF=[dict(path=n) for n in names]))
        report['elf16k']=dict(sha256=s.sha((runtime/'elf16k.json').read_bytes()),ELFs=len(names));s.save(runtime/'runtime.json',report)
        (runtime/'private.raw').write_bytes(b'excluded')
        self.acquisition=self.work/'acquisition.json'
        s.save(self.acquisition,dict(status='RESTORED_HASH_VERIFIED',source_revision=K.REVISION,sha256=K.ARCHIVE,bytes=262965559,
            partial_absent=True,cache_partial_absent=True,result=dict(sha256=K.ARCHIVE,bytes=262965559),
            cache=dict(status='HIT_HASH_VERIFIED',key='asahi-kernel-source-v1-'+K.ARCHIVE+'-262965559')))
        return base,runtime,proof,manifest,report,original

    def test_25_public_retention_replays_derived_contract_and_keeps_pixels_pending(self):
        base,runtime,proof,manifest,_,_=self.public_fixture();out=self.work/'public'
        result=self.caller.retain(base,runtime,proof,out,self.runner,manifest,acquisition=self.acquisition)
        self.assertEqual(result['status'],'PASS_GENERIC16K_INSTALLED_GUI_METADATA_PIXELS_PENDING_VISUAL_REVIEW',result['errors'])
        self.assertEqual(len(result['frames']),14);self.assertEqual(result['visual_review'],'NOT_RUN')
        self.assertFalse((out/'runtime/private.raw').exists())

    def test_26_missing_capture_and_config_drift_refuse_public_acceptance(self):
        base,runtime,proof,manifest,report,_=self.public_fixture();(runtime/'frames/overlay-recovery.ppm').unlink()
        self.assertEqual(self.caller.retain(base,runtime,proof,self.work/'public',self.runner,manifest,acquisition=self.acquisition)['status'],'NOT_ACCEPTED')
        shutil.copyfile(runtime/'frames/minimal-home.ppm',runtime/'frames/overlay-recovery.ppm')
        report['kernel_config']='drift';s.save(runtime/'runtime.json',report)
        self.assertEqual(self.caller.retain(base,runtime,proof,self.work/'public2',self.runner,manifest,acquisition=self.acquisition)['status'],'NOT_ACCEPTED')

    def test_27_generated_runner_drift_and_original_cleanup_refused(self):
        base,runtime,proof,manifest,report,original=self.public_fixture()
        mf=json.loads(manifest.read_text());mf['generated_runner']['contract.py']['sha256']='0'*64;s.save(manifest,mf)
        value=json.loads(proof.read_text());value['manifest_sha256']=s.sha(manifest.read_bytes());s.save(proof,value)
        self.assertEqual(self.caller.retain(base,runtime,proof,self.work/'public',self.runner,manifest,acquisition=self.acquisition)['status'],'NOT_ACCEPTED')
        original['owned_cleanup']['image']['absence_verified']=False;s.save(base/'report.json',original)
        self.assertEqual(self.caller.retain(base,runtime,proof,self.work/'public2',self.runner,manifest,acquisition=self.acquisition)['status'],'NOT_ACCEPTED')


    def test_28_original_4k_doctor_validator_is_preserved(self):
        original=load('control_original_4k_gui',SOURCE/'scripts/ci/welcome-managed-gui/gui_contract.py')
        proof=copy.deepcopy(next(e for e in self.events if e.get('event')=='doctor_result')['proof'])
        proof['doctor']['checks'][0]['value']['page_size_bytes']=4096
        original.validate_doctor(proof,proof['stage'],proof['nonce'],proof['terminal_pid'])
        with self.assertRaises(ValueError):self.contract.C.validate_doctor(proof,proof['stage'],proof['nonce'],proof['terminal_pid'])


    def test_29_gui_resources_deadlines_and_actions_match_accepted_source(self):
        runtime=(self.runner/'desktop574_runtime.py').read_text()
        for value in ('-accel tcg -cpu max -smp 2 -m 4096','format=raw,snapshot=on',
            'deadline = time.monotonic() + 1300','signal.setitimer(signal.ITIMER_REAL, 1750)',
            "execute(cmd + ['/runner/desktop574_fixture.sh'], 'fixture', 600)"):
            self.assertIn(value,runtime)
        self.assertEqual((self.runner/'session.py').read_bytes(),(SOURCE/'scripts/ci/welcome-managed-gui/session.py').read_bytes())
        self.assertIn('session.wait(timeout=1080)',(self.runner/'base_guest.py').read_text())
        self.assertIn('TimeoutStartSec=1200',(self.runner/'desktop574_fixture.sh').read_text())

    def test_30_gui_cache_flow_is_the_canonical_seed_acquire_early_save_sequence(self):
        text=(s.HERE.parents[2]/'.github/workflows/native-arm-managed-gui-generic16k.yml').read_text()
        for action in ('restore','save'):
            self.assertIn('actions/cache/'+action+'@0057852bfaa89a56745cba8c7296529d2fc39830',text)
        self.assertEqual(text.count('key: asahi-kernel-source-v1-'+K.ARCHIVE+'-262965559'),2)
        self.assertNotIn('restore-keys:',text);self.assertNotIn('continue-on-error:',text)
        self.assertLess(text.index('Save verified archive'),text.index('Build only the separately derived'))
        self.assertIn("seed=s.load(root,'scripts/ci/tools-generic16k/retained_kernel.py')",text)
        self.assertIn('cache_hit=os.environ',text);self.assertIn('cache_matched_key=os.environ',text)
        self.assertIn('retained_archive=os.environ',text)
        self.assertIn('30s 2050s',text);self.assertNotIn('2130s',text)

    def test_31_missing_or_wrong_acquisition_receipt_cannot_earn_gui_acceptance(self):
        base,runtime,proof,manifest,_,_=self.public_fixture()
        acquired=json.loads(self.acquisition.read_text());acquired['sha256']='0'*64;s.save(self.acquisition,acquired)
        result=self.caller.retain(base,runtime,proof,self.work/'public',self.runner,manifest,acquisition=self.acquisition)
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertTrue(any('acquisition/receipt join' in e for e in result['errors']))
        self.acquisition.unlink()
        result=self.caller.retain(base,runtime,proof,self.work/'public2',self.runner,manifest,acquisition=self.acquisition)
        self.assertEqual(result['status'],'NOT_ACCEPTED')


    def test_32_true_miss_seed_and_direct_fallback_receipts_preserve_exact_scope(self):
        base,runtime,proof,manifest,_,_=self.public_fixture();acquired=json.loads(self.acquisition.read_text())
        seed=self.work/'seed.json'
        common=dict(asset_id=647949735,release_id=415175342,expected_sha256=K.ARCHIVE,expected_bytes=262965559,
            natural_exit=True,group_absent=True,partial_absent=True,release_admission=False,release_draft=False,release_prerelease=True)
        acquired['status']='RETAINED_ARCHIVE_HASH_VERIFIED';acquired['cache']['status']='MISS_RETAINED_ARCHIVE_HASH_VERIFIED'
        s.save(self.acquisition,acquired);s.save(seed,common|dict(status='RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED',exit=0,sha256=K.ARCHIVE,bytes=262965559))
        result=self.caller.retain(base,runtime,proof,self.work/'public',self.runner,manifest,acquisition=self.acquisition,seed=seed)
        self.assertEqual(result['status'],'PASS_GENERIC16K_INSTALLED_GUI_METADATA_PIXELS_PENDING_VISUAL_REVIEW',result['errors'])
        acquired['status']='FETCHED_HASH_VERIFIED';acquired['cache']['status']='MISS_FETCHED_HASH_VERIFIED'
        s.save(self.acquisition,acquired);s.save(seed,common|dict(status='RETAINED_ASSET_UNAVAILABLE',exit=1))
        result=self.caller.retain(base,runtime,proof,self.work/'public2',self.runner,manifest,acquisition=self.acquisition,seed=seed)
        self.assertEqual(result['status'],'PASS_GENERIC16K_INSTALLED_GUI_METADATA_PIXELS_PENDING_VISUAL_REVIEW',result['errors'])
        s.save(seed,common|dict(status='RETAINED_ASSET_UNAVAILABLE',exit=1,asset_id=1))
        result=self.caller.retain(base,runtime,proof,self.work/'public3',self.runner,manifest,acquisition=self.acquisition,seed=seed)
        self.assertEqual(result['status'],'NOT_ACCEPTED')


    def test_33_full_staged_audit_cannot_skip_an_unreadable_subtree(self):
        if os.geteuid()==0:self.skipTest('permission fixture requires the ordinary CI user')
        (self.work/'native').write_bytes(fake_elf());hidden=self.work/'unreadable';hidden.mkdir()
        (hidden/'incompatible').write_bytes(fake_elf(4096));hidden.chmod(0)
        try:
            with self.assertRaises(PermissionError):E.audit(self.work,self.reader)
        finally:hidden.chmod(0o700)


    def test_34_systemd_locking_is_builtin_and_old_or_modular_profiles_refused(self):
        config=self.work/'locking.config';text=(s.HERE/'kernel.fragment').read_text()+self.helper.DIAGNOSTIC_FRAGMENT
        config.write_text(text);self.helper.config_check(config,True)
        for replacement in ('','# CONFIG_FILE_LOCKING is not set','CONFIG_FILE_LOCKING=n','CONFIG_FILE_LOCKING=m'):
            config.write_text(text.replace('CONFIG_FILE_LOCKING=y',replacement))
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'CONFIG_FILE_LOCKING'):
                self.helper.config_check(config,True)
        old=profile()|dict(fragment_sha256='1394b2b622c047aa689d56e48cc4bcf3ef23ff814e595f988c0b350a89eeb2c3')
        with self.assertRaises(ValueError):K.validate(old)

    def test_35_draft_or_nonprerelease_seed_cannot_claim_the_current_public_transport(self):
        base,runtime,proof,manifest,_,_=self.public_fixture();acquired=json.loads(self.acquisition.read_text())
        acquired['status']='RETAINED_ARCHIVE_HASH_VERIFIED';acquired['cache']['status']='MISS_RETAINED_ARCHIVE_HASH_VERIFIED';s.save(self.acquisition,acquired)
        seed=self.work/'seed.json';common=dict(asset_id=647949735,release_id=415175342,expected_sha256=K.ARCHIVE,expected_bytes=262965559,
            natural_exit=True,group_absent=True,partial_absent=True,release_admission=False,status='RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED',
            exit=0,sha256=K.ARCHIVE,bytes=262965559,release_draft=False,release_prerelease=True)
        for index,change in enumerate((dict(release_draft=True),dict(release_prerelease=False))):
            s.save(seed,common|change)
            result=self.caller.retain(base,runtime,proof,self.work/('bad-seed-'+str(index)),self.runner,manifest,acquisition=self.acquisition,seed=seed)
            self.assertEqual(result['status'],'NOT_ACCEPTED')


    def test_36_copied_contract_stale_or_missing_pin_refused_before_source_proof(self):
        name=self.caller.SLICE+'/kernel_contract.py';row=dict(bytes=4659,sha256='a'*64)
        good=dict(files={name:row},generated_runner={'kernel_contract.py':dict(row)})
        self.caller.verify_kernel_contract_pin(good)
        for changed in ({'bytes':4659,'sha256':'b'*64},{'bytes':1,'sha256':'a'*64},None):
            bad=copy.deepcopy(good)
            if changed is None:bad['generated_runner'].pop('kernel_contract.py')
            else:bad['generated_runner']['kernel_contract.py']=changed
            with self.subTest(changed=changed),self.assertRaisesRegex(ValueError,'source/generated pins differ'):
                self.caller.verify_kernel_contract_pin(bad)
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        with patch.object(self.caller,'verify_files'),self.assertRaisesRegex(ValueError,'source/generated pins differ'):
            self.caller.prove(self.work,bad,env)

    def test_37_generated_contract_bytes_still_checked_after_consistent_pin(self):
        target=self.work/'kernel_contract.py';shutil.copyfile(self.runner/'kernel_contract.py',target)
        row=dict(bytes=target.stat().st_size,sha256=s.sha(target.read_bytes()))
        self.caller.verify_files(self.work,{'kernel_contract.py':row})
        target.write_bytes(target.read_bytes()+b'\n# drift\n')
        with self.assertRaisesRegex(ValueError,'source pin differs: kernel_contract.py'):
            self.caller.verify_files(self.work,{'kernel_contract.py':row})


    def test_38_glycin_sandbox_kernel_requirements_are_built_in(self):
        # --unshare-all initializes IPv4 loopback even in an isolated network.
        text=(s.HERE/'kernel.fragment').read_text()+self.helper.DIAGNOSTIC_FRAGMENT
        path=self.work/'sandbox.config';path.write_text(text);self.helper.config_check(path,True)
        for name in ('NET','INET','UNIX','NAMESPACES','USER_NS','UTS_NS','IPC_NS','PID_NS',
                     'NET_NS','CGROUPS','SYSVIPC','PROC_FS','TMPFS','UNIX98_PTYS',
                     'MULTIUSER','SECCOMP','SECCOMP_FILTER'):
            line='CONFIG_'+name+'=y\n';self.assertEqual(text.count(line),1)
            for value in ('n','m',None):
                with self.subTest(name=name,value=value):
                    replacement='' if value is None else 'CONFIG_'+name+'='+value+'\n'
                    path.write_text(text.replace(line,replacement))
                    with self.assertRaisesRegex(ValueError,'generated configuration differs: CONFIG_'+name):
                        self.helper.config_check(path,True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--assets',type=Path,required=True)
    args=parser.parse_args();SOURCE=args.source.resolve();ASSETS=args.assets.resolve()
    unittest.main(argv=[sys.argv[0]],verbosity=2)
