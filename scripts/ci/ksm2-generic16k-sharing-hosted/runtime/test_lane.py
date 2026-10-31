#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/refusal and private regular-file controls; never accepting boot evidence."""
import argparse,ast,copy,importlib.machinery,importlib.util,json,os,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import contract as C,guest as G,host as H,media_adapter as M,prepare_driver as P,kernel_input as K

def product():
 p=HERE/'native-source/packages/tools/cachy-asahi-ksmctl2/cachy-asahi-ksm-experiment';loader=importlib.machinery.SourceFileLoader('_ksm_vm_test_product',str(p));spec=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m);return m

class SourceTests(unittest.TestCase):
 def test_closed_source_and_all_borrowed_files(self):
  rows=C.source_check();self.assertGreater(len(rows),580);self.assertGreater(len(C.support()),580)
 def test_default_refuses_before_input_or_process(self):
  s=C.decode(C.read(HERE/'input-policy.json'))
  with patch.object(C,'read',side_effect=AssertionError('no input IO')),patch.object(subprocess,'Popen',side_effect=AssertionError('no process')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.gate(s,'/unsupplied')
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.native_gate(s,'/unsupplied')
   with self.assertRaisesRegex(ValueError,'UNBOUND'):K.imported(s,'/unsupplied')
 def test_guest_outside_actual_pid1_or_child_refuses(self):
  with self.assertRaisesRegex(ValueError,'actual private generic16K'):C.guest_guard(dict(nonce='0'*32))
 def test_duplicate_nonfinite_and_reference_escape(self):
  for raw in(b'{"a":0,"a":1}',b'{"a":NaN}'):
   with self.assertRaises(ValueError):C.decode(raw)
  for name in('../x','/x','a//b','a/./b','a\\b','a\0b'):
   with self.assertRaises(ValueError):C.relative(name)
 def test_borrowed_whole_media_semantics_inverse(self):
  original=C.read(HERE/M.DONOR/'disk.py',256*1024).decode();changed=M.derived_disk(HERE).decode();inverse=changed.replace('init-ksm2','init-updater16k').replace("'-L','KSM2_'","'-L','APPS6_'").replace("'mount -t sysfs -o rw,nosuid,nodev,noexec sysfs /sys'","'mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys'").replace("target.mkdir();shutil.copyfile(source/'source-files.json',target/'source-files.json')","target.mkdir()").replace("('/out','/measurement')","('/out','/measurement','/upgrade-signing')")
  for path in('scripts/apps/file_capabilities.py','scripts/ci/managed-gui-generic16k/elf_audit.py','scripts/virtual/generic16k/fixture.py'):inverse=inverse.replace('/source/media-source/'+path,'/source/'+path)
  self.assertEqual(inverse,original)
 def test_original_guest_isolation_only_source_paths_differ(self):
  text=C.read(HERE/M.DONOR/'guest.py',256*1024).decode();source=ast.get_source_segment(text,next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='isolate'));self.assertIn('helper.reduce_capabilities()',source);self.assertIn("prctl(22,2",source);self.assertEqual(M.WORKER_MASK,0x800400fb);self.assertEqual(M.PREPARE_MASK,0x8000001b)
 def test_whole_historical_kernel_profile_four_inputs(self):
  KP=C.load('_ksm_profile_controls',HERE/'profile/ksm_profile.py')
  for name in KP.PINS:KP.held(HERE/'kernel-source',name)
  self.assertEqual(KP.fragment(KP.held(HERE/'kernel-source','kernel.fragment')),KP.held(HERE/'kernel-source','kernel.fragment')+b'CONFIG_KSM=y\nCONFIG_ADVISE_SYSCALLS=y\n')
 def test_prepare_argv_actual_five_caps_no_host_bus_sysfs(self):
  name,argv=P.argv('sha256:'+'a'*64,'b'*32,Path('/source-own'),Path('/work-own'),Path('/inputs-own'),Path('/disks-own'));self.assertIn('--network=none',argv);self.assertIn('--cap-drop=ALL',argv);self.assertIn('--security-opt=no-new-privileges',argv);self.assertEqual([a for a in argv if a.startswith('--cap-add=')],['--cap-add='+n for n in P.CAPS]);self.assertFalse(any('SYS_ADMIN'in a or 'SYS_PTRACE'in a or 'privileged'in a for a in argv));self.assertEqual(sum('dst=/measurement'in a for a in argv),1);self.assertFalse(any('src=/sys,'in a or '/run/dbus'in a for a in argv))
 def test_qemu_argv_no_network_and_exact_guest_marker(self):
  cmd=H.qemu(Path('/Image'),Path('/boot'),Path('/data'),'c'*32,1767225600000000000);self.assertEqual(cmd[cmd.index('-nic')+1],'none');self.assertIn('arm64.nomops',cmd[cmd.index('-append')+1]);self.assertIn('init=/init-ksm2',cmd[cmd.index('-append')+1]);self.assertNotIn('host',cmd);self.assertEqual(C.SHARED_SECONDS,3000);self.assertEqual(C.PRODUCT_SECONDS,5)
 def test_protocol_refuses_no_boot_failed_or_old_page(self):
  for raw in(b'',b'KSM2_VM_ERROR failed\n',b'KSM2_VM '+'0'.encode()*32+b' {"page_size":4096}\n'):
   with self.assertRaises(ValueError):H.protocol(raw,dict(nonce='0'*32),dict(release='unsupplied'),1767225600000000000)
 def test_root_future_contracts_not_acceptance(self):
  for name in('native','kernel'):
   v=C.decode(C.read(HERE/(name+'-decision-contract.json')));self.assertIsNone(v['actual_acceptance']);self.assertIn('NOT_ACCEPTANCE',v['status'])
 def test_actual_sysfs_primitive_refuses_ordinary_model(self):
  with tempfile.TemporaryDirectory(prefix='ksm-vm-refuse-')as tmp:
   p=Path(tmp)/'run';p.write_bytes(b'0\n')
   with patch.object(G,'RUN',p):
    with self.assertRaisesRegex(ValueError,'actual sysfs'):G.scalar()
   self.assertEqual(p.read_bytes(),b'0\n')
 def test_real_private_model_apply_conflict_and_exact_undo(self):
  # Real shipped helper API on owned regular files; not VM/sysfs evidence.
  E=product()
  with tempfile.TemporaryDirectory(prefix='ksm-vm-model-')as tmp:
   root=Path(tmp);ksm=root/'ksm';boot=root/'boot';ksm.mkdir(mode=0o700);boot.mkdir(mode=0o700);run=ksm/'run';run.write_text('0\n');(boot/'boot_id').write_text('11111111-2222-4333-8444-555555555555\n');store=root/'state';control=E.Control(ksm,boot,model=True)
   for name in('restore','conflict'):
    plan=E.preview(control,store,name,1);digest=plan['plan_sha256'];applied=E.operate(control,store,name,'apply',digest);self.assertEqual(applied['current'],1);self.assertEqual(E.operate(control,store,name,'inspect')['phase'],'APPLIED')
    if name=='conflict':
     run.write_text('0\n');before={p.name:p.read_bytes()for p in(store/name).iterdir()}
     with self.assertRaisesRegex(ValueError,'conflict preserved'):E.operate(control,store,name,'undo',digest)
     self.assertEqual(before,{p.name:p.read_bytes()for p in(store/name).iterdir()});run.write_text('1\n')
    self.assertEqual(E.operate(control,store,name,'undo',digest)['phase'],'UNDONE');self.assertEqual(run.read_text(),'0\n')
    self.assertEqual(json.loads((store/name/'journal.json').read_bytes())['phase'],'UNDONE')
   self.assertEqual(set(p.name for p in store.iterdir()),{'.lock','restore','conflict'})
 def test_receipt_projection_changes_only_two_paths_and_keeps_original(self):
  original=dict(image=dict(path='/original/Image',bytes=2,sha256='a'*64),config=dict(path='/original/config',bytes=3,sha256='b'*64),helper=dict(path='/original/helper',sha256='c'*64),other=dict(nested=[1,2]));held=copy.deepcopy(original);v=K.project_paths(original,Path('/import'));self.assertEqual(original,held);self.assertEqual(v['helper'],held['helper']);self.assertEqual(v['other'],held['other']);self.assertEqual(v['image']['path'],'/import/Image');self.assertEqual(v['config']['path'],'/import/config')
 def test_explicit_zero_length_stream_pin_only(self):
  with tempfile.TemporaryDirectory(prefix='ksm-empty-')as tmp:
   p=Path(tmp)/'stderr';p.write_bytes(b'');row=dict(path='stderr',**C.pin(b''))
   with self.assertRaises(ValueError):C.checked(tmp,row)
   self.assertEqual(C.checked(tmp,row,allow_empty=True),b'')
 def test_declared_future_root_native_schema_refuses_as_actual(self):
  value=C.decode(C.read(HERE/'native-decision-contract.json'))
  with self.assertRaisesRegex(ValueError,'foreign acceptance'):C.native_record(value,'0'*40,1)
 def test_real_invalid_image_header_is_refused(self):
  KP=C.load('_ksm_bad_header_profile',HERE/'profile/ksm_profile.py');H=KP.helper(HERE/'kernel-source')
  with tempfile.TemporaryDirectory(prefix='ksm-bad-header-')as tmp:
   p=Path(tmp)/'Image';p.write_bytes(b'\0'*64)
   with self.assertRaisesRegex(ValueError,'ARM64 Image header'):H.image_check(p)
 def test_workflow_environment_is_mandatory_not_source_strings_only(self):
  with patch.dict(os.environ,{},clear=True):
   with self.assertRaisesRegex(ValueError,'workflow environment'):C.actual_environment(dict(VM_source='a'*40,VM_ref='codex/local-data-only',VM_run=1))
 def test_unknown_state_never_deleted(self):
  with tempfile.TemporaryDirectory(prefix='ksm-vm-unknown-')as tmp:
   store=Path(tmp)/'state';store.mkdir(mode=0o700);(store/'foreign').write_text('keep')
   with patch.object(G,'STORE',store):
    with self.assertRaisesRegex(ValueError,'only own'):G.cleanup_store([],{})
   self.assertEqual((store/'foreign').read_text(),'keep')
 def test_media_retained_when_group_absence_unknown(self):
  with tempfile.TemporaryDirectory(prefix='ksm-vm-lease-')as tmp:
   p=Path(tmp)/'media';p.mkdir();(p/'foreign').write_text('keep')
   with self.assertRaisesRegex(ValueError,'group absence unknown'):H.retire_media(p,{}, {},dict(group_absence_verified=False))
   self.assertTrue((p/'foreign').exists())

if __name__=='__main__':unittest.main()
