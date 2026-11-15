#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced source/config DATA controls. No compiler, daemon or guest."""
import copy,hashlib,importlib.util,json,os,shutil,socket,struct,subprocess,sys,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
HERE=Path(__file__).resolve().parent

def denied(*a,**kw):raise AssertionError('runtime actor forbidden in source controls')
for name in ('Popen','run','call','check_call','check_output'):setattr(subprocess,name,denied)
for name in ('system','fork','forkpty','execv','execve','posix_spawn','posix_spawnp'):
 if hasattr(os,name):setattr(os,name,denied)
socket.socket=denied
s=importlib.util.spec_from_file_location('ui_contract',HERE/'contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
class Contract(unittest.TestCase):
 def setUp(self):
  self.ref,self.receipt=C.reference();self.raw=C.overlay(self.ref,C.changes());self.facts=self.receipt['config_proof']['compiler_facts']
 def test_source_pins(self):C.verify()
 def test_dependencies(self):self.assertEqual(C.dependencies()['missing_builtin'],'CONFIG_VIRTIO_INPUT=y')
 def test_two_only_effective_changes(self):self.assertEqual(set(C.delta(self.ref,self.raw)),{'CONFIG_LOCALVERSION','CONFIG_VIRTIO_INPUT'})
 def test_construct_inverse(self):self.assertEqual(C.inverse(C.construct(C.data())),C.data())
 def test_tampered_inverse(self):
  with self.assertRaises(ValueError):C.inverse(C.construct(C.data())+b'CONFIG_FAKE=y\n')
 def test_wrong_baseline(self):
  with self.assertRaises(ValueError):C.construct(self.ref)
 def test_full_final_positive(self):self.assertTrue(C.final_config(self.raw,self.facts)['non_ui_seat_features_unchanged'])
 def test_wrong_release(self):self.refuse({'CONFIG_LOCALVERSION':'"-generic16k-managed-gui-rtc1"'})
 def test_missing_input(self):self.refuse({'CONFIG_VIRTIO_INPUT':'n'})
 def test_module_input(self):self.refuse({'CONFIG_VIRTIO_INPUT':'m'})
 def test_original_translation_policy_held(self):self.assertEqual(C.values(self.raw).get('CONFIG_CONSOLE_TRANSLATIONS','n'),C.values(self.ref).get('CONFIG_CONSOLE_TRANSLATIONS','n'))
 def test_fourk(self):self.refuse({'CONFIG_ARM64_16K_PAGES':'n'})
 def test_rtc_removed(self):self.refuse({'CONFIG_RTC_DRV_PL031':'n'})
 def test_evdev_removed(self):self.refuse({'CONFIG_INPUT_EVDEV':'n'})
 def test_vt_removed(self):self.refuse({'CONFIG_VT':'n'})
 def test_drm_removed(self):self.refuse({'CONFIG_DRM_VIRTIO_GPU':'n'})
 def test_pc_i8042(self):self.refuse({'CONFIG_SERIO_I8042':'y'})
 def test_unrelated_bus(self):self.refuse({'CONFIG_I2C':'n'})
 def test_new_unknown_feature(self):
  with self.assertRaises(ValueError):C.final_config(self.raw+b'CONFIG_UNREVIEWED=y\n',self.facts)
 def test_new_compiler_probe(self):
  facts=copy.deepcopy(self.facts);facts['CONFIG_CC_UNKNOWN']={'before':'n','after':'y'}
  with self.assertRaises(ValueError):C.final_config(self.raw,facts)
 def test_wrong_compiler_before(self):
  facts=copy.deepcopy(self.facts);facts['CONFIG_CLANG_VERSION']['before']='220108'
  with self.assertRaises(ValueError):C.final_config(self.raw,facts)
 def test_missing_compiler_fact(self):
  facts=copy.deepcopy(self.facts);facts.pop('CONFIG_CLANG_VERSION')
  with self.assertRaises(ValueError):C.final_config(self.raw,facts)
 def test_duplicate(self):
  with self.assertRaises(ValueError):C.values(self.raw+b'CONFIG_VIRTIO_INPUT=y\n')
 def refuse(self,changes):
  with self.assertRaises(ValueError):C.final_config(C.overlay(self.raw,changes),self.facts)
 def test_frozen_build_only_five_declared_edits(self):
  old=(HERE/'frozen/rtc/build.py').read_text()
  expected=old.replace("HERE/'toolchain.py'","HERE/'frozen/rtc/toolchain.py'").replace("Path('/work/rtc-kernel')","Path('/work/ui-seat-kernel')").replace("'rtc-reference-new-toolchain'","'ui-seat-reference-new-toolchain'").replace("'BUILT_ONLY_RTC_BOOT_NOT_RUN'","'BUILT_ONLY_UI_SEAT_BOOT_NOT_RUN'").replace('Root-admitted two-stage build only.','Separate UI-seat operation; frozen RTC two-stage build logic.')
  self.assertEqual((HERE/'build.py').read_text(),expected)
 def test_build_no_automatic_actor(self):
  s=importlib.util.spec_from_file_location('ui_build',HERE/'build.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
  self.assertTrue(callable(m.main));self.assertTrue(callable(m.owned_command))
 def test_owned_supervision_and_firstfailure_retained(self):
  text=(HERE/'build.py').read_text();self.assertIn('raise refusal',text);self.assertIn('retain_image(C,',text);self.assertIn("out/'observed.config'",text)
 def test_plan(self):C.device_plan(json.loads((HERE/'device-plan.json').read_text()))
 def test_no_pci_keyboard(self):self.badplan('device_args',['-device','virtio-keyboard-pci','-device','virtio-gpu-device'])
 def test_no_host_input(self):self.badplan('host_input_passthrough',True)
 def test_no_native_seat_claim(self):self.badplan('actual_seat0','PASS')
 def test_no_kvm(self):self.badplan('KVM',True)
 def badplan(self,k,v):
  p=json.loads((HERE/'device-plan.json').read_text());p[k]=v
  with self.assertRaises(ValueError):C.device_plan(p)
 def test_header_bss_positive_and_new_bundle_identity(self):
  with tempfile.TemporaryDirectory() as d:
   image=Path(d)/'Image';raw=bytearray(256);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,16,128*1024**2);struct.pack_into('<Q',raw,24,12);image.write_bytes(raw);config=Path(d)/'config';config.write_bytes(self.raw)
   b=C.bundle(image,config,{'compiler_facts':self.facts,'mode':'HOST_CROSS_ARM64'},'a'*64,{},[],'NOT RUN MODEL','NOT RUN MODEL')
   self.assertEqual(b['kind'],'ARM16K_UI_SEAT_REFERENCE_KERNEL_BUNDLE_V1');self.assertEqual(b['status'],'BUILT_ONLY_UI_SEAT_BOOT_NOT_RUN');self.assertFalse(b['release_accepted']);self.assertEqual(C.header(image)['page_size'],16384)
 def test_wrong_header_flags(self):
  with tempfile.TemporaryDirectory() as d:
   image=Path(d)/'Image';raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,16,256)
   for flags in (0,2,5,13):
    struct.pack_into('<Q',raw,24,flags);image.write_bytes(raw)
    with self.assertRaises(ValueError):C.header(image)
 def test_changed_pinned_source_refuses(self):self.badfile('data/virtio.Kconfig','changed')
 def test_missing_pinned_source_refuses(self):self.badfile('data/virtio-input.c','missing')
 def test_changed_frozen_supervisor_refuses(self):self.badfile('frozen/rtc/build.py','changed')
 def test_symlink_source_refuses(self):self.badfile('data/virtio.Kconfig','symlink')
 def badfile(self,name,action):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)/'recipe';shutil.copytree(HERE,root);p=root/name
   if action=='changed':p.write_bytes(p.read_bytes()+b'\nchanged\n')
   else:
    p.unlink()
    if action=='symlink':p.symlink_to(HERE/name)
   with patch.object(C,'HERE',root):
    with self.assertRaises(ValueError):C.verify()
 def test_source_only_pending(self):
  for key in ('configure','compile','guest_boot','Root_resource_authority'):self.assertIsNone(C.spec()[key])
if __name__=='__main__':
 if not (__debug__ and sys.flags.isolated):raise RuntimeError('isolated assertions required')
 unittest.main()
