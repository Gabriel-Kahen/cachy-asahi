#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RTC source/DATA controls; kernel scripts, compilers and actors are fenced."""
import ast,contextlib,ctypes,hashlib,importlib.util,json,os,signal,socket,struct,subprocess,tarfile,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent


def load(name):
 spec=importlib.util.spec_from_file_location('rtc_test_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


C=load('contract');T=load('toolchain');B=load('build')


class Controls(unittest.TestCase):
 def test_exact_original_pin(self):self.assertEqual(C.pin(HERE/'data/baseline.config')['sha256'],'e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b')
 def test_whole_byte_inverse(self):self.assertEqual(C.inverse(C.construct(C.data())),C.data())
 def test_eight_effective_changes_only(self):
  self.assertEqual(set(C.delta(C.data(),C.construct(C.data()))),{'CONFIG_LOCALVERSION','CONFIG_RTC_CLASS','CONFIG_RTC_LIB','CONFIG_RTC_HCTOSYS','CONFIG_RTC_HCTOSYS_DEVICE','CONFIG_RTC_INTF_SYSFS','CONFIG_RTC_DRV_PL031','CONFIG_RTC_I2C_AND_SPI'})
 def test_nvmem_and_clock_write_defaults_disabled(self):
  v=C.values(C.construct(C.data()))
  for key in ('CONFIG_RTC_NVMEM','CONFIG_RTC_SYSTOHC','CONFIG_RTC_INTF_PROC','CONFIG_RTC_INTF_DEV'):self.assertEqual(v[key],'n')
 def test_original_not_mutated(self):self.assertEqual(C.values(C.data())['CONFIG_RTC_CLASS'],'n')
 def test_wrong_original_refused(self):
  with self.assertRaises(ValueError):C.construct(C.data()+b'\n')
 def test_changed_inverse_refused(self):
  with self.assertRaises(ValueError):C.inverse(C.construct(C.data())+b'\n')
 def test_prompted_off_seeds_append_and_replace_without_duplicates(self):
  raw=b'# CONFIG_ARM64_LSUI is not set\nCONFIG_WARN_CONTEXT_ANALYSIS=n\n';seed=C.seed_off(raw);self.assertEqual(C.values(seed),C.BASELINE_OFF);self.assertEqual(seed.count(b'CONFIG_ARM64_LSUI'),1);self.assertEqual(seed.count(b'CONFIG_WARN_CONTEXT_ANALYSIS'),1)
  self.assertEqual(C.values(C.seed_off(b'')),C.BASELINE_OFF)
  self.assertEqual(C.values(C.seed_off(b'CONFIG_LOCALVERSION="held"')),{**C.BASELINE_OFF,'CONFIG_LOCALVERSION':'"held"'})
 def test_off_seed_requires_original_semantic_n(self):
  with self.assertRaises(ValueError):C.seed_off(b'CONFIG_ARM64_LSUI=y\n')
 def test_disabled_runtime_feature_cannot_be_compiler_fact(self):
  for key in C.BASELINE_OFF:
   with self.subTest(key=key),self.assertRaises(ValueError):C.final_config(C.construct(C.data()),{key:{'before':'n','after':'y'}})
 def test_explicit_cc_has_prefix_is_not_an_exemption(self):
  with self.assertRaises(ValueError):C.final_config(C.construct(C.data())+b'CONFIG_CC_HAS_UNAUDITED_PROBE=y\n',{'CONFIG_CC_HAS_UNAUDITED_PROBE':{'before':'n','after':'y'}})
 def test_exact_observed_fifteen_probe_definitions(self):
  p=json.loads((HERE/'data/configure-r2-facts.json').read_text());self.assertEqual(len(p['observed_delta']),18);self.assertEqual(set(p['genuine_compiler_auxiliary_facts']),C.COMPILER_NAMES);self.assertEqual(len(C.COMPILER_NAMES),15);self.assertEqual(p['derived_RTC_helper']['selects_or_implies'],[]);self.assertFalse(p['derived_RTC_helper']['Makefile_object_binding'])
 def test_original_kconfig_builtin_closure(self):self.assertTrue(C.dependencies()['existing_dependencies_held'])
 def test_held_16k_mmio_ext4_modules(self):
  v=C.values(C.construct(C.data()))
  for k in ('CONFIG_ARM64_16K_PAGES','CONFIG_ARM_AMBA','CONFIG_VIRTIO_MMIO','CONFIG_EXT4_FS','CONFIG_UNIX98_PTYS'):self.assertEqual(v[k],'y')
  self.assertEqual(v.get('CONFIG_MODULES','n'),'n')
 def test_builtin_driver_not_module(self):
  raw=C.construct(C.data()).replace(b'CONFIG_RTC_DRV_PL031=y',b'CONFIG_RTC_DRV_PL031=m')
  with self.assertRaises(ValueError):C.final_config(raw,{})
 def test_wrong_clock_device_refused(self):
  with self.assertRaises(ValueError):C.final_config(C.construct(C.data()).replace(b'"rtc0"',b'"rtc1"'),{})
 def test_non_rtc_feature_drift_refused(self):
  with self.assertRaises(ValueError):C.final_config(C.construct(C.data()).replace(b'CONFIG_EXT4_FS=y',b'# CONFIG_EXT4_FS is not set'),{})
 def test_modules_cannot_be_whitelisted_as_compiler_fact(self):
  with self.assertRaises(ValueError):C.final_config(C.construct(C.data()),{'CONFIG_MODULES':{'before':'n','after':'y'}})
 def test_unprofiled_compiler_drift_refused(self):
  raw=C.construct(C.data()).replace(b'CONFIG_CLANG_VERSION=180103',b'CONFIG_CLANG_VERSION=220108')
  with self.assertRaises(ValueError):C.final_config(raw,{})
 def test_explicit_reviewed_compiler_fact(self):
  raw=C.construct(C.data()).replace(b'CONFIG_CLANG_VERSION=180103',b'CONFIG_CLANG_VERSION=220108');facts={'CONFIG_CLANG_VERSION':{'before':'180103','after':'220108'}}
  self.assertEqual(C.final_config(raw,facts)['compiler_facts'],facts)
 def test_wrong_compiler_before_refused(self):
  with self.assertRaises(ValueError):C.final_config(C.construct(C.data()),{'CONFIG_CLANG_VERSION':{'before':'wrong','after':'220108'}})
 def test_no_generic_compiler_prefix_exemption(self):
  with self.assertRaises(ValueError):C.final_config(C.construct(C.data())+b'CONFIG_CC_NEW_UNKNOWN=y\n',{})
 def test_duplicate_assignment_refused(self):
  with self.assertRaises(ValueError):C.values(b'CONFIG_RTC_CLASS=y\nCONFIG_RTC_CLASS=n\n')
 def test_malformed_assignment_refused(self):
  with self.assertRaises(ValueError):C.values(b'CONFIG_bad-symbol=y\n')
 def test_correct_image_header(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'Image';raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);struct.pack_into('<Q',raw,16,64);p.write_bytes(raw);self.assertEqual(C.header(p)['page_size'],16384)
 def test_4k_or_big_endian_header_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'Image'
   for flags in (2,5):
    raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,flags);p.write_bytes(raw)
    with self.assertRaises(ValueError):C.header(p)
 def test_bss_effective_span_larger_than_file_is_valid(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'Image';raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);struct.pack_into('<Q',raw,16,128*1024**2);p.write_bytes(raw);self.assertEqual(C.header(p)['effective_image_size'],128*1024**2)
 def test_zero_and_over_cap_effective_span_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'Image'
   for span in (0,128*1024**2+1):
    raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);struct.pack_into('<Q',raw,16,span);p.write_bytes(raw)
    with self.subTest(span=span),self.assertRaises(ValueError):C.header(p)
 def test_wrong_magic_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'Image';p.write_bytes(bytes(64))
   with self.assertRaises(ValueError):C.header(p)
 def test_over_cap_image_file_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'Image';raw=bytearray(64);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,24,4);struct.pack_into('<Q',raw,16,64);p.write_bytes(raw)
   with p.open('ab') as stream:stream.truncate(C.IMAGE_FILE_CAP+1)
   with self.assertRaises(ValueError):C.header(p)
 def test_rejected_image_and_raw_decoded_header_retained_before_validation(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);image=root/'Image';image.write_bytes(bytes(64));out=root/'output';out.mkdir();retained,fields=B.retain_image(C,image,out)
   with self.assertRaises(ValueError):C.header(retained)
   self.assertEqual(retained.read_bytes(),image.read_bytes());self.assertEqual((out/'image-header.bin').read_bytes(),bytes(64));self.assertEqual(json.loads((out/'image-header.json').read_text()),fields);self.assertFalse((out/'bundle').exists())
 def test_total_output_budget_refuses_copy_but_retains_header(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);image=root/'Image';image.write_bytes(bytes(64));out=root/'output';out.mkdir()
   with (out/'other').open('wb') as stream:stream.truncate(C.IMAGE_FILE_CAP)
   with self.assertRaises(ValueError):B.retain_image(C,image,out)
   self.assertTrue((out/'image-header.bin').is_file());self.assertTrue((out/'image-header.json').is_file());self.assertFalse((out/'observed-Image').exists())
 def test_exact_upstream_effective_memory_span_evidence(self):
  self.assertIn('_kernel_size_le, _end - _text',(HERE/'data/arm64-image.h').read_text());lds=(HERE/'data/arm64-vmlinux.lds.S').read_text();self.assertLess(lds.index('_edata = .;'),lds.index('BSS_SECTION(SBSS_ALIGN'));self.assertLess(lds.index('BSS_SECTION(SBSS_ALIGN'),lds.index('\n\t_end = .;'));self.assertIn('Effective Image size',(HERE/'data/arm64-booting.rst').read_text())
 def test_pending_tool_profile_refused(self):
  p=HERE/'tool-profile.template.json'
  with self.assertRaisesRegex(ValueError,'pending'):T.profile(p,C.pin(p)['sha256'],C)
 def test_environment_stable_across_fact_review(self):
  p={k:{} for k in ('tools','runtime_files','packages')};p.update(mode='HOST_CROSS_ARM64',host_architecture='x86_64',target_architecture='arm64',image_id='sha256:'+'a'*64);before=T.environment(p);p['compiler_facts']={'CONFIG_CLANG_VERSION':{'before':'180103','after':'220108'}};self.assertEqual(T.environment(p),before)
 def test_environment_changes_with_actual_tool(self):
  p={k:{} for k in ('tools','runtime_files','packages')};p.update(mode='HOST_CROSS_ARM64',host_architecture='x86_64',target_architecture='arm64',image_id='sha256:'+'a'*64);before=T.environment(p);p['tools']['clang']={'sha256':'b'*64};self.assertNotEqual(T.environment(p),before)
 def test_environment_binds_usr_domain_and_loader_cache(self):
  p={k:{} for k in ('tools','runtime_files','packages')};p.update(mode='HOST_CROSS_ARM64',host_architecture='x86_64',target_architecture='arm64',image_id='sha256:'+'a'*64);before=T.environment(p);p['runtime_domain']='HOST_USR_READONLY_BIND_V1';self.assertNotEqual(T.environment(p),before);before=T.environment(p);p['ld_cache']={'sha256':'b'*64};self.assertNotEqual(T.environment(p),before)
 def test_fresh_host_guard_does_not_change_same_environment(self):
  p={k:{} for k in ('tools','runtime_files','packages')};p.update(mode='HOST_CROSS_ARM64',host_architecture='x86_64',target_architecture='arm64',image_id='sha256:'+'a'*64);before=T.environment(p);p['host_provenance']={'sha256':'b'*64};self.assertEqual(T.environment(p),before)
 def test_host_bind_proposal_keeps_authority_null(self):
  p=json.loads((HERE/'actor-proposal.json').read_text());self.assertIsNone(p['resource_authority']);self.assertEqual(p['source_readonly_binds']['/usr'],'/usr');self.assertEqual(p['single_write_bind'],{'FRESH_ROOT_OWNED_OUTPUT_DIRECTORY':'/outputs'});self.assertEqual(p['runtime']['network'],'none');self.assertEqual(p['runtime']['cap_drop'],['ALL'])
 def test_source_extraction_escape_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);archive=p/'bad.tar.gz'
   with tarfile.open(archive,'w:gz') as t:t.addfile(tarfile.TarInfo('linux-asahi-7.1.13-3/../../escape'))
   with self.assertRaises(ValueError):B.extract(archive,p,'linux-asahi-7.1.13-3')
 def test_source_special_file_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);archive=p/'bad.tar.gz';m=tarfile.TarInfo('linux-asahi-7.1.13-3/fifo');m.type=tarfile.FIFOTYPE
   with tarfile.open(archive,'w:gz') as t:t.addfile(m)
   with self.assertRaises(ValueError):B.extract(archive,p,'linux-asahi-7.1.13-3')
 def test_frozen_bundle_contract(self):
  schema=json.loads((HERE/'bundle-contract.json').read_text());self.assertEqual(schema['rtc_required'],C.RTC);self.assertEqual(schema['directory_files'],['Image','config','bundle.json']);self.assertFalse(schema['release_accepted'])
 def test_two_phase_and_owned_runner_held(self):
  code=(HERE/'build.py').read_text();self.assertIn("a.stage=='compile'",code);self.assertIn("profile['configured_result_sha256']",code);self.assertIn('O.supervise(',code);self.assertNotIn('os.killpg(',code)
  for bad in ('modules_install','make install','--ignorearch','--nodeps','--faked-system-time'):self.assertNotIn(bad,code)
 def test_invalid_supervision_params_refuse_before_popen(self):
  for cap,limit in ((0,65536),(float('inf'),65536),(4,-1),(4,True),(4,16777217)):
   with self.subTest(cap=cap,limit=limit),self.assertRaises(ValueError):B.owned_command(None,['never-launched'],cap=cap,max_output=limit)
 def test_changed_sigchld_refuses_before_popen(self):
  with patch.object(signal,'getsignal',return_value=lambda *_:None),self.assertRaises(ValueError):B.owned_command(None,['never-launched'],cap=4,max_output=65536)
 def test_released_ownership_never_reentered(self):
  child=types.SimpleNamespace(returncode=None,_child_created=True);calls=[]
  def refuses(child,**kwargs):calls.append(kwargs);child._child_created=False;raise ValueError('modeled ownership already released')
  with patch.object(subprocess,'Popen',return_value=child):
   with self.assertRaises(B.OwnedCommandError) as caught:B.owned_command(types.SimpleNamespace(supervise=refuses),['modeled'],cap=4,max_output=65536)
  self.assertEqual(len(calls),1);self.assertEqual(caught.exception.retirement['ownership'],'NOT_REENTERED_AFTER_RELEASE')
 def test_all_python_syntax(self):
  for p in HERE.glob('*.py'):ast.parse(p.read_text(),filename=str(p))


if __name__=='__main__':
 with contextlib.ExitStack() as stack:
  for module,names in ((subprocess,('Popen',)),(socket,('socket','create_connection')),(ctypes,('CDLL',)),(os,('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','execvp','execvpe'))):
   for name in names:
    if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=AssertionError('actor fenced: '+name)))
  unittest.main()
