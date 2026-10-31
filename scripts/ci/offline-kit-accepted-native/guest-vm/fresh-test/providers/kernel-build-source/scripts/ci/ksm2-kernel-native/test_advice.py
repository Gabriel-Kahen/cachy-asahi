"""Real generated Kconfig and strict source/refusal controls; no Image or VM."""
import ast,json,tempfile,unittest
from pathlib import Path
import lane as L
HERE=L.HERE;ROOT=L.ROOT
class Advice(unittest.TestCase):
 def test_explicit_advice_fragment_and_held_whole_historical_inputs(self):
  raw=L.KP.held(ROOT,'kernel.fragment');self.assertEqual(L.KP.fragment(raw),raw+b'CONFIG_KSM=y\nCONFIG_ADVISE_SYSCALLS=y\n')
  for name in L.KP.PINS:L.KP.held(ROOT,name)
 def test_exact_three_bit_configuration_delta(self):
  before=L.read(HERE/'fixtures/baseline.config');after=L.read(HERE/'fixtures/ksm.config');result=L.delta(before,after)
  self.assertEqual(result['changed'],{name:{'before':'n','proposed':'y'}for name in('CONFIG_ADVISE_SYSCALLS','CONFIG_KSM','CONFIG_XXHASH')})
  self.assertEqual(L.config_values(after).get('CONFIG_TRANSPARENT_HUGEPAGE','n'),'n');self.assertEqual(L.config_values(after).get('CONFIG_PROC_PAGE_MONITOR','n'),'n')
 def test_original_advice_disabled_configuration_is_not_new_qualification(self):
  after=L.read(HERE/'fixtures/ksm.config').replace(b'CONFIG_ADVISE_SYSCALLS=y',b'# CONFIG_ADVISE_SYSCALLS is not set')
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'config';p.write_bytes(after)
   with self.assertRaises(ValueError):L.KP.check_config(p)
  with self.assertRaises(ValueError):L.delta(L.read(HERE/'fixtures/baseline.config'),after)
 def test_duplicate_advice_symbol_and_unrelated_config_change_refuse(self):
  before=L.read(HERE/'fixtures/baseline.config');after=L.read(HERE/'fixtures/ksm.config')
  for bad in(after+b'CONFIG_ADVISE_SYSCALLS=y\n',after.replace(b'CONFIG_ADVISE_SYSCALLS=y',b'CONFIG_ADVISE_SYSCALLS=n'),after.replace(b'CONFIG_MMU=y',b'CONFIG_MMU=n'),after.replace(b'# CONFIG_ANON_VMA_NAME is not set',b'CONFIG_ANON_VMA_NAME=y')):
   with self.assertRaises(ValueError):L.delta(before,bad)
 def test_no_thp_pagemap_or_new_tools_required(self):
  H=L.KP.helper(ROOT);self.assertNotIn('CONFIG_TRANSPARENT_HUGEPAGE=y',L.KP.fragment(L.KP.held(ROOT,'kernel.fragment')).decode())
  self.assertEqual(H.TOOLS,('make','clang','clang++','ld.lld','llvm-ar','llvm-nm','llvm-strip','llvm-objcopy','llvm-objdump','llvm-readelf','bison','flex','bc','perl','sh'))
 def test_source_policy_remains_unbound_and_build_only(self):
  v=L.decode(L.read(HERE/'input-policy.json'))
  for key in('actual_source','actual_ref','actual_run','native_package_decision'):self.assertIsNone(v[key])
  for key in('boot','VM','live_kernel_write','hardware'):self.assertEqual(v[key],'NOT_RUN')
  self.assertEqual(v['profile'],'KSM_ADVICE_GENERIC16K_DIAGNOSTIC_V1')
if __name__=='__main__':unittest.main(verbosity=2)
