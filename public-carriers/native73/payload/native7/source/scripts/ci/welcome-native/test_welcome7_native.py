# SPDX-License-Identifier: MIT
"""Source-only controls. No native actor or accepting build fixture."""
import ast,hashlib,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import contract as C
HERE=Path(__file__).resolve().parent;SOURCE=HERE.parents[2]
class Controls(unittest.TestCase):
 def test_complete_recipe27_hashes_metadata_and_owned_payload(self):
  C.verify_source(SOURCE);v=C.recipe(SOURCE,C.NAME)
  self.assertEqual(len(v['input_sha256']),27);self.assertEqual(v['metadata']['pkgrel'],['7']);self.assertEqual(len(v['metadata']['source']),25)
  self.assertEqual(set(C.NAMES),{C.NAME});self.assertEqual(len(C.FILES),9)
  self.assertIn('cachy-asahi-boot-report>=0.1.0-1: optional read-only visible boot history',v['metadata']['optdepends'])
 def test_audited_linkage_exactly_adds_atk_without_unexpected_sonames(self):
  expected=['libgtk-3.so.0','libpango-1.0.so.0','libgio-2.0.so.0','libgobject-2.0.so.0','libglib-2.0.so.0','libc.so.6','ld-linux-aarch64.so.1','libatk-1.0.so.0']
  self.assertEqual(C.linkage(expected),expected)
  for bad in(expected[:-1],expected+['libforeign.so.1'],expected+[expected[0]],expected[:-1]+['libatk-2.0.so.0']):
   with self.assertRaises(ValueError):C.linkage(bad)
 def test_full_held574_atk_package_and_library_custody(self):
  v=C.atk_dependency(SOURCE)
  self.assertEqual(v['soname'],'libatk-1.0.so.0')
  self.assertEqual(v['library']['sha256'],'230e593fee45b05b5d48cfac79f34960e3a3c3d67c66def596f46fb346b8c1be')
  for field in ('sha256','signature_sha256','version','license','provides'):
   bad=dict(C.AUDITED_ATK_PACKAGE);bad[field]='foreign'
   with patch.object(C,'AUDITED_ATK_PACKAGE',bad),self.assertRaises(ValueError):C.atk_dependency(SOURCE)
 def test_explicit_atk_dependency_and_original_elf_guards_remain(self):
  self.assertIn('at-spi2-core',C.recipe(SOURCE,C.NAME)['metadata']['depends'])
  s=(HERE/'contract.py').read_text();body=ast.get_source_segment(s,next(n for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)and n.name=='elf'))
  for token in ("result.get('machine')==183","b'/lib/ld-linux-aarch64.so.1\\0'",'dynamic string table outside file-backed load','unsafe DT_NEEDED','linkage(needed)'):
   self.assertIn(token,body)
 def test_source_identity_remains_null_and_only_root_selection_activates(self):
  value=json.loads((HERE/'welcome7-policy.json').read_bytes())
  self.assertTrue(all(value[k]is None for k in('actual_source','actual_ref','actual_run')))
  if value['status']=='UNBOUND':
   with self.assertRaises(ValueError):C.activation(SOURCE)
  else:self.assertEqual(C.activation(SOURCE),value)
 def test_mutated_source_hash_fails_closed(self):
  with patch.object(C,'digest',return_value='0'*64),self.assertRaises(ValueError):C.verify_source(SOURCE)
 def test_missing_and_failed_full_recipe_checks_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'build.log'
   for text in('', 'Starting check()\nnot ok 1 /boot-history/listed-empty-unavailable\n', 'Starting check()\nRan 5 tests\nOK\n'):
    p.write_text(text)
    with self.assertRaises(ValueError):C.check_log(p,C.NAME)
 def test_no_lifecycle_actor_and_full_original_cleanup_clock_held(self):
  s=(HERE/'run.py').read_text();main=ast.get_source_segment(s,next(n for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)and n.name=='main'))
  self.assertNotIn("context=out/'lifecycle-inputs'",main);self.assertNotIn("report['lifecycle']",main)
  for token in('signal.setitimer(signal.ITIMER_REAL,1800)','for name in reversed(containers):',"execute(['docker','rm','-f',name]", "row['absence_verified']=True",'finally:'):
   self.assertIn(token,main)
  self.assertIn("for side in ('a','b')",main);self.assertIn("report['status']='PASS_NATIVE_WELCOME7_BUILD_PAIR_CONTENTS_ONLY'",main)
if __name__=='__main__':
 with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_NATIVE_SOURCE_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('NO_NATIVE_SOURCE_ACTORS')):unittest.main()
