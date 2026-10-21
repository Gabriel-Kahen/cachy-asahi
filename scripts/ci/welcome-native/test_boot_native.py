# SPDX-License-Identifier: MIT
"""Finite source controls: no native/package/API actors or synthetic acceptance."""
import copy,hashlib,importlib.util,json,re,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import contract as C
ROOT=Path(__file__).resolve().parents[3];HERE=Path(__file__).resolve().parent
class Boot(unittest.TestCase):
 def test_exact_single_product_and_six_recipe_inputs(self):
  self.assertEqual(C.NAMES,('cachy-asahi-boot-report',));self.assertEqual(len(C.recipe(ROOT,C.BOOT)['input_sha256']),6);self.assertEqual(C.VERSIONS[C.BOOT],'0.1.0-1')
 def test_source_pins_whole_manifest_alias(self):
  C.verify_source(ROOT);mf=json.loads((HERE/'ci/source-manifest.json').read_bytes())
  for name,pin in mf['files'].items():self.assertEqual(dict(bytes=(ROOT/name).stat().st_size,sha256=C.digest(ROOT/name)),pin)
  self.assertEqual((ROOT/'.github/workflows/native-arm-build.yml').read_bytes(),(ROOT/'.github/workflows/native-arm-welcome-doctor-products.yml').read_bytes())
 def test_null_default_refuses_before_source_proof_output(self):
  policy=json.loads((HERE/'boot-policy.json').read_bytes());self.assertTrue(all(policy[n]is None for n in ('actual_source','actual_ref','actual_run')))
  original=Path.read_text
  with patch.object(Path,'read_text',lambda p,*a,**k:json.dumps(dict(policy,status='UNBOUND',recipe=None,version=None,input_sha256=None))if p==HERE/'boot-policy.json'else original(p,*a,**k)):
   with self.assertRaises(ValueError):C.activation(ROOT)
 def test_crosswired_recipe_version_map_refuses(self):
  policy=C.activation(ROOT);original=Path.read_text
  for key,value in [('version','0.2.0-1'),('recipe','packages/tools/cachy-asahi-doctor2'),('input_sha256',{})]:
   with patch.object(Path,'read_text',lambda p,*a,**k:json.dumps(dict(policy,**{key:value}))if p==HERE/'boot-policy.json'else original(p,*a,**k)):
    with self.assertRaises(ValueError):C.activation(ROOT)
 def test_complete_native18_suite_noskips(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'log';p.write_text('Starting check()\nRan 18 tests in 0.1s\nOK\n');self.assertEqual(C.check_log(p,C.BOOT)['boot_fixtures'],18)
   for raw in ('Starting check()\nRan 17 tests\nOK\n','Starting check()\nRan 18 tests\nOK\nskipped=1\n','Starting check()\nRan 18 tests\nFAILED\n'):
    p.write_text(raw)
    with self.assertRaises(ValueError):C.check_log(p,C.BOOT)
 def test_fixture_decoded_fields_are_exact_synthetic_authored_records(self):
  authored=json.loads((HERE/'boot-fixture/authored-records.json').read_bytes());decoded=json.loads((HERE/'boot-fixture/decoded-records.json').read_bytes());self.assertEqual(len(decoded),4)
  for i,(a,b)in enumerate(zip(authored,decoded),1):
   self.assertEqual({k:v for k,v in b.items()if k not in ('__CURSOR','__SEQNUM','__SEQNUM_ID')},a);self.assertEqual(set(b),set(a)|{'__CURSOR','__SEQNUM','__SEQNUM_ID'});self.assertEqual(b['__SEQNUM'],str(i));self.assertEqual(a['_MACHINE_ID'],'a'*32);self.assertEqual(a['_UID'],'65534');self.assertEqual(a['_HOSTNAME'],'synthetic-boot-fixture');self.assertTrue(a['MESSAGE'].startswith('SYNTHETIC TEST ONLY '))
 def test_fixture_provenance_and_binary_hash_join(self):
  generation=json.loads((HERE/'boot-fixture/generation.json').read_bytes());self.assertEqual(generation['journal'],dict(bytes=(HERE/'boot-fixture/system.journal').stat().st_size,sha256=C.digest(HERE/'boot-fixture/system.journal')));self.assertFalse(generation['host_history_read']);self.assertFalse(generation['network']);self.assertEqual(generation['generator']['sha256'],C.digest(HERE/'boot-fixture/make_fixture.py'));self.assertEqual(generation['input']['sha256'],C.digest(HERE/'boot-fixture/journal.export'))
 def test_runtime_security_lifetime_and_acquisition_held(self):
  text=(HERE/'run.py').read_text()
  for needle in ("'--network=none'","'--cap-drop=ALL'","'--security-opt=no-new-privileges'","'--memory=3g'","'--pids-limit=256'","signal.setitimer(signal.ITIMER_REAL,1800)"):self.assertIn(needle,text)
  wf=(ROOT/'.github/workflows/native-arm-build.yml').read_text();self.assertIn('timeout-minutes: 90',wf);self.assertEqual(wf.count('timeout-minutes: 4\n'),3);self.assertLess(wf.index('archive32 inputs'),wf.index('Reconstruct pinned'));self.assertIn('2300s',wf);self.assertIn('2100s',wf)
 def test_missing_lifecycle_cannot_qualify(self):
  for value in ({},dict(status='PASS_PRODUCTS_INSTALLED_CLI_LIFECYCLE',base_count=574,installed_count=576)):
   with self.assertRaises((ValueError,KeyError)):C.validate_lifecycle(value)
 def test_cli_entry_has_only_private_fixture_queries(self):
  s=(HERE/'boot_fixture.py').read_text();self.assertNotIn("invoke(['list'])",s);self.assertNotIn('/sys/fs/pstore',s);self.assertIn("'--journal-directory'",s)
 def test_original_native_pair_build_command_is_held(self):
  r=C.load('boot_run_control',HERE/'run.py');argv=r.docker('sha256:'+'a'*64,'cachy-asahi-product-'+'b'*32,Path('/tmp/owned'));self.assertIn('--read-only',argv);self.assertNotIn('--privileged',argv)
 def test_finite_retainer_has_four_confirmed_absences(self):
  s=(HERE/'ci/caller.py').read_text();self.assertIn("len(report['cleanup'])==4",s);self.assertIn("r.get('absence_verified') is True",s);self.assertIn("original['owned_cleanup']['probe']['absence_verified'] is True",s);self.assertIn("NAMES=('cachy-asahi-boot-report',)",s)
if __name__=='__main__':unittest.main(verbosity=2)
