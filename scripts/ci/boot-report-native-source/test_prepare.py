# SPDX-License-Identifier: MIT
"""Finite factory controls; no native, package, journal or network actors."""
import importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as F
CURRENT=Path(os.environ.get('BOOT_CURRENT_SOURCE',str(F.HERE.parents[2])))
NATIVE=Path(os.environ.get('BOOT_NATIVE_SOURCE',str(CURRENT/'.ci-inputs/boot-report-native-source')))
class Factory(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  for name in('Popen','run'):
   p=patch.object(subprocess,name,side_effect=AssertionError('source actor forbidden'));p.start();cls.addClassCleanup(p.stop)
 def test_full_selected_default79_and_null_actuals(self):
  lock=json.loads((F.HERE/'source.json').read_bytes())
  with tempfile.TemporaryDirectory()as t:
   for selected,name in((False,'default'),(True,'selected')):
    out=Path(t)/name;F.prepare(CURRENT,NATIVE,out,selected);self.assertEqual(F.files(out),lock['selected_files']if selected else lock['default_files']);policy=json.loads((out/'scripts/ci/welcome-native/boot-policy.json').read_bytes());self.assertTrue(all(policy[n]is None for n in('actual_source','actual_ref','actual_run')))
 def test_current_recipe_change_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);c=d/'current';shutil.copytree(CURRENT/'packages/tools/cachy-asahi-boot-report',c/'packages/tools/cachy-asahi-boot-report');(c/'packages/tools/cachy-asahi-boot-report/cachy-asahi-boot-report').write_text('changed')
   with self.assertRaises(ValueError):F.prepare(c,NATIVE,d/'out')
   self.assertFalse((d/'out').exists())
 def test_reviewed_metadata_missing_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);c=d/'current';shutil.copytree(CURRENT/'packages/tools/cachy-asahi-boot-report',c/'packages/tools/cachy-asahi-boot-report');(c/'packages/tools/cachy-asahi-boot-report/.SRCINFO').unlink()
   with self.assertRaises(ValueError):F.prepare(c,NATIVE,d/'out')
   self.assertFalse((d/'out').exists())
 def test_changed_or_extra_carrier_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);n=d/'native';shutil.copytree(NATIVE,n,ignore=shutil.ignore_patterns('.git'));p=n/'scripts/ci/welcome-native/run.py';raw=p.read_bytes();p.write_bytes(raw+b'\n')
   with self.assertRaises(ValueError):F.prepare(CURRENT,n,d/'out')
   p.write_bytes(raw);(n/'extra').write_text('extra')
   with self.assertRaises(ValueError):F.prepare(CURRENT,n,d/'out')
   self.assertFalse((d/'out').exists())
 def test_carrier_alias_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);n=d/'native';n.symlink_to(NATIVE,target_is_directory=True)
   with self.assertRaises(ValueError):F.prepare(CURRENT,n,d/'out')
   self.assertFalse((d/'out').exists())
 def test_existing_output_preserved(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);out=d/'out';out.mkdir();(out/'sentinel').write_text('held')
   with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,out)
   self.assertEqual((out/'sentinel').read_text(),'held')
 def test_default_contract_refuses_activation(self):
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'view';F.prepare(CURRENT,NATIVE,out);s=importlib.util.spec_from_file_location('boot_default_contract',out/'scripts/ci/welcome-native/contract.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c);c.verify_source(out)
   with self.assertRaises(ValueError):c.activation(out)
 def test_original_source_and_current_inputs_held(self):
  before=F.files(NATIVE);recipe=CURRENT/'packages/tools/cachy-asahi-boot-report';inputs=F.files(recipe)
  with tempfile.TemporaryDirectory()as t:F.prepare(CURRENT,NATIVE,Path(t)/'view')
  self.assertEqual(F.files(NATIVE),before);self.assertEqual(F.files(recipe),inputs)
if __name__=='__main__':unittest.main(verbosity=2)
