# SPDX-License-Identifier: MIT
"""No native/API actors; exact default/selected source and preservation controls."""
import importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as F
CURRENT=Path(os.environ.get('DOCTOR2_CURRENT_SOURCE',str(F.HERE.parents[2])))
NATIVE=Path(os.environ.get('DOCTOR2_NATIVE_SOURCE',str(CURRENT/'.ci-inputs/doctor2-native-source')))
class Factory(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.p=patch.object(subprocess,'Popen',side_effect=AssertionError('source actor forbidden'));cls.p.start();cls.addClassCleanup(cls.p.stop);cls.r=patch.object(subprocess,'run',side_effect=AssertionError('source actor forbidden'));cls.r.start();cls.addClassCleanup(cls.r.stop)
 def test_selected_and_default_close_exact62(self):
  lock=json.loads((F.HERE/'source.json').read_bytes())
  with tempfile.TemporaryDirectory()as t:
   for selected,name in((False,'default'),(True,'selected')):
    out=Path(t)/name;F.prepare(CURRENT,NATIVE,out,selected);self.assertEqual(F.files(out),lock['selected_files']if selected else lock['default_files']);policy=json.loads((out/'scripts/ci/welcome-native/doctor2-policy.json').read_bytes());self.assertTrue(all(policy[n]is None for n in('actual_source','actual_ref','actual_run')))
 def test_changed_current_recipe_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);current=d/'current';shutil.copytree(CURRENT/'packages/tools/cachy-asahi-doctor2',current/'packages/tools/cachy-asahi-doctor2');(current/'packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor').write_text('changed')
   with self.assertRaises(ValueError):F.prepare(current,NATIVE,d/'out')
   self.assertFalse((d/'out').exists())
 def test_extra_or_changed_native_source_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);native=d/'native';shutil.copytree(NATIVE,native,ignore=shutil.ignore_patterns('.git'));(native/'extra').write_text('extra')
   with self.assertRaises(ValueError):F.prepare(CURRENT,native,d/'out')
   self.assertFalse((d/'out').exists())
 def test_existing_output_unchanged(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);out=d/'out';out.mkdir();(out/'sentinel').write_text('hold')
   with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,out)
   self.assertEqual((out/'sentinel').read_text(),'hold')
 def test_default_source_proof_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);out=d/'view';F.prepare(CURRENT,NATIVE,out);s=importlib.util.spec_from_file_location('doctor2_default_registration',out/'scripts/ci/welcome-native/contract.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
   with self.assertRaises(ValueError):c.activation(out)
 def test_historical_and_default_inventory_untouched(self):
  before=F.files(NATIVE)
  with tempfile.TemporaryDirectory()as t:F.prepare(CURRENT,NATIVE,Path(t)/'view')
  self.assertEqual(F.files(NATIVE),before);self.assertEqual(json.loads((F.HERE/'source.json').read_bytes())['actual_run'],None)
if __name__=='__main__':unittest.main(verbosity=2)
