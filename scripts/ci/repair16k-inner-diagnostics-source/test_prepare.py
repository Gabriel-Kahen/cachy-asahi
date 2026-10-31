# SPDX-License-Identifier: MIT
"""Genuine carrier and complete selected/default emission; no native actors."""
import json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as F
BASE=Path(os.environ.get('REPAIR_INNER_BASE_SOURCE',str(F.HERE.parents[2]/'.ci-inputs/repair204-diagnostic-base')))
class Factory(unittest.TestCase):
 def test_complete_default_selected203_and_null_actuals(self):
  lock=json.loads((F.HERE/'source.json').read_bytes())
  with tempfile.TemporaryDirectory()as t,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   for selected,name in((False,'default'),(True,'selected')):
    out=Path(t)/name;v=F.prepare(BASE,out,selected);self.assertEqual(F.files(out),lock['selected'if selected else'default']['files']);self.assertIsNone(v['source']);self.assertTrue(all(x is None for x in v['run_ids'].values()))
 def test_base_drift_extra_and_alias_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   d=Path(t);base=d/'base';shutil.copytree(BASE,base,ignore=shutil.ignore_patterns('.git'));leaf=base/'scripts/ci/apps7-full574-repair16k/disk.py';raw=leaf.read_bytes();leaf.write_bytes(raw+b'\n')
   with self.assertRaises(ValueError):F.prepare(base,d/'out')
   self.assertFalse((d/'out').exists());leaf.write_bytes(raw);(base/'unknown').write_bytes(b'UNKNOWN')
   with self.assertRaises(ValueError):F.prepare(base,d/'out')
   (base/'unknown').unlink();(base/'unknown').symlink_to(leaf)
   with self.assertRaises(ValueError):F.prepare(base,d/'out')
   self.assertFalse((d/'out').exists())
 def test_existing_output_and_input_carrier_preserved(self):
  before=F.files(BASE)
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'out';out.mkdir();(out/'sentinel').write_bytes(b'PRESERVE')
   with self.assertRaises(ValueError):F.prepare(BASE,out)
   self.assertEqual((out/'sentinel').read_bytes(),b'PRESERVE')
  self.assertEqual(F.files(BASE),before)
 def test_no_optimization_or_core_observer_or_native_role_change(self):
  lock=json.loads((F.HERE/'source.json').read_bytes());held=('scripts/update/full_root.py','scripts/install/local_transaction.py','scripts/apps/full574_closure.py','scripts/ci/apps7-full574-repair-native/path_view.py')
  for name in held:self.assertEqual(lock['base_files'][name],lock['selected']['files'][name]);self.assertEqual(lock['base_files'][name],lock['default']['files'][name])
  text=lock['selected']['delta']['scripts/ci/apps7-full574-repair16k/adapter.py'];self.assertNotIn('value.isascii()',text);self.assertIn('parent_code=compile(body',text)
if __name__=='__main__':unittest.main(verbosity=2)
