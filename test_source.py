"""Focused source-only capacity closure; never a native/admission replay."""
import ast,importlib.util,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
class ContextSource(unittest.TestCase):
 def test_top_closed_source_and_unbound_profile(self):
  spec=importlib.util.spec_from_file_location('_context_entry',ROOT/'entry.py');entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry);profile=entry.verify()
  self.assertFalse(profile['normal_updater_acceptance']);self.assertEqual(profile['production_copy_seconds'],1200);self.assertTrue(all(profile[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')))
  binding=json.loads((ROOT/'binding.json').read_bytes());self.assertTrue(all(binding[k]is None for k in('source','ref','run','attempt','case')))
 def test_both_private_source_manifests_and_all_parseable_bodies(self):
  for role in('production','capacity'):
   path=ROOT/role/'custody.py';spec=importlib.util.spec_from_file_location('_custody_'+role,path);q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q);q.verify()
  for path in ROOT.rglob('*.py'):ast.parse(path.read_bytes())
 def test_no_normal_acceptance_surface(self):
  code=(ROOT/'capacity/vm/contract.py').read_text();self.assertIn('MEASURED_GENERIC16K_FULL_COPY_CAPACITY_NOT_ACCEPTANCE',code)
  self.assertIn('APPS6_COPY_CAPACITY',(ROOT/'capacity/vm/vm.py').read_text());self.assertIn('capacity_verify',(ROOT/'capacity/selected.py').read_text())
if __name__=='__main__':unittest.main()
