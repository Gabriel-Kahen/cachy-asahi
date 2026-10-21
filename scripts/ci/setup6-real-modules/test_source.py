# SPDX-License-Identifier: MIT
import ast,copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C,adapter,real_recovery as R
ROOT=Path(__file__).resolve().parents[3]
class Controls(unittest.TestCase):
 def test_complete_source_and_typed_581(self):
  C.verify_source(ROOT);base={r['name']:r['version']for r in C.read(ROOT/'scripts/ci/maintained-desktop574-inputs.json')['packages']};self.assertEqual(C.expected(),base|C.VERSIONS);self.assertEqual(len(C.expected()),581)
 def test_real_native_guard_precedes_output(self):
  import installed
  from unittest.mock import patch
  with patch.object(installed.platform,'machine',return_value='x86_64'):
   with self.assertRaises(ValueError):installed.exercise(ROOT,ROOT/'forbidden')
  self.assertFalse((ROOT/'forbidden').exists())
 def test_original_budget_and_ownership_routes(self):
  raw=adapter.source(ROOT);ast.parse(raw);self.assertIn('signal.ITIMER_REAL,1500',raw);self.assertIn("out/'lifecycle.log',600",raw);self.assertNotIn('shared.build(',raw);self.assertIn('len(self)<4',raw)
 def test_all_extension_cases_and_refusals(self):
  v=dict(status='PASS',scope='ACTUAL_CLI_SIX_INSTALLED_MODULES_PRIVATE_HOMES_TEMPLATE_DRIFT_USES_OWNED_EXACT_COPY',homes={n:True for n in R.NAMES},cases={n:dict(status='PASS',preview_readonly=True,preserved=True)for n in R.NAMES});R.validate(v)
  for key in ('homes','cases'):
   b=copy.deepcopy(v);b[key].pop(next(iter(b[key])))
   with self.assertRaises(ValueError):R.validate(b)
if __name__=='__main__':unittest.main()
