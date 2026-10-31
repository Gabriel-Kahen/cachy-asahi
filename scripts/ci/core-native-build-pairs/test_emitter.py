# SPDX-License-Identifier: MIT
"""Whole-source integration control requires the explicit complete pinned public373 fixture."""
import json,os,tempfile,unittest
from pathlib import Path
import prepare as F
RUNTIME=os.environ.get('CORE_NATIVE_RUNTIME')
if not RUNTIME:raise SystemExit('Set CORE_NATIVE_RUNTIME to the absolute complete pinned public373 checkout; no test is silently skipped.')
class Controls(unittest.TestCase):
 def test_whole_default_selected_emission_and_selection_refusal(self):
  runtime=Path(RUNTIME).absolute();profile=F.profile()
  with tempfile.TemporaryDirectory()as td:
   td=Path(td);binding=td/'Root-component-selection.json';binding.write_bytes(F.enc(profile['reviewed_selection']))
   for view,b in(('default',None),('selected',binding)):
    receipt=F.assemble(runtime,td/view,b);self.assertEqual(receipt['view'],view);self.assertEqual({n:F.pin(raw)for n,raw in F.files(td/view).items()},profile['expected_sources'][view])
   with self.assertRaises(ValueError):F.assemble(runtime,td/'selected',binding)
   bad=json.loads(binding.read_bytes());bad['lane/root-source-authorization.json']['hardware_acceptance']=True;binding.write_bytes(F.enc(bad))
   with self.assertRaises(ValueError):F.assemble(runtime,td/'bad',binding)
   self.assertFalse((td/'bad').exists())
if __name__=='__main__':unittest.main(verbosity=2)
