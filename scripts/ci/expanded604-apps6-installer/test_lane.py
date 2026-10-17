# SPDX-License-Identifier: MIT
import ast,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as P
ROOT=Path(os.environ.get('APPS6_LIFECYCLE_ROOT',Path(__file__).resolve().parents[3]));COMP=Path(os.environ.get('APPS6_COMPOSITION_ROOT',ROOT))
class Fresh(unittest.TestCase):
 def test_unbound_before_output_or_actors(self):
  with tempfile.TemporaryDirectory() as td,patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):
   out=Path(td)/'fresh';P.emit(ROOT,COMP,out);lane=out/P.NEW
   spec=importlib.util.spec_from_file_location('apps6_fresh_control',lane/'contract.py');C=importlib.util.module_from_spec(spec);__import__('sys').modules[spec.name]=C;spec.loader.exec_module(C)
   self.assertEqual(C.locks()[1]['cachy-asahi-apps'],'0.1.0-6')
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
   self.assertEqual(json.loads((lane/'policy.json').read_bytes())['native604']['source_sha'],None)
 def test_only_apps_changes_and_pipeline_bounds_unchanged(self):
  before=dict(line.split() for line in (ROOT/'scripts/ci/expanded604-current-management/expected604.lock').read_text().splitlines());after=dict(line.split() for line in (COMP/P.COMP/'expected604.lock').read_text().splitlines())
  self.assertEqual(after,before|{'cachy-asahi-apps':'0.1.0-6'});self.assertEqual(len(set(before)-{'cachy-asahi-apps'}),603)
  old=ast.parse((ROOT/P.OLD/'ci.py').read_bytes());new=ast.parse(P.adapt((ROOT/P.OLD/'ci.py').read_bytes(),'ci.py')[0])
  numeric=lambda tree:[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and type(n.value) in (int,float)]
  self.assertEqual(numeric(old),numeric(new))
 def test_drift_refuses_before_output(self):
  with tempfile.TemporaryDirectory() as td,patch.object(P,'pin',return_value={}):
   out=Path(td)/'source'
   with self.assertRaisesRegex(ValueError,'pinned source'):P.emit(ROOT,COMP,out)
   self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(verbosity=2)
