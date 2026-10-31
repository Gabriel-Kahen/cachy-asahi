from test_owner import NULL_POLICY
import importlib.util,json,unittest
from pathlib import Path
P=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_owner_selection',P/'selection.py');S=importlib.util.module_from_spec(s);s.loader.exec_module(S)
class Selection(unittest.TestCase):
 def test_real_default_all_roles_refuse_before_io(self):
  policy=json.loads(json.dumps(NULL_POLICY));self.assertTrue(all(v is None for v in policy['current606'].values()))
  for role in S.CAPS:
   with self.subTest(role=role),self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):S.verify_actor(policy,role,'a'*32)
 def test_null_decision_is_not_permanent_false_stub(self):
  with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):S.decision(dict.fromkeys(('source','run','decision_source','decision_path','decision_pin','decision_base64')))
  self.assertEqual(S.CAPS['capture'],('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID'));self.assertEqual(S.MASKS,{'capture':0xdb,'finalizer':0x8000001b,'copy-worker8':0x800400db,'dispose':0x8000001b})
 def test_nonfinite_duplicate_decisions_refuse(self):
  for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):S.decode(raw)
if __name__=='__main__':unittest.main()
