# SPDX-License-Identifier: MIT
import hashlib,importlib.util,json,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('latest_plan',D/'implementation/latest_plan.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
LOCK=D.parent/'historical/boot391/held606/scripts/ci/current606-native/expected606.lock'
class Plan(unittest.TestCase):
 def test_genuine606_full25actions_and607joint(self):
  raw=LOCK.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),P.LOCK);base=dict(r.split()for r in raw.decode().splitlines());events=P.transitions(base);self.assertEqual(len(events),25);self.assertEqual(events[-1]['after'],base);self.assertEqual([len(e['after'])for e in events[:5]],[606,606,606,606,607]);self.assertTrue(all(len(e['after'])==607 for e in events[5:10]));self.assertEqual([len(e['after'])for e in events[10:20]],[606,607]*5);self.assertTrue(all(len(e['after'])==606 for e in events[20:]));self.assertEqual(events[4]['after'],base|{n:v for _,n,_,v in P.PRODUCTS});self.assertEqual(base,dict(r.split()for r in raw.decode().splitlines()))
 def test_every_action_holds_all_nonacted_andruntime(self):
  base=dict(r.split()for r in LOCK.read_text().splitlines())
  for e in P.transitions(base):
   self.assertEqual({n:v for n,v in e['before'].items()if n!=e['name']},{n:v for n,v in e['after'].items()if n!=e['name']});self.assertEqual(e['after'][P.RUNTIME],'0.1.0-1');self.assertGreaterEqual(e['unaffected_count'],605)
 def test_changedlock_runtime_oldversions_extra_product_refuse(self):
  base=dict(r.split()for r in LOCK.read_text().splitlines())
  for key,value in((P.RUNTIME,'FOREIGN'),('cachy-asahi-welcome','0.1.0-7'),('foreign','0.1.0')):
   v=dict(base);v[key]=value
   with self.assertRaises(ValueError):P.transitions(v)
  with self.assertRaises(ValueError):P.product('unknown')
 def test_original_andtarget_roles_strict(self):
  base=dict(r.split()for r in LOCK.read_text().splitlines());events=P.transitions(base)
  self.assertTrue(all(e['archive_role']=='latest'for e in events[:10]));self.assertEqual([e['archive_role']for e in events[-5:]],[None,'original','original','original','original']);self.assertEqual(P.BOUNDS['consumer'],4200);self.assertEqual(P.BOUNDS['owner'],6600);self.assertEqual(P.BOUNDS['transaction'],90)
if __name__=='__main__':unittest.main(verbosity=2)
