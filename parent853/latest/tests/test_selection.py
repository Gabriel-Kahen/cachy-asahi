# SPDX-License-Identifier: MIT
import copy,json,sys,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D/'implementation'))
import latest_selection as S
BASE=D.parent/'historical/boot391/boot607/input-policy.json'
class Selection(unittest.TestCase):
 def test_defaultNULL_refuses_before_external_or_actor(self):
  value=json.loads((D/'implementation/default-policy.json').read_bytes());old=json.loads(BASE.read_bytes())['current606']
  with self.assertRaisesRegex(ValueError,'NULL'):S.authorize(value,old)
 def test_only_past_components_andexact_carriers_selected(self):
  value=json.loads((D/'implementation/default-policy.json').read_bytes());old=json.loads(BASE.read_bytes())['current606'];value.update(status='ROOT_BOUND_HISTORICAL_INPUTS_NO_COMBINED_ACCEPTANCE',current606=old,component_inputs=S.components(),packet_checkouts=copy.deepcopy(S.PACKETS));value['apps8_current606']=json.loads((D/'implementation/input-policy.json').read_bytes())['apps8_current606']
  if json.loads((D/'implementation/apps8-qualified-profile.json').read_bytes())['source']is None:
   with self.assertRaisesRegex(ValueError,'NULL'):S.authorize(value,old)
  else:self.assertEqual(S.authorize(value,old),value)
  for change in(lambda v:v.update(actual_run=1),lambda v:v['packet_checkouts']['welcome'].update(source='0'*40),lambda v:v['component_inputs'].pop('welcome5'),lambda v:v['current606'].update(source='3660e6cb87b4cb5591b1d295c62c8b02cca4b7e6')):
   v=copy.deepcopy(value);change(v)
   with self.assertRaises(ValueError):S.authorize(v,old)
if __name__=='__main__':unittest.main(verbosity=2)
