# SPDX-License-Identifier: MIT
"""Finite source/inverse/refusal controls; no accepting native/GUI fixture."""
import ast,base64,json,sys,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D/'implementation'))
import latest_guard as G,latest_plan as P,latest_selection as S
class Welcome7(unittest.TestCase):
 def test_whole_original544_before_and_exact549_after(self):
  self.assertEqual(G.verify()['original_files'],549);self.assertEqual(G.verify()['files'],568)
 def test_welcome_version_and_explicit_correctness_budget_inverses(self):
  proof=json.loads((D/'implementation/welcome7-successor.json').read_bytes());before=base64.b64decode(proof['before_bodies']['latest/implementation/latest_plan.py']);after=(D/'implementation/latest_plan.py').read_bytes()
  self.assertEqual(after.replace(b"('welcome','cachy-asahi-welcome','0.1.0-4','0.1.0-7')",b"('welcome','cachy-asahi-welcome','0.1.0-4','0.1.0-6')",1).replace(b'BOUNDS=dict(consumer=2400,owner=6600',b'BOUNDS=dict(consumer=1800,owner=6600',1),before);self.assertEqual(P.BOUNDS,dict(consumer=2400,owner=6600,transaction=90,fixture=100,cleanup=60))
 def test_same_original_five_installed_cli_controls_only(self):
  proof=json.loads((D/'implementation/welcome7-successor.json').read_bytes());before=base64.b64decode(proof['before_bodies']['latest/implementation/latest_fixture.py']);after=(D/'implementation/latest_fixture.py').read_bytes();self.assertEqual(after.replace(b"\n if version=='0.1.0-7':\n",b"\n if version=='0.1.0-6':\n",1),before)
  self.assertEqual(S.pin((D.parent/'welcome6-test_cli.py').read_bytes()),dict(bytes=3170,sha256='722182698ca07b14b03787a52f5b3976f2f039ae048f142f2dee72e6176fa972'));self.assertEqual(S.PACKETS['welcome']['files'],226);self.assertEqual(S.PACKETS['welcome']['source'],'1057f6b5494adc71c469e8867d14fb0db01ce02f')
 def test_full_new_native_decision_is_explicitly_not_gui_or_installed_credit(self):
  pins=S.components();v=json.loads((D/'implementation/accepted/welcome7.json').read_bytes());self.assertEqual(pins['welcome7']['run'],39348847325);self.assertEqual(v['status'],'ROOT_ACCEPTED_FINITE_NATIVE_WELCOME7_BUILD_PAIR_ONLY')
  for key in('GUI','installed_lifecycle','M2','actual16K','hardware'):self.assertEqual(v[key],'NOT_RUN')
  rows=dict(line.split()for line in(G.BASE/'held606/scripts/ci/current606-native/expected606.lock').read_text().splitlines());self.assertIn('at-spi2-core',rows)
 def test_all_five_exact_checkouts_dominate_inputs_and_private_actors(self):
  import latest_workflow as W
  raw=(D.parent/'.github/workflows/native-arm-build.yml').read_text();fact=W.order(raw);self.assertEqual(set(fact['checkouts']),set(S.PACKETS));self.assertLess(max(fact['checkouts'].values()),fact['first_consumer'])
  rows=W.steps(raw);apps=next(r['body']for r in rows if r['name']=='Checkout exact accepted apps latest tool input DATA')
  for changed in(raw.replace(apps,'',1)+apps,raw.replace(S.PACKETS['welcome']['source'],'0'*40,1),raw.replace('path: boot79-native-inputs','path: wrong-private-input',1)):
   with self.assertRaises(ValueError):W.order(changed)
if __name__=='__main__':unittest.main(verbosity=2)
