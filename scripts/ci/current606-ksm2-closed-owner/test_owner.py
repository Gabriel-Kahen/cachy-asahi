# SPDX-License-Identifier: MIT
"""Source, counted owner interfaces and NULL refusal, no actors or positive fixture."""
import importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE))
import contract as C,owner,selection as S,builds,runtime
class Owner(unittest.TestCase):
 def setUp(self):
  for name in('Popen','run'):
   p=patch.object(subprocess,name,side_effect=AssertionError('NO_ACTORS_GIT_API'));p.start();self.addCleanup(p.stop)
 def test_whole_source_counted_producer_and_capture_program_conservation(self):
  C.verify();P,A,X,original=owner.source_context(ROOT);P.verify(bound=False);raw=A.owner(P.ROOT);derived=owner.owner_program(raw);self.assertIn("len(owned.rows)==8",derived);self.assertIn('active.process.wait(timeout=1800)',derived);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',derived);owner.capture_program((P.HERE/'tools606.py').read_text())
 def test_default_current606_and_public_carrier_refuse_before_inputs(self):
  p=C.read(HERE/'input-policy.json');self.assertIsNone(p['native_pair_source']);self.assertTrue(all(x is None for x in p['current606'].values()))
  with patch.object(builds,'public_checkout',side_effect=AssertionError('must refuse first')):
   with self.assertRaisesRegex(ValueError,'NULL|UNBOUND'):owner.Integration(ROOT,None,None,p,Path('/ABSENT')).authorize()
 def test_exact_worker_five_generated_mounts_caps_network_and_namespace(self):
  paths={k:Path('/owned')/k for k in('runner','seed','proof','work','out')};argv=runtime.argv('worker','sha256:'+'a'*64,'b'*32,paths);mounts=owner.parse_mounts(argv)
  worker=C.module('ksm_worker_contract',ROOT/'copyworker/scripts/ci/current606-ksm2-copy/contract.py');worker.bindings(mounts);self.assertEqual({v for v in argv if v.startswith('--cap-add=')},{'--cap-add='+v for v in worker.WORKER_CAPS});self.assertIn('--network=none',argv);self.assertIn('/runner/scripts/ci/current606-ksm2-copy/worker.py',argv);self.assertNotIn('--privileged',argv)
 def test_native_pair_source_is_not_apps_or_welcome_qualification(self):
  self.assertEqual(S.KSM,'72ea5a1e81268f08da9b9cc04cdc7e23a1a9ff8a');self.assertIsNone(S.PAIR_SOURCE);self.assertIsNone(S.PAIR_INDEX)
  for name in('apps_source','welcome_source','apps_qualification','welcome_qualification'):self.assertNotIn(name,C.read(HERE/'input-policy.json'))
 def test_pure_role_hierarchy_and_future_actuals_null(self):
  fact=C.verify();self.assertIsNone(fact['actual_source']);self.assertIsNone(fact['actual_ref']);self.assertIsNone(fact['actual_run']);self.assertEqual(fact['roles']['held606'],263)
if __name__=='__main__':unittest.main(verbosity=2)
