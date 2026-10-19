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
  p=C.read(HERE/'null-policy.json');self.assertIsNone(p['native_pair_source']);self.assertTrue(all(x is None for x in p['current606'].values()))
  with patch.object(builds,'public_checkout',side_effect=AssertionError('must refuse first')):
   with self.assertRaisesRegex(ValueError,'NULL|UNBOUND'):owner.Integration(ROOT,None,None,p,Path('/ABSENT')).authorize()
 def test_exact_worker_five_generated_mounts_caps_network_and_namespace(self):
  paths={k:Path('/owned')/k for k in('runner','seed','proof','work','out')};argv=runtime.argv('worker','sha256:'+'a'*64,'b'*32,paths);mounts=owner.parse_mounts(argv)
  worker=C.module('ksm_worker_contract',ROOT/'copyworker/scripts/ci/current606-ksm2-copy/contract.py');worker.bindings(mounts);self.assertEqual({v for v in argv if v.startswith('--cap-add=')},{'--cap-add='+v for v in worker.WORKER_CAPS});self.assertIn('--network=none',argv);self.assertIn('/runner/scripts/ci/current606-ksm2-copy/worker.py',argv);self.assertNotIn('--privileged',argv)
 def test_native_pair_source_is_not_apps_or_welcome_qualification(self):
  self.assertEqual(S.KSM,'72ea5a1e81268f08da9b9cc04cdc7e23a1a9ff8a');policy=C.read(HERE/'input-policy.json');self.assertEqual(S.PAIR_SOURCE,policy['native_pair_source']);self.assertEqual(S.PAIR_INDEX,policy['native_pair_index'])
  for name in('apps_source','welcome_source','apps_qualification','welcome_qualification'):self.assertNotIn(name,C.read(HERE/'input-policy.json'))
 def test_pure_role_hierarchy_and_future_actuals_null(self):
  fact=C.verify();self.assertIsNone(fact['actual_source']);self.assertIsNone(fact['actual_ref']);self.assertIsNone(fact['actual_run']);self.assertEqual(fact['roles']['held606'],263)
class Activation(unittest.TestCase):
 def test_exact_shared_recovery_helpers_and_absolute_workflow_operands(self):
  import hashlib
  expected={'archive32.py':(11102,'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418'),'archive32-policy.json':(9488,'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585'),'archive6.py':(None,'5e448ef6677fc26485e044b3ac2d35a07105703d4f1a719bb7c030678eff87ae'),'archive6-policy.json':(None,'4d83dbda592b8b6575d02df65de829226cae3ddffc7268e3d47873ac83f3b322')}
  for name,(size,digest)in expected.items():
   raw=(HERE/name).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
   if size is not None:self.assertEqual(len(raw),size)
  w=(ROOT/'.github/workflows/native-arm-current606-ksm2-owned-copy.yml').read_text()
  for operand in ('archive32_helper','archive32_policy','archive32_inputs','archive6_helper','archive6_policy','archive6_inputs'):
   values=[line.strip()for line in w.splitlines()if line.strip().startswith(operand+'=')];self.assertTrue(values)
   for line in values:self.assertIn('="$GITHUB_WORKSPACE/',line)
  self.assertIn('"$RUNNER_TEMP/frozen574-archive32"',w);self.assertIn('"$RUNNER_TEMP/frozen-updater-archive6"',w);self.assertIn('"$RUNNER_TEMP/alarm-cache"',w)
  self.assertLess(w.index('Prefetch exact original26'),w.index('Build the fresh native base'));self.assertLess(w.index('archive6_helper='),w.index('Required signed604 plus606'))
  self.assertIn("&& steps.frozen574_archive32.outcome == 'success'",w)
 def test_prospective_public_pair_and_genuine606_or_null_before_actors(self):
  p=C.read(HERE/'input-policy.json')
  self.assertTrue(all(p[k]is None for k in('actual_source','actual_ref','actual_run','nonce','measurement','output','retirement','capture_receipt')))
  if p['native_pair_source']is None:
   with self.assertRaisesRegex(ValueError,'NULL|UNBOUND'):C.authorize(p)
  else:
   self.assertEqual(p['native_pair_source'],'fe67aaaae7ef4ea94dfc8a42cd2c806cc5436fc7');self.assertIs(C.authorize(p),p);self.assertEqual(S.decision(p['current606'])['package_count'],606)
   wrong=dict(p,actual_run=1)
   with self.assertRaises(ValueError):C.authorize(wrong)
 def test_worker_and_lifecycle_budgets_runtime_and_six_checkpoints_held(self):
  W,P,I=builds.apis();self.assertEqual((W.COPY_SECONDS,W.WORKER_SECONDS,W.CLEANUP_SECONDS),(600,1800,60));self.assertEqual(runtime.SECONDS,dict(finalize=600,worker=1800,dispose=120))
  import ast
  tree=ast.parse((ROOT/'copyworker/scripts/ci/current606-ksm2-copy/lifecycle.py').read_bytes());phases=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PHASES'for t in n.targets)))
  self.assertEqual(phases,(('baseline1','0.1.0-1'),('upgrade2','0.1.0-2'),('same-version2','0.1.0-2'),('remove2',None),('reinstall2','0.1.0-2'),('restore-original1','0.1.0-1')))


if __name__=='__main__':unittest.main(verbosity=2)
