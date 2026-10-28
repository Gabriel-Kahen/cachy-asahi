# SPDX-License-Identifier: MIT
"""Selected source-owned verify/capture/stage controls; no ancestor/native replay."""
import importlib.util,json,os,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fixed_readback_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
SOURCE=F.ordinary(os.environ['GUI_READBACK_SOURCE']);PARENT=F.ordinary(os.environ['GUI_READBACK_INPUT'])
class Controls(unittest.TestCase):
 def test_actual_selected_main_capture_defaults_foreign_actions_and_stage_cap(self):
  values=F.tree(SOURCE);p=json.loads(F.read(HERE/'profile.json'));self.assertEqual({n:F.pin(b)for n,b in values.items()},p['result']['files'])
  saved=dict(sys.modules);paths=list(sys.path)
  try:
   sys.path.insert(0,str(SOURCE/'implementation'));spec=importlib.util.spec_from_file_location('_trusted_current_observer_controls',SOURCE/'implementation/test_observer.py');m=importlib.util.module_from_spec(spec)
   with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_OR_ANCESTOR_PROOF')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS_OR_ANCESTOR_PROOF')):
    spec.loader.exec_module(m)
    suite=unittest.TestSuite(m.Controls(n)for n in('test_selected_verify_only_deadline_and_original_capture_defaults','test_fixed_stage_allowlist_caps_capture_loss_no_contents'));result=unittest.TestResult();suite.run(result)
   self.assertEqual(result.testsRun,2);self.assertEqual(result.errors,[]);self.assertEqual(result.failures,[])
  finally:
   sys.path[:]=paths
   for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
   sys.modules.update(saved)
 def test_qualified_fourcase_policy_typed_profile_and_all_other_clocks(self):
  root=F.tree(SOURCE);before=F.tree(PARENT);policy=json.loads(root['implementation/runner-context-policy.json']);self.assertEqual(set(policy['code']),{'minimal-generic4k','minimal-generic16k','overlay-generic4k','overlay-generic16k'});self.assertFalse(policy['acceptance']);self.assertIsNone(policy['actual']);self.assertEqual(policy['target'],dict(bytes=12076,sha256='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'))
  p=json.loads(root['implementation/build-inventory-parent.json'])['selected_readback']['profile'];self.assertEqual(tuple(p[k]for k in('observer_seconds','caller_seconds','default_observer_seconds','default_caller_seconds','capture_seconds','diagnostic_elapsed_cap_ns')),(1200,1210,600,600,600,1215000000000));self.assertEqual(tuple(p[k]for k in('service_seconds','loop_seconds','runtime_seconds','owner_wait_seconds','native_owner_seconds')),(1800,1900,2350,2800,6600));self.assertEqual(p['native_fit'],'NOT_ESTABLISHED');self.assertTrue(all(p[k]is None for k in('actual_source','actual_ref','actual_run')))
  for n in('implementation/factory/installed607.py','implementation/factory/factory.py','implementation/factory/run.py','implementation/factory/service-vm-profile.json','implementation/expected607.lock'):self.assertEqual(root[n],before[n],n)
if __name__=='__main__':unittest.main(verbosity=2)
