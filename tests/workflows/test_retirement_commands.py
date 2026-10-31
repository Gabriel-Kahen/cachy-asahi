"""Bounded host Python-child controls for the explicit v2 caller only."""
import importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
P=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('workflow_v2',P/'scripts/workflows/developer_workflow.py');W=importlib.util.module_from_spec(spec);spec.loader.exec_module(W)
def host_only(event,args):
 if event=='subprocess.Popen':
  argv=args[1]
  if type(argv)is not list or argv[:3]!=[sys.executable,'-I','-B']:raise AssertionError('only fixed fresh host Python fixtures allowed')
 if event.startswith('socket.'):raise AssertionError('no network fixtures')
sys.addaudithook(host_only)
class WorkflowV2Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='release-v2-workflow-host-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.output=self.root/'out';self.output.mkdir();self.home=self.root/'home';self.home.mkdir()
  self.commands=W.RetirementCommands(self.output,self.home,os.defpath,timeout=2,total=8,max_output=4096)
 def run_python(self,code,expected=0):return self.commands.run('fixture',[sys.executable,'-I','-B','-c',code],self.root,expected)
 def test_exit_zero_requires_reserved_group_proof(self):
  self.assertEqual(self.run_python('print("fixture")'),b'fixture\n');r=self.commands.records[-1]
  self.assertTrue(r['success']);self.assertEqual(r['supervision']['group_census'],'RESERVED_LEADER_ONLY');self.assertTrue(r['supervision']['reaped'])
 def test_observed_native_classification_remains_failure(self):
  supervise=self.commands.core.supervise
  def counterfactual(child,**kwargs):
   result=supervise(child,**kwargs);self.assertEqual(result['group_census'],'RESERVED_LEADER_ONLY');result=dict(result,group_census='PRESENT_OR_REUSED',passed=False);return result
  with patch.object(self.commands.core,'supervise',side_effect=counterfactual),self.assertRaises(W.Failure):self.run_python('print("fixture")')
  self.assertEqual(self.commands.records[-1]['supervision']['exit'],0);self.assertFalse(self.commands.records[-1]['success'])
 def test_expected_nonzero_still_needs_custody(self):
  self.run_python('raise SystemExit(7)','nonzero');r=self.commands.records[-1];self.assertTrue(r['success']);self.assertEqual(r['supervision']['exit'],7);self.assertEqual(r['supervision']['group_census'],'RESERVED_LEADER_ONLY')
  with self.assertRaises(W.Failure):self.run_python('pass','nonzero')
 def test_unqualified_expected_nonzero_is_refused(self):
  supervise=self.commands.core.supervise
  def counterfactual(child,**kwargs):return dict(supervise(child,**kwargs),group_census='RESERVED_MEMBERS_REMAIN',passed=False)
  with patch.object(self.commands.core,'supervise',side_effect=counterfactual),self.assertRaises(W.Failure):self.run_python('raise SystemExit(7)','nonzero')
 def test_strict_v2_pin_and_unknown_profile_refuse(self):
  with patch.object(W,'RETIREMENT_V2_PIN','0'*64),self.assertRaisesRegex(ValueError,'pin differs'):W.load_retirement_core()
  with self.assertRaises(ValueError):W.Commands(self.output,self.home,os.defpath,retirement_profile='guess')
 def test_legacy_loader_and_default_profile_remain(self):
  with patch.object(W,'load_core',return_value=object())as old,patch.object(W,'load_retirement_core',side_effect=AssertionError('v2 not default')):
   legacy=W.Commands(self.output,self.home,os.defpath);self.assertEqual(legacy.retirement_profile,'legacy');old.assert_called_once()
if __name__=='__main__':unittest.main(verbosity=2)
