"""Pure regression for source-bound management readiness; no process/GUI actors."""
import ast,importlib.util,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(ROOT/'scripts/ci/welcome-management-native'))
spec=importlib.util.spec_from_file_location('retirement_phase',HERE/'management_phase.py');G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
class Retirement(unittest.TestCase):
 def setUp(self):
  block=patch.object(G.subprocess,'Popen',side_effect=AssertionError('actors forbidden'));block.start();self.addCleanup(block.stop)
 def test_no_accessibility_action_until_both_pidfds_retire(self):
  clock=[100.];states=[dict(helper_absent=False,supervisor_absent=False),dict(helper_absent=True,supervisor_absent=False),dict(helper_absent=False,supervisor_absent=True),dict(helper_absent=True,supervisor_absent=True)];seen=[];calls=[]
  def wait(probe,healthy,seconds,label):
   self.assertEqual(seconds,45);self.assertEqual(label,'actual owned management completion')
   for state in states:
    clock[0]+=2
    with patch.object(G,'request',return_value=state):result=probe()
    if result is not None:return result
    self.assertEqual(calls,[])
   self.fail('both retired must complete')
  def activate(label,scope):
   self.assertEqual(seen[-1],states[-1]);self.assertEqual(label,'View report');self.assertEqual(scope,'Orphan assessment');calls.append(label);clock[0]+=3
  with patch.object(G.time,'monotonic',side_effect=lambda:clock[0]):
   until=G.open_completed_report(wait,Mock(),activate,'Orphan assessment',seen.append)
   self.assertEqual(until,145);self.assertEqual(G.remaining(until),34)
  self.assertEqual(seen,states);self.assertEqual(calls,['View report'])
 def test_expander_cannot_reset_or_exceed_shared_deadline(self):
  clock=[100.]
  def wait(probe,healthy,seconds,label):
   clock[0]=140.
   with patch.object(G,'request',return_value=dict(helper_absent=True,supervisor_absent=True)):self.assertTrue(probe())
  def activate(*args,**kwargs):clock[0]=146.
  with patch.object(G.time,'monotonic',side_effect=lambda:clock[0]),self.assertRaisesRegex(ValueError,'shared45s deadline'):
   G.open_completed_report(wait,Mock(),activate,'Doctor')
 def test_invalid_or_incomplete_completion_never_activates(self):
  activate=Mock()
  def wait(probe,*args):
   with patch.object(G,'request',return_value=dict(helper_absent=1,supervisor_absent=True)):probe()
  with self.assertRaises(ValueError):G.open_completed_report(wait,Mock(),activate,'Doctor')
  activate.assert_not_called()
 def test_exercise_uses_same_deadline_through_capture_and_preserves_live_close(self):
  source=(HERE/'management_phase.py').read_text();tree=ast.parse(source)
  exercise=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='exercise');text=ast.get_source_segment(source,exercise)
  self.assertIn("report_until=open_completed_report(hooks['wait'],healthy,action,",text)
  self.assertIn("capture('management-'+kind,expected,report_until)",text)
  self.assertIn("hooks['wait'](actual_doctor,healthy,remaining(report_until)",text)
  self.assertIn("45 if deadline is None else remaining(deadline)",text)
  self.assertIn("action(ui['labels']['orphans'],scroll=True);closing=observed('orphans',True)",text)
  for original in ("product_timeout(value,current.process.pid)","actual '+view+' reached original product30s command limit",'until=time.monotonic()+40',"base.terminate(current.process);current.finish()",'retain_failure(base,stage,pending,last_snapshot,error)'):
   self.assertIn(original,source)
if __name__=='__main__':unittest.main(verbosity=2)
