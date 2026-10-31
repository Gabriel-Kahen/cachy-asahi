"""Pure bounded failure-operand controls; no product, GUI or native actors."""
import base64,json,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path[:0]=[str(HERE),str(ROOT/'scripts/ci/welcome-management-native')]
import management_phase as G
import management_contract as C

def snapshot(text='Check stopped: time limit reached.\nExit status: 137; elapsed: 30.1 seconds.',pid=80,showing=True):
 raw=text.encode();return dict(status='PASS',pid=pid,nodes=[dict(name_base64='',role=29,showing=showing,selected=False,checked=False,enabled=True,sensitive=True,body_base64=base64.b64encode(raw).decode(),text_sha256=C.sha(raw),text_bytes=len(raw))])

class FailureCapture(unittest.TestCase):
 def setUp(self):
  block=patch.object(G.subprocess,'Popen',side_effect=AssertionError('actors forbidden'));block.start();self.addCleanup(block.stop)
 def test_only_owned_valid_visible_actual_timeout_text_is_terminal(self):
  self.assertTrue(G.product_timeout(snapshot(),80))
  self.assertFalse(G.product_timeout(snapshot(showing=False),80))
  self.assertFalse(G.product_timeout(snapshot('Elapsed: 1.2 seconds.'),80))
  self.assertFalse(G.product_timeout(snapshot('Assessment refused: existing ALPM lock'),80))
  for value in (snapshot(pid=81),dict(snapshot(),status='FAIL')):
   with self.assertRaises(ValueError):G.product_timeout(value,80)
  value=snapshot();value['nodes'][0]['text_sha256']='0'*64
  with self.assertRaises(ValueError):G.product_timeout(value,80)
 def test_live_child_or_supervisor_never_starts_accessibility_snapshot(self):
  for child,parent in ((False,False),(True,False),(False,True)):
   remember=Mock();a11y=Mock(side_effect=AssertionError('no snapshot while helper live'))
   with patch.object(G,'request',return_value=dict(helper_absent=child,supervisor_absent=parent)):
    self.assertIsNone(G.completed_report_snapshot(a11y,remember))
   remember.assert_called_once_with(dict(helper_absent=child,supervisor_absent=parent));a11y.assert_not_called()
 def test_typed_completion_retained_without_unrelated_root_fields(self):
  remember=Mock();actual=snapshot();a11y=Mock(return_value=actual)
  with patch.object(G,'request',return_value=dict(helper_absent=True,supervisor_absent=True,private_other_field='not copied')):
   self.assertIs(G.completed_report_snapshot(a11y,remember),actual)
  remember.assert_called_once_with(dict(helper_absent=True,supervisor_absent=True));a11y.assert_called_once_with('snapshot')
  with patch.object(G,'request',return_value=dict(helper_absent=1,supervisor_absent=True)),self.assertRaises(ValueError):G.completed_report_snapshot(a11y,remember)
 def test_exact_counterpart_bytes_timing_and_failure_snapshot_retained_only_as_failure(self):
  raw=b'{"unit_control_only":true}\n';pending=dict(kind='orphans',counterpart_elapsed_ns=123,bytes=len(raw),sha256=C.sha(raw),base64=base64.b64encode(raw).decode(),gui_process=dict(pid=90,supervisor_pid=89),gui_completion=dict(helper_absent=True,supervisor_absent=True));emit=Mock();actual=snapshot()
  G.retain_failure(SimpleNamespace(emit=emit),'minimal',pending,actual,ValueError('actual product command limit'))
  args=emit.call_args;self.assertEqual(args.args,('management_failure',));value=args.kwargs
  self.assertEqual(value['counterpart'],pending);self.assertEqual(base64.b64decode(value['counterpart']['base64']),raw)
  self.assertEqual(value['snapshot'],actual);self.assertEqual(value['snapshot_sha256'],C.sha(C.encoded(actual)))
  self.assertEqual(value['status'],'FAIL');self.assertEqual(value['acceptance'],'NOT_ISSUED');self.assertNotIn('frames',value)
 def test_failure_capture_bounds_and_missing_operand_are_honest(self):
  emit=Mock();G.retain_failure(SimpleNamespace(emit=emit),'minimal',None,None,ValueError('original'))
  self.assertIsNone(emit.call_args.kwargs['counterpart']);self.assertNotIn('snapshot',emit.call_args.kwargs)
  with self.assertRaisesRegex(ValueError,'snapshot byte bound'):G.retain_failure(SimpleNamespace(emit=emit),'minimal',None,dict(huge='x'*(C.REPORT_CAP+1)),ValueError('original'))
 def test_original_limits_cleanup_and_acceptance_gates_stay_present(self):
  text=(HERE/'management_phase.py').read_text()
  for original in ('until=time.monotonic()+40',"hooks['wait'](probe,healthy,45",'len(raw)<=ui[\'max_output_bytes\']',"base.terminate(current.process);current.finish()",'reports[kind]=dict(gui_report=gui_report',"base.emit('management_result',stage=stage,reports=reports"):
   self.assertIn(original,text)
  self.assertIn("except BaseException as error:",text);self.assertIn("        raise\n    finally:",text)
  with self.assertRaises(ValueError):C.verify_result([dict(event='management_failure',status='FAIL')],dict(status='VERIFIED_NATIVE_CANDIDATES',products={n:{} for n in ('cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-orphans')},policy={}))

if __name__=='__main__':unittest.main(verbosity=2)
