# SPDX-License-Identifier: MIT
"""Disposable host diagnostic controls; no package/native/network/signing actors."""
import base64,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import driver_progress as D
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='normal604-progress-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.data=self.root/'data';self.data.mkdir(mode=0o700)
 def row(self,**values):return dict(stdout=b'partial stdout\xff',stderr=b'actual stderr\x00',termination='timeout',returncode=-15,direct_child_reaped=True,group_kill_sent=True,**values)
 def state(self,phase='copy'):return dict(phase=phase,commit_started='UNKNOWN',packages_committed='UNKNOWN',checkpoint_changed='UNKNOWN')
 def test_actual_captured_bytes_and_partial_phase_never_grant_commit_truth(self):
  w=D.Writer(self.data);state=self.state();w.record(state);state['phase']='update';w.record(state);w.close();report=D.capture(self.row(),self.data)
  for name in ('stdout','stderr'):self.assertEqual(base64.b64decode(report['outputs'][name]['base64']),self.row()[name]);self.assertIn('PARTIAL',report['outputs'][name]['capture'])
  self.assertEqual(report['progress']['last_completed_write']['phase'],'update');self.assertEqual(report['commit_inference'],'FORBIDDEN_FROM_PROGRESS');self.assertEqual(state['packages_committed'],'UNKNOWN')
 def test_partial_last_write_is_retained_without_interpreting_it(self):
  w=D.Writer(self.data);w.record(self.state());w.close();p=self.data/D.FILE;p.write_bytes(p.read_bytes()+b'{"partial":');report=D.capture(self.row(),self.data)['progress'];self.assertEqual(report['status'],'OBSERVED_COMPLETE_WRITES_ONLY');self.assertEqual(len(report['records']),1);self.assertEqual(base64.b64decode(report['trailing_fragment']['base64']),b'{"partial":')
 def test_aliases_nonprivate_and_conflicting_journal_are_refused(self):
  outside=self.root/'outside';outside.write_bytes(b'untouched');(self.data/D.FILE).symlink_to(outside)
  self.assertEqual(D.capture(self.row(),self.data)['progress']['status'],'UNAVAILABLE_OR_REFUSED');state=self.state();self.assertIsNone(D.start(self.data,state));self.assertEqual(outside.read_bytes(),b'untouched');(self.data/D.FILE).unlink()
  os.link(outside,self.data/D.FILE);self.assertEqual(D.capture(self.row(),self.data)['progress']['status'],'UNAVAILABLE_OR_REFUSED');(self.data/D.FILE).unlink();self.data.chmod(0o755)
  self.assertEqual(D.capture(self.row(),self.data)['progress']['status'],'UNAVAILABLE_OR_REFUSED')
 def test_malformed_duplicate_and_nonfinite_journals_refuse(self):
  for raw in (b'{"sequence":0,"sequence":0}\n',b'{"elapsed_ms":NaN}\n',b'[]\n'):
   p=self.data/D.FILE;p.write_bytes(raw);p.chmod(0o600)
   report=D.capture(self.row(),self.data)['progress'];self.assertEqual(report['status'],'UNAVAILABLE_OR_REFUSED');self.assertEqual(base64.b64decode(report['base64']),raw)
 def test_writer_failure_does_not_replace_original_failure(self):
  state=self.state();state.update(status='FAIL',error='original guard',error_type='ValueError');w=D.Writer(self.data);(self.data/D.FILE).chmod(0o644);D.note(w,state);w.close();self.assertEqual(state['error'],'original guard');self.assertIn('progress_diagnostic_error',state)
 def test_frame_budget_and_original_combined_output_limit(self):
  row=self.row();row.update(stdout=b'x'*D.OUTPUT,stderr=b'');report=D.capture(row,self.data);hook=dict(driver={'retained':'x'*D.OUTPUT},worker_diagnostic=report);raw=json.dumps(hook).encode();self.assertLess(len(raw),4*1024**2);self.assertLess(2*len(raw)+65536,8*1024**2)
  row['stderr']=b'x'
  with self.assertRaisesRegex(ValueError,'combined'):D.capture(row,self.data)
 def test_real_owned_host_timeout_captures_bytes_and_journal_after_reap(self):
  root=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file());path=root/'scripts/update/supervision.py';spec=importlib.util.spec_from_file_location('original_progress_supervisor',path);s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
  child=self.root/'child.py';child.write_text('import sys,time,os\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(Path(D.__file__).parent))+')\nimport driver_progress as D\nw=D.Writer(Path('+repr(str(self.data))+'))\nw.record(dict(phase="update",commit_started="UNKNOWN",packages_committed="UNKNOWN",checkpoint_changed="UNKNOWN"))\nos.write(1,b"host partial stdout\\xff")\nos.write(2,b"host stderr")\ntime.sleep(10)\n')
  row=s.run([sys.executable,'-I','-B',str(child)],env=dict(PATH='/usr/bin:/bin',HOME=str(self.root),LC_ALL='C'),cwd=str(self.root),timeout=.5,output_limit=1024)
  self.assertEqual(row['termination'],'timeout');self.assertTrue(row['direct_child_reaped']);report=D.capture(row,self.data);self.assertEqual(base64.b64decode(report['outputs']['stdout']['base64']),b'host partial stdout\xff');self.assertEqual(report['progress']['last_completed_write']['phase'],'update')
if __name__=='__main__':unittest.main(verbosity=2)
