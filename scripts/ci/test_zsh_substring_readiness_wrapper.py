# SPDX-License-Identifier: MIT
"""Exact unchanged checker and finite real local PTY failure-observation controls."""
import contextlib,hashlib,importlib.util,io,json,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('ZSH_SUBSTRING_WRAPPER_SOURCE',HERE.parents[1]));CHECKER=ROOT/'packages/tools/cachy-asahi-zsh-history-substring-search/check-module.py'
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
W=load('outer_readiness',HERE/'zsh-substring-readiness-wrapper.py')
A=load('explicit_queued_reset',HERE/'zsh-substring-zle-reset-adapter.py')
class Controls(unittest.TestCase):
 def args(self,root):return ['--module-dir',str(CHECKER.parent),'--work',str(root)]
 def test_exact_checker_and_four_callsite_source_gate(self):
  path,raw=W.source(CHECKER);self.assertEqual(hashlib.sha256(raw).hexdigest(),W.CHECKER);self.assertEqual(tuple(W.phases(raw).values()),W.PHASES)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'checker.py';p.write_bytes(raw+b' ')
   with self.assertRaisesRegex(ValueError,'size'):W.run(p,[])
   p.write_bytes(raw[:-1]+b'x')
   with self.assertRaisesRegex(ValueError,'hash'):W.run(p,[])
   p.unlink();p.symlink_to(CHECKER)
   with self.assertRaisesRegex(ValueError,'ordinary'):W.run(p,[])
 def test_real_adapted_five_cases_success_exit_and_declared_source_identity(self):
  with tempfile.TemporaryDirectory() as td,contextlib.redirect_stdout(io.StringIO()) as stdout:
   root=Path(td);before=list(sys.argv);code=A.run(CHECKER,self.args(root));self.assertEqual(code,0,stdout.getvalue()[-8192:]);self.assertEqual(sys.argv,before);value=json.loads((root/'receipt.json').read_bytes());self.assertEqual(value['status'],'PASS_HOST_ZSH_PTY_CONTROLS');self.assertEqual(len(value['tests']),5);self.assertTrue(all(r['status']=='PASS' for r in value['tests']));self.assertFalse((root/'outer-readiness.json').exists());self.assertNotIn('ZSH_SUBSTRING_READINESS',stdout.getvalue());facts=json.loads((root/'reset-adapter.json').read_bytes());self.assertEqual(facts,A.identity());self.assertNotEqual(facts['derived_checker_sha256'],facts['original_checker_sha256']);self.assertIn('ZSH_SUBSTRING_RESET_ADAPTER',stdout.getvalue())
 def test_real_final_reset_stall_retains_phase_without_changing_original_failure(self):
  # A CONTROLLED dropped final fixture Ctrl-C, not the cause of hosted39046824013.
  checker,raw=W.source(CHECKER);M=load('controlled_original_checker',checker);original=M.Terminal.send;counter=[0];processes=[];init=M.Terminal.__init__
  def capture(terminal,zsh,home):init(terminal,zsh,home);processes.append(terminal.process)
  def send(terminal,data):
   if data==b'\x03':
    counter[0]+=1
    if counter[0]==5:return # Force exactly the unfulfilled FINAL reset predicate.
   return original(terminal,data)
  with tempfile.TemporaryDirectory() as td,patch.object(M.Terminal,'send',send),patch.object(M.Terminal,'__init__',capture),contextlib.redirect_stdout(io.StringIO()) as stdout:
   root=Path(td);self.assertEqual(W.execute(M,checker,raw,self.args(root)),1);receipt=json.loads((root/'receipt.json').read_bytes());self.assertEqual([r['status'] for r in receipt['tests']],['PASS','FAIL','PASS','PASS','PASS']);self.assertEqual(receipt['tests'][1]['reason'],'PTY readiness deadline/exit; status=None')
   facts=json.loads((root/'outer-readiness.json').read_bytes());row=facts['failures'][0];self.assertEqual(row['case'],'editing');self.assertEqual(row['phase'],'reset-prompt');self.assertEqual(row['snapshots_requested'],10);self.assertTrue(row['snapshot_exists'] and row['snapshot_done_exists']);self.assertIs(type(row['prompt_sequence']),int);self.assertFalse(facts['acceptance_authority'] or facts['cleanup_authority']);self.assertEqual(stat.S_IMODE((root/'outer-readiness.json').stat().st_mode),0o600);self.assertLess((root/'outer-readiness.json').stat().st_size,8192);self.assertIn('ZSH_SUBSTRING_READINESS',stdout.getvalue());self.assertNotIn(str(root),json.dumps(facts))
   for proc in processes:self.assertIsNotNone(proc.returncode)
   self.assertEqual((root/'editing/history').read_bytes(),b'preserve existing on-disk history\n');self.assertFalse((root/'editing/PWNED').exists());self.assertFalse((root/'editing/unexpected-rc').exists())
 def test_partial_counter_is_unavailable_not_success_or_exception(self):
  checker,raw=W.source(CHECKER);M=load('finite_projection_checker',checker)
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);home=root/'editing';home.mkdir(mode=0o700);(home/'prompt-sequence').write_bytes(b'')
   observer=W.Observer(M,checker,raw,root);observer.failures=[dict(home=home,phase='snapshot-done',snapshots_requested=10,wait_calls=26,process_status=None)];value=observer.project();row=value['failures'][0];self.assertIsNone(row['prompt_sequence']);self.assertEqual(row['prompt_counter_status'],'UNAVAILABLE_OR_PARTIAL');self.assertFalse(value['acceptance_authority']);self.assertFalse(row['snapshot_exists'] or row['snapshot_done_exists'])
 def test_only_finite_original_methods_are_observed_no_profiler(self):
  text=(HERE/'zsh-substring-readiness-wrapper.py').read_text();self.assertNotIn('setprofile',text);self.assertNotIn('settrace',text);self.assertNotIn('f_locals',text);self.assertIn('return observer.original[2](terminal,predicate)',text);self.assertNotIn('time.sleep',text);self.assertNotIn('setrlimit',text)

 def test_exact_derivation_refuses_drift_and_preserves_other_original_functions(self):
  checker,raw=W.source(CHECKER);derived=A.derive(raw);self.assertEqual(hashlib.sha256(derived).hexdigest(),A.DERIVED)
  with self.assertRaisesRegex(ValueError,'exact original checker'):A.derive(raw+b' ')
  self.assertEqual(tuple(W.phases(derived).values()),W.PHASES)
 def test_real_queued_final_reset_stall_is_still_a_failure(self):
  checker,original=W.source(CHECKER);raw=A.derive(original);filename='explicit-derived-checker-negative';M=A.module(raw,filename);send_original=M.Terminal.send;counter=[0];processes=[];init=M.Terminal.__init__
  def capture(terminal,zsh,home):init(terminal,zsh,home);processes.append(terminal.process)
  def send(terminal,data):
   if data==b'\x07':
    counter[0]+=1
    if counter[0]==5:return
   return send_original(terminal,data)
  with tempfile.TemporaryDirectory() as td,patch.object(M.Terminal,'send',send),patch.object(M.Terminal,'__init__',capture),contextlib.redirect_stdout(io.StringIO()):
   root=Path(td);self.assertEqual(A.execute(M,filename,raw,self.args(root)),1);value=json.loads((root/'receipt.json').read_bytes());self.assertEqual([r['status'] for r in value['tests']],['PASS','FAIL','PASS','PASS','PASS']);self.assertEqual(value['tests'][1]['reason'],'PTY readiness deadline/exit; status=None');facts=json.loads((root/'outer-readiness.json').read_bytes());row=facts['failures'][0];self.assertEqual((row['case'],row['phase'],row['snapshots_requested'],row['wait_calls']),('editing','reset-prompt',10,26));self.assertEqual(facts['checker_sha256'],A.DERIVED);self.assertEqual(facts['original_checker_sha256'],W.CHECKER);self.assertFalse(facts['acceptance_authority']);self.assertEqual((root/'editing/history').read_bytes(),b'preserve existing on-disk history\n')
   for process in processes:self.assertIsNotNone(process.returncode)

if __name__=='__main__':unittest.main(verbosity=2)
