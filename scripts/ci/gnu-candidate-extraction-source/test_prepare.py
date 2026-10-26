# SPDX-License-Identifier: MIT
"""Complete771 generation and hostile DATA controls; no input code executes."""
import copy,importlib.util,json,os,shutil,socket,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('_gnu_extraction_factory',HERE/'prepare.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B)

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.parent=B.canonical(os.environ['GNU_EXTRACT_PARENT']);cls.expected=B.canonical(os.environ['GNU_EXTRACT_EXPECTED']);cls.v=B.profile();cls.before=B.snapshot(cls.parent)[0];cls.target=B.snapshot(cls.expected)[0];cls.payload=B.snapshot(HERE/'payload')[0]
  assert B.pins(cls.before)==cls.v['before']and B.pins(cls.target)==cls.v['after'];cls.tmp=tempfile.TemporaryDirectory(prefix='gnu-extraction-factory-controls-',dir=HERE.parent);cls.work=Path(cls.tmp.name)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()

 def test_complete771_exact_target_whole766_inverse_and_all_held_paths(self):
  out=B.transformed(self.before,self.payload,self.v);self.assertEqual(out,self.target);self.assertEqual(B.inverse(out,self.v),self.before);self.assertEqual(len(out),771);self.assertEqual(len(self.v['held']),757);self.assertEqual(len(self.v['changed']),9);self.assertEqual(len(self.v['added']),5)
  self.assertEqual(sum(n.startswith('runtime/')for n in self.before),667);self.assertEqual({n:B.pin(b)for n,b in self.before.items()if out[n]==b},self.v['held'])
  for n,b in self.before.items():
   if n.startswith('runtime/')or n in(B.LANE+'/fixed_case.py',B.LANE+'/interruption_case.py',B.LANE+'/interruption_source.py',B.LANE+'/test_interruption.py'):self.assertEqual(out[n],b)
  q=json.loads(out[B.PROFILE]);self.assertTrue(all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')))

 def test_known_NULL_actual_CLIs_every_byte_mode0644_and_selectors_NULL(self):
  receipts=[]
  for known in(False,True):
   output=self.work/('cli-known'if known else'cli-null');argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--parent',str(self.parent),'--output',str(output)]+(['--known-context']if known else[]);previous=os.umask(0o077)
   try:r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
   finally:os.umask(previous)
   self.assertEqual((r.returncode,r.stderr),(0,b''));receipt=json.loads(r.stdout);receipts.append(receipt);self.assertEqual(receipt['known_parent_context'],known);self.assertEqual(receipt['files'],self.v['after']);self.assertEqual(B.snapshot(output)[0],self.target)
   self.assertTrue(all(receipt[n]is None for n in('current_source','current_ref','current_run','Root_acceptance')));self.assertFalse(receipt['supplied_source_execution']);self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o644 for p in output.rglob('*')if p.is_file()))
  self.assertEqual({k:v for k,v in receipts[0].items()if k!='known_parent_context'},{k:v for k,v in receipts[1].items()if k!='known_parent_context'})

 def test_actual_generation_with_exec_eval_compile_process_network_forbidden(self):
  with patch('builtins.exec',side_effect=AssertionError('NO_INPUT_EXEC')),patch('builtins.eval',side_effect=AssertionError('NO_INPUT_EVAL')),patch('builtins.compile',side_effect=AssertionError('NO_INPUT_COMPILE')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(socket,'socket',side_effect=AssertionError('NO_NETWORK')):receipt=B.emit(self.parent,self.work/'generation-no-execution')
  self.assertEqual(receipt['files'],self.v['after'])

 def test_missing_foreign_changed_and_executable_input_refusals_prewrite(self):
  changes=(lambda p:(p/'foreign').write_bytes(b'foreign DATA'),lambda p:(p/B.LANE/'entry.py').unlink(),lambda p:(p/B.LANE/'entry.py').write_bytes(b'raise SystemExit("NEVER_EXECUTE")\n'))
  for index,change in enumerate(changes):
   bad=self.work/('bad-input-'+str(index));shutil.copytree(self.parent,bad);change(bad);output=self.work/('input-refused-'+str(index))
   with self.assertRaises(ValueError):B.emit(bad,output)
   self.assertFalse(output.exists())

 def test_pinned_profile_metadata_and_readable_payload_drift_refusals(self):
  names=['profile.json',*['payload/'+n for n in self.payload]]
  for index,name in enumerate(names):
   factory=self.work/('bad-factory-'+str(index));shutil.copytree(HERE,factory);path=factory/name;raw=path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:]);output=self.work/('operand-refused-'+str(index))
   with patch.object(B,'HERE',factory),self.assertRaises(ValueError):B.emit(self.parent,output)
   self.assertFalse(output.exists())

 def test_alias_overlap_existing_noncanonical_and_relative_refusals(self):
  alias=self.work/'input-alias';alias.symlink_to(self.parent,target_is_directory=True);existing=self.work/'existing';existing.mkdir()
  for parent,output in((alias,self.work/'alias-refused'),(self.parent,self.parent/'forbidden'),(self.parent,HERE/'forbidden'),(self.parent,existing),(self.parent,Path('relative')),(self.parent,self.work/'missing/../forbidden')):
   with self.assertRaises(ValueError):B.emit(parent,output)
  self.assertEqual(list(existing.iterdir()),[]);self.assertFalse((self.work/'alias-refused').exists())

 def test_empty_directory_symlink_hardlink_FIFO_refusals(self):
  leaf=B.LANE+'/entry.py'
  for index,change in enumerate((lambda p:(p/'empty').mkdir(),lambda p:(p/'alias').symlink_to(leaf),lambda p:os.link(p/leaf,p/'second-link'),lambda p:os.mkfifo(p/'fifo'))):
   bad=self.work/('bad-node-'+str(index));shutil.copytree(self.parent,bad);change(bad);output=self.work/('node-refused-'+str(index))
   with self.assertRaises(ValueError):B.emit(bad,output)
   self.assertFalse(output.exists())

 def test_late_same_bytes_inode_replacement_refuses_before_staging(self):
  bad=self.work/'late-input';shutil.copytree(self.parent,bad);output=self.work/'late-refused';real=B.transformed
  def swap(*args):
   values=real(*args);path=bad/B.LANE/'entry.py';raw=path.read_bytes();fresh=path.with_name('replacement');fresh.write_bytes(raw);fresh.replace(path);return values
  with patch.object(B,'transformed',side_effect=swap),self.assertRaises(ValueError):B.emit(bad,output)
  self.assertFalse(output.exists())

 def test_whole_inverse_wrong_target_and_unknown_context_refusals(self):
  for name in(B.LANE+'/entry.py','runtime/immutable/worker.py'):
   bad=dict(self.target);bad[name]+=b'\n'
   with self.assertRaises(ValueError):B.inverse(bad,self.v)
  real=B.transformed
  def wrong(*args):
   out=real(*args);out[B.LANE+'/entry.py']+=b'\n';return out
  output=self.work/'wrong-target'
  with patch.object(B,'transformed',side_effect=wrong),patch.object(B.tempfile,'TemporaryDirectory',side_effect=AssertionError('NO_STAGING_BEFORE_TARGET_JOIN')),self.assertRaises(ValueError):B.emit(self.parent,output)
  self.assertFalse(output.exists())
  for known in(None,1,'known'):
   with self.assertRaises(ValueError):B.emit(self.parent,self.work/'unknown-context',known)
  self.assertFalse((self.work/'unknown-context').exists())

if __name__=='__main__':unittest.main(verbosity=2)
