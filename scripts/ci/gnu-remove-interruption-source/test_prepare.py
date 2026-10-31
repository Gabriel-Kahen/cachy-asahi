# SPDX-License-Identifier: MIT
"""Focused ordinary-DATA generation/refusal controls; no supplied code runs."""
import copy,importlib.util,json,os,shutil,socket,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('_gnu_remove_factory',HERE/'prepare.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B)

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.parent=B.canonical(os.environ['GNU_REMOVE_PARENT']);cls.record=B.canonical(os.environ['GNU_REMOVE_NORMAL_RECORD']);cls.expected=B.canonical(os.environ['GNU_REMOVE_EXPECTED']);cls.v=B.profile()
  cls.before=B.snapshot(cls.parent)[0];cls.records=B.snapshot(cls.record)[0];cls.payload=B.snapshot(HERE/'payload')[0];cls.target=B.snapshot(cls.expected)[0]
  assert B.pins(cls.before)==cls.v['before']and B.pins(cls.records)==cls.v['normal_record']and B.pins(cls.target)==cls.v['after']
  cls.tmp=tempfile.TemporaryDirectory(prefix='gnu-remove-factory-controls-',dir=HERE.parent);cls.work=Path(cls.tmp.name)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()

 def test_entire_exact766_public_target_and_whole749_inverse(self):
  out=B.transformed(self.before,self.records,self.payload,self.v);self.assertEqual(out,self.target)
  self.assertEqual(sum(n.startswith('runtime/')for n in self.before),667)
  self.assertEqual({n:B.pin(b)for n,b in self.before.items()if out[n]==b},self.v['held'])
  self.assertEqual(out[B.LANE+'/fixed_case.py'],self.before[B.LANE+'/fixed_case.py'])
  q=json.loads(out[B.PROFILE]);self.assertTrue(all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')))
  self.assertEqual(q['runtime_profiles'],json.loads(self.target[B.PROFILE])['runtime_profiles'])

 def test_known_and_NULL_real_CLI_whole766_and_modes(self):
  for known in(False,True):
   out=self.work/('cli-known'if known else'cli-null');argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--parent',str(self.parent),'--normal-record',str(self.record),'--output',str(out)]+(['--known-context']if known else[])
   previous_umask=os.umask(0o077)
   try:p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
   finally:os.umask(previous_umask)
   self.assertEqual((p.returncode,p.stderr),(0,b''));r=json.loads(p.stdout)
   self.assertEqual(r['known_parent_context'],known);self.assertEqual(r['files'],self.v['after']);self.assertEqual(B.snapshot(out)[0],self.target)
   self.assertTrue(all(r[n]is None for n in('current_source','current_ref','current_run','Root_acceptance')));self.assertFalse(r['supplied_source_execution'])
   self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o644 for p in out.rglob('*')if p.is_file()))

 def test_generation_with_exec_eval_compile_process_and_network_forbidden(self):
  with patch('builtins.exec',side_effect=AssertionError('NO_INPUT_EXEC')),patch('builtins.eval',side_effect=AssertionError('NO_INPUT_EVAL')),patch('builtins.compile',side_effect=AssertionError('NO_INPUT_COMPILE')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(socket,'socket',side_effect=AssertionError('NO_NETWORK')):
   receipt=B.emit(self.parent,self.record,self.work/'no-execution')
  self.assertEqual(receipt['files'],self.v['after'])

 def test_foreign_missing_and_changed_input_or_record_refuses_before_writes(self):
  variants=[('parent',lambda p:(p/'foreign').write_bytes(b'foreign')),('parent',lambda p:(p/B.LANE/'entry.py').write_bytes(b'raise SystemExit("NEVER_EXECUTE")\n')),('record',lambda p:(p/'decision.json').unlink())]
  for index,(kind,change)in enumerate(variants):
   bad=self.work/('bad-input-'+str(index));shutil.copytree(self.parent if kind=='parent'else self.record,bad);change(bad);out=self.work/('refused-input-'+str(index))
   with self.assertRaises(ValueError):B.emit(bad if kind=='parent'else self.parent,bad if kind=='record'else self.record,out)
   self.assertFalse(out.exists())

 def test_profile_payload_and_same_size_content_drift_refuse_before_writes(self):
  for index,name in enumerate(('profile.json','payload/profile-operands.json','payload/interruption_case.py')):
   factory=self.work/('bad-factory-'+str(index));shutil.copytree(HERE,factory);path=factory/name;raw=path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:]);out=self.work/('refused-factory-'+str(index))
   with patch.object(B,'HERE',factory),self.assertRaises(ValueError):B.emit(self.parent,self.record,out)
   self.assertFalse(out.exists())

 def test_alias_overlap_existing_and_noncanonical_paths_refuse_prewrite(self):
  alias=self.work/'parent-alias';alias.symlink_to(self.parent,target_is_directory=True);existing=self.work/'existing';existing.mkdir()
  for parent,record,out in((alias,self.record,self.work/'alias-refused'),(self.parent,self.record,self.parent/'forbidden'),(self.parent,self.record,self.record/'forbidden'),(self.parent,self.record,HERE/'forbidden'),(self.parent,self.record,existing),(self.parent,self.record,Path('relative')),(self.parent,self.record,self.work/'missing/../forbidden'),(self.parent,self.parent,self.work/'same-input-refused')):
   with self.assertRaises(ValueError):B.emit(parent,record,out)
  self.assertEqual(list(existing.iterdir()),[])
  self.assertFalse((self.work/'alias-refused').exists());self.assertFalse((self.work/'same-input-refused').exists())

 def test_empty_directory_symlink_hardlink_and_FIFO_refusals(self):
  for index,change in enumerate((lambda p:(p/'empty').mkdir(),lambda p:(p/'alias').symlink_to('decision.json'),lambda p:os.link(p/'decision.json',p/'second-link'),lambda p:os.mkfifo(p/'fifo'))):
   bad=self.work/('bad-node-'+str(index));shutil.copytree(self.record,bad);change(bad);out=self.work/('refused-node-'+str(index))
   with self.assertRaises(ValueError):B.emit(self.parent,bad,out)
   self.assertFalse(out.exists())

 def test_late_same_bytes_inode_replacement_refuses_prewrite(self):
  bad=self.work/'late-input';shutil.copytree(self.record,bad);out=self.work/'late-refused';real=B.transformed
  def swap(*args):
   value=real(*args);p=bad/'decision.json';raw=p.read_bytes();fresh=bad/'replacement';fresh.write_bytes(raw);fresh.replace(p);return value
  with patch.object(B,'transformed',side_effect=swap),self.assertRaisesRegex(ValueError,'late complete input/operand identity drift'):B.emit(self.parent,bad,out)
  self.assertFalse(out.exists())

 def test_wrong_target_and_unknown_context_refuse_before_staging(self):
  real=B.transformed
  def wrong(*args):
   out=real(*args);out[B.LANE+'/entry.py']+=b'\n';return out
  output=self.work/'wrong-target'
  with patch.object(B,'transformed',side_effect=wrong),patch.object(B.tempfile,'TemporaryDirectory',side_effect=AssertionError('NO_STAGING_BEFORE_TARGET_JOIN')),self.assertRaisesRegex(ValueError,'entire exact766 target before staging'):B.emit(self.parent,self.record,output)
  self.assertFalse(output.exists())
  for known in(None,1,'known'):
   with self.assertRaises(ValueError):B.emit(self.parent,self.record,self.work/'unknown-context',known)
  self.assertFalse((self.work/'unknown-context').exists())

if __name__=='__main__':unittest.main(verbosity=2)
