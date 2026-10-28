# SPDX-License-Identifier: MIT
"""Portable source fixtures and exact public-byte controls, never native acceptance."""
import base64,builtins,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('_dependency_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(sp);sp.loader.exec_module(F)
SOURCE=F.ordinary(os.environ['FRESH_DEPENDENCY_INPUT']);EXPECTED=F.ordinary(os.environ['FRESH_DEPENDENCY_EXPECTED'])
class Controls(unittest.TestCase):
 def test_literal_cli_both_receipts_all1203_bytes_modes_and_null_actuals(self):
  expected=F.tree(EXPECTED)
  with tempfile.TemporaryDirectory()as td:
   for context in('known','null'):
    output=Path(td)/context;argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--context',context]
    done=subprocess.run(argv,capture_output=True,timeout=30,umask=0o077);self.assertEqual(done.returncode,0,done.stderr.decode());row=json.loads(done.stdout)
    self.assertEqual(F.tree(output),expected);self.assertEqual(len(row['files']),1203);self.assertEqual(row['source'],'15eed0d72b793117e0a44e670567acea63c2819c'if context=='known'else None)
    self.assertTrue(all(row[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertTrue(all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in expected))
 def test_constructor_never_executes_supplied_source_or_actors(self):
  sentinel=object();saved=sys.modules.get('common',sentinel)
  try:
   sys.modules['common']=sentinel
   with patch.object(builtins,'exec',side_effect=AssertionError('NO_PARENT_EXECUTION')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(base64,'b64decode',side_effect=AssertionError('NO_CODECS')):
    result,*_=F.compose(SOURCE)
   self.assertIs(sys.modules['common'],sentinel);self.assertEqual(result,F.tree(EXPECTED))
  finally:
   if saved is sentinel:sys.modules.pop('common',None)
   else:sys.modules['common']=saved
 def test_full_before_inverse_all1197_held_and_fixed_diagnostic_clock_contract(self):
  values,p,*_=F.compose(SOURCE);before=F.tree(SOURCE);parent=json.loads(values['implementation/page-parent.json']);d=parent['dependency_parent'];restored=dict(values)
  for n,b in d['before_bodies'].items():restored[n]=b.encode()
  self.assertEqual(restored,before);self.assertEqual(len(p['held']),1197);self.assertEqual({n for n in before if before[n]!=values[n]},set(p['changed']))
  for n in p['held']:self.assertEqual(values[n],before[n],n)
  self.assertEqual(p['clocks'],dict(source=300,dependency=180,term=10,kill=5,data=393216,report=458752,transport_member=4194304))
  changes=json.loads(F.read(HERE/'helper-edits.json'));helper=values['implementation/producer_diagnostic.py'];self.assertTrue(helper.endswith(changes['append'].encode()));self.assertEqual(F.apply(helper[:-len(changes['append'].encode())],changes['edits'],True),before['implementation/producer_diagnostic.py'])
  self.assertEqual(values['implementation/workflow-template.yml'],before['implementation/workflow-template.yml']);self.assertEqual(values['implementation/run.py'],before['implementation/run.py'])
 def test_paths_double_slash_literal_cli_and_no_writes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);source=root/'source';shutil.copytree(SOURCE,source);alias=root/'alias';alias.symlink_to(source,target_is_directory=True);actual=root/'native-actual-fixture';actual.mkdir()
   for supplied,out in((source,source),(source,source/'child'),(alias,root/'out'),(source,'relative'),(source,str(root)+'/a/../out'),(source,actual/'out'),(source,HERE/'out')):
    with self.subTest(out=out),self.assertRaises(ValueError):F.emit(supplied,out,'null')
   for supplied,out in((source,'//'+str(source).lstrip('/')+'/double-slash-output'),('//'+str(source).lstrip('/'),root/'alias-output')):
    before=F.scan(source);done=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(supplied),'--output',str(out),'--context','null'],capture_output=True,timeout=10)
    self.assertNotEqual(done.returncode,0);self.assertIn(b'canonical resolved path required',done.stderr);self.assertFalse(Path(out).exists());self.assertEqual(F.scan(source),before)
   with self.assertRaises(ValueError):F.emit(source,root/'absent','foreign')
   self.assertFalse((root/'absent').exists())
 def test_whole_source_drift_empty_links_special_nodes_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for kind in('drift','missing','foreign','empty','symlink','hardlink','fifo'):
    source=root/kind;shutil.copytree(SOURCE,source);leaf=source/'implementation/producer_diagnostic.py'
    if kind=='drift':leaf.write_bytes(leaf.read_bytes()+b'\n')
    elif kind=='missing':leaf.unlink()
    elif kind=='foreign':(source/'foreign').write_bytes(b'foreign')
    elif kind=='empty':(source/'foreign-empty').mkdir()
    elif kind=='symlink':leaf.unlink();leaf.symlink_to(SOURCE/'implementation/producer_diagnostic.py')
    elif kind=='hardlink':leaf.unlink();os.link(source/'implementation/run.py',leaf)
    else:leaf.unlink();os.mkfifo(leaf)
    out=root/(kind+'-output')
    with self.subTest(kind=kind),self.assertRaises(ValueError):F.emit(source,out,'known')
    self.assertFalse(out.exists())
 def test_profile_and_each_readable_operand_drift_refuse_prewrite(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for name in('profile.json','helper-edits.json','dependency-context.json'):
    local=root/name;shutil.copytree(HERE,local);leaf=local/name;leaf.write_bytes(leaf.read_bytes()+b' ');previous=F.HERE
    try:
     F.HERE=local;out=root/(name+'-output')
     with self.subTest(name=name),self.assertRaises(ValueError):F.emit(SOURCE,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
 def test_late_inode_operand_drift_and_stable_atime_exclusion(self):
  self.assertNotIn('st_atime_ns',F.identity.__code__.co_consts)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for kind in('source','operand'):
    source=root/(kind+'-source');local=root/(kind+'-factory');shutil.copytree(SOURCE,source);shutil.copytree(HERE,local);previous=F.HERE;original=F.scan;calls=[]
    def scan(path):
     value=original(path)
     if Path(path)==source and not calls:
      calls.append(True)
      if kind=='source':leaf=source/'implementation/run.py';replacement=source/'replacement';replacement.write_bytes(leaf.read_bytes());os.replace(replacement,leaf)
      else:leaf=local/'dependency-context.json';leaf.write_bytes(leaf.read_bytes()+b' ')
     return value
    try:
     F.HERE=local;out=root/(kind+'-output')
     with patch.object(F,'scan',side_effect=scan),self.assertRaises(ValueError):F.emit(source,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
if __name__=='__main__':unittest.main(verbosity=2)
