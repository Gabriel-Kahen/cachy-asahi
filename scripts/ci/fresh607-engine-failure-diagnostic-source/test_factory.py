# SPDX-License-Identifier: MIT
"""Portable source fixtures and exact public-byte controls, never native acceptance."""
import base64,builtins,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('_page_binding_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(sp);sp.loader.exec_module(F)
SOURCE=F.ordinary(os.environ['FRESH_CACHE_INPUT']);EXPECTED=F.ordinary(os.environ['FRESH_CACHE_EXPECTED'])
class Controls(unittest.TestCase):
 def test_literal_cli_both_receipts_all1203_bytes_modes_and_null_actuals(self):
  expected=F.tree(EXPECTED)
  with tempfile.TemporaryDirectory()as td:
   for context in('known','null'):
    output=Path(td)/context;argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--context',context]
    done=subprocess.run(argv,capture_output=True,timeout=30,umask=0o077);self.assertEqual(done.returncode,0,done.stderr.decode());row=json.loads(done.stdout)
    self.assertEqual(F.tree(output),expected);self.assertEqual(len(row['files']),1203);self.assertEqual(row['source'],'ad31d0c6010d03c8114888ef4cf39075f912ada1'if context=='known'else None)
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
 def test_full_before_inverse_all1196_held_and_only_failure_DATA_operands(self):
  values,p,*_=F.compose(SOURCE);before=F.tree(SOURCE);parent=json.loads(values['implementation/page-parent.json']);c=parent.pop('engine_failure_parent');parent['guard_template']=c['guard_template']
  for name,row in c['products_before'].items():parent['products'][name]=row
  self.assertEqual(F.encoded(parent),before['implementation/page-parent.json'])
  mode=values['implementation/page_mode.py'];self.assertTrue(mode.endswith(c['mode_append'].encode()));self.assertEqual(F.apply(mode[:-len(c['mode_append'].encode())],c['mode_edits'],reverse=True),before['implementation/page_mode.py'])
  test=values['implementation/test_page_mode.py'];entry=b"if __name__=='__main__':\n";test=test.replace(c['test_append'].encode()+b'\n'+entry,entry,1);self.assertEqual(F.apply(test,c['test_edits'],reverse=True),before['implementation/test_page_mode.py'])
  oldsha=F.pin(before['implementation/page-parent.json'])['sha256'];newsha=F.pin(values['implementation/page-parent.json'])['sha256'];guard=values['implementation/page_source.py'].replace(newsha.encode(),b'@PARENT_SHA@',1);self.assertTrue(guard.endswith(c['guard_append'].encode()));guard=guard[:-len(c['guard_append'].encode())];self.assertEqual(F.apply(guard,c['guard_edits'],reverse=True).replace(b'@PARENT_SHA@',oldsha.encode(),1),before['implementation/page_source.py'])
  self.assertEqual(len(p['held']),1196);self.assertEqual(len(p['changed']),7)
  for n in p['held']:self.assertEqual(values[n],before[n],n)
  for n in before:
   if n.startswith('parent604/')or n in('implementation/run.py','implementation/producer_diagnostic.py','implementation/workflow-template.yml','implementation/page-mode-profile.json'):self.assertEqual(values[n],before[n],n)
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
    source=root/kind;shutil.copytree(SOURCE,source);leaf=source/'implementation/page_mode.py'
    if kind=='drift':leaf.write_bytes(leaf.read_bytes()+b'\n')
    elif kind=='missing':leaf.unlink()
    elif kind=='foreign':(source/'foreign').write_bytes(b'foreign')
    elif kind=='empty':(source/'foreign-empty').mkdir()
    elif kind=='symlink':leaf.unlink();leaf.symlink_to(SOURCE/'implementation/compiler6.py')
    elif kind=='hardlink':leaf.unlink();os.link(source/'implementation/run.py',leaf)
    else:leaf.unlink();os.mkfifo(leaf)
    out=root/(kind+'-output')
    with self.subTest(kind=kind),self.assertRaises(ValueError):F.emit(source,out,'known')
    self.assertFalse(out.exists())
 def test_profile_and_each_readable_operand_drift_refuse_prewrite(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for name in('profile.json',*F.compose(SOURCE)[1]['operands']):
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
      else:leaf=local/'engine-context.json';leaf.write_bytes(leaf.read_bytes()+b' ')
     return value
    try:
     F.HERE=local;out=root/(kind+'-output')
     with patch.object(F,'scan',side_effect=scan),self.assertRaises(ValueError):F.emit(source,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
 def test_exact_emitted_private_runtime_source_controls_not_actual_acceptance(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'emitted';row=F.emit(SOURCE,out,'null');self.assertEqual(row['files'],{n:F.pin(b)for n,b in F.tree(EXPECTED).items()})
   # Only the factory's fully pinned exact public result is executed as trusted
   # source controls; compose itself never imports or executes caller source.
   run=subprocess.run([sys.executable,'-I','-B','-Werror',str(out/'implementation/test_page_mode.py')],capture_output=True,timeout=30)
   self.assertEqual(run.returncode,0,run.stderr.decode());self.assertIn(b'Ran 10 tests',run.stderr);self.assertTrue(run.stderr.rstrip().endswith(b'OK'));self.assertEqual(F.tree(out),F.tree(EXPECTED))
if __name__=='__main__':unittest.main(verbosity=2)
