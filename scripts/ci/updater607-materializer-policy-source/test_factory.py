# SPDX-License-Identifier: MIT
"""Portable source fixtures and exact public-byte controls, never native acceptance."""
import base64,builtins,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('_updater_argument_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(sp);sp.loader.exec_module(F)
SOURCE=F.ordinary(os.environ['UPDATER_POLICY_INPUT']);EXPECTED=F.ordinary(os.environ['UPDATER_POLICY_EXPECTED'])
class Controls(unittest.TestCase):
 def test_literal_cli_both_receipts_all360_bytes_modes_and_null_actuals(self):
  expected=F.tree(EXPECTED)
  with tempfile.TemporaryDirectory()as td:
   for context in('known','null'):
    output=Path(td)/context;argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--context',context]
    done=subprocess.run(argv,capture_output=True,timeout=30,umask=0o077);self.assertEqual(done.returncode,0,done.stderr.decode());row=json.loads(done.stdout)
    self.assertEqual(F.tree(output),expected);self.assertEqual(len(row['files']),360);self.assertEqual(row['source'],'c6a5de859c3f190d47a5aef30962d2c3b50eaf8d'if context=='known'else None)
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
 def test_complete_public_parent_and_all_three_source_inverses_all344_held(self):
  values,p,*_=F.compose(SOURCE);before=F.tree(SOURCE);contexts=json.loads(F.read(HERE/'binding-context.json'));edits=json.loads(F.read(HERE/'edits.json'))
  api=__import__('types').SimpleNamespace(need=F.need,pin=F.pin,encoded=F.encoded,apply=F.apply)
  intermediate=F._TRANSFORM.descriptor(before,p,contexts['descriptor'],edits,api)
  database_before=F._TRANSFORM.cleanup(intermediate,p,contexts['cleanup'],edits,api)
  restored=F._TRANSFORM.database_inverse(values,database_before,p,contexts['database'],edits,api)
  self.assertEqual(F._TRANSFORM.inverse(restored,before,intermediate,p,contexts,edits,api),before)
  self.assertEqual(len(p['held']),344);self.assertEqual(len(p['changed']),16);self.assertEqual({n for n in before if before[n]!=values[n]},set(p['changed']))
  parent=json.loads(values['implementation/parent355.json']);self.assertIsNone(parent['producer_cleanup_binding']['source']);self.assertIsNone(parent['producer_cleanup_binding']['ref']);self.assertEqual(p['intermediate']['kind'],'FROZEN_AUTHOR_SOURCE_DATA_NOT_PUBLISHED_AUTHORITY')
  for n in p['held']:self.assertEqual(values[n],before[n],n)
  for n in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-updater4k.yml','implementation/compiler6.py','implementation/cache.py','implementation/entry.py','cases/normal/scripts/update/full_root.py'):
   self.assertEqual(values[n],before[n],n)
  wrong=dict(values);wrong['implementation/runtime.py']+=b'\n'
  with self.assertRaises(ValueError):F._TRANSFORM.database_inverse(wrong,database_before,p,contexts['database'],edits,api)
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
    source=root/kind;shutil.copytree(SOURCE,source);leaf=source/'implementation/runtime.py'
    if kind=='drift':leaf.write_bytes(leaf.read_bytes()+b'\n')
    elif kind=='missing':leaf.unlink()
    elif kind=='foreign':(source/'foreign').write_bytes(b'foreign')
    elif kind=='empty':(source/'foreign-empty').mkdir()
    elif kind=='symlink':leaf.unlink();leaf.symlink_to(SOURCE/'implementation/runtime.py')
    elif kind=='hardlink':leaf.unlink();os.link(source/'implementation/entry.py',leaf)
    else:leaf.unlink();os.mkfifo(leaf)
    out=root/(kind+'-output')
    with self.subTest(kind=kind),self.assertRaises(ValueError):F.emit(source,out,'known')
    self.assertFalse(out.exists())
 def test_profile_and_each_readable_operand_drift_refuse_prewrite(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for name in('profile.json','edits.json','binding-context.json','transformed.py'):
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
      if kind=='source':leaf=source/'implementation/runtime.py';replacement=source/'replacement';replacement.write_bytes(leaf.read_bytes());os.replace(replacement,leaf)
      else:leaf=local/'binding-context.json';leaf.write_bytes(leaf.read_bytes()+b' ')
     return value
    try:
     F.HERE=local;out=root/(kind+'-output')
     with patch.object(F,'scan',side_effect=scan),self.assertRaises(ValueError):F.emit(source,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
 def test_actual_emitted_selected37_cli_not_discovery_or_native(self):
  held=F.ordinary(os.environ['UPDATER_HELD_INPUT']);values,p,*_=F.compose(SOURCE)
  source_profile=json.loads(values['implementation/profile.json']);self.assertEqual({n:F.pin(b)for n,b in F.tree(held).items()},source_profile['held_files']);self.assertEqual(len(source_profile['held_files']),489)
  with tempfile.TemporaryDirectory()as td:
   target=Path(td)/'source';F.emit(SOURCE,target,'known');self.assertEqual(F.tree(target),F.tree(EXPECTED))
   env={k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')};env['LATEST607_HELD_SOURCE']=str(held)
   done=subprocess.run([sys.executable,'-I','-B','-Werror',str(target/'test_source.py')],env=env,capture_output=True,timeout=90)
   self.assertEqual(done.returncode,0,done.stderr.decode());self.assertIn(b'Ran 37 tests',done.stderr);self.assertTrue(done.stderr.rstrip().endswith(b'OK'));self.assertEqual(F.tree(target),F.tree(EXPECTED));self.assertEqual({n:F.pin(b)for n,b in F.tree(held).items()},source_profile['held_files'])
if __name__=='__main__':unittest.main(verbosity=2)
