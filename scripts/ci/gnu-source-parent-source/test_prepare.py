"""Portable complete-source factory controls; no native or immutable activation credit."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));import prepare as F
PARENT=Path(os.environ['GNU_PARENT_SOURCE']).absolute();EXPECTED=Path(os.environ['GNU_EXPECTED_SOURCE']).absolute()
LANE='scripts/ci/gnu-immutable-source-native';LEAF='runtime/immutable/worker_api.py'
class Controls(unittest.TestCase):
 def test_complete745_maps_and_actual_isolated_cli(self):
  p=F.profile();self.assertEqual((p['parent_source'],p['expected_source']),('4a9b38339f23eca5ba1a413e267c97d0916c8f7e','236405a169d764e612e6e9028d196ee3500f6c33'))
  self.assertEqual(F.pins(F.tree(PARENT,checkout=True)),p['before']);self.assertEqual(F.pins(F.tree(EXPECTED,checkout=True)),p['after'])
  self.assertEqual((len(p['changed']),p['held']),(8,737))
  for n in p['before']:
   if n not in p['changed']:self.assertEqual((PARENT/n).read_bytes(),(EXPECTED/n).read_bytes())
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';result=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--parent',str(PARENT),'--output',str(out)],cwd=td,capture_output=True,timeout=30,check=True)
   self.assertEqual(result.stderr,b'');v=json.loads(result.stdout);self.assertEqual((v['status'],v['files'],v['changed'],v['held'],v['native_fit'],v['acceptance']),('SOURCE_ONLY',745,8,737,'UNKNOWN',False));self.assertEqual(F.tree(out),F.tree(EXPECTED,checkout=True))
  result=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--help'],capture_output=True,timeout=10,check=True);self.assertIn(b'--parent',result.stdout);self.assertEqual(result.stderr,b'')
 def test_only_top_level_checkout_metadata_ignored(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));(parent/'.git').mkdir();(parent/'.git/config').write_text('NOT_EXECUTED_METADATA');out=root/'out';F.emit(parent,out);self.assertEqual(F.pins(F.tree(out)),F.profile()['after']);self.assertFalse((out/'.git').exists())
   (parent/'foreign').mkdir();(parent/'foreign/.git').write_text('NOT_CHECKOUT_METADATA')
   with self.assertRaisesRegex(ValueError,'whole pinned GNU'):F.emit(parent,root/'extra')
   self.assertFalse((root/'extra').exists())
 def test_parent_drift_missing_extra_refused_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/LEAF;raw=leaf.read_bytes()
   for mode in('drift','missing','extra'):
    if mode=='drift':leaf.write_bytes(raw+b'x')
    elif mode=='missing':leaf.unlink()
    else:leaf.write_bytes(raw);(parent/'foreign').write_bytes(b'x')
    out=root/mode
    with self.assertRaisesRegex(ValueError,'whole pinned GNU'):F.emit(parent,out)
    self.assertFalse(out.exists())
    if mode in('drift','missing'):leaf.write_bytes(raw)
 def test_payload_profile_drift_refused_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);payload=factory/'payload';leaf=payload/LEAF;raw=leaf.read_bytes()
   with patch.object(F,'HERE',factory):
    for mode in('drift','missing','extra'):
     if mode=='drift':leaf.write_bytes(raw+b'x')
     elif mode=='missing':leaf.unlink()
     else:leaf.write_bytes(raw);(payload/'foreign').write_bytes(b'x')
     out=root/mode
     with self.assertRaisesRegex(ValueError,'whole eight readable'):F.emit(PARENT,out)
     self.assertFalse(out.exists())
     if mode in('drift','missing'):leaf.write_bytes(raw)
    (payload/'foreign').unlink();(factory/'profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'whole fixed GNU'):F.emit(PARENT,root/'profile')
    self.assertFalse((root/'profile').exists())
 def test_source_output_ancestor_and_file_aliases_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for parent,out in[(alias,root/'out'),(PARENT,PARENT),(PARENT,PARENT/'never-created'),(PARENT,HERE/'never-created'),(PARENT,alias/'never-created')]:
    with self.assertRaises(ValueError):F.emit(parent,out)
   holder=root/'owned-alias-file';holder.write_bytes((PARENT/LEAF).read_bytes())
   for mode in('symlink','hardlink'):
    parent=root/mode;shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/LEAF;leaf.unlink()
    if mode=='symlink':leaf.symlink_to(holder)
    else:os.link(holder,leaf)
    try:
     with self.assertRaisesRegex(ValueError,'ordinary single-link'):F.emit(parent,root/(mode+'-out'))
     self.assertFalse((root/(mode+'-out')).exists())
    finally:leaf.unlink()
 def test_read_stable_bytes_allows_actual_atime_refresh(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm')as td:
   leaf=Path(td)/'ordinary';leaf.write_bytes(b'owned');s=leaf.stat();os.utime(leaf,ns=(1,s.st_mtime_ns));self.assertEqual(leaf.stat().st_atime_ns,1);self.assertEqual(F.read(leaf),b'owned');self.assertGreater(leaf.stat().st_atime_ns,1)
   # Deliberate mutation at final path identity read must still be refused.
   before=leaf.lstat;calls=[]
   def lstat(path):
    if path==leaf:
     calls.append(True)
     if len(calls)==2:leaf.write_bytes(b'changed')
     return before()
    return original(path)
   original=Path.lstat
   with patch.object(Path,'lstat',lstat):
    with self.assertRaisesRegex(ValueError,'whole stable'):F.read(leaf)
 def test_complete_emitted_source_preflight_cli(self):
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'source';F.emit(PARENT,source)
   result=subprocess.run([sys.executable,'-I','-B','-Werror',str(source/LANE/'entry.py'),'source','--source',str(source)],cwd=td,capture_output=True,timeout=60,check=True)
   self.assertEqual(result.stderr,b'');value=json.loads(result.stdout);self.assertEqual(value['files'],745);self.assertEqual(value['status'],'PASS_CLOSED_SOURCE_ONLY_NO_ACTORS');self.assertIsNone(value['actual_run']);self.assertIsNone(value['actual_source']);self.assertEqual(F.pins(F.tree(source)),F.profile()['after'])
 def test_all56_actual_emitted_source_controls(self):
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'source';F.emit(PARENT,source)
   result=subprocess.run([sys.executable,'-I','-B','-Werror',str(source/LANE/'test_deployment.py'),'--source',str(source)],cwd=td,capture_output=True,timeout=180)
   sys.stderr.buffer.write(result.stdout+result.stderr);self.assertEqual(result.returncode,0);self.assertRegex(result.stderr,rb'Ran 56 tests in ');self.assertNotRegex(result.stderr,rb'\b(?:skipped|FAILED|ERROR|FAIL)\b');self.assertEqual(F.pins(F.tree(source)),F.profile()['after'])
if __name__=='__main__':unittest.main(verbosity=2)
