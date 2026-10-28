"""Portable full-source controls for the explicit immutable-map route; no actors."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import prepare as F,immutable_map as M
PARENT=Path(os.environ['GNU_IMMUTABLE_PARENT_SOURCE']).absolute();EXPECTED=Path(os.environ['GNU_IMMUTABLE_EXPECTED_SOURCE']).absolute()
OLD_PARENT=Path(os.environ['GNU_PARENT_SOURCE']).absolute();OLD_EXPECTED=Path(os.environ['GNU_EXPECTED_SOURCE']).absolute()
LANE='scripts/ci/gnu-immutable-source-native';LEAF='runtime/immutable/worker_api.py'
def command(argv,seconds=180):
 r=subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,argv)],capture_output=True,timeout=seconds)
 if r.returncode:sys.stderr.buffer.write(r.stdout+r.stderr)
 return r
class Controls(unittest.TestCase):
 def test_exact745_cli_aliases_and_null_actual_source(self):
  v=M.profile();self.assertEqual((v['parent_source'],v['expected_source'],v['held']),('406d5a3a8902570c8fb1fa5043c557b18d15b308','46db580a56f0a88621216f869fd5b1333d21b6b7',736));self.assertEqual(F.pins(F.tree(PARENT,True)),v['before']);self.assertEqual(F.pins(F.tree(EXPECTED,True)),v['after'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=command([HERE/'prepare.py','--immutable-map','--parent',PARENT,'--output',out]);self.assertEqual((r.returncode,r.stderr),(0,b''));receipt=json.loads(r.stdout);self.assertEqual((receipt['files'],receipt['changed'],receipt['held'],receipt['acceptance']),(745,9,736,False));self.assertEqual(F.tree(out),F.tree(EXPECTED,True));self.assertEqual((out/'.github/workflows/native-arm-build.yml').read_bytes(),(out/'.github/workflows/native-arm-gnu-immutable-source.yml').read_bytes())
   r=command([out/LANE/'entry.py','source','--source',out]);self.assertEqual((r.returncode,r.stderr),(0,b''));proof=json.loads(r.stdout);self.assertEqual(proof['status'],'PASS_CLOSED_SOURCE_ONLY_NO_ACTORS');self.assertIsNone(proof['actual_run']);self.assertIsNone(proof['actual_source']);self.assertEqual(F.pins(F.tree(out)),v['after'])
 def test_default_output_byteheld(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'default';r=command([HERE/'prepare.py','--parent',OLD_PARENT,'--output',out]);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.tree(out),F.tree(OLD_EXPECTED,True));self.assertEqual(F.pins(F.tree(out)),F.profile()['after'])
 def test_parent_drift_missing_extra_and_wrong_profile_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/LEAF;raw=leaf.read_bytes()
   for mode in('drift','missing','extra'):
    if mode=='drift':leaf.write_bytes(raw+b'x')
    elif mode=='missing':leaf.unlink()
    else:leaf.write_bytes(raw);(parent/'foreign').write_bytes(b'x')
    out=root/mode
    with self.assertRaisesRegex(ValueError,'whole pinned immutable'):M.emit(parent,out)
    self.assertFalse(out.exists())
    if mode in('drift','missing'):leaf.write_bytes(raw)
   with self.assertRaisesRegex(ValueError,'whole pinned immutable'):M.emit(OLD_PARENT,root/'wrong')
 def test_payload_profile_and_basis_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory)
   with patch.object(M,'HERE',factory):
    for base,name,message in [('immutable-map-payload',LEAF,'whole nine readable'),('runtime-basis-special','immutable/inputs.py','whole three original')]:
     leaf=factory/base/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'x');out=root/base
     with self.assertRaisesRegex(ValueError,message):M.emit(PARENT,out)
     self.assertFalse(out.exists());leaf.write_bytes(raw)
    (factory/'immutable-map-profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'whole immutable-map profile'):M.emit(PARENT,root/'profile')
    self.assertFalse((root/'profile').exists())
 def test_symlink_hardlink_overlap_and_top_level_git(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for parent,out in[(alias,root/'out'),(PARENT,PARENT),(PARENT,PARENT/'new'),(PARENT,HERE/'new')]:
    with self.assertRaises(ValueError):M.emit(parent,out)
   parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));(parent/'.git').write_text('CHECKOUT_METADATA_ONLY');M.emit(parent,root/'git');self.assertEqual(F.pins(F.tree(root/'git')),M.profile()['after'])
   leaf=parent/LEAF;raw=leaf.read_bytes();holder=root/'holder';holder.write_bytes(raw)
   for kind in('symlink','hardlink'):
    leaf.unlink()
    if kind=='symlink':leaf.symlink_to(holder)
    else:os.link(holder,leaf)
    with self.assertRaisesRegex(ValueError,'ordinary single-link'):M.emit(parent,root/kind)
    self.assertFalse((root/kind).exists());leaf.unlink();leaf.write_bytes(raw)
 def test_entire667_runtime_adapter_and_whole_proof(self):
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'source';M.emit(PARENT,source);sys.path.insert(0,str(source/LANE))
   try:
    import deploy,runtime_adapter
    proof=json.loads((source/LANE/'runtime-derivation.json').read_bytes());basis=json.loads((source/LANE/'runtime-basis.json').read_bytes());self.assertEqual(len(basis),667);runtime=Path(td)/'basis';shutil.copytree(source/'runtime',runtime)
    for n,row in proof['changed'].items():
     leaf=runtime/n;self.assertEqual(F.pin(leaf.read_bytes()),row['after'])
     if isinstance(row['inverse'],str):raw=F.read(HERE/'runtime-basis-special'/n)
     else:
      text=leaf.read_text()
      for edit in reversed(row['inverse']):
       self.assertEqual(text.count(edit['new']),edit['count']);text=text.replace(edit['new'],edit['old'],edit['count'])
      raw=text.encode()
     self.assertEqual(F.pin(raw),row['before']);leaf.write_bytes(raw)
    self.assertEqual(F.pins(F.tree(runtime)),basis)
    with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR_API_GIT')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTOR_API_GIT')):actual=runtime_adapter.apply(runtime)
    self.assertEqual(F.tree(runtime),F.tree(source/'runtime'));self.assertEqual(deploy.encoded(actual),(source/LANE/'runtime-derivation.json').read_bytes());self.assertEqual(F.pins(F.tree(source)),M.profile()['after'])
   finally:sys.path.pop(0)
 def test_all69_actual_emitted_source_controls(self):
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'source';M.emit(PARENT,source);r=command([source/LANE/'test_deployment.py','--source',source]);sys.stderr.buffer.write(r.stdout+r.stderr);self.assertEqual(r.returncode,0);self.assertRegex(r.stderr,rb'Ran 69 tests in ');self.assertNotRegex(r.stderr,rb'\b(?:skipped|FAILED|ERROR|FAIL)\b');self.assertEqual(F.pins(F.tree(source)),M.profile()['after'])
if __name__=='__main__':unittest.main(verbosity=2)
