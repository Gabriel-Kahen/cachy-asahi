# SPDX-License-Identifier: MIT
"""Portable exact emission and mutation-boundary checks; no native acceptance."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_gnu_cleanup_factory',HERE/'prepare.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M);F=M.F
PARENT=Path(os.environ['GNU_CLEANUP_PARENT']).resolve();EXPECTED=Path(os.environ['GNU_CLEANUP_EXPECTED']).resolve()
LANE='scripts/ci/gnu-immutable-source-native';LEAF='runtime/immutable/worker_api.py'
def command(args):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,timeout=300)
class Controls(unittest.TestCase):
 def test_exact_cli_source_entry_and_all69_controls(self):
  v=M.profile();self.assertEqual(F.pins(F.tree(PARENT,True)),v['before']);self.assertEqual(F.pins(F.tree(EXPECTED,True)),v['after'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';p=command([HERE/'prepare.py','--parent',PARENT,'--output',out]);self.assertEqual((p.returncode,p.stderr),(0,b''));self.assertEqual(json.loads(p.stdout)['files'],746);self.assertEqual(F.tree(out),F.tree(EXPECTED,True))
   p=command([out/LANE/'entry.py','source','--source',out]);self.assertEqual((p.returncode,p.stderr),(0,b''));self.assertEqual(json.loads(p.stdout)['status'],'PASS_CLOSED_SOURCE_ONLY_NO_ACTORS')
   p=command([out/LANE/'test_deployment.py','--source',out]);self.assertEqual(p.returncode,0,p.stderr.decode());self.assertRegex(p.stderr,rb'Ran 69 tests in ');self.assertNotRegex(p.stderr,rb'\b(?:skipped|FAILED|ERROR|FAIL)\b');self.assertEqual(F.pins(F.tree(out)),v['after'])
 def test_parent_and_payload_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent);leaf=parent/LEAF;raw=leaf.read_bytes()
   for mode in('drift','missing','extra'):
    if mode=='drift':leaf.write_bytes(raw+b'x')
    elif mode=='missing':leaf.unlink()
    else:leaf.write_bytes(raw);(parent/'foreign').write_bytes(b'x')
    with self.assertRaisesRegex(ValueError,'pinned GNU745'):M.emit(parent,root/mode)
    self.assertFalse((root/mode).exists())
    if mode!='extra':leaf.write_bytes(raw)
   factory=root/'factory';shutil.copytree(HERE,factory);changed=factory/'payload'/LEAF;changed.write_bytes(changed.read_bytes()+b'x')
   with patch.object(M,'HERE',factory),self.assertRaisesRegex(ValueError,'nine readable'):M.emit(PARENT,root/'payload')
   self.assertFalse((root/'payload').exists());(factory/'profile.json').write_bytes(b'{}')
   with patch.object(M,'HERE',factory),self.assertRaisesRegex(ValueError,'fixed GNU cleanup profile'):M.emit(PARENT,root/'profile')
   self.assertFalse((root/'profile').exists())
 def test_alias_links_overlap_and_existing_output_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True);existing=root/'existing';existing.mkdir()
   for parent,out in[(alias,root/'a'),(PARENT,PARENT),(PARENT,PARENT/'new'),(PARENT,HERE/'new'),(PARENT,existing),(PARENT,root/'missing'/'..'/'dots')]:
    with self.assertRaises(ValueError):M.emit(parent,out)
   parent=root/'parent';shutil.copytree(PARENT,parent);leaf=parent/LEAF;raw=leaf.read_bytes();holder=root/'holder';holder.write_bytes(raw)
   for kind in('symlink','hardlink'):
    leaf.unlink()
    if kind=='symlink':leaf.symlink_to(holder)
    else:os.link(holder,leaf)
    with self.assertRaises(ValueError):M.emit(parent,root/kind)
    self.assertFalse((root/kind).exists());leaf.unlink();leaf.write_bytes(raw)
if __name__=='__main__':unittest.main(verbosity=2)
