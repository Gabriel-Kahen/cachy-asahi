"""Exact new842 source, old routes and physical output refusals; no native actors."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_codec842_factory',HERE/'installed_codec842.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C);F=C.F
PARENT=Path(os.environ['INSTALLED_CODEC_PARENT']).absolute();EXPECTED=Path(os.environ['INSTALLED_CODEC_EXPECTED']).absolute();PACKET=Path(os.environ['LATEST607_APPS8_TEST_PACKET']).absolute();SETUP='latest/implementation/latest_setup.py'
def command(args,seconds=180):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,timeout=seconds)
class Controls(unittest.TestCase):
 def test_exact842_whole_parent_proof_and_NULL_authority(self):
  p,_=C.inputs();self.assertEqual(F.files(EXPECTED),p['after']);self.assertEqual(F.files(PARENT),p['before'])
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR_API_GIT')):
   out=Path(td)/'source';v=C.emit(PARENT,out);self.assertEqual(F.files(out),p['after']);self.assertEqual(v['expected_fixture_source'],'8b22845252d01e1a813ed078be60315a39a27a5f');self.assertTrue(all(v[k]is None for k in('source','ref','actual')));proof=json.loads((out/'latest/implementation/installed-codec-successor.json').read_bytes());self.assertTrue(all(proof[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertEqual(len(proof['before']),840)
 def test_isolated_real_CLI_and_authorization(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);out=root/'source';auth=root/'auth.json';r=command([HERE/'prepare.py','--profile',C.NAME,'--source',PARENT,'--output',out,'--authorization',auth]);self.assertEqual((r.returncode,r.stderr,r.stdout),(0,b'',b''));v=json.loads(auth.read_bytes());self.assertEqual(v['files'],F.files(EXPECTED));self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertIsNone(v['actual']);self.assertEqual(F.files(out),F.files(EXPECTED))
 def test_implicit_foreign_profile_and_authorization_inside_source_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for mode in(None,'codec','sixcap842'):
    args=[HERE/'prepare.py','--source',PARENT,'--output',root/'out','--authorization',root/'auth']+([]if mode is None else['--profile',mode]);r=command(args);self.assertNotEqual(r.returncode,0);self.assertFalse((root/'out').exists());self.assertFalse((root/'auth').exists())
   before=F.files(PARENT)
   for out,auth in[(root/'out',PARENT/'never-written-auth.json'),(root/'out',root/'out/auth.json')]:
    r=command([HERE/'prepare.py','--profile',C.NAME,'--source',PARENT,'--output',out,'--authorization',auth]);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists());self.assertFalse(auth.exists());self.assertEqual(F.files(PARENT),before)
 def test_missing_extra_bytes_and_late_source_drift_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/SETUP;raw=leaf.read_bytes()
   for mode in('bytes','missing','extra','directory'):
    if mode=='bytes':leaf.write_bytes(raw+b'x')
    elif mode=='missing':leaf.unlink()
    elif mode=='extra':(parent/'foreign').write_bytes(b'x')
    else:(parent/'foreign-empty').mkdir()
    with self.assertRaises(ValueError):C.emit(parent,root/mode)
    self.assertFalse((root/mode).exists())
    if mode in('bytes','missing'):leaf.write_bytes(raw)
    elif mode=='extra':(parent/'foreign').unlink()
    else:(parent/'foreign-empty').rmdir()
   old=C.closed;calls=[]
   def late(path,wanted):
    if path==parent:
     calls.append(True)
     if len(calls)==2:leaf.write_bytes(raw+b'late')
    return old(path,wanted)
   with patch.object(C,'closed',side_effect=late),self.assertRaises(ValueError):C.emit(parent,root/'late')
   self.assertFalse((root/'late').exists())
 def test_profile_payload_and_support_membership_drift_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);leaf=factory/'installed-codec842'/SETUP;raw=leaf.read_bytes()
   with patch.object(C,'HERE',factory):
    leaf.write_bytes(raw+b'x')
    with self.assertRaises(ValueError):C.emit(PARENT,root/'payload')
    self.assertFalse((root/'payload').exists());leaf.write_bytes(raw);(factory/'installed-codec842/extra-directory').mkdir()
    with self.assertRaises(ValueError):C.emit(PARENT,root/'extra')
    self.assertFalse((root/'extra').exists());(factory/'installed-codec842/extra-directory').rmdir();(factory/'installed-codec842-profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'hardpinned installed codec profile'):C.emit(PARENT,root/'profile')
    self.assertFalse((root/'profile').exists())
 def test_normalized_source_output_alias_hardlink_and_overlap(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'hop').mkdir();alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   for source,out in[(alias,root/'out'),(PARENT,PARENT/'new'),(PARENT,HERE/'new'),(PARENT,root/'hop'/'..'/'out')]:
    with self.assertRaises(ValueError):C.emit(source,out)
   parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));before=F.files(parent)
   with self.assertRaises(ValueError):C.emit(root/'hop'/'..'/'parent',root/'source-dotdot')
   self.assertEqual(F.files(parent),before);leaf=parent/SETUP;holder=root/'holder';holder.write_bytes(leaf.read_bytes());leaf.unlink();os.link(holder,leaf)
   with self.assertRaises(ValueError):C.emit(parent,root/'hardlink')
   self.assertFalse((root/'hardlink').exists());leaf.unlink()
 def test_actual_emitted_whole40_and12_source_controls(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';C.emit(PARENT,out);r=command([out/'next/test_source.py']);self.assertEqual(r.returncode,0,r.stderr[-8192:].decode(errors='replace'));self.assertRegex(r.stderr,rb'Ran 40 tests in ');self.assertRegex(r.stderr,rb'Ran 12 tests in ');self.assertNotRegex(r.stderr,rb'\b(?:FAILED|ERROR|skipped)\b');self.assertEqual(F.files(out),F.files(EXPECTED));print('whole40 inherited+12six-tool source controls PASS',file=sys.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
