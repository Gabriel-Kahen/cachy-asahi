"""Finite portable Apps13 source generation controls, no original evidence/actors."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import apps13 as A
F=A.F;BASE=Path(os.environ['APPS13_REPAIR_BASE_SOURCE']).absolute();EXPECTED=Path(os.environ['APPS13_REPAIR_EXPECTED_SOURCE']).absolute();CARRIER=Path(os.environ['APPS13_REPAIR_CARRIER']).absolute();FULL=False
LEAF='scripts/ci/apps7-full574-repair16k/adapter.py'
def command(args,seconds=60):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,timeout=seconds)
class Factory(unittest.TestCase):
 def test_complete_bound_and_NULL235_and_source_gates(self):
  p,_=A.inputs();self.assertEqual((F.files(BASE),F.files(EXPECTED),F.files(CARRIER)),(p['before'],p['after'],p['carrier_files']));self.assertEqual(len(p['held']),197)
  with tempfile.TemporaryDirectory()as td:
   for selected in(False,True):
    root=Path(td)/str(selected)
    with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):v=A.prepare(BASE,root,A.NAME,CARRIER if selected else None)
    self.assertEqual(F.files(root),p['after']if selected else p['null']);self.assertEqual(v['selected'],selected);self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertIsNone(v['repair_acceptance']);self.assertTrue(all(x is None for x in v['run_ids'].values()));self.assertEqual(v['clocks'],'UNCHANGED')
    r=command([root/'apps13-repair/entry.py','--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIsNone(json.loads(r.stdout)['authority'])
    if not selected:
     r=command([root/'apps13-repair/entry.py','--require-selection']);self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL',r.stderr)
    self.assertEqual(F.files(root),p['after']if selected else p['null'])
 def test_isolated_exact_cli_authorization_help_and_actualsNULL(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';auth=Path(td)/'authorization.json';r=command([HERE/'apps13.py','--profile',A.NAME,'--base-root',BASE,'--carrier',CARRIER,'--output',out,'--authorization',auth]);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(F.files(out),F.files(EXPECTED));v=json.loads(auth.read_bytes());self.assertEqual(v['expected_fixture_source'],'1ed3510ac2f4ae653c471fc1ea4ba710a0b198d6');self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertEqual(v['files'],A.inputs()[0]['after'])
   r=command([HERE/'apps13.py','--help']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIn(b'--carrier',r.stdout)
 def test_missing_foreign_profile_and_auth_inside_input_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source'
   with patch.object(A,'inputs',side_effect=AssertionError('NO_INPUT_READ')):
    for v in(None,'apps12-repair235','apps13','postcopy-cli210'):
     with self.assertRaisesRegex(ValueError,'explicit --profile'):A.prepare(Path('/not-read'),out,v)
   self.assertFalse(out.exists());r=command([HERE/'apps13.py','--profile',A.NAME,'--base-root',BASE,'--output',out,'--authorization',BASE/'never-written-authorization.json']);self.assertNotEqual(r.returncode,0);self.assertIn(b'authorization outside',r.stderr);self.assertFalse(out.exists());self.assertFalse((BASE/'never-written-authorization.json').exists())
 def test_parent_missing_extra_bytes_and_late_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);base=root/'base';shutil.copytree(BASE,base,ignore=shutil.ignore_patterns('.git'));leaf=base/LEAF;raw=leaf.read_bytes()
   for mode in('bytes','extra','missing'):
    if mode=='bytes':leaf.write_bytes(raw+b'x')
    elif mode=='extra':(base/'foreign').write_bytes(b'x')
    else:leaf.unlink()
    with self.assertRaises(ValueError):A.prepare(base,root/mode,A.NAME)
    self.assertFalse((root/mode).exists())
    if mode=='extra':(base/'foreign').unlink()
    else:leaf.write_bytes(raw)
   original=F.files;calls=[]
   def changed(path):
    if path==base:
     calls.append(True)
     if len(calls)==2:leaf.write_bytes(raw+b'late')
    return original(path)
   with patch.object(F,'files',side_effect=changed),self.assertRaisesRegex(ValueError,'fresh parent'):A.prepare(base,root/'late',A.NAME)
   self.assertFalse((root/'late').exists())
 def test_payload_profile_carrier_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);leaf=factory/'apps13-payload/apps13-repair/selection.py';raw=leaf.read_bytes()
   with patch.object(A,'HERE',factory):
    leaf.write_bytes(raw+b'x')
    with self.assertRaisesRegex(ValueError,'38 used readable'):A.prepare(BASE,root/'payload',A.NAME)
    self.assertFalse((root/'payload').exists());leaf.write_bytes(raw);(factory/'apps13-profile.json').write_bytes(b'{}')
    with self.assertRaisesRegex(ValueError,'fixed Apps13'):A.prepare(BASE,root/'profile',A.NAME)
    self.assertFalse((root/'profile').exists())
   carrier=root/'carrier';shutil.copytree(CARRIER,carrier,ignore=shutil.ignore_patterns('.git'));(carrier/'foreign').write_bytes(b'x')
   with self.assertRaisesRegex(ValueError,'accepted Apps13 carrier94'):A.prepare(BASE,root/'carrier-out',A.NAME,carrier)
   self.assertFalse((root/'carrier-out').exists())
 def test_source_output_and_descriptor_aliases_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(BASE,target_is_directory=True)
   for base,out in[(alias,root/'alias-out'),(BASE,BASE),(BASE,BASE/'new'),(BASE,HERE/'new')]:
    with self.assertRaises(ValueError):A.prepare(base,out,A.NAME)
   base=root/'base';shutil.copytree(BASE,base,ignore=shutil.ignore_patterns('.git'));leaf=base/LEAF;raw=leaf.read_bytes();holder=root/'holder';holder.write_bytes(raw)
   for mode in('symlink','hardlink'):
    leaf.unlink()
    if mode=='symlink':leaf.symlink_to(holder)
    else:os.link(holder,leaf)
    with self.assertRaises(ValueError):A.prepare(base,root/mode,A.NAME)
    self.assertFalse((root/mode).exists());leaf.unlink();leaf.write_bytes(raw)
 def test_actual_emitted_observer_or_full_source_controls(self):
  # Local qualification exercises the actual backend/App13 loader. CI also runs
  # the complete previously-qualified ten source controls in each view.
  with tempfile.TemporaryDirectory()as td:
   for selected in(False,True):
    root=Path(td)/str(selected);A.prepare(BASE,root,A.NAME,CARRIER if selected else None);args=[root/'apps13-repair/test_source.py']+([]if FULL else['ObserverControls']);r=command(args,120);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));count=10 if FULL else 3;self.assertRegex(r.stderr,('Ran %d tests in '%count).encode());self.assertNotRegex(r.stderr,rb'\b(?:FAILED|ERROR|skipped)\b');print('emitted',('full10'if FULL else'observer3'),('bound'if selected else'NULL'),'PASS',file=sys.stderr)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--full-emitted-tests',action='store_true');a,rest=p.parse_known_args();FULL=a.full_emitted_tests;unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
