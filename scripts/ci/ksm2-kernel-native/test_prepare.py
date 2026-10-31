"""Private source-factory controls; all process creation forbidden."""
import json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import prepare as P
SOURCE=Path(os.environ.get('KSM2_FACTORY_SOURCE',HERE.parents[2])).absolute()
class Factory(unittest.TestCase):
 def setUp(self):
  for n in('Popen','run'):
   g=patch.object(subprocess,n,side_effect=AssertionError('NO_BUILD_GIT_API_ACTORS'));g.start();self.addCleanup(g.stop)
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.source=self.base/'source';self.source.mkdir()
  for n in P.EXPECTED-{P.ALIAS}:
   p=self.source/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(P.read(SOURCE/n))
  p=self.source/P.ALIAS;p.write_bytes(b'HELD_CANONICAL_MAIN_WORKFLOW_NOT_TRIAL_ALIAS\n')
  self.output=self.base/'emitted'
 def test_exact18_alias_default_null_and_source_main_unchanged(self):
  before=P.read(self.source/P.ALIAS);result=P.prepare(self.source,self.output)
  rows={p.relative_to(self.output).as_posix():P.pin(P.read(p))for p in self.output.rglob('*')if p.is_file()};pins=P.decode(P.read(HERE/'source-pins.json'))['files'];self.assertEqual(rows,pins);self.assertEqual(len(rows),18)
  self.assertEqual(P.read(self.source/P.ALIAS),before);self.assertEqual(P.read(self.output/P.ALIAS),P.read(self.output/P.WORKFLOW))
  receipt=P.decode(P.read(Path(result['authorization'])));self.assertTrue(all(receipt[k]is None for k in('source','ref','run_id','native_package_decision')));self.assertEqual(set(p.name for p in self.output.iterdir()),{'.github','scripts'})
 def test_shared_and_own_tamper_refuse_before_output_creation(self):
  for n in (P.HELD[0],P.LANE+'/lane.py',P.LANE+'/input-policy.json',P.WORKFLOW):
   p=self.source/n;before=p.read_bytes();p.write_bytes(before+b'\n')
   with self.assertRaisesRegex(ValueError,'source pin'):P.prepare(self.source,self.output)
   self.assertFalse(self.output.exists());p.write_bytes(before)
 def test_missing_input_and_symlink_and_hardlink_refuse(self):
  p=self.source/P.HELD[0];raw=p.read_bytes();p.unlink()
  with self.assertRaises(FileNotFoundError):P.prepare(self.source,self.output)
  target=self.base/'real';target.write_bytes(raw);p.symlink_to(target)
  with self.assertRaisesRegex(ValueError,'aliases'):P.prepare(self.source,self.output)
  p.unlink();os.link(target,p)
  with self.assertRaisesRegex(ValueError,'singlelink'):P.prepare(self.source,self.output)
  self.assertFalse(self.output.exists())
 def test_existing_output_or_authorization_not_overwritten(self):
  self.output.mkdir();(self.output/'keep').write_bytes(b'held')
  with self.assertRaises(ValueError):P.prepare(self.source,self.output)
  self.assertEqual((self.output/'keep').read_bytes(),b'held');shutil.rmtree(self.output)
  auth=self.output.with_name(self.output.name+'-authorization.json');auth.write_bytes(b'held')
  with self.assertRaises(ValueError):P.prepare(self.source,self.output)
  self.assertEqual(auth.read_bytes(),b'held');self.assertFalse(self.output.exists())
 def test_only_declared_inputs_exported_no_git_or_factory_metadata(self):
  (self.source/'.git').mkdir();(self.source/'.git/config').write_bytes(b'INERT')
  (self.source/'unrelated').write_bytes(b'NOT_EXPORTED')
  P.prepare(self.source,self.output)
  self.assertFalse((self.output/'.git').exists());self.assertFalse((self.output/'unrelated').exists());self.assertFalse((self.output/P.LANE/'prepare.py').exists())
 def test_ambiguous_metadata_and_source_alias_refuse(self):
  for raw in(b'{"a":1,"a":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):P.decode(raw)
  alias=self.base/'alias';alias.symlink_to(self.source,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'ordinary'):P.prepare(alias,self.output)
if __name__=='__main__':unittest.main(verbosity=2)
