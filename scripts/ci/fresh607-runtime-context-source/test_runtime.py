# SPDX-License-Identifier: MIT
"""Real legacy import/digest and owned readonly-cache removal; no guest authority."""
import importlib.util,json,os,shutil,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent
SOURCE=Path(os.environ['FRESH_RUNTIME_SOURCE']).resolve();LEGACY=Path(os.environ['FRESH_RUNTIME_LEGACY']).resolve()
sys.path.insert(0,str(SOURCE/'implementation'))
import common as C,runtime_context as R
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
CONTRACT=load('_actual_original604_contract',SOURCE/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/contract.py')
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='runtime-owned-cache-',dir='/tmp');self.producer=Path(self.temp.name);self.base=self.producer/'private/latest607-base604';self.base.mkdir(parents=True,mode=0o700);(self.producer/'private').chmod(0o700)
 def tearDown(self):
  for p in self.producer.rglob('*'):
   if p.is_dir()and not p.is_symlink():p.chmod(0o700)
  self.temp.cleanup()
 def fixture(self):
  (self.base/'packages').mkdir();(self.base/'keys').mkdir();rows=[]
  for i in range(604):
   a='packages/p%03d.pkg'%i;s=a+'.sig';b=('PRIVATE_FIXTURE_%03d'%i).encode()
   for n in(a,s):(self.base/n).write_bytes(b);(self.base/n).chmod(0o444)
   w=C.pin(b);rows.append(dict(archive=a,signature=s,size=w['bytes'],sha256=w['sha256'],signature_size=w['bytes'],signature_sha256=w['sha256']))
  key=b'PRIVATE_FIXTURE_KEY';(self.base/'keys/public.key').write_bytes(key);(self.base/'keys/public.key').chmod(0o444);w=C.pin(key)
  manifest=dict(status='READY_SIGNED_EXPANDED604',packages=rows,keyrings=[dict(path='keys/public.key',size=w['bytes'],sha256=w['sha256'])])
  for n,b in(('manifest.json',C.enc(manifest)),('expected-installed.lock',b'PRIVATE604'),('builder-packages.lock',b'PRIVATE_BUILDER')):(self.base/n).write_bytes(b);(self.base/n).chmod(0o444)
  for n in('packages','keys'):(self.base/n).chmod(0o555)
  (self.producer/'producer-owner.json').write_bytes(C.enc(dict(schema_version=1,token='a'*32)))
 def test_actual_legacy_import_collision_and_source_relative_digest(self):
  legacy=LEGACY;old=sys.modules['common'];self.assertIs(old,C)
  with self.assertRaisesRegex(ImportError,"cannot import name 'digest'"):CONTRACT.scoped_load('_wrong_common_audit',legacy/'scripts/virtual/audit_tooling.py')
  with patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')),patch('urllib.request.urlopen',side_effect=AssertionError('network forbidden')):
   tool=R.tooling(CONTRACT,legacy);p=self.producer/'digest-input';p.write_bytes(b'actual legacy digest');self.assertEqual(tool.digest(p),C.pin(p.read_bytes())['sha256'])
  self.assertIs(sys.modules['common'],old);self.assertFalse(hasattr(C,'digest'))
 def test_real_sealed_cache_retirement_and_sibling_preservation(self):
  self.fixture();sibling=self.producer/'private/ready';sibling.mkdir();(sibling/'sentinel').write_bytes(b'held');lease=R.BaseCache(self.producer,self.base)
  verifier=self.producer/'private/latest607-verifier';verifier.mkdir();verifier.rmdir();lease.retire();self.assertFalse(self.base.exists());self.assertEqual((sibling/'sentinel').read_bytes(),b'held')
 def test_namespace_metadata_owner_and_live_verifier_refusals(self):
  self.fixture();lease=R.BaseCache(self.producer,self.base)
  verifier=self.producer/'private/expanded604-verifier';verifier.mkdir()
  with self.assertRaisesRegex(ValueError,'verifier homes'):lease.retire()
  verifier.rmdir();owner=self.producer/'producer-owner.json';raw=owner.read_bytes();owner.write_bytes(raw.replace(b'a'*32,b'b'*32))
  with self.assertRaisesRegex(ValueError,'token/receipt'):lease.retire()
  owner.write_bytes(raw);extra=self.base/'extra';extra.write_bytes(b'extra')
  with self.assertRaises(ValueError):lease.retire()
  extra.unlink();lease=R.BaseCache(self.producer,self.base);member=self.base/'packages/p000.pkg';member.chmod(0o644)
  with self.assertRaisesRegex(ValueError,'member unchanged'):lease.retire()
  self.assertTrue(self.base.exists());self.assertEqual((self.base/'packages').stat().st_mode&0o777,0o555)
 def test_actual_integration_retirement_on_error_and_original_failure(self):
  import run
  contract=types.SimpleNamespace(scoped_load=lambda *a:object());api=run.Integration(self.producer,self.producer,self.producer,contract);args=['eight','seven','audio','legacy',self.producer/'target','policy','management','setup','welcome','source','apps','authority']
  original=types.SimpleNamespace(prepare=lambda *a:None)
  with patch.object(run,'load',return_value=object()),patch.object(run.runtime_context,'BaseCache')as lease,patch.object(run.materialize,'prepare',side_effect=RuntimeError('current materializer refused')):
   with self.assertRaisesRegex(RuntimeError,'current materializer'):api.bind(original,self.producer).prepare('ready',self.producer,*args)
   lease.return_value.retire.assert_called_once_with()
  def fail(*a):raise RuntimeError('original604 refused')
  with patch.object(run.runtime_context,'BaseCache')as lease,self.assertRaisesRegex(RuntimeError,'original604'):api.bind(types.SimpleNamespace(prepare=fail),self.producer).prepare('ready',self.producer,*args)
  lease.assert_not_called()
 def test_closed_constructor_refuses_links_extra_and_unsealed(self):
  self.fixture();extra=self.base/'foreign';extra.symlink_to('/etc/passwd')
  with self.assertRaises(ValueError):R.BaseCache(self.producer,self.base)
  extra.unlink();lease=R.BaseCache(self.producer,self.base);member=self.base/'packages/p000.pkg';member.chmod(0o644)
  with self.assertRaisesRegex(ValueError,'sealed cache member'):R.BaseCache(self.producer,self.base)
  member.chmod(0o444);outside=self.producer/'hardlink';os.link(member,outside)
  with self.assertRaisesRegex(ValueError,'sealed cache member'):R.BaseCache(self.producer,self.base)
if __name__=='__main__':unittest.main(verbosity=2)
