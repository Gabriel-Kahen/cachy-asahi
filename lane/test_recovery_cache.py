# SPDX-License-Identifier: MIT
"""Real128-leaf seeding and unchanged offline fetch; Git transport simulated."""
import hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True;sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C,recovery_cache as R,prefetch as P
CARRIER=Path(os.environ['CORE64_RECOVERY_CARRIER']).absolute();TMP=Path(os.environ['CORE64_CONTROL_TMP']).absolute()

def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

class Cache(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temporary=tempfile.TemporaryDirectory(dir=TMP);cls.base=Path(cls.temporary.name);cls.carrier=cls.base/'core64-recovered-inputs';shutil.copytree(CARRIER,cls.carrier);cls.profile=R.profile()
  cls.tree=b''.join(b'100644 blob '+blob(C.read(cls.carrier/name)).encode()+b'\t'+name.encode()+b'\0'for name in sorted(cls.profile['files']))
 @classmethod
 def tearDownClass(cls):cls.temporary.cleanup()
 def git(self,carrier,*args,deadline):
  self.assertEqual(carrier,self.carrier)
  if args==('rev-parse','HEAD'):return(self.profile['source']+'\n').encode()
  if args==('ls-tree','-rz','--full-tree',self.profile['source']):return self.tree
  self.assertEqual(args[:2],('cat-file','blob'));source,name=args[2].split(':',1);self.assertEqual(source,self.profile['source']);return C.read(carrier/name)
 def fresh(self,path):
  core=path/'materialized-core';P.prepare_core(core);return core
 def test_real_all128_seed_and_original_fetch_without_network(self):
  with tempfile.TemporaryDirectory(dir=self.base)as directory:
   core=self.fresh(Path(directory))
   with patch.object(R,'git',side_effect=self.git),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_GIT_OR_ACTORS')):receipt=R.seed(core,time.monotonic()+30,self.carrier)
   self.assertEqual(len(receipt['carrier']['files']),133);self.assertEqual(len(receipt['inputs']),128);self.assertFalse(receipt['actual_authority']);self.assertEqual(len(C.files(core/'builder-context/deps')),129)
   sys.path.insert(0,str(core/'trusted-tools'));spec=importlib.util.spec_from_file_location('_held_acquire64_authenticate',core/'trusted-tools/authenticate.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
   with patch.object(A.native.urllib.request,'urlopen',side_effect=AssertionError('NO_NETWORK')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_PACKAGE_OR_GPG_ACTOR')):
    for row in C.load(core/'builder-inputs.lock.json')['packages']:
     A.fetch(row,core/'builder-context/deps');A.fetch(A.native.signature_item(row),core/'builder-context/deps')
   self.assertEqual(len(C.files(core/'builder-context/deps')),129)
 def test_missing_carrier_blob_refuses_before_any_cache_write(self):
  with tempfile.TemporaryDirectory(dir=self.base)as directory:
   core=self.fresh(Path(directory))
   def missing(carrier,*args,deadline):
    value=self.git(carrier,*args,deadline=deadline)
    return b''if args[:2]==('cat-file','blob')else value
   with patch.object(R,'git',side_effect=missing),self.assertRaises(ValueError):R.seed(core,time.monotonic()+30,self.carrier)
   self.assertEqual(set(q.name for q in(core/'builder-context/deps').iterdir()),{'SHA256SUMS'})
 def test_wrong_head_refuses_before_any_cache_write(self):
  with tempfile.TemporaryDirectory(dir=self.base)as directory:
   core=self.fresh(Path(directory))
   with patch.object(R,'git',return_value=b'0'*40+b'\n'),self.assertRaisesRegex(ValueError,'HEAD'):R.seed(core,time.monotonic()+30,self.carrier)
   self.assertEqual(len(C.files(core/'builder-context/deps')),1)
 def test_existing_cache_foreign_leaf_refuses(self):
  with tempfile.TemporaryDirectory(dir=self.base)as directory:
   core=self.fresh(Path(directory));(core/'builder-context/deps/foreign').write_bytes(b'foreign')
   with patch.object(R,'git',side_effect=self.git),self.assertRaisesRegex(ValueError,'checksum-only'):R.seed(core,time.monotonic()+30,self.carrier)
   self.assertEqual(len(C.files(core/'builder-context/deps')),2)
 def test_nonprivate_cache_and_symlink_carrier_refuse(self):
  with tempfile.TemporaryDirectory(dir=self.base)as directory:
   path=Path(directory);core=self.fresh(path);(core/'builder-context/deps').chmod(0o755)
   with patch.object(R,'git',side_effect=self.git),self.assertRaises(ValueError):R.seed(core,time.monotonic()+30,self.carrier)
   alias=path/'core64-recovered-inputs';alias.symlink_to(self.carrier,target_is_directory=True)
   with patch.object(R,'git',side_effect=AssertionError('REFUSE_BEFORE_GIT')),self.assertRaises(ValueError):R.prove(alias,time.monotonic()+30)
 def test_profile_tamper_refuses_before_git(self):
  with patch.object(R,'PROFILE_SHA','0'*64),patch.object(R,'git',side_effect=AssertionError('REFUSE_BEFORE_GIT')),self.assertRaises(ValueError):R.prove(self.carrier,time.monotonic()+30)
 def test_consumed_seed_code_drift_refuses_before_cache_write(self):
  with tempfile.TemporaryDirectory(dir=self.base)as directory:
   core=self.fresh(Path(directory));path=self.carrier/'seed.py';raw=path.read_bytes();original=R.prove
   def drift(carrier,deadline):
    result=original(carrier,deadline);path.write_bytes(raw+b'\nraise RuntimeError("UNAPPROVED_CODE_MUST_NOT_RUN")\n');return result
   try:
    with patch.object(R,'git',side_effect=self.git),patch.object(R,'prove',side_effect=drift),self.assertRaisesRegex(ValueError,'consumed public seeder'):R.seed(core,time.monotonic()+30,self.carrier)
    self.assertEqual(len(C.files(core/'builder-context/deps')),1)
   finally:path.write_bytes(raw)
 def test_wrong_original_lock_refuses_before_cache_write(self):
  with tempfile.TemporaryDirectory(dir=self.base)as directory:
   core=self.fresh(Path(directory));path=core/'builder-inputs.lock.json';path.write_bytes(path.read_bytes()+b' ')
   with patch.object(R,'git',side_effect=self.git),self.assertRaisesRegex(ValueError,'original signed64 lock'):R.seed(core,time.monotonic()+30,self.carrier)
   self.assertEqual(len(C.files(core/'builder-context/deps')),1)
 def test_real_stale_atime_read_keeps_stable_source_identity(self):
  # Use an updating-atime control filesystem, independent of repository mount flags.
  with tempfile.TemporaryDirectory(prefix='core64-atime-',dir='/dev/shm')as directory:
   path=Path(directory)/'data';path.write_bytes(b'bounded public DATA');info=path.stat();os.utime(path,ns=(1,info.st_mtime_ns));before=path.stat()
   self.assertEqual(C.read(path),b'bounded public DATA');after=path.stat()
   self.assertGreater(after.st_atime_ns,before.st_atime_ns,'control must exercise a real kernel atime update')
   identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
   self.assertEqual(identity(before),identity(after))
 def test_source_hook_order_and_original_authentication_body_held(self):
  raw=C.read(C.ROOT/'lane/prefetch.py').decode();self.assertLess(raw.index('prepare_core(core)'),raw.index('recovery_cache.seed('));self.assertLess(raw.index('recovery_cache.seed('),raw.index("str(C.ROOT/'lane/acquire64.py')"))
  self.assertIn('A.fetch(row,cache);A.fetch(A.native.signature_item(row),cache)',C.read(C.ROOT/'lane/acquire64.py').decode());self.assertIn('A.status(r)',C.read(C.ROOT/'lane/acquire64.py').decode());self.assertIn('A.observe(cache/row[\'filename\'],row)',C.read(C.ROOT/'lane/acquire64.py').decode())
if __name__=='__main__':unittest.main(verbosity=2)
