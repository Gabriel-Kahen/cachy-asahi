# SPDX-License-Identifier: MIT
"""Real complete574 cache hook; Git transport simulated, no native credit."""
import hashlib,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C,native248_cache as N
CARRIER=Path(os.environ['CORE574_RECOVERY_CARRIER']).absolute();TMP=Path(os.environ['CORE574_CONTROL_TMP']).absolute()
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(dir=TMP);cls.base=Path(cls.temp.name);cls.carrier=cls.base/'core-native248-recovered-inputs';shutil.copytree(CARRIER,cls.carrier);cls.root=cls.base/'core-source';shutil.copytree(C.ROOT,cls.root)
  with patch.object(C,'ROOT',cls.root):cls.p=N.profile()
  cls.tree=b''.join(b'100644 blob '+hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest().encode()+b'\t'+n.encode()+b'\0'for n in sorted(cls.p['files'])for raw in[C.read(cls.carrier/n)])
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def git(self,carrier,*args,deadline):
  self.assertEqual(carrier,self.carrier)
  if args==('rev-parse','HEAD'):return(self.p['source']+'\n').encode()
  if args==('ls-tree','-rz','--full-tree',self.p['source']):return self.tree
  self.assertEqual(args[:2],('cat-file','blob'));source,n=args[2].split(':',1);self.assertEqual(source,self.p['source']);return C.read(carrier/n)
 def fresh(self,root):
  out=root/'out';out.mkdir(mode=0o700);(out/'context').mkdir(mode=0o700);cache=out/'context/deps';cache.mkdir(mode=0o700)
  for n,want in self.p['before_inputs'].items():shutil.copyfile(self.carrier/'packages'/n,cache/n)
  return out,cache
 def test_real80_to1148_and_original500plus_fetch_no_network(self):
  with tempfile.TemporaryDirectory(dir=self.base)as td:
   out,cache=self.fresh(Path(td))
   with patch.dict(os.environ,{'GITHUB_WORKSPACE':str(self.base)}),patch.object(C,'ROOT',self.root),patch.object(N,'git',side_effect=self.git),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_GIT_OR_ACTORS')):v=N.seed(out,time.monotonic()+890)
   self.assertEqual(len(v['inputs']),1148);self.assertEqual(v['cache']['cache']['added'],1068);self.assertEqual(v['cache']['cache']['before_identity'],v['cache']['cache']['after_previous_identity']);self.assertEqual(C.files(cache),self.p['inputs']);self.assertFalse(v['actual_authority'])
 def test_wrong_head_and_foreign_before_refuse(self):
  with tempfile.TemporaryDirectory(dir=self.base)as td:
   out,cache=self.fresh(Path(td))
   with patch.dict(os.environ,{'GITHUB_WORKSPACE':str(self.base)}),patch.object(C,'ROOT',self.root),patch.object(N,'git',return_value=b'0'*40+b'\n'),self.assertRaisesRegex(ValueError,'HEAD'):N.seed(out,time.monotonic()+890)
   self.assertEqual(len(C.files(cache)),80);(cache/'foreign').write_bytes(b'foreign')
   with patch.dict(os.environ,{'GITHUB_WORKSPACE':str(self.base)}),patch.object(C,'ROOT',self.root),patch.object(N,'git',side_effect=self.git),self.assertRaisesRegex(ValueError,'original80'):N.seed(out,time.monotonic()+890)
   self.assertEqual(len(C.files(cache)),81)
 def test_profile_full_original574_and_hook_after_fresh_public14(self):
  self.assertEqual(len(self.p['files']),1154);self.assertEqual(len(self.p['inputs']),1148);self.assertEqual(len(self.p['before_inputs']),80)
  text=C.read(C.ROOT/'lane/prefetch.py').decode();self.assertLess(text.index('baseline_inputs=m.prepare(out,deadline)'),text.index('native248_cache.seed(out,deadline)'));self.assertIn("deadline=started+890",text);self.assertIn("C.BUDGET['new64']",text)
 def test_real_original32_20_8_prefetch_and_seed_with_network_denied(self):
  import archive_prefill,importlib.util
  with tempfile.TemporaryDirectory(dir=self.base)as td:
   out=Path(td);deps=out/'deps';deps.mkdir(mode=0o700);reports=[]
   for n in('32','20','8'):
    path=self.root/'baseline'/('archive'+n+'.py');spec=importlib.util.spec_from_file_location('original_legacy'+n,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    v=m.policy(self.root/'baseline'/('archive'+n+'-policy.json'),self.root/'baseline/maintained-desktop574-inputs.json');cache=out/('archive'+n)
    receipt=archive_prefill.prefill(self.carrier,cache,v,time.monotonic()+890)
    before={p.name:archive_prefill.exact(p,{k:v['files'][p.name][k]for k in('bytes','sha256')},time.monotonic()+30)for p in cache.iterdir()}
    index=m.prefetch(cache,v,open_url=lambda *a,**k:(_ for _ in()).throw(AssertionError('NO_NETWORK')));m.seed_exact(cache,deps,v)
    self.assertEqual(index['requests'],0);self.assertEqual(index['reused'],int(n));self.assertEqual(receipt['index'],'NOT_CREATED_ORIGINAL_CLI_REQUIRED')
    for name,identity in before.items():self.assertEqual(archive_prefill.exact(cache/name,receipt['files'][name],time.monotonic()+30),identity)
    reports.append(dict(kind=n,requests=index['requests'],reused=index['reused']))
   self.assertEqual(len(C.files(deps)),60);self.assertEqual([r['reused']for r in reports],[32,20,8])
if __name__=='__main__':unittest.main(verbosity=2)
