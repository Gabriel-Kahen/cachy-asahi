# SPDX-License-Identifier: MIT
"""Real public35 copies, original cached-fetch, owned FD/refusal and source controls."""
import ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,time,types,unittest,urllib.request
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;S=Path(os.environ['FRESH_TOOLING_SOURCE']).resolve();P=Path(os.environ['FRESH_TOOLING_PARENT']).resolve();K=Path(os.environ['FRESH_TOOLING_CARRIER']).resolve();L=Path(os.environ['FRESH_TOOLING_LEGACY']).resolve();sys.path.insert(0,str(S/'implementation'))
import common as C,tooling_inputs as T,tooling_source as G,runtime_context
from loaders import load
contract=load('_known_original_installer_contract',S/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/contract.py');auditor=runtime_context.tooling(contract,L)

def owner(root):return dict(schema_version=1,purpose='latest607-fresh-installer',token='a'*32,output=str(root),producer=str(root.with_name(root.name+'-producer')),vm=str(root.with_name(root.name+'-vm')),legacy_source='b6b17e5f6b322f160f7eeb22c8a01380a3c854cd')
class Controls(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory(prefix='private-tooling-controls-');self.work=Path(self.tmp.name);self.p=T.configuration()
 def tearDown(self):self.tmp.cleanup()
 def cache(self,label='owner'):
  root=self.work/label;root.mkdir(mode=0o700);cache=root/'tooling-cache';cache.mkdir(mode=0o700);o=owner(root);(root/'owner.json').write_bytes(C.enc(o));return cache,o
 def seed(self,cache,o,downloads=None,carrier=K):return T.seed(carrier,L,self.p['downloads']if downloads is None else downloads,cache,o)
 def test_real_all35_copy_and_original_fetch_with_http_forbidden(self):
  cache,o=self.cache();before=T.snapshot(K,time.monotonic()+240);proof=self.seed(cache,o);self.assertEqual((proof['files'],proof['bytes']),(35,13203918));self.assertNotIn('PASS',proof['status']);self.assertEqual(len(list(cache.iterdir())),35)
  with patch.object(urllib.request,'urlopen',side_effect=AssertionError('HTTP_FORBIDDEN_ALL35_CACHED'))as network:
   for row in self.p['downloads']:
    p=auditor.fetch(row,cache,True);self.assertEqual(C.pin(p.read_bytes()),dict(bytes=row['size'],sha256=row['sha256']))
   network.assert_not_called()
  self.assertEqual(T.snapshot(K,time.monotonic()+240),before);self.assertEqual(C.read(cache.parent/'owner.json'),C.enc(o))
 def test_whole89_lock_policy_signature_license_original_selector_joins(self):
  values,_,selected=T.selection(self.p,K,L,time.monotonic()+240);self.assertEqual(len(values),89);self.assertEqual(len(selected),35);self.assertEqual(sum(map(len,selected.values())),13203918);policy=json.loads(values['tooling32-policy.json']);self.assertEqual(len(policy['rows']),16);self.assertEqual(len(policy['files']),32);self.assertIn('package-licenses.json',values);self.assertEqual(values['tooling.lock.json'],C.read(L/'scripts/virtual/tooling.lock.json'));self.assertEqual(T.preflight(K,L)['authority'],'DATA_ONLY_ORIGINAL_GPG_AND_VM_CHECKS_MANDATORY')
 def test_wrong_missing_duplicate_float_url_and_foreign_download_rows_refuse(self):
  mutations=[lambda x:x.pop(),lambda x:x.append(copy.deepcopy(x[0])),lambda x:x[0].__setitem__('size',float(x[0]['size'])),lambda x:x[0].__setitem__('sha256','0'*64),lambda x:x[0].__setitem__('url','https://foreign.invalid/input'),lambda x:x[0].__setitem__('filename','../foreign')]
  for i,change in enumerate(mutations):
   cache,o=self.cache('malformed'+str(i));rows=copy.deepcopy(self.p['downloads']);change(rows)
   with self.subTest(mutation=i),self.assertRaises(ValueError):self.seed(cache,o,rows)
   self.assertFalse(list(cache.iterdir()))
 def test_exact_empty_owned0700_cache_owner_and_no_overwrite(self):
  for kind in('preexisting','wrong-mode','wrong-parent-mode','owner-token','owner-path','owner-file','foreign-cache'):
   cache,o=self.cache(kind);original=C.read(cache.parent/'owner.json')
   if kind=='preexisting':(cache/self.p['downloads'][0]['filename']).write_bytes(b'foreign')
   if kind=='wrong-mode':cache.chmod(0o755)
   if kind=='wrong-parent-mode':cache.parent.chmod(0o755)
   if kind=='owner-token':o=dict(o,token='foreign')
   if kind=='owner-path':o=dict(o,output=str(self.work/'other'))
   if kind=='owner-file':(cache.parent/'owner.json').write_bytes(C.enc(dict(o,token='b'*32)))
   if kind=='foreign-cache':cache.rename(cache.with_name('foreign-cache'));cache=cache.with_name('foreign-cache')
   before={p.name:p.read_bytes()for p in cache.iterdir()}
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.seed(cache,o)
   self.assertEqual({p.name:p.read_bytes()for p in cache.iterdir()},before)
 def test_public_member_missing_symlink_hardlink_mutation_and_foreign_namespace(self):
  for kind in('missing','symlink','hardlink','mutation','foreign','empty'):
   root=self.work/kind;shutil.copytree(K,root);member=root/'packages'/self.p['rows'][0]['filename'];before=member.read_bytes()
   if kind=='missing':member.unlink()
   if kind=='symlink':member.unlink();member.symlink_to(K/'packages'/self.p['rows'][0]['filename'])
   if kind=='hardlink':os.link(member,self.work/('alias-'+kind))
   if kind=='mutation':member.write_bytes(before+b'bad')
   if kind=='foreign':(root/'foreign').write_bytes(b'bad')
   if kind=='empty':(root/'empty').mkdir()
   cache,o=self.cache('cache-'+kind)
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.seed(cache,o,carrier=root)
   self.assertFalse(list(cache.iterdir()))
 def test_partial_write_progress_fd_retirement_and_deadline(self):
  cache,o=self.cache('partial');fds=len(os.listdir('/proc/self/fd'));write=os.write
  def short(fd,data):return write(fd,data[:max(1,min(32768,len(data)))])
  with patch.object(T.os,'write',side_effect=short):self.seed(cache,o)
  self.assertEqual(len(os.listdir('/proc/self/fd')),fds)
  zero,o=self.cache('zero')
  with patch.object(T.os,'write',return_value=0),self.assertRaisesRegex(ValueError,'copy progress'):self.seed(zero,o)
  self.assertEqual(len(os.listdir('/proc/self/fd')),fds)
  expired,o=self.cache('expired')
  with patch.object(T.time,'monotonic',side_effect=[0,241]),self.assertRaisesRegex(ValueError,'preparation deadline'):self.seed(expired,o)
  self.assertFalse(list(expired.iterdir()));self.assertEqual(len(os.listdir('/proc/self/fd')),fds)
 def test_during_copy_source_inode_and_original_cache_fd_identity_drift_refuse(self):
  root=self.work/'mutable-carrier';shutil.copytree(K,root);cache,o=self.cache('late-carrier');write=os.write;changed=False
  def replace(fd,data):
   nonlocal changed
   if not changed:
    p=root/'packages'/self.p['rows'][0]['filename'];q=p.with_name('replacement');q.write_bytes(p.read_bytes());os.replace(q,p);changed=True
   return write(fd,data)
  with patch.object(T.os,'write',side_effect=replace),self.assertRaisesRegex(ValueError,'input/owner identities'):self.seed(cache,o,carrier=root)
  cache,o=self.cache('late-cache');changed=False
  def rename(fd,data):
   nonlocal changed
   if not changed:cache.rename(cache.with_name('moved-cache'));cache.mkdir(mode=0o700);changed=True
   return write(fd,data)
  with patch.object(T.os,'write',side_effect=rename),self.assertRaisesRegex(ValueError,'cache FD/path'):self.seed(cache,o)
 def test_entire1192_inverse_current_aliases_clocks_and_original_fetch_body(self):
  p,old,actual=G.inverse();self.assertEqual(len(old),1192);self.assertEqual(len(actual),1197)
  for n,w in p['before'].items():self.assertEqual(C.pin(C.read(P/n)),w)
  self.assertEqual(C.read(S/'implementation/runtime_context.py'),C.read(P/'implementation/runtime_context.py'));self.assertEqual(C.read(S/'parent604/prepare.py'),C.read(P/'parent604/prepare.py'));self.assertEqual(C.read(S/'implementation/profile.json'),C.read(P/'implementation/profile.json'));self.assertEqual(C.read(S/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py'),C.read(P/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py'))
  raw=C.read(P/'implementation/run.py');current=G.run_body(raw);self.assertEqual(current,C.read(S/'implementation/run.py'));before=C.read(P/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py');old_run=load('_parent1192_run',P/'implementation/run.py');new_run=load('_current1197_run',S/'implementation/run.py');derived=new_run.derive(before);prior=old_run.derive(before);self.assertEqual(derived.replace('            Y.seed_tooling(auditor,downloads,cache,owner)\n',''),prior);self.assertIn('auditor.fetch(row,cache,True)',derived)
  text=C.read(S/'implementation/workflow-template.yml');self.assertIn(b'--tooling-inputs "$GITHUB_WORKSPACE/fresh607-tooling-inputs"',text);self.assertIn(b'ref: fb515d735a81194f06ea117539dee60438bb8d87',text);self.assertEqual(G.with_tooling(C.read(P/'implementation/workflow-template.yml')),text)
  for n in G.ALIASES:self.assertEqual(C.read(S/n),text.replace(b'@FRESH607_MANIFEST@',C.pin(C.read(S/'source-manifest.json'))['sha256'].encode()))
 def test_actual_integration_selector_private_seed_and_no_collected_code(self):
  run=load('_current_seed_integration',S/'implementation/run.py');integration=run.Integration(None,None,L,None,tooling_root=K);cache,o=self.cache('integration');integration.seed_tooling(auditor,self.p['downloads'],cache,o);self.assertEqual(len(list(cache.iterdir())),35)
  with self.assertRaises(ValueError):run.Integration(None,None,L,None).seed_tooling(auditor,self.p['downloads'],cache,o)
if __name__=='__main__':unittest.main(verbosity=2)
