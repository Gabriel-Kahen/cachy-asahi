# SPDX-License-Identifier: MIT
"""Changed-callable DATA tests with real owned DirFD fixtures; no Source actor role."""
import argparse,ast,contextlib,hashlib,os,re,stat,subprocess,socket,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;INVENTORY_RAW=None
raw=(HERE/'payload/consumer/native_adapter/native.py').read_text();tree=ast.parse(raw)
def need(v,why):
 if not v:raise ValueError(why)
c=SimpleNamespace(need=need,pin=lambda b:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()))
namespace=dict(c=c,os=os,re=re,stat=stat,Path=Path,INVENTORY='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453')
for name in('alpm_inventory','read_alpm_desc','actor_dispatch'):
 node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name);exec(compile(ast.Module(body=[node],type_ignores=[]),'<changed-callable-DATA-fixture>','exec'),namespace)

class Controls(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  for n in('subprocess.run','subprocess.Popen','socket.socket','socket.create_connection','fcntl.flock','os.pidfd_open','os.fork','os.system'):stack.enter_context(patch(n,side_effect=AssertionError('operational actor/network/lease forbidden'),create=True))
  self.admitted=namespace['alpm_inventory'](INVENTORY_RAW)
 def fixture(self,name='avahi'):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);package=next(k for k,v in self.admitted.items()if v[0]==name);pair=self.admitted[package];directory=root/'var/lib/pacman/local'/package;directory.mkdir(parents=True);desc=directory/'desc';desc.write_bytes(('%NAME%\n'+pair[0]+'\n\n%VERSION%\n'+pair[1]+'\n\n%DESC%\nOwned fixture\n\n').encode());return root,desc,Path('/var/lib/pacman/local')/package/'desc'
 def read(self,root,logical):
  actual=os.open
  with patch.object(os,'open',side_effect=lambda p,*a,**k:actual(root if p=='/'else p,*a,**k)):return namespace['read_alpm_desc'](logical,self.admitted)
 def test_actual349_inventory_epoch_class_and_pinned_hash(self):
  self.assertEqual(len(self.admitted),349);self.assertEqual(sum(':'in v for n,v in self.admitted.values()),21)
  with self.assertRaises(ValueError):namespace['alpm_inventory'](INVENTORY_RAW+b'changed')
 def test_real_DirFD_read_accepts_all_three_actual_epoch_examples(self):
  for name in('avahi','fakeroot','fontconfig'):
   root,desc,logical=self.fixture(name);self.assertIn(':',logical.parent.name);self.assertEqual(self.read(root,logical),' '.join(self.admitted[logical.parent.name]))
 def test_real_DirFD_read_non_epoch_class(self):
  root,desc,logical=self.fixture('acl');self.assertEqual(self.read(root,logical),' '.join(self.admitted[logical.parent.name]))
 def test_wrong_root_traversal_or_unadmitted_dir_refuses_before_open(self):
  paths=['/tmp/var/lib/pacman/local/avahi-1:0.9rc5-1/desc','/var/lib/pacman/local/../avahi-1:0.9rc5-1/desc','/var/lib/pacman/local/avahi-9:0.9rc5-1/desc','/var/lib/pacman/local/avahi-1:0.9rc5-1/files','/var/lib/pacman/local/avahi-1:0.9rc5-1/extra/desc']
  for p in paths:
   with self.subTest(path=p),patch.object(os,'open',side_effect=AssertionError('must refuse before IO')),self.assertRaises(ValueError):namespace['read_alpm_desc'](p,self.admitted)
 def test_name_version_or_duplicate_field_mismatch_refuses(self):
  for kind in('name','version','duplicate','NUL'):
   root,desc,logical=self.fixture();body=desc.read_bytes()
   if kind=='name':body=body.replace(b'avahi',b'foreign',1)
   elif kind=='version':body=body.replace(b'1:0.9rc5-1',b'2:0.9rc5-1',1)
   elif kind=='duplicate':body+=b'%NAME%\navahi\n\n'
   else:body+=b'\0'
   desc.write_bytes(body)
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.read(root,logical)
 def test_symlink_leaf_or_ancestry_never_followed(self):
  for kind in('leaf','package','ancestor'):
   root,desc,logical=self.fixture()
   if kind=='leaf':target=desc.parent/'original';desc.rename(target);desc.symlink_to(target)
   elif kind=='package':target=desc.parent.with_name('saved');desc.parent.rename(target);desc.parent.symlink_to(target,target_is_directory=True)
   else:parent=desc.parent.parent;target=parent.with_name('saved-local');parent.rename(target);parent.symlink_to(target,target_is_directory=True)
   with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):self.read(root,logical)
 def test_hardlink_size_and_FIFO_refuse_bounded(self):
  for kind in('hardlink','size','FIFO'):
   root,desc,logical=self.fixture()
   if kind=='hardlink':os.link(desc,desc.parent/'link')
   elif kind=='size':desc.write_bytes(b'x'*(1024**2+1))
   else:desc.unlink();os.mkfifo(desc)
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.read(root,logical)
 def test_descriptor_mutation_during_read_refuses(self):
  root,desc,logical=self.fixture();actual=os.read;changed=[]
  def read(fd,n):
   body=actual(fd,n)
   if not changed:changed.append(True);desc.write_bytes(desc.read_bytes()+b'changed')
   return body
  with patch.object(os,'read',side_effect=read),self.assertRaises(ValueError):self.read(root,logical)
 def test_directory_replacement_after_open_refuses(self):
  root,desc,logical=self.fixture();actual=os.read;changed=[]
  def read(fd,n):
   body=actual(fd,n)
   if not changed:
    changed.append(True);desc.parent.rename(desc.parent.with_name('saved-package'));desc.parent.mkdir();desc.write_bytes(b'new')
   return body
  with patch.object(os,'read',side_effect=read),self.assertRaises(ValueError):self.read(root,logical)
 def dispatch(self,primary,secondary):
  fd=os.open(os.devnull,os.O_RDONLY);closed=[]
  def actor(_):
   if primary is not None:raise primary
   return 0
  def record(*_):
   if secondary is not None:raise secondary
  prior={k:namespace.get(k)for k in('work_preentry','actor','record_work_preentry')}
  namespace.update(work_preentry=lambda _:({},fd),actor=actor,record_work_preentry=record)
  try:return namespace['actor_dispatch']('a'*64)
  finally:
   namespace.update(prior)
   with self.assertRaises(OSError):os.fstat(fd)
 def test_primary_error_preserved_when_early_output_does_not_exist(self):
  primary=ValueError('ordinary absolute path required')
  with self.assertRaises(ValueError)as caught:self.dispatch(primary,FileNotFoundError('output'))
  self.assertIs(caught.exception,primary);self.assertIsNone(primary.__cause__);self.assertIn('FileNotFoundError',primary.__notes__[0]);self.assertLess(len(primary.__notes__[0]),640)
 def test_primary_still_refuses_if_preentry_record_succeeds(self):
  primary=ValueError('primary')
  with self.assertRaises(ValueError)as caught:self.dispatch(primary,None)
  self.assertIs(caught.exception,primary)
 def test_receipt_failure_after_actor_success_never_grants_early_success(self):
  with self.assertRaises(FileNotFoundError):self.dispatch(None,FileNotFoundError('output'))
 def test_global_path_guard_and_work_volume_functions_unchanged(self):
  parent=Path(INVENTORY_PATH).parent.parent;old=(parent/'consumer/native_adapter/native.py').read_text();functions=lambda s:{n.name:ast.get_source_segment(s,n)for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)};before,after=functions(old),functions(raw)
  for name in before:
   if name not in('actor','actor_dispatch'):self.assertEqual(before[name],after[name],name)
  self.assertEqual((parent/'consumer/native_adapter/support/common.py').read_bytes(),(HERE.parents[4]/'scripts/port/perl5423-xs-consumer/native_adapter/support/common.py').read_bytes())
  common=(parent/'consumer/native_adapter/support/common.py').read_text();node=next(n for n in ast.parse(common).body if isinstance(n,ast.FunctionDef)and n.name=='path');ns=dict(need=need,os=os,Path=Path);exec(compile(ast.Module(body=[node],type_ignores=[]),'<unchanged-global-path-DATA-test>','exec'),ns)
  with self.assertRaises(ValueError):ns['path']('/var/lib/pacman/local/avahi-1:0.9rc5-1/desc')

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--inventory',type=Path,required=True);a=p.parse_args();INVENTORY_PATH=a.inventory.resolve();INVENTORY_RAW=INVENTORY_PATH.read_bytes();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));raise SystemExit(not result.wasSuccessful())
