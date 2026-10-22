# SPDX-License-Identifier: MIT
"""Portable control of the fixed plan and strict transaction preparation boundary."""
import copy,ctypes,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C,transaction as T
class Controls(unittest.TestCase):
 def test_exact_closed_thirteen_and_seven_574_589_574(self):
  base,supported,installed=C.states();self.assertEqual((len(base),len(supported),len(installed)),(574,587,589));self.assertEqual(set(installed)-set(base),set(C.profile()['support'])|{'systemd-tests','systemd-ukify'});self.assertEqual({n for n in base if base[n]!=installed[n]},C.REPLACED)
 def test_missing_or_extra_support_and_versions_refuse(self):
  original=C.read
  for edit in('missing','extra','version'):
   v=json.loads(original(C.HERE/'support-closure.json'))
   if edit=='missing':v['support'].pop('python-psutil')
   elif edit=='extra':v['support']['bash']={}
   else:v['candidate']['systemd']='262-1'
   with patch.object(C,'read',side_effect=lambda p,*a:C.encoded(v)if Path(p).name=='support-closure.json'else original(p,*a)):
    with self.assertRaises(ValueError):C.states()
 def test_full_protected_nodes_and_database_records_never_excluded(self):
  before={'boot/Image':dict(sha256='a'),'usr/lib/libc.so.6':dict(sha256='b'),'var/lib/pacman/local/mesa-1/desc':dict(sha256='c'),'usr/bin/pacman':dict(sha256='d'),'usr':dict(type='directory',mode=0o755,uid=0,gid=0)};after=copy.deepcopy(before);after['usr/bin/pacman']={'sha256':'e'};package=dict(nodes={'usr/bin/pacman':{'type':'file'},'usr':dict(type='directory',mode=0o755,uid=0,gid=0)})
  self.assertTrue(C.changes(before,after,[package],[('pacman','old')])['unrelated_complete_nodes_preserved'])
  for n in('boot/Image','usr/lib/libc.so.6','var/lib/pacman/local/mesa-1/desc','usr'):
   wrong=copy.deepcopy(after);wrong[n]={'sha256':'f'}
   with self.assertRaisesRegex(ValueError,'protected'):C.changes(before,wrong,[package],[('pacman','old')])
 def test_any_wrong_root_or_missing_full_seven_refuses_before_alpm(self):
  base,_,installed=C.states();api={'roots':types.SimpleNamespace(Alpm=lambda *a,**k:(_ for _ in()).throw(AssertionError('ALPM_REACHED')))}
  with self.assertRaisesRegex(ValueError,'owned copied'):T.apply(api,Path('/'),Path('/tmp/core-public-gpg'),Path('/out/t.log'),[],{},base,installed,sys.float_info.max)
  with self.assertRaisesRegex(ValueError,'all seven'):T.apply(api,Path('/work/pristine/root'),Path('/tmp/core-public-gpg'),Path('/out/t.log'),[],{},base,installed,sys.float_info.max)
 def test_complete_original_observer_inverse_and_real_unsafe_archive_refusals(self):
  import ast,io,tarfile
  source=(C.HERE/'package_data.py').read_text();tree=ast.parse(source);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='archive');body=ast.get_source_segment(source,fn)
  new="m.uid==m.gid==0 and(not m.mode&0o7000 or(m.isdir()and n=='var/log/journal'and m.mode==0o2755))"
  old="m.uid==m.gid==0 and not m.mode&0o7000";self.assertEqual(body.count(new),1);body=body.replace(new,old)
  a="need('\\x00'not in m.linkname and(not m.linkname.startswith('/')or(n,m.linkname)in(('usr/share/licenses/systemd/MIT-0.txt','/usr/share/doc/systemd/LICENSES/MIT-0.txt'),('usr/share/licenses/python-pytest/LICENSE','/usr/lib/python3.14/site-packages/pytest-9.1.1.dist-info/licenses/LICENSE'))),'only original relative links or exact accepted systemd license link')"
  b="need(not m.linkname.startswith('/') and '\\x00' not in m.linkname,'relative package link')";self.assertEqual(body.count(a),1);body=body.replace(a,b);self.assertEqual(body,(C.HERE/'test_support/archive-before.py').read_text().rstrip())
  for mode,target in((0o4755,None),(0o644,'/private/foreign')):
   with tempfile.TemporaryDirectory()as td:
    path=Path(td)/'bad.tar'
    with tarfile.open(path,'w')as t:
     m=tarfile.TarInfo('usr/unsafe');m.mode=mode
     if target:m.type=tarfile.SYMTYPE;m.linkname=target;t.addfile(m)
     else:m.size=1;t.addfile(m,io.BytesIO(b'x'))
    with self.assertRaises(ValueError):C.P.archive(path)
 def test_precommit_routes_strict_signature_flags_and_refuses_extra_prepared_package(self):
  base,_,installed=C.states();profile=C.profile();closure=C.closure();versions={n:r['version']for n,r in profile['packages'].items()}|{n:r['version']for n,r in closure['support'].items()};add=[dict(name=n,version=v,archive=Path('/inputs/packages')/n,signature=Path('/inputs/packages')/(n+'.sig'),signer='A'*40)for n,v in versions.items()]
  class Fake:
   def __init__(self,*a,**kw):self.handle=object();self.started=False;self.committed=False;self.closed=False;self.loaded={};self.flags=None;self.signature_levels=[]
   def inventory(self):return installed if self.committed else base
   def ok(self,code,label):self_outer.assertEqual(code,0)
   def alpm_trans_init(self,h,flags):self.flags=flags;return 0
   def alpm_pkg_load(self,h,path,full,sig,out):
    n=Path(path.decode()).name;out._obj.value=len(self.loaded)+1;self.loaded[out._obj.value]=(n,versions[n]);self.signature_levels.append((full,sig));return 0
   def alpm_pkg_get_name(self,p):return self.loaded[p.value][0].encode()
   def alpm_pkg_get_version(self,p):return self.loaded[p.value][1].encode()
   def alpm_pkg_get_arch(self,p):return b'aarch64'
   def alpm_add_pkg(self,*a):return 0
   def alpm_trans_prepare(self,*a):return 0
   def alpm_trans_get_add(self,h):return dict(versions,**({'foreign':'1'}if drift else{}))
   def alpm_trans_get_remove(self,h):return{}
   def packages(self,v):return v
   def alpm_trans_commit(self,*a):self.committed=True;return 0
   def close(self):self.closed=True
  self_outer=self
  for drift in(False,True):
   instance=Fake();api={'roots':types.SimpleNamespace(Alpm=lambda *a,**kw:instance,Limits=lambda **kw:kw,installer=types.SimpleNamespace(Ptr=ctypes.c_void_p))}
   args=(api,Path('/work/pristine/root'),Path('/tmp/core-public-gpg'),Path('/out/test.log'),add,{},base,installed,sys.float_info.max)
   if drift:
    with self.assertRaisesRegex(ValueError,'prepared'):T.apply(*args,prepare_only=True)
   else:self.assertFalse(T.apply(*args,prepare_only=True)['commit_started'])
   self.assertEqual(instance.flags,T.FLAGS);self.assertEqual(instance.signature_levels,[(1,1)]*20);self.assertFalse(instance.committed);self.assertTrue(instance.closed)
if __name__=='__main__':unittest.main(verbosity=2)
