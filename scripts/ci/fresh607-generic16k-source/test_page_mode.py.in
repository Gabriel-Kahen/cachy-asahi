#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Six explicit source-only page controls; synthetic observations are not boot evidence."""
import ast,copy,json,sys,tempfile,types,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import common as C,page_mode as P,adapter,page_source as G

def code(name,raw):
 m=types.ModuleType(name);m.__file__='<SOURCE_ONLY_'+name+'>';exec(compile(raw,m.__file__,'exec'),m.__dict__);return m

def current(name):return adapter.transform(C.read(C.ROOT/'parent604'/name),name)[0]
class Controls(unittest.TestCase):
 def test_default4k_bytes_whole_parent_and_inventory_held(self):
  from run import Integration
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'candidate';Integration(None,None,None,None).candidate(out)
   for n in adapter.NAMES:self.assertEqual(C.read(out/n),current(n))
  self.assertEqual(C.profile()['target'],C.pin(C.read(C.HERE/'expected607.lock')));self.assertEqual(P.configuration()['default'],'generic4k')
  for mode,kernel in(('foreign',None),(True,None),('generic4k',Path('/not-used')),('generic16k',None)):
   with self.assertRaises(ValueError):P.select(mode,kernel)
 def test_six_exact_16k_inverse_clocks_and_stockkernel_preserved(self):
  for n in adapter.NAMES:
   raw=current(n);new=P.transform(raw,n);restored=new
   for a,b in reversed(P.edits()[n]):restored=restored.replace(b.encode(),a.encode(),1)
   self.assertEqual(restored,raw);clocks=lambda b:[q.value for q in ast.walk(ast.parse(b))if isinstance(q,ast.Constant)and type(q.value)is int and q.value in(600,1800,1900,4500,4650,5200,5400,5500,9600,15600)];self.assertEqual(clocks(raw),clocks(new))
  self.assertIn(b'generic16K VM',P.transform(current('profile.py'),'profile.py'));self.assertIn(b'generic4K VM',current('profile.py'));raw=P.transform(current('prepare.py'),'prepare.py');self.assertIn(b"common.digest('/boot/Image') == common.IMAGE_SHA",raw);self.assertIn(b"'-b',str(root),common.KERNEL",raw);self.assertIn(b"'kernel16k.Image'",raw)
 def test_complete_host_parser_actual_page_release_nonce_and_original_flags(self):
  vm=code('vm',P.transform(current('run.py'),'run.py'));nonce='1'*32;profile='2'*64;result=dict(event='result',status='PASS_PUBLIC_PAIRS_APPS6_CURRENT607_INSTALLER',phase='complete',package_count=607,expected_lock_sha256=C.profile()['target']['sha256'],hooks='DISABLED',scriptlets='DISABLED',hardware='NOT RUN',native_container_P0='UNCHANGED-FAILED',nonce=nonce,profile_sha256=profile,**{k:True for k in vm.PASS_FLAGS});events=[dict(event='boot',scope='generic-arm-full-installer-software',page_size=16384,kernel=P.RELEASE,uid=0),result,dict(event='exit',status=result['status'],cleanup='PASS')];self.assertIs(vm.validate_completion(events,nonce,types.SimpleNamespace(KERNEL='4K_STOCK_NOT_16K_AUTHORITY'),profile),result)
  for field,value in(('page_size',4096),('page_size',True),('kernel','foreign'),('uid',True)):
   bad=copy.deepcopy(events);bad[0][field]=value
   with self.assertRaises(ValueError):vm.validate_completion(bad,nonce,None,profile)
  for field in vm.PASS_FLAGS:
   bad=copy.deepcopy(events);bad[1][field]=False
   with self.assertRaises(ValueError):vm.validate_completion(bad,nonce,None,profile)
  with self.assertRaises(ValueError):vm.validate_completion(events,'3'*32,None,profile)
 def test_source_root_ordinary_and_numeric_page_guards_independent(self):
  class ReachedNextSourceStep(Exception):pass
  def need(v,why):
   if not v:raise ValueError(why)
   raise ReachedNextSourceStep()
  fakepath=lambda *_:types.SimpleNamespace(read_text=lambda:'cachy_asahi_virtual_proof=1')
  for name,function,uid in(('guest.py','main',0),('installer.py','ordinary_preflight',23001),('numeric_vm.py','root_guard',0)):
   tree=ast.parse(P.transform(current(name),name));node=next(q for q in tree.body if isinstance(q,ast.FunctionDef)and q.name==function)
   for page,release,success in((16384,P.RELEASE,True),(4096,P.RELEASE,False),(16384,'7.2.10-1-aarch64-ARCH',False)):
    fakeos=types.SimpleNamespace(getuid=lambda:uid,geteuid=lambda:uid,getgid=lambda:uid,getegid=lambda:uid,getgroups=lambda:[],uname=lambda:types.SimpleNamespace(machine='aarch64',release=release),sysconf=lambda _:page,environ={'CACHY_ASAHI_FULL_INSTALLER_GUEST':'1'})
    scope=dict(os=fakeos,sys=types.SimpleNamespace(argv=['source','boot'],platform='linux'),need=need,p=types.SimpleNamespace(need=need),Path=fakepath,observer_budget=lambda:None);exec(compile(ast.Module(body=[node],type_ignores=[]),'<EXACT_SOURCE_FIRST_GUARD>','exec'),scope)
    with self.assertRaises(ReachedNextSourceStep if success else ValueError):scope[function]()
 def test_buildonly_descriptor_closed_and_changed_input_refusal(self):
  d=P.descriptor();self.assertEqual((d['page_size'],d['kernel'],d['modules']),(16384,P.RELEASE,'DISABLED'));self.assertEqual(d['boot'],d['fresh607']);self.assertEqual(d['boot'],'NOT_RUN')
  with self.assertRaises(ValueError):P.kernel_bytes(b'not a kernel',b'not a config')
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'Image').write_bytes(b'not a kernel');(root/'config').write_bytes(b'');(root/'kernel-input.json').write_bytes(C.enc(d))
   with self.assertRaises(ValueError):P.inputs(root)
   (root/'extra').write_bytes(b'')
   with self.assertRaises(ValueError):P.inputs(root)
 def test_current_workflow_source_inverse_and_all_selectors_null(self):
  p=json.loads(C.read(C.HERE/'page-parent.json'));self.assertEqual(C.pin(C.read(C.HERE/'page_source.py').replace(G.PARENT_SHA.encode(),b'@PARENT_'+b'SHA@')),p['guard_template']);before={n:p['before_bodies'][n].encode()if n in p['before_bodies']else C.read(C.ROOT/n)for n in p['files']};self.assertEqual({n:C.pin(b)for n,b in before.items()},p['files']);products={n:C.checked(C.ROOT/n,w)for n,w in p['products'].items()};expected=G.transformed(before,products,C.read(C.HERE/'page-parent.json'),C.read(C.HERE/'page_source.py'));self.assertEqual(len(expected),1203)
  for n,b in expected.items():self.assertEqual(C.read(C.ROOT/n),b)
  self.assertIn(b'options: [generic4k, generic16k]',expected[G.ALIASES[0]]);self.assertIn(b'--kill-after=10s 300s',expected[G.ALIASES[0]]);self.assertIn(b'actions: read',expected[G.ALIASES[0]]);self.assertTrue(all(C.profile()[k]is None for k in('actual_source','actual_ref','actual_run')))
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls);assert suite.countTestCases()==6;r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
