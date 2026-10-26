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
   raw=current(n);new=P.transform(raw,n);restored=P.engine_failure_inverse(new)if n=='installer.py'else new
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

def engine_fixture(receipt,success=False):
 """Execute the exact emitted ordinary caller with private DATA-only dependencies."""
 import contextlib,hashlib,io,os,stat,time,fcntl
 raw=P.transform(current('installer.py'),'installer.py');tree=ast.parse(raw)
 nodes=[q for q in tree.body if isinstance(q,ast.FunctionDef)and q.name in('execute','engine_failure_projection')]
 assert len(nodes)==2
 with tempfile.TemporaryDirectory()as td:
  root=Path(td);calls=[];nonce='1'*32;profile_sha='2'*64
  class Trial:
   def is_dir(self):return True
   def stat(self):return types.SimpleNamespace(st_uid=23001,st_mode=stat.S_IFDIR|0o700)
   def __truediv__(self,name):return root/name
   def __str__(self):return str(root)
  class Evidence:
   def __init__(self,path):self.path=path;self.fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY);s=path.stat();self.identity=[s.st_dev,s.st_ino]
   def save(self,name,row):(self.path/name).write_bytes(C.enc(row))
   def write(self,name,data,exclusive=False):(self.path/name).write_bytes(data)
   def view(self):return self.path
   def node_identity(self,name):s=(self.path/name).stat();return[s.st_dev,s.st_ino]
   def check(self):calls.append('evidence_identity')
   def close(self):os.close(self.fd);calls.append('evidence_close')
  def supervise(*args,**kwargs):
   assert kwargs['timeout']==4550 and len(kwargs['pass_fds'])==2
   assert fcntl.fcntl(kwargs['pass_fds'][0],getattr(fcntl,'F_GET_SEALS',1034))==15
   if success:
    path=root/'work/evidence/result.json';path.write_bytes(C.enc(dict(status='PROVISIONAL_FULL_COMPOSITION_INSTALLER',phase='complete',nonce=nonce,profile_sha256=profile_sha)))
   return receipt
  def checked_inputs(**kw):calls.append(('protected_rehash',kw));return None
  def observe(*args,**kw):calls.append('parent_observe');return dict(nodes={})
  def compare(*args,**kw):calls.append('payload_compare')
  def database(*args,**kw):calls.append('database');return []
  base=types.SimpleNamespace(Evidence=Evidence,namespaces=lambda:{},environment=lambda **kw:kw)
  roots=types.SimpleNamespace(Limits=lambda **kw:kw,observe=observe)
  c=dict(nonce=nonce,tooling_inventory={});profile=dict(expected={});driver=types.SimpleNamespace(database=database)
  p=types.SimpleNamespace(need=C.need,decode=json.loads,encoded=C.enc,sha=lambda _:profile_sha,EXPECTED=hashlib.sha256(b'').hexdigest(),GIB=1024**3)
  local_os=os
  if not hasattr(os,'memfd_create'):
   import ctypes
   libc=ctypes.CDLL(None,use_errno=True);create=libc.memfd_create;create.argtypes=(ctypes.c_char_p,ctypes.c_uint);create.restype=ctypes.c_int
   def real_memfd(name,flags):
    fd=create(name.encode(),flags)
    if fd<0:raise OSError(ctypes.get_errno(),'real fixture memfd_create')
    return fd
   local_os=types.SimpleNamespace(**{n:getattr(os,n)for n in dir(os)});local_os.memfd_create=real_memfd;local_os.MFD_CLOEXEC=1;local_os.MFD_ALLOW_SEALING=2
  local_fcntl=types.SimpleNamespace(fcntl=fcntl.fcntl,F_ADD_SEALS=getattr(fcntl,'F_ADD_SEALS',1033))
  scope=dict(p=p,ordinary_preflight=lambda *_:(c,profile,{},dict(nodes={},ownership={}),roots,base,driver,None),TRIAL=Trial(),Path=Path,stat=stat,os=local_os,time=time,hashlib=hashlib,fcntl=local_fcntl,json=json,SHARED=root,engine_argv=lambda *_:['SOURCE_FIXTURE_NOT_AN_ACTOR'],supervise=supervise,checked_inputs=checked_inputs,compare_payload=compare,PASS='PASS_SOURCE_FIXTURE')
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'<EXACT_EMITTED_EXECUTE_PRIVATE_FIXTURE>','exec'),scope)
  out=io.StringIO()
  with contextlib.redirect_stdout(out):status=scope['execute']()
  return status,json.loads(out.getvalue()),calls

def test_engine_actual_caller_failure_retains_original_error(self):
 raw=bytes(range(256))*200;receipt=dict(returncode=1,termination=None,direct_child_reaped=True,group_retired=True,output=raw)
 status,result,calls=engine_fixture(receipt);self.assertEqual(status,1);self.assertEqual((result['status'],result['phase'],result['parent_error_type'],result['parent_error']),('FAIL','parent','ValueError','guarded engine incomplete'))
 row=result['engine_failure_data'];import base64,hashlib
 self.assertEqual(base64.b64decode(row['tail_base64'],validate=True),raw[-2048:]);self.assertEqual((row['output_bytes'],row['output_sha256']),(len(raw),hashlib.sha256(raw).hexdigest()));self.assertFalse(row['tail_complete']);self.assertFalse(row['transaction_authority']);self.assertFalse(row['cleanup_authority']);self.assertEqual(row['returncode'],1);self.assertNotIn('parent_observe',calls);self.assertEqual(calls[-1],'evidence_close')

def test_engine_actual_caller_positive_has_no_projection(self):
 receipt=dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True,output=b'unchanged success')
 status,result,calls=engine_fixture(receipt,True);self.assertEqual(status,0);self.assertEqual(result['status'],'PASS_SOURCE_FIXTURE');self.assertNotIn('engine_failure_data',result);self.assertTrue(all(result[n]for n in('process_retirement','parent_inventory_preserved','source_cache_preserved','ordinary_parent_nnp_cap0')));self.assertIn('parent_observe',calls);self.assertIn('payload_compare',calls);self.assertIn(('protected_rehash',{'protected':True}),calls);self.assertEqual(calls.count('database'),3)

def test_engine_typed_boundary_and_shape_failure_preserve_refusal(self):
 import hashlib,base64
 tree=ast.parse(P.transform(current('installer.py'),'installer.py'));node=next(q for q in tree.body if isinstance(q,ast.FunctionDef)and q.name=='engine_failure_projection');m=types.SimpleNamespace();import hashlib;scope=dict(hashlib=hashlib,json=json);exec(compile(ast.Module(body=[node],type_ignores=[]),'<EXACT_ENGINE_HELPER>','exec'),scope);m.engine_failure_projection=scope['engine_failure_projection']
 good=dict(returncode=1,termination=None,direct_child_reaped=True,group_retired=True,output=b'x'*(1024**2))
 row=m.engine_failure_projection(good);self.assertEqual(row['output_bytes'],1024**2);self.assertEqual(base64.b64decode(row['tail_base64']),b'x'*2048);self.assertLess(len(C.enc(row)),4096)
 for field,value in(('output',b'x'*(1024**2+1)),('output','text'),('returncode',True),('returncode',256),('termination','foreign'),('direct_child_reaped',1),('group_retired',None)):
  bad=dict(good,**{field:value});self.assertEqual(m.engine_failure_projection(bad)['status'],'REFUSED_DIAGNOSTIC_SHAPE');status,result,_=engine_fixture(bad);self.assertEqual(status,1);self.assertEqual(result['parent_error'],'guarded engine incomplete')
 for raw in(b'',b'a'*2048,b'\xff\x00\n'):
  row=m.engine_failure_projection(dict(good,output=raw));self.assertTrue(row['tail_complete']);self.assertEqual(base64.b64decode(row['tail_base64']),raw);self.assertEqual(row['output_sha256'],hashlib.sha256(raw).hexdigest())
 self.assertEqual(m.engine_failure_projection(dict(good,foreign=True))['status'],'REFUSED_DIAGNOSTIC_SHAPE')

def test_engine_frame_is_failure_data_not_host_acceptance(self):
 raw_source=P.transform(current('installer.py'),'installer.py');tree=ast.parse(raw_source);helper_index=next(i for i,q in enumerate(tree.body)if isinstance(q,ast.FunctionDef)and q.name=='engine_failure_projection');entry_index=next(i for i,q in enumerate(tree.body)if isinstance(q,ast.If)and '__main__'in ast.unparse(q.test));self.assertLess(helper_index,entry_index)
 status,result,_=engine_fixture(dict(returncode=1,termination=None,direct_child_reaped=True,group_retired=False,output=b'inner preflight example SOURCE_FIXTURE'))
 vm=code('host_failure_projection',P.transform(current('run.py'),'run.py'));nonce='1'*32
 events=[dict(event='boot',scope='generic-arm-full-installer-software',page_size=16384,kernel=P.RELEASE,uid=0),dict(result,event='result'),dict(event='exit',status='FAIL',cleanup='FAIL')]
 raw=b''.join(('FULL_INSTALLER '+nonce+' '+json.dumps(row,sort_keys=True)+'\n').encode()for row in events)
 parsed=vm.parse_protocol(raw,nonce,complete=False);self.assertEqual(parsed,events);self.assertLess(len(raw),8192)
 with self.assertRaises(ValueError):vm.validate_completion(parsed,nonce,None,'2'*64)
 before=current('installer.py');self.assertEqual(P.engine_failure_inverse(P.transform(before,'installer.py')).count(P.ENGINE_GUARD.encode()),1)
 # Exact original guard text survives; no output/deadline increase or acceptance rewrite.
 self.assertIn(b'timeout=4550',before);self.assertIn(b'limit=1024**2',before)

Controls.test_engine_actual_caller_failure_retains_original_error=test_engine_actual_caller_failure_retains_original_error
Controls.test_engine_actual_caller_positive_has_no_projection=test_engine_actual_caller_positive_has_no_projection
Controls.test_engine_typed_boundary_and_shape_failure_preserve_refusal=test_engine_typed_boundary_and_shape_failure_preserve_refusal
Controls.test_engine_frame_is_failure_data_not_host_acceptance=test_engine_frame_is_failure_data_not_host_acceptance

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls);assert suite.countTestCases()==10;r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
