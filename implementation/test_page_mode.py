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
   if n in('run.py','guest.py'):restored=P.clock_inverse(restored,n)
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

def numeric_source_fixture(mode='generic16k'):
 """Real emitted caller+same raw library; only platform/proc DATA are mocked."""
 import contextlib,hashlib
 @contextlib.contextmanager
 def fixture():
  saved,paths=dict(sys.modules),sys.path[:]
  try:
   source=C.ROOT/'parent853/roles/ksm-worker/held-copy';relative='scripts/install/local_transaction.py';raw=C.read(source/relative);profile=dict(code_files={relative:C.pin(raw)})
   for held in (relative,'scripts/update/full_root.py','scripts/ci/full-root-upgrade/root_upgrade.py'):C.need(C.read(source/held)==C.read(C.ROOT/'installer604'/held),'complete genuine helper fixture exact raw installer inputs')
   p=code('_numeric_actual_profile',P.transform(current('profile.py'),'profile.py')if mode=='generic16k'else current('profile.py'));sys.modules['profile']=p
   n=code('_numeric_actual_guest',P.transform(current('numeric_vm.py'),'numeric_vm.py')if mode=='generic16k'else current('numeric_vm.py'));sys.modules['numeric_vm']=n
   installer=code('_numeric_actual_installer',P.transform(current('installer.py'),'installer.py')if mode=='generic16k'else current('installer.py'))
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);(root/'installer-profile.json').write_bytes(p.encoded(profile))
    class Shared:
     def __truediv__(self,name):
      if name=='code':return source
      if name=='installer-profile.json':return root/name
      raise AssertionError('foreign fixture source role')
    installer.SHARED=Shared();modules=installer.source_modules(profile);yield installer,p,modules,profile,raw
  finally:
   sys.path[:]=paths
   for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
   sys.modules.update(saved)
 return fixture()

def numeric_platform_fixture(base,page=16384,release=P.RELEASE,**change):
 """Exact source-owned UID/GID maps; no host namespace/capability mutation."""
 import copy
 value=dict(purpose=base.NUMERIC_FIXTURE_PURPOSE,uid_map=[[0,23001,1]],gid_map=[list(row)for row in base.NUMERIC_FIXTURE_GIDS])
 state=dict(machine='aarch64',release=release,page=page,uid=0,euid=0,gid=0,egid=0,groups=[],marker='cachy_asahi_virtual_proof=1',uid_map='0 23001 1\n',gid_map=''.join(' '.join(map(str,r))+'\n'for r in value['gid_map']),setgroups='allow');state.update(change)
 fakeos=types.SimpleNamespace(uname=lambda:types.SimpleNamespace(machine=state['machine'],release=state['release']),sysconf=lambda _:state['page'],getuid=lambda:state['uid'],geteuid=lambda:state['euid'],getgid=lambda:state['gid'],getegid=lambda:state['egid'],getgroups=lambda:state['groups'],getpid=lambda:1)
 oldpath=Path
 def path(name):
  text={'/proc/cmdline':state['marker'],'/proc/self/uid_map':state['uid_map'],'/proc/self/gid_map':state['gid_map'],'/proc/self/setgroups':state['setgroups']}
  return types.SimpleNamespace(read_text=lambda:text[str(name)])if str(name)in text else oldpath(name)
 base.os=fakeos;base.Path=path;return value,state

class NumericPlatformControls(unittest.TestCase):
 def test_real_selected_private_globals_three_literal_inverse_and_raw_held(self):
  with numeric_source_fixture()as(installer,p,modules,profile,raw):
   roots,base,driver,aux=modules;self.assertIsNot(base,roots.installer);self.assertIs(base.isolate.__globals__,vars(base));self.assertIs(base.reduce_capabilities.__globals__['numeric_fixture_environment'],base.numeric_fixture_environment);self.assertEqual(C.read(C.ROOT/'installer604/scripts/install/local_transaction.py'),raw)
   before=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='numeric_fixture_environment');old=ast.get_source_segment(raw.decode(),before);selected=old
   changes=(("os.uname().release=='7.2.10-1-aarch64-ARCH'","os.uname().release=='7.1.13-generic16k-managed-gui'"),("os.sysconf('SC_PAGE_SIZE')==4096","os.sysconf('SC_PAGE_SIZE')==16384"),('numeric fixture mapped generic4K guest required','numeric fixture mapped generic16K guest required'))
   for a,b in changes:self.assertEqual(selected.count(a),1);selected=selected.replace(a,b,1)
   expected=compile(selected,'<exact-source-numeric16k-environment>','exec');fn=next(x for x in expected.co_consts if isinstance(x,types.CodeType));self.assertEqual(base.numeric_fixture_environment.__code__.co_code,fn.co_code);self.assertEqual(base.numeric_fixture_environment.__code__.co_consts,fn.co_consts)
   for name in('isolate','reduce_capabilities','capability_mask','numeric_fixture_selection','validate_contract'):
    self.assertEqual(getattr(base,name).__code__.co_code,getattr(roots.installer,name).__code__.co_code);self.assertEqual(getattr(base,name).__code__.co_consts,getattr(roots.installer,name).__code__.co_consts)
   self.assertEqual(base.NATIVE_PROFILE_SHA,roots.installer.NATIVE_PROFILE_SHA);self.assertEqual(base.RUNTIME_SHA,roots.installer.RUNTIME_SHA);self.assertEqual(base.FLAGS,roots.installer.FLAGS)
 def test_exact16k_kernel_page_maps_guestmarker_ids_groups_and_wrongcases(self):
  with numeric_source_fixture()as(_,p,modules,profile,raw):
   base=modules[1];value,state=numeric_platform_fixture(base);self.assertIsNone(base.numeric_fixture_environment(value))
   for field,wrong in(('page',4096),('page',65536),('release','7.2.10-1-aarch64-ARCH'),('release','foreign16k'),('machine','x86_64'),('uid',1),('euid',1),('gid',1),('egid',1),('groups',[5]),('marker',''),('uid_map','0 0 1\n'),('gid_map','0 23001 1\n'),('setgroups','deny')):
    value,state=numeric_platform_fixture(base,**{field:wrong})
    with self.subTest(field=field,wrong=wrong),self.assertRaises(ValueError):base.numeric_fixture_environment(value)
   value,state=numeric_platform_fixture(base);value['uid_map'][0][0]=False
   with self.assertRaises(ValueError):base.numeric_fixture_environment(value)
 def test_default4k_real_module_stays_callable_and16k_refuses_in_oldguard(self):
  with numeric_source_fixture('generic4k')as(_,p,modules,profile,raw):
   roots,base,_,_=modules;self.assertIs(base,roots.installer);value,state=numeric_platform_fixture(base,page=4096,release='7.2.10-1-aarch64-ARCH');self.assertIsNone(base.numeric_fixture_environment(value));value,state=numeric_platform_fixture(base)
   with self.assertRaisesRegex(ValueError,'generic4K'):base.numeric_fixture_environment(value)
  for name in adapter.NAMES:self.assertEqual(adapter.transform(C.read(C.ROOT/'parent604'/name),name)[0],current(name))
 def test_actual_engine_isolate_and_reduce_use_selected_guard_before_any_mutation(self):
  import ctypes,fcntl,hashlib,os,time
  class ReachedBeforeMutation(Exception):pass
  with numeric_source_fixture()as(installer,p,modules,profile,raw):
   roots,base,driver,aux=modules;value,state=numeric_platform_fixture(base);base.architecture_profile=lambda a:p.need(a=='aarch64','fixture architecture');base.namespaces=lambda:dict(user='new',mnt='new',pid='new',net='new');base.private=lambda *a:(_ for _ in()).throw(ReachedBeforeMutation('before first mount'))
   installer.checked_inputs=lambda **kw:(dict(nonce='a'*32),profile,{},{});installer.source_modules=lambda prof:modules;installer.fcntl=types.SimpleNamespace(fcntl=fcntl.fcntl,F_GET_SEALS=1034);profile['numeric_vm']=value
   spec=dict(contract=dict(architecture='aarch64',purpose=base.NUMERIC_FIXTURE_PURPOSE,workspace='/SYNTHETIC_PRIVATE_ONLY'),host_uid=23001,host_namespaces=dict(user='old',mnt='old',pid='old',net='old'),fixture_identity_map=value,namespace_identity=[Path('/proc/self/ns/user').stat().st_dev,Path('/proc/self/ns/user').stat().st_ino],profile_sha256=p.sha(installer.SHARED/'installer-profile.json'),nonce='a'*32,deadline=time.monotonic()+60)
   if hasattr(os,'memfd_create'):fd=os.memfd_create('source-only-numeric-control',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
   else:
    libc=ctypes.CDLL(None,use_errno=True);libc.memfd_create.argtypes=[ctypes.c_char_p,ctypes.c_uint];fd=libc.memfd_create(b'source-only-numeric-control',3);self.assertGreaterEqual(fd,0)
   data=p.encoded(spec);os.write(fd,data);fcntl.fcntl(fd,1033,15);self.assertEqual(fcntl.fcntl(fd,1034)&15,15)
   with self.assertRaises(ReachedBeforeMutation):installer.engine(str(fd),hashlib.sha256(data).hexdigest(),'99')
   # Engine owns/closes the real sealed FD. No mount/namespace operation ran.
   with self.assertRaises(OSError):os.fstat(fd)
   mask=sum(1<<bit for bit in(0,1,3,4,6,7,18));self.assertEqual(base.capability_mask(value),mask)
   base.C=types.SimpleNamespace(Structure=ctypes.Structure,c_uint=ctypes.c_uint,c_int=ctypes.c_int,CDLL=lambda *a,**kw:(_ for _ in()).throw(ReachedBeforeMutation('before first prctl')))
   with self.assertRaises(ReachedBeforeMutation):base.reduce_capabilities(fixture_identity_map=value)
   state['release']='foreign'
   with self.assertRaises(ValueError):base.reduce_capabilities(fixture_identity_map=value)

# Keep the original ten controls and add these four real binding groups.
for _name,_method in vars(NumericPlatformControls).items():
 if _name.startswith('test_'):setattr(Controls,_name,_method)

def authentication_command_fixture(row,argv=None,save_fail=False):
 """Exact nested engine.command body and failure helper from emitted source."""
 import hashlib
 raw=P.transform(current('installer.py'),'installer.py');tree=ast.parse(raw)
 engine=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='engine')
 command=next(n for n in engine.body if isinstance(n,ast.FunctionDef)and n.name=='command')
 helper=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='authentication_failure_projection')
 calls=[];result={};saved=[]
 def run(args,**kw):calls.append((args,kw));return row
 def save(name,value):
  saved.append((name,copy.deepcopy(value)))
  if save_fail:raise OSError('SOURCE_FIXTURE_DIAGNOSTIC_WRITE_FAILURE')
 def need(ok,why):
  if not ok:raise ValueError(why)
 scope=dict(hashlib=hashlib,json=json,runner=types.SimpleNamespace(run=run),result=result,evidence=types.SimpleNamespace(save=save),p=types.SimpleNamespace(need=need))
 exec(compile(ast.Module(body=[helper,command],type_ignores=[]),'<ACTUAL_SELECTED_ENGINE_COMMAND>','exec'),scope)
 return scope,calls,result,saved

class AuthenticationControls(unittest.TestCase):
 def test_actual_authentication_caller_failure_preserves_error_and_original_bounds(self):
  import hashlib,base64
  argv=['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir','/PRIVATE_FIXTURE','--no-auto-key-retrieve','--import','/PINNED_PUBLIC_KEY']
  for raw in (b'',b'GPG_FAILURE_SOURCE_FIXTURE\n',b'x'*2048,b'x'*2049,b'x'*(1024**2)):
   scope,calls,result,saved=authentication_command_fixture(types.SimpleNamespace(returncode=2,stdout=raw))
   with self.assertRaisesRegex(ValueError,'^private authentication command failed$'):scope['command'](argv)
   self.assertEqual(calls,[(argv,dict(timeout=60,limit=1024**2))]);self.assertEqual(saved[0][0],'result.json');self.assertEqual(saved[0][1],result)
   row=result['authentication_failure_data'];self.assertEqual(row['output_bytes'],len(raw));self.assertEqual(row['output_sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(base64.b64decode(row['tail_base64']),raw[-2048:]);self.assertEqual(row['tail_complete'],len(raw)<=2048);self.assertEqual(row['argv_sha256'],hashlib.sha256(json.dumps(argv,separators=(',',':'),ensure_ascii=True).encode('ascii')).hexdigest());self.assertNotIn('argv',row);self.assertLess(len(C.enc(row)),4096);self.assertFalse(any(row[k]for k in('signature_authority','transaction_authority','cleanup_authority')))
 def test_actual_success_no_projection_and_write_failure_preserves_original_refusal(self):
  scope,calls,result,saved=authentication_command_fixture(types.SimpleNamespace(returncode=0,stdout=b'ORIGINAL_SUCCESS_BYTES'));self.assertEqual(scope['command'](['/usr/bin/gpg']),b'ORIGINAL_SUCCESS_BYTES');self.assertEqual(result,{});self.assertEqual(saved,[])
  scope,calls,result,saved=authentication_command_fixture(types.SimpleNamespace(returncode=2,stdout=b'FAIL'),save_fail=True)
  with self.assertRaisesRegex(ValueError,'^private authentication command failed$'):scope['command'](['/usr/bin/gpg'])
 def test_bad_shape_cannot_credit_failure_or_replace_original_error(self):
  for row in (types.SimpleNamespace(returncode=2,stdout=b'x'*(1024**2+1)),types.SimpleNamespace(returncode=2,stdout='foreign'),types.SimpleNamespace(returncode=True,stdout=b'x'),types.SimpleNamespace(returncode=-256,stdout=b'x')):
   scope,_,result,_=authentication_command_fixture(row)
   with self.assertRaisesRegex(ValueError,'^private authentication command failed$'):scope['command'](['/usr/bin/gpg'])
   self.assertEqual(result['authentication_failure_data']['status'],'REFUSED_DIAGNOSTIC_SHAPE')
 def test_complete_command_whole_installer_inverse_and_default_bytes_held(self):
  raw=current('installer.py');selected=P.transform(raw,'installer.py');self.assertEqual(P.engine_failure_inverse(selected).count(P.AUTH_COMMAND.encode()),1);self.assertIn(b'authentication_failure_projection',selected);self.assertNotIn(b'authentication_failure_projection',raw)
  scope,_,_,_=authentication_command_fixture(types.SimpleNamespace(returncode=1,stdout=b''))
  for argv in ([],['a']*33,['a'*4097],[False]):self.assertEqual(scope['authentication_failure_projection'](argv,types.SimpleNamespace(returncode=1,stdout=b''))['status'],'REFUSED_DIAGNOSTIC_SHAPE')
for _name,_method in vars(AuthenticationControls).items():
 if _name.startswith('test_'):setattr(Controls,_name,_method)


class ClockControls(unittest.TestCase):
 def clock_fixture(self):
  import os,stat
  from unittest.mock import patch
  context=dict(schema_version=1,purpose='SOURCE_OWNED_GENERIC16K_REALTIME_INIT_V1',source='1'*40,run_id='17',run_attempt='1')
  vm=code('source_clock_host',P.transform(current('run.py'),'run.py'));vm.FRESH607_CLOCK_CONTEXT=context
  fake=types.SimpleNamespace(time_ns=lambda:1_792_991_315_000_000_000);vm.time=fake
  c=dict(nonce='2'*32)
  with tempfile.TemporaryDirectory()as td:vm.fresh607_clock_contract(c,Path(td))
  fake.time_ns=lambda:c['fresh607_realtime']['created_realtime_ns']+5_000_000_000
  argv=vm.qemu_argv(Path('/kernel'),Path('/image'),c);return context,c,argv,vm
 def guest_call(self,context,c,commandline,bad_readback=False):
  import hashlib,time
  from unittest.mock import patch
  tree=ast.parse(P.transform(current('guest.py'),'guest.py'));node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='fresh607_initialize_realtime');calls=[];elapsed=2_000_000_000;state={}
  def setter(clock,value):self.assertEqual(clock,0);calls.append(value);state['realtime']=value
  fake=types.SimpleNamespace(CLOCK_REALTIME=0,monotonic_ns=lambda:elapsed,clock_settime_ns=setter,clock_gettime_ns=lambda _:(state['realtime']+(2_000_000_000 if bad_readback else 0)))
  def path(value):return types.SimpleNamespace(read_text=lambda:commandline)if str(value)=='/proc/cmdline'else Path(value)
  space=dict(FRESH607_CLOCK_CONTEXT=context,need=C.need,Path=path,hashlib=hashlib,json=json)
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<EXACT_SELECTED_GUEST_INERT_CLOCK_SETTER>','exec'),space)
  with patch.dict(sys.modules,{'time':fake}):space['fresh607_initialize_realtime'](c)
  return calls
 def test_actual_launch_host_time_and_guest_clock_readback_inert_setter(self):
  context,c,argv,vm=self.clock_fixture();cmdline=argv[argv.index('-append')+1];calls=self.guest_call(context,c,cmdline);self.assertEqual(calls,[c['fresh607_realtime']['created_realtime_ns']+7_000_000_000])
  old=code('source_clock_before',P.clock_inverse(P.transform(current('run.py'),'run.py'),'run.py'));prior=old.qemu_argv(Path('/kernel'),Path('/image'));expected=list(prior);expected[expected.index('-append')+1]+=vm.fresh607_clock_argument(c);self.assertEqual(argv,expected)
 def test_clock_foreign_replay_type_namespace_timestamp_and_readback_refuse(self):
  context,c,argv,_=self.clock_fixture();cmdline=argv[argv.index('-append')+1];variants=[]
  for field,value in(('nonce','3'*32),('source','4'*40),('run_id','18'),('run_attempt','2'),('workspace','/foreign'),('created_realtime_ns',True),('extra',None)):
   bad=copy.deepcopy(c);bad['fresh607_realtime'][field]=value;variants.append((bad,cmdline))
  stamp=str(c['fresh607_realtime']['created_realtime_ns']+5_000_000_000)
  for badline in(cmdline.replace(stamp,str(c['fresh607_realtime']['created_realtime_ns']-1)),cmdline.replace(stamp,str(c['fresh607_realtime']['created_realtime_ns']+9_600_000_000_001)),cmdline+' caa_fresh607_realtime_ns='+stamp,cmdline+' caa_fresh607_unknown=1',cmdline.replace('caa_fresh607_clock_sha256=','foreign_clock_sha256=')):
   variants.append((c,badline))
  for bad,badline in variants:
   with self.subTest(fields=bad['fresh607_realtime']),self.assertRaises(ValueError):self.guest_call(context,bad,badline)
  with self.assertRaisesRegex(ValueError,'readback'):self.guest_call(context,c,cmdline,bad_readback=True)
 def test_clock_actual_workflow_context_bound_literals_and_default4k_held(self):
  import os
  from unittest.mock import patch
  with patch.dict(os.environ,dict(FRESH_SOURCE='1'*40,GITHUB_RUN_ID='17',GITHUB_RUN_ATTEMPT='1'),clear=True):context=P.clock_context()
  for key,value in(('FRESH_SOURCE','foreign'),('GITHUB_RUN_ID','0'),('GITHUB_RUN_ATTEMPT','0')):
   env=dict(FRESH_SOURCE='1'*40,GITHUB_RUN_ID='17',GITHUB_RUN_ATTEMPT='1');env[key]=value
   with patch.dict(os.environ,env,clear=True),self.assertRaises(ValueError):P.clock_context()
  with patch.dict(os.environ,{},clear=True),self.assertRaises(ValueError):P.clock_context()
  for name in('run.py','guest.py'):
   raw=P.transform(current(name),name);bound=P.clock_bind(raw,name,context);self.assertEqual(P.clock_inverse(bound,name,context),P.clock_inverse(raw,name));self.assertEqual(code('bound_'+name.replace('.','_'),bound).FRESH607_CLOCK_CONTEXT,context)
  workflow=C.read(C.HERE/'workflow-template.yml');self.assertIn(b'FRESH_SOURCE: ${{ inputs.fresh_source_revision }}',workflow);self.assertIn(b'--fresh-source-revision "$FRESH_SOURCE"',workflow);self.assertIn(b'test "$CURRENT_CHILD_SOURCE" = "$CURRENT_WORKFLOW_SHA"',workflow);self.assertIn(b'CURRENT_CHILD_SOURCE: ${{ inputs.fresh_source_revision }}',workflow);self.assertIn(b'CURRENT_WORKFLOW_SHA: ${{ github.sha }}',workflow);self.assertIn(b'PYTHONDONTWRITEBYTECODE=1 "${clock_env[@]}"',workflow);self.assertIn(b'clock_env=(FRESH_SOURCE="$FRESH_SOURCE" GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT")',workflow)
  from run import Integration
  with tempfile.TemporaryDirectory()as td,patch.dict(os.environ,{},clear=True):
   output=Path(td)/'default4k';Integration(None,None,None,None).candidate(output)
   for n in adapter.NAMES:self.assertEqual(C.read(output/n),current(n))
 def test_clock_pinned_source_before_setter_original_auth_and_monotonic_caps_held(self):
  guest=P.transform(current('guest.py'),'guest.py').decode();self.assertLess(guest.index('    pinned_sources(c)\n'),guest.index('    fresh607_initialize_realtime(c)\n'));self.assertLess(guest.index('    fresh607_initialize_realtime(c)\n'),guest.index('        namespace_fd,lease_sha=numeric.bootstrap'))
  installer=P.transform(current('installer.py'),'installer.py');self.assertEqual(P.engine_failure_inverse(installer),current('installer.py').replace(b"os.uname().release=='7.2.10-1-aarch64-ARCH'",b"os.uname().release=='7.1.13-generic16k-managed-gui'").replace(b"os.sysconf('SC_PAGE_SIZE')==4096",b"os.sysconf('SC_PAGE_SIZE')==16384").replace(b'ordinary generic4K guest required',b'ordinary generic16K guest required').replace(b'details=base.Ptr(); alpm.ok(alpm.alpm_trans_prepare',b'details=roots.installer.Ptr(); alpm.ok(alpm.alpm_trans_prepare').replace(b'details=base.Ptr(); alpm.ok(alpm.alpm_trans_commit',b'details=roots.installer.Ptr(); alpm.ok(alpm.alpm_trans_commit'))
  self.assertIn(b"gpg=['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(keys),'--no-auto-key-retrieve']",installer)
  for n in adapter.NAMES:
   raw=P.transform(current(n),n);self.assertNotIn(b'--faked-system-time',raw);self.assertNotIn(b'--ignore-time-conflict',raw)
   if n in('run.py','guest.py'):raw=P.clock_inverse(raw,n)
   old=__import__('page_mode').engine_failure_inverse(raw)if n=='installer.py'else raw
   for a,b in reversed(P.edits()[n]):old=old.replace(b.encode(),a.encode(),1)
   self.assertEqual(old,current(n))
for _name,_method in vars(ClockControls).items():
 if _name.startswith('test_')or _name in('clock_fixture','guest_call'):setattr(Controls,_name,_method)

def test_exact_selected_engine_uses_alpm_origin_at_prepare_and_commit(self):
 import ctypes as CT
 for mode in('generic4k','generic16k'):
  with numeric_source_fixture(mode)as(installer,p,modules,profile,raw):
   roots,base,_,_=modules
   self.assertIs(roots.Alpm.__mro__[1],roots.installer.Alpm)
   self.assertIs(roots.installer.Alpm.__init__.__globals__['Ptr'],roots.installer.Ptr)
   self.assertIs(installer.engine.__globals__['C'],CT)
   if mode=='generic16k':
    self.assertIsNot(base.Ptr,roots.installer.Ptr);self.assertEqual(CT.sizeof(base.List),CT.sizeof(roots.installer.List))
   else:self.assertIs(base.Ptr,roots.installer.Ptr)
   calls=[]
   callback=CT.CFUNCTYPE(CT.c_int,CT.c_void_p,CT.POINTER(roots.installer.Ptr))(lambda handle,details:calls.append(handle)or 0)
   with self.assertRaises(CT.ArgumentError)if mode=='generic16k'else __import__('contextlib').nullcontext():callback(None,CT.byref(base.Ptr()))
   calls.clear();alpm=types.SimpleNamespace(handle=None,alpm_trans_prepare=callback,alpm_trans_commit=callback,ok=lambda value,label:self.assertEqual(value,0))
   tree=ast.parse(P.transform(current('installer.py'),'installer.py')if mode=='generic16k'else current('installer.py'));engine=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='engine');selected=[]
   for node in ast.walk(engine):
    if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='details'for t in node.targets):selected.append(node)
    elif isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and isinstance(node.value.func,ast.Attribute)and node.value.func.attr=='ok'and any(isinstance(q,ast.Attribute)and q.attr in('alpm_trans_prepare','alpm_trans_commit')for q in ast.walk(node)):selected.append(node)
   selected.sort(key=lambda n:n.lineno);self.assertEqual(len(selected),4)
   scope=dict(roots=roots,base=base,C=CT,alpm=alpm);exec(compile(ast.Module(body=selected,type_ignores=[]),'<ACTUAL_EMITTED_ENGINE_TYPED_PREPARE_COMMIT>','exec'),scope);self.assertEqual(calls,[None,None]);self.assertIs(type(scope['details']),roots.installer.Ptr)
   self.assertEqual(C.read(C.ROOT/'installer604/scripts/install/local_transaction.py'),raw)
Controls.test_exact_selected_engine_uses_alpm_origin_at_prepare_and_commit=test_exact_selected_engine_uses_alpm_origin_at_prepare_and_commit

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls);assert suite.countTestCases()==23;r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
