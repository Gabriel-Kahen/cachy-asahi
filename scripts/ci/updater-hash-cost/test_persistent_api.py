"""NEW DATA controls: actual emitted binder and disk preparation API seam only."""
import argparse,ast,contextlib,hashlib,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;F=D/'persistent-api';parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--support-root',type=Path);options,rest=parser.parse_known_args();SUPPORT=options.support_root or D.parents[2];NORMAL=None;ATTEMPTS=[]
contract=json.loads((F/'contract.json').read_bytes())
for n,p in contract['assets'].items():
 raw=(F/n).read_bytes()
 if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=p:raise ValueError('exact maintained operand '+n)

def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','pty.spawn'):
  ATTEMPTS.append(event);raise RuntimeError('DATA actor fence '+event)
sys.addaudithook(fence)
def need(ok,why):
 if not ok:raise ValueError(why)
def probe(*args,**kwargs):return args,kwargs
@contextlib.contextmanager
def parent(*args,**kwargs):yield None
def definitions(path,names,namespace):
 tree=ast.parse(path.read_bytes());nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names or isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id in names for x in n.targets)]
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<DATA_BINDING_DEFINITIONS>','exec'),namespace)
 return namespace
class Controls(unittest.TestCase):
 def setUp(self):
  global NORMAL
  self.scratch=tempfile.TemporaryDirectory(prefix='normal-persistent-api-data-');self.addCleanup(self.scratch.cleanup);NORMAL=Path(self.scratch.name)
  sources={'scripts/update/full_root.py':D/'frozen-full_root.py.txt',**{n:SUPPORT/n for n in ('scripts/update/measure_copy.py','scripts/update/root_path.py','scripts/install/local_transaction.py','scripts/ci/full-root-upgrade/root_upgrade.py')}}
  sources['scripts/update/full_root.py']=SUPPORT/'scripts/ci/updater-hash-cost/frozen-full_root.py.txt'
  for name,path in sources.items():target=NORMAL/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_bytes(path.read_bytes())
  self.installer=types.SimpleNamespace(__file__=str(NORMAL/'scripts/install/local_transaction.py'),relative=probe)
  self.roots=types.ModuleType('full_root');vars(self.roots).update(__file__=str(NORMAL/'scripts/update/full_root.py'),installer=self.installer,_mount_id=probe,observe=probe)
  self.copy=types.ModuleType('measure_copy');vars(self.copy).update(__file__=str(NORMAL/'scripts/update/measure_copy.py'),_parent=parent,_root_check=probe,_source_alias=probe,_copy_internal=probe,copy_data=probe)
  self.resolver=types.ModuleType('root_path');self.resolver.__file__=str(NORMAL/'scripts/update/root_path.py')
  self.driver=types.SimpleNamespace(__file__=str(NORMAL/'scripts/ci/full-root-upgrade/root_upgrade.py'),relative=probe,database=probe)
  util=types.SimpleNamespace(spec_from_file_location=lambda name,path:object(),module_from_spec=lambda spec:self.driver)
  class Spec:
   loader=types.SimpleNamespace(exec_module=lambda module:None)
  util.spec_from_file_location=lambda name,path:Spec()
  self.g=definitions(F/'normal-binder.py.txt',{'_NORMAL_PERSISTENT_API_PROFILE','normal_persistent_profile','need','_apis','persistent_apis'},dict(Path=Path,sys=sys,hashlib=hashlib,importlib=types.SimpleNamespace(util=util),_mount600=lambda fn:fn))
  self.scope=types.SimpleNamespace(_apis=self.g['_apis']);self.config=json.loads((F/'normal-config.json').read_bytes());self.loads=[]
  def load(name,path):self.loads.append((name,path));return self.scope
  self.C=types.SimpleNamespace(load=load,decode=json.loads,read=lambda path:json.dumps(self.config).encode(),need=need)
  self.d=definitions(F/'disk.py.txt',{'_NORMAL_PERSISTENT_API_PROFILE','disk_observation_profile','apis'},dict(C=self.C,Path=lambda p:NORMAL if p=='/upgrade-code'else Path(p)))
  self.modules=patch.dict(sys.modules,{'full_root':self.roots,'measure_copy':self.copy,'root_path':self.resolver});self.modules.start();self.addCleanup(self.modules.stop)
 def test_actual_disk_prepare_api_seam_accepts_exact_normal_v2(self):
  maintained=(D/'persistent_api.py').read_text();normal=(F/'normal-binder.py.txt').read_text();disk=(F/'disk.py.txt').read_text()
  def function(text,name):return ast.get_source_segment(text,next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name))
  self.assertEqual(function(maintained,'normal_persistent_profile'),function(normal,'normal_persistent_profile'));self.assertEqual(function(maintained,'disk_observation_profile'),function(disk,'disk_observation_profile'))
  cfg=json.loads((F/'normal-config.json').read_bytes());self.assertEqual(len(cfg['code_pins']),106);self.assertEqual(cfg['code_pins']['scripts/ci/full-root-upgrade-caller/persistent_scope.py'],hashlib.sha256((F/'normal-binder.py.txt').read_bytes()).hexdigest());self.assertEqual(cfg['external_pins']['/persistent_scope.py'],cfg['code_pins']['scripts/ci/full-root-upgrade-caller/persistent_scope.py'])
  scope,roots,copier,caps=self.d['apis']();self.assertIs(scope,self.scope);self.assertIsNot(roots,self.roots);self.assertIsNot(copier,self.copy);self.assertIsNone(caps);self.assertEqual(self.loads,[('scope','/persistent_scope.py')]);self.assertIs(self.roots.installer,self.installer);self.assertIsNot(roots.installer,self.installer);self.assertEqual(roots.installer.relative('usr/lib'),'usr/lib');self.assertIs(self.roots.observe,probe)
 def test_profile_mismatch_does_not_fall_back(self):
  with self.assertRaisesRegex(ValueError,'exact normal-v2 persistent'):
   self.g['persistent_apis'](self.roots,self.copy,self.resolver,None,observation_profile=('I16K_STATX_V1',(35970,'cece'),(35970,'cece')))
 def test_normal_disk_config_pin_mismatch_refuses_before_api(self):
  self.config['code_pins']['scripts/update/full_root.py']='0'*64
  with self.assertRaisesRegex(ValueError,'disk configuration/root'):self.d['apis']()
 def test_changed_raw_normal_root_refuses(self):
  original=Path.read_bytes;target=Path(self.roots.__file__)
  with patch.object(Path,'read_bytes',lambda p:original(p)+(b'\n'if p==target else b'')):
   with self.assertRaisesRegex(ValueError,'whole selected normal-v2'):self.d['apis']()
 def test_changed_copier_still_refuses(self):
  original=Path.read_bytes;target=Path(self.copy.__file__)
  with patch.object(Path,'read_bytes',lambda p:original(p)+(b'\n'if p==target else b'')):
   with self.assertRaisesRegex(ValueError,'whole persistent observation API source'):self.d['apis']()
 def test_shadowed_root_origin_still_refuses(self):
  self.roots.__file__='/tmp/unbound-full_root.py'
  with self.assertRaisesRegex(ValueError,'selected scope API origin'):self.d['apis']()
 def test_fault_route_forwards_original_api_shape_without_normal_profile(self):
  calls=[];sentinel=(self.roots,self.copy,self.resolver,None)
  self.scope._apis=lambda *a,**k:(calls.append((a,k))or sentinel)
  for case in('precommit-exit86','postcommit-exit87'):
   self.config=json.loads((F/(case+'-config.json')).read_bytes());self.d['apis']()
  self.assertEqual(calls,[((NORMAL,),{}),((NORMAL,),{})])
 def test_unknown_disk_context_cannot_fall_back(self):
  self.config['purpose']='unbound'
  with self.assertRaisesRegex(ValueError,'exact frozen fault-v1'):self.d['apis']()
 def test_mixed_fault_case_cannot_select_legacy_profile(self):
  self.config=json.loads((F/'precommit-exit86-config.json').read_bytes());self.config['failure']['case']='postcommit-exit87'
  with self.assertRaisesRegex(ValueError,'exact frozen fault-v1'):self.d['apis']()
 def test_original_inverse_is_exact_main_body(self):
  raw=(NORMAL/'scripts/update/full_root.py').read_bytes();text=(F/'normal-binder.py.txt').read_text();f=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='persistent_apis');held=next(n for n in f.body if isinstance(n,ast.FunctionDef)and n.name=='held');pairs=ast.literal_eval(next(n for n in ast.walk(held)if isinstance(n,ast.For)).iter)
  self.assertEqual(len(pairs),14)
  for added,old in pairs:self.assertEqual(raw.count(added),1);raw=raw.replace(added,old,1)
  self.assertEqual(raw.count(b'max_packages: int = 607'),1);raw=raw.replace(b'max_packages: int = 607',b'max_packages: int = 587',1)
  self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),self.g['_NORMAL_PERSISTENT_API_PROFILE'][2]);self.assertEqual(raw,(SUPPORT/'scripts/update/full_root.py').read_bytes())
 def tearDown(self):self.assertEqual(ATTEMPTS,[])
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest])
