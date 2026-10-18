# SPDX-License-Identifier: MIT
import ast,copy,hashlib,importlib.util,json,os,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('diagnostic_protocol_controls',HERE/'protocol.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Codec:
 @staticmethod
 def decode(raw):
  def pairs(rows):
   value={}
   for key,v in rows:
    if key in value:raise ValueError('duplicate JSON')
    value[key]=v
   return value
  return json.loads(raw,object_pairs_hook=pairs)
def fixture():
 s=dict(nonce='a'*32,source_sha='b'*40,kernel=dict(release='actual-test-kernel'),kernel_profile_sha256='c'*64,source_nodes_sha256='d'*64,capabilities_sha256='e'*64,diagnostic_route=P.ROUTE)
 pin=dict(bytes=1,sha256='f'*64)
 subject=dict(status=P.STATUS,acceptance=P.FORBIDDEN,source_sha=s['source_sha'],nonce=s['nonce'],page_size=16384,source_nodes_sha256=s['source_nodes_sha256'],complete=True,nodes=4,capabilities='NOT_RUN_STOPPED_BEFORE_CAPABILITY_OBSERVER',stop='AFTER_FIRST_ROOTS_OBSERVE_BEFORE_CAPS_CLONE_ALPM',normal_subject='UNCHANGED_NORMAL_G_WORKER_MAIN',normal_failure=dict(exit_code=1,status='FAIL',error_type='FirstObserverComplete',error='DIAGNOSTIC_STOP_AFTER_FIRST_OBSERVER_BEFORE_CAPABILITIES'),ALPM='NOT_RUN',normal_lifecycle='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
 boot=dict(event='boot',page_size=16384,kernel=s['kernel']['release'],architecture='aarch64',kernel_profile_sha256=s['kernel_profile_sha256'],diagnostic_route=P.ROUTE,observer_nofile=dict(before=[1024,1048576],after=[8192,8192],scope='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD'))
 result=dict(event='result',subject=subject,isolation=dict(status='PASS_OBSERVED_NATIVE_CAPS_AND_MOUNT_FENCE',filter_sha256='0'*64,held_capability_helper='UNCHANGED_REDUCE_CAPABILITIES_BODY_WITH_EXPLICIT_GNU_MASK',held_ipc_helper='UNCHANGED_AARCH64_BLOCK_SERVICE_IPC',mask=2149843195,no_new_privs=1,seccomp=2,raw_block_devices=[],writable_source_alias=False,mount_flags=[15,4096]),files={name:dict(pin) for name in P.FILES},bytes=3,acceptance=P.FORBIDDEN,supervisor=dict(exit_code=0,group_absence_verified=True,time_limit=600))
 exit=dict(event='exit',status=P.DONE,cleanup='PASS_OWNED_CLONES_REMOVED',acceptance=P.FORBIDDEN)
 return s,[boot,result,exit]
def uart(s,events):return b'kernel console\n'+b'\n'.join((P.PREFIX+' '+s['nonce']+' '+json.dumps(e,separators=(',',':'))).encode() for e in events)+b'\n'
class Controls(unittest.TestCase):
 def test_real_original_main_first_run_case_walk_then_explicit_stop_before_caps_or_clone(self):
  import tempfile,time,types
  root=next(p for p in HERE.parents if (p/'scripts/update/full_root.py').is_file())
  def load(name,path):
   spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
  roots=load('diagnostic_real_roots',root/'scripts/update/full_root.py');hooks=load('diagnostic_real_hooks',HERE/'observer_progress.py');module=load('diagnostic_real_normal',root/'scripts/ci/glibc-gnu-provider-lifecycle/container.py');bridge=load('diagnostic_real_bridge',root/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py')
  raw=(HERE/'source_diagnostic.py').read_text();nodes=[n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ('intercept','FirstObserverComplete')]
  def need(ok,why):
   if not ok:raise ValueError(why)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);tree=p/'held';tree.mkdir();(tree/'sub').mkdir();data=b'genuine first observer bytes';(tree/'sub/file').write_bytes(data);work=p/'work';work.mkdir();out=p/'out';out.mkdir();rows=[];capcalls=[]
   before=roots.observe(tree,limits=roots.Limits(deadline=time.monotonic()+5),hardlinks='generic-development-internal');digest=hashlib.sha256(json.dumps(before['nodes'],sort_keys=True).encode()).hexdigest();index=dict(source_nodes_sha256=digest,source_capabilities={},source_capabilities_sha256=bridge.digest({}));api=dict(roots=hooks.facade(roots,rows.append),capabilities=bridge,caps=types.SimpleNamespace(observe=lambda *a:capcalls.append(a)),proc_probe=types.SimpleNamespace(check=lambda *a:dict(status='PASS_READONLY_PROC_PREFLIGHT',cleanup='PASS_OWNED_EMPTY_PROBE_REMOVED')))
   # Fixture paths/guard/configuration replace unavailable native authority only.
   # Original main/run_case/snapshot and full_root traversal bodies execute intact.
   def path(value):return tree if str(value)=='/held' else out/'result.json' if str(value)=='/out/result.json' else Path(value)
   C=types.SimpleNamespace(need=need,sha=lambda d:hashlib.sha256(d).hexdigest(),read=lambda name,*a:path(name).read_bytes(),decode=json.loads,load=lambda *a:module,configuration=lambda *a:(index,{},dict(nodes={}),dict(nodes={})),helpers=lambda *a:dict(api),CASES=('pristine','modified'))
   module.C=C;module.HELD=tree;module.WORK=work;module.OUT=out;module.guard=lambda:None;module.os=types.SimpleNamespace(**dict(vars(os),chown=lambda *a:None,environ=dict(INPUT_INDEX_SHA256='fixture',OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid()))))
   namespace=dict(Path=path,json=json,G=types.SimpleNamespace(types=types));exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-diagnostic-interception>','exec'),namespace);state=namespace['intercept'](C,dict(source_nodes_sha256=digest))
   with self.assertRaises(namespace['FirstObserverComplete']):C.load('guest_worker','/installed16k/container16k.py').main()
   self.assertEqual(state['observations'],1);self.assertEqual(state['completed']['nodes'],2);self.assertEqual(state['normal_failure']['exit_code'],1);self.assertEqual(state['normal_failure']['status'],'FAIL');self.assertEqual(rows[-1]['hashed_bytes'],len(data));self.assertEqual(rows[-1]['operation'],'done');self.assertEqual(capcalls,[]);self.assertEqual(list(work.iterdir()),[]);self.assertEqual({x.name for x in out.iterdir()},{'result.json'});self.assertNotEqual(json.loads((out/'result.json').read_bytes())['status'],'PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE')
 def test_complete_diagnostic_only_protocol(self):
  s,e=fixture();self.assertEqual(P.protocol(Codec,uart(s,e),s),e[1]);self.assertNotIn('PASS',e[1]['subject']['status']);self.assertNotIn('LIFECYCLE_AND_RECOVERY',P.DONE)
 def test_hostile_subject_and_authority_are_rejected(self):
  mutations=[lambda e:e[1]['subject'].update(status='PASS_DEBIAN_MAINTAINED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY'),lambda e:e[1]['subject'].update(ALPM='PASS'),lambda e:e[1]['subject'].update(complete=False),lambda e:e[1]['subject'].update(capabilities='PASS'),lambda e:e[1]['subject'].update(extra_map={}),lambda e:e[1]['supervisor'].update(group_absence_verified=False),lambda e:e[1]['supervisor'].update(time_limit=10800),lambda e:e[1]['supervisor'].update(exit_code=True),lambda e:e[1]['files'].update({'pristine-source-before-root.json.gz':dict(bytes=1,sha256='f'*64)}),lambda e:e[1]['files']['result.json'].update(bytes=65537),lambda e:e[1]['isolation'].update(writable_source_alias=True),lambda e:e[0].update(diagnostic_route='NORMAL'),lambda e:e[2].update(acceptance='ADMITTED')]
  for mutate in mutations:
   with self.subTest(mutation=mutate):
    s,e=fixture();mutate(e)
    with self.assertRaises(ValueError):P.protocol(Codec,uart(s,e),s)
 def test_partial_wrong_nonce_and_unknown_event_refused(self):
  s,e=fixture()
  for raw in (uart(s,e[:2]),uart(s,e+[e[-1]]),uart(dict(s,nonce='0'*32),e),uart(s,e)+b'GNU_INSTALLED16K foreign receipt\n'):
   with self.assertRaises(ValueError):P.protocol(Codec,raw,s)
 def test_source_subject_enters_unchanged_normal_worker_and_explicit_stop(self):
  raw=(HERE/'source_diagnostic.py').read_text();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='child');calls={ast.unparse(n.func) for n in ast.walk(node) if isinstance(n,ast.Call)}
  self.assertIn('G.worker',calls);self.assertIn('G.install_progress',calls);self.assertFalse({'native.snapshot','native.main','native.run_case','native.transaction','native.smoke','native.copy_probes','sandbox.apply'}&calls)
  self.assertIn(',600,512*1024)',raw);self.assertIn('value=observe(root,**options)',raw);self.assertIn("raise FirstObserverComplete('DIAGNOSTIC_STOP_AFTER_FIRST_OBSERVER_BEFORE_CAPABILITIES')",raw)
 def test_assembled_real_source_and_boot_selection_export_path(self):
  folder=os.environ.get('CAA_SOURCE_DIAGNOSTIC_VM') or os.environ.get('VM_SOURCE');self.assertTrue(folder,'explicit assembled source required');root=Path(folder);target=root/'scripts/ci/glibc-debian-maintained-source-observer16k';normal=root/'scripts/ci/glibc-debian-maintained-installed16k'
  for name in ('sandbox.py','adapter.py','support.py'):self.assertEqual((target/name).read_bytes(),(normal/name).read_bytes())
  self.assertIn(',10500,512*1024)',(normal/'guest.py').read_text());self.assertIn('seconds=10800,cap=16*1024**2',(normal/'run.py').read_text())
  run=(target/'run.py').read_text();prepare=(target/'prepare.py').read_text();self.assertIn('seconds=900,cap=16*1024**2',run);self.assertIn('caa_gnu_source_observer_only=1',run);self.assertIn('diagnostic_route=',run);self.assertIn('exec /usr/bin/python3 -I -B /debian-maintained-source-observer16k/diagnostic_boot.py',prepare)
  self.assertIn("'observer_progress.py','source_diagnostic.py','diagnostic_boot.py','protocol.py'",prepare);self.assertIn("row['time_limit']==900",(target/'export.py').read_text());self.assertIn('fixed bounded diagnostic export manifest',(target/'export.py').read_text())
  for table in ('dependencies.json','source-manifest.json'):
   value=json.loads((target/table).read_bytes())
   for name,row in value['files'].items():
    raw=(root/name).read_bytes();self.assertEqual(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),row)
 def test_original_pid1_mount_retirement_and_poweroff_bodies_preserved(self):
  root=next(p for p in HERE.parents if (p/'scripts/ci/glibc-gnu-provider-installed16k/guest.py').is_file())
  original=ast.parse((root/'scripts/ci/glibc-gnu-provider-installed16k/guest.py').read_text());adapted=ast.parse((HERE/'diagnostic_boot.py').read_text())
  def cleanup(tree):return next(n for n in ast.walk(tree) if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='point')
  self.assertEqual(ast.dump(cleanup(original)),ast.dump(cleanup(adapted)))
  def poweroff(tree):return next(n.finalbody for n in ast.walk(tree) if isinstance(n,ast.Try) and any(isinstance(x,ast.Raise) and 'guest poweroff failed' in ast.unparse(x) for x in n.finalbody))
  self.assertEqual([ast.dump(n) for n in poweroff(original)],[ast.dump(n) for n in poweroff(adapted)])
if __name__=='__main__':unittest.main(verbosity=2)
