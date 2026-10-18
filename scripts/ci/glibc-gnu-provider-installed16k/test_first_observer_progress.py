# SPDX-License-Identifier: MIT
"""Real original traversal through the normal progress installer; source controls only."""
import ast,gzip,hashlib,importlib.util,json,os,re,stat,sys,tempfile,threading,time,types,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'scripts/update/full_root.py').is_file())
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
O=load('first_observer_hooks',HERE/'observer_progress.py')
S=load('first_observer_journal',HERE/'snapshot_progress.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def scope(path,selection,module):
 raw=(HERE/'guest.py').read_text();nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and (n.name in ('progress_value','install_progress') or n.name.startswith('_copy_')) or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id.startswith('_COPY_') for t in n.targets)]
 # Host-user controls exercise the real writer; production uid0 guard is unchanged.
 C=types.SimpleNamespace(need=lambda ok,why:need(ok or why=='owned progress replacement',why),decode=json.loads,read=lambda *a:json.dumps(selection).encode(),ref=lambda root,row:ROOT/row['path'],load=lambda name,path:load(name,path) if name=='gnu_installed_fresh_mount_query' else module)
 result=dict(C=C,S=S,O=O,Path=Path,os=os,stat=stat,types=types,sys=sys,json=json,re=re,threading=threading,time=time,PHASES=('source-before','source-after'),PROGRESS=path)
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<normal-original-progress-installer>','exec'),result)
 original_copy=result['_copy_capability_bridge'];result['_copy_capability_bridge']=lambda bridge,source:original_copy(bridge,ROOT) # Test-only checkout root; fixed runtime /source argument is held.
 return result
class Controls(unittest.TestCase):
 def test_normal_installer_real_before_enter_then_inner_counts_and_complete_snapshot(self):
  roots=load('first_original_roots',ROOT/'scripts/update/full_root.py');caps=load('first_original_caps',ROOT/'scripts/apps/file_capabilities.py');bridge=load('first_original_bridge',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py');module=load('first_original_container',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/container.py')
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);tree=p/'tree';tree.mkdir();(tree/'sub').mkdir();data=b'original payload'*100000;(tree/'sub/file').write_bytes(data);os.link(tree/'sub/file',tree/'alias');(tree/'link').symlink_to('sub/file');out=p/'out';out.mkdir();module.OUT=out;selection=dict(nonce='a'*32,source_sha='b'*40);log=p/'progress.log';seen=[];scans=[]
   real=roots.os.scandir
   def scanned(fd):
    value=json.loads(log.read_bytes());seen.extend(value['records']);scans.append(fd);return real(fd)
   roots.os=types.SimpleNamespace(**dict(vars(os),scandir=scanned))
   api=dict(roots=roots,caps=caps,capabilities=bridge,capability_index=dict(source_capabilities={},source_capabilities_sha256=bridge.digest({})),capability_checks={});module.C.helpers=lambda *a:dict(api)
   env=scope(log,selection,module);env['install_progress']();actual=env['C'].load('guest_worker','/installed16k/container16k.py');instrumented=actual.C.helpers();value=actual.snapshot(instrumented,tree,'pristine-source-before')
   receipt=env['progress_value'](log.read_bytes(),selection);seen+=receipt['records'];observer=[r for r in seen if 'observer' in r]
   self.assertTrue(any(r['stage']=='observer' and r['edge']=='enter' and 'observer' not in r for r in seen));self.assertTrue(any(r['observer']['nodes']>0 for r in observer));self.assertEqual(len(scans),2)
   last=observer[-1]['observer'];self.assertEqual(last['operation'],'done');self.assertEqual(last['nodes'],4);self.assertEqual(last['declared_bytes'],2*len(data));self.assertEqual(last['hashed_bytes'],len(data));self.assertGreater(last['ticks'],0);self.assertGreater(last['mount_queries'],0)
   retained=json.loads(gzip.decompress((out/'pristine-source-before-root.json.gz').read_bytes()));self.assertEqual(retained['nodes'],value['nodes']);self.assertEqual(retained['security_capabilities'],{});self.assertEqual(len(retained['hardlink_groups']),1);self.assertEqual(retained['nodes']['sub/file']['sha256'],hashlib.sha256(data).hexdigest());self.assertEqual(instrumented['roots'].Limits,roots.Limits)
   self.assertLessEqual(len(log.read_bytes()),65536);self.assertNotIn(str(tree),json.dumps(observer))
   last_sequence=receipt['records'][-1]['sequence'];second=actual.snapshot(instrumented,tree,'pristine-source-after')
   later=env['progress_value'](log.read_bytes(),selection);new=[r for r in later['records'] if r['sequence']>last_sequence]
   self.assertTrue(new);self.assertFalse(any('observer' in r for r in new));self.assertEqual(second['nodes'],value['nodes']);self.assertEqual(second['security_capabilities'],value['security_capabilities'])
   self.assertIn('pristine-source-after',instrumented['capability_checks']);self.assertTrue((out/'pristine-source-after-root.json.gz').is_file())
 def test_real_read_stall_keeps_current_seam_and_original_supervisor_retires(self):
  runner=load('first_original_supervisor',ROOT/'scripts/ci/glibc-owned-runtime/runner.py')
  code="""import importlib.util,json,os,sys,time,types
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
base=Path(sys.argv[1]);tree=Path(sys.argv[2]);O=load('child_inner',base/'scripts/ci/glibc-gnu-provider-installed16k/observer_progress.py');S=load('child_journal',base/'scripts/ci/glibc-gnu-provider-installed16k/snapshot_progress.py');R=load('child_roots',base/'scripts/update/full_root.py');journal=S.Journal(dict(nonce='a'*32,source_sha='b'*40));log=Path(sys.argv[3]);original=os.read;calls=0
def stalled(*args):
 global calls
 calls+=1
 if calls==2:time.sleep(30)
 return original(*args)
R.os=types.SimpleNamespace(**dict(vars(os),read=stalled))
def retain(metrics):log.write_bytes(journal.push('observer','sample',dict(case='pristine',phase='source-before'),metrics))
O.facade(R,retain).observe(tree,limits=R.Limits(deadline=time.monotonic()+600),hardlinks='generic-development-internal')
"""
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);tree=p/'tree';tree.mkdir();(tree/'file').write_bytes(b'actual original read');log=p/'progress.json';row,out,err,error=runner.run_command([sys.executable,'-I','-B','-c',code,ROOT,tree,log],p,dict(os.environ),6,65536)
   self.assertEqual(str(error),'command-time-limit');self.assertTrue(row['group_absence_verified']);self.assertNotEqual(row['exit_code'],0);self.assertEqual(out+err,b'');v=json.loads(log.read_bytes());last=v['records'][-1]['observer'];self.assertEqual((last['operation'],last['edge']),('file-read','enter'));self.assertEqual(last['nodes'],1);self.assertEqual(last['reads'],1);self.assertEqual(last['hashed_bytes'],20);self.assertGreaterEqual(last['elapsed_ms'],5000)
 def test_normal_duration_counter_simulation_coalesces_and_preserves_terminal_rows(self):
  selection=dict(nonce='a'*32,source_sha='b'*40);j=S.Journal(selection);env=scope(Path('/unused'),selection,None);context=dict(case='pristine',phase='source-before');metrics=dict(operation='file-read',edge='enter',elapsed_ms=0,**dict.fromkeys(O.COUNTERS,0))
  j.push('observer','enter',context)
  for n in range(2200):
   raw=j.push('observer','sample',context,dict(metrics,elapsed_ms=n*5000,nodes=n,hashed_bytes=n*1024));v=env['progress_value'](raw,selection)
  self.assertEqual(len(v['records']),2);self.assertEqual(v['omitted_records'],2199);self.assertEqual(v['records'][-1]['observer']['elapsed_ms'],10995000)
  for n in range(700):raw=j.push('observer','enter' if n%2 else 'leave',context)
  raw=j.push('lifecycle','leave',dict(case='none',phase='none'));v=env['progress_value'](raw,selection);self.assertLessEqual(len(raw),65536);self.assertLessEqual(len(v['records']),256);self.assertEqual(v['records'][-1]['stage'],'lifecycle');self.assertGreater(v['omitted_records'],2200)
  bad=json.loads(j.push('observer','sample',context,dict(metrics,operation='/private/path')))
  with self.assertRaises(ValueError):env['progress_value'](json.dumps(bad).encode(),selection)
 def test_hook_failure_never_changes_original_observation_or_deadline_refusal(self):
  roots=load('first_refusal_roots',ROOT/'scripts/update/full_root.py')
  def broken(*args):raise OSError('diagnostic sink')
  api=O.facade(roots,broken)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);os.mkfifo(p/'unsupported');a=roots.observe(p,limits=roots.Limits(deadline=time.monotonic()+5));b=api.observe(p,limits=roots.Limits(deadline=time.monotonic()+5));self.assertEqual(a['nodes'],b['nodes']);self.assertEqual(a['unsupported_counts'],b['unsupported_counts']);self.assertFalse(b['eligible'])
   for subject in (roots,api):
    with self.assertRaisesRegex(ValueError,'root observation deadline'):subject.observe(p,limits=roots.Limits(deadline=time.monotonic()-1))

from unittest.mock import patch
import shutil
sys.path.insert(0,str(ROOT/'scripts/update'))
import full_root as _copy_test_roots
import measure_copy as _copy_test_measure
import aux_copy as A

def _copy_test_clone(function,**replace):
 namespace=dict(function.__globals__,**replace);value=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__);value.__kwdefaults__=function.__kwdefaults__;return value

def _copy_test_helpers():
 raw=(HERE/'guest.py').read_text();tree=ast.parse(raw)
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name.startswith('_copy_') or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id.startswith('_COPY_') for t in n.targets)]
 namespace={'types':types};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<source-owned-copy-routing>','exec'),namespace)
 return types.SimpleNamespace(scoped_aux=namespace['_copy_scoped_aux'],capability_bridge=namespace['_copy_capability_bridge'])
B=_copy_test_helpers()
def _copy_test_candidate():
 query=load('copy_test_fresh_query',ROOT/'scripts/ci/expanded600-installer-vm/observer600.py')._mount600(_copy_test_roots._mount_id)
 roots=types.SimpleNamespace(**vars(_copy_test_roots));roots._mount_id=query;roots.observe=_copy_test_clone(_copy_test_roots.observe,_mount_id=query)
 module=types.ModuleType('copy_test_private');module.__file__=_copy_test_measure.__file__;exec(compile(Path(module.__file__).read_bytes(),module.__file__,'exec'),module.__dict__);module.roots=roots;return module

def _copy_test_strip(report):
 value=json.loads(json.dumps(report));fp=value['footprint']
 for key in ('filesystem_free_bytes','filesystem_free_inodes'):fp.pop(key,None)
 return value
P=types.SimpleNamespace(R=_copy_test_roots,M=_copy_test_measure,SOURCE=ROOT,load=load,clone=_copy_test_clone,candidate=_copy_test_candidate,strip=_copy_test_strip)

class CopyMountControls(unittest.TestCase):
 def setUp(self):
  temporary=tempfile.TemporaryDirectory(prefix='copy-mount-check-');self.addCleanup(temporary.cleanup);self.base=Path(temporary.name)
  self.source=self.base/'source';self.source.mkdir();(self.source/'a').mkdir();(self.source/'a/file').write_bytes(b'whole bounded content')
  os.link(self.source/'a/file',self.source/'alias');(self.source/'link').symlink_to('a/file')
 def limits(self):return P.R.Limits(deadline=time.monotonic()+30,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)
 def test_actual_copy_full_report_and_logical_mount_queries_equal(self):
  reports=[];traces=[]
  for role,m in [('old',P.M),('fresh',P.candidate())]:
   original=m.roots._mount_id;trace=[]
   def query(fd,limits):
    answer=original(fd,limits);trace.append(answer);return answer
   roots=types.SimpleNamespace(**vars(m.roots));roots._mount_id=query
   roots.observe=P.clone(m.roots.observe,_mount_id=query)
   body=types.ModuleType('trace_copy');exec(compile(Path(P.M.__file__).read_bytes(),P.M.__file__,'exec'),body.__dict__);body.roots=roots
   reports.append(P.strip(body.copy_data(self.source,self.base/role,limits=self.limits(),hardlinks='generic-development-internal')));traces.append(trace)
  self.assertEqual(reports[0],reports[1]);self.assertEqual(traces[0],traces[1]);self.assertGreater(len(traces[0]),20)
 def test_real_mount_crossing_refused_by_parent(self):
  m=P.candidate();fd=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY)
  try:
   with self.assertRaisesRegex(ValueError,'copy mount crossing'):
    with m._parent(fd,'self/status',m.roots._mount_id(fd,self.limits())+1,{},self.limits()):pass
  finally:os.close(fd)
 def test_real_component_symlink_refused(self):
  m=P.candidate();(self.source/'alias-dir').symlink_to('a');fd=os.open(self.source,os.O_RDONLY|os.O_DIRECTORY)
  try:
   with self.assertRaises(OSError):
    with m._parent(fd,'alias-dir/file',m.roots._mount_id(fd,self.limits()),{},self.limits()):pass
  finally:os.close(fd)
 def test_expired_original_limit_still_refuses(self):
  m=P.candidate();limits=P.R.Limits(deadline=time.monotonic()-1)
  with self.assertRaisesRegex(ValueError,'root observation deadline'):
   m.copy_data(self.source,self.base/'out',limits=limits,hardlinks='generic-development-internal')
  self.assertFalse((self.base/'out').exists())
 def test_source_pinned_composition_routes_aux_closure_without_global_mutation(self):
  before=A.roots._mount_id;value,roots=B.scoped_aux(A,P.SOURCE);m=value._copy_binding(self.limits())
  self.assertIs(A.roots._mount_id,before);self.assertIs(m.roots._mount_id,roots._mount_id)
  cells=dict(zip(m.roots.observe.__code__.co_freevars,(c.cell_contents for c in m.roots.observe.__closure__ or ())))
  self.assertIs(m.roots.observe.__globals__['roots'],roots)
  self.assertEqual(roots.observe.__code__.co_code,P.R.observe.__code__.co_code)
  self.assertEqual(value._copy_binding.__code__.co_code,A._copy_binding.__code__.co_code)
  self.assertIs(value.measure_copy,A.measure_copy);self.assertIs(value.aux,A.aux);self.assertIs(value.links,A.links)
 def test_original_capability_copy_cleanup_and_scope_receipts_byte_held(self):
  bridge=P.load('old_capability_bridge',P.SOURCE/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py')
  result=B.capability_bridge(bridge,P.SOURCE)
  self.assertEqual(result.copied_root.__wrapped__.__code__,bridge.copied_root.__wrapped__.__code__)
  private=result.copied_root.__wrapped__.__globals__['scope']
  self.assertEqual(private.copied_root.__code__,bridge.scope.copied_root.__code__)
  self.assertIs(private.receipt,bridge.scope.receipt)
  derived=private.copied_root.__globals__['qualified']()
  old=bridge.scope.qualified()
  self.assertEqual(derived.copy_data.__code__,old.copy_data.__code__)
  self.assertEqual(derived.gnu_proof_sha256,old.gnu_proof_sha256)
  self.assertIsNot(derived.aux_copy,bridge.scope.aux_copy)
  self.assertIs(derived.aux_copy.measure_copy,bridge.scope.aux_copy.measure_copy)
  self.assertIs(derived.aux_copy.aux,bridge.scope.aux_copy.aux)
  self.assertIs(result.binding,bridge.binding);self.assertIs(result.disjoint,bridge.disjoint)
 def test_changed_whole_root_source_refused_before_compile(self):
  root=self.base/'tamper';path=root/'scripts/update/full_root.py';path.parent.mkdir(parents=True);path.write_bytes(Path(P.R.__file__).read_bytes()+b'\n')
  with self.assertRaisesRegex(ValueError,'copier-source-pin-or-drift'):B.scoped_aux(A,root)
 def test_exact_proposed_guest_facade_runs_same_source_pinned_composition(self):
  import ast
  raw=(HERE/'guest.py').read_text()
  tree=ast.parse(raw);names={'_COPY_ROOT_SHA','_COPY_AUX_SHA','_COPY_QUERY_SHA'}
  nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name.startswith('_copy_')or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in names for t in n.targets)]
  namespace={'types':types};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-proposed-guest>','exec'),namespace)
  bridge=P.load('proposed_capability_bridge',P.SOURCE/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py')
  value=namespace['_copy_capability_bridge'](bridge,P.SOURCE)
  private=value.copied_root.__wrapped__.__globals__['scope']
  derived=private.copied_root.__globals__['qualified']()
  binding=derived.aux_copy._copy_binding(self.limits())
  self.assertIs(binding.roots.observe.__globals__['roots']._mount_id,binding.roots._mount_id)
  self.assertEqual(value.copied_root.__wrapped__.__code__,bridge.copied_root.__wrapped__.__code__)
 def test_original_copy_and_guard_functions_byte_held(self):
  m=P.candidate()
  for name in ('_parent','_copy_internal','_root_check','copy_data','_source_alias','_metadata_equal','_descriptors','_write'):
   a,b=getattr(P.M,name),getattr(m,name);self.assertEqual(a.__code__.co_code,b.__code__.co_code);self.assertEqual(a.__code__.co_consts,b.__code__.co_consts)
  self.assertEqual(P.R.observe.__code__,m.roots.observe.__code__)


if __name__=='__main__':unittest.main(verbosity=2)
