# SPDX-License-Identifier: MIT
"""Real small-tree original capability/snapshot controls; no ALPM or actors."""
import ast,gzip,hashlib,importlib.util,json,os,sys,tempfile,time,types,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'scripts/update/full_root.py').is_file())
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
S=load('postwalk_progress',HERE/'snapshot_progress.py')
class Controls(unittest.TestCase):
 def test_real_capability_original_maps_hardlinks_and_readonly_counts(self):
  caps=load('original_caps_control',ROOT/'scripts/apps/file_capabilities.py');roots=load('original_roots_control',ROOT/'scripts/update/full_root.py');rows=[]
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);(p/'sub').mkdir();(p/'sub/file').write_bytes(b'actual source bytes');os.link(p/'sub/file',p/'alias');(p/'relative').symlink_to('sub/file');limits=roots.Limits(deadline=time.monotonic()+10);nodes=roots.observe(p,limits=limits,hardlinks='generic-development-internal')['nodes'];original=caps.observe(p,nodes,limits);instrumented=S.capability_facade(caps,lambda *r:rows.append(r)).observe(p,nodes,limits)
   self.assertEqual(original,instrumented);self.assertEqual(original,{});last=rows[-1][2];self.assertEqual(last['walk_nodes'],4);self.assertEqual(last['recheck_nodes'],4);self.assertEqual(last['graph_nodes'],4);self.assertGreater(last['mount_queries'],0);self.assertGreater(last['attribute_queries'],0);self.assertEqual(last['hashed_bytes'],0);self.assertEqual(last['operation'],'capability');self.assertLess(len(json.dumps(rows)),65536);self.assertNotIn(str(p),json.dumps(rows))
 def test_real_original_capability_refusal_remains_and_broken_sink_does_not_change_it(self):
  caps=load('original_caps_refusal',ROOT/'scripts/apps/file_capabilities.py');roots=load('original_roots_refusal',ROOT/'scripts/update/full_root.py')
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);(p/'file').write_bytes(b'actual');limits=roots.Limits(deadline=time.monotonic()+10);nodes=roots.observe(p,limits=limits)['nodes'];nodes['file']['bytes']+=1
   def broken(*args):raise OSError('inert sink failure')
   for api in (caps,S.capability_facade(caps,broken)):
    with self.assertRaisesRegex(ValueError,'pinned file size differs'):api.observe(p,nodes,limits)
 def test_original_snapshot_complete_maps_and_serialization_hooks(self):
  raw=(ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/container.py').read_text();nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in ('limits','snapshot')]
  roots=load('original_snapshot_roots',ROOT/'scripts/update/full_root.py');caps=load('original_snapshot_caps',ROOT/'scripts/apps/file_capabilities.py');bridge=load('original_snapshot_bridge',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py');rows=[]
  def need(ok,why):
   if not ok:raise ValueError(why)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);tree=p/'tree';tree.mkdir();(tree/'file').write_bytes(b'original complete bytes');out=p/'out';out.mkdir();scope=dict(time=time,gzip=gzip,json=json,OUT=out,C=types.SimpleNamespace(need=need));exec(compile(ast.Module(body=nodes,type_ignores=[]),'<original-snapshot-control>','exec'),scope)
   # S.snapshot reads the actual original source module but preserves its globals.
   module=load('original_snapshot_subject',ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/container.py');module.OUT=out
   api=dict(roots=roots,caps=S.capability_facade(caps,lambda *r:rows.append(r)),capabilities=bridge,capability_index=dict(source_capabilities={},source_capabilities_sha256=bridge.digest({})),capability_checks={})
   value=S.snapshot(module,lambda *r:rows.append(r))(api,tree,'pristine-source-before');retained=json.loads(gzip.decompress((out/'pristine-source-before-root.json.gz').read_bytes()));self.assertEqual(retained['nodes'],value['nodes']);self.assertEqual(retained['security_capabilities'],{});self.assertEqual(retained['nodes']['file']['sha256'],hashlib.sha256(b'original complete bytes').hexdigest());operations=[r[2]['operation'] for r in rows];self.assertTrue({'capability','graph','walk','recheck','rebind','json','gzip','snapshot-write'}<=set(operations));self.assertGreater(rows[-1][2]['json_bytes'],0);self.assertGreater(rows[-1][2]['compressed_bytes'],0)
 def test_shape_and_exact_source_refusals(self):
  caps=load('cap_source_refusal',ROOT/'scripts/apps/file_capabilities.py');caps.__file__=str(HERE/'test_snapshot_progress.py')
  with self.assertRaisesRegex(ValueError,'exact original capability'):S.capability_facade(caps,lambda *r:None)
  v=dict(operation='walk',elapsed_ms=0,**dict.fromkeys(S.COUNTERS,0));S.validate(v)
  for key,value in (('operation','private/path'),('walk_nodes',True),('hashed_bytes',-1)):
   with self.assertRaises(ValueError):S.validate(dict(v,**{key:value}))
 def test_real_attribute_stall_has_bounded_progress_and_original_supervisor_retires(self):
  runner=load('postwalk_original_supervisor',ROOT/'scripts/ci/glibc-owned-runtime/runner.py')
  code="""import importlib.util,json,os,sys,time
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
base=Path(sys.argv[1]);tree=Path(sys.argv[2]);S=load('postwalk_child_progress',base/'scripts/ci/glibc-gnu-provider-installed16k/snapshot_progress.py');roots=load('postwalk_child_roots',base/'scripts/update/full_root.py');caps=load('postwalk_child_caps',base/'scripts/apps/file_capabilities.py');limits=roots.Limits(deadline=time.monotonic()+30);nodes=roots.observe(tree,limits=limits)['nodes'];original=os.listxattr;calls=0
api=S.capability_facade(caps,lambda stage,edge,metrics:print(json.dumps(dict(stage=stage,edge=edge,metrics=metrics)),flush=True))
def blocked(*args,**kwargs):
 global calls
 calls+=1
 if calls==2:time.sleep(30)
 return original(*args,**kwargs)
os.listxattr=blocked
api.observe(tree,nodes,limits)
"""
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);tree=p/'tree';tree.mkdir();(tree/'file').write_bytes(b'actual attribute stall');subject=p/'subject.py';subject.write_text(code);row,out,err,failure=runner.run_command([sys.executable,'-I','-B',subject,ROOT,tree],p,dict(os.environ),6,65536)
   self.assertEqual(str(failure),'command-time-limit');self.assertTrue(row['group_absence_verified']);self.assertNotEqual(row['exit_code'],0);self.assertLess(row['seconds'],8);self.assertEqual(err,b'');records=[json.loads(line) for line in out.splitlines()];samples=[r for r in records if r['edge']=='sample'];self.assertTrue(samples);self.assertEqual(samples[-1]['metrics']['operation'],'walk');self.assertEqual(samples[-1]['metrics']['attribute_queries'],2);self.assertLessEqual(row['stdout_bytes'],65536)
 def test_normal_budget_simulated_samples_and_boundaries_saturate_without_stopping(self):
  selection=dict(nonce='a'*32,source_sha='b'*40);journal=S.Journal(selection);context=dict(case='pristine',phase='source-before');metrics=dict(operation='walk',elapsed_ms=0,**dict.fromkeys(S.COUNTERS,0))
  raw=(HERE/'guest.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='progress_value')
  def need(ok,why):
   if not ok:raise ValueError(why)
  scope=dict(C=types.SimpleNamespace(need=need,decode=json.loads),S=S,PHASES=('source-before','source-after'));exec(compile(ast.Module(body=[node],type_ignores=[]),'<real-public-progress-validator>','exec'),scope)
  # Counter/elapsed simulation only; this does not claim10500s native execution.
  for n in range(2200):
   metrics=dict(metrics,elapsed_ms=n*5000,walk_nodes=n);value=scope['progress_value'](journal.push('postwalk','sample',context,metrics),selection)
  self.assertEqual(len(value['records']),1);self.assertEqual(value['omitted_records'],2199);self.assertEqual(value['records'][-1]['postwalk']['elapsed_ms'],10995000)
  for n in range(700):
   raw=journal.push('postwalk','enter' if n%2 else 'leave',context,metrics);value=scope['progress_value'](raw,selection);self.assertLessEqual(len(raw),65536);self.assertLessEqual(len(value['records']),256)
  raw=journal.push('lifecycle','leave',dict(case='none',phase='none'));value=scope['progress_value'](raw,selection);self.assertEqual(value['records'][-1]['sequence'],2901);self.assertEqual(value['records'][-1]['stage'],'lifecycle');self.assertGreater(value['omitted_records'],2200)
  # Saturated diagnostics remain optional to the actual original capability observer.
  caps=load('original_caps_after_saturation',ROOT/'scripts/apps/file_capabilities.py');roots=load('original_roots_after_saturation',ROOT/'scripts/update/full_root.py')
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);(p/'file').write_bytes(b'actual');limits=roots.Limits(deadline=time.monotonic()+10);nodes=roots.observe(p,limits=limits)['nodes'];self.assertEqual(S.capability_facade(caps,lambda stage,edge,metrics:journal.push(stage,edge,context,metrics)).observe(p,nodes,limits),caps.observe(p,nodes,limits))
 def test_normal_worker_supervisor_and_runtime_bodies_are_byte_exact(self):
  raw=(HERE/'guest.py').read_text();actual={n.name:ast.get_source_segment(raw,n) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  expected={'emit': 'b0630e292d4c5841e0467ea8fbe76fe62e13ee7a014e014e4f78d3c9c1628f6e', 'inner_failure_report': '94a36e6d3ce4489559f40a98e89d8076b7a799646d0a5c503d7cbab84658b45b', 'child_failure': '125da665815c06af272b7df75e4c07823164d0530d800d346a1ec5ab9c252f51', 'supervised_progress': '0de94f12e956f2a2e62e457b7fb58c355b2d070273e212ff50f37f75fee8007b', 'worker': 'cf850dfc98c5988407dcebe6fe5a059ea3d3fd648ec05fa36725985ecceb9fda', 'observer_file_limit': '06709106995438415526523e9c61a24d11d237b85c5a021651516da1b51fe816', 'run': '5c53b88d4ade24ee50ec75f867bbc160089d855c600ef9755cdd6ef95a0e9226'}
  for name,digest in expected.items():self.assertEqual(hashlib.sha256(actual[name].encode()).hexdigest(),digest,name)
  self.assertIn(',10500,512*1024)',actual['supervised_progress']);self.assertIn('seconds=10800,cap=16*1024**2',(HERE/'run.py').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
