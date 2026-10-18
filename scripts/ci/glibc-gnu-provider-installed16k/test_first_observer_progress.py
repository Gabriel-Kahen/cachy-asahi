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
 raw=(HERE/'guest.py').read_text();nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in ('progress_value','install_progress')]
 # Host-user controls exercise the real writer; production uid0 guard is unchanged.
 C=types.SimpleNamespace(need=lambda ok,why:need(ok or why=='owned progress replacement',why),decode=json.loads,read=lambda *a:json.dumps(selection).encode(),load=lambda *a:module)
 result=dict(C=C,S=S,O=O,Path=Path,os=os,stat=stat,types=types,sys=sys,json=json,re=re,threading=threading,time=time,PHASES=('source-before','source-after'),PROGRESS=path)
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<normal-original-progress-installer>','exec'),result)
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
if __name__=='__main__':unittest.main(verbosity=2)
