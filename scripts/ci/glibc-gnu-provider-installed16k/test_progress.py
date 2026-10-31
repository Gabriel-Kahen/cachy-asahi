# SPDX-License-Identifier: MIT
"""Actual short process stall, ordinary receipt IO and passive fixed readback controls."""
import ast,copy,hashlib,importlib.util,io,json,os,re,resource,stat,subprocess,sys,tempfile,threading,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
SOURCE='a'*40;NONCE='b'*32
spec=importlib.util.spec_from_file_location('original_snapshot_progress_controls',HERE/'snapshot_progress.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)

def need(ok,why):
 if not ok:raise ValueError(why)
def read(path,cap=2*1024**2):
 p=Path(path);need(not p.is_symlink() and p.stat().st_nlink==1 and p.stat().st_size<=cap,'ordinary bounded file');return p.read_bytes()
def C():return types.SimpleNamespace(need=need,read=read,decode=json.loads,sha=lambda r:hashlib.sha256(r).hexdigest(),GIB=1024**3,save=lambda p,v:Path(p).write_text(json.dumps(v)))
def scope(names,path='guest.py',**extra):
 text=(HERE/path).read_text();tree=ast.parse(text);selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names];need(len(selected)==len(names),'exact function controls');space=dict(C=C(),S=S,Path=Path,os=os,stat=stat,types=types,sys=sys,json=json,re=re,threading=threading,time=time,hashlib=hashlib,resource=resource,subprocess=subprocess,PHASES=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'));space.update(extra);exec(compile(ast.Module(body=selected,type_ignores=[]),str(HERE/path)+':inert','exec'),space);return space

def row():return dict(sequence=1,stage='observer',edge='enter',case='pristine',phase='source-before')
def value():return dict(status='DIAGNOSTIC_CALL_BOUNDARIES_NO_ACCEPTANCE',nonce=NONCE,source_sha=SOURCE,records=[row()],omitted_records=0)
class Controls(unittest.TestCase):
 def test_worker_and_original_observer_are_not_rewritten_or_profiled(self):
  text=(HERE/'guest.py').read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='worker');raw=ast.get_source_segment(text,node).encode();self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(2992,'cf850dfc98c5988407dcebe6fe5a059ea3d3fd648ec05fa36725985ecceb9fda'));self.assertNotIn('setprofile',text);self.assertIn(',10500,512*1024)',text);self.assertIn('seconds=10800,cap=16*1024**2',(HERE/'run.py').read_text())
 def test_closed_nonce_source_labels_sequence_and_bounds_refuse(self):
  space=scope(('progress_value',));f=space['progress_value'];s=dict(nonce=NONCE,source_sha=SOURCE);v=value();self.assertEqual(f(json.dumps(v).encode(),s),v)
  for mutation in (dict(nonce='c'*32),dict(source_sha='d'*40),dict(records=[]),dict(omitted_records=True),dict(omitted_records=1),dict(records=[dict(row(),sequence=True)]),dict(records=[dict(row(),phase='/private/key')]),dict(records=[dict(row(),stage='arbitrary')]),dict(records=[dict(row(),case='other')])):
   with self.assertRaises(ValueError):f(json.dumps(dict(v,**mutation)).encode(),s)
  with self.assertRaises(ValueError):f(b'x'*65537,s)
 def test_omitted_tail_and_postwalk_schema_keep_strict_sequence_and_counter_bounds(self):
  f=scope(('progress_value',))['progress_value'];selection=dict(nonce=NONCE,source_sha=SOURCE);v=value();v.update(omitted_records=4,records=[dict(row(),sequence=5)]);self.assertEqual(f(json.dumps(v).encode(),selection),v)
  metrics=dict(operation='walk',elapsed_ms=1,**dict.fromkeys(S.COUNTERS,0));v['records']=[dict(row(),sequence=5,stage='postwalk',edge='sample',postwalk=metrics)];self.assertEqual(f(json.dumps(v).encode(),selection),v)
  for bad in (dict(metrics,walk_nodes=True),dict(metrics,operation='arbitrary'),dict(metrics,elapsed_ms=-1)):
   v['records'][0]['postwalk']=bad
   with self.assertRaises(ValueError):f(json.dumps(v).encode(),selection)
 def test_finite_wrappers_preserve_return_exception_and_no_per_node_events(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);path=root/'progress.log';# Outer-boundary unit fixture uses inert facades; exact capability/snapshot bodies
   # and refusal/return behavior have real small-tree controls in test_snapshot_progress.py.
   outer=types.SimpleNamespace(Journal=S.Journal,validate=S.validate,snapshot=lambda module,record:module.snapshot,capability_facade=lambda module,record,**kw:module)
   copy_bindings=[]
   def copy_binding(bridge,source,*,record=None):self.assertTrue(callable(record));copy_bindings.append((bridge,source));return bridge
   space=scope(('progress_value','install_progress'),PROGRESS=path,S=outer,O=types.SimpleNamespace(facade=lambda module,record,**kw:module),_copy_capability_bridge=copy_binding);c=space['C'];original_return=object();calls=[]
   def observe(*a,**k):
    for n in range(10000):str(n)
    calls.append(('observe',a,k));return original_return
   roots=types.SimpleNamespace(observe=observe);api={'roots':roots,'caps':object(),'capabilities':object()};common=types.SimpleNamespace(helpers=lambda *a,**k:api);module=types.SimpleNamespace(C=common)
   for name in ('main','run_case','snapshot','transaction','smoke','caches','copy_probes','config_handoff'):setattr(module,name,lambda *a,**k:original_return)
   def bad(*a,**k):raise RuntimeError('original exception')
   module.transaction=bad;c.ref=lambda root,row:root/row['path'];c.load=lambda name,path:types.SimpleNamespace(_mount600=lambda old:old,_observer600=lambda roots,*a,**kw:roots.observe(*a,**kw)) if name=='gnu_installed_fresh_mount_query' else module;c.read=lambda *a:json.dumps(dict(nonce=NONCE,source_sha=SOURCE)).encode();c.need=lambda ok,why:need(ok or why=='owned progress replacement',why) # Ordinary host-owned temp; productionroot0 check remains.
   space['install_progress']();wrapped=c.load('guest_worker','/installed16k/container16k.py');self.assertIs(wrapped.main(),original_return);newapi=wrapped.C.helpers(Path('/source'));self.assertIs(newapi['roots'].observe('unchanged',hardlinks='generic-development-internal'),original_return);self.assertEqual(calls,[('observe',('unchanged',),{'hardlinks':'generic-development-internal'})]);self.assertIs(api['roots'].observe, newapi['roots'].observe)
   self.assertEqual(copy_bindings,[(api['capabilities'],Path('/source'))])
   with self.assertRaisesRegex(RuntimeError,'original exception'):wrapped.transaction('same')
   v=json.loads(path.read_bytes());self.assertEqual(len(v['records']),7);self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600);self.assertTrue(all(set(r)==set(row()) for r in v['records']))
 def test_real_short_stall_has_live_phase_before_original_group_timeout(self):
  repo=next(p for p in HERE.parents if (p/'scripts/ci/glibc-owned-runtime/runner.py').is_file());spec=importlib.util.spec_from_file_location('actual_short_runner',repo/'scripts/ci/glibc-owned-runtime/runner.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);path=root/'progress.log';space=scope(('progress_value','supervised_progress'),PROGRESS=path);output=io.StringIO();recorded=[]
   script="import pathlib,os,time; p=pathlib.Path("+repr(str(path))+");p.write_bytes("+repr(json.dumps(value()).encode())+");p.chmod(0o600);time.sleep(30)"
   def run(argv,work,env,seconds,cap):
    self.assertEqual((seconds,cap),(10500,512*1024));v=runtime.run_command([sys.executable,'-I','-B','-c',script],root,dict(PATH='/usr/bin:/bin',HOME=str(root),LANG='C'),1,512*1024);recorded.append(output.getvalue());return v
   # Real local child owns temp as caller; sourceproduction requiresroot0.
   original_need=space['C'].need;space['C'].need=lambda ok,why:original_need(ok or why=='owned progress reader',why)
   with patch('sys.stdout',output):v=space['supervised_progress'](types.SimpleNamespace(run_command=run),dict(nonce=NONCE,source_sha=SOURCE),NONCE)
   self.assertTrue(v[0]['group_absence_verified']);self.assertIsNotNone(v[3]);self.assertIn('GNU_INSTALLED16K_PROGRESS '+NONCE+' ',recorded[0]);self.assertIn('"source_sha":"'+SOURCE+'"',recorded[0]);self.assertLess(len(output.getvalue()),1024)
 def test_polled_missing_partial_drift_does_not_abort_original_supervision(self):
  with tempfile.TemporaryDirectory() as td:
   space=scope(('progress_value','supervised_progress'),PROGRESS=Path(td)/'missing');expected=object();calls=[]
   def run(*args):calls.append(args);time.sleep(.3);return expected
   self.assertIs(space['supervised_progress'](types.SimpleNamespace(run_command=run),dict(nonce=NONCE,source_sha=SOURCE),NONCE),expected);self.assertEqual(len(calls),1)
 def test_passive_debugfs_metadata_refuses_links_types_and_over_cap(self):
  f=scope(('diagnostic_metadata',),'export.py')['diagnostic_metadata'];text='Inode: 42 Type: regular Mode: 0600 Flags: 0x0\nUser: 0 Group: 0 Size: 123\nLinks: 1 Blockcount: 8\n';self.assertEqual(f(text,123),123)
  for bad in (text.replace('regular','symlink'),text.replace('Links: 1','Links: 2'),text.replace('123','124'),text.replace('Size: 123','Size: 0'),'File not found by ext2_lookup'):
   with self.assertRaises(ValueError):f(bad,123)
 def test_original_worker_projection_has_no_raw_map_key_path_or_error_message(self):
  f=scope(('diagnostic_projection',),'export.py')['diagnostic_projection'];raw=json.dumps(dict(status='FAIL',error_type='ValueError',error='/private/signing-key full raw payload',commands=[{'argv':['/secret']}],nodes={'/private':'payload'},cases=dict(pristine=dict(status='FAIL',root_observation_failures={'pristine-source-before':dict(complete=False,unsupported_counts={'filesystem-observation-failed':1},unsupported_records=[{'path':'/secret'}])})))).encode();v=f(raw);encoded=json.dumps(v);self.assertNotIn('/private',encoded);self.assertNotIn('/secret',encoded);self.assertNotIn('raw payload',encoded);self.assertEqual(v['recorded_commands'],1);self.assertEqual(v['cases']['pristine']['observation_failures']['source-before']['unsupported_counts'],{'filesystem-observation-failed':1})
 def test_failure_readback_is_after_qemu_absence_before_disk_disposal(self):
  t=(HERE/'run.py').read_text();self.assertLess(t.index("qemus[0][1]['group_absence_verified'] is True"),t.index("actor('export','export.py',public)",t.index("qemus=")));self.assertLess(t.index("'failure-diagnostics.json'"),t.index("for path in (disks/'boot.raw'"));self.assertIn("if role=='export':mounts.append((disks,'/disks',True))",t)
 def test_real_ordinary_export_755_parent_0600_write_and_same_id_chown(self):
  f=scope(('export_ids',),'export.py')['export_ids'];uid,gid=os.getuid(),os.getgid();self.assertGreater(uid,0);self.assertGreater(gid,0);self.assertEqual(f(dict(OUTPUT_UID=str(uid),OUTPUT_GID=str(gid)),(uid,uid,gid,gid)),(uid,gid))
  with tempfile.TemporaryDirectory() as td:
   parent=Path(td)/'public';parent.mkdir(mode=0o755);p=parent/'actual-owned-result';fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
   with os.fdopen(fd,'wb') as stream:stream.write(b'bounded diagnostic data')
   os.chown(p,uid,gid);self.assertEqual((p.stat().st_uid,p.stat().st_gid,stat.S_IMODE(p.stat().st_mode)),(uid,gid,0o600));self.assertEqual(stat.S_IMODE(parent.stat().st_mode),0o755)
  for environment,actual in ((dict(OUTPUT_UID='0',OUTPUT_GID=str(gid)),(0,0,gid,gid)),(dict(OUTPUT_UID=str(uid),OUTPUT_GID=str(gid)),(uid+1,uid+1,gid,gid)),(dict(OUTPUT_UID='0'+str(uid),OUTPUT_GID=str(gid)),(uid,uid,gid,gid))):
   with self.assertRaises(ValueError):f(environment,actual)
 def test_original_normal_export_body_and_all_other_actor_identities_unchanged(self):
  root=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());old=(root/'scripts/ci/glibc-gnu-provider-installed16k/export.py').read_text();new=(HERE/'export.py').read_text();start="    files=C.decode(C.read('/selection/guest-files.json'));";end="\nif __name__=='__main__':";self.assertEqual(old[old.index(start):old.index(end)],new[new.index(start):new.index(end)])
  t=(HERE/'run.py').read_text();self.assertIn("if role=='export' else '--user=0:0'",t);self.assertIn("if role in ('prepare','scrub'):argv+=",t);self.assertIn("if role=='export':mounts.append((disks,'/disks',True))",t)
 def test_fixed_readback_present_missing_invalid_oversize_and_absence_guards(self):
  for variant in ('valid','missing','invalid','oversize','unretired','tool-unknown'):
   with self.subTest(variant=variant),tempfile.TemporaryDirectory() as td:
    root=Path(td);(root/'out').mkdir();(root/'disks').mkdir();(root/'tmp').mkdir();(root/'disks/volume.raw').write_bytes(b'owned model disk only');calls=[];selection=dict(nonce=NONCE,source_sha=SOURCE);owner=dict(token=NONCE,commands=[dict(argv=['/usr/bin/qemu-system-aarch64'],group_absence_verified=variant!='unretired',time_limit=10800,output_limit=16*1024**2)]);request=dict(status='FIXED_READONLY_DIAGNOSTICS_AFTER_QEMU_ABSENCE',nonce=NONCE,source_sha=SOURCE,qemu_command_index=0);metadata={'/selection/selection.json':selection,'/selection/owner.json':owner,'/selection/failure-diagnostics.json':request}
    def mapped(p):
     p=Path(p);return root/str(p).lstrip('/') if str(p)=='/tmp' or str(p).startswith(('/out','/disks','/tmp/gnu-installed16k-diagnostic')) else p
    def reading(p,cap=2*1024**2):return json.dumps(metadata[str(p)]).encode() if str(p) in metadata else read(mapped(p),cap)
    records={'result.json':b'{broken' if variant=='invalid' else json.dumps(dict(status='FAIL',error_type='ValueError',error='/private-never-published')).encode(),'pristine-guest-progress.log':json.dumps(value()).encode()};schema=scope(('progress_value',));space=scope(('diagnostic_metadata','diagnostic_projection','failure_capture'),'export.py',Path=mapped,__file__=str(HERE/'export.py'));space['C'].read=reading
    def command(argv,work,env,seconds,cap):
     calls.append(argv);self.assertEqual((seconds,cap),(15,65536));self.assertNotIn('-w',argv);self.assertEqual(argv[:4],['/usr/bin/python3','-I','-B','-c']);self.assertIn('RLIMIT_FSIZE',argv[4]);op=argv[6];name=op.split()[1].removeprefix('/out/');raw=records[name]
     if op.startswith('stat '):
      if variant=='missing':out=b'File not found by ext2_lookup'
      else:out=('Inode:42 Type: regular Mode: 0600\nSize: '+str(8*1024**2+1 if variant=='oversize' else len(raw))+'\nLinks: 1\n').encode()
     else:Path(op.split()[2]).write_bytes(raw);out=b''
     return dict(exit_code=0,group_absence_verified=variant!='tool-unknown'),out,b'',None
    runtime=types.SimpleNamespace(run_command=command);space['C'].load=lambda n,p:runtime if n=='original_diagnostic_supervisor' else types.SimpleNamespace(progress_value=schema['progress_value'])
    with patch.dict(os.environ,OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid())):
     if variant=='unretired':
      with self.assertRaisesRegex(ValueError,'group absence'):space['failure_capture']()
      self.assertEqual(calls,[]);continue
     if variant=='tool-unknown':
      with self.assertRaisesRegex(ValueError,'retirement unknown'):space['failure_capture']()
     else:space['failure_capture']()
    result=json.loads((root/'out/failure-diagnostics.json').read_bytes());self.assertEqual(result['acceptance'],'FORBIDDEN_DIAGNOSTIC_ONLY');self.assertEqual({p.name for p in (root/'out').iterdir()},{'failure-diagnostics.json'});self.assertNotIn('/private-never-published',json.dumps(result))
    state=result['files']['result.json']['status'];self.assertEqual(state,'READ_ORIGINAL_FIXED_RECEIPT_DIAGNOSTIC_ONLY' if variant=='valid' else 'MISSING_PARTIAL_OR_UNREADABLE_NO_AUTHORITY')
 def test_export_retained_owner_proof_and_disk_modes_refuse_substitution(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'out').mkdir(mode=0o755);(root/'disks').mkdir(mode=0o755);disk=root/'disks/volume.raw';disk.write_bytes(b'ordinary disk fixture');disk.chmod(0o600);uid,gid=os.getuid(),os.getgid();owner=dict(output_uid=uid,output_gid=gid,token=NONCE,source_sha=SOURCE);selection=dict(nonce=NONCE,source_sha=SOURCE)
   def mapped(path):return root/str(path).lstrip('/')
   space=scope(('export_ids','export_identity'),'export.py',Path=mapped);space['C'].read=lambda path,cap=0:json.dumps(owner if path=='/selection/owner.json' else selection).encode()
   with patch.dict(os.environ,OUTPUT_UID=str(uid),OUTPUT_GID=str(gid)):
    self.assertEqual(space['export_identity'](),(uid,gid));owner['output_uid']=uid+1
    with self.assertRaises(ValueError):space['export_identity']()
    owner['output_uid']=uid;selection['nonce']='f'*32
    with self.assertRaises(ValueError):space['export_identity']()
    selection['nonce']=NONCE;disk.chmod(0o666)
    with self.assertRaises(ValueError):space['export_identity']()
    disk.chmod(0o600);os.link(disk,root/'alias')
    with self.assertRaises(ValueError):space['export_identity']()
if __name__=='__main__':unittest.main(verbosity=2)
