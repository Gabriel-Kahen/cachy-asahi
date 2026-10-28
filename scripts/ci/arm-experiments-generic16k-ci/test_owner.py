# SPDX-License-Identifier: MIT
"""Bounded data/source controls; forbid native/container/network actors."""
import base64,copy,gzip,hashlib,importlib.util,io,json,os,sys,tarfile,tempfile,unittest,zipfile,subprocess
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import acquire as Q,owner as O,capture_entry as E
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);no=patch.object(subprocess,'Popen',side_effect=AssertionError('no actor'));no.start();self.addCleanup(no.stop)
 def frame(self,kind='good'):
  members={'experiment-artifacts/archive-manifest.json':b'{}','experiment-artifacts/outputs.tar.gz':b'original retained bytes'};stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w:gz') as t:
   for name,data in members.items():
    info=tarfile.TarInfo('../../outside' if kind=='path' else name);info.size=len(data)
    if kind=='hardlink':info.type=tarfile.LNKTYPE;info.linkname='outside';info.size=0
    t.addfile(info,io.BytesIO(data))
  raw=stream.getvalue();header=b'CACHY_ASAHI_EVIDENCE_BEGIN experiment-artifacts '+('sha256='+Q.pin(raw)['sha256']+' bytes='+str(len(raw))).encode();encoded=base64.b64encode(raw);body=header+b'\n'+b'\xef\xbb\xbf2026-10-15T16:56:52.7585481Z '+(b'bad!' if kind=='base64' else encoded)+b'\nCACHY_ASAHI_EVIDENCE_END experiment-artifacts\n'
  if kind=='duplicate-frame':body+=body
  target=io.BytesIO()
  with zipfile.ZipFile(target,'w') as z:z.writestr('0_trial.txt',body)
  archive=target.getvalue();origin=dict(logs=Q.pin(archive),frame=Q.pin(raw));entry=dict(archive_manifest=dict(path='inputs/manifest.json',**Q.pin(b'{}')),bundle=dict(path='inputs/outputs.tar.gz',**Q.pin(b'original retained bytes')));return archive,origin,entry
 def test_original_frame_shape_with_BOM_and_exact_two_outputs(self):
  raw,origin,entry=self.frame();self.assertEqual(Q.decode(raw,origin,entry),{'inputs/manifest.json':b'{}','inputs/outputs.tar.gz':b'original retained bytes'})
 def test_hash_encoding_frame_path_and_hardlink_refuse(self):
  for kind in ('base64','duplicate-frame','path','hardlink'):
   with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):Q.decode(*self.frame(kind))
  raw,origin,entry=self.frame();origin['frame']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'exact frame header'):Q.decode(raw,origin,entry)
 def test_repacked_transport_keeps_exact_authenticated_frame(self):
  raw,origin,entry=self.frame();target=io.BytesIO()
  with zipfile.ZipFile(io.BytesIO(raw)) as old,zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as new:
   info=zipfile.ZipInfo('0_trial.txt',date_time=(2026,10,17,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;new.comment=b'different transport container';new.writestr(info,old.read('0_trial.txt'))
  repacked=target.getvalue();self.assertNotEqual(Q.pin(repacked),origin['logs']);self.assertEqual(Q.decode(repacked,origin,entry),Q.decode(raw,origin,entry))
 def test_repacked_transport_cannot_change_frame_or_object(self):
  raw,origin,entry=self.frame();target=io.BytesIO()
  with zipfile.ZipFile(io.BytesIO(raw)) as old,zipfile.ZipFile(target,'w') as new:
   body=old.read('0_trial.txt');new.writestr('0_trial.txt',body.replace(b'bytes='+str(origin['frame']['bytes']).encode(),b'bytes=0',1))
  with self.assertRaisesRegex(ValueError,'exact frame header'):Q.decode(target.getvalue(),origin,entry)
  changed=copy.deepcopy(entry);changed['bundle']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'input object pin'):Q.decode(raw,origin,changed)
 def test_log_transport_unsafe_paths_types_and_aggregate_ambiguity_refuse(self):
  raw,origin,entry=self.frame()
  with zipfile.ZipFile(io.BytesIO(raw)) as old:body=old.read('0_trial.txt')
  for name,mode in (('../outside',0),('/outside',0),('unsafe\\name',0),('link',0o120777),('0_trial.txt/',0)):
   with self.subTest(name=name):
    target=io.BytesIO()
    with zipfile.ZipFile(target,'w') as z:
     if name!='0_trial.txt/':z.writestr('0_trial.txt',body)
     info=zipfile.ZipInfo(name);info.external_attr=mode<<16;z.writestr(info,body)
    with self.assertRaises(ValueError):Q.decode(target.getvalue(),origin,entry)
 def source(self):
  view=self.work/'source';view.mkdir();manifest=json.loads((HERE/'integration-manifest.json').read_bytes());proposed=next((p for p in HERE.parents if p.name=='proposed'),None)
  for name in manifest['files']:
   source=proposed/name if proposed is not None and (proposed/name).is_file() else ROOT/name;target=view/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes())
  for name in ('integration-manifest.json',):
   target=view/'scripts/ci/arm-experiments-generic16k-ci'/name;target.write_bytes((HERE/name).read_bytes())
  source='a'*40;run='1234';experiment='ARM-C01';token=hashlib.sha256(('armexperiments16k:'+run+':1:'+source+':'+experiment).encode()).hexdigest()[:16];args=NS(source_root=view,source_commit=source,manifest_sha256=O.pin((HERE/'integration-manifest.json').read_bytes())['sha256'],experiment=experiment,job_token=token,output=self.work/'public',base_dir=self.work/'base',input_root=self.work/'inputs',private=self.work/'private',kernel_receipt=self.work/'kernel.json',kernel_work=self.work/'tools16k-kernel',execute=True);environment=dict(GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_WORKFLOW_SHA=source,GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID=run,RUNNER_TEMP=str(self.work));return args,environment
 def test_source_authorization_rejects_cross_run_case_digest_and_bytes(self):
  args,environment=self.source()
  with patch.dict(os.environ,environment,clear=True):
   self.assertEqual(O.authorize(args)['status'],'SOURCE_AUTHORIZATION_ONLY_NOT_RUNTIME_ACCEPTANCE')
   for key,value in [('experiment','ARM-C05'),('job_token','0'*16),('manifest_sha256','0'*64)]:
    old=getattr(args,key);setattr(args,key,value)
    with self.subTest(key=key),self.assertRaises(ValueError):O.authorize(args)
    setattr(args,key,old)
   with patch.dict(os.environ,GITHUB_RUN_ID='1235'),self.assertRaises(ValueError):O.authorize(args)
   first=next(iter(json.loads((HERE/'integration-manifest.json').read_bytes())['files']));(args.source_root/first).write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'source pin'):O.authorize(args)
 def namespace(self,args,environment):
  scope=patch.dict(sys.modules);scope.start();self.addCleanup(scope.stop)
  for key in ('adapter','prepare','runtime','support'):sys.modules.pop(key,None)
  with patch.dict(os.environ,environment,clear=True):return O.namespace(args)
 def test_one_counted_marker_edit_original_probe_owner_stages_and_default_unbound(self):
  args,environment=self.source();value,receipt=self.namespace(args,environment);self.assertEqual(receipt['counted_edits'],1);self.assertIn('retire',receipt['unchanged_bodies']);self.assertIn('finalize',receipt['unchanged_bodies']);self.assertEqual(value['s'].SCOPE,O.SCOPE);self.assertEqual(json.loads((args.source_root/O.LANE/'policy.json').read_bytes())['status'],'UNBOUND_DO_NOT_EXECUTE');self.assertIn('SOURCE_AUTHORIZATION_ONLY',receipt['source_authorization']['status'])
 def test_manual_bound_raw_capture_refuses_missing_probe_before_actors(self):
  args,environment=self.source();self.namespace(args,environment);import adapter
  original=adapter.P.read
  def read(path,cap):return b'{"status":"BOUND_BY_ROOT"}' if path==adapter.HERE/'policy.json' else original(path,cap)
  with patch.object(adapter.P,'read',side_effect=read),self.assertRaisesRegex(ValueError,'probe stage inputs required before actors'):adapter.trial(args)
 def test_capture_entry_orders_import_before_unchanged_capture(self):
  order=[]
  with patch.object(E,'import_extensions',side_effect=lambda root:order.append(('import',str(root)))),patch.object(E.runpy,'run_path',side_effect=lambda *a,**k:order.append(('capture',a,k))):E.main()
  self.assertEqual(order,[('import','/repo'),('capture',('/source/capture.py',),{'run_name':'__main__'})])
 def test_actual_arm_import_closure_seeds_ctypes_without_helper_collisions(self):
  keys=('runtime','prepare','support','sandbox');prior={k:sys.modules.get(k) for k in keys};paths=list(sys.path);ctypes=E.import_extensions(ROOT)
  self.assertIn('_ctypes',sys.modules);self.assertTrue(Path(sys.modules['_ctypes'].__file__).name.endswith('.so'));self.assertEqual(sys.path,paths);self.assertEqual({k:sys.modules.get(k) for k in keys},prior);self.assertEqual(ctypes.__name__,'ctypes')
  lane=self.work/'scripts/ci/arm-experiments-generic16k';lane.mkdir(parents=True);(lane/'guest.py').write_text('import ctypes,foreign_root\n')
  with self.assertRaisesRegex(ValueError,'import closure changed'):E.import_extensions(self.work)
 def test_original_capture_helper_context_and_native_scan_root_preserved(self):
  paths=list(sys.path)
  with patch.dict(sys.modules):
   sys.modules.pop('support',None)
   def capture(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts/ci/tools-generic16k/capture.py');value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
   try:
    before=capture('original_capture_before');helpers={k:sys.modules.get(k) for k in ('runtime','prepare','support','sandbox')};E.import_extensions(ROOT);after=capture('original_capture_after');self.assertIs(before.s,after.s);self.assertEqual(Path(after.s.__file__).resolve(),ROOT/'scripts/ci/tools-generic16k/support.py');self.assertEqual({k:sys.modules.get(k) for k in helpers},helpers)
    import sysconfig
    self.assertTrue(Path(sys.modules['_ctypes'].__file__).resolve().is_relative_to(Path(sysconfig.get_path('stdlib')).resolve()))
   finally:sys.path[:]=paths
 def test_capture_import_alias_refuses_before_import_or_capture(self):
  lane=self.work/'scripts/ci/arm-experiments-generic16k';lane.mkdir(parents=True);(lane/'guest.py').symlink_to(ROOT/'scripts/ci/arm-experiments-generic16k/guest.py')
  with self.assertRaisesRegex(ValueError,'ordinary bounded exact source'):E.import_extensions(self.work)
 def test_capture_argv_changes_only_entry_and_records_source_pin(self):
  args,environment=self.source();value,receipt=self.namespace(args,environment);capture=self.work/'capture';image='sha256:'+'b'*64;name='capture-'+args.job_token
  original={};raw=(args.source_root/'scripts/ci/tools-generic16k/run.py').read_text();exec(compile(raw,str(args.source_root/'scripts/ci/tools-generic16k/run.py'),'exec'),dict(value,__name__='original_capture_only'),original)
  before=original['capture_command'](args,image,name,capture);after=value['capture_command'](args,image,name,capture);position=before.index('/source/capture.py');self.assertEqual(after[:position],before[:position]);self.assertEqual(after[position+1:],before[position+1:]);self.assertEqual(after[position],'/repo/scripts/ci/arm-experiments-generic16k-ci/capture_entry.py');self.assertEqual(receipt['capture_entry'],dict(path='scripts/ci/arm-experiments-generic16k-ci/capture_entry.py',**O.pin((HERE/'capture_entry.py').read_bytes())))
 def report(self,args):
  image='sha256:'+'b'*64;consumer=dict(capture_absent=True,private_removed=True,producer='BORROWED_PRESERVED');report=dict(job_token=args.job_token,status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT',natural_VM_exit=True,QEMU_exit=0,actors=[dict(natural_exit=True,exit=0,group_absent=True) for _ in range(3)],consumer_cleanup=consumer,image_id=image,kernel=dict(helper=dict(path=str(args.kernel_work/'helper/build_kernel.py')),status='BUILT_ONLY',kernel_build='PASS'));args.output.mkdir();O.save(args.output/'runtime.json',report);return report,image
 def test_cleanup_safe_refuses_uncertain_or_partial_actor_retirement(self):
  args,environment=self.source();self.assertFalse(O.cleanup_safe(args));report,image=self.report(args);self.assertTrue(O.cleanup_safe(args))
  for kind in ('group','count','capture'):
   bad=copy.deepcopy(report)
   if kind=='group':bad['actors'][2]['group_absent']=False
   elif kind=='count':bad['actors'].pop()
   else:bad['consumer_cleanup']['capture_absent']=False
   O.save(args.output/'runtime.json',bad);self.assertFalse(O.cleanup_safe(args))
 def test_aggregate_success_only_after_original_producer_and_kernel_cleanup(self):
  args,environment=self.source();self.namespace(args,environment);report,image=self.report(args);args.base_dir.mkdir();args.kernel_work.mkdir();base=dict(ownership=dict(token=args.job_token),owned_cleanup=dict(status='PASS',probe=dict(absence_verified=True),image=dict(absence_verified=False,id=image)));O.save(args.base_dir/'report.json',base)
  with patch.dict(os.environ,environment,clear=True):self.assertEqual(O.finalize(args)['status'],'FAIL')
  self.assertTrue(args.kernel_work.exists());O.save(args.output/'runtime.json',report);base['owned_cleanup']['image']['absence_verified']=True;O.save(args.base_dir/'report.json',base)
  with patch.dict(os.environ,environment,clear=True):result=O.finalize(args)
  self.assertEqual(result['status'],'PASS_RETAINED_ARM_EXPERIMENT_GENERIC16K_AND_ORDERED_CLEANUP');self.assertEqual(result['tools_correctness'],'NOT_RUN_CAPTURE_ONLY');self.assertFalse(args.kernel_work.exists())
if __name__=='__main__':unittest.main()
