# SPDX-License-Identifier: MIT
"""Inert finite report/log controls. Synthetic data is never acceptance authority."""
import base64,copy,importlib.util,json,os,subprocess,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());spec=importlib.util.spec_from_file_location('gnu_failure_summary',HERE/'summary.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
class Controls(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name);self.owner=self.root/'owner';self.public=self.root/'export';self.child=self.owner/'inner/public';self.child.mkdir(parents=True);self.public.mkdir();self.env=dict(SOURCE_SHA='1'*40,WORKFLOW_SHA='1'*40,GITHUB_SHA='1'*40,GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1');self.proof=self.root/'proof.json';self.cleanup=self.root/'cleanup.json';self.put(self.proof,dict(source_sha='1'*40,run_id='1',attempt='1',consumer_token='a'*32));p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));p.start();self.addCleanup(p.stop)
 def put(self,path,value):path.write_bytes(S.encoded(value))
 def collect(self,lane='lifecycle'):return S.collect(self.owner,self.proof,self.cleanup,self.public,lane,self.env,1)
 def fixture(self):
  meta=dict(device=2,inode=3,mode=448,uid=0,gid=0);root=dict(status='PASS_CLONE_ROOT_ONLY_0700_TO_0755_AFTER_COPY_PROOF',path='/work/pristine/root',before=meta,after=dict(meta,mode=493),parent_before=dict(meta,inode=4),parent_after=dict(meta,inode=4),source_before=dict(meta,inode=5),source_after=dict(meta,inode=5),source_mutation='NONE',payload_nodes_mutation='NONE_FOR_ROOT_MODE_INITIALIZATION');error=[dict(type='ValueError',message='actual primary UNIT',frames=[dict(file='/runner/container.py',function='run_case',line=274)],frames_clipped=False,notes=[])]
  case=dict(status='FAIL',root_initialization=root,primary_failure=error,cleanup_failure=[],clone_cleanup_check='PASS',copy_lifetime=dict(cleanup='PASS-owned-workspace-removed',copy=dict(copy_byte_identical_before_initialization=True)),before_runtime=dict(result=dict(status='PASS',cases=8,page_size=4096)),source_before='b'*64,source_after='b'*64)
  self.put(self.owner/'owner.json',dict(status='FAIL',token='a'*32,source_sha='1'*40,image='sha256:'+'c'*64,error='actual installed lifecycle and inner teardown',commands=[]));self.put(self.owner/'inner/owner.json',dict(status='FAIL',token='a'*32,image_id='sha256:'+'c'*64,error='installed provider lifecycle child failed',commands=[],actor_cleanup='PASS_ALL_ABSENCE_VERIFIED'))
  self.put(self.child/'result.json',dict(status='FAIL',cases=dict(pristine=case),commands=[],error_type='ValueError',error='actual primary UNIT',PAYLOAD='PRIVATE_SENTINEL',environment=dict(SECRET='PRIVATE_SENTINEL')));self.put(self.cleanup,dict(status='PASS_ORDERED_ALL_CONSUMERS_THEN_PRODUCER',consumer='PASS_ALL_ACTORS_CLONES_AND_SOURCE_DATA_RETIRED',producer=dict(status='PASS'),apparmor=dict(status='PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS')));self.put(self.public/'export.json',dict(status='FAIL_OR_INCOMPLETE',errors=[dict(file='acceptance',error='closed native lifecycle refused')],files=dict(secret='PRIVATE_SENTINEL')));return case
 def log(self,frames):
  p=self.root/'logs.zip'
  with zipfile.ZipFile(p,'w') as z:
   for name,values in frames.items():z.writestr(name,b'\n'.join(b'2026-10-17T03:42:45.9875948Z '+v.encode() for v in values))
  return p
 def test_full_primary_root_initialization_and_cleanup_retained_without_payload(self):
  case=self.fixture();v=self.collect();self.assertEqual(v['owner_identity'],'MATCH');c=v['reports']['child']['cases']['pristine'];self.assertEqual(c['root_initialization'],case['root_initialization']);self.assertEqual(c['primary_failure'],case['primary_failure']);self.assertEqual(c['copy_initialization'],dict(copy_byte_identical_before_initialization=True));self.assertEqual(v['reports']['cleanup']['producer']['status'],'PASS');self.assertFalse(v['native_acceptance']);self.assertNotIn(b'PRIVATE_SENTINEL',S.encoded(v));self.assertLessEqual(len(S.frame(v)),S.MAX_FRAME)
 def test_missing_child_and_cleanup_are_unknown_never_synthetic_pass(self):
  v=self.collect();self.assertEqual(v['reports']['child']['observation'],'MISSING_OR_UNREADABLE');self.assertEqual(v['owner_identity'],'UNKNOWN');self.assertEqual(v['reports']['cleanup']['observation'],'MISSING_OR_UNREADABLE');self.assertFalse(v['native_acceptance'])
 def test_source_run_token_and_lane_mismatch_refused(self):
  self.fixture()
  for field,value in (('WORKFLOW_SHA','2'*40),('GITHUB_SHA','2'*40),('GITHUB_RUN_ID','2'),('GITHUB_RUN_ATTEMPT','2')):
   e=dict(self.env);e[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):S.collect(self.owner,self.proof,self.cleanup,self.public,'lifecycle',e,1)
  with self.assertRaises(ValueError):self.collect('unknown')
  v=S.decode(self.proof.read_bytes());v['consumer_token']='bad';self.put(self.proof,v)
  with self.assertRaises(ValueError):self.collect()
 def test_alias_hardlink_oversized_and_duplicate_report_refused(self):
  self.fixture();p=self.child/'result.json';p.unlink();p.symlink_to(self.proof);self.assertEqual(self.collect()['reports']['child']['observation'],'MISSING_OR_UNREADABLE');p.unlink();other=self.root/'hardlink-target';other.write_bytes(self.proof.read_bytes());os.link(other,p);self.assertEqual(self.collect()['reports']['child']['observation'],'MISSING_OR_UNREADABLE');p.unlink();p.write_bytes(b'x'*(8*1024**2+1));self.assertEqual(self.collect()['reports']['child']['observation'],'MISSING_OR_UNREADABLE');p.write_bytes(b'{"status":"A","status":"B"}');self.assertEqual(self.collect()['reports']['child']['observation'],'MISSING_OR_UNREADABLE')
 def test_owner_identity_mismatch_is_explicit_no_credit(self):
  self.fixture();v=S.decode((self.owner/'inner/owner.json').read_bytes());v['token']='b'*32;self.put(self.owner/'inner/owner.json',v);self.assertEqual(self.collect()['owner_identity'],'MISMATCH_NO_CREDIT')
 def test_nonzero_command_stderr_exact_hash_preview_without_argv_env_stdout(self):
  self.fixture();data=b'UNIT actual command error\n'+b'x'*1200;row=dict(exit_code=126,group_absence_verified=True,stderr_bytes=len(data),stderr_sha256=S.pin(data)['sha256'],stdout_bytes=0,stdout_sha256=S.pin(b'')['sha256'],argv=['PRIVATE_SENTINEL']);v=S.decode((self.child/'result.json').read_bytes());v['commands']=[row];self.put(self.child/'result.json',v);(self.child/'command-000.stderr').write_bytes(data);c=self.collect()['reports']['child']['command'];self.assertEqual(c['exit_code'],126);self.assertEqual(len(c['stderr_preview']),512);self.assertTrue(c['stderr_preview_clipped']);self.assertNotIn('argv',c);(self.child/'command-000.stderr').write_text('tampered');self.assertEqual(self.collect()['reports']['child']['command']['stderr_observation'],'ValueError')
 def test_interruption_second_case_and_five_runtime_stages_are_data_only(self):
  case=self.fixture();case['recovered_runtime']=dict(result=dict(status='PASS',cases=8,page_size=4096));case['interruption']=dict(status='PASS_ACTUAL_REMOVE_PHASE_KILL_AND_EXTERNAL_RECOVERY',observed_stop='KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER');v=S.decode((self.child/'result.json').read_bytes());v['cases']['modified']=case;self.put(self.child/'result.json',v);r=self.collect('interruption');self.assertEqual(r['reports']['child']['cases']['modified']['normal_runtime']['recovered_runtime']['page_size'],4096);self.assertFalse(r['native_acceptance'])
 def test_bounded_exception_frame_projection_and_large_unknown_fields(self):
  self.fixture();v=S.decode((self.child/'result.json').read_bytes());err=dict(type='X'*500,message='E'*2000,frames=[dict(file='F'*2000,function='G'*1000,line=1) for _ in range(30)],notes=['N'*1000]*20);v['cases']['pristine']['primary_failure']=[err]*10;v['cases']['pristine']['cleanup_failure']=[err]*10;v['cases']['modified']=copy.deepcopy(v['cases']['pristine']);v['unknown']='PRIVATE_SENTINEL'*10000;self.put(self.child/'result.json',v);r=self.collect();self.assertLessEqual(len(S.encoded(r)),S.MAX_JSON);self.assertNotIn(b'PRIVATE_SENTINEL',S.encoded(r));self.assertLessEqual(len(r['reports']['child']['cases']['pristine']['primary_failure']),2)
 def test_extract_original_logs_deduplicates_identical_aggregate_step_frame(self):
  self.fixture();v=self.collect();frame=S.frame(v);logs=self.log({'0_native.txt':[frame],'native/13_retain.txt':[frame]});self.assertEqual(S.extract(logs,'1'*40,'1','1','lifecycle'),v)
 def test_missing_conflicting_foreign_frames_never_accept(self):
  logs=self.log({'0_native.txt':['exit code1; upload ETIMEDOUT']})
  with self.assertRaisesRegex(ValueError,'UNOBSERVABLE'):S.extract(logs,'1'*40,'1','1','lifecycle')
  logs.unlink();self.fixture();v=self.collect();other=dict(v,retain_exit_code=2);logs=self.log({'0_native.txt':[S.frame(v),S.frame(other)]})
  with self.assertRaisesRegex(ValueError,'conflicting'):S.extract(logs,'1'*40,'1','1','lifecycle')
  with self.assertRaisesRegex(ValueError,'differs'):S.extract(logs,'2'*40,'1','1','lifecycle')
 def test_log_zip_traversal_and_unbounded_frame_refused(self):
  logs=self.log({'../escape':['ignored']})
  with self.assertRaisesRegex(ValueError,'safe log ZIP'):S.extract(logs,'1'*40,'1','1','lifecycle')
  logs.unlink();logs=self.log({'0_native.txt':[S.PREFIX+base64.b64encode(b'x'*S.MAX_JSON*2).decode()]})
  with self.assertRaisesRegex(ValueError,'bounded frame'):S.extract(logs,'1'*40,'1','1','lifecycle')
 def test_two_workflows_only_retain_shell_changed_and_original_status_preserved(self):
  root=next(p for p in HERE.parents if (p/'.github/workflows/native-arm-glibc-gnu-provider-lifecycle.yml').is_file())
  for lane in S.LANES:
   rel='.github/workflows/native-arm-glibc-gnu-provider-'+lane+'.yml';old=(ROOT/rel).read_text();new=(root/rel).read_text();start=old.index('      - name: Retain only');end=old.index('      - name: Upload only',start);nstart=new.index('      - name: Retain only');nend=new.index('      - name: Upload only',nstart);self.assertEqual(old[:start],new[:nstart]);self.assertEqual(old[end:],new[nend:]);block=new[nstart:nend];self.assertIn('|| retain_status=$?',block);self.assertIn('if [ "$retain_status" -ne 0 ]; then exit "$retain_status"; fi',block);self.assertIn('timeout-minutes: 5',block);self.assertIn(S.pin((HERE/'summary.py').read_bytes())['sha256'],block)
if __name__=='__main__':unittest.main(verbosity=2)
