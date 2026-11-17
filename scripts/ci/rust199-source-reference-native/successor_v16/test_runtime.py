# SPDX-License-Identifier: MIT
"""Successful maintained qualification MODEL to final return; no actor/network."""
import hashlib,importlib.util,io,json,sys,tarfile,tempfile,time,unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
T=module('v16_held_workspace_models',HERE.parent/'successor_v15/test_runtime.py');P,D=T.P,T.D
Q=module('v16_qualification_success',HERE/'payload/hosted/qualification.py');OLD=module('v16_consumed_qualification',HERE.parent/'successor_v15/payload/hosted/qualification.py')
LIFE=dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0)

class SuccessfulDaemon(T.Daemon):
 def __init__(self,audit):
  super().__init__();self.audit=audit;self.owned=SimpleNamespace(run=self.export);self.exports=0
 def __call__(self,argv,timeout=60,check=True):
  args=argv[2:]
  if args and args[0]=='start'and '-c'not in self.actors[args[-1]]['Config']['Cmd']:
   row=self.actors[args[-1]];self.events.append(args);self.rows.append(dict(argv=argv));row['State']['Status']='exited'
   if args[-1].endswith('-data'):
    work=Path(next(m['Source']for m in row['Mounts']if m['Destination']=='/work'));(work/'build/stage0').mkdir(parents=True)
   return SimpleNamespace(stdout=b'',stderr=b'',returncode=0)
  return super().__call__(argv,timeout,check)
 def export(self,argv,**kw):
  assert argv[:3]==P.DOCKER+['cp']and argv[-1]=='-'and argv[-2].endswith(':/work/output')
  assert kw['stdout_limit']==128*1024**2 and kw['stderr_limit']==16*1024**2 and 0<kw['timeout']<=120
  kw['on_tick']();body=Q.encode(dict(MODEL_OUTPUT_ONLY=True,source_audit=self.audit,native_acceptance=False,holds_preserved=True))
  with tarfile.open(fileobj=kw['stdout'],mode='w|',format=tarfile.GNU_FORMAT)as tar:
   row=tarfile.TarInfo('output/native-qualification.json');row.size=len(body);row.mode=0o444;tar.addfile(row,io.BytesIO(body))
  kw['lifecycle'].update(LIFE);self.exports+=1;return SimpleNamespace(stdout=b'',stderr=b'',returncode=0)

class Runtime(unittest.TestCase):
 def exercise(self,qualifier,mode='success'):
  with tempfile.TemporaryDirectory(dir=HERE,prefix='MODEL-success-')as tmp,T.domain(),ExitStack()as patches:
   root=Path(tmp)/'source';work=Path(tmp)/'rust199-hosted';root.mkdir();work.mkdir(mode=0o700);(work/'daemon.json').write_bytes(P.encode(dict(info=T.INFO)))
   audit=dict(MODEL_AUDIT_ONLY=True);path=work/'audit.json';path.write_bytes(P.encode(audit));materials=[]
   for i in range(5):
    p=work/(str(i)+'.xz');p.write_bytes(b'MODEL finite material');materials.append(dict(name=p.name,local_path=str(p),transport='LOCAL_READONLY',**P.pin(p,1024)))
   provider=dict(source=T.SOURCE,dispatch_sha256='3'*64);plan=dict(reviews={k:True for k in('stage0','source','llvm_material')},source_audit=audit,holds_preserved=True);delivered=dict(materials=materials,files=dict(source_audit=dict(local_path=str(path))))
   daemon=SuccessfulDaemon(audit);deadline=daemon.deadline;clock=[time.monotonic()];events=[];leases=[];post_checks=[];original=D.Lease
   def outer_tick():
    closed=bool(leases and leases[-1].closed);events.append('outer-retired'if closed else'outer-active')
    if closed and mode=='outer-failure':raise ValueError('MODEL restored outer guard failure')
   daemon.on_tick=outer_tick
   class Lease(original):
    def __init__(self,*a,**kw):
     self.closed=False;super().__init__(*a,**kw);leases.append(self)
    def check(self):
     if self.closed:post_checks.append('closed-workspace-check');raise ValueError('MODEL closed workspace FDs still held')
     if leases and mode=='active-failure'and not daemon.cleaning:raise ValueError('MODEL active workspace guard failure')
     return super().check()
    def close(self):
     super().close();self.closed=True;events.append('workspace-closed')
     if mode=='timeout':clock[0]=deadline+1
     if mode=='cancel':daemon.cancelled[0]=True
   def model_validate(value,*args):
    assert value['MODEL_OUTPUT_ONLY']is True and value['source_audit']==audit and value['native_acceptance']is False
    proof=value['owned_work_bind'];D.validate(proof,proof['volume'],proof['labels']);assert leases and not leases[-1].closed
    events.append('MODEL-output-validator-active')
   patches.enter_context(patch.object(qualifier,'load',return_value=P));patches.enter_context(patch.object(P,'workspace_module',return_value=D));patches.enter_context(patch.object(D,'Lease',Lease));patches.enter_context(patch.object(qualifier,'validate_result',side_effect=model_validate))
   patches.enter_context(patch.object(qualifier.resource,'setrlimit',return_value=None));patches.enter_context(patch.object(qualifier.time,'monotonic',side_effect=lambda:clock[0]))
   result=None;error=None
   try:result=qualifier.run(root,work,provider,plan,delivered,dict(image=T.IMAGE,rootfs_tree_sha256='4'*64),daemon)
   except ValueError as exc:error=str(exc)
   report=json.loads((work/'qualification/controller.json').read_bytes())
   self.assertFalse(daemon.actors);self.assertTrue(report['owned_resources_absent']);self.assertEqual([r['status']for r in report['workspace_lifecycle']],['CREATED_HELD','RETIRED_ABSENT']);self.assertTrue(leases[-1].closed);self.assertFalse(leases[-1].path.exists());self.assertIs(daemon.on_tick,outer_tick);self.assertEqual(daemon.deadline,deadline);self.assertFalse(daemon.cleaning)
   if result is not None:
    descriptor=result['files']['qualification_controller'];body=Path(descriptor['local_path']).read_bytes();self.assertEqual({k:descriptor[k]for k in('bytes','sha256')},dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest()));self.assertEqual(result['proof_path'],result['files']['native_qualification']['local_path'])
   return SimpleNamespace(result=result,error=error,events=events,closed_checks=post_checks,report=report,exports=daemon.exports)
 def test_old_fails_new_passes_after_complete_successful_qualification_retirement(self):
  old=self.exercise(OLD);self.assertIsNone(old.result);self.assertIn('closed workspace FDs still held',old.error);self.assertEqual(old.report['status'],'PASS_NATIVE_SOURCE_QUALIFICATION_ONLY');self.assertEqual(old.exports,1);self.assertTrue(old.closed_checks);self.assertNotIn('outer-retired',old.events)
  new=self.exercise(Q);self.assertIsNone(new.error);self.assertIsNotNone(new.result);self.assertEqual(new.exports,1);self.assertIn('MODEL-output-validator-active',new.events);self.assertIn('outer-active',new.events);self.assertIn('outer-retired',new.events);self.assertLess(new.events.index('workspace-closed'),new.events.index('outer-retired'));self.assertFalse(new.closed_checks)
 def test_restored_global_deadline_still_refuses_after_retirement(self):
  v=self.exercise(Q,'timeout');self.assertIsNone(v.result);self.assertIn('qualification report global deadline',v.error);self.assertFalse(v.closed_checks);self.assertNotIn('outer-retired',v.events)
 def test_cancellation_still_refuses_after_retirement(self):
  v=self.exercise(Q,'cancel');self.assertIsNone(v.result);self.assertIn('qualification report cancellation',v.error);self.assertFalse(v.closed_checks);self.assertNotIn('outer-retired',v.events)
 def test_restored_outer_guard_failure_still_refuses_after_retirement(self):
  v=self.exercise(Q,'outer-failure');self.assertIsNone(v.result);self.assertIn('MODEL restored outer guard failure',v.error);self.assertFalse(v.closed_checks);self.assertIn('outer-retired',v.events)
 def test_pre_retirement_workspace_guard_remains_mandatory(self):
  v=self.exercise(Q,'active-failure');self.assertIsNone(v.result);self.assertIn('MODEL active workspace guard failure',v.error);self.assertFalse(v.closed_checks);self.assertEqual(v.exports,0)
 def test_curated_actual_global_failure_and_partial_native_facts_stay_distinct(self):
  raw=(HERE/'fixtures/public-failure.ACTUAL361.json').read_bytes();self.assertEqual(len(raw),3585);self.assertEqual(hashlib.sha256(raw).hexdigest(),'b77783095035ca5eef88176b78fcc24af71aa3321890897929e6f09587cabb67');value=json.loads(raw);self.assertEqual(value['run'],43973692325);self.assertEqual(value['bootstrap'],'FAIL');self.assertEqual(value['build'],'SKIPPED');self.assertEqual(value['qualification_status'],'PASS_NATIVE_SOURCE_QUALIFICATION_ONLY');self.assertEqual(value['native_probe_count'],9);self.assertTrue(value['owned_resources_absent']);self.assertIsNone(value['Root_native_acceptance'])

if __name__=='__main__':unittest.main(verbosity=2)
