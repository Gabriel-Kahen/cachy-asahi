# SPDX-License-Identifier: MIT
"""Bounded owner-aware benchmark adoption controls; physical conditions are fixtures."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('rss_platform_controls',HERE/'test_benchmark_platform_metrics.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
b,a=t.b,t.a

ALLOCATION='''import hashlib,os,time
size=int(os.environ.get('BENCH_BYTES','4194304'))
data=bytearray(size)
for i in range(0,len(data),4096): data[i]=1
answer=hashlib.sha256(b'fixed representative work').hexdigest()
time.sleep(.34)
print(answer,flush=True)
'''
DESCENDANT='''import json,os,signal,time
leader=bytearray(4*1024**2)
for i in range(0,len(leader),4096): leader[i]=1
child=os.fork()
if child==0:
 signal.signal(signal.SIGTERM,signal.SIG_DFL)
 data=bytearray(12*1024**2)
 for i in range(0,len(data),4096): data[i]=1
 with open(READY_PATH,'x') as ready:
  json.dump({'leader_pid':os.getppid(),'descendant_pid':os.getpid(),'allocated_bytes':len(data),'monotonic_ns':time.monotonic_ns()},ready)
 time.sleep(.34)
 os._exit(0)
def retire(signum,frame):
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 try: os.waitpid(child,0)
 except ChildProcessError: pass
 raise SystemExit(143)
signal.signal(signal.SIGTERM,retire)
_,status=os.waitpid(child,0)
print('descendant reaped',os.waitstatus_to_exitcode(status),flush=True)
'''



def descendant_ready_owner(path, boundary):
 """Test-only launch boundary; core gets the same timeout and real live group."""
 collector,owner=a.load_dependencies()
 def supervise(child,**kwargs):
  deadline=time.monotonic()+.5
  try:
   while time.monotonic()<deadline:
    try:
     terminal=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
    except ChildProcessError:
     child._child_created=False  # UNKNOWN: forbid fallback numeric cleanup.
     raise
    if terminal is not None: break
    try:
     with path.open('rb') as stream: raw=stream.read(4097)
     if len(raw)>4096: raise AssertionError('fixture readiness byte bound')
     ready=json.loads(raw)
     if ready['leader_pid']!=child.pid: raise AssertionError('foreign fixture readiness')
     boundary.update(ready)
     break
    except (FileNotFoundError,json.JSONDecodeError):
     time.sleep(.002)
  except BaseException:
   if child._child_created:
    owner.supervise(child,**kwargs)  # Retire only this still-owned fresh child.
   raise
  return owner.supervise(child,**kwargs)
 return collector,SimpleNamespace(__file__=owner.__file__,prepare=owner.prepare,supervise=supervise)


def prepare(root,owned=True,program=ALLOCATION,paired=False):
 config,identity=t.files(root,program=program)
 if owned: config['owned_rss']={'interval_seconds':.5}
 if paired:
  config['change']={'variable':'scratch allocation size','baseline':str(2*1024**2),'candidate':str(10*1024**2),
    'environment_key':'BENCH_BYTES','rationale':'intentional memory-regression control; fixed work/output; no optimization claim'}
  config['variant_env']={'baseline':{'BENCH_BYTES':str(2*1024**2)},'candidate':{'BENCH_BYTES':str(10*1024**2)}}
  config['variant_inputs']={'baseline':[str(root/'workload.py')],'candidate':[str(root/'workload.py')]}
  config['thresholds']['minimum_elapsed_improvement_pct']=0
  config['thresholds']['maximum_regression']={'root_rss_kib_pct':5,'process_group_sampled_rss_kib_pct':5}
 (root/'plan.json').unlink();(root/'config.json').write_text(json.dumps(config))
 b.freeze(root/'config.json',root/'state.json',root/'state.json',root/'plan.json')
 return config,identity


def run(root,slot=0,identity=None):
 if identity is None: identity=b.state_identity(b.read_json(root/'state.json'))
 directory=root/('trial-'+str(slot))
 with patch.object(b,'live_identity',return_value=identity):
  code=b.run(root/'plan.json',slot,root/'state.json',root/'conditions.json',root,directory,platform_metrics=True)
 return code,b.read_json(directory/'trial.json'),directory


class OwnedRssTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.shared=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.shared.cleanup)
  cls.base=Path(cls.shared.name);prepare(cls.base)
  code,cls.trial,cls.source=run(cls.base)
  if code: raise AssertionError(cls.trial)
  cls.raw=b.read_json(cls.source/'owned-rss.json')

 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.directory=self.root/'trial'
  shutil.copytree(self.source,self.directory)
  self.trial=copy.deepcopy(type(self).trial);self.raw=copy.deepcopy(type(self).raw)

 def project(self,rss=None):
  return b.owned_rss_metrics(rss or self.raw['observation'],self.raw['monotonic_start_ns'],self.raw['monotonic_end_ns'],.5)

 def test_actual_allocation_has_usable_separate_group_and_leader_rss(self):
  metrics=self.project()
  self.assertTrue(self.trial['valid'])
  self.assertEqual(self.trial['metrics']['root_rss_kib'],metrics['root_rss_kib'])
  self.assertGreater(metrics['root_rss_kib'],0)
  self.assertGreater(metrics['process_group_sampled_rss_kib'],0)
  self.assertEqual(self.raw['observation']['status'],'complete')
  capture=b.read_json(self.directory/'platform-metrics/capture.json')
  self.assertEqual(capture['supervision']['group_census'],'RESERVED_LEADER_ONLY')
  self.assertTrue(capture['supervision']['reaped'])
  self.assertEqual(capture['supervision']['ownership'],'REAPED')
  self.assertEqual(self.trial['optimization_acceptance'],'NOT RUN')

 def test_actual_descendant_is_measured_or_churn_is_explicitly_invalid(self):
  root=self.root/'descendant';ready=root/'descendant-ready.json';boundary={}
  prepare(root,program=DESCENDANT.replace('READY_PATH',repr(str(ready))))
  dependencies=descendant_ready_owner(ready,boundary)
  with patch.object(a,'load_dependencies',return_value=dependencies):
   code,trial,directory=run(root)
  self.assertTrue(boundary,'allocated descendant did not reach the bounded readiness boundary')
  metrics=trial['metrics']
  if code:
   self.assertFalse(trial['valid'])
   self.assertIsNone(metrics['root_rss_kib']);self.assertIsNone(metrics['process_group_sampled_rss_kib'])
   self.assertIn('RSS',trial['error'])
   capture=b.read_json(directory/'platform-metrics/capture.json')
   self.assertTrue(capture['supervision']['reaped'])
   return
  self.assertGreater(metrics['process_group_sampled_rss_kib'],metrics['root_rss_kib'])
  raw=b.read_json(directory/'owned-rss.json')
  observed=[s for s in raw['observation']['samples'] if s['status']=='complete'
    and s['monotonic_start_ns']>=boundary['monotonic_ns']
    and any(m['pid']==boundary['descendant_pid'] and m['state'] not in ('Z','X')
            and m['rss_kib']>=12*1024 for m in s['members'])]
  self.assertTrue(observed,'no complete live allocated-descendant observation')
  self.assertTrue(any(len(s['members'])>=2 for s in observed))
  self.assertIn('descendant reaped 0',(directory/'stdout.txt').read_text())

 def test_disabled_mode_remains_explicitly_unavailable(self):
  root=self.root/'disabled';prepare(root,owned=False)
  code,trial,directory=run(root)
  self.assertEqual(code,0,trial)
  self.assertIsNone(trial['metrics']['root_rss_kib'])
  self.assertNotIn('owned_rss',trial)
  self.assertFalse((directory/'owned-rss.json').exists())

 def test_invalid_config_and_old_core_cannot_select_rss(self):
  config=b.read_json(self.base/'config.json')
  for value in ({},{'interval_seconds':True},{'interval_seconds':.001},{'interval_seconds':float('nan')},{'interval_seconds':61}):
   changed=copy.deepcopy(config);changed['owned_rss']=value
   with self.subTest(value=value),self.assertRaises(b.Invalid): b.validate_config(changed)
  changed=copy.deepcopy(config);changed.pop('platform_metrics')
  with self.assertRaises(b.Invalid): b.validate_config(changed)
  with patch.object(b,'OWNED_RSS_CORE_SHA256','0'*64),self.assertRaises(b.Invalid): b.validate_config(config)

 def test_sum_identity_scope_clock_and_cached_peak_tampering_refused(self):
  for mutation in ('sum','group','scope','clock','peak','negative','duplicate'):
   rss=copy.deepcopy(self.raw['observation'])
   sample=next(row for row in rss['samples'] if row['status']=='complete')
   if mutation=='sum': sample['rss_sum_kib']+=1
   elif mutation=='group': sample['members'][0]['group']+=1
   elif mutation=='scope': sample['scope']='leader only'
   elif mutation=='clock': sample['monotonic_end_ns']=0
   elif mutation=='peak': rss['process_group_sampled_rss_kib']+=1
   elif mutation=='negative': sample['members'][0]['rss_kib']=-1
   else: sample['members'].append(copy.deepcopy(sample['members'][0]))
   with self.subTest(mutation=mutation),self.assertRaises(b.Invalid): self.project(rss)

 def test_pure_two_member_fixture_keeps_leader_and_group_quantities_distinct(self):
  rss=copy.deepcopy(self.raw['observation'])
  for sample in rss['samples']:
   if sample['status']!='complete': continue
   member=copy.deepcopy(sample['members'][0])
   member.update(pid=sample['group_id']+1,rss_kib=6144,state='S')
   sample['members'].append(member);sample['rss_sum_kib']+=6144
  rss.update(b.process_group_memory.summarize(rss['samples']))
  value=self.project(rss)
  self.assertEqual(value['root_rss_kib'],self.trial['metrics']['root_rss_kib'])
  self.assertEqual(value['process_group_sampled_rss_kib'],self.trial['metrics']['process_group_sampled_rss_kib']+6144)

 def test_partial_raw_data_retains_diagnostic_peak_but_has_no_usable_peak(self):
  rss=copy.deepcopy(self.raw['observation']);stamp=self.raw['monotonic_end_ns']
  gid=rss['samples'][0]['group_id']
  rss['samples'].append({'status':'incomplete','group_id':gid,'rss_sum_kib':None,'members':[],
    'scope':b.process_group_memory.SCOPE,'reason':'fixture missing read','monotonic_start_ns':stamp,'monotonic_end_ns':stamp})
  rss.update(b.process_group_memory.summarize(rss['samples']))
  rss.update(status='partial',error='fixture missing read',leader_sampled_rss_kib=None)
  value=self.project(rss)
  self.assertIsNone(value['root_rss_kib']);self.assertIsNone(value['process_group_sampled_rss_kib'])
  self.assertGreater(value['process_group_observed_rss_kib'],0)
  self.assertEqual(value['process_group_rss_coverage']['missing_or_incomplete_samples'],1)

 def test_raw_rss_binding_and_metric_swap_refused_by_comparator(self):
  for mutation in ('raw','metrics','declaration'):
   trial=copy.deepcopy(self.trial)
   if mutation=='raw':
    changed=copy.deepcopy(self.raw);changed['observation']['leader_sampled_rss_kib']+=1
    (self.directory/'owned-rss.json').write_text(json.dumps(changed))
    trial['raw_sha256']['owned-rss.json']=b.digest(self.directory/'owned-rss.json')
   elif mutation=='metrics': trial['metrics']['root_rss_kib']=trial['metrics']['process_group_sampled_rss_kib']+1
   else: trial['owned_rss']['interval_seconds']=1
   (self.directory/'trial.json').write_text(json.dumps(trial))
   with self.subTest(mutation=mutation),self.assertRaises(b.Invalid):
    b.compare(self.base/'plan.json',[self.directory],self.root/('refused-'+mutation+'.json'))
   (self.directory/'owned-rss.json').write_text(json.dumps(self.raw,indent=2)+'\n')

 def test_successful_trial_cannot_contradict_captured_supervision(self):
  original=b.read_json(self.directory/'platform-metrics/capture.json')
  legacy=[json.loads(line) for line in (self.directory/'telemetry.jsonl').read_text().splitlines()]
  for key,value in (('passed',False),('error','fixture failure'),('timeout',True),('signals',['SIGTERM']),('output_complete',False),('group_census','EMPTY_TWICE')):
   capture=copy.deepcopy(original);capture['supervision'][key]=value
   (self.directory/'platform-metrics/capture.json').write_text(json.dumps(capture))
   with self.subTest(key=key),self.assertRaisesRegex(b.Invalid,'contradicts supervision'):
    b.verify_owned_rss(self.directory,self.trial,b.read_json(self.base/'config.json'),legacy)

 def test_capture_larger_than_replay_bound_cannot_be_a_valid_result(self):
  capture=b.read_json(self.directory/'platform-metrics/capture.json')
  capture['padding']='x'*(512*1024)
  (self.directory/'platform-metrics/capture.json').write_text(json.dumps(capture))
  (self.directory/'owned-rss.json').unlink()
  config=b.read_json(self.base/'config.json')
  with patch.object(a,'execute',return_value=copy.deepcopy(self.trial)):
   result=b.execute_owned_rss(config,self.trial['argv'],Path(self.trial['cwd']),{},self.directory)
  self.assertIn('metadata replay bound',result['error'])
  self.assertFalse(result['owned_rss']['capture_replayable'])

 def test_complete_report_replays_from_raw_and_same_capture(self):
  legacy=[json.loads(line) for line in (self.directory/'telemetry.jsonl').read_text().splitlines()]
  expected=b.verify_owned_rss(self.directory,self.trial,b.read_json(self.base/'config.json'),legacy)
  self.assertEqual(expected,self.trial['metrics'])


if __name__=='__main__':unittest.main()
